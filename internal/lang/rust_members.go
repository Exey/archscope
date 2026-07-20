package lang

import (
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/parser"
)

// rust_members.go is Rust's phase-1 coupling/cohesion data source. Rust
// doesn't put methods inside the struct body like Go/Swift/TS/C++/Java —
// fields live in `struct Name { ... }`, methods live in one or more
// separate `impl Name { ... }` (or `impl Trait for Name { ... }`) blocks
// elsewhere in the file. So this can't reuse members_common.go's
// single-pass extractor; it's a dedicated two-pass version instead: collect
// every struct's fields first, then walk impl blocks collecting only
// self-taking methods (associated functions like `fn new() -> Self` are
// skipped — they have no receiver to compare against, same reasoning Go's
// receiver-based extractor uses). Same accuracy caveats as the other
// regex-based extractors (see members_common.go's doc comment).
var (
	rustStructDecl = regexp.MustCompile(`^(?:pub(?:\([^)]*\))?\s+)?struct\s+(\w+)`)
	rustFieldDecl  = regexp.MustCompile(`^(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*`)
	rustImplDecl   = regexp.MustCompile(`^impl(?:<[^>]*>)?\s+(?:[\w:]+(?:<[^>]*>)?\s+for\s+)?([\w:]+)`)
	rustFnDecl     = regexp.MustCompile(`^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*`)
)

var rustBuiltinTypes = map[string]bool{
	"i8": true, "i16": true, "i32": true, "i64": true, "i128": true, "isize": true,
	"u8": true, "u16": true, "u32": true, "u64": true, "u128": true, "usize": true,
	"f32": true, "f64": true, "bool": true, "char": true, "str": true, "String": true,
	"Self": true, "Vec": true, "Option": true, "Result": true, "Box": true, "Rc": true, "Arc": true,
	"HashMap": true, "HashSet": true, "BTreeMap": true,
}

func extractRustMembers(lines []string) []parser.TypeMembers {
	fieldSets := map[string]map[string]bool{}
	var structOrder []string

	var curStruct string
	structDepth := 0
	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if curStruct == "" {
			if m := rustStructDecl.FindStringSubmatch(trimmed); m != nil && strings.Contains(trimmed, "{") {
				curStruct = m[1]
				if _, ok := fieldSets[curStruct]; !ok {
					fieldSets[curStruct] = map[string]bool{}
					structOrder = append(structOrder, curStruct)
				}
				structDepth = 0
			}
		} else if structDepth == 1 {
			if m := rustFieldDecl.FindStringSubmatch(trimmed); m != nil {
				fieldSets[curStruct][m[1]] = true
			}
		}
		if curStruct != "" {
			structDepth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
			if structDepth <= 0 && strings.Contains(trimmed, "}") {
				curStruct = ""
			}
		}
	}

	methodsByType := map[string][]parser.MethodMembers{}

	var curImplType string
	implDepth := 0
	var curMethod *braceMethodCtx
	fnCfg := braceMembersConfig{methodName: rustFnDecl}
	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if curImplType == "" {
			if m := rustImplDecl.FindStringSubmatch(trimmed); m != nil && strings.Contains(trimmed, "{") {
				curImplType = m[1]
				implDepth = 0
			}
		} else if curMethod == nil && implDepth == 1 {
			if name, params, ok := matchMethodDecl(trimmed, fnCfg); ok && isRustSelfParam(params) {
				curMethod = &braceMethodCtx{
					mm:           parser.MethodMembers{Name: name, ParamTypes: paramTypesFromRaw(params)},
					fieldRefs:    map[string]bool{},
					externalRefs: map[string]bool{},
				}
			}
		}
		if curMethod != nil {
			fs := fieldSets[curImplType]
			for _, id := range identRe.FindAllString(trimmed, -1) {
				if fs[id] {
					curMethod.fieldRefs[id] = true
				}
			}
			for _, m := range capitalCallRe.FindAllStringSubmatch(trimmed, -1) {
				if m[1] != curImplType && !rustBuiltinTypes[m[1]] {
					curMethod.externalRefs[m[1]] = true
				}
			}
		}

		delta := strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if curMethod != nil {
			curMethod.depth += delta
		}
		if curImplType != "" {
			implDepth += delta
		}

		if curMethod != nil && curMethod.depth <= 0 && strings.Contains(trimmed, "}") {
			mc := curMethod
			curMethod = nil
			for f := range mc.fieldRefs {
				mc.mm.FieldRefs = append(mc.mm.FieldRefs, f)
			}
			for e := range mc.externalRefs {
				mc.mm.ExternalRefs = append(mc.mm.ExternalRefs, e)
			}
			for _, pt := range mc.mm.ParamTypes {
				if !rustBuiltinTypes[pt] && !mc.externalRefs[pt] {
					mc.mm.ExternalRefs = append(mc.mm.ExternalRefs, pt)
				}
			}
			methodsByType[curImplType] = append(methodsByType[curImplType], mc.mm)
		}
		if curImplType != "" && implDepth <= 0 && strings.Contains(trimmed, "}") {
			curImplType = ""
		}
	}

	var out []parser.TypeMembers
	for _, name := range structOrder {
		methods := methodsByType[name]
		if len(methods) == 0 {
			continue
		}
		var fields []string
		for f := range fieldSets[name] {
			fields = append(fields, f)
		}
		out = append(out, parser.TypeMembers{TypeName: name, Fields: fields, Methods: methods})
	}
	return out
}

// isRustSelfParam reports whether a raw parameter list's first segment is a
// self receiver (self, &self, &mut self, or the rarer self: Pin<&mut Self>
// form) — the signal that separates an instance method from an associated
// function like `fn new(...) -> Self`, which has nothing to compare field
// refs against.
func isRustSelfParam(params string) bool {
	segs := splitTopLevel(params, ',')
	if len(segs) == 0 {
		return false
	}
	first := strings.TrimSpace(segs[0])
	first = strings.TrimPrefix(first, "&")
	first = strings.TrimPrefix(strings.TrimSpace(first), "mut ")
	first = strings.TrimSpace(first)
	return first == "self" || strings.HasPrefix(first, "self:") || strings.HasPrefix(first, "self ")
}
