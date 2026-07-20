package lang

import (
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/parser"
)

// members_common.go is the shared field/method extractor for brace-delimited
// languages (Swift, TypeScript/JS) — the scanning algorithm (find a type's
// body span, then within it find field lines and method bodies) is the same
// regex + brace-depth technique internal/parser/universal.go already uses
// for BigFunctions/LongestType, just one level deeper (looking *inside* a
// type's body instead of only measuring its span). It deliberately tracks
// only one active type and one active method at a time, mirroring
// universal.go's own non-nested inType/inFunc flags — nested types/closures
// are an accepted miss, not a bug.
//
// This — like extractGoMembers — is a phase-1, per-language heuristic. See
// that file's doc comment for the longer-term shared-AST-layer plan; regex
// field/call extraction is inherently more fragile than Go's AST-based pass
// (multi-line signatures, computed properties, and nested closures can all
// throw it off), so treat Swift/TS cohesion numbers as directional, not
// exact.

// braceMembersConfig parameterizes the shared extractor per language.
type braceMembersConfig struct {
	typeDecl   *regexp.Regexp // group 1 = type name; only tried when not already inside a type
	fieldDecl  *regexp.Regexp // group 1 = field name; only tried directly inside a type body
	methodName *regexp.Regexp // group 1 = method name; match ends right before the "(" of its param list
	keywords   map[string]bool // control-flow words that can look like a call but aren't a method decl
	builtins   map[string]bool // primitive type names excluded from ExternalRefs (kept in ParamTypes)
}

var identRe = regexp.MustCompile(`[A-Za-z_]\w*`)
var capitalCallRe = regexp.MustCompile(`\b([A-Z]\w*)\s*\(`)

type braceTypeCtx struct {
	name    string
	fields  map[string]bool
	methods []parser.MethodMembers
}

type braceMethodCtx struct {
	depth        int
	mm           parser.MethodMembers
	fieldRefs    map[string]bool
	externalRefs map[string]bool
}

func extractBraceMembers(lines []string, cfg braceMembersConfig) []parser.TypeMembers {
	var out []parser.TypeMembers
	var curType *braceTypeCtx
	var curMethod *braceMethodCtx
	typeDepth := 0

	finalizeMethod := func() {
		mc := curMethod
		curMethod = nil
		for f := range mc.fieldRefs {
			mc.mm.FieldRefs = append(mc.mm.FieldRefs, f)
		}
		ext := mc.externalRefs
		for e := range ext {
			mc.mm.ExternalRefs = append(mc.mm.ExternalRefs, e)
		}
		for _, pt := range mc.mm.ParamTypes {
			if !cfg.builtins[pt] && !ext[pt] {
				mc.mm.ExternalRefs = append(mc.mm.ExternalRefs, pt)
			}
		}
		curType.methods = append(curType.methods, mc.mm)
	}
	finalizeType := func() {
		if len(curType.methods) > 0 {
			var fields []string
			for f := range curType.fields {
				fields = append(fields, f)
			}
			out = append(out, parser.TypeMembers{TypeName: curType.name, Fields: fields, Methods: curType.methods})
		}
		curType = nil
	}

	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		// Try to open a method or register a field — only directly inside a
		// type body, not already inside a method.
		if curMethod == nil && curType != nil && typeDepth == 1 {
			if name, params, ok := matchMethodDecl(trimmed, cfg); ok {
				mm := parser.MethodMembers{Name: name}
				if params != "" {
					mm.ParamTypes = paramTypesFromRaw(params)
				}
				curMethod = &braceMethodCtx{mm: mm, fieldRefs: map[string]bool{}, externalRefs: map[string]bool{}}
			} else if m := cfg.fieldDecl.FindStringSubmatch(trimmed); m != nil {
				curType.fields[m[1]] = true
			}
		}
		// Try to open a type — only when not already inside one.
		if curType == nil {
			if m := cfg.typeDecl.FindStringSubmatch(trimmed); m != nil && strings.Contains(trimmed, "{") {
				curType = &braceTypeCtx{name: m[1], fields: map[string]bool{}}
				typeDepth = 0
			}
		}

		// Scan this line for field/external refs against the (possibly
		// just-opened, on this very line) active method.
		if curMethod != nil {
			for _, id := range identRe.FindAllString(trimmed, -1) {
				if curType.fields[id] {
					curMethod.fieldRefs[id] = true
				}
			}
			for _, m := range capitalCallRe.FindAllStringSubmatch(trimmed, -1) {
				if m[1] != curType.name && !cfg.builtins[m[1]] {
					curMethod.externalRefs[m[1]] = true
				}
			}
		}

		delta := strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if curMethod != nil {
			curMethod.depth += delta
		}
		if curType != nil {
			typeDepth += delta
		}

		if curMethod != nil && curMethod.depth <= 0 && strings.Contains(trimmed, "}") {
			finalizeMethod()
		}
		if curType != nil && typeDepth <= 0 && strings.Contains(trimmed, "}") {
			finalizeType()
		}
	}
	return out
}

// matchMethodDecl tries cfg.methodName against trimmed and, on a match
// immediately followed by "(" (optionally after a generic <...>), manually
// scans for the matching ")" to pull out the raw parameter list — a regex
// can't capture balanced parens, so this does it by hand. Returns ok=false
// for control-flow keywords (if/for/while/...) that would otherwise look
// like a call, and for signatures with no body on this line (protocol/
// interface requirements, abstract methods) since those never get a
// closing brace for the depth tracker to find.
func matchMethodDecl(trimmed string, cfg braceMembersConfig) (name, params string, ok bool) {
	loc := cfg.methodName.FindStringSubmatchIndex(trimmed)
	if loc == nil {
		return "", "", false
	}
	name = trimmed[loc[2]:loc[3]]
	if cfg.keywords[name] {
		return "", "", false
	}
	i := loc[1]
	for i < len(trimmed) && (trimmed[i] == ' ' || trimmed[i] == '\t') {
		i++
	}
	if i >= len(trimmed) || trimmed[i] != '(' {
		return "", "", false
	}
	depth := 0
	start := i + 1
	end := -1
	for ; i < len(trimmed); i++ {
		switch trimmed[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return "", "", false // multi-line param list — accepted miss
	}
	if !strings.Contains(trimmed[end+1:], "{") {
		return "", "", false // no body on this line
	}
	return name, trimmed[start:end], true
}

// splitTopLevel splits s on sep, ignoring occurrences nested inside (), [],
// <>, or {} — needed so a param like "cb: (x: Int) -> Void" or
// "opts: Record<string, number>" doesn't get split on its inner comma.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth := 0
	last := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '<', '{':
			depth++
		case ')', ']', '>', '}':
			depth--
		default:
			if s[i] == sep && depth == 0 {
				out = append(out, s[last:i])
				last = i + 1
			}
		}
	}
	out = append(out, s[last:])
	return out
}

// paramTypesFromRaw extracts type names from a raw "name: Type, name2: Type2"
// parameter list (Swift/TS shape). Segments without a top-level colon (no
// type annotation — plain JS, or a Swift closure param) contribute nothing.
func paramTypesFromRaw(raw string) []string {
	var types []string
	for _, seg := range splitTopLevel(raw, ',') {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if i := strings.Index(seg, "="); i >= 0 {
			seg = seg[:i]
		}
		ci := strings.LastIndex(seg, ":")
		if ci < 0 {
			continue
		}
		typePart := strings.TrimSpace(seg[ci+1:])
		if m := identRe.FindString(typePart); m != "" {
			types = append(types, m)
		}
	}
	return types
}
