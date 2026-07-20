package lang

import (
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/parser"
)

// python_members.go is Python's phase-1 coupling/cohesion data source.
// Python has no braces, so it can't reuse members_common.go's brace-depth
// walker — blocks are indentation-delimited instead. Fields aren't declared
// up front either: any `self.x` reference anywhere in a method makes `x` a
// field, which is the natural Python reading (mirrors how the language
// itself treats attributes). Same accuracy caveats as the other phase-1
// extractors: only top-level classes, only `self`-taking instance methods
// (no @staticmethod/@classmethod), single-file view only.
var (
	pyClassDecl  = regexp.MustCompile(`^class\s+(\w+)\s*[:\(]`)
	pyMethodDecl = regexp.MustCompile(`^(?:async\s+)?def\s+(\w+)\s*\(\s*self\s*(?:,\s*(.*))?\)\s*(?:->[^:]*)?:`)
	pySelfAttr   = regexp.MustCompile(`self\.(\w+)`)
)

var pyBuiltinTypes = map[string]bool{
	"int": true, "str": true, "float": true, "bool": true, "bytes": true, "list": true, "dict": true,
	"set": true, "tuple": true, "object": true, "None": true, "Any": true, "Optional": true, "List": true,
	"Dict": true, "Set": true, "Tuple": true, "Union": true, "Callable": true,
}

// indentOf counts leading whitespace characters — only used for relative
// comparisons within one file, so spaces vs. tabs don't need normalizing.
func indentOf(line string) int {
	n := 0
	for _, r := range line {
		if r != ' ' && r != '\t' {
			break
		}
		n++
	}
	return n
}

// pyBlockEnd returns the index of the last line belonging to the indented
// block opened by lines[headerIdx] (indent == headerIndent) — i.e. the last
// line with indent > headerIndent, treating blank/comment lines as
// transparent (they neither end nor extend a block, matching Python's own
// rule that they don't affect indentation structure).
func pyBlockEnd(lines []string, headerIdx, headerIndent int) int {
	end := headerIdx
	for i := headerIdx + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if indentOf(lines[i]) <= headerIndent {
			break
		}
		end = i
	}
	return end
}

func extractPythonMembers(lines []string) []parser.TypeMembers {
	var out []parser.TypeMembers
	for i := 0; i < len(lines); i++ {
		if indentOf(lines[i]) != 0 {
			continue
		}
		m := pyClassDecl.FindStringSubmatch(strings.TrimSpace(lines[i]))
		if m == nil {
			continue
		}
		className := m[1]
		classEnd := pyBlockEnd(lines, i, 0)

		bodyIndent := -1
		for k := i + 1; k <= classEnd; k++ {
			t := strings.TrimSpace(lines[k])
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			bodyIndent = indentOf(lines[k])
			break
		}

		var methods []parser.MethodMembers
		fields := map[string]bool{}
		if bodyIndent >= 0 {
			for j := i + 1; j <= classEnd; j++ {
				if indentOf(lines[j]) != bodyIndent {
					continue
				}
				mm := pyMethodDecl.FindStringSubmatch(strings.TrimSpace(lines[j]))
				if mm == nil {
					continue
				}
				methodEnd := pyBlockEnd(lines, j, bodyIndent)
				method := parser.MethodMembers{Name: mm[1]}
				if len(mm) > 2 && mm[2] != "" {
					method.ParamTypes = paramTypesFromRaw(mm[2])
				}
				fieldRefs := map[string]bool{}
				externalRefs := map[string]bool{}
				for k := j; k <= methodEnd; k++ {
					for _, fm := range pySelfAttr.FindAllStringSubmatch(lines[k], -1) {
						fieldRefs[fm[1]] = true
						fields[fm[1]] = true
					}
					for _, cm := range capitalCallRe.FindAllStringSubmatch(lines[k], -1) {
						if cm[1] != className && !pyBuiltinTypes[cm[1]] {
							externalRefs[cm[1]] = true
						}
					}
				}
				for f := range fieldRefs {
					method.FieldRefs = append(method.FieldRefs, f)
				}
				for e := range externalRefs {
					method.ExternalRefs = append(method.ExternalRefs, e)
				}
				for _, pt := range method.ParamTypes {
					if !pyBuiltinTypes[pt] && !externalRefs[pt] {
						method.ExternalRefs = append(method.ExternalRefs, pt)
					}
				}
				methods = append(methods, method)
				j = methodEnd
			}
		}
		if len(methods) > 0 {
			var fieldList []string
			for f := range fields {
				fieldList = append(fieldList, f)
			}
			out = append(out, parser.TypeMembers{TypeName: className, Fields: fieldList, Methods: methods})
		}
		i = classEnd
	}
	return out
}
