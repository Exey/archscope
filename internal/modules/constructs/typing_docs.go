// typing_docs.go holds two coverage readings for Code Structure:
//
//   - 🏷️ Typing health (Python): what share of functions carry full type
//     annotations, how often `Any` is used, and how many `# type: ignore`
//     comments switch the checker off (TS/JS `@ts-ignore` / `@ts-nocheck` /
//     `@ts-expect-error` count into the same ignore total) — the Python
//     counterpart of the TS loose-`any` stat, as mypy/pyright would see it.
//   - 📝 Documentation coverage: the share of public functions, classes and
//     types that have a doc comment (docstring, godoc, JSDoc, KDoc/Javadoc,
//     `///`), per language, with the worst files listed.
//
// Both are lexical readings of the masked source; neither changes a score —
// they are metrics a reviewer can watch move.
package constructs

import (
	"regexp"
	"strings"
)

// CSTypingFile is one Python file's typing numbers.
type CSTypingFile struct {
	FilePath     string
	Funcs        int
	Typed        int
	AnyCount     int
	Ignores      int
	FirstUntyped int // 1-based line of the first untyped function
}

// CSDocFile is one file's public-API documentation numbers.
type CSDocFile struct {
	FilePath     string
	Public       int
	Documented   int
	FirstMissing int // 1-based line of the first undocumented public symbol
}

var (
	reTypeIgnore   = regexp.MustCompile(`#\s*type:\s*ignore\b|@ts-ignore\b|@ts-nocheck\b|@ts-expect-error\b`)
	rePyAny        = regexp.MustCompile(`\bAny\b`)
	rePyDocOpen    = regexp.MustCompile(`^[rRuUbBfF]{0,2}("""|'''|"|')`)
	reDocGoDecl    = regexp.MustCompile(`^(?:func\s+(?:\([^)]*\)\s*)?([A-Z]\w*)\s*[(\[]|type\s+([A-Z]\w*)\b|(?:var|const)\s+([A-Z]\w*)\b)`)
	reDocTSDecl    = regexp.MustCompile(`^export\s+(?:default\s+)?(?:declare\s+)?(?:async\s+)?(?:function\*?|class|interface|type|enum|const|abstract\s+class)\s+(\w+)`)
	reDocJavaDecl  = regexp.MustCompile(`^\s*public\s+(?:static\s+|final\s+|abstract\s+|synchronized\s+|default\s+)*(?:(?:class|interface|enum|record)\s+(\w+)|[\w<>\[\],.? ]+?\s+(\w+)\s*\()`)
	reDocKtDecl    = regexp.MustCompile(`^\s*(?:public\s+)?(?:open\s+|abstract\s+|suspend\s+|inline\s+|data\s+|sealed\s+|enum\s+|annotation\s+)*(?:fun\s+(?:<[^>]*>\s*)?(?:[\w.<>?]+\.)?(\w+)|class\s+(\w+)|interface\s+(\w+)|object\s+(\w+))`)
	reDocSwiftDecl = regexp.MustCompile(`^\s*(?:public|open)\s+(?:final\s+|static\s+|class\s+|override\s+|mutating\s+|indirect\s+)*(?:func\s+(\w+)|class\s+(\w+)|struct\s+(\w+)|enum\s+(\w+)|protocol\s+(\w+)|actor\s+(\w+))`)
	reDocRustDecl  = regexp.MustCompile(`^\s*pub\s+(?:async\s+|unsafe\s+|const\s+)*(?:fn\s+(\w+)|struct\s+(\w+)|enum\s+(\w+)|trait\s+(\w+)|type\s+(\w+))`)
	reDocCSDecl    = regexp.MustCompile(`^\s*public\s+(?:static\s+|sealed\s+|abstract\s+|async\s+|virtual\s+|override\s+|partial\s+)*(?:(?:class|interface|enum|struct|record)\s+(\w+)|[\w<>\[\],.? ]+?\s+(\w+)\s*\()`)
)

// pyTypingStats measures one Python file's annotations.
func pyTypingStats(filePath string, m maskedFile) CSTypingFile {
	funcs, _ := pyParse(m)
	t := CSTypingFile{FilePath: filePath}
	for _, f := range funcs {
		t.Funcs++
		if pyFullyTyped(m, f) {
			t.Typed++
		} else if t.FirstUntyped == 0 {
			t.FirstUntyped = f.start + 1
		}
	}
	for _, l := range m.code {
		if strings.Contains(l, "import") {
			continue
		}
		t.AnyCount += len(rePyAny.FindAllStringIndex(l, -1))
	}
	return t
}

// pyFullyTyped reports a def with a return annotation (not required on
// __init__) and an annotation on every parameter except self/cls.
func pyFullyTyped(m maskedFile, f pyFunc) bool {
	sigText := strings.Join(m.code[f.start:f.sigEnd+1], " ")
	hasReturn := strings.Contains(sigText, "->")
	if !hasReturn && f.name != "__init__" {
		return false
	}
	for _, p := range splitTopLevel(f.params, f.params, ',') {
		p = strings.TrimSpace(p)
		if p == "" || p == "*" || p == "/" || p == "self" || p == "cls" {
			continue
		}
		name := strings.TrimLeft(p, "*")
		if i := indexTop(name, '='); i >= 0 {
			name = name[:i]
		}
		if name == "self" || name == "cls" || strings.TrimSpace(name) == "" {
			continue
		}
		if !strings.Contains(name, ":") {
			return false
		}
	}
	return true
}

// countTypeIgnores counts type-checker suppression comments in raw lines.
func countTypeIgnores(raw []string) int {
	n := 0
	for _, l := range raw {
		if strings.Contains(l, "ignore") || strings.Contains(l, "@ts-") {
			n += len(reTypeIgnore.FindAllStringIndex(l, -1))
		}
	}
	return n
}

// docStats counts a file's public symbols and how many carry a doc comment.
// Unsupported languages return ok=false.
func docStats(filePath string, m maskedFile) (CSDocFile, bool) {
	fe := ext(filePath)
	d := CSDocFile{FilePath: filePath}
	miss := func(line int) {
		if d.FirstMissing == 0 {
			d.FirstMissing = line + 1
		}
	}
	prevDoc := func(i int, isDoc func(string) bool) bool {
		for j := i - 1; j >= 0 && j >= i-6; j-- {
			t := strings.TrimSpace(m.raw[j])
			if t == "" {
				return false
			}
			if strings.HasPrefix(t, "@") || strings.HasPrefix(t, "#[") || strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
				continue // annotations / attributes sit between the doc and the declaration
			}
			return isDoc(t)
		}
		return false
	}
	switch fe {
	case ".py", ".pyi":
		funcs, classes := pyParse(m)
		check := func(name string, start, bodyStart int) {
			if strings.HasPrefix(name, "_") {
				return
			}
			d.Public++
			for j := bodyStart; j < len(m.code); j++ {
				t := strings.TrimSpace(m.code[j])
				if t == "" {
					continue
				}
				if rePyDocOpen.MatchString(t) {
					d.Documented++
				} else {
					miss(start)
				}
				return
			}
			miss(start)
		}
		for _, f := range funcs {
			if f.enclosedDef || f.oneLiner {
				continue
			}
			check(f.name, f.start, f.bodyStart)
		}
		for _, c := range classes {
			check(c.name, c.start, c.start+1)
		}
	case ".go":
		for i, l := range m.code {
			g := reDocGoDecl.FindStringSubmatch(l)
			if g == nil {
				continue
			}
			d.Public++
			if prevDoc(i, func(t string) bool { return strings.HasPrefix(t, "//") }) {
				d.Documented++
			} else {
				miss(i)
			}
		}
	case ".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs":
		if strings.HasSuffix(strings.ToLower(filePath), ".d.ts") {
			return d, false
		}
		for i, l := range m.code {
			if !reDocTSDecl.MatchString(l) {
				continue
			}
			d.Public++
			if prevDoc(i, func(t string) bool { return strings.HasSuffix(t, "*/") || strings.HasPrefix(t, "//") }) {
				d.Documented++
			} else {
				miss(i)
			}
		}
	case ".java", ".kt", ".kts", ".cs":
		re := reDocJavaDecl
		switch fe {
		case ".kt", ".kts":
			re = reDocKtDecl
		case ".cs":
			re = reDocCSDecl
		}
		for i, l := range m.code {
			if !re.MatchString(l) || strings.Contains(l, "private ") || strings.Contains(l, "protected ") || strings.Contains(l, "internal ") || strings.Contains(l, "override ") {
				continue
			}
			if fe == ".java" && strings.TrimSpace(l) != "" && strings.Contains(l, "=") && !strings.Contains(l, "(") {
				continue // a public field, not a method
			}
			d.Public++
			if prevDoc(i, func(t string) bool { return strings.HasSuffix(t, "*/") || strings.HasPrefix(t, "///") }) {
				d.Documented++
			} else {
				miss(i)
			}
		}
	case ".swift":
		for i, l := range m.code {
			if !reDocSwiftDecl.MatchString(l) {
				continue
			}
			d.Public++
			if prevDoc(i, func(t string) bool { return strings.HasPrefix(t, "///") || strings.HasSuffix(t, "*/") }) {
				d.Documented++
			} else {
				miss(i)
			}
		}
	case ".rs":
		for i, l := range m.code {
			if !reDocRustDecl.MatchString(l) {
				continue
			}
			d.Public++
			if prevDoc(i, func(t string) bool {
				return strings.HasPrefix(t, "///") || strings.HasPrefix(t, "//!") || strings.HasSuffix(t, "*/")
			}) {
				d.Documented++
			} else {
				miss(i)
			}
		}
	default:
		return d, false
	}
	return d, true
}
