// pydocs.go is the one model of Python documentation that Code Structure's
// 📝 Documentation coverage and review mode's "complex function without a doc"
// both read. A Python symbol is documented when its *docstring* — the first
// statement of its body, a string literal — exists; a `#` comment above the
// def is not (help(), IDEs and doc generators never see it).
//
// The reader works on the length-preserving masked source (srcmask.go), so it
// copes with what trips naive line checks: signatures that span several lines
// with keyword-only markers and defaults, decorators, async defs, one-line defs
// with their docstring after the colon, r/u prefixes, single-quoted docstrings,
// and text in any language (nothing here looks at the words, only at the quotes).
package constructs

import (
	"regexp"
	"strings"
)

// pyDoc is one documentable Python symbol and what its docstring says.
type pyDoc struct {
	kind     string // "module" | "class" | "func"
	name     string
	class    string // enclosing class of a method
	line     int    // 0-based line of the def / class statement (0 for the module)
	has      bool
	text     string // the docstring, cleaned of indentation and its quotes
	docStart int    // 0-based first and last line of the docstring literal
	docEnd   int
	params   []string // parameter names, without self / cls / bare * and /
	public   bool     // name does not start with an underscore
	nested   bool     // a def inside another function: not part of any API
	oneLiner bool     // `def f(): …` with no body of its own
}

// reDocOpen matches the opening of a docstring literal: only r/u prefixes —
// f-strings and bytes are never docstrings.
var reDocOpen = regexp.MustCompile(`^[rRuU]{0,2}("""|'''|"|')`)

// pyDocstring reads the docstring that starts at or after line `from` — the
// first statement of a body. tail, when set, is the text of a one-line def after
// its colon (`def f(): """doc"""`). ok is false when the first statement is not a
// string literal.
func pyDocstring(m maskedFile, from int, tail string) (text string, start, end int, ok bool) {
	i, first := from, strings.TrimSpace(tail)
	if first == "" {
		for ; i < len(m.code); i++ {
			if strings.TrimSpace(m.code[i]) != "" { // comments are blanked in code
				break
			}
		}
		if i >= len(m.raw) {
			return "", 0, 0, false
		}
		first = strings.TrimSpace(m.raw[i])
	}
	g := reDocOpen.FindStringSubmatchIndex(first)
	if g == nil {
		return "", 0, 0, false
	}
	quote := first[g[2]:g[3]]
	rest := first[g[3]:]
	if len(quote) == 1 { // "…" on one line (a backslash escapes the closer)
		for k := 0; k < len(rest); k++ {
			switch rest[k] {
			case '\\':
				k++
			case quote[0]:
				return cleanDoc(rest[:k]), i, i, true
			}
		}
		return "", 0, 0, false
	}
	if k := strings.Index(rest, quote); k >= 0 {
		return cleanDoc(rest[:k]), i, i, true
	}
	lines := []string{rest}
	for j := i + 1; j < len(m.raw); j++ {
		if k := strings.Index(m.raw[j], quote); k >= 0 {
			lines = append(lines, m.raw[j][:k])
			return cleanDoc(strings.Join(lines, "\n")), i, j, true
		}
		lines = append(lines, m.raw[j])
	}
	return cleanDoc(strings.Join(lines, "\n")), i, len(m.raw) - 1, true
}

// cleanDoc trims a docstring the way inspect.cleandoc does: the first line is
// stripped, the rest lose their common indentation, blank edges go.
func cleanDoc(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r", ""), "\n")
	indent := -1
	for _, l := range lines[1:] {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if n := pyIndent(l); indent < 0 || n < indent {
			indent = n
		}
	}
	for i := range lines {
		if i == 0 {
			lines[i] = strings.TrimSpace(lines[i])
		} else if indent > 0 && len(lines[i]) >= indent {
			lines[i] = lines[i][indent:]
		}
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// pyDocs reads every documentable symbol of a file: its module docstring, each
// class and each function or method, with the docstring each has (or lacks).
func pyDocs(m maskedFile) []pyDoc {
	funcs, classes := pyParse(m)
	var out []pyDoc
	mod := pyDoc{kind: "module", name: "(module)", public: true}
	if t, s, e, ok := pyDocstring(m, 0, ""); ok {
		mod.has, mod.text, mod.docStart, mod.docEnd = true, t, s, e
	}
	out = append(out, mod)
	for _, c := range classes {
		d := pyDoc{kind: "class", name: c.name, line: c.start, public: !strings.HasPrefix(c.name, "_")}
		if t, s, e, ok := pyDocstring(m, c.start+1, ""); ok {
			d.has, d.text, d.docStart, d.docEnd = true, t, s, e
		}
		out = append(out, d)
	}
	for _, f := range funcs {
		d := pyDoc{kind: "func", name: f.name, class: f.class, line: f.start, public: !strings.HasPrefix(f.name, "_"), params: pyParamNames(f.params), nested: f.enclosedDef, oneLiner: f.oneLiner}
		tail := ""
		if f.oneLiner {
			if l := m.raw[f.sigEnd]; len(l) >= 0 {
				_, _, ct := collectUntilColon(m.code, f.start, strings.Index(m.code[f.start], "("))
				if n := len(ct); n <= len(l) {
					tail = l[len(l)-n:]
				}
			}
		}
		if t, s, e, ok := pyDocstring(m, f.bodyStart, tail); ok {
			d.has, d.text, d.docStart, d.docEnd = true, t, s, e
		}
		out = append(out, d)
	}
	return out
}

// ── DocIndex: "is the declaration on this line documented?" for review mode ──

// DocIndex answers, for one source file, whether the function or class declared
// at a line carries a doc comment. Python is read with the docstring model
// above; every other language by the comment sitting directly above the
// declaration (godoc, JSDoc, KDoc/Javadoc, ///).
type DocIndex struct {
	lines []string
	py    map[int]bool // 1-based def/class line → documented (Python only)
	isPy  bool
}

// NewDocIndex reads one file's lines. path decides the language by extension.
func NewDocIndex(path string, lines []string) *DocIndex {
	d := &DocIndex{lines: lines}
	if e := ext(path); e == ".py" || e == ".pyi" {
		d.isPy, d.py = true, map[int]bool{}
		for _, s := range pyDocs(maskSource(lines, e)) {
			if s.kind != "module" {
				d.py[s.line+1] = s.has
			}
		}
	}
	return d
}

// Has reports whether the declaration at the 1-based line is documented. For
// Python a decorator line resolves to the def below it.
func (d *DocIndex) Has(line int) bool {
	if d.isPy {
		for l := line; l < line+4 && l <= len(d.lines); l++ {
			if has, ok := d.py[l]; ok {
				return has
			}
		}
		return false
	}
	return hasDocAbove(d.lines, line)
}

// hasDocAbove reports whether a comment directly precedes the declaration at
// the 1-based line, skipping annotations and attributes between them.
func hasDocAbove(lines []string, line int) bool {
	for i := line - 2; i >= 0 && i < len(lines) && i >= line-8; i-- {
		t := strings.TrimSpace(lines[i])
		switch {
		case t == "":
			return false
		case strings.HasPrefix(t, "@"), strings.HasPrefix(t, "#["), strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]"):
			continue
		}
		return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") ||
			strings.HasSuffix(t, "*/") || strings.HasPrefix(t, "--")
	}
	return false
}
