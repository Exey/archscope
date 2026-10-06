// pyparse.go is the indentation-aware reader for Python that the brace-based
// scanners can't be: it finds functions, methods and classes, their parameter
// lists and bodies, over the length-preserving masked source (srcmask.go —
// comments and string contents are already blanked, so a '#' or a ':' in a
// string can't fool it). It is what lets Code Structure, cyclomatic complexity,
// the shape limits and the Python bug-class checks work on Python at all.
package constructs

import (
	"regexp"
	"strings"
)

// pyFunc is one def / async def.
type pyFunc struct {
	name        string
	class       string // directly enclosing class ("" for plain functions and nested defs)
	async       bool
	start       int // line index of the `def`
	sigEnd      int // line index where the signature's closing `:` is
	bodyStart   int // first body line index
	end         int // last body line index (inclusive)
	indent      int
	params      string   // text between the signature's parentheses
	decorators  []string // decorator lines (stripped of '@'), nearest first
	oneLiner    bool
	enclosedDef bool // defined inside another function
}

// pyClass is one class statement.
type pyClass struct {
	name       string
	start, end int
	indent     int
	bases      string
}

var (
	rePyDef   = regexp.MustCompile(`^(async\s+)?def\s+([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*\(`)
	rePyClass = regexp.MustCompile(`^class\s+([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(\(|:)`)
	rePyBlock = regexp.MustCompile(`^(?:async\s+)?(?:if|elif|else|for|while|try|except|finally|with|match|case)\b[^\n]*:\s*$|^(?:else|try|finally)\s*:\s*$`)
)

// pyIndent is the indentation width of a line (tabs count as 8, like Python 2's rule).
func pyIndent(line string) int {
	w := 0
	for _, c := range line {
		switch c {
		case ' ':
			w++
		case '\t':
			w += 8 - w%8
		default:
			return w
		}
	}
	return w
}

// pyLogicalStarts marks the lines that begin a logical statement (not a
// continuation inside brackets or after a backslash) and skips blank lines.
func pyLogicalStarts(code []string) []bool {
	starts := make([]bool, len(code))
	depth, cont := 0, false
	for i, l := range code {
		if strings.TrimSpace(l) != "" && depth == 0 && !cont {
			starts[i] = true
		}
		for k := 0; k < len(l); k++ {
			switch l[k] {
			case '(', '[', '{':
				depth++
			case ')', ']', '}':
				if depth > 0 {
					depth--
				}
			}
		}
		cont = strings.HasSuffix(strings.TrimRight(l, " \t\r"), "\\")
	}
	return starts
}

// pyParse finds every function and class in the file.
func pyParse(m maskedFile) (funcs []pyFunc, classes []pyClass) {
	code := m.code
	starts := pyLogicalStarts(code)
	type block struct {
		kind   string // "def" or "class"
		indent int
		name   string
		fi, ci int // index into funcs / classes
	}
	var stack []block
	var decos []string
	for i := 0; i < len(code); i++ {
		if !starts[i] {
			continue
		}
		line := code[i]
		ind := pyIndent(line)
		t := strings.TrimSpace(line)
		for len(stack) > 0 && ind <= stack[len(stack)-1].indent {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			last := lastNonBlank(code, i-1)
			if top.kind == "def" {
				funcs[top.fi].end = last
			} else {
				classes[top.ci].end = last
			}
		}
		if strings.HasPrefix(t, "@") {
			decos = append(decos, strings.TrimPrefix(t, "@"))
			continue
		}
		if g := rePyDef.FindStringSubmatchIndex(t); g != nil {
			f := pyFunc{name: t[g[4]:g[5]], async: g[2] >= 0, start: i, indent: ind, decorators: reverseStrings(decos)}
			decos = nil
			// the signature runs from the opening paren to the ':' that ends it
			open := strings.Index(line, "(")
			sig, endLine, tail := collectUntilColon(code, i, open)
			f.params, f.sigEnd = sig, endLine
			f.bodyStart = f.sigEnd + 1
			if strings.TrimSpace(tail) != "" {
				f.oneLiner, f.bodyStart, f.end = true, f.sigEnd, f.sigEnd
			}
			for j := len(stack) - 1; j >= 0; j-- {
				if stack[j].kind == "def" {
					f.enclosedDef = true
					break
				}
			}
			if n := len(stack); n > 0 && stack[n-1].kind == "class" {
				f.class = stack[n-1].name
			}
			funcs = append(funcs, f)
			if !f.oneLiner {
				stack = append(stack, block{kind: "def", indent: ind, name: f.name, fi: len(funcs) - 1})
			}
			continue
		}
		if g := rePyClass.FindStringSubmatchIndex(t); g != nil {
			c := pyClass{name: t[g[2]:g[3]], start: i, indent: ind}
			decos = nil
			if t[g[4]:g[5]] == "(" {
				open := strings.Index(line, "(")
				c.bases, _, _ = collectUntilColon(code, i, open)
			}
			classes = append(classes, c)
			stack = append(stack, block{kind: "class", indent: ind, name: c.name, ci: len(classes) - 1})
			continue
		}
		decos = nil
	}
	last := lastNonBlank(code, len(code)-1)
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if top.kind == "def" {
			funcs[top.fi].end = last
		} else {
			classes[top.ci].end = last
		}
	}
	return funcs, classes
}

func lastNonBlank(code []string, from int) int {
	for i := from; i >= 0; i-- {
		if i < len(code) && strings.TrimSpace(code[i]) != "" {
			return i
		}
	}
	return 0
}

func reverseStrings(s []string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[len(s)-1-i] = v
	}
	return out
}

// collectUntilColon returns the text inside the parentheses opened at
// (line, col), the index of the line holding the signature's closing ':', and
// whatever follows that colon on its line (non-empty for `def f(): return 1`).
func collectUntilColon(code []string, line, col int) (string, int, string) {
	var sb strings.Builder
	depth := 0
	for j := line; j < len(code) && j < line+60; j++ {
		l := code[j]
		from := 0
		if j == line {
			from = col
		}
		for k := from; k < len(l); k++ {
			c := l[k]
			switch c {
			case '(', '[', '{':
				depth++
				if depth == 1 && c == '(' && j == line && k == col {
					continue
				}
			case ')', ']', '}':
				depth--
				if depth == 0 {
					// params end here; the colon follows on this or a later line
					for e := j; e < len(code) && e < j+5; e++ {
						rest := code[e]
						if e == j {
							rest = l[k+1:]
						}
						if ci := topColon(rest); ci >= 0 {
							return sb.String(), e, rest[ci+1:]
						}
					}
					return sb.String(), j, ""
				}
			}
			if depth >= 1 {
				sb.WriteByte(c)
			}
		}
		sb.WriteByte(' ')
	}
	return sb.String(), line, ""
}

// topColon is the index of the ':' ending `) -> T:` — a colon outside any
// brackets (return types like `Dict[str, int]` hide theirs) — or -1.
func topColon(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ':':
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// pyParamCount counts a def's parameters, excluding self/cls and the bare `*` / `/` separators.
func pyParamCount(params string) int {
	n := 0
	for _, p := range splitTopLevel(params, params, ',') {
		p = strings.TrimSpace(p)
		if p == "" || p == "*" || p == "/" || p == "self" || p == "cls" {
			continue
		}
		if i := indexTop(p, ':'); i >= 0 {
			if name := strings.TrimSpace(p[:i]); name == "self" || name == "cls" {
				continue
			}
		}
		if i := indexTop(p, '='); i >= 0 && (strings.TrimSpace(p[:i]) == "self" || strings.TrimSpace(p[:i]) == "cls") {
			continue
		}
		n++
	}
	return n
}

// pyNestDepth is the deepest block nesting inside the function body: a flat
// body is 0, a statement inside one `if` is 1, and so on. Nested def/class
// statements count as blocks, like closures do for brace languages.
func pyNestDepth(code []string, starts []bool, f pyFunc) int {
	var stack []int // indents of open block statements
	maxD := 0
	for i := f.bodyStart; i <= f.end && i < len(code); i++ {
		if !starts[i] {
			continue
		}
		ind := pyIndent(code[i])
		for len(stack) > 0 && ind <= stack[len(stack)-1] {
			stack = stack[:len(stack)-1]
		}
		if len(stack) > maxD {
			maxD = len(stack)
		}
		t := strings.TrimSpace(code[i])
		if rePyBlock.MatchString(t) || (strings.HasSuffix(t, ":") && (strings.HasPrefix(t, "def ") || strings.HasPrefix(t, "class ") || strings.HasPrefix(t, "async def "))) {
			stack = append(stack, ind)
		}
	}
	return maxD
}
