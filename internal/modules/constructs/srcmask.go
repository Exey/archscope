// srcmask.go gives the structural checks (duplicate branches/cases, the Go
// bug-class checks) a *length-preserving* view of a source file. readSource's
// stripped lines drop string contents and comments, so offsets no longer line
// up with the original and "if a { f("x") } else { f("y") }" looks like two
// identical bodies. maskSource instead overwrites comments and string contents
// with spaces in place — braces and keywords stay findable, every offset stays
// valid, and the unmasked text is still there to compare bodies by.
package constructs

import (
	"regexp"
	"sort"
	"strings"
)

// maskedFile is one source file in three aligned views (same line count, same
// length per line): raw as read, code (comments AND string contents blanked)
// and text (only comments blanked, so literals can still be compared).
type maskedFile struct {
	raw, code, text []string
}

type tmplState struct {
	expr  bool
	brace int
}

var reRustChar = regexp.MustCompile(`^'(?:\\.[^']*|[^'\\])'`)

// maskSource builds the three views. Handles // and /* */ comments, "…" '…'
// strings, Go/JS backtick strings and """…""" text blocks across lines. It is
// for brace languages; Python-style # comments are not handled.
func maskSource(raw []string, fileExt string) maskedFile {
	m := maskedFile{raw: raw, code: make([]string, len(raw)), text: make([]string, len(raw))}
	rust := fileExt == ".rs"
	backtick := fileExt == ".go" || fileExt == ".js" || fileExt == ".jsx" || fileExt == ".ts" || fileExt == ".tsx" || fileExt == ".mjs" || fileExt == ".cjs" || fileExt == ".mts" || fileExt == ".cts"
	jsTemplate := fileExt != ".go" // ${…} interpolation exists in JS/TS templates, not Go raw strings
	python := fileExt == ".py" || fileExt == ".pyi"
	triple := python || fileExt == ".java" || fileExt == ".kt" || fileExt == ".kts" || fileExt == ".swift" || fileExt == ".cs"
	inBlock := false
	ml := "" // closer of a """ string spanning lines
	// tstack tracks JS/Go template literals, which nest: `a ${ cond ? `b` : `c` } d`.
	// Each entry is either template text or a ${…} expression with its brace depth.
	var tstack []tmplState
	for li, line := range raw {
		c, t := []byte(line), []byte(line)
		blank := func(buf []byte, from, to int) {
			if to > len(buf) {
				to = len(buf)
			}
			for k := from; k < to; k++ {
				buf[k] = ' '
			}
		}
		i := 0
		for i < len(line) {
			if inBlock {
				j := strings.Index(line[i:], "*/")
				if j < 0 {
					blank(c, i, len(line))
					blank(t, i, len(line))
					i = len(line)
					break
				}
				blank(c, i, i+j+2)
				blank(t, i, i+j+2)
				i += j + 2
				inBlock = false
				continue
			}
			if ml != "" {
				j := strings.Index(line[i:], ml)
				if j < 0 {
					blank(c, i, len(line))
					i = len(line)
					break
				}
				blank(c, i, i+j) // keep the closing delimiter
				i += j + len(ml)
				ml = ""
				continue
			}
			ch := line[i]
			if n := len(tstack); n > 0 {
				top := &tstack[n-1]
				if !top.expr { // template text
					switch {
					case ch == '\\' && i+1 < len(line):
						blank(c, i, i+2)
						i += 2
					case ch == '`':
						if n > 1 { // a nested closer: hide it so only the outermost delimiters survive
							blank(c, i, i+1)
						}
						tstack = tstack[:n-1]
						i++
					case jsTemplate && ch == '$' && i+1 < len(line) && line[i+1] == '{':
						blank(c, i, i+2)
						tstack = append(tstack, tmplState{expr: true, brace: 1})
						i += 2
					default:
						blank(c, i, i+1)
						i++
					}
					continue
				}
				// inside ${ … }: code, kept readable only in the text view
				switch {
				case ch == '`':
					blank(c, i, i+1)
					tstack = append(tstack, tmplState{})
					i++
				case ch == '"' || ch == '\'':
					j := i + 1
					for j < len(line) && line[j] != ch {
						if line[j] == '\\' {
							j++
						}
						j++
					}
					blank(c, i, j+1)
					i = j + 1
				case ch == '{':
					top.brace++
					blank(c, i, i+1)
					i++
				case ch == '}':
					top.brace--
					blank(c, i, i+1)
					if top.brace == 0 {
						tstack = tstack[:n-1]
					}
					i++
				default:
					blank(c, i, i+1)
					i++
				}
				continue
			}
			switch {
			case !python && ch == '/' && i+1 < len(line) && line[i+1] == '/':
				blank(c, i, len(line))
				blank(t, i, len(line))
				i = len(line)
			case !python && ch == '/' && i+1 < len(line) && line[i+1] == '*':
				inBlock = true
				blank(c, i, i+2)
				blank(t, i, i+2)
				i += 2
			case python && ch == '#':
				blank(c, i, len(line))
				blank(t, i, len(line))
				i = len(line)
			case python && (ch == '"' || ch == '\'') && strings.HasPrefix(line[i:], strings.Repeat(string(ch), 3)):
				ml = strings.Repeat(string(ch), 3)
				i += 3
			case triple && ch == '"' && strings.HasPrefix(line[i:], `"""`):
				ml = `"""`
				i += 3
			case backtick && ch == '`':
				tstack = append(tstack, tmplState{})
				i++
			case ch == '"' || ch == '\'':
				if ch == '\'' && rust && !reRustChar.MatchString(line[i:]) {
					i++ // a lifetime, not a char literal
					continue
				}
				j := i + 1
				for j < len(line) && line[j] != ch {
					if line[j] == '\\' {
						j++
					}
					j++
				}
				blank(c, i+1, j)
				i = j + 1
			default:
				i++
			}
		}
		m.code[li], m.text[li] = string(c), string(t)
	}
	return m
}

// flat is the joined code/text with a line index, so a regexp or brace walk can
// work on whole-file offsets and map them back to a 1-based line.
type flatSrc struct {
	code, text string
	starts     []int
	raw        []string // original lines, for checks that need the comments
}

func (m maskedFile) flat() flatSrc {
	f := flatSrc{code: strings.Join(m.code, "\n"), text: strings.Join(m.text, "\n"), raw: m.raw}
	f.starts = make([]int, len(m.code))
	off := 0
	for i, l := range m.code {
		f.starts[i] = off
		off += len(l) + 1
	}
	return f
}

// line returns the 0-based line index of a byte offset.
func (f flatSrc) line(off int) int {
	return sort.Search(len(f.starts), func(i int) bool { return f.starts[i] > off }) - 1
}

// matchClose returns the offset of the bracket closing the one at open
// (code[open] must be one of ({[), or -1.
func (f flatSrc) matchClose(open int) int {
	var o, c byte
	switch f.code[open] {
	case '{':
		o, c = '{', '}'
	case '(':
		o, c = '(', ')'
	default:
		o, c = '[', ']'
	}
	depth := 0
	for i := open; i < len(f.code); i++ {
		switch f.code[i] {
		case o:
			depth++
		case c:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// skipSpace returns the first offset ≥ i that is not whitespace.
func (f flatSrc) skipSpace(i int) int {
	for i < len(f.code) && (f.code[i] == ' ' || f.code[i] == '\t' || f.code[i] == '\n' || f.code[i] == '\r') {
		i++
	}
	return i
}

// wordAt reports whether the identifier word starts exactly at i.
func (f flatSrc) wordAt(i int, w string) bool {
	if !strings.HasPrefix(f.code[i:], w) {
		return false
	}
	end := i + len(w)
	return end >= len(f.code) || !isIdentByte(f.code[end])
}

// bodyStart finds the '{' that opens the block of a statement keyword (if /
// switch / for) whose keyword ends at from. Go, Swift and Rust conditions are
// bare (first '{' at bracket depth 0); every other brace language parenthesises
// them. Returns -1 when the statement has no braced block (one-liners).
func (f flatSrc) bodyStart(from int, bare bool) int {
	i := f.skipSpace(from)
	if i >= len(f.code) {
		return -1
	}
	if !bare {
		if f.code[i] != '(' {
			return -1
		}
		cl := f.matchClose(i)
		if cl < 0 {
			return -1
		}
		i = f.skipSpace(cl + 1)
		if i < len(f.code) && f.code[i] == '{' {
			return i
		}
		return -1
	}
	depth := 0
	for ; i < len(f.code); i++ {
		switch f.code[i] {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		case '{':
			if depth == 0 {
				return i
			}
		case '}':
			if depth == 0 {
				return -1
			}
		}
	}
	return -1
}

// bareConditions reports languages whose if/switch conditions aren't wrapped
// in parentheses.
func bareConditions(fileExt string) bool {
	return fileExt == ".go" || fileExt == ".swift" || fileExt == ".rs"
}

// squash removes all whitespace so two bodies compare equal regardless of layout.
func squash(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// rawContains reports whether any original line in [from,to] (0-based, clamped)
// contains substr — used to honour `eslint-disable` style comments.
func (f flatSrc) rawContains(from, to int, substr string) bool {
	if from < 0 {
		from = 0
	}
	for i := from; i <= to && i < len(f.raw); i++ {
		if strings.Contains(f.raw[i], substr) {
			return true
		}
	}
	return false
}
