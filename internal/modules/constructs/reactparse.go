// reactparse.go is the small lexical React reader shared by the hooks/state and
// component checks (a port of the rule set in ~/react-code-audit): it finds
// function components and custom hooks, reads their props, collects hook calls
// and scans JSX tags — all over the length-preserving masked source
// (srcmask.go), with no AST. Approximate by design: it recognises the common
// shapes (function declarations, `const X = (...) =>`, memo/forwardRef wrappers)
// and stays silent on anything it can't read.
package constructs

import (
	"regexp"
	"strings"
)

// reactFunc is one component or custom hook.
type reactFunc struct {
	name        string
	hook        bool // custom hook (useXxx) rather than a component
	declOff     int  // offset of the declaration start
	open, close int  // body range (braces, parenthesised or bare expression)
	params      string
	props       []string // destructured prop local names
	propsIdent  string   // `props` when the first parameter is a plain identifier
}

var (
	reReactFuncDecl = regexp.MustCompile(`\bfunction\s+([A-Za-z_$][\w$]*)\s*(?:<[^>(]*>)?\s*\(`)
	reConstFunc     = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*`)
	reWrapper       = regexp.MustCompile(`^(?:React\.)?(?:memo|forwardRef|observer)\s*(?:<[^>(]*>)?\s*\(\s*`)
	reJSXOpen       = regexp.MustCompile(`(?:^|[^\w$)\]])<(?:[A-Za-z][\w.:-]*[\s/>]|>)`)
	reHookName      = regexp.MustCompile(`^use[A-Z]`)
	reCompName      = regexp.MustCompile(`^[A-Z]`)
	reJSXTagName    = regexp.MustCompile(`^[A-Za-z][\w.:-]*`)
)

// isJSFamily reports the JS/TS extensions the React and dead-code checks run on.
func isJSFamily(fileExt string) bool { return csStringLang(fileExt) == csStrJS }

// findReactFuncs returns every component and custom hook in the file.
func findReactFuncs(f flatSrc) []reactFunc {
	var out []reactFunc
	seen := map[int]bool{}
	add := func(name string, declOff, paramOpen int) {
		if !reCompName.MatchString(name) && !reHookName.MatchString(name) {
			return
		}
		pc := f.matchClose(paramOpen)
		if pc < 0 {
			return
		}
		open, close := f.bodyAfterParams(pc + 1)
		if open < 0 || seen[open] {
			return
		}
		fn := reactFunc{name: name, hook: reHookName.MatchString(name), declOff: declOff, open: open, close: close, params: f.code[paramOpen+1 : pc]}
		if !fn.hook && !reJSXOpen.MatchString(f.code[open:close+1]) {
			return // not a component: no JSX in the body
		}
		seen[open] = true
		fn.props, fn.propsIdent = readProps(fn.params)
		out = append(out, fn)
	}
	for _, m := range reReactFuncDecl.FindAllStringSubmatchIndex(f.code, -1) {
		add(f.code[m[2]:m[3]], m[0], m[1]-1)
	}
	for _, m := range reConstFunc.FindAllStringSubmatchIndex(f.code, -1) {
		name := f.code[m[2]:m[3]]
		if !reCompName.MatchString(name) && !reHookName.MatchString(name) {
			continue
		}
		i := m[1]
		for { // unwrap memo( / forwardRef( / observer(
			w := reWrapper.FindStringIndex(f.code[i:])
			if w == nil {
				break
			}
			i += w[1]
		}
		rest := f.code[i:]
		rest = strings.TrimPrefix(rest, "async ")
		i = len(f.code) - len(rest)
		switch {
		case strings.HasPrefix(rest, "function"):
			if p := strings.IndexByte(rest, '('); p >= 0 && p < 80 {
				add(name, m[0], i+p)
			}
		case strings.HasPrefix(rest, "<"): // generic arrow `<T,>(props) =>`
			if g := f.matchAngle(i); g > 0 {
				if j := f.skipSpace(g + 1); j < len(f.code) && f.code[j] == '(' {
					add(name, m[0], j)
				}
			}
		case strings.HasPrefix(rest, "("):
			add(name, m[0], i)
		default: // single identifier parameter `props => …`
			if id := reJSXTagName.FindString(rest); id != "" {
				after := f.skipSpace(i + len(id))
				if strings.HasPrefix(f.code[after:], "=>") {
					// synthesise a parameter list from the identifier
					body, end := f.arrowBody(after + 2)
					if body >= 0 && !seen[body] && reJSXOpen.MatchString(f.code[body:end+1]) && reCompName.MatchString(name) {
						seen[body] = true
						out = append(out, reactFunc{name: name, declOff: m[0], open: body, close: end, params: id, propsIdent: id})
					}
				}
			}
		}
	}
	return out
}

// bodyAfterParams finds the function body after a parameter list closed at
// from-1: an optional `: ReturnType`, then either `{ … }` (function) or `=>`
// followed by a block / parenthesised / bare-expression body.
func (f flatSrc) bodyAfterParams(from int) (open, close int) {
	i := from
	for i < len(f.code) && i < from+300 {
		switch f.code[i] {
		case '{':
			// `function F() {` or a return-type object literal; take it as the body
			if cl := f.matchClose(i); cl > 0 {
				return i, cl
			}
			return -1, -1
		case ';', '}':
			return -1, -1
		case '=':
			if i+1 < len(f.code) && f.code[i+1] == '>' {
				return f.arrowBody(i + 2)
			}
		}
		i++
	}
	return -1, -1
}

// arrowBody returns the body range after `=>` at from.
func (f flatSrc) arrowBody(from int) (open, close int) {
	i := f.skipSpace(from)
	if i >= len(f.code) {
		return -1, -1
	}
	if f.code[i] == '{' || f.code[i] == '(' {
		if cl := f.matchClose(i); cl > 0 {
			return i, cl
		}
		return -1, -1
	}
	end := stmtEnd(f.code, i)
	return i, end - 1
}

// matchAngle returns the offset of the '>' closing the '<' at open, or -1.
func (f flatSrc) matchAngle(open int) int {
	depth := 0
	for i := open; i < len(f.code) && i < open+200; i++ {
		switch f.code[i] {
		case '<':
			depth++
		case '>':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// readProps reads the destructured prop names (and/or the props identifier)
// from a component's parameter list.
func readProps(params string) (names []string, ident string) {
	p := strings.TrimSpace(params)
	if p == "" {
		return nil, ""
	}
	if p[0] != '{' {
		id := reJSXTagName.FindString(p)
		return nil, id
	}
	depth, end := 0, -1
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '{':
			depth++
		case '}':
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
		return nil, ""
	}
	for _, e := range splitTopLevel(p[1:end], p[1:end], ',') {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		e = strings.TrimPrefix(e, "...")
		if i := indexTop(e, '='); i >= 0 {
			e = strings.TrimSpace(e[:i])
		}
		if i := indexTop(e, ':'); i >= 0 {
			e = strings.TrimSpace(e[i+1:]) // `a: b` binds b
		}
		e = strings.TrimSuffix(e, "?")
		if id := reJSXTagName.FindString(e); id != "" && id == e {
			names = append(names, id)
		}
	}
	return names, ""
}

// indexTop is the first index of c outside any bracket pair.
func indexTop(s string, c byte) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{', '<':
			depth++
		case ')', ']', '}', '>':
			depth--
		default:
			if s[i] == c && depth == 0 {
				return i
			}
		}
	}
	return -1
}

// stmtEnd returns the offset just past the statement that starts at from: the
// first ';' at bracket depth 0, a line break at depth 0 that is not followed by a
// continuation (`.method()`, `? :`, `&&`, `+` …), or the closing bracket of the
// enclosing block.
func stmtEnd(code string, from int) int {
	depth, inTemplate := 0, false
	for i := from; i < len(code); i++ {
		if code[i] == '`' { // template literal contents are masked; a line break inside one isn't a statement end
			inTemplate = !inTemplate
			continue
		}
		if inTemplate {
			continue
		}
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return i
			}
			depth--
		case ';':
			if depth == 0 && !isHTMLEntityEnd(code, i) {
				return i + 1
			}
		case '\n':
			if depth != 0 {
				continue
			}
			j := i + 1
			for j < len(code) && (code[j] == ' ' || code[j] == '\t' || code[j] == '\n' || code[j] == '\r') {
				j++
			}
			if j >= len(code) {
				return i
			}
			if strings.IndexByte(".?:&|+*/=<>,%^", code[j]) >= 0 {
				continue
			}
			// a line that ends in an operator or `=>` continues on the next line
			k := i - 1
			for k > from && (code[k] == ' ' || code[k] == '\t' || code[k] == '\r') {
				k--
			}
			if k > from && strings.IndexByte("=>+-*/&|?:,%^<", code[k]) >= 0 {
				continue
			}
			return i
		}
	}
	return len(code)
}

// jsxTag is one tag found by scanJSX.
type jsxTag struct {
	name  string
	off   int
	attrs string
	kind  int // 0 open, 1 close, 2 self-closing
	depth int // nesting depth of the element (root = 1)
}

// scanJSX lists the JSX tags in code[from:to] with their nesting depth.
func scanJSX(code string, from, to int) []jsxTag {
	var tags []jsxTag
	depth := 0
	for i := from; i < to; i++ {
		if code[i] != '<' || i+1 >= len(code) {
			continue
		}
		if code[i+1] == '/' { // closing tag
			j := i + 2
			for j < len(code) && j < i+80 && code[j] != '>' && code[j] != '\n' {
				j++
			}
			if j < len(code) && code[j] == '>' {
				if depth > 0 {
					depth--
				}
				tags = append(tags, jsxTag{name: strings.TrimSpace(code[i+2 : j]), off: i, kind: 1, depth: depth + 1})
				i = j
			}
			continue
		}
		if i > 0 {
			if p := code[i-1]; isIdentByte(p) || p == ')' || p == ']' || p == '$' {
				continue // generic argument or comparison, not a tag
			}
		}
		nm := reJSXTagName.FindString(code[i+1:])
		if nm == "" && code[i+1] != '>' {
			continue
		}
		// find the end of the tag, skipping {…} attribute expressions
		j, brace := i+1+len(nm), 0
		end, self := -1, false
		for ; j < len(code) && j < i+4000; j++ {
			switch code[j] {
			case '{':
				brace++
			case '}':
				brace--
			case '>':
				if brace == 0 {
					end = j
					self = code[j-1] == '/'
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			continue
		}
		attrStart := i + 1 + len(nm)
		attrEnd := end
		if self {
			attrEnd--
		}
		t := jsxTag{name: nm, off: i, attrs: code[attrStart:attrEnd]}
		if self {
			t.kind, t.depth = 2, depth+1
		} else {
			depth++
			t.kind, t.depth = 0, depth
		}
		tags = append(tags, t)
		i = end
	}
	return tags
}

// hookCall is one useEffect / useLayoutEffect / useCallback / useMemo call.
type hookCall struct {
	name       string
	off        int
	end        int    // offset of the call's closing paren
	cbCode     string // callback source (masked)
	cbText     string // callback source (strings intact)
	hasDeps    bool
	deps       []string // dependency array entries (nil when deps isn't an array literal)
	depsLit    bool     // deps is an array literal
	argCount   int
	depsSpread bool
}

var reHookCall = regexp.MustCompile(`\b(useEffect|useLayoutEffect|useInsertionEffect|useCallback|useMemo|useImperativeHandle)\s*(?:<[^>(]*>)?\s*\(`)

// hookCalls lists the memo/effect hook calls inside code[from:to].
func hookCalls(f flatSrc, from, to int) []hookCall {
	var out []hookCall
	for _, m := range reHookCall.FindAllStringSubmatchIndex(f.code[from:to], -1) {
		open := from + m[1] - 1
		cl := f.matchClose(open)
		if cl < 0 || cl > to {
			continue
		}
		code, text := f.code[open+1:cl], f.text[open+1:cl]
		argsC := splitTopLevel(code, code, ',')
		argsT := splitTopLevel(code, text, ',')
		h := hookCall{name: f.code[from+m[2] : from+m[3]], off: from + m[0], end: cl, argCount: len(argsC)}
		if strings.TrimSpace(argsC[len(argsC)-1]) == "" { // trailing comma
			h.argCount--
			argsC, argsT = argsC[:len(argsC)-1], argsT[:len(argsT)-1]
		}
		if len(argsC) == 0 {
			continue
		}
		cbIdx, depIdx := 0, 1
		if h.name == "useImperativeHandle" {
			cbIdx, depIdx = 1, 2
		}
		if len(argsC) <= cbIdx {
			continue
		}
		h.cbCode, h.cbText = argsC[cbIdx], argsT[cbIdx]
		if len(argsC) > depIdx {
			h.hasDeps = true
			d := strings.TrimSpace(argsC[depIdx])
			if strings.HasPrefix(d, "[") && strings.HasSuffix(d, "]") {
				h.depsLit = true
				inner := d[1 : len(d)-1]
				for _, e := range splitTopLevel(inner, inner, ',') {
					if e = strings.TrimSpace(e); e != "" {
						if strings.HasPrefix(e, "...") {
							h.depsSpread = true
						}
						h.deps = append(h.deps, e)
					}
				}
			}
		}
		out = append(out, h)
	}
	return out
}

// isHTMLEntityEnd reports a ';' that ends an HTML entity (`&nbsp;`, `&#160;`)
// sitting in JSX text rather than a statement terminator.
func isHTMLEntityEnd(code string, semi int) bool {
	for k := semi - 1; k >= 0 && semi-k <= 10; k-- {
		c := code[k]
		if c == '&' {
			return k < semi-1
		}
		if !(isIdentByte(c) || c == '#') {
			return false
		}
	}
	return false
}
