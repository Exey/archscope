package openapi

import (
	"fmt"
	"strings"
)

// Parse reads a YAML or JSON document. It supports what OpenAPI documents use:
// block mappings and sequences, flow collections (also multi-line, which is all
// of JSON), quoted/plain scalars, block scalars (| and >), comments, anchors and
// tags (ignored; aliases read as null). It is not a general YAML parser.
func Parse(src string) (root *Node, err error) {
	defer func() {
		if r := recover(); r != nil {
			root, err = nil, fmt.Errorf("openapi: %v", r)
		}
	}()
	src = strings.TrimPrefix(src, "\ufeff")
	trim := strings.TrimSpace(src)
	if strings.HasPrefix(trim, "{") || strings.HasPrefix(trim, "[") {
		p := &flowParser{s: src, line: 1}
		p.skipWS()
		return p.value(), nil
	}
	return parseYAML(src), nil
}

type yline struct {
	indent int
	text   string // content without indent or comment, right-trimmed
	no     int    // 1-based line number
	raw    string // original line, for block scalars
}

func parseYAML(src string) *Node {
	var lines []yline
	for i, raw := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		t := stripComment(raw)
		if strings.TrimSpace(t) == "" {
			lines = append(lines, yline{indent: -1, no: i + 1, raw: raw})
			continue
		}
		ind := len(t) - len(strings.TrimLeft(t, " \t"))
		text := strings.TrimSpace(t)
		if text == "---" || strings.HasPrefix(text, "--- ") {
			if len(lines) > 0 && hasContent(lines) {
				break // only the first document
			}
			continue
		}
		if text == "..." {
			break
		}
		lines = append(lines, yline{indent: ind, text: text, no: i + 1, raw: raw})
	}
	p := &yamlParser{lines: lines}
	p.skipBlank()
	if p.i >= len(p.lines) {
		return &Node{Kind: Null, Line: 1}
	}
	return p.block(p.lines[p.i].indent)
}

func hasContent(ls []yline) bool {
	for _, l := range ls {
		if l.indent >= 0 {
			return true
		}
	}
	return false
}

// stripComment removes a trailing `# comment` that is outside quotes.
func stripComment(s string) string {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if inD {
				i++
			}
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case '#':
			if !inS && !inD && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
				return strings.TrimRight(s[:i], " \t")
			}
		}
	}
	return strings.TrimRight(s, " \t")
}

type yamlParser struct {
	lines []yline
	i     int
}

func (p *yamlParser) skipBlank() {
	for p.i < len(p.lines) && p.lines[p.i].indent < 0 {
		p.i++
	}
}

// block parses the node whose first line sits at the given indent.
func (p *yamlParser) block(indent int) *Node {
	p.skipBlank()
	if p.i >= len(p.lines) {
		return &Node{Kind: Null}
	}
	l := p.lines[p.i]
	switch {
	case l.text == "-" || strings.HasPrefix(l.text, "- "):
		return p.sequence(l.indent)
	case isKeyLine(l.text):
		return p.mapping(l.indent)
	default:
		p.i++
		return scalarNode(l.text, l.no)
	}
}

func (p *yamlParser) sequence(indent int) *Node {
	n := &Node{Kind: Seq, Line: p.lines[p.i].no}
	for {
		p.skipBlank()
		if p.i >= len(p.lines) || p.lines[p.i].indent != indent {
			break
		}
		l := p.lines[p.i]
		if !(l.text == "-" || strings.HasPrefix(l.text, "- ")) {
			break
		}
		rest := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
		if rest == "" {
			p.i++
			p.skipBlank()
			if p.i < len(p.lines) && p.lines[p.i].indent > indent {
				n.Vals = append(n.Vals, p.block(p.lines[p.i].indent))
			} else {
				n.Vals = append(n.Vals, &Node{Kind: Null, Line: l.no})
			}
			continue
		}
		// `- key: v` / `- - x`: the item content starts at the column after "- "
		col := indent + (len(l.text) - len(strings.TrimLeft(strings.TrimPrefix(l.text, "-"), " ")))
		p.lines[p.i] = yline{indent: col, text: rest, no: l.no, raw: l.raw}
		switch {
		case rest == "-" || strings.HasPrefix(rest, "- "):
			n.Vals = append(n.Vals, p.sequence(col))
		case isKeyLine(rest):
			n.Vals = append(n.Vals, p.mapping(col))
		default:
			p.i++
			n.Vals = append(n.Vals, p.inlineValue(rest, l.no, indent))
		}
	}
	return n
}

func (p *yamlParser) mapping(indent int) *Node {
	n := &Node{Kind: Map, Line: p.lines[p.i].no}
	for {
		p.skipBlank()
		if p.i >= len(p.lines) || p.lines[p.i].indent != indent || !isKeyLine(p.lines[p.i].text) {
			break
		}
		l := p.lines[p.i]
		key, rest := splitKey(l.text)
		p.i++
		var val *Node
		switch {
		case rest == "" || strings.HasPrefix(rest, "&") && !strings.Contains(strings.TrimSpace(rest[1:]), " ") || strings.HasPrefix(rest, "!!") && !strings.Contains(rest, " "):
			p.skipBlank()
			switch {
			case p.i < len(p.lines) && p.lines[p.i].indent > indent:
				val = p.block(p.lines[p.i].indent)
			case p.i < len(p.lines) && p.lines[p.i].indent == indent && (p.lines[p.i].text == "-" || strings.HasPrefix(p.lines[p.i].text, "- ")):
				val = p.sequence(indent) // `key:` followed by an un-indented sequence
			default:
				val = &Node{Kind: Null, Line: l.no}
			}
		default:
			val = p.inlineValue(rest, l.no, indent)
		}
		n.setPair(key, val, l.no)
	}
	return n
}

// inlineValue handles what follows `key:` or `- `: block scalars, flow
// collections, quoted/plain scalars (with plain-scalar continuation lines).
func (p *yamlParser) inlineValue(rest string, no, parentIndent int) *Node {
	rest = strings.TrimSpace(rest)
	if i := strings.IndexByte(rest, ' '); strings.HasPrefix(rest, "&") && i > 0 { // anchor
		rest = strings.TrimSpace(rest[i:])
	}
	if strings.HasPrefix(rest, "!") {
		if i := strings.IndexByte(rest, ' '); i > 0 {
			rest = strings.TrimSpace(rest[i:])
		}
	}
	switch {
	case strings.HasPrefix(rest, "|") || strings.HasPrefix(rest, ">"):
		return p.blockScalar(rest, no, parentIndent)
	case strings.HasPrefix(rest, "*"):
		return &Node{Kind: Null, Line: no}
	case strings.HasPrefix(rest, "[") || strings.HasPrefix(rest, "{"):
		text := rest
		for !balanced(text) && p.i < len(p.lines) {
			if p.lines[p.i].indent >= 0 {
				text += "\n" + p.lines[p.i].text
			}
			p.i++
		}
		fp := &flowParser{s: text, line: no}
		return fp.value()
	}
	n := scalarNode(rest, no)
	if n.Quoted && !closedQuote(rest) {
		for p.i < len(p.lines) && !closedQuote(rest) {
			rest += " " + strings.TrimSpace(p.lines[p.i].text)
			p.i++
		}
		return scalarNode(rest, no)
	}
	if !n.Quoted {
		// plain scalar continued on more-indented lines
		for p.i < len(p.lines) {
			nl := p.lines[p.i]
			if nl.indent < 0 {
				p.i++
				continue
			}
			if nl.indent <= parentIndent || isKeyLine(nl.text) || strings.HasPrefix(nl.text, "- ") {
				break
			}
			rest += " " + nl.text
			p.i++
		}
		return scalarNode(rest, no)
	}
	return n
}

func (p *yamlParser) blockScalar(head string, no, parentIndent int) *Node {
	var parts []string
	blockIndent := -1
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent < 0 {
			parts = append(parts, "")
			p.i++
			continue
		}
		if l.indent <= parentIndent {
			break
		}
		if blockIndent < 0 {
			blockIndent = l.indent
		}
		raw := strings.TrimRight(l.raw, " \t\r")
		if len(raw) >= blockIndent {
			raw = raw[blockIndent:]
		}
		parts = append(parts, raw)
		p.i++
	}
	sep := "\n"
	if strings.HasPrefix(head, ">") {
		sep = " "
	}
	return &Node{Kind: Scalar, Value: strings.TrimRight(strings.Join(parts, sep), "\n "), Line: no, Quoted: true}
}

// isKeyLine reports `key: …` / `key:` (plain or quoted key).
func isKeyLine(t string) bool {
	_, _, ok := cutKey(t)
	return ok
}

func splitKey(t string) (key, rest string) {
	k, r, _ := cutKey(t)
	return k, r
}

func cutKey(t string) (key, rest string, ok bool) {
	if t == "" {
		return
	}
	if t[0] == '"' || t[0] == '\'' {
		q := t[0]
		i := 1
		for i < len(t) {
			if t[i] == '\\' && q == '"' {
				i += 2
				continue
			}
			if t[i] == q {
				if q == '\'' && i+1 < len(t) && t[i+1] == '\'' {
					i += 2
					continue
				}
				break
			}
			i++
		}
		if i >= len(t) {
			return
		}
		after := t[i+1:]
		if strings.HasPrefix(after, ":") && (len(after) == 1 || after[1] == ' ' || after[1] == '\t') {
			return unquote(t[:i+1]), strings.TrimSpace(after[1:]), true
		}
		return
	}
	if t[0] == '[' || t[0] == '{' || t[0] == '&' || t[0] == '*' || t[0] == '!' || t[0] == '|' || t[0] == '>' || t[0] == '#' {
		if !(t[0] == '*' && false) {
			return
		}
	}
	for i := 0; i < len(t); i++ {
		if t[i] == ':' && (i+1 == len(t) || t[i+1] == ' ' || t[i+1] == '\t') {
			return strings.TrimSpace(t[:i]), strings.TrimSpace(t[i+1:]), true
		}
	}
	return
}

func balanced(s string) bool {
	depth := 0
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if inD {
				i++
			}
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case '[', '{':
			if !inS && !inD {
				depth++
			}
		case ']', '}':
			if !inS && !inD {
				depth--
			}
		}
	}
	return depth <= 0 && !inS && !inD
}

func closedQuote(s string) bool {
	if s == "" || (s[0] != '"' && s[0] != '\'') {
		return true
	}
	q := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] == '\\' && q == '"' {
			i++
			continue
		}
		if s[i] == q {
			if q == '\'' && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			return true
		}
	}
	return false
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		var b strings.Builder
		for i := 1; i < len(s)-1; i++ {
			if s[i] == '\\' && i+1 < len(s)-1 {
				i++
				switch s[i] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				case '"', '\\', '/':
					b.WriteByte(s[i])
				default:
					b.WriteByte('\\')
					b.WriteByte(s[i])
				}
				continue
			}
			b.WriteByte(s[i])
		}
		return b.String()
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	return s
}

func scalarNode(s string, line int) *Node {
	s = strings.TrimSpace(s)
	switch {
	case s == "" || s == "~" || s == "null":
		return &Node{Kind: Null, Line: line}
	case s[0] == '"' || s[0] == '\'':
		return &Node{Kind: Scalar, Value: unquote(s), Quoted: true, Line: line}
	}
	return &Node{Kind: Scalar, Value: s, Line: line}
}

// ---- flow collections / JSON ----

type flowParser struct {
	s    string
	pos  int
	line int
}

func (f *flowParser) skipWS() {
	for f.pos < len(f.s) {
		switch f.s[f.pos] {
		case '\n':
			f.line++
			f.pos++
		case ' ', '\t', '\r', ',':
			if f.s[f.pos] == ',' {
				return
			}
			f.pos++
		default:
			return
		}
	}
}

func (f *flowParser) value() *Node {
	f.skipWS()
	if f.pos >= len(f.s) {
		return &Node{Kind: Null, Line: f.line}
	}
	line := f.line
	switch f.s[f.pos] {
	case '{':
		f.pos++
		n := &Node{Kind: Map, Line: line}
		for {
			f.skipWS()
			for f.pos < len(f.s) && f.s[f.pos] == ',' {
				f.pos++
				f.skipWS()
			}
			if f.pos >= len(f.s) {
				return n
			}
			if f.s[f.pos] == '}' {
				f.pos++
				return n
			}
			kl := f.line
			key := f.scalarText(true)
			f.skipWS()
			if f.pos < len(f.s) && f.s[f.pos] == ':' {
				f.pos++
			}
			val := f.value()
			n.setPair(key, val, kl)
		}
	case '[':
		f.pos++
		n := &Node{Kind: Seq, Line: line}
		for {
			f.skipWS()
			for f.pos < len(f.s) && f.s[f.pos] == ',' {
				f.pos++
				f.skipWS()
			}
			if f.pos >= len(f.s) {
				return n
			}
			if f.s[f.pos] == ']' {
				f.pos++
				return n
			}
			n.Vals = append(n.Vals, f.value())
		}
	case '"', '\'':
		return scalarNode(f.quoted(), line)
	}
	t := f.scalarText(false)
	return scalarNode(t, line)
}

func (f *flowParser) quoted() string {
	q := f.s[f.pos]
	start := f.pos
	f.pos++
	for f.pos < len(f.s) {
		c := f.s[f.pos]
		if c == '\n' {
			f.line++
		}
		if c == '\\' && q == '"' {
			f.pos += 2
			continue
		}
		if c == q {
			if q == '\'' && f.pos+1 < len(f.s) && f.s[f.pos+1] == '\'' {
				f.pos += 2
				continue
			}
			f.pos++
			break
		}
		f.pos++
	}
	return f.s[start:min(f.pos, len(f.s))]
}

// scalarText reads a key or a plain scalar up to a flow delimiter.
func (f *flowParser) scalarText(key bool) string {
	f.skipWS()
	if f.pos < len(f.s) && (f.s[f.pos] == '"' || f.s[f.pos] == '\'') {
		return unquote(f.quoted())
	}
	start := f.pos
	for f.pos < len(f.s) {
		c := f.s[f.pos]
		if c == ',' || c == '}' || c == ']' || c == '\n' || (key && c == ':' && (f.pos+1 >= len(f.s) || f.s[f.pos+1] == ' ' || f.s[f.pos+1] == '\n')) {
			break
		}
		f.pos++
	}
	return strings.TrimSpace(f.s[start:f.pos])
}
