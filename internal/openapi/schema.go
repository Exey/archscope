package openapi

import (
	"sort"
	"strconv"
	"strings"
)

// schema.go is the Schema Object half of vacuum's schema-validity rules
// (oas-schema-check / schemachecks and allOf-conflicts): invalid types, keywords
// that don't apply to the declared type, inconsistent limits, malformed regular
// expressions, default/example values that don't fit, malformed `required`,
// conflicting compositions, discriminators pointing nowhere — and, across an
// allOf, properties that no value can satisfy because their types don't overlap.

var schemaTypes = map[string]bool{"string": true, "number": true, "integer": true, "boolean": true, "array": true, "object": true, "null": true}

var schema30Keywords = map[string]bool{
	"$ref": true, "title": true, "multipleOf": true, "maximum": true, "exclusiveMaximum": true, "minimum": true, "exclusiveMinimum": true,
	"maxLength": true, "minLength": true, "pattern": true, "maxItems": true, "minItems": true, "uniqueItems": true, "maxProperties": true,
	"minProperties": true, "required": true, "enum": true, "type": true, "not": true, "allOf": true, "oneOf": true, "anyOf": true, "items": true,
	"properties": true, "additionalProperties": true, "description": true, "format": true, "default": true, "nullable": true, "discriminator": true,
	"readOnly": true, "writeOnly": true, "xml": true, "externalDocs": true, "example": true, "deprecated": true,
}

// keywordTypes maps a constraint keyword to the types it applies to.
var keywordTypes = map[string][]string{
	"minLength": {"string"}, "maxLength": {"string"}, "pattern": {"string"},
	"minimum": {"number", "integer"}, "maximum": {"number", "integer"}, "exclusiveMinimum": {"number", "integer"},
	"exclusiveMaximum": {"number", "integer"}, "multipleOf": {"number", "integer"},
	"minItems": {"array"}, "maxItems": {"array"}, "uniqueItems": {"array"}, "items": {"array"},
	"minProperties": {"object"}, "maxProperties": {"object"}, "properties": {"object"}, "additionalProperties": {"object"},
}

// schemaTree checks n and every schema nested in it.
func (l *linter) schemaTree(n *Node, where string) {
	if n == nil || n.Kind != Map || l.schemaSeen[n] {
		return
	}
	l.schemaSeen[n] = true
	if n.Has("$ref") && len(n.Keys) == 1 {
		return
	}
	v31 := strings.HasPrefix(l.d.Ver, "3.1")
	types := schemaTypeSet(n)
	// 1. type validity
	if t := n.Get("type"); t != nil {
		for _, tv := range typeNodes(t) {
			if !schemaTypes[tv.Value] {
				l.add("oas-schema-type", tv.Line, where+": `"+tv.Value+"`")
			}
		}
		if t.Kind == Seq && !v31 {
			l.add("oas-schema-type", t.Line, where+": a list of types needs OpenAPI 3.1")
		}
	}
	// 2. unknown keywords (3.0 / 2.0 schemas are a closed vocabulary)
	if !v31 {
		for i, k := range n.Keys {
			if !schema30Keywords[k] && !strings.HasPrefix(k, "x-") {
				l.add("oas-spec-unknown", n.KLines[i], "Schema."+k)
			}
		}
	}
	// 3. constraints that don't apply
	if len(types) > 0 {
		for kw, applies := range keywordTypes {
			if !n.Has(kw) {
				continue
			}
			ok := false
			for _, a := range applies {
				if types[a] {
					ok = true
				}
			}
			if !ok {
				l.add("oas-schema-constraint", n.KeyLine(kw), "`"+kw+"` on type "+typeList(types))
			}
		}
	}
	// 4. limits
	l.checkLimits(n, where, v31)
	// 5. pattern
	if p := n.Get("pattern"); p != nil && p.Kind == Scalar && !patternLooksValid(p.Value) {
		l.add("oas-schema-pattern", p.Line, where+": "+p.Value)
	}
	pk, pv := n.Get("patternProperties").Pairs()
	for i, k := range pk {
		if !patternLooksValid(k) {
			l.add("oas-schema-pattern", n.Get("patternProperties").KLines[i], where+": "+k)
		}
		l.schemaTree(pv[i], where+".patternProperties."+k)
	}
	// 6. default / example / const against the type
	if len(types) == 1 {
		for _, kw := range []string{"default", "example", "const"} {
			if v := n.Get(kw); v != nil && !valueFitsTypes(v, types, n.Get("nullable").Bool()) {
				l.add("oas-schema-value", v.Line, where+": "+kw+" does not match type "+typeList(types))
			}
		}
	}
	// 7. required
	if req := n.Get("required"); req != nil && !(req.Kind == Scalar && req.Quoted == false && (req.Value == "true" || req.Value == "false")) {
		if req.Kind != Seq {
			l.add("oas-schema-required", req.Line, where+": `required` must be a list of property names")
		} else {
			seen := map[string]bool{}
			for _, it := range req.Vals {
				if it.Kind != Scalar {
					l.add("oas-schema-required", it.Line, where+": `required` entries must be strings")
					continue
				}
				if seen[it.Value] {
					l.add("oas-schema-required", it.Line, where+": `"+it.Value+"` is listed twice")
				}
				seen[it.Value] = true
			}
		}
	}
	// 8. composition
	l.checkComposition(n, where)
	// 9. discriminator, read/write, exclusive bounds, array items, const/enum
	l.checkMisc(n, where, v31, types)
	// 10. missing type (advisory)
	if len(types) == 0 && (n.Has("properties") || n.Has("items")) && !n.Has("allOf") && !n.Has("oneOf") && !n.Has("anyOf") {
		l.add("oas-schema-missing-type", n.Line, where)
	}

	// recurse
	pks, pvs := n.Get("properties").Pairs()
	for i, k := range pks {
		l.schemaTree(pvs[i], where+"."+k)
	}
	l.schemaTree(n.Get("items"), where+"[]")
	l.schemaTree(n.Get("not"), where+".not")
	if ap := n.Get("additionalProperties"); ap != nil && ap.Kind == Map {
		l.schemaTree(ap, where+".additionalProperties")
	}
	for _, c := range []string{"allOf", "oneOf", "anyOf", "prefixItems"} {
		for i, sub := range n.Get(c).Items() {
			l.schemaTree(sub, where+"."+c+"["+itoa(i)+"]")
		}
	}
	for _, c := range []string{"if", "then", "else", "contains", "propertyNames"} {
		l.schemaTree(n.Get(c), where+"."+c)
	}
}

func typeNodes(t *Node) []*Node {
	if t.Kind == Scalar {
		return []*Node{t}
	}
	var out []*Node
	for _, it := range t.Items() {
		if it.Kind == Scalar {
			out = append(out, it)
		}
	}
	return out
}

func schemaTypeSet(n *Node) map[string]bool {
	out := map[string]bool{}
	if t := n.Get("type"); t != nil {
		for _, tv := range typeNodes(t) {
			if schemaTypes[tv.Value] {
				out[tv.Value] = true
			}
		}
	}
	return out
}

func typeList(m map[string]bool) string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, "|")
}

func valueFitsTypes(v *Node, types map[string]bool, nullable bool) bool {
	if v.Kind == Null {
		return nullable || types["null"]
	}
	for t := range types {
		switch t {
		case "object":
			if v.Kind == Map {
				return true
			}
		case "array":
			if v.Kind == Seq {
				return true
			}
		default:
			if enumValueFits(t, v) {
				return true
			}
		}
	}
	return false
}

func num(n *Node) (float64, bool) {
	if n == nil || n.Kind != Scalar || n.Quoted {
		return 0, false
	}
	f, err := strconv.ParseFloat(n.Value, 64)
	return f, err == nil
}

func (l *linter) checkLimits(n *Node, where string, v31 bool) {
	pair := func(lo, hi string) {
		a, ok1 := num(n.Get(lo))
		b, ok2 := num(n.Get(hi))
		if ok1 && ok2 && a > b {
			l.add("oas-schema-range", n.KeyLine(hi), where+": `"+hi+"` is below `"+lo+"`")
		}
	}
	pair("minimum", "maximum")
	pair("minLength", "maxLength")
	pair("minItems", "maxItems")
	pair("minProperties", "maxProperties")
	if v31 {
		pair("exclusiveMinimum", "exclusiveMaximum")
	}
	for _, kw := range []string{"minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties"} {
		if v, ok := num(n.Get(kw)); ok && v < 0 {
			l.add("oas-schema-range", n.KeyLine(kw), where+": `"+kw+"` must not be negative")
		}
	}
	if v, ok := num(n.Get("multipleOf")); ok && v <= 0 {
		l.add("oas-schema-range", n.KeyLine("multipleOf"), where+": `multipleOf` must be greater than 0")
	}
}

func (l *linter) checkComposition(n *Node, where string) {
	// allOf: members whose single type differs can never both hold
	var seenType, seenFrom string
	for i, sub := range n.Get("allOf").Items() {
		r := l.resolve(sub)
		if r == nil || r.Kind != Map {
			continue
		}
		ts := schemaTypeSet(r)
		if len(ts) != 1 {
			continue
		}
		t := typeList(ts)
		if seenType != "" && !typesOverlap(seenType, t) {
			l.add("oas-schema-composition", sub.Line, where+": allOf mixes `"+seenType+"` ("+seenFrom+") and `"+t+"`")
		}
		if seenType == "" {
			seenType, seenFrom = t, "allOf["+itoa(i)+"]"
		}
	}
	// oneOf / anyOf: the same branch twice
	for _, c := range []string{"oneOf", "anyOf"} {
		seen := map[string]bool{}
		for _, sub := range n.Get(c).Items() {
			if ref := sub.Get("$ref").Str(); ref != "" {
				if seen[ref] {
					l.add("oas-schema-composition", sub.Line, where+": "+c+" lists "+ref+" twice")
				}
				seen[ref] = true
			}
		}
	}
	l.allOfConflicts(n, where)
}

func typesOverlap(a, b string) bool {
	return a == b || (a == "integer" && b == "number") || (a == "number" && b == "integer")
}

// allOfConflicts finds properties whose types, across the members of an allOf (and
// the schema's own properties), have nothing in common.
func (l *linter) allOfConflicts(n *Node, where string) {
	if len(n.Get("allOf").Items()) == 0 {
		return
	}
	type src struct {
		types string
		from  string
	}
	props := map[string][]src{}
	visited := map[*Node]bool{}
	var collect func(s *Node, from string, depth int)
	collect = func(s *Node, from string, depth int) {
		s = l.resolve(s)
		if s == nil || s.Kind != Map || depth > 6 || visited[s] {
			return
		}
		visited[s] = true
		pk, pv := s.Get("properties").Pairs()
		for i, name := range pk {
			p := l.resolve(pv[i])
			if p == nil || p.Kind != Map {
				continue
			}
			ts := schemaTypeSet(p)
			if len(ts) != 1 {
				continue // untyped or multi-typed: nothing to compare
			}
			t := typeList(ts)
			if p.Get("nullable").Bool() {
				continue // nullable adds null: overlap is guaranteed
			}
			props[name] = append(props[name], src{t, from})
		}
		for i, sub := range s.Get("allOf").Items() {
			collect(sub, from+"/allOf["+itoa(i)+"]", depth+1)
		}
	}
	collect(n, "this", 0)
	var names []string
	for k := range props {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		srcs := props[name]
		for i := 1; i < len(srcs); i++ {
			if !typesOverlap(srcs[0].types, srcs[i].types) {
				l.add("oas-allof-conflict", n.KeyLine("allOf"), where+": `"+name+"` is `"+srcs[0].types+"` and `"+srcs[i].types+"`")
				break
			}
		}
	}
}

func (l *linter) checkMisc(n *Node, where string, v31 bool, types map[string]bool) {
	if n.Get("readOnly").Bool() && n.Get("writeOnly").Bool() {
		l.add("oas-schema-readwrite", n.KeyLine("readOnly"), where)
	}
	for _, kw := range []string{"exclusiveMinimum", "exclusiveMaximum"} {
		v := n.Get(kw)
		if v == nil || v.Kind != Scalar {
			continue
		}
		isBool := !v.Quoted && (v.Value == "true" || v.Value == "false")
		if v31 && isBool {
			l.add("oas-schema-exclusive", v.Line, where+": `"+kw+"` is a number in OpenAPI 3.1")
		}
		if !v31 && !isBool {
			l.add("oas-schema-exclusive", v.Line, where+": `"+kw+"` is a boolean before OpenAPI 3.1")
		}
	}
	if types["array"] && !n.Has("items") && !n.Has("prefixItems") && !n.Has("$ref") {
		l.add("oas-schema-array-items", n.KeyLine("type"), where)
	}
	if c := n.Get("const"); c != nil {
		if en := n.Get("enum"); en != nil && en.Kind == Seq {
			found := false
			for _, it := range en.Vals {
				if it.Kind == Scalar && c.Kind == Scalar && it.Value == c.Value {
					found = true
				}
			}
			if !found {
				l.add("oas-schema-const-enum", c.Line, where)
			}
		}
	}
	if d := n.Get("discriminator"); d != nil && d.Kind == Map && !l.d.V2 {
		pn := d.Get("propertyName").Str()
		switch {
		case pn == "":
			l.add("oas-schema-discriminator", d.Line, where+": `propertyName` is missing")
		case !n.Has("oneOf") && !n.Has("anyOf") && !l.schemaDefinesProp(n, pn, 0):
			l.add("oas-schema-discriminator", d.KeyLine("propertyName"), where+": `"+pn+"` is not a property of the schema")
		}
	}
}

func (l *linter) schemaDefinesProp(n *Node, name string, depth int) bool {
	n = l.resolve(n)
	if n == nil || depth > 6 {
		return false
	}
	if n.Get("properties").Has(name) {
		return true
	}
	for _, sub := range n.Get("allOf").Items() {
		if l.schemaDefinesProp(sub, name, depth+1) {
			return true
		}
	}
	return false
}

// patternLooksValid is a tolerant ECMA-262 check: balanced groups and classes, no
// dangling quantifier. (Go's regexp can't be used: it rejects valid ECMA syntax such
// as lookahead and backreferences.)
func patternLooksValid(p string) bool {
	depth, inClass := 0, false
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c == '\\':
			i++
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth < 0 {
				return false
			}
		case (c == '*' || c == '+' || c == '?') && (i == 0 || p[i-1] == '(' || p[i-1] == '|') && !(c == '?' && i > 0 && p[i-1] == '('):
			return false
		}
	}
	return depth == 0 && !inClass
}
