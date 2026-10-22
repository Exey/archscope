package openapi

import (
	"sort"
	"strings"
)

// Change is one difference between two versions of a specification, classified
// by what it does to existing consumers — the question a merge-request reviewer
// has about an API change ("does this break my clients?").
type Change struct {
	Level    string // "breaking" | "warning" | "info"
	Rule     string // short label
	Detail   string // "GET /pets: response 200 property `id` removed"
	Line     int    // line in the NEW document (the parent's line when something was removed)
	Severity string // HIGH (breaking) | MEDIUM (warning) | LOW (info)
}

const (
	lvBreaking = "breaking"
	lvWarning  = "warning"
	lvInfo     = "info"
)

// Diff compares two documents. ok is false when either isn't a specification.
// Directions matter: a schema used by a request must keep accepting what it
// accepted (narrowing breaks callers); one used by a response must keep
// producing what it produced (widening breaks readers).
func Diff(oldSrc, newSrc string) (changes []Change, ok bool) {
	od, ok1 := Load(oldSrc)
	nd, ok2 := Load(newSrc)
	if !ok1 || !ok2 {
		return nil, false
	}
	d := &differ{
		ol:   &linter{d: od, seen: map[string]bool{}, schemaSeen: map[*Node]bool{}},
		nl:   &linter{d: nd, seen: map[string]bool{}, schemaSeen: map[*Node]bool{}},
		seen: map[string]bool{}, refSeen: map[string]bool{},
	}
	d.run()
	rank := map[string]int{lvBreaking: 0, lvWarning: 1, lvInfo: 2}
	sort.SliceStable(d.out, func(i, j int) bool {
		if rank[d.out[i].Level] != rank[d.out[j].Level] {
			return rank[d.out[i].Level] < rank[d.out[j].Level]
		}
		return d.out[i].Line < d.out[j].Line
	})
	return d.out, true
}

type differ struct {
	ol, nl  *linter
	out     []Change
	seen    map[string]bool
	refSeen map[string]bool
}

func (d *differ) add(level, rule, detail string, line int) {
	key := level + "|" + rule + "|" + detail
	if d.seen[key] {
		return
	}
	d.seen[key] = true
	sev := "LOW"
	switch level {
	case lvBreaking:
		sev = "HIGH"
	case lvWarning:
		sev = "MEDIUM"
	}
	d.out = append(d.out, Change{Level: level, Rule: rule, Detail: detail, Line: line, Severity: sev})
}

func opKey(method, path string) string { return strings.ToUpper(method) + " " + path }

func (d *differ) run() {
	oldOps := indexOps(d.ol)
	newOps := indexOps(d.nl)
	newPaths := d.nl.d.Root.Get("paths")

	// removed
	var removed []string
	for k := range oldOps {
		if _, ok := newOps[k]; !ok {
			removed = append(removed, k)
		}
	}
	sort.Strings(removed)
	for _, k := range removed {
		o := oldOps[k]
		if newPaths.Has(o.path) {
			d.add(lvBreaking, "Operation removed", k, newPaths.KeyLine(o.path))
		} else {
			d.add(lvBreaking, "Path removed", k, newPathsLine(d.nl))
		}
	}
	// added
	for k, n := range newOps {
		if _, ok := oldOps[k]; !ok {
			d.add(lvInfo, "Operation added", k, n.line)
		}
	}
	// changed
	var keys []string
	for k := range newOps {
		if _, ok := oldOps[k]; ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		d.operation(k, oldOps[k], newOps[k])
	}
	d.servers()
}

func newPathsLine(l *linter) int {
	if l.d.Root.Has("paths") {
		return l.d.Root.KeyLine("paths")
	}
	return l.d.Root.Line
}

func indexOps(l *linter) map[string]operation {
	m := map[string]operation{}
	for _, o := range l.operations() {
		m[opKey(o.method, o.path)] = o
	}
	return m
}

func (d *differ) operation(key string, o, n operation) {
	if oid, nid := o.op.Get("operationId").Str(), n.op.Get("operationId").Str(); oid != nid && oid != "" {
		d.add(lvWarning, "operationId changed", key+": `"+oid+"` → `"+nid+"` (generated client methods are renamed)", n.op.KeyLine("operationId"))
	}
	if !o.op.Get("deprecated").Bool() && n.op.Get("deprecated").Bool() {
		d.add(lvInfo, "Operation deprecated", key, n.op.KeyLine("deprecated"))
	}
	d.parameters(key, o, n)
	d.requestBody(key, o, n)
	d.responses(key, o, n)
	d.security(key, o, n)
}

// ---- parameters ----

type paramID struct{ name, in string }

func (d *differ) paramMap(l *linter, o operation) map[paramID]*Node {
	m := map[paramID]*Node{}
	for _, src := range []*Node{o.item.Get("parameters"), o.op.Get("parameters")} {
		for _, p := range src.Items() {
			if p = l.resolve(p); p != nil && p.Kind == Map {
				m[paramID{p.Get("name").Str(), p.Get("in").Str()}] = p
			}
		}
	}
	return m
}

func (d *differ) parameters(key string, o, n operation) {
	op, np := d.paramMap(d.ol, o), d.paramMap(d.nl, n)
	var ids []paramID
	for id := range op {
		ids = append(ids, id)
	}
	for id := range np {
		if _, ok := op[id]; !ok {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].in+ids[i].name < ids[j].in+ids[j].name })
	for _, id := range ids {
		a, b := op[id], np[id]
		label := key + ": " + id.in + " parameter `" + id.name + "`"
		switch {
		case a != nil && b == nil:
			d.add(lvWarning, "Parameter removed", label, n.op.KeyLine("parameters"))
		case a == nil && b != nil:
			if b.Get("required").Bool() || id.in == "path" {
				d.add(lvBreaking, "Required parameter added", label, b.Line)
			} else {
				d.add(lvInfo, "Optional parameter added", label, b.Line)
			}
		default:
			if !a.Get("required").Bool() && b.Get("required").Bool() {
				d.add(lvBreaking, "Parameter became required", label, b.Line)
			} else if a.Get("required").Bool() && !b.Get("required").Bool() {
				d.add(lvInfo, "Parameter became optional", label, b.Line)
			}
			as, bs := paramSchema(d.ol, a), paramSchema(d.nl, b)
			d.schema(as, bs, "request", label, 0, b.Line)
		}
	}
}

func paramSchema(l *linter, p *Node) *Node {
	if s := p.Get("schema"); s != nil {
		return s
	}
	// Swagger 2: type/format/enum live on the parameter itself
	if p.Has("type") {
		return p
	}
	return nil
}

// ---- request body ----

func (d *differ) requestBody(key string, o, n operation) {
	a, b := d.ol.resolve(o.op.Get("requestBody")), d.nl.resolve(n.op.Get("requestBody"))
	switch {
	case a == nil && b == nil:
		return
	case a != nil && b == nil:
		d.add(lvWarning, "Request body removed", key, n.line)
		return
	case a == nil && b != nil:
		if b.Get("required").Bool() {
			d.add(lvBreaking, "Required request body added", key, b.Line)
		} else {
			d.add(lvInfo, "Optional request body added", key, b.Line)
		}
		return
	}
	if !a.Get("required").Bool() && b.Get("required").Bool() {
		d.add(lvBreaking, "Request body became required", key, b.Line)
	}
	d.content(a.Get("content"), b.Get("content"), "request", key+": request body", b.KeyLine("content"))
}

// content compares two `content` maps (media type → schema).
func (d *differ) content(a, b *Node, dir, label string, line int) {
	ak, av := a.Pairs()
	for i, mt := range ak {
		if !b.Has(mt) {
			level, rule := lvBreaking, "Media type removed"
			if dir == "request" {
				level = lvBreaking
			}
			d.add(level, rule, label+": `"+mt+"`", line)
			continue
		}
		d.schema(av[i].Get("schema"), b.Get(mt).Get("schema"), dir, label+" ("+mt+")", 0, b.Get(mt).Line)
	}
	bk, bv := b.Pairs()
	for i, mt := range bk {
		if !a.Has(mt) {
			d.add(lvInfo, "Media type added", label+": `"+mt+"`", bv[i].Line)
		}
	}
}

// ---- responses ----

func (d *differ) responses(key string, o, n operation) {
	a, b := o.op.Get("responses"), n.op.Get("responses")
	ak, av := a.Pairs()
	for i, code := range ak {
		if !b.Has(code) {
			level, rule := lvInfo, "Response removed"
			if strings.HasPrefix(code, "2") {
				level, rule = lvBreaking, "Success response removed"
			} else if strings.HasPrefix(code, "4") || strings.HasPrefix(code, "5") {
				level = lvInfo
			}
			d.add(level, rule, key+": response "+code, n.op.KeyLine("responses"))
			continue
		}
		ra, rb := d.ol.resolve(av[i]), d.nl.resolve(b.Get(code))
		if ra == nil || rb == nil {
			continue
		}
		d.content(ra.Get("content"), rb.Get("content"), "response", key+": response "+code, rb.KeyLine("content"))
		// Swagger 2 response schema
		if ra.Has("schema") || rb.Has("schema") {
			d.schema(ra.Get("schema"), rb.Get("schema"), "response", key+": response "+code, 0, rb.Line)
		}
	}
	bk, bv := b.Pairs()
	for i, code := range bk {
		if !a.Has(code) {
			d.add(lvInfo, "Response added", key+": response "+code, bv[i].Line)
		}
	}
}

// ---- security ----

func secNames(sec *Node) map[string]bool {
	m := map[string]bool{}
	for _, req := range sec.Items() {
		keys, _ := req.Pairs()
		for _, k := range keys {
			m[k] = true
		}
	}
	return m
}

func (d *differ) effectiveSecurity(l *linter, o operation) (map[string]bool, bool) {
	if o.op.Has("security") {
		return secNames(o.op.Get("security")), true
	}
	return secNames(l.d.Root.Get("security")), false
}

func (d *differ) security(key string, o, n operation) {
	a, _ := d.effectiveSecurity(d.ol, o)
	b, _ := d.effectiveSecurity(d.nl, n)
	switch {
	case len(a) == 0 && len(b) > 0:
		d.add(lvBreaking, "Authentication now required", key, n.line)
	case len(a) > 0 && len(b) == 0:
		d.add(lvWarning, "Operation is no longer protected", key, n.line)
	default:
		for name := range b {
			if !a[name] && len(a) > 0 {
				d.add(lvWarning, "Security scheme changed", key+": `"+name+"` added", n.line)
			}
		}
	}
}

func (d *differ) servers() {
	ov, nv := map[string]bool{}, d.nl.d.Root.Get("servers")
	for _, s := range d.ol.d.Root.Get("servers").Items() {
		ov[s.Get("url").Str()] = true
	}
	nset := map[string]bool{}
	for _, s := range nv.Items() {
		nset[s.Get("url").Str()] = true
	}
	for u := range ov {
		if !nset[u] && len(nset) > 0 {
			d.add(lvWarning, "Server URL removed", u, d.nl.d.Root.KeyLine("servers"))
		}
	}
}

// ---- schemas ----

// schema compares two schemas in a direction ("request": consumers send it;
// "response": consumers read it). line is the new document's line to report at.
func (d *differ) schema(a, b *Node, dir, label string, depth int, line int) {
	if a == nil || b == nil || depth > 8 {
		return
	}
	if ref := b.Get("$ref").Str(); ref != "" {
		key := dir + "|" + ref
		if d.refSeen[key] {
			return
		}
		d.refSeen[key] = true
		label += " → " + ref[strings.LastIndex(ref, "/")+1:]
	}
	a, b = d.ol.resolve(a), d.nl.resolve(b)
	if a == nil || b == nil || a.Kind != Map || b.Kind != Map {
		return
	}
	if b.Line > 0 {
		line = b.Line
	}
	ta, tb := typeList(schemaTypeSet(a)), typeList(schemaTypeSet(b))
	if ta != "" && tb != "" && ta != tb {
		widening := dir == "request" && ta == "integer" && tb == "number"
		narrowing := dir == "response" && ta == "number" && tb == "integer"
		if !widening && !narrowing {
			d.add(lvBreaking, "Type changed", label+": `"+ta+"` → `"+tb+"`", line)
		}
		return
	}
	if fa, fb := a.Get("format").Str(), b.Get("format").Str(); fa != fb && (fa != "" || fb != "") && ta != "string" {
		d.add(lvWarning, "Format changed", label+": `"+fa+"` → `"+fb+"`", line)
	}
	// nullability
	an, bn := a.Get("nullable").Bool(), b.Get("nullable").Bool()
	if dir == "request" && an && !bn {
		d.add(lvBreaking, "No longer nullable", label, line)
	}
	if dir == "response" && !an && bn {
		d.add(lvBreaking, "Now nullable", label+" (readers may not expect null)", line)
	}
	d.enumDiff(a, b, dir, label, line)
	d.limitsDiff(a, b, dir, label, line)

	// required
	ar, br := requiredSet(a), requiredSet(b)
	for p := range br {
		if !ar[p] && dir == "request" {
			d.add(lvBreaking, "Property became required", label+": `"+p+"`", line)
		}
	}
	for p := range ar {
		if !br[p] && dir == "response" {
			d.add(lvBreaking, "Property no longer guaranteed", label+": `"+p+"` is not required any more", line)
		}
	}
	// properties
	apk, apv := a.Get("properties").Pairs()
	bprops := b.Get("properties")
	for i, p := range apk {
		if !bprops.Has(p) {
			if dir == "response" {
				d.add(lvBreaking, "Response property removed", label+": `"+p+"`", line)
			} else {
				d.add(lvWarning, "Request property removed", label+": `"+p+"`", line)
			}
			continue
		}
		d.schema(apv[i], bprops.Get(p), dir, label+"."+p, depth+1, line)
	}
	bpk, bpv := bprops.Pairs()
	for i, p := range bpk {
		if !a.Get("properties").Has(p) {
			if dir == "request" && br[p] {
				continue // reported as required
			}
			d.add(lvInfo, "Property added", label+": `"+p+"`", bpv[i].Line)
		}
	}
	// items and compositions
	d.schema(a.Get("items"), b.Get("items"), dir, label+"[]", depth+1, line)
	for _, c := range []string{"allOf", "oneOf", "anyOf"} {
		ai, bi := a.Get(c).Items(), b.Get(c).Items()
		if len(ai) != len(bi) {
			d.add(lvWarning, "Composition changed", label+": `"+c+"` has "+itoa(len(ai))+" → "+itoa(len(bi))+" members", line)
			continue
		}
		for i := range ai {
			d.schema(ai[i], bi[i], dir, label+"."+c+"["+itoa(i)+"]", depth+1, line)
		}
	}
}

func requiredSet(n *Node) map[string]bool {
	m := map[string]bool{}
	for _, r := range n.Get("required").Items() {
		m[r.Str()] = true
	}
	return m
}

func (d *differ) enumDiff(a, b *Node, dir, label string, line int) {
	ae, be := a.Get("enum"), b.Get("enum")
	if ae == nil && be == nil {
		return
	}
	as, bs := enumSet(ae), enumSet(be)
	if ae == nil && be != nil && dir == "request" {
		d.add(lvBreaking, "Request value restricted to an enum", label, line)
		return
	}
	if ae != nil && be == nil {
		if dir == "response" {
			d.add(lvWarning, "Response enum removed (any value possible)", label, line)
		}
		return
	}
	for v := range as {
		if !bs[v] && dir == "request" {
			d.add(lvBreaking, "Request enum value removed", label+": `"+v+"`", line)
		}
	}
	for v := range bs {
		if !as[v] && dir == "response" {
			d.add(lvWarning, "Response enum value added", label+": `"+v+"` (readers with exhaustive switches break)", line)
		}
	}
}

func enumSet(n *Node) map[string]bool {
	m := map[string]bool{}
	for _, it := range n.Items() {
		m[it.Value] = true
	}
	return m
}

func (d *differ) limitsDiff(a, b *Node, dir, label string, line int) {
	type lim struct {
		kw    string
		upper bool // an upper bound: lowering it narrows what is accepted
	}
	for _, c := range []lim{{"maxLength", true}, {"minLength", false}, {"maximum", true}, {"minimum", false}, {"maxItems", true}, {"minItems", false}, {"maxProperties", true}, {"minProperties", false}} {
		av, aok := num(a.Get(c.kw))
		bv, bok := num(b.Get(c.kw))
		if aok == bok && av == bv {
			continue
		}
		tighter := false
		switch {
		case bok && !aok:
			tighter = true
		case aok && bok && c.upper:
			tighter = bv < av
		case aok && bok:
			tighter = bv > av
		}
		loosened := (aok && !bok) || (aok && bok && !tighter)
		switch {
		case tighter && dir == "request":
			d.add(lvBreaking, "Request validation tightened", label+": `"+c.kw+"` "+fmtLim(a.Get(c.kw))+" → "+fmtLim(b.Get(c.kw)), line)
		case loosened && dir == "response":
			d.add(lvWarning, "Response limit loosened", label+": `"+c.kw+"` "+fmtLim(a.Get(c.kw))+" → "+fmtLim(b.Get(c.kw)), line)
		}
	}
	if pa, pb := a.Get("pattern").Str(), b.Get("pattern").Str(); pa != pb && dir == "request" && pb != "" {
		d.add(lvBreaking, "Request pattern changed", label+": `"+pa+"` → `"+pb+"`", line)
	}
}

func fmtLim(n *Node) string {
	if n == nil {
		return "none"
	}
	return n.Str()
}
