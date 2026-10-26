package openapi

import (
	"fmt"
	"regexp"
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

	// Places lists the operations a grouped change shows up in (root-cause
	// grouping: the same change reached through several endpoints is one change).
	Places []string
	// Question is what a reviewer has to decide about it.
	Question string
}

const (
	lvBreaking = "breaking"
	lvWarning  = "warning"
	lvInfo     = "info"
	// lvRefactor: the schema was restructured (inline ↔ $ref / allOf) and the
	// effective properties, types and required flags are unchanged.
	lvRefactor = "refactor"
	// lvDocs: descriptions and summaries only.
	lvDocs = "docs"
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
	d.out = groupChanges(d.out)
	rank := map[string]int{lvBreaking: 0, lvWarning: 1, lvRefactor: 2, lvInfo: 3, lvDocs: 4}
	sort.SliceStable(d.out, func(i, j int) bool {
		if rank[d.out[i].Level] != rank[d.out[j].Level] {
			return rank[d.out[i].Level] < rank[d.out[j].Level]
		}
		return d.out[i].Line < d.out[j].Line
	})
	return d.out, true
}

type differ struct {
	// shape counts changes to what a schema contains (properties, types,
	// required flags …) — as opposed to nullability, docs or refactors — so a
	// restructuring is only called a refactor when the shape really is the same.
	shape   int
	ol, nl  *linter
	out     []Change
	seen    map[string]bool
	refSeen map[string]bool
}

func (d *differ) add(level, rule, detail string, line int) {
	if level != lvDocs && level != lvRefactor && rule != "Now nullable" && rule != "No longer nullable" {
		d.shape++
	}
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
	d.out = append(d.out, Change{Level: level, Rule: rule, Detail: detail, Line: line, Severity: sev, Question: questionFor(level, rule)})
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
	if os, ns := o.op.Get("summary").Str(), n.op.Get("summary").Str(); os != ns && (os != "" || ns != "") {
		d.add(lvDocs, "Summary changed", key+": summary text", n.op.KeyLine("summary"))
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

// A schema is compared by what it *means*, not how it is written: $refs are
// followed and allOf members merged, so moving an inline object into a $ref (or
// wrapping it in allOf) is a refactor, not "every property removed".

// expand lists the nodes that together make up a schema: the node itself (without
// its allOf) and, recursively, every allOf member, each with $ref resolved.
func (d *differ) expand(l *linter, n *Node, depth int) []*Node {
	if n == nil || depth > 6 {
		return nil
	}
	n = l.resolve(n)
	if n == nil || n.Kind != Map {
		return nil
	}
	out := []*Node{n}
	for _, m := range n.Get("allOf").Items() {
		out = append(out, d.expand(l, m, depth+1)...)
	}
	return out
}

type sv []*Node

func (v sv) first(key string) *Node {
	for _, n := range v {
		if n.Has(key) {
			return n.Get(key)
		}
	}
	return nil
}

func (v sv) str(key string) string {
	if n := v.first(key); n != nil {
		return n.Str()
	}
	return ""
}

func (v sv) any(key string) bool {
	for _, n := range v {
		if n.Get(key).Bool() {
			return true
		}
	}
	return false
}

func (v sv) typ() string {
	for _, n := range v {
		if t := typeList(schemaTypeSet(n)); t != "" {
			return t
		}
	}
	return ""
}

func (v sv) required() map[string]bool {
	m := map[string]bool{}
	for _, n := range v {
		for _, r := range n.Get("required").Items() {
			m[r.Str()] = true
		}
	}
	return m
}

// props returns the property names in order, and each property's raw schemas
// (one per member that declares it).
func (v sv) props() ([]string, map[string][]*Node) {
	var names []string
	m := map[string][]*Node{}
	for _, n := range v {
		keys, vals := n.Get("properties").Pairs()
		for i, k := range keys {
			if _, ok := m[k]; !ok {
				names = append(names, k)
			}
			m[k] = append(m[k], vals[i])
		}
	}
	return names, m
}

func composed(raw []*Node) bool {
	for _, n := range raw {
		if n != nil && (n.Has("$ref") || n.Has("allOf")) {
			return true
		}
	}
	return false
}

// schema compares two schema nodes in a direction ("request": consumers send it;
// "response": consumers read it). line is the new document's line to report at.
func (d *differ) schema(a, b *Node, dir, label string, depth int, line int) {
	if a == nil || b == nil {
		return
	}
	d.schemaN([]*Node{a}, []*Node{b}, dir, label, depth, line)
}

func (d *differ) schemaN(rawA, rawB []*Node, dir, label string, depth int, line int) {
	if len(rawA) == 0 || len(rawB) == 0 || depth > 8 {
		return
	}
	for _, n := range rawB {
		if ref := n.Get("$ref").Str(); ref != "" {
			key := dir + "|" + ref
			if len(rawB) == 1 {
				if d.refSeen[key] {
					return
				}
				d.refSeen[key] = true
			}
			label += " → " + ref[strings.LastIndex(ref, "/")+1:]
		}
	}
	var av, bv sv
	for _, n := range rawA {
		av = append(av, d.expand(d.ol, n, 0)...)
	}
	for _, n := range rawB {
		bv = append(bv, d.expand(d.nl, n, 0)...)
	}
	if len(av) == 0 || len(bv) == 0 {
		return
	}
	if bv[0].Line > 0 {
		line = bv[0].Line
	}
	before := d.shape
	d.schemaV(av, bv, dir, label, depth, line)
	if d.shape == before && composed(rawA) != composed(rawB) {
		d.add(lvRefactor, "Refactor, same shape", label+": inline schema ↔ $ref / allOf — properties, types and required flags unchanged (verified)", line)
	}
}

func (d *differ) schemaV(av, bv sv, dir, label string, depth int, line int) {
	ta, tb := av.typ(), bv.typ()
	if ta != "" && tb != "" && ta != tb {
		widening := dir == "request" && ta == "integer" && tb == "number"
		narrowing := dir == "response" && ta == "number" && tb == "integer"
		if !widening && !narrowing {
			d.add(lvBreaking, "Type changed", label+": `"+ta+"` → `"+tb+"`", line)
		}
		return
	}
	if fa, fb := av.str("format"), bv.str("format"); fa != fb && (fa != "" || fb != "") && ta != "string" {
		d.add(lvWarning, "Format changed", label+": `"+fa+"` → `"+fb+"`", line)
	}
	an, bn := av.any("nullable"), bv.any("nullable")
	if dir == "request" && an && !bn {
		d.add(lvBreaking, "No longer nullable", label, line)
	}
	if dir == "response" && !an && bn {
		d.add(lvBreaking, "Now nullable", label+" (readers may not expect null)", line)
	}
	if da, db := av.str("description"), bv.str("description"); da != db && (da != "" || db != "") {
		d.add(lvDocs, "Description changed", label+": description text", line)
	}
	d.enumDiffV(av, bv, dir, label, line)
	d.limitsDiffV(av, bv, dir, label, line)

	ar, br := av.required(), bv.required()
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
	an2, am := av.props()
	bn2, bm := bv.props()
	for _, p := range an2 {
		if _, ok := bm[p]; !ok {
			if dir == "response" {
				d.add(lvBreaking, "Response property removed", label+": `"+p+"`", line)
			} else {
				d.add(lvWarning, "Request property removed", label+": `"+p+"`", line)
			}
			continue
		}
		d.schemaN(am[p], bm[p], dir, label+"."+p, depth+1, line)
	}
	for _, p := range bn2 {
		if _, ok := am[p]; !ok && !(dir == "request" && br[p]) {
			d.add(lvInfo, "Property added", label+": `"+p+"`", line)
		}
	}
	if ai, bi := av.first("items"), bv.first("items"); ai != nil && bi != nil {
		d.schemaN([]*Node{ai}, []*Node{bi}, dir, label+"[]", depth+1, line)
	}
	for _, c := range []string{"oneOf", "anyOf"} {
		ca, cb := av.first(c), bv.first(c)
		if ca == nil && cb == nil {
			continue
		}
		ai, bi := ca.Items(), cb.Items()
		if len(ai) != len(bi) {
			d.add(lvWarning, "Composition changed", label+": `"+c+"` has "+itoa(len(ai))+" → "+itoa(len(bi))+" members", line)
			continue
		}
		for i := range ai {
			d.schemaN([]*Node{ai[i]}, []*Node{bi[i]}, dir, label+"."+c+"["+itoa(i)+"]", depth+1, line)
		}
	}
}

func (d *differ) enumDiffV(a, b sv, dir, label string, line int) {
	ae, be := a.first("enum"), b.first("enum")
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

func (d *differ) limitsDiffV(a, b sv, dir, label string, line int) {
	type lim struct {
		kw    string
		upper bool // an upper bound: lowering it narrows what is accepted
	}
	for _, c := range []lim{{"maxLength", true}, {"minLength", false}, {"maximum", true}, {"minimum", false}, {"maxItems", true}, {"minItems", false}, {"maxProperties", true}, {"minProperties", false}} {
		an, bn := a.first(c.kw), b.first(c.kw)
		av, aok := num(an)
		bv, bok := num(bn)
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
			d.add(lvBreaking, "Request validation tightened", label+": `"+c.kw+"` "+fmtLim(an)+" → "+fmtLim(bn), line)
		case loosened && dir == "response":
			d.add(lvWarning, "Response limit loosened", label+": `"+c.kw+"` "+fmtLim(an)+" → "+fmtLim(bn), line)
		}
	}
	if pa, pb := a.str("pattern"), b.str("pattern"); pa != pb && dir == "request" && pb != "" {
		d.add(lvBreaking, "Request pattern changed", label+": `"+pa+"` → `"+pb+"`", line)
	}
}

func fmtLim(n *Node) string {
	if n == nil {
		return "none"
	}
	return n.Str()
}

func requiredSet(n *Node) map[string]bool {
	m := map[string]bool{}
	for _, r := range n.Get("required").Items() {
		m[r.Str()] = true
	}
	return m
}

// ---- reviewer questions and root-cause grouping ----

// questionFor is what a reviewer must decide about a change of this kind.
func questionFor(level, rule string) string {
	switch {
	case rule == "Now nullable" || rule == "No longer nullable":
		return "Intentional? If yes: plan migration, deprecation or a new version, and regenerate SDKs. If accidental: revert."
	case level == lvBreaking:
		return "Intentional? If yes: plan migration / deprecation / a new API version / SDK regeneration. If not: revert."
	case level == lvRefactor:
		return "Confirm the referenced schema still has the same properties, types and required flags."
	}
	return ""
}

var reOpPrefix = regexp.MustCompile(`^([A-Z]+ \S+): (.*)$`)

// subjectRules are the rules whose subjects (the `property` names) merge into one
// change when they share an origin: "6 properties removed from model" is one finding.
var subjectRules = map[string]bool{
	"Response property removed": true, "Request property removed": true, "Property added": true,
	"Property became required": true, "Property no longer guaranteed": true,
	"Response enum value added": true, "Request enum value removed": true,
}

// groupChanges collapses changes that share a root cause: the same rule on the
// same schema member reached through several endpoints is ONE change that lists
// its places; several properties removed from one schema are one change.
func groupChanges(in []Change) []Change {
	type g struct {
		idx      int
		places   []string
		subjects []string
		seenP    map[string]bool
		seenS    map[string]bool
	}
	groups := map[string]*g{}
	var out []Change
	for _, c := range in {
		m := reOpPrefix.FindStringSubmatch(c.Detail)
		if m == nil {
			out = append(out, c)
			continue
		}
		op, loc := m[1], m[2]
		subj := ""
		if i := strings.LastIndex(loc, ": "); i >= 0 {
			loc, subj = loc[:i], loc[i+2:]
		}
		leaf := loc
		if i := strings.LastIndexAny(leaf, ".→ "); i >= 0 {
			leaf = leaf[i+1:]
		}
		key := c.Level + "|" + c.Rule + "|" + leaf
		if !subjectRules[c.Rule] {
			key += "|" + subj
		}
		gr, ok := groups[key]
		if !ok {
			gr = &g{idx: len(out), seenP: map[string]bool{}, seenS: map[string]bool{}}
			groups[key] = gr
			cc := c
			cc.Detail = strings.TrimSpace(leaf + ": " + subj)
			if subj == "" {
				cc.Detail = loc
			}
			out = append(out, cc)
		}
		if !gr.seenP[op] {
			gr.seenP[op] = true
			gr.places = append(gr.places, op)
		}
		if subj != "" && subjectRules[c.Rule] && !gr.seenS[subj] {
			gr.seenS[subj] = true
			gr.subjects = append(gr.subjects, subj)
		}
	}
	for _, gr := range groups {
		c := &out[gr.idx]
		c.Places = gr.places
		if len(gr.subjects) > 0 {
			// leaf is kept as the context; subjects are the merged `names`
			ctx := strings.SplitN(c.Detail, ": ", 2)[0]
			c.Detail = ctx + ": " + strings.Join(gr.subjects, ", ")
		}
		if len(gr.places) > 0 {
			c.Detail += " — " + placesSummary(gr.places)
		}
	}
	return out
}

func placesSummary(p []string) string {
	if len(p) == 1 {
		return "in " + p[0]
	}
	shown := p
	if len(shown) > 4 {
		shown = shown[:4]
	}
	s := strings.Join(shown, ", ")
	if len(p) > 4 {
		s += fmt.Sprintf(" +%d more", len(p)-4)
	}
	return fmt.Sprintf("in %d places: %s", len(p), s)
}
