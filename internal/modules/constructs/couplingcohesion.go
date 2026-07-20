// couplingcohesion.go computes package-level Coupling (Ca/Ce/Instability,
// plus CBO where available) and class-level Cohesion (LCOM/Normalized
// LCOM/CAM) metrics.
//
// Coupling works for every language today: internal/graph already builds a
// module-level import dependency graph from data every parser already
// produces (ParsedFile.ModuleName + Imports), so Ca/Ce/I need no new
// parsing — this module just re-runs the same graph.Build over its own
// files (already in memory, no new file walk).
//
// Cohesion (and per-type CBO) need real field/method/call data. Go, Swift,
// TypeScript/JS, Python, C++, Java, and Rust parsers extract it today
// (internal/lang/golang_members.go, swift_members.go, typescript_members.go,
// python_members.go, cpp_members.go, java_members.go, rust_members.go) —
// Go's is AST-based (stdlib go/ast); the rest are regex/brace-or-indent
// heuristics (members_common.go for the brace-delimited majority, dedicated
// walkers for Python's indentation and Rust's separate struct+impl shape),
// so treat their cohesion numbers as directional, not exact. See
// golang_members.go's doc comment for the longer-term shared-AST-layer plan
// that would eventually replace all of these with one consistent pass.
// Plain C has no extractor — it has no member functions to bind fields and
// methods together, so class-level cohesion isn't a meaningful concept for
// it. Platforms with no ParsedFile.Extra["members"] data at all get
// Coupling only; Cohesion is explicitly reported as unsupported, never a
// fabricated score.
package constructs

import (
	"fmt"
	"html"
	"sort"
	"strings"

	depgraph "github.com/exey/archscope/internal/graph"
	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
)

func init() { modules.Default.Register(CouplingCohesion{}) }

// CouplingCohesion is the universal coupling/cohesion analyzer.
type CouplingCohesion struct{}

func (CouplingCohesion) ID() string                       { return "couplingcohesion" }
func (CouplingCohesion) Title() string                    { return "Coupling & Cohesion" }
func (CouplingCohesion) AppliesTo(languageID string) bool { return true } // universal

// ModuleCoupling is one package/module's Martin-metric reading.
type ModuleCoupling struct {
	Name        string
	Ca, Ce      int
	Instability float64 // Ce / (Ca+Ce)
}

// TypeCoupling is one type's CBO reading (only where a members extractor exists).
type TypeCoupling struct {
	TypeName, FilePath string
	Line               int
	CBO                int
}

// TypeCohesion is one type's cohesion reading (only where a members extractor exists).
type TypeCohesion struct {
	TypeName, FilePath string
	Line               int
	Methods            int
	LCOM               int // Chidamber & Kemerer / LCOM2: max(P-Q, 0)
	LCOM4              int // Henderson-Sellers: connected components
	NormalizedLCOM     float64
	CAM                float64
}

// CouplingCohesionResult is the module output.
type CouplingCohesionResult struct {
	Modules  []ModuleCoupling
	Types    []TypeCoupling // only where members data exists, CBO > 0
	Cohesion []TypeCohesion // only where members data exists, types with 2+ methods

	HasCohesionData bool // true when any file on this platform had Extra["members"]
	CouplingScore   int
	CohesionScore   int
}

// HasData reports whether there's anything to render.
func (r CouplingCohesionResult) HasData() bool { return len(r.Modules) > 0 }

func (CouplingCohesion) Analyze(files []*parser.ParsedFile) any {
	g := depgraph.New()
	g.Build(files)

	var mods []ModuleCoupling
	for _, h := range g.GetTopHotspots(0) {
		ca, ce := h.InDeg, h.OutDeg
		var inst float64
		if ca+ce > 0 {
			inst = float64(ce) / float64(ca+ce)
		}
		mods = append(mods, ModuleCoupling{Name: h.Name, Ca: ca, Ce: ce, Instability: inst})
	}
	sort.Slice(mods, func(i, j int) bool {
		if mods[i].Ce != mods[j].Ce {
			return mods[i].Ce > mods[j].Ce
		}
		return mods[i].Name < mods[j].Name
	})

	var loc int
	var types []TypeCoupling
	var cohesion []TypeCohesion
	hasGoData := false
	for _, f := range files {
		loc += f.LineCount
		tms, ok := f.Extra["members"].([]parser.TypeMembers)
		if !ok || len(tms) == 0 {
			continue
		}
		hasGoData = true
		for _, tm := range tms {
			line := declLine(f, tm.TypeName)

			ext := map[string]bool{}
			for _, m := range tm.Methods {
				for _, e := range m.ExternalRefs {
					ext[e] = true
				}
			}
			if len(ext) > 0 {
				types = append(types, TypeCoupling{TypeName: tm.TypeName, FilePath: f.FilePath, Line: line, CBO: len(ext)})
			}

			if n := len(tm.Methods); n > 1 {
				lcom, lcom4 := lcomStats(tm.Methods)
				cohesion = append(cohesion, TypeCohesion{
					TypeName: tm.TypeName, FilePath: f.FilePath, Line: line, Methods: n,
					LCOM: lcom, LCOM4: lcom4,
					NormalizedLCOM: float64(lcom4-1) / float64(n-1),
					CAM:            camScore(tm.Methods),
				})
			}
		}
	}
	sort.Slice(types, func(i, j int) bool { return types[i].CBO > types[j].CBO })
	sort.Slice(cohesion, func(i, j int) bool { return cohesion[i].NormalizedLCOM > cohesion[j].NormalizedLCOM })

	kloc := float64(loc) / 1000
	if kloc < 0.1 {
		kloc = 0.1
	}

	// Coupling smells: a module with too many outgoing deps (Ce > 8, works
	// for every language) or, where CBO is available, a type coupled to
	// too many others (CBO > 10 — the QMOOD-model threshold).
	highCe, highCBO := 0, 0
	for _, m := range mods {
		if m.Ce > 8 {
			highCe++
		}
	}
	for _, t := range types {
		if t.CBO > 10 {
			highCBO++
		}
	}
	couplingPen := (float64(highCe)*8 + float64(highCBO)*10) / kloc
	couplingScore := clampInt(100-int(couplingPen+0.5), 5, 100)

	// Cohesion smells, using the thresholds a "practical" reading of these
	// metrics uses: Normalized LCOM > 0.8 is critical, > 0.5 borderline;
	// CAM < 0.5 means the methods don't share a parameter-type vocabulary.
	critical, borderline, lowCAM := 0, 0, 0
	for _, t := range cohesion {
		switch {
		case t.NormalizedLCOM > 0.8:
			critical++
		case t.NormalizedLCOM > 0.5:
			borderline++
		}
		if t.CAM < 0.5 {
			lowCAM++
		}
	}
	cohesionPen := (float64(critical)*15 + float64(borderline)*6 + float64(lowCAM)*8) / kloc
	cohesionScore := clampInt(100-int(cohesionPen+0.5), 5, 100)

	return CouplingCohesionResult{
		Modules: mods, Types: types, Cohesion: cohesion,
		HasCohesionData: hasGoData,
		CouplingScore:   couplingScore,
		CohesionScore:   cohesionScore,
	}
}

// declLine finds the declaration line for a type name within one file, for
// deep-linking worst-offender rows back to source.
func declLine(f *parser.ParsedFile, name string) int {
	for _, d := range f.Declarations {
		if d.Name == name && (d.Kind == parser.DeclStruct || d.Kind == parser.DeclClass) {
			return d.Line
		}
	}
	return 0
}

// lcomStats computes both the classic Chidamber & Kemerer LCOM (max(P-Q,0))
// and the Henderson-Sellers LCOM4 (connected components of the
// method-shares-a-field graph) from each method's field-reference set.
func lcomStats(methods []parser.MethodMembers) (lcom, lcom4 int) {
	n := len(methods)
	if n == 0 {
		return 0, 0
	}
	sets := make([]map[string]bool, n)
	for i, m := range methods {
		s := make(map[string]bool, len(m.FieldRefs))
		for _, f := range m.FieldRefs {
			s[f] = true
		}
		sets[i] = s
	}
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
	}
	p, q := 0, 0
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			shared := false
			for fld := range sets[i] {
				if sets[j][fld] {
					shared = true
					break
				}
			}
			if shared {
				q++
				union(i, j)
			} else {
				p++
			}
		}
	}
	lcom = p - q
	if lcom < 0 {
		lcom = 0
	}
	comps := map[int]bool{}
	for i := 0; i < n; i++ {
		comps[find(i)] = true
	}
	return lcom, len(comps)
}

// camScore is the standard Cohesion-Among-Methods formula: for each
// distinct parameter type used anywhere in the class, count how many
// methods use it, sum that, and normalize by methods×distinctTypes. All
// methods sharing the exact same parameter-type vocabulary gives 1.0;
// completely disjoint vocabularies trend toward 0.
func camScore(methods []parser.MethodMembers) float64 {
	n := len(methods)
	if n == 0 {
		return 0
	}
	distinct := map[string]bool{}
	for _, m := range methods {
		for _, t := range m.ParamTypes {
			distinct[t] = true
		}
	}
	dt := len(distinct)
	if dt == 0 {
		return 1 // nothing to disagree about
	}
	sum := 0
	for t := range distinct {
		for _, m := range methods {
			for _, pt := range m.ParamTypes {
				if pt == t {
					sum++
					break
				}
			}
		}
	}
	return float64(sum) / float64(n*dt)
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

const maxOffendersShown = 15

var couplingGlossary = []struct{ term, desc string }{
	{"Ca", "modules that depend on this one (incoming)"},
	{"Ce", "modules this one depends on (outgoing)"},
	{"I", "instability — Ce/(Ca+Ce): 0 stable, 1 unstable"},
	{"CBO", "distinct types this type touches via calls/fields/literals"},
}

var cohesionGlossary = []struct{ term, desc string }{
	{"LCOM", "method pairs with no shared field, minus pairs that share one"},
	{"Norm. LCOM", "LCOM4 (connected method/field groups) scaled 0–1"},
	{"CAM", "parameter-type overlap across a type's methods"},
}

func (CouplingCohesion) RenderHTML(res any) string {
	r, ok := res.(CouplingCohesionResult)
	if !ok || !r.HasData() {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="as-cc">`)

	b.WriteString(`<div class="as-cx__health">`)
	writeGauge(&b, "🔗 Coupling", r.CouplingScore)
	if r.HasCohesionData {
		writeGauge(&b, "🧬 Cohesion", r.CohesionScore)
	} else {
		b.WriteString(`<div class="as-cx__gauge as-cc__na"><div class="as-cx__glabel"><span>🧬 Cohesion</span><span>N/A</span></div>` +
			`<div class="as-cc__hint">Needs per-method field/call data — not available for this language yet.</div></div>`)
	}
	b.WriteString(`</div>`)

	b.WriteString(`<div class="as-cc__gloss">`)
	b.WriteString(`<div class="as-cc__glosscol"><div class="as-cc__glosshead">🔗 Coupling</div>`)
	for _, g := range couplingGlossary {
		fmt.Fprintf(&b, `<span class="as-cc__term"><b>%s</b> — %s</span>`, html.EscapeString(g.term), html.EscapeString(g.desc))
	}
	b.WriteString(`</div>`)
	b.WriteString(`<div class="as-cc__glosscol"><div class="as-cc__glosshead">🧬 Cohesion</div>`)
	for _, g := range cohesionGlossary {
		fmt.Fprintf(&b, `<span class="as-cc__term"><b>%s</b> — %s</span>`, html.EscapeString(g.term), html.EscapeString(g.desc))
	}
	b.WriteString(`</div>`)
	b.WriteString(`</div>`)

	writeCouplingOffenders(&b, r.Modules, r.Types)
	writeCohesionOffenders(&b, r.Cohesion)

	b.WriteString(`</div>`)
	return b.String()
}

func writeCouplingOffenders(b *strings.Builder, mods []ModuleCoupling, types []TypeCoupling) {
	var rows []string
	shown := 0
	for _, m := range mods {
		if m.Ce <= 8 {
			continue
		}
		if shown == maxOffendersShown {
			break
		}
		rows = append(rows, fmt.Sprintf(`<tr><td class="mono">%s</td><td>Ca %d / Ce %d</td><td>I %.2f</td><td>—</td></tr>`,
			html.EscapeString(m.Name), m.Ca, m.Ce, m.Instability))
		shown++
	}
	for _, t := range types {
		if t.CBO <= 10 {
			continue
		}
		if shown == maxOffendersShown {
			break
		}
		loc := occurrenceLink(fmt.Sprintf("%s:%d", baseName(t.FilePath), t.Line), t.FilePath, t.Line)
		rows = append(rows, fmt.Sprintf(`<tr><td class="mono">%s</td><td>CBO %d</td><td>—</td><td>%s</td></tr>`,
			html.EscapeString(t.TypeName), t.CBO, loc))
		shown++
	}
	if len(rows) == 0 {
		return
	}
	fmt.Fprintf(b, `<div class="as-cx__viol-title">Coupling hotspots <span class="as-count">(%d)</span></div>`, len(rows))
	b.WriteString(`<table class="as-table as-cx__table"><thead><tr><th>Module / Type</th><th>Ca/Ce or CBO</th><th>Instability</th><th>Location</th></tr></thead><tbody>`)
	for _, row := range rows {
		b.WriteString(row)
	}
	b.WriteString(`</tbody></table>`)
}

func writeCohesionOffenders(b *strings.Builder, types []TypeCohesion) {
	var rows []string
	for i, t := range types {
		if t.NormalizedLCOM <= 0.5 && t.CAM >= 0.5 {
			continue
		}
		if i == maxOffendersShown {
			break
		}
		loc := occurrenceLink(fmt.Sprintf("%s:%d", baseName(t.FilePath), t.Line), t.FilePath, t.Line)
		rows = append(rows, fmt.Sprintf(`<tr><td class="mono">%s</td><td>LCOM %d / LCOM4 %d</td><td>%.2f</td><td>%.2f</td><td>%s</td></tr>`,
			html.EscapeString(t.TypeName), t.LCOM, t.LCOM4, t.NormalizedLCOM, t.CAM, loc))
	}
	if len(rows) == 0 {
		return
	}
	fmt.Fprintf(b, `<div class="as-cx__viol-title">Cohesion hotspots <span class="as-count">(%d)</span></div>`, len(rows))
	b.WriteString(`<table class="as-table as-cx__table"><thead><tr><th>Type</th><th>LCOM / LCOM4</th><th>Norm. LCOM</th><th>CAM</th><th>Location</th></tr></thead><tbody>`)
	for _, row := range rows {
		b.WriteString(row)
	}
	b.WriteString(`</tbody></table>`)
}

func (CouplingCohesion) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(CouplingCohesionResult)
	if !ok || !r.HasData() {
		return nil
	}
	cards := []modules.SummaryCard{{Num: fmt.Sprintf("%d%%", r.CouplingScore), Label: "Coupling"}}
	if r.HasCohesionData {
		cards = append(cards, modules.SummaryCard{Num: fmt.Sprintf("%d%%", r.CohesionScore), Label: "Cohesion"})
	}
	return cards
}

func (CouplingCohesion) RenderMarkdown(res any) string {
	r, ok := res.(CouplingCohesionResult)
	if !ok || !r.HasData() {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**Coupling:** %d%%", r.CouplingScore)
	if r.HasCohesionData {
		fmt.Fprintf(&b, " · **Cohesion:** %d%%\n", r.CohesionScore)
	} else {
		b.WriteString(" · **Cohesion:** N/A (not available for this language yet)\n")
	}
	if len(r.Modules) > 0 {
		b.WriteString("\n| Module | Ca | Ce | Instability |\n|---|---|---|---|\n")
		for i, m := range r.Modules {
			if i == maxOffendersShown {
				break
			}
			fmt.Fprintf(&b, "| %s | %d | %d | %.2f |\n", m.Name, m.Ca, m.Ce, m.Instability)
		}
	}
	return b.String()
}
