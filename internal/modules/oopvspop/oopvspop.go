// Package oopvspop is a Swift-specific report module, generalized from
// ArchSwiftScope's OOP-vs-POP analyzer. Swift uniquely sits on a spectrum
// between classic object-oriented programming (reference types + inheritance)
// and Apple's protocol-oriented programming (value types + protocols +
// extensions). This module places the codebase on that spectrum using a
// weighted blend — Protocol Design 55% · Value Semantics 30% · Anti-inheritance
// 15% — mirroring the upstream weighting, and renders an ArchSwiftScope-style
// panel: the spectrum bar, three weighted category bars, and a metrics table
// with per-signal POP scores. It is gated to Swift (AppliesTo "swift").
package oopvspop

import (
	"fmt"
	"html"
	"strings"

	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
)

func init() { modules.Default.Register(Module{}) }

// Module is the Swift OOP-vs-POP analyzer.
type Module struct{}

func (Module) ID() string    { return "oopvspop" }
func (Module) Title() string { return "OOP vs POP" }

// AppliesTo restricts this module to Swift.
func (Module) AppliesTo(languageID string) bool { return languageID == "swift" }

// category weights (must sum to 1.0), matching the upstream analyzer.
const (
	wProtocolDesign = 0.55
	wValueSemantics = 0.30
	wAntiInherit    = 0.15
)

// Result is the analyzer output.
type Result struct {
	Classes, Actors, Structs, Enums, Protocols, Extensions       int
	Final, Singletons, Assoc, Some, Generics, Override, NSObject int

	TotalTypes int

	ProtoDesignScore int
	ValueScore       int
	AntiInheritScore int
	POPScore         int // 0..100

	Verdict string
}

// HasData reports whether any Swift types were found.
func (r Result) HasData() bool { return r.TotalTypes > 0 }

// POPPercent is the 0..100 protocol-oriented share.
func (r Result) POPPercent() int { return r.POPScore }

// Analyze tallies Swift type kinds + captured signals and computes the score.
func (Module) Analyze(files []*parser.ParsedFile) any {
	var r Result
	for _, f := range files {
		if f.LanguageID != "swift" {
			continue
		}
		r.Classes += f.CountKind(parser.DeclClass)
		r.Actors += f.CountKind(parser.DeclActor)
		r.Structs += f.CountKind(parser.DeclStruct)
		r.Enums += f.CountKind(parser.DeclEnum)
		r.Protocols += f.CountKind(parser.DeclInterface)
		r.Extensions += f.CountKind(parser.DeclExtension)
		r.Final += extra(f, "oopFinal")
		r.Singletons += extra(f, "oopSingletons")
		r.Assoc += extra(f, "oopAssoc")
		r.Some += extra(f, "oopSome")
		r.Generics += extra(f, "oopGenerics")
		r.Override += extra(f, "oopOverride")
		r.NSObject += extra(f, "oopNSObject")
	}
	refTypes := r.Classes + r.Actors
	r.TotalTypes = refTypes + r.Structs + r.Enums + r.Protocols

	// ── Protocol Design (55%) ──
	concrete := r.Classes + r.Structs + r.Enums
	protoPresence := ratio(r.Protocols, r.Protocols+concrete)
	generics01 := capped(r.Generics, max1(r.TotalTypes))
	some01 := capped(r.Some, max1(r.TotalTypes))
	assoc01 := condRatio(r.Protocols > 0, r.Assoc, r.Protocols)
	ext01 := capped(r.Extensions, max1(r.TotalTypes))
	protoDesign01 := 0.40*protoPresence + 0.15*generics01 + 0.15*some01 + 0.15*assoc01 + 0.15*ext01

	// ── Value Semantics (30%) ──
	structRatio := ratio(r.Structs, r.Structs+r.Classes)
	finalRatio := ratio(r.Final, max1(r.Classes))
	enum01 := 0.0
	if r.Enums > 0 {
		enum01 = 1.0
	}
	value01 := 0.60*structRatio + 0.30*finalRatio + 0.10*enum01

	// ── Anti-inheritance (15%) — higher = less inheritance = more POP ──
	overridePenalty := capped(r.Override, max1(r.Classes))
	nsobjectPenalty := ratio(r.NSObject, max1(r.Classes))
	singletonPenalty := 0.0
	if r.Singletons > 0 {
		singletonPenalty = capped(r.Singletons, max1(refTypes))
	}
	anti01 := clamp01(1.0 - (0.50*overridePenalty + 0.40*nsobjectPenalty + 0.10*singletonPenalty))
	if refTypes == 0 {
		anti01 = 1.0
	}

	r.ProtoDesignScore = pct(protoDesign01)
	r.ValueScore = pct(value01)
	r.AntiInheritScore = pct(anti01)
	pop := wProtocolDesign*protoDesign01 + wValueSemantics*value01 + wAntiInherit*anti01
	r.POPScore = pct(pop)

	switch {
	case r.TotalTypes == 0:
		r.Verdict = "No types found"
	case r.POPScore >= 70:
		r.Verdict = "Strongly protocol-oriented"
	case r.POPScore >= 55:
		r.Verdict = "Leaning protocol-oriented"
	case r.POPScore >= 45:
		r.Verdict = "Balanced OOP / POP"
	case r.POPScore >= 30:
		r.Verdict = "Leaning object-oriented"
	default:
		r.Verdict = "Strongly object-oriented"
	}
	return r
}

// SummaryCards surfaces the POP share.
func (Module) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(Result)
	if !ok || !r.HasData() {
		return nil
	}
	return []modules.SummaryCard{
		{Num: fmt.Sprintf("%d%%", r.POPScore), Label: "protocol-oriented"},
	}
}

// RenderHTML draws the spectrum bar (kept), three weighted category bars, and
// the metrics table — ArchSwiftScope's report style.
func (Module) RenderHTML(res any) string {
	r, ok := res.(Result)
	if !ok {
		return ""
	}
	if !r.HasData() {
		return `<p class="as-empty">No Swift types found to place on the OOP–POP spectrum.</p>`
	}
	pop := r.POPScore
	var b strings.Builder
	b.WriteString(`<div class="as-pop">`)
	fmt.Fprintf(&b, `<p class="as-pop__sub">Style signal across %d types · Protocol Design 55%% · Value Semantics 30%% · Anti-inheritance 15%%</p>`, r.TotalTypes)
	fmt.Fprintf(&b, `<div class="as-pop__verdict">%s</div>`, esc(r.Verdict))

	b.WriteString(`<div class="as-pop__scale"><span class="as-pop__end">◀ OOP</span>`)
	fmt.Fprintf(&b, `<div class="as-pop__track"><span class="as-pop__fill" style="width:%d%%"></span><span class="as-pop__marker" style="left:%d%%"></span></div>`, pop, pop)
	b.WriteString(`<span class="as-pop__end">POP ▶</span></div>`)
	fmt.Fprintf(&b, `<div class="as-pop__legend">%d%% protocol-oriented · %d%% object-oriented</div>`, pop, 100-pop)

	b.WriteString(`<div class="as-pop__cats">`)
	catBar(&b, "Protocol Design", r.ProtoDesignScore, "W 55%")
	catBar(&b, "Value Semantics", r.ValueScore, "W 30%")
	catBar(&b, "Anti-inheritance", r.AntiInheritScore, "W 15%")
	b.WriteString(`</div>`)

	b.WriteString(`<table class="as-pop__metrics"><thead><tr><th>#</th><th>Metric</th><th>Value</th><th>POP Score</th><th>Signal</th></tr></thead><tbody>`)
	concrete := r.Classes + r.Structs + r.Enums
	n := 0
	sect(&b, "Protocol Design · 55%")
	metric(&b, &n, "Protocol presence", fmt.Sprintf("%d protocols · %d types", r.Protocols, r.TotalTypes), ratio(r.Protocols, r.Protocols+concrete))
	metric(&b, &n, "Constrained generics", fmt.Sprintf("%d generic funcs", r.Generics), capped(r.Generics, max1(r.TotalTypes)))
	metric(&b, &n, "<code>some</code> usage", fmt.Sprintf("%d usages", r.Some), capped(r.Some, max1(r.TotalTypes)))
	metric(&b, &n, "<code>associatedtype</code>", fmt.Sprintf("%d / %d protocols", r.Assoc, r.Protocols), condRatio(r.Protocols > 0, r.Assoc, r.Protocols))
	metric(&b, &n, "Protocol extensions", fmt.Sprintf("%d extensions", r.Extensions), capped(r.Extensions, max1(r.TotalTypes)))

	sect(&b, "Value Semantics · 30%")
	metric(&b, &n, "Struct vs Class ratio", fmt.Sprintf("%d structs · %d classes", r.Structs, r.Classes), ratio(r.Structs, r.Structs+r.Classes))
	metric(&b, &n, "<code>final</code> classes", fmt.Sprintf("%d / %d classes", r.Final, r.Classes), ratio(r.Final, max1(r.Classes)))
	infoRow(&b, &n, "Enums (value type)", fmt.Sprintf("%d enums", r.Enums))

	sect(&b, "Anti-inheritance · 15%")
	metric(&b, &n, `<code>override</code> density <span class="as-pop__inv">↓ lower = POP</span>`, fmt.Sprintf("%d in %d classes", r.Override, r.Classes), clamp01(1.0-capped(r.Override, max1(r.Classes))))
	metric(&b, &n, `NSObject inheritance <span class="as-pop__inv">↓ lower = POP</span>`, fmt.Sprintf("%d / %d classes", r.NSObject, r.Classes), clamp01(1.0-ratio(r.NSObject, max1(r.Classes))))

	sect(&b, "Counter-signals")
	note := ""
	if r.Singletons > 0 {
		note = " — OOP indicator"
	}
	infoRow(&b, &n, "⚠ Singletons (static shared/instance)", fmt.Sprintf("%d found%s", r.Singletons, note))

	b.WriteString(`</tbody></table></div>`)
	return b.String()
}

// ── render helpers ─────────────────────────────────────────────────────────

func catBar(b *strings.Builder, label string, score int, weight string) {
	fmt.Fprintf(b,
		`<div class="as-pop__catbar"><span class="as-pop__catlabel">%s</span><div class="as-bar"><span class="as-bar__fill %s" style="width:%d%%"></span></div><span class="as-pop__catpct %s">%d%%</span><span class="as-pop__catw">%s</span></div>`,
		esc(label), fillClass(score), score, textClass(score), score, esc(weight))
}

func sect(b *strings.Builder, title string) {
	fmt.Fprintf(b, `<tr class="as-pop__sect"><td colspan="5">%s</td></tr>`, esc(title))
}

func metric(b *strings.Builder, n *int, name, value string, score01 float64) {
	*n++
	p := pct(score01)
	fmt.Fprintf(b,
		`<tr><td class="mono">%d</td><td>%s</td><td class="mono">%s</td><td><div class="as-mini"><span class="as-mini__fill %s" style="width:%d%%"></span></div></td><td>%s</td></tr>`,
		*n, name, esc(value), fillClass(p), p, signalTag(p))
}

func infoRow(b *strings.Builder, n *int, name, value string) {
	*n++
	fmt.Fprintf(b,
		`<tr><td class="mono">%d</td><td class="as-pop__infocell">%s</td><td class="mono as-pop__infocell">%s</td><td></td><td></td></tr>`,
		*n, name, esc(value))
}

func signalTag(p int) string {
	switch {
	case p >= 65:
		return `<span class="as-tag tag-pop">POP</span>`
	case p >= 40:
		return `<span class="as-tag tag-mixed">Mixed</span>`
	default:
		return `<span class="as-tag tag-oop">OOP</span>`
	}
}

func fillClass(p int) string {
	switch {
	case p >= 65:
		return "fill-good"
	case p >= 40:
		return "fill-warn"
	default:
		return "fill-crit"
	}
}

func textClass(p int) string {
	switch {
	case p >= 65:
		return "as-pop__t-good"
	case p >= 40:
		return "as-pop__t-warn"
	default:
		return "as-pop__t-crit"
	}
}

// ── math helpers ───────────────────────────────────────────────────────────

func extra(f *parser.ParsedFile, key string) int {
	if f.Extra == nil {
		return 0
	}
	if v, ok := f.Extra[key].(int); ok {
		return v
	}
	return 0
}
func ratio(a, b int) float64 {
	if b <= 0 {
		return 0
	}
	return clamp01(float64(a) / float64(b))
}
func condRatio(cond bool, a, b int) float64 {
	if !cond {
		return 0
	}
	return ratio(a, b)
}
func capped(a, b int) float64 {
	if b <= 0 {
		return 0
	}
	return clamp01(float64(a) / float64(b))
}
func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
func pct(v float64) int { return int(v*100 + 0.5) }
func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
func esc(s string) string { return html.EscapeString(s) }
