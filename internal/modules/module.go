// Package modules defines the pluggable report-module system. A report module
// is a language-scoped (or universal) analysis that contributes an HTML panel
// and optional summary cards to a platform tab. Modules self-register in init()
// and are referenced by ID from a LanguageSpec.ReportModuleIDs (or run for all
// platforms when AppliesTo returns true for any present language).
package modules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/exey/archscope/internal/parser"
)

// SummaryCard is a small headline stat shown in a tab header.
type SummaryCard struct {
	Num   string
	Label string
}

// ReportModule is a language-specific (or universal) analysis panel.
type ReportModule interface {
	ID() string
	Title() string
	// AppliesTo reports whether this module should run for a given languageID.
	AppliesTo(languageID string) bool
	// Analyze consumes the relevant files and returns an opaque result.
	Analyze(files []*parser.ParsedFile) any
	// RenderHTML turns an Analyze result into an HTML fragment for the tab.
	RenderHTML(result any) string
	// SummaryCards returns optional extra cards for the tab header.
	SummaryCards(result any) []SummaryCard
}

// MarkdownRenderer is an optional extension of ReportModule. Modules that
// implement it produce rich markdown sections in --md output reports.
// Modules that do not implement it are silently skipped in markdown output.
type MarkdownRenderer interface {
	RenderMarkdown(result any) string
}

// ─── Module metadata ──────────────────────────────────────────────────────────

// ModuleMeta holds display metadata that modules don't carry themselves:
// the emoji icon and the canonical render order within a platform tab.
type ModuleMeta struct {
	Icon  string // emoji shown in headings
	Order int    // lower = rendered first within a platform tab
}

// MetaByID is the single source of truth for module render order and icons.
// Modules not listed here sort last (order 99) with a generic icon.
var MetaByID = map[string]ModuleMeta{
	"arch":           {Icon: "🏛️", Order: 0},
	"dddmodel":       {Icon: "🍱", Order: 1},
	"oopvspop":       {Icon: "⚖️", Order: 1},
	"traffic":        {Icon: "🛜", Order: 2},
	"speccoverage":   {Icon: "🧱", Order: 3},
	"designpattern":  {Icon: "🧩", Order: 4},
	"datastructures": {Icon: "🌳", Order: 5},
	"algorithms":     {Icon: "🔀", Order: 6},
	"complexity":     {Icon: "🧮", Order: 7},
	"magicconstants": {Icon: "🪄", Order: 8},
	"langrichness":   {Icon: "🎖️", Order: 9},
	"codestructure":  {Icon: "💻", Order: 10},
}

// MetaFor returns the ModuleMeta for id, falling back to a generic entry.
func MetaFor(id string) ModuleMeta {
	if m, ok := MetaByID[id]; ok {
		return m
	}
	return ModuleMeta{Icon: "📦", Order: 99}
}

// ─── Transformer ──────────────────────────────────────────────────────────────

// RenderedPanel is one module's output produced by Transformer.HTMLPanels.
type RenderedPanel struct {
	ModuleID string
	Title    string
	HTML     string
	Cards    []SummaryCard
	Result   any
}

// Transformer accumulates module analysis results for a single platform tab
// and renders them in the canonical order defined by MetaByID.
// Use NewTransformer, call Add for each module+result, then call HTMLPanels or
// Markdown to produce output.
type Transformer struct {
	entries []xfmEntry
}

type xfmEntry struct {
	module ReportModule
	result any
}

// NewTransformer returns an empty Transformer.
func NewTransformer() *Transformer { return &Transformer{} }

// Add records a module alongside its Analyze result.
func (t *Transformer) Add(m ReportModule, result any) {
	t.entries = append(t.entries, xfmEntry{m, result})
}

// HTMLPanels returns all non-empty HTML panels in canonical order.
func (t *Transformer) HTMLPanels() []RenderedPanel {
	var out []RenderedPanel
	for _, e := range t.sorted() {
		html := e.module.RenderHTML(e.result)
		if strings.TrimSpace(html) == "" {
			continue
		}
		out = append(out, RenderedPanel{
			ModuleID: e.module.ID(),
			Title:    e.module.Title(),
			HTML:     html,
			Cards:    e.module.SummaryCards(e.result),
			Result:   e.result,
		})
	}
	return out
}

// Markdown returns all non-empty markdown fragments joined in canonical order.
// Modules that do not implement MarkdownRenderer are silently skipped.
func (t *Transformer) Markdown() string {
	var b strings.Builder
	for _, e := range t.sorted() {
		mr, ok := e.module.(MarkdownRenderer)
		if !ok {
			continue
		}
		md := mr.RenderMarkdown(e.result)
		if strings.TrimSpace(md) == "" {
			continue
		}
		meta := MetaFor(e.module.ID())
		fmt.Fprintf(&b, "### %s %s\n\n%s", meta.Icon, e.module.Title(), md)
	}
	return b.String()
}

func (t *Transformer) sorted() []xfmEntry {
	entries := append([]xfmEntry(nil), t.entries...)
	sort.SliceStable(entries, func(i, j int) bool {
		return MetaFor(entries[i].module.ID()).Order < MetaFor(entries[j].module.ID()).Order
	})
	return entries
}

// ─── Registry ─────────────────────────────────────────────────────────────────

// Registry holds modules by ID.
type Registry struct {
	byID map[string]ReportModule
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{byID: map[string]ReportModule{}} }

// Default is the process-wide registry modules populate via init().
var Default = NewRegistry()

// Register adds a module (last write wins on duplicate ID).
func (r *Registry) Register(m ReportModule) { r.byID[m.ID()] = m }

// Get returns the module with id, or nil.
func (r *Registry) Get(id string) ReportModule { return r.byID[id] }

// All returns every registered module in stable order by ID.
func (r *Registry) All() []ReportModule {
	out := make([]ReportModule, 0, len(r.byID))
	for _, m := range r.byID {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}
