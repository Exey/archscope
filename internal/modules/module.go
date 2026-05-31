// Package modules defines the pluggable report-module system. A report module
// is a language-scoped (or universal) analysis that contributes an HTML panel
// and optional summary cards to a platform tab. Modules self-register in init()
// and are referenced by ID from a LanguageSpec.ReportModuleIDs (or run for all
// platforms when AppliesTo returns true for any present language).
package modules

import (
	"sort"

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
