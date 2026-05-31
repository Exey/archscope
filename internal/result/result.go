// Package result defines AnalysisResult, the single in-memory product of the
// pipeline that both output writers (HTML, SARIF) consume. Writers know nothing
// language-specific beyond the platform bucket carried on each file and the
// pre-rendered module panels.
package result

import (
	"github.com/exey/archscope/internal/git"
	"github.com/exey/archscope/internal/graph"
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/scanner"
	"github.com/exey/archscope/internal/security"
)

// AnalysisResult is the single product of the pipeline; both writers read it.
type AnalysisResult struct {
	ProjectName   string
	RootPath      string
	IsRemote      bool
	SourceURL     string
	Files         []*parser.ParsedFile
	Scan          *scanner.ScanResult
	Graph         *graph.DependencyGraph
	Hotspots      []graph.HotspotEntry
	Security      []security.RuleResult
	SecurityScore security.Score
	Git           GitBundle

	// ModulePanels are report-module outputs already rendered to HTML, grouped
	// per platform tab. This is the pragmatic form of DESIGN's ModuleResults:
	// the pipeline runs each applicable module against a platform's files and
	// stores the panel so the HTML writer stays free of module-specific logic.
	ModulePanels []ModulePanel
}

// ModulePanel is one report module's rendered output within one platform tab.
type ModulePanel struct {
	Platform langspec.Platform
	ModuleID string
	Title    string
	HTML     string
	Cards    []modules.SummaryCard
}

// GitBundle is the repository-history surface (DESIGN §9.3), shared across all
// platforms (git history is repo-wide, not per-language).
type GitBundle struct {
	Available bool
	Authors   map[string]*git.AuthorStats
	Churn     []git.FileChurnStat
	Tags      git.TagStats
	Commits   git.CommitStats
	Branch    git.BranchStats
	Repos     []string
}

// PanelsForPlatform returns the module panels belonging to one platform tab.
func (r *AnalysisResult) PanelsForPlatform(p langspec.Platform) []ModulePanel {
	var out []ModulePanel
	for _, panel := range r.ModulePanels {
		if panel.Platform == p {
			out = append(out, panel)
		}
	}
	return out
}

// FilesForPlatform returns the parsed files bucketed into one platform tab.
func (r *AnalysisResult) FilesForPlatform(p langspec.Platform) []*parser.ParsedFile {
	var out []*parser.ParsedFile
	for _, f := range r.Files {
		if langspec.Platform(f.Platform) == p {
			out = append(out, f)
		}
	}
	return out
}

// TotalLines sums line counts across all parsed files.
func (r *AnalysisResult) TotalLines() int {
	n := 0
	for _, f := range r.Files {
		n += f.LineCount
	}
	return n
}

// TotalFindings sums uncapped findings across all rules.
func (r *AnalysisResult) TotalFindings() int {
	n := 0
	for _, rr := range r.Security {
		n += rr.TotalCount
	}
	return n
}

// FiringRules counts rules with at least one finding.
func (r *AnalysisResult) FiringRules() int {
	n := 0
	for _, rr := range r.Security {
		if !rr.Passed() {
			n++
		}
	}
	return n
}
