// Package security is the generalized port of ArchSwiftScope's SecurityAnalyzer
// (which replaced the old anti-patterns section). Each Rule is a detector plus
// metadata; rules declare which languages they apply to, and rules with no
// languages are universal (run against every language). The engine aggregates
// findings into a 0..1000 weighted security index across 14 categories.
package security

// Severity is a finding's priority.
type Severity string

const (
	SevHigh   Severity = "HIGH"
	SevMedium Severity = "MEDIUM"
	SevLow    Severity = "LOW"
)

// Weight is the multiplier applied to a finding when computing weighted density
// (HIGH counts double a MEDIUM; LOW counts half).
func (s Severity) Weight() float64 {
	switch s {
	case SevHigh:
		return 2.0
	case SevMedium:
		return 1.0
	case SevLow:
		return 0.5
	default:
		return 1.0
	}
}

// Rank orders severities (HIGH highest) for min-severity filtering.
func (s Severity) Rank() int {
	switch s {
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	default:
		return 0
	}
}

// Category is one of the 14 weighted security categories. Weights sum to 1000.
type Category struct {
	ID     int    // 1..14, shown in the report
	Key    string // stable key, e.g. "insecure_data_storage"
	Title  string
	Icon   string
	Weight int // points out of 1000
	Blurb  string
}

// Finding is one violation located at file:line.
type Finding struct {
	RuleID   string `json:"ruleId"`
	File     string `json:"file"`     // display path
	FullPath string `json:"fullPath"` // absolute path (for git blame)
	Line     int    `json:"line"`
	Snippet  string `json:"snippet"`
	Author   string `json:"author,omitempty"` // filled by blame enrichment (later)
}

// Rule is one security check.
type Rule struct {
	ID          string
	Name        string
	Description string
	Severity    Severity
	Category    string // Category.Key

	// Languages this rule applies to (by LanguageSpec.ID). Empty = universal:
	// the rule runs against files of every language (e.g. hardcoded secrets).
	Languages []string

	// Detect is the per-file detector. It receives the file's display path and
	// its already-loaded lines (the same slice the parser used).
	Detect func(filePath string, lines []string) []Finding

	// ProjectDetect is an optional whole-project pass (e.g. scan plist/manifest
	// files, or assert a key is absent repo-wide). Called once with the repo root.
	ProjectDetect func(repoPath string) []Finding

	// ProjectOnly marks a rule whose findings come solely from ProjectDetect;
	// Detect may be nil. Used so the runner skips it in the per-file phase.
	ProjectOnly bool
}

// AppliesToLanguage reports whether this rule should run for a given language.
func (r Rule) AppliesToLanguage(langID string) bool {
	if len(r.Languages) == 0 {
		return true // universal
	}
	for _, l := range r.Languages {
		if l == langID {
			return true
		}
	}
	return false
}

// RuleResult bundles a rule with its (capped) findings and the uncapped total.
type RuleResult struct {
	Rule       Rule
	Findings   []Finding
	TotalCount int // uncapped, used for density scoring
}

// Passed reports whether the rule produced no findings.
func (rr RuleResult) Passed() bool { return rr.TotalCount == 0 }

// CategoryScore is one category's contribution to the index.
type CategoryScore struct {
	Category     Category
	CheckCount   int     // rules defined for this category that ran
	Violations   int     // uncapped total across the category's rules
	RiskFraction float64 // 0..1 (density / (density + C))
	Points       int     // RiskFraction * Category.Weight, rounded
}

// NotAssessed is true when no rules backed this category.
func (cs CategoryScore) NotAssessed() bool { return cs.CheckCount == 0 }

// RiskPercent is the 0..100 risk for per-category bars.
func (cs CategoryScore) RiskPercent() int { return int(cs.RiskFraction*100 + 0.5) }

// Score is the whole-project security index.
type Score struct {
	Total      int             // 0..1000 (higher = more risk)
	Categories []CategoryScore // ordered by Category.ID
	Band       string          // "Hardened" | "Minor exposure" | "Elevated risk" | "Critical exposure"
}

// bandFor returns the band label for a 0..1000 total.
func bandFor(total int) string {
	switch {
	case total < 200:
		return "Hardened"
	case total < 500:
		return "Minor exposure"
	case total < 800:
		return "Elevated risk"
	default:
		return "Critical exposure"
	}
}
