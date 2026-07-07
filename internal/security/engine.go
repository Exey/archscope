package security

import (
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// DefaultMaxFindingsPerRule caps stored findings per rule for display; the
// uncapped TotalCount is still tracked for scoring.
const DefaultMaxFindingsPerRule = 100

// densityConstant C in the saturating risk curve risk = density / (density + C).
const densityConstant = 2.0

// SourceFile is the minimal view of a file the engine needs: where it is and
// which language owns it (so language-scoped rules can be filtered).
type SourceFile struct {
	Path       string
	LanguageID string
}

// LineLoader loads a file's lines. The pipeline passes the same loader the
// parser used, so files are read once per phase.
type LineLoader interface {
	Load(filePath string) ([]string, error)
}

// Engine holds the rule table and runs analyses.
type Engine struct {
	mu    sync.RWMutex
	rules map[string]Rule // by ID

	// MaxFindingsPerRule caps stored findings; 0 means DefaultMaxFindingsPerRule.
	MaxFindingsPerRule int
	// MinSeverity filters out rules below this severity ("" = no filter).
	MinSeverity Severity
	// DisabledRules holds rule IDs to skip.
	DisabledRules map[string]bool
}

// NewEngine returns an engine with no rules registered.
func NewEngine() *Engine {
	return &Engine{
		rules:         map[string]Rule{},
		DisabledRules: map[string]bool{},
	}
}

// Default is the process-wide engine that rule packages populate via init().
var Default = NewEngine()

// RegisterRule adds or replaces a rule. Called from universal rule packages and
// from language files' init() functions.
func (e *Engine) RegisterRule(r Rule) {
	if r.ID == "" {
		panic("security: rule with empty ID")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules[r.ID] = r
}

// Rules returns all registered rules in stable order by ID.
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, 0, len(e.rules))
	for _, r := range e.rules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// activeRules returns rules that pass the disabled/min-severity filters.
func (e *Engine) activeRules() []Rule {
	all := e.Rules()
	out := all[:0:0]
	for _, r := range all {
		if e.DisabledRules[r.ID] {
			continue
		}
		if e.MinSeverity != "" && r.Severity.Rank() < e.MinSeverity.Rank() {
			continue
		}
		out = append(out, r)
	}
	return out
}

// Run executes every active rule against the files it applies to, plus the
// project-level pass, streaming each RuleResult through onComplete as it
// finishes (may be nil). It mirrors SecurityAnalyzer's phased design but is
// language-generic. Blame enrichment is added in a later milestone.
func (e *Engine) Run(files []SourceFile, loader LineLoader, repoPath string, onComplete func(RuleResult)) []RuleResult {
	maxFindings := e.MaxFindingsPerRule
	if maxFindings <= 0 {
		maxFindings = DefaultMaxFindingsPerRule
	}
	rules := e.activeRules()

	// ── Phase 1: load lines for each file once, grouped by language ──
	type loaded struct {
		path       string
		relPath    string // repo-root-relative (for SARIF uri); "" if unreachable
		languageID string
		lines      []string
	}
	all := make([]loaded, len(files))
	// Pre-compute relative paths (cheap string ops, no I/O) before the goroutines.
	for i := range files {
		rel, err := filepath.Rel(repoPath, files[i].Path)
		if err != nil || strings.HasPrefix(rel, "..") {
			rel = "" // falls back to displayPath in SARIF
		}
		all[i].relPath = filepath.ToSlash(rel)
	}
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	if workers > len(files) {
		workers = len(files)
	}
	work := make(chan int, len(files))
	for i := range files {
		work <- i
	}
	close(work)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range work {
				lines, err := loader.Load(files[i].Path)
				if err != nil {
					lines = nil
				}
				all[i].path = files[i].Path
				all[i].languageID = files[i].LanguageID
				all[i].lines = lines
			}
		}()
	}
	wg.Wait()

	// ── Phase 2: per-rule parallel scan ──
	results := make([]RuleResult, len(rules))
	var rwg sync.WaitGroup
	rwg.Add(len(rules))
	for ri := range rules {
		go func(ri int) {
			defer rwg.Done()
			rule := rules[ri]
			rr := RuleResult{Rule: rule}
			if !rule.ProjectOnly && rule.Detect != nil {
				for _, f := range all {
					if len(f.lines) == 0 || !rule.AppliesToLanguage(f.languageID) {
						continue
					}
					vs := rule.Detect(displayPath(f.path), f.lines)
					for k := range vs {
						vs[k].FullPath = f.path
						vs[k].RelPath = f.relPath
						vs[k].RuleID = rule.ID
					}
					rr.TotalCount += len(vs)
					if len(rr.Findings) < maxFindings {
						take := maxFindings - len(rr.Findings)
						if take > len(vs) {
							take = len(vs)
						}
						rr.Findings = append(rr.Findings, vs[:take]...)
					}
				}
			}
			results[ri] = rr
			if onComplete != nil && !rule.ProjectOnly {
				onComplete(rr)
			}
		}(ri)
	}
	rwg.Wait()

	// ── Phase 3: project-level pass (sequential) ──
	if repoPath != "" {
		for ri := range rules {
			rule := rules[ri]
			if rule.ProjectDetect == nil {
				continue
			}
			vs := rule.ProjectDetect(repoPath)
			for k := range vs {
				vs[k].RuleID = rule.ID
				if vs[k].FullPath == "" {
					vs[k].FullPath = filepath.Join(repoPath, vs[k].File)
				}
				if vs[k].RelPath == "" && vs[k].FullPath != "" {
					if rel, err := filepath.Rel(repoPath, vs[k].FullPath); err == nil && !strings.HasPrefix(rel, "..") {
						vs[k].RelPath = filepath.ToSlash(rel)
					}
				}
			}
			rr := results[ri]
			rr.TotalCount += len(vs)
			if len(rr.Findings) < maxFindings {
				take := maxFindings - len(rr.Findings)
				if take > len(vs) {
					take = len(vs)
				}
				rr.Findings = append(rr.Findings, vs[:take]...)
			}
			results[ri] = rr
			if onComplete != nil && rule.ProjectOnly {
				onComplete(rr)
			}
		}
	}

	return results
}

// RunWithScore runs all rules and also computes the 0..1000 index.
func (e *Engine) RunWithScore(files []SourceFile, loader LineLoader, repoPath string) (results []RuleResult, score Score) {
	results = e.Run(files, loader, repoPath, nil)
	score = e.ComputeScore(results, len(files))
	return
}

// ComputeScore aggregates results into per-category scores and the overall
// 0..1000 index. Each category contributes up to its weight; its contribution
// scales with a saturating function of weighted violation density (violations
// per scanned file). Categories with no rules are "not assessed" (0 points).
func (e *Engine) ComputeScore(results []RuleResult, fileCount int) Score {
	byCat := map[string][]RuleResult{}
	for _, r := range results {
		byCat[r.Rule.Category] = append(byCat[r.Rule.Category], r)
	}
	denom := float64(fileCount)
	if denom < 1 {
		denom = 1
	}

	var cats []CategoryScore
	total := 0
	for _, cat := range Categories { // ordered by ID
		rs := byCat[cat.Key]
		checkCount := len(rs)
		violations := 0
		weighted := 0.0
		for _, r := range rs {
			violations += r.TotalCount
			weighted += float64(r.TotalCount) * r.Rule.Severity.Weight()
		}

		risk := 0.0
		if checkCount > 0 && violations > 0 {
			density := weighted / denom
			risk = density / (density + densityConstant)
		}
		points := int(risk*float64(cat.Weight) + 0.5)

		// Each HIGH finding guarantees at least 1 point from its category,
		// so sparse HIGH issues (1-3 in a large codebase) always register.
		highViol := 0
		for _, r := range rs {
			if r.Rule.Severity == SevHigh {
				highViol += r.TotalCount
			}
		}
		if floor := min(highViol, cat.Weight); points < floor {
			points = floor
		}

		total += points

		cats = append(cats, CategoryScore{
			Category:     cat,
			CheckCount:   checkCount,
			Violations:   violations,
			RiskFraction: risk,
			Points:       points,
		})
	}
	if total < 0 {
		total = 0
	}
	if total > 1000 {
		total = 1000
	}
	return Score{Total: total, Categories: cats, Band: bandFor(total)}
}

// displayPath shortens an absolute path to its last few segments for display.
func displayPath(p string) string {
	parts := strings.Split(filepath.ToSlash(p), "/")
	if len(parts) > 3 {
		return strings.Join(parts[len(parts)-3:], "/")
	}
	return strings.TrimPrefix(filepath.ToSlash(p), "/")
}
