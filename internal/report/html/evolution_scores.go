package html

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/exey/archscope/internal/evolution"
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules/constructs"
	"github.com/exey/archscope/internal/result"
	"github.com/exey/archscope/internal/security"
)

// CultureScores reads the Programming Culture scores of an analysis as plain
// evolution.Score values — the same numbers the 🔰 table shows — together with
// the raw metrics and the individual offenders behind each dimension, so an
// evolution report can say not just "Code Quality −1" but why and where. It is
// the ScoreFunc handed to result.RunEvolution, so "then" (a past commit) and
// "now" are scored by the exact same model.
func CultureScores(res *result.AnalysisResult) []evolution.Score {
	rank := make(map[string]int, len(devLevels))
	for i, d := range devLevels {
		rank[d.name] = i
	}
	pmap := make(map[string]langspec.Platform, len(res.Files))
	for _, f := range res.Files {
		pmap[f.FilePath] = langspec.Platform(f.Platform)
	}

	rows := cultureRows(res)
	out := make([]evolution.Score, 0, len(rows))
	for _, r := range rows {
		lv := levelFor(r.overall, r.design, r.quality, r.security, r.perf)
		sc := evolution.Score{
			Key: string(r.key), Label: r.label, Abbr: r.abbr, Lang: string(r.lang),
			IsDevOps: r.isDevOps, LOC: r.loc,
			Design: r.design, Quality: r.quality, Security: r.security, Perf: r.perf, Overall: r.overall,
			Level: lv.name, LevelRank: rank[lv.name],
		}
		if !r.isDevOps {
			sc.Metrics = cultureMetrics(r)
			sc.Items = cultureItems(res, r, pmap)
		}
		out = append(out, sc)
	}
	return out
}

// Dimension indexes into evolution.Dims.
const (
	dimDesign = 1 + iota
	dimQuality
	dimSecurity
	dimPerf
)

// cultureMetrics lists the raw signals behind each dimension of a row. A signal
// only appears when it applies to the platform, so then/now join on what both have.
func cultureMetrics(r cultureRow) []evolution.Metric {
	var m []evolution.Metric
	add := func(dim int, name string, v int, unit string, higherBetter bool) {
		m = append(m, evolution.Metric{Dim: dim, Name: name, Value: v, Unit: unit, HigherBetter: higherBetter})
	}

	// 🏛️ Design
	if r.dddScore > 0 {
		add(dimDesign, "Domain-model (DDD) score", r.dddScore, "%", true)
	} else if r.popScore > 0 {
		add(dimDesign, "Protocol-oriented (POP) score", r.popScore, "%", true)
	}
	if r.hasLangRichness {
		add(dimDesign, "Language richness", r.langRichness, "%", true)
	}
	add(dimDesign, "Architecture layers", r.archLayers, "", true)
	add(dimDesign, "Design patterns", r.patternCount, "", true)
	if r.hasCouplingCohesion {
		add(dimDesign, "Coupling score", r.couplingScore, "%", true)
		if r.hasCohesionData {
			add(dimDesign, "Cohesion score", r.cohesionScore, "%", true)
		}
	}

	// 🧹 Code Quality
	add(dimQuality, fmt.Sprintf("Long functions (>%d lines)", cultureLongFuncMinLines), r.godFuncs, "", false)
	add(dimQuality, "Longest function", r.maxFunc, " lines", false)
	add(dimQuality, "Big types", r.bigTypes, "", false)
	add(dimQuality, "Largest type", r.maxType, " lines", false)
	add(dimQuality, "TODO / FIXME", r.todos, "", false)
	add(dimQuality, "Data structures detected", r.dsCount, "", true)
	add(dimQuality, "Algorithms detected", r.algoCount, "", true)
	if r.csHasData {
		add(dimQuality, "Code-structure score", r.csScore, "%", true)
		add(dimQuality, "Review issues (bug / duplicate / shape / React)", r.reviewIssues, "", false)
		if r.hasDocs {
			add(dimQuality, "Documented public API", r.docPercent, "%", true)
		}
		if r.hasTyping {
			add(dimQuality, "Fully typed Python functions", r.typedPercent, "%", true)
		}
	}
	if r.hasDead {
		add(dimQuality, "Dead-code issues", r.deadTotal, "", false)
	}

	// 🛡️ Security
	add(dimSecurity, "HIGH findings", r.high, "", false)
	add(dimSecurity, "MEDIUM findings", r.med, "", false)
	if r.hasTrafficHealth {
		add(dimSecurity, "Traffic health", r.trafficHealthScore, "%", true)
	}

	// ⚡ Performance
	add(dimPerf, "O(N³)+ hotspots", r.n3, "", false)
	add(dimPerf, "O(N²) hotspots", r.n2, "", false)
	add(dimPerf, "Memory leaks (HIGH)", r.memLeaksHigh, "", false)
	add(dimPerf, "Memory leaks (MEDIUM)", r.memLeaksMed, "", false)
	if r.hasRegex {
		add(dimPerf, "Strings & Regex issues (HIGH)", r.regexHigh, "", false)
		add(dimPerf, "Strings & Regex issues (MEDIUM)", r.regexMed, "", false)
	}
	if r.hasConc {
		add(dimPerf, "Concurrency / API issues (HIGH)", r.concHigh, "", false)
		add(dimPerf, "Concurrency / API issues (MEDIUM)", r.concMed, "", false)
	}
	return m
}

// relPath is p relative to the scan root, slash-separated, so the same file has
// the same identity in the working tree and in a baseline extracted elsewhere.
func relPath(root, p string) string {
	if root != "" {
		if rel, err := filepath.Rel(root, p); err == nil && !strings.HasPrefix(rel, "..") {
			p = rel
		}
	}
	return filepath.ToSlash(p)
}

// cultureItems lists the individual offenders behind a row's dimensions — the
// same things the scores count: scored security findings, O(N²)+ hotspots,
// HIGH/MEDIUM memory leaks, long functions and types, deep nesting and
// parameter-heavy functions.
func cultureItems(res *result.AnalysisResult, r cultureRow, pmap map[string]langspec.Platform) []evolution.Item {
	root := ""
	if res.Scan != nil {
		root = res.Scan.Root
	}
	var items []evolution.Item
	seen := map[string]int{}
	add := func(it evolution.Item, base string) {
		n := seen[base]
		seen[base]++
		it.Key = base
		if n > 0 { // keep keys unique: a second identical offender in a file is a new item
			it.Key = fmt.Sprintf("%s#%d", base, n)
		}
		it.Rel = relPath(root, it.Path)
		items = append(items, it)
	}
	key := func(parts ...string) string { return strings.Join(parts, "|") }

	// 🛡️ Security findings counted by the score (HIGH and MEDIUM).
	for _, rr := range res.Security {
		weight, kind := 0, ""
		switch rr.Rule.Severity {
		case security.SevHigh:
			weight, kind = 7, "HIGH security"
		case security.SevMedium:
			weight, kind = 2, "MEDIUM security"
		default:
			continue
		}
		for _, f := range rr.Findings {
			if pmap[f.FullPath] != r.key || security.IsTestOrBenchPath(f.FullPath) {
				continue // tests are not scored (see computeCultureRow)
			}
			rel := relPath(root, f.FullPath)
			snippet := strings.Join(strings.Fields(f.Snippet), " ")
			if len(snippet) > 90 {
				snippet = snippet[:90] + "…"
			}
			add(evolution.Item{Dim: dimSecurity, Kind: kind, Name: rr.Rule.Name, Note: snippet,
				Path: f.FullPath, Line: f.Line, Weight: weight},
				key("sec", rr.Rule.ID, rel, snippet))
		}
	}

	// 🧹 Long functions and big types straight from the parsed files.
	for _, f := range res.FilesForPlatform(r.key) {
		if security.IsTestOrBenchPath(f.FilePath) {
			continue
		}
		rel := relPath(root, f.FilePath)
		for _, bf := range f.BigFunctions {
			if bf.LineCount > cultureLongFuncMinLines {
				add(evolution.Item{Dim: dimQuality, Kind: "Long function", Name: bf.Name,
					Note: fmt.Sprintf("%d lines", bf.LineCount), Path: bf.FilePath, Line: bf.StartLine,
					Size: bf.LineCount, Weight: 3}, key("fn", rel, bf.Name))
			}
		}
		for _, bt := range f.BigTypes {
			add(evolution.Item{Dim: dimQuality, Kind: "Big type", Name: bt.Name,
				Note: fmt.Sprintf("%d lines", bt.LineCount), Path: bt.FilePath, Line: bt.StartLine,
				Size: bt.LineCount, Weight: 2}, key("ty", rel, bt.Name))
		}
	}

	// Module-derived offenders.
	for _, p := range res.PanelsForPlatform(r.key) {
		switch v := p.RawResult.(type) {
		case constructs.CodeStructureReport:
			for _, o := range v.DeepNestFuncs {
				add(evolution.Item{Dim: dimQuality, Kind: "Deep nesting", Name: o.Symbol,
					Note: fmt.Sprintf("%d levels", o.Value), Path: o.FilePath, Line: o.Line,
					Size: o.Value, Weight: 2}, key("nest", relPath(root, o.FilePath), o.Symbol))
			}
			for _, o := range v.HighParamFuncs {
				add(evolution.Item{Dim: dimQuality, Kind: "Many parameters", Name: o.Symbol,
					Note: fmt.Sprintf("%d params", o.Value), Path: o.FilePath, Line: o.Line,
					Size: o.Value, Weight: 1}, key("params", relPath(root, o.FilePath), o.Symbol))
			}
			addIssues := func(kind string, set []constructs.CSIssue) {
				for _, o := range set {
					add(evolution.Item{Dim: dimQuality, Kind: kind, Name: o.Label(),
						Note: o.Snippet, Path: o.FilePath, Line: o.Line, Weight: issueWeight(o.Severity),
						AltPath: o.AltFile, AltRel: relPath(root, o.AltFile), AltLine: o.AltLine},
						key("cs", o.RuleID, relPath(root, o.FilePath), o.Snippet))
				}
			}
			addIssues("Suspicious code", v.BugIssues)
			addIssues("Duplicate code", v.DupIssues)
			addIssues("Shape limit", v.ShapeIssues)
			addIssues("Merge / diff marker", v.MarkerIssues)
			for _, o := range v.HighComplexity {
				w := 1
				if o.Value > 50 {
					w = 5
				} else if o.Value > 20 {
					w = 2
				}
				add(evolution.Item{Dim: dimQuality, Kind: "High complexity", Name: o.Symbol,
					Note: fmt.Sprintf("cyclomatic %d", o.Value), Path: o.FilePath, Line: o.Line, Size: o.Value, Weight: w},
					key("cc", relPath(root, o.FilePath), o.Symbol))
			}
			addIssues("React hooks & state", v.HookIssues)
			addIssues("React component", v.ReactIssues)
		case constructs.ComplexityReport:
			for _, viol := range v.TimeViolations {
				weight := 0
				switch {
				case viol.Order >= 3:
					weight = 7
				case viol.Order == 2:
					weight = 2
				default:
					continue
				}
				add(evolution.Item{Dim: dimPerf, Kind: bigOString(viol.Order), Name: viol.Symbol,
					Note: viol.Reason, Path: viol.FilePath, Line: viol.Line, Weight: weight},
					key("cx", relPath(root, viol.FilePath), viol.Symbol, fmt.Sprint(viol.Order)))
			}
		case constructs.RegexReport:
			for _, o := range v.Issues {
				add(evolution.Item{Dim: dimPerf, Kind: perfIssueKind(o, "Regex"), Name: o.Label(),
					Note: o.Snippet, Path: o.FilePath, Line: o.Line, Weight: issueWeight(o.Severity)},
					key("rx", o.RuleID, relPath(root, o.FilePath), o.Snippet))
			}
		case constructs.DeadCodeReport:
			for _, o := range v.Issues {
				add(evolution.Item{Dim: dimQuality, Kind: "Dead code", Name: o.Label(),
					Note: o.Snippet, Path: o.FilePath, Line: o.Line, Weight: issueWeight(o.Severity)},
					key("dc", o.RuleID, relPath(root, o.FilePath), o.Snippet))
			}
		case constructs.ConcurrencyReport:
			for _, o := range v.Issues {
				add(evolution.Item{Dim: dimPerf, Kind: "Concurrency / API", Name: o.Label(),
					Note: o.Snippet, Path: o.FilePath, Line: o.Line, Weight: issueWeight(o.Severity)},
					key("cc", o.RuleID, relPath(root, o.FilePath), o.Snippet))
			}
		case constructs.MemoryLeaksReport:
			for _, fd := range v.Findings {
				weight := 0
				switch fd.Severity {
				case security.SevHigh:
					weight = 7
				case security.SevMedium:
					weight = 2
				default:
					continue
				}
				add(evolution.Item{Dim: dimPerf, Kind: "Memory leak", Name: fd.Label,
					Path: fd.FilePath, Line: fd.Line, Weight: weight},
					key("ml", relPath(root, fd.FilePath), fd.RuleID))
			}
		}
	}
	return items
}

// issueWeight is a review item's weight: the same HIGH 7 / MEDIUM 2 scale the
// scored dimensions use, with unscored advice at 1.
func issueWeight(s security.Severity) int {
	switch s {
	case security.SevHigh:
		return 7
	case security.SevMedium:
		return 2
	}
	return 1
}

// perfIssueKind names a Regex-card item: the regex checks, or the Go
// performance idioms that share the card.
func perfIssueKind(o constructs.CSIssue, fallback string) string {
	if o.Group == "Strings" {
		return "String issue"
	}
	if o.Group != "" && o.Group != "Regex" {
		return o.Group
	}
	return fallback
}
