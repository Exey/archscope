package constructs

import (
	"fmt"
	"html"
	"math"
	"path/filepath"
	"sort"
	"strings"
)

// crap.go is the 🧨 CRAP risk subcard, after crapkit (Change Risk Anti-Patterns,
// Savoia & Evans 2007):
//
//	CRAP = ccn² × (1 − cov)³ + ccn          the function's complexity, discounted by its tests
//	risk = ccn × churn weight               how much recent change a complex function sits in
//
// crapkit ranks its worklist by risk, and so does this card: a complex function in
// a file nobody touches is dormant, a moderately complex one in the file edited
// every week is where the next bug is. Coverage, read from the project's own
// artifacts when present, shows in CRAP and the tooltip; it does not move the rank.
// A function whose risk reaches CrapRiskThreshold must carry a doc comment.

// CrapRiskThreshold is the risk from which a function needs a doc comment.
const CrapRiskThreshold = 5.5

const crapTopN = 20

// CrapFunc is one scored function.
type CrapFunc struct {
	Symbol, FilePath string
	Line, EndLine    int // 1-based, inclusive
	LOC, CCN         int

	Churn      float64 // churn weight of the file (see crap_churn.go)
	Commits    int     // commits behind it
	ChurnKnown bool    // false: no git history, weight 1
	Cov        float64 // 0–1 line coverage of the function's span
	CovState   string  // "measured" | "no data" (artifact silent on these lines) | "not in artifact" | "no artifact"
	CovSource  string
	CovCovered int
	CovTotal   int

	Risk, CRAP float64
	Documented bool
}

// Why is the tooltip: every number behind the risk score.
func (f CrapFunc) Why() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s — %d lines (%d–%d)\n", f.Symbol, f.LOC, f.Line, f.EndLine)
	fmt.Fprintf(&b, "Complexity: cyclomatic %d (decision points + 1)\n", f.CCN)
	if f.ChurnKnown {
		fmt.Fprintf(&b, "Churn: weight %.2f from %d commit(s) touching the file in the last %d months — recent commits weigh most\n", f.Churn, f.Commits, crapChurnMonths)
	} else {
		b.WriteString("Churn: no git history here — weight 1\n")
	}
	fmt.Fprintf(&b, "Risk = %d × %.2f = %.1f", f.CCN, f.Churn, f.Risk)
	if f.Risk >= CrapRiskThreshold {
		fmt.Fprintf(&b, "  (≥ %.1f: needs a doc comment)", CrapRiskThreshold)
	}
	b.WriteString("\n")
	switch f.CovState {
	case "measured":
		fmt.Fprintf(&b, "Coverage: %d of %d measured lines ran (%d%%) · %s\n", f.CovCovered, f.CovTotal, int(f.Cov*100+0.5), f.CovSource)
	case "no data":
		b.WriteString("Coverage: the artifact has no measured line in this function — counted as 0%\n")
	case "not in artifact":
		b.WriteString("Coverage: the file is not in the coverage artifact (no test imports it) — counted as 0%\n")
	default:
		b.WriteString("Coverage: no coverage artifact found (pass --coverage <file>) — counted as 0%\n")
	}
	fmt.Fprintf(&b, "CRAP = %d² × (1 − %.2f)³ + %d = %.1f", f.CCN, f.Cov, f.CCN, f.CRAP)
	if !f.Documented {
		b.WriteString("\nNo doc comment")
	}
	return b.String()
}

// CrapReport is the card's data.
type CrapReport struct {
	Total         int        // functions scored
	Risky         []CrapFunc // risk ≥ CrapRiskThreshold, worst first
	Top           []CrapFunc // the first crapTopN by risk
	UndocRisky    int        // …of Risky, without a doc comment
	CoverageFiles []string   // artifacts read
	ChurnKnown    bool       // a git history answered
	ChurnWindow   int        // commits in the window (largest repository)
}

// HasData reports whether the card has anything to show.
func (c CrapReport) HasData() bool { return c.Total > 0 }

// crapRaw is a function as the complexity pass sees it, before churn and coverage.
type crapRaw struct {
	symbol, path string
	line, end    int
	ccn          int
	doc          bool
}

// buildCrap joins the functions with churn and coverage and ranks them.
func buildCrap(raw []crapRaw) CrapReport {
	var rep CrapReport
	if len(raw) == 0 {
		return rep
	}
	roots := map[string]string{} // dir → repo root
	realDir := map[string]string{}
	tables := map[string]*churnTable{}
	rootSet := map[string]bool{}
	abs := make([]string, len(raw))
	baseFiles := map[string]map[string]bool{} // base name → the distinct files carrying it
	for i, f := range raw {
		dir := filepath.Dir(f.path)
		rd, ok := realDir[dir]
		if !ok {
			rd = dir
			if r, err := filepath.EvalSymlinks(dir); err == nil {
				rd = r
			}
			realDir[dir] = rd
		}
		abs[i] = filepath.Join(rd, filepath.Base(f.path))
		if baseFiles[filepath.Base(f.path)] == nil {
			baseFiles[filepath.Base(f.path)] = map[string]bool{}
		}
		baseFiles[filepath.Base(f.path)][abs[i]] = true
		if root := repoRootOf(roots, dir); root != "" {
			rootSet[root] = true
		}
	}
	for root := range rootSet {
		tables[root] = gitChurn(root, crapChurnMonths)
		if t := tables[root]; t != nil {
			rep.ChurnKnown = true
			if t.window > rep.ChurnWindow {
				rep.ChurnWindow = t.window
			}
		}
	}

	coverageMu.Lock()
	files := append([]string(nil), coveragePaths...)
	coverageMu.Unlock()
	seen := map[string]bool{}
	for _, p := range files {
		seen[p] = true
	}
	var roots2 []string
	for root := range rootSet {
		roots2 = append(roots2, root)
	}
	sort.Strings(roots2)
	for _, root := range roots2 {
		for _, p := range findCoverageFiles(root) {
			if !seen[p] {
				seen[p] = true
				files = append(files, p)
			}
		}
	}
	var cov *covIndex
	if len(files) > 0 {
		cov, rep.CoverageFiles = loadCoverage(files)
		if len(rep.CoverageFiles) == 0 {
			cov = nil
		}
	}

	rep.Total = len(raw)
	all := make([]CrapFunc, 0, len(raw))
	for i, f := range raw {
		root := roots[filepath.Dir(f.path)]
		fn := CrapFunc{Symbol: f.symbol, FilePath: f.path, Line: f.line, EndLine: f.end, LOC: f.end - f.line + 1, CCN: f.ccn, Documented: f.doc, Churn: 1}
		if t := tables[root]; t != nil && root != "" {
			if rel, err := filepath.Rel(root, abs[i]); err == nil {
				rel = filepath.ToSlash(rel)
				fn.Churn, fn.Commits, fn.ChurnKnown = t.weight[rel], t.commits[rel], true
			}
		}
		fn.CovState = "no artifact"
		if cov != nil {
			fn.CovState = "not in artifact"
			if fc := cov.lookup(abs[i], len(baseFiles[filepath.Base(f.path)]) == 1); fc != nil {
				fn.CovCovered, fn.CovTotal = fc.span(f.line, f.end)
				fn.CovSource = fc.source
				fn.CovState = "no data"
				if fn.CovTotal > 0 {
					fn.CovState = "measured"
					fn.Cov = float64(fn.CovCovered) / float64(fn.CovTotal)
				}
			}
		}
		u := 1 - fn.Cov
		fn.CRAP = float64(f.ccn*f.ccn)*u*u*u + float64(f.ccn)
		fn.Risk = math.Round(float64(f.ccn)*fn.Churn*100) / 100
		all = append(all, fn)
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		switch {
		case a.Risk != b.Risk:
			return a.Risk > b.Risk
		case a.CRAP != b.CRAP:
			return a.CRAP > b.CRAP
		case a.CCN != b.CCN:
			return a.CCN > b.CCN
		case a.FilePath != b.FilePath:
			return a.FilePath < b.FilePath
		}
		return a.Line < b.Line
	})
	for _, f := range all {
		if f.Risk >= CrapRiskThreshold {
			rep.Risky = append(rep.Risky, f)
			if !f.Documented {
				rep.UndocRisky++
			}
		}
	}
	rep.Top = all[:min(crapTopN, len(all))]
	return rep
}

// crapMini is the header tile: "50/1000" functions that need a doc comment and lack one.
func (c CrapReport) crapMini() (num, share string, pct int) {
	pct = 0
	if c.Total > 0 {
		pct = c.UndocRisky * 100 / c.Total
	}
	return fmt.Sprintf("%d/%d", c.UndocRisky, c.Total), fmt.Sprintf("risk ≥ %.1f, no doc comment", CrapRiskThreshold), pct
}

func (c CrapReport) hint() string {
	cov := "no coverage artifact found — counted as 0% (pass --coverage <file>, or run your tests with coverage first)"
	if len(c.CoverageFiles) > 0 {
		cov = "line coverage from " + strings.Join(c.CoverageFiles, ", ")
	}
	hist := "no git history: churn weight 1, so risk = complexity"
	if c.ChurnKnown {
		hist = fmt.Sprintf("churn over the last %d months (%d commits)", crapChurnMonths, c.ChurnWindow)
	}
	return fmt.Sprintf("Ranked by risk = complexity × churn weight (crapkit): a complex function in a file that keeps changing. CRAP = ccn²·(1−cov)³ + ccn shows what tests would save. Risk ≥ %.1f needs a doc comment. %s; %s.", CrapRiskThreshold, hist, cov)
}

// crapTitle names the subcard; its count is the functions at or above the risk threshold.
func crapTitle(c CrapReport) string {
	if len(c.Top) == 1 {
		return "CRAP risk — the function"
	}
	return fmt.Sprintf("CRAP risk — top %d functions", len(c.Top))
}

func covCell(f CrapFunc) string {
	if f.CovState == "measured" {
		return fmt.Sprintf("%d%%", int(f.Cov*100+0.5))
	}
	return "—"
}

func writeCrapSubcard(b *strings.Builder, c CrapReport) {
	if !c.HasData() {
		return
	}
	writeSubOpen(b, "crap", "🧨", crapTitle(c), len(c.Risky), c.hint())
	b.WriteString(`<table class="as-table as-cs__table"><thead><tr><th>#</th><th>Function</th><th>Lines</th><th>CCN</th><th>Churn</th><th>Cov</th><th>CRAP</th><th>Risk</th><th>Doc</th></tr></thead><tbody>`)
	for i, f := range c.Top {
		doc := `<span class="as-evo__d as-evo__d--up">✓</span>`
		if !f.Documented {
			doc = `<span class="as-evo__d as-evo__d--down">✗</span>`
		}
		churn := fmt.Sprintf("%.2f · %dc", f.Churn, f.Commits)
		if !f.ChurnKnown {
			churn = "—"
		}
		lines := occurrenceLink(fmt.Sprintf("%s:%d–%d", baseName(f.FilePath), f.Line, f.EndLine), f.FilePath, f.Line)
		fmt.Fprintf(b, `<tr title="%s"><td>%d</td><td class="mono">%s</td><td class="mono">%s <span class="as-count">%d LOC</span></td><td class="mono">%d</td><td class="mono">%s</td><td class="mono">%s</td><td class="mono">%.1f</td><td class="mono"><strong>%.1f</strong></td><td>%s</td></tr>`,
			html.EscapeString(f.Why()), i+1, occurrenceLink(f.Symbol, f.FilePath, f.Line), lines, f.LOC, f.CCN, churn, covCell(f), f.CRAP, f.Risk, doc)
	}
	b.WriteString(`</tbody></table>`)
	writeSubClose(b)
}

func writeCrapMarkdown(b *strings.Builder, c CrapReport) {
	if !c.HasData() {
		return
	}
	mdSubOpen(b, "🧨", crapTitle(c), len(c.Risky), c.hint())
	b.WriteString("| # | Function | Lines | CCN | Churn | Cov | CRAP | Risk | Doc | Why |\n|--:|----------|-------|----:|------:|----:|-----:|-----:|:---:|-----|\n")
	for i, f := range c.Top {
		doc := "✓"
		if !f.Documented {
			doc = "✗"
		}
		churn := fmt.Sprintf("%.2f (%dc)", f.Churn, f.Commits)
		if !f.ChurnKnown {
			churn = "—"
		}
		fmt.Fprintf(b, "| %d | %s | %s:%d–%d (%d LOC) | %d | %s | %s | %.1f | **%.1f** | %s | ccn %d × churn %.2f |\n",
			i+1, mdTableCell(f.Symbol), baseName(f.FilePath), f.Line, f.EndLine, f.LOC, f.CCN, churn, covCell(f), f.CRAP, f.Risk, doc, f.CCN, f.Churn)
	}
	b.WriteString("\n")
}
