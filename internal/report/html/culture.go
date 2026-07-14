package html

// culture.go renders the global "🔰 Programming Culture" card: a heuristic
// seniority signal per language platform (and DevOps), read from four
// dimensions — Design/Architecture, Code Quality, Security, Performance — that
// are each derived from metrics already computed elsewhere in the report (DDD /
// OOP-vs-POP score, long functions & TODO density, HIGH security findings,
// Big-O complexity health). It is explicitly a conversation starter, not a
// verdict, and says so in the card. Below the table it summarises the highest-
// priority issues pulled from the Programming Methods detectors — worst
// algorithmic complexity first (O(N³)↑), then credential/database security
// findings — each a clickable VS Code deep link tagged with its platform.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules/arch"
	"github.com/exey/archscope/internal/modules/constructs"
	"github.com/exey/archscope/internal/modules/dddmodel"
	"github.com/exey/archscope/internal/modules/oopvspop"
	"github.com/exey/archscope/internal/modules/speccoverage"
	"github.com/exey/archscope/internal/result"
	"github.com/exey/archscope/internal/scanner"
	"github.com/exey/archscope/internal/security"
)

// minCultureLOC is the smallest a language platform can be and still get a
// Programming Culture row — below this, a handful of files can swing every
// dimension wildly, so the read isn't meaningful. DevOps is exempt (it has no
// LOC of its own; it's scored from the DevOps Health Score instead).
const minCultureLOC = 10000

// devLevel is one rung on the seniority ladder: the inclusive lower bound of
// the 0–100 overall culture score that lands on it, plus an optional minDim
// gate — the minimum every individual dimension (Design/Quality/Security/
// Performance) must clear to hold this level even if the weighted overall
// score qualifies. From Senior upward, levels are gated this way so one weak
// dimension (a security HIGH, a god function, a stray O(N³)) can't be averaged
// away by three excellent ones — the senior+ levels require genuinely
// consistent metrics, not just a high average.
type devLevel struct {
	name   string
	min    int
	minDim int // 0 = no per-dimension gate
	color  string
}

// devLevels is the ascending ladder. Between Trainee and Senior the Junior and
// Middle bands are each split with a +/− half-step for finer resolution where
// most real codebases sit.
var devLevels = []devLevel{
	{"Trainee", 0, 0, "#8a8f98"},
	{"Junior−", 20, 0, "#c0603a"},
	{"Junior", 32, 0, "#c78a2a"},
	{"Junior+ / Middle−", 44, 0, "#b3a12a"},
	{"Middle", 55, 0, "#4a9e5c"},
	{"Middle+ / Senior−", 63, 0, "#3a9e82"},
	{"Senior", 70, 61, "#2f8f8f"},
	{"Senior+ / Lead−", 77, 70, "#356f9e"},
	{"Lead", 84, 75, "#3a6ea5"},
	{"Architect", 93, 99, "#7d5ba6"},
}

// levelFor picks the highest level whose score threshold is met AND — for the
// gated top levels — whose weakest of the given dimension scores clears that
// level's minDim. dims is optional: pass none to skip dimension gating (used
// for the LOC-weighted repo-wide badge, where "one weak dimension" doesn't
// mean the same thing).
func levelFor(score int, dims ...int) devLevel {
	minDim := 100
	for _, d := range dims {
		if d < minDim {
			minDim = d
		}
	}
	l := devLevels[0]
	for _, d := range devLevels {
		if score < d.min {
			continue
		}
		if d.minDim > 0 && minDim < d.minDim {
			continue
		}
		l = d
	}
	return l
}

// cultureRow is one platform's (or DevOps') computed culture reading.
type cultureRow struct {
	key      langspec.Platform
	lang     langspec.Platform // for the color/abbr class
	label    string
	abbr     string
	loc      int
	isDevOps bool

	design, quality, security, perf, overall int

	// context surfaced in the unfoldable per-dimension detail

	// Design: base DDD/POP/arch/richness signal + 🎖️ Language Richness (a
	// separate line only when DDD/POP is also present) + Architecture Layers
	// + Design Patterns.
	dddScore, popScore, specReady int
	hasDesign, hasSpec            bool
	designBase                    int // base signal, 0–100, before layers/patterns
	designBaseWeight              int // 30 when DDD/POP drives Base, else 75
	langRichness                  int // raw keyword-coverage %, for display
	hasLangRichness               bool
	langRichnessScore             int // softened 0–100 score (same curve as Base)
	langRichnessWeight            int // 45 when DDD/POP + richness both present, else 0
	archLayers                    int // distinct architectural layers detected
	archLayerScore                int // 50 (<5 layers) or 100 (≥5)
	patternCount                  int // distinct deliberate (non-idiom) GoF patterns
	patternScore                  int // 0/30/70/100 per patternCount

	// Code Quality: Long Functions + Long Types + Data Structures + Algorithms
	// + "Other" (from 💻 Code Structure).
	godFuncs, maxFunc, todos int
	lfScore, lfWeight        int
	bigTypes, maxType        int
	ltScore, ltWeight        int
	hasDataStructures        bool
	dsScore                  int
	hasAlgorithms            bool
	algoScore                int
	csScore, csWeight        int
	csHasData                bool

	// Security: HIGH/MEDIUM findings out of every rule ArchScope checked.
	high, med, secTotalRules int

	// Performance.
	n3, n2 int
}

// clampInt bounds v to [lo, hi].
func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// cultureRows computes one row per language platform with enough LOC to be
// meaningful (see minCultureLOC), plus the DevOps row when present. Shared by
// renderProgrammingCulture (the ranking table) and renderTabs (the per-tab
// Code Level badge) so both read the exact same numbers.
func cultureRows(res *result.AnalysisResult) []cultureRow {
	platforms := res.Scan.PlatformsOrdered()

	// File → platform, for security attribution.
	pmap := make(map[string]langspec.Platform, len(res.Files))
	for _, f := range res.Files {
		pmap[f.FilePath] = langspec.Platform(f.Platform)
	}
	// Panels grouped by platform, for module-result lookup.
	panelsByPlat := map[langspec.Platform][]result.ModulePanel{}
	for _, p := range res.ModulePanels {
		panelsByPlat[p.Platform] = append(panelsByPlat[p.Platform], p)
	}

	// Platforms under minCultureLOC lines don't carry enough signal for a
	// meaningful seniority read (a handful of files can swing every dimension
	// wildly) — skip them. DevOps has no LOC of its own and is exempt.
	var rows []cultureRow
	for _, pg := range platforms {
		row := computeCultureRow(res, pg, panelsByPlat[pg.Platform], pmap)
		if row.loc < minCultureLOC {
			continue
		}
		rows = append(rows, row)
	}
	if dv, ok := computeDevOpsRow(res); ok {
		rows = append(rows, dv)
	}
	return rows
}

// cultureLevels maps each row's platform key to its computed devLevel.
func cultureLevels(rows []cultureRow) map[langspec.Platform]devLevel {
	m := make(map[langspec.Platform]devLevel, len(rows))
	for _, r := range rows {
		m[r.key] = levelFor(r.overall, r.design, r.quality, r.security, r.perf)
	}
	return m
}

// platformCultureLevels is the devLevel per language platform, keyed the same
// way as the 🗂️ Platforms tab cards — used to badge each tab with its
// Programming Culture level.
func platformCultureLevels(res *result.AnalysisResult) map[langspec.Platform]devLevel {
	return cultureLevels(cultureRows(res))
}

// renderProgrammingCulture builds the whole card, or "" when there is nothing
// to read (no language platforms).
func renderProgrammingCulture(res *result.AnalysisResult) string {
	rows := cultureRows(res)
	if len(rows) == 0 {
		return ""
	}

	// LOC-weighted overall repo level (language platforms only) — dimensions
	// are weighted-averaged the same way so the repo badge is gated too.
	var wSum, wDesign, wQuality, wSecurity, wPerf, locSum int
	for _, r := range rows {
		if r.isDevOps {
			continue
		}
		w := max(r.loc, 1)
		wSum += r.overall * w
		wDesign += r.design * w
		wQuality += r.quality * w
		wSecurity += r.security * w
		wPerf += r.perf * w
		locSum += w
	}
	repoOverall := 55
	repoDesign, repoQuality, repoSecurity, repoPerf := 55, 55, 55, 55
	if locSum > 0 {
		repoOverall = wSum / locSum
		repoDesign = wDesign / locSum
		repoQuality = wQuality / locSum
		repoSecurity = wSecurity / locSum
		repoPerf = wPerf / locSum
	}
	repoLevel := levelFor(repoOverall, repoDesign, repoQuality, repoSecurity, repoPerf)

	// Sort rows by level from top: highest rung first, ties broken by overall
	// score (also descending) so equally-levelled platforms still order
	// sensibly.
	rank := make(map[string]int, len(devLevels))
	for i, d := range devLevels {
		rank[d.name] = i
	}
	rowLevel := make(map[langspec.Platform]devLevel, len(rows))
	for _, r := range rows {
		rowLevel[r.key] = levelFor(r.overall, r.design, r.quality, r.security, r.perf)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		li, lj := rank[rowLevel[rows[i].key].name], rank[rowLevel[rows[j].key].name]
		if li != lj {
			return li > lj
		}
		return rows[i].overall > rows[j].overall
	})

	var b strings.Builder
	b.WriteString(`<div class="as-section as-culture">`)
	fmt.Fprintf(&b, `<div class="as-section__head"><span class="ico">🔰</span><h2>Programming Culture</h2>`+
		`<span class="as-cult-badge" style="background:%s22;color:%s;border-color:%s55" title="LOC-weighted repository level">%s</span></div>`,
		repoLevel.color, repoLevel.color, repoLevel.color, esc(repoLevel.name))
	b.WriteString(`<p class="as-section__sub">Heuristic seniority signal per language &amp; DevOps — read from Design/Architecture, Code Quality, Security, and Performance. A conversation starter, not a verdict. Sorted by level, highest first. Lead and Architect require strong scores across every dimension, not just a high average. Click any bar for how its score is computed.</p>`)

	// Table.
	b.WriteString(`<div class="as-cult-scroll"><table class="as-cult-table">`)
	b.WriteString(`<thead><tr>` +
		`<th>Platform</th><th>Code Level</th>` +
		`<th>🏛️ Design</th><th>🧹 Code Quality</th><th>🛡️ Security</th><th>⚡ Performance</th>` +
		`</tr></thead><tbody>`)
	// Platform → tab index in 🗂️ Platforms, so the platform name can jump
	// straight to its card (DevOps has no tab and is left unlinked).
	cardIdx := platformCardIndex(res)

	for _, r := range rows {
		lv := rowLevel[r.key]
		b.WriteString(`<tr>`)
		nameHTML := esc(r.label)
		if idx, ok := cardIdx[r.key]; ok {
			nameHTML = fmt.Sprintf(`<a class="as-cult-namelink" href="#p%d" data-platcard-link="%d" title="Jump to this platform in 🗂️ Platforms">%s</a>`,
				idx, idx, esc(r.label))
		}
		fmt.Fprintf(&b, `<td class="as-cult-plat"><span class="as-plat-badge as-plat-%s">%s</span><span class="as-cult-name">%s</span></td>`,
			esc(string(r.lang)), esc(r.abbr), nameHTML)
		fmt.Fprintf(&b, `<td><span class="as-cult-lvl" style="background:%s22;color:%s;border-color:%s55">%s</span></td>`,
			lv.color, lv.color, lv.color, esc(lv.name))
		writeDimCell(&b, r.design, designTip(r))
		writeDimCell(&b, r.quality, qualityTip(r))
		writeDimCell(&b, r.security, securityTip(r))
		writeDimCell(&b, r.perf, perfTip(r))
		b.WriteString(`</tr>`)
	}
	b.WriteString(`</tbody></table></div>`)

	// Priority issues from Programming Methods.
	platforms := res.Scan.PlatformsOrdered()
	pmap := make(map[string]langspec.Platform, len(res.Files))
	for _, f := range res.Files {
		pmap[f.FilePath] = langspec.Platform(f.Platform)
	}
	panelsByPlat := map[langspec.Platform][]result.ModulePanel{}
	for _, p := range res.ModulePanels {
		panelsByPlat[p.Platform] = append(panelsByPlat[p.Platform], p)
	}
	b.WriteString(renderCultureIssues(res, panelsByPlat, pmap, platforms))

	b.WriteString(`</div>`)
	return b.String()
}

// writeDimCell renders one dimension as an unfoldable mini-bar: the bar itself
// is always visible, click (or the native title hover) reveals how the score
// was computed — replacing the old, separate "how to read these metrics"
// legend with the explanation living right next to the number it explains.
// writeDimCell renders one dimension as an unfoldable mini-bar. detailHTML is
// pre-built markup (one <div> per formula component — see designTip/
// qualityTip/securityTip/perfTip) rendered as-is, not escaped: every value
// folded in is an internally-computed count or fixed English label, never
// scanned-repo content.
func writeDimCell(b *strings.Builder, v int, detailHTML string) {
	col := gradeColor(v)
	fmt.Fprintf(b, `<td class="as-cult-dim"><details class="as-cult-dimfold">`+
		`<summary title="Click for how this score is computed"><div class="as-cult-dimbar"><div class="as-cult-dimfill" style="width:%d%%;background:%s"></div></div><span class="as-cult-dimval">%d</span></summary>`+
		`<div class="as-cult-dimdetail">%s</div></details></td>`,
		v, col, v, detailHTML)
}

// ── per-platform computation ─────────────────────────────────────────────────

// archWeightPct and patternWeightPct are the Design dimension's fixed weights
// for the Architecture Layers and Design Patterns sub-signals. The rest of
// the budget goes to Base (DDD/POP score, arch-pattern confidence, 🎖️
// Language Richness, or a flat neutral value — whichever signal is
// available) plus, when a real DDD/POP score exists, a separate 🎖️ Language
// Richness line: DDD/POP is a stronger, more specific signal than a
// keyword-coverage count, so it keeps most of the weight (30%) while
// Richness still contributes (45%) rather than being dropped entirely.
// Without DDD/POP, Richness *is* Base (for TS/JS and any other language with
// a known keyword list but no domain-model detector) at the full 75%.
const (
	archWeightPct    = 10
	patternWeightPct = 15
	// designBaseWeightDefault is Base's weight whenever there's no DDD/POP
	// score to share the budget with.
	designBaseWeightDefault = 100 - archWeightPct - patternWeightPct // 75
	// designBaseWeightWithDDD is Base's (now DDD/POP-only) weight once 🎖️
	// Language Richness becomes a separate line; the remainder
	// (designBaseWeightDefault - designBaseWeightWithDDD) goes to Richness.
	designBaseWeightWithDDD = 30
)

// Code Quality's Data Structures and Algorithms sub-signals carry fixed
// weights; Long Functions and Long Types carry a *dynamic* weight — the more
// of them a platform has, the more that signal dominates the read — ranging
// between these bounds. Whatever weight is left over comes from 💻 Code
// Structure (comments, nesting, parameters, folder layout).
const (
	dsWeightPct              = 12
	algoWeightPct            = 8
	lfWeightMin, lfWeightMax = 10, 30
	ltWeightMin, ltWeightMax = 5, 15
)

// dynamicWeight scales linearly from lo at count=0 to hi at count>=capAt.
func dynamicWeight(count, capAt, lo, hi int) int {
	if count >= capAt {
		return hi
	}
	return lo + (hi-lo)*count/capAt
}

func computeCultureRow(res *result.AnalysisResult, pg *scanner.PlatformGroup, panels []result.ModulePanel, pmap map[string]langspec.Platform) cultureRow {
	lp := pg.LanguagePlatform
	if lp == "" {
		lp = pg.Platform
	}
	r := cultureRow{
		key:   pg.Platform,
		lang:  lp,
		label: pg.TabLabel(),
		abbr:  platAbbr(lp),
	}

	// Files for this platform → LOC, god functions, TODO density, biggest
	// func/type, and architecture-layer separation.
	platFiles := res.FilesForPlatform(pg.Platform)
	for _, f := range platFiles {
		r.loc += f.LineCount
		r.godFuncs += len(f.BigFunctions)
		r.bigTypes += len(f.BigTypes)
		r.todos += f.TodoCount + f.FixmeCount
		if f.LongestFunc != nil && f.LongestFunc.LineCount > r.maxFunc {
			r.maxFunc = f.LongestFunc.LineCount
		}
		if f.LongestType != nil && f.LongestType.LineCount > r.maxType {
			r.maxType = f.LongestType.LineCount
		}
	}
	r.archLayers = countArchLayers(platFiles)

	// Module-derived signals.
	dddOrPopSignal := -1    // DDD or POP score specifically, 0–100
	archPatternSignal := -1 // client arch-pattern confidence, 0–100
	for _, p := range panels {
		switch v := p.RawResult.(type) {
		case dddmodel.Result:
			if v.HasData() {
				r.dddScore = v.DDDScore
				r.hasDesign = true
				dddOrPopSignal = v.DDDScore
			}
		case oopvspop.Result:
			if v.HasData() && dddOrPopSignal < 0 {
				r.popScore = v.POPScore
				r.hasDesign = true
				dddOrPopSignal = v.POPScore
			}
		case arch.Result:
			if archPatternSignal < 0 && v.HasDetection() && len(v.Patterns) > 0 {
				archPatternSignal = int(v.Patterns[0].Confidence*100 + 0.5)
				r.hasDesign = true
			}
		case constructs.LanguageRichnessReport:
			if len(v.Entries) > 0 {
				r.langRichness = v.Entries[0].Percent
				r.hasLangRichness = true
			}
		case speccoverage.Result:
			if v.HasData() {
				r.specReady = v.SpecReady
				r.hasSpec = true
			}
		case constructs.DesignPatternResult:
			for _, m := range v.Matches {
				if !m.IsIdiom {
					r.patternCount++
				}
			}
		case constructs.Result: // datastructures
			r.hasDataStructures = v.HasDetection()
		case constructs.AlgorithmsResult:
			r.hasAlgorithms = v.HasDetection()
		case constructs.CodeStructureReport:
			r.csHasData = v.HasData()
			r.csScore = codeStructureScore(v, r.loc)
		case constructs.ComplexityReport:
			r.perf = v.TimeHealth
			for _, viol := range v.TimeViolations {
				switch {
				case viol.Order >= 3:
					r.n3++
				case viol.Order == 2:
					r.n2++
				}
			}
		}
	}

	// Security tally for this platform, plus the total rule count every
	// platform is checked against (repo-wide, language-independent — the
	// "out of N rules" denominator).
	r.secTotalRules = len(security.Default.Rules())
	for _, rr := range res.Security {
		for _, f := range rr.Findings {
			if pmap[f.FullPath] != pg.Platform {
				continue
			}
			switch rr.Rule.Severity {
			case security.SevHigh:
				r.high++
			case security.SevMedium:
				r.med++
			}
		}
	}

	// ── Design (0–100): Base + (sometimes) a separate 🎖️ Language Richness
	// line + Architecture Layers + Design Patterns — see the const doc above
	// for why Base's source/weight branches this way.
	softenSignal := func(raw int) int { return clampInt(30+raw*7/10, 5, 100) }
	if r.hasLangRichness {
		r.langRichnessScore = softenSignal(r.langRichness)
	}
	switch {
	case dddOrPopSignal >= 0 && r.hasLangRichness:
		r.designBase = softenSignal(dddOrPopSignal)
		r.designBaseWeight = designBaseWeightWithDDD
		r.langRichnessWeight = designBaseWeightDefault - designBaseWeightWithDDD
	case dddOrPopSignal >= 0:
		r.designBase = softenSignal(dddOrPopSignal)
		r.designBaseWeight = designBaseWeightDefault
	case r.hasLangRichness:
		// No DDD/POP (TS/JS and any other language with a keyword list but no
		// domain-model detector): Language Richness replaces Base entirely.
		r.designBase = r.langRichnessScore
		r.designBaseWeight = designBaseWeightDefault
	case archPatternSignal >= 0:
		r.designBase = softenSignal(archPatternSignal)
		r.designBaseWeight = designBaseWeightDefault
	default:
		r.designBase = 52
		r.designBaseWeight = designBaseWeightDefault
	}
	if r.archLayers >= 5 {
		r.archLayerScore = 100
	} else {
		r.archLayerScore = 50
	}
	switch {
	case r.patternCount >= 3:
		r.patternScore = 100
	case r.patternCount == 2:
		r.patternScore = 70
	case r.patternCount == 1:
		r.patternScore = 30
	default:
		r.patternScore = 0
	}
	r.design = clampInt(
		(r.designBase*r.designBaseWeight+r.langRichnessScore*r.langRichnessWeight+
			r.archLayerScore*archWeightPct+r.patternScore*patternWeightPct+50)/100,
		5, 100)

	// ── Code Quality (0–100): Long Functions (dynamic 10–30%) + Long Types
	// (dynamic 5–15%) + Data Structures (12%) + Algorithms (8%) + whatever
	// weight is left over, from 💻 Code Structure (comments, nesting,
	// parameters, folder layout) ──
	kloc := float64(r.loc) / 1000
	if kloc < 0.1 {
		kloc = 0.1
	}
	lfPen := float64(r.godFuncs) / kloc * 10
	switch {
	case r.maxFunc > 600:
		lfPen += 18
	case r.maxFunc > 300:
		lfPen += 9
	case r.maxFunc > 150:
		lfPen += 3
	}
	// TODO/FIXME backlog density folds into the Long Functions read — both are
	// "leaving things unfinished" signals and neither has its own component
	// in this breakdown.
	lfPen += float64(r.todos) / kloc * 2.5
	r.lfScore = clampInt(100-int(lfPen+0.5), 5, 100)
	r.lfWeight = dynamicWeight(r.godFuncs, 10, lfWeightMin, lfWeightMax)

	ltPen := float64(r.bigTypes) / kloc * 10
	switch {
	case r.maxType > 900:
		ltPen += 18
	case r.maxType > 450:
		ltPen += 9
	case r.maxType > 200:
		ltPen += 3
	}
	r.ltScore = clampInt(100-int(ltPen+0.5), 5, 100)
	r.ltWeight = dynamicWeight(r.bigTypes, 10, ltWeightMin, ltWeightMax)

	if r.hasDataStructures {
		r.dsScore = 100
	}
	if r.hasAlgorithms {
		r.algoScore = 100
	}
	r.csWeight = 100 - r.lfWeight - r.ltWeight - dsWeightPct - algoWeightPct

	r.quality = clampInt(
		(r.lfScore*r.lfWeight+r.ltScore*r.ltWeight+r.dsScore*dsWeightPct+r.algoScore*algoWeightPct+r.csScore*r.csWeight+50)/100,
		5, 100)

	// Security: absolute HIGH findings dominate (a single HIGH is a flag).
	r.security = clampInt(100-(r.high*7+r.med*2), 0, 100)

	// Performance: Big-O health, with an extra dent per O(N³)+ hotspot.
	perf := r.perf
	if perf == 0 && r.n2 == 0 && r.n3 == 0 {
		perf = 80 // no complexity panel / no loops → assume adequate
	}
	r.perf = clampInt(perf-r.n3*5, 0, 100)

	r.overall = overallScore(r.design, r.quality, r.security, r.perf)
	return r
}

// codeStructureScore folds 💻 Code Structure's signals (comment density,
// worst nesting depth, high-parameter functions, folder-layout smells) into a
// single 0–100 read for Code Quality's "Other" component.
func codeStructureScore(v constructs.CodeStructureReport, loc int) int {
	if !v.HasData() {
		return 70 // no signal either way — neutral, doesn't drag Code Quality down
	}
	kloc := float64(loc) / 1000
	if kloc < 0.1 {
		kloc = 0.1
	}
	pen := 0.0
	if v.CommentPercent < 5 {
		pen += 10
	}
	if v.WorstNest.Value > constructs.MaxNestDepth {
		pen += float64(v.WorstNest.Value-constructs.MaxNestDepth) * 4
	}
	pen += float64(len(v.HighParamFuncs)) / kloc * 5
	if v.HasFolderSmells() {
		pen += 8
	}
	return clampInt(100-int(pen+0.5), 0, 100)
}

func overallScore(design, quality, sec, perf int) int {
	return int(float64(design)*0.25 + float64(quality)*0.30 + float64(sec)*0.25 + float64(perf)*0.20 + 0.5)
}

// computeDevOpsRow reads a DevOps culture level from the DevOps/Kubernetes
// health already computed for the DevOps section.
func computeDevOpsRow(res *result.AnalysisResult) (cultureRow, bool) {
	lint := res.DevOpsLint
	k8s := res.K8sLint
	if (lint == nil || lint.Empty()) && (k8s == nil || k8s.Empty()) {
		return cultureRow{}, false
	}
	health, ok := devopsHealthScore(lint, k8s)
	if !ok {
		health = 70
	}
	r := cultureRow{
		key:       langspec.Platform("devops"),
		lang:      langspec.Platform("universal"),
		label:     "DevOps",
		abbr:      "Ops",
		isDevOps:  true,
		hasDesign: true,
	}
	// DevOps has no per-language dimensions; map its single health signal to the
	// config/security-shaped columns and leave performance neutral.
	r.design = health
	r.quality = health
	r.security = health
	r.perf = clampInt(health+5, 0, 100)
	r.overall = overallScore(r.design, r.quality, r.security, r.perf)
	return r, true
}

// ── dimension tooltips ───────────────────────────────────────────────────────

func designTip(r cultureRow) string {
	if r.isDevOps {
		return "<div>DevOps: IaC/config hygiene from the DevOps Health Score.</div>"
	}
	var base string
	switch {
	case r.dddScore > 0:
		base = fmt.Sprintf("DDD %d%%", r.dddScore)
	case r.popScore > 0:
		base = fmt.Sprintf("POP %d%%", r.popScore)
	case r.hasLangRichness && r.langRichnessWeight == 0:
		// No DDD/POP: 🎖️ Language Richness replaces Base entirely.
		base = fmt.Sprintf("🎖️ Richness %d%%", r.langRichness)
	case r.hasDesign:
		base = "arch confidence"
	default:
		base = "no signal"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<div>Base %d%% (%s → %d%% W)</div>", r.designBase, base, r.designBaseWeight)
	if r.langRichnessWeight > 0 {
		fmt.Fprintf(&b, "<div>🎖️ Richness %d%% (%d%% raw → %d%% W)</div>", r.langRichnessScore, r.langRichness, r.langRichnessWeight)
	}
	fmt.Fprintf(&b, "<div>Arch Layers %d%% (%d layer(s) → %d%% W)</div>", r.archLayerScore, r.archLayers, archWeightPct)
	fmt.Fprintf(&b, "<div>Design Patterns %d%% (%d pattern(s) → %d%% W).</div>", r.patternScore, r.patternCount, patternWeightPct)
	return b.String()
}

func qualityTip(r cultureRow) string {
	if r.isDevOps {
		return "<div>DevOps: static-analysis pass rate across Dockerfile/Compose/Helm.</div>"
	}
	return fmt.Sprintf(
		"<div>Long Func %d%% (%d god func), %d TODO/FIXME → %d%% W</div>"+
			"<div>Long Types %d%% (%d big type(s), longest %d lines → %d%% W)</div>"+
			"<div>Data Structures %d%% (%s → %d%% W)</div>"+
			"<div>Algorithms %d%% (%s → %d%% W)</div>"+
			"<div>Code Structure %d%% → %d%% W).</div>",
		r.lfScore, r.godFuncs, r.todos, r.lfWeight,
		r.ltScore, r.bigTypes, r.maxType, r.ltWeight,
		r.dsScore, boolWord(r.hasDataStructures, "≥1", "none"), dsWeightPct,
		r.algoScore, boolWord(r.hasAlgorithms, "≥1", "none"), algoWeightPct,
		r.csScore, r.csWeight)
}

func securityTip(r cultureRow) string {
	if r.isDevOps {
		return "<div>DevOps: security-context / privilege checks from the DevOps Health Score.</div>"
	}
	return fmt.Sprintf(
		"<div>%d/%d HIGH+MEDIUM findings out of every rule checked</div><div>(%d HIGH, %d MEDIUM)</div>"+
			"<div>A single HIGH is a red flag; 10+ suggests no SAST in CI.</div>",
		r.high+r.med, r.secTotalRules, r.high, r.med)
}

func perfTip(r cultureRow) string {
	if r.isDevOps {
		return "<div>DevOps: resource limits / budgets (neutral proxy).</div>"
	}
	return fmt.Sprintf(
		"<div>Big-O health, %d O(N³)+ and %d O(N²) hotspot(s)</div>"+
			"<div>Nested loops over large data suggest brute-force over hashing/indexing.</div>",
		r.n3, r.n2)
}

// boolWord picks whenTrue/whenFalse based on ok — a tiny helper so tooltip
// sentences read naturally instead of printing raw booleans.
func boolWord(ok bool, whenTrue, whenFalse string) string {
	if ok {
		return whenTrue
	}
	return whenFalse
}

// ── priority issues ──────────────────────────────────────────────────────────

// cultIssue is one clickable priority issue with its platform and location.
type cultIssue struct {
	rank    int // sort key: lower = shown first
	badge   string
	badgeCl string
	kind    string
	desc    string
	plat    string
	platCls langspec.Platform
	path    string
	line    int
}

// dbSecurityRule reports whether a rule ID is a credential / database-auth /
// injection issue — the "database without password" class the summary leads on.
func dbSecurityRule(id string) bool {
	for _, n := range []string{"hardcoded_credential", "dotenv_credentials", "sql_concat",
		"sql_string_interpolation", "sql_injection", "nosql_injection", "hardcoded_key",
		"hardcoded_byte_key", "insecure_data_storage"} {
		if strings.Contains(id, n) {
			return true
		}
	}
	return false
}

func renderCultureIssues(res *result.AnalysisResult, panelsByPlat map[langspec.Platform][]result.ModulePanel, pmap map[string]langspec.Platform, platforms []*scanner.PlatformGroup) string {
	// Platform key → display label + language class.
	labelOf := map[langspec.Platform]string{}
	langOf := map[langspec.Platform]langspec.Platform{}
	for _, pg := range platforms {
		labelOf[pg.Platform] = pg.TabLabel()
		lp := pg.LanguagePlatform
		if lp == "" {
			lp = pg.Platform
		}
		langOf[pg.Platform] = lp
	}

	var issues []cultIssue

	// 1) Complexity hotspots — O(N³)+ first, then O(N²).
	for plat, panels := range panelsByPlat {
		for _, p := range panels {
			cr, ok := p.RawResult.(constructs.ComplexityReport)
			if !ok {
				continue
			}
			for _, v := range cr.TimeViolations {
				if v.Order < 2 {
					continue
				}
				rank := 100 - v.Order // O(N³)=97 < O(N²)=98 → higher order first
				issues = append(issues, cultIssue{
					rank:    rank,
					badge:   bigOString(v.Order),
					badgeCl: "as-cult-io--perf",
					kind:    "Complexity",
					desc:    v.Symbol + " — " + v.Reason,
					plat:    labelOf[plat],
					platCls: langOf[plat],
					path:    v.FilePath,
					line:    v.Line,
				})
			}
		}
	}

	// 2) Credential / database-auth security findings (HIGH first).
	for _, rr := range res.Security {
		if !dbSecurityRule(rr.Rule.ID) {
			continue
		}
		base := 200
		if rr.Rule.Severity == security.SevHigh {
			base = 150
		}
		for _, f := range rr.Findings {
			plat := pmap[f.FullPath]
			issues = append(issues, cultIssue{
				rank:    base,
				badge:   string(rr.Rule.Severity),
				badgeCl: "as-cult-io--sec",
				kind:    "Security",
				desc:    rr.Rule.Name,
				plat:    labelOf[plat],
				platCls: langOf[plat],
				path:    f.FullPath,
				line:    f.Line,
			})
		}
	}

	if len(issues) == 0 {
		return `<div class="as-cult-issues"><div class="as-cult-issues__head">🔎 Priority Issues</div><p class="as-clean">✓ No O(N²)+ hotspots or credential/database security findings.</p></div>`
	}

	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].rank != issues[j].rank {
			return issues[i].rank < issues[j].rank
		}
		return issues[i].desc < issues[j].desc
	})

	const maxIssues = 18
	var b strings.Builder
	b.WriteString(`<div class="as-cult-issues"><div class="as-cult-issues__head">🔎 Priority Issues <span class="as-count">(from Programming Methods · worst first)</span></div>`)
	b.WriteString(`<div class="as-cult-issuelist">`)
	for i, is := range issues {
		if i == maxIssues {
			fmt.Fprintf(&b, `<div class="as-cult-more">… and %d more</div>`, len(issues)-maxIssues)
			break
		}
		loc := fmt.Sprintf("%s:%d", baseFile(is.path), is.line)
		if href := vscodeHref(is.path, is.line); href != "" {
			loc = fmt.Sprintf(`<a class="as-vs" href="%s" title="Open in VS Code">%s</a>`, esc(href), esc(loc))
		} else {
			loc = esc(loc)
		}
		platPill := ""
		if is.plat != "" {
			platPill = fmt.Sprintf(`<span class="as-plat-badge as-plat-%s">%s</span>`, esc(string(is.platCls)), esc(is.plat))
		}
		fmt.Fprintf(&b, `<div class="as-cult-io"><span class="as-cult-io-badge %s">%s</span>%s<span class="as-cult-io-desc">%s</span><span class="as-cult-io-loc">%s</span></div>`,
			is.badgeCl, esc(is.badge), platPill, esc(is.desc), loc)
	}
	b.WriteString(`</div></div>`)
	return b.String()
}

// bigOString renders a complexity order as its O-notation badge.
func bigOString(order int) string {
	switch {
	case order <= 1:
		return "O(N)"
	case order == 2:
		return "O(N²)"
	case order == 3:
		return "O(N³)"
	case order == 4:
		return "O(N⁴)"
	default:
		return "O(Nⁿ)"
	}
}

// baseFile returns the final path segment.
func baseFile(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}
