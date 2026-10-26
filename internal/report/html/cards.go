package html

// cards.go draws the report's cards from report.Cards — the one list the HTML
// document and the Markdown export both walk (see report/cards.go for how to
// add a card). A card backed by a report module is drawn generically from its
// panel; every other card registers its HTML renderer here.

import (
	"fmt"
	"strings"

	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules/speccoverage"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/report"
	"github.com/exey/archscope/internal/result"
	"github.com/exey/archscope/internal/scanner"
)

func init() {
	// One call per card, the HTML renderer and its Markdown twin side by side:
	// both are required (see report.Add), so a card cannot exist in one format only.

	// ── Global ──────────────────────────────────────────────────────────────
	report.Add("summary", func(c report.Ctx) string { return renderGlobalCards(c.Res) }, mdSummary)
	report.Add("culture", func(c report.Ctx) string { return renderProgrammingCulture(c.Res) }, mdCulture)
	report.Add("stack", func(c report.Ctx) string { return renderStackAndModules(c.Res) }, mdStack)
	report.Add("radar", func(c report.Ctx) string { return renderTechRadarSection(c.Res) }, mdRadar)
	report.Add("archgraph", func(c report.Ctx) string { return renderGlobalArchGraph(c.Res) }, mdArchGraph)
	report.Add("danger", func(c report.Ctx) string { return renderSecurityIndex(c.Res) }, mdDanger)
	report.Add("devops", func(c report.Ctx) string { return renderDevOpsSection(c.Res) }, mdDevOps)
	report.Add("openapi", func(c report.Ctx) string { return renderOpenAPISection(c.Res) }, mdOpenAPI)
	report.Add("vscode", func(c report.Ctx) string { return renderVSCodePathCard(c.Res.RootPath) }, nil)
	report.Add("contributions", func(c report.Ctx) string { return renderContributionsCard(c.Res) }, mdContributions)
	report.Add("infra", func(c report.Ctx) string { return renderInfraPlatforms(c.Res.K8sLint) }, mdInfra)

	// ── Per platform ────────────────────────────────────────────────────────
	report.Add("overview", renderOverviewCard, mdOverview)
	report.Add("architecture", renderArchitectureCard, mdArchitecture)
	report.Add("traffic", renderTrafficCard, mdTraffic)
	report.Add("hotspots", func(c report.Ctx) string { return renderHotspots(c.Res, c.PG) }, mdHotspots)
	report.Add("microservices", func(c report.Ctx) string {
		return renderMicroservicesSection(c.PG, c.Files, c.Res.Scan.RenderModules)
	}, mdMicroservices)
	report.Add("todos", func(c report.Ctx) string { return renderTodosFixmes(c.Files) }, mdTodos)
	report.Add("longestfuncs", func(c report.Ctx) string {
		return renderLongestFunctions(c.Files, c.Res.RootPath, c.PG.Platform)
	}, mdLongestFuncs)
	report.Add("biggesttypes", func(c report.Ctx) string {
		return renderBiggestTypes(c.Files, c.Res.RootPath, c.PG.Platform)
	}, mdBiggestTypes)
	report.Add("git", func(c report.Ctx) string { return renderPlatformGit(c.Res, c.PG, c.Files, c.Badge) }, mdGit)
	report.Add("security", func(c report.Ctx) string { return renderPlatformSecurity(c.Res, c.PG.Platform, c.Badge) }, mdSecurity)
	report.Add("moduledetails", func(c report.Ctx) string {
		if !c.Res.Scan.RenderModules {
			return ""
		}
		return renderModuleDetailsPlatform(c.Res.RootPath, c.Files, c.Badge)
	}, mdModuleDetails)
	report.Add("penetration", nil, mdPenetration)
}

// renderOverviewCard is the row of size cards at the top of a platform panel.
func renderOverviewCard(c report.Ctx) string {
	lines, decls := 0, 0
	for _, f := range c.Files {
		lines += f.LineCount
		decls += len(f.Declarations)
	}
	var b strings.Builder
	b.WriteString(`<div class="as-cards">`)
	card(&b, fmtNum(c.PG.FileCount), "files", false)
	card(&b, fmtNum(lines), "lines", false)
	card(&b, fmtNum(decls), "declarations", false)
	card(&b, fmtNum(len(c.PG.Modules)), plural(len(c.PG.Modules), "module", "modules"), false)
	b.WriteString(`</div>`)
	return b.String()
}

// mdOverview is the platform's stats line: the size cards plus what the card
// header adds — APIs, the architecture chip and the Programming Culture level.
func mdOverview(c report.Ctx) string {
	lines, decls := 0, 0
	for _, f := range c.Files {
		lines += f.LineCount
		decls += len(f.Declarations)
	}
	parts := []string{
		fmt.Sprintf("**%s files**", fmtNum(c.PG.FileCount)),
		fmt.Sprintf("**%s lines**", fmtNum(lines)),
		fmt.Sprintf("**%s declarations**", fmtNum(decls)),
		fmt.Sprintf("**%d %s**", len(c.PG.Modules), plural(len(c.PG.Modules), "module", "modules")),
	}
	hs := platformHeaderStats(c.Res)[c.PG.Platform]
	if hs.apiTotal > 0 {
		parts = append(parts, fmt.Sprintf("%d APIs", hs.apiTotal))
	}
	if l := hs.archLabel(); l != "" {
		parts = append(parts, l)
	}
	if lv, ok := platformCultureLevels(c.Res)[c.PG.Platform]; ok {
		parts = append(parts, "🔰 "+lv.name)
	}
	return strings.Join(parts, " · ") + "\n"
}

// renderGlobalCardList walks the Global cards in order.
func renderGlobalCardList(res *result.AnalysisResult) string {
	var b strings.Builder
	for _, card := range report.CardsOf(report.Global) {
		b.WriteString(report.HTML(report.Ctx{Res: res, Card: card}))
	}
	return b.String()
}

// renderPlatformCards walks the Platform cards in order. Consecutive cards that
// share an HTMLGroup are wrapped in that group's frame (🧠 Programming Methods,
// 💡 Module Insights), which is left out when none of them has anything to show.
// Module panels no card claims follow, so a module added without a Card still
// appears.
func renderPlatformCards(res *result.AnalysisResult, pg *scanner.PlatformGroup, files []*parser.ParsedFile, badge string) string {
	cards := report.CardsOf(report.Platform)
	var b strings.Builder
	for i := 0; i < len(cards); {
		c := cards[i]
		if c.HTMLGroup == "" {
			b.WriteString(renderPlatformCard(res, pg, files, c, badge))
			i++
			continue
		}
		j := i
		var inner strings.Builder
		for ; j < len(cards) && cards[j].HTMLGroup == c.HTMLGroup; j++ {
			inner.WriteString(renderPlatformCard(res, pg, files, cards[j], ""))
		}
		if inner.Len() > 0 {
			b.WriteString(wrapHTMLGroup(c.HTMLGroup, badge, inner.String()))
		}
		i = j
	}
	b.WriteString(renderModulePanels(report.UnclaimedPanels(res, pg.Platform)))
	return b.String()
}

func renderPlatformCard(res *result.AnalysisResult, pg *scanner.PlatformGroup, files []*parser.ParsedFile, c report.Card, badge string) string {
	ctx := report.Ctx{Res: res, PG: pg, Files: files, Badge: badge, Card: c}
	if c.Module == "" {
		return report.HTML(ctx)
	}
	p, ok := ctx.Panel()
	if !ok || strings.TrimSpace(p.HTML) == "" {
		return ""
	}
	if c.Style == report.StyleInsight {
		icon, title := splitIcon(c.Title)
		return fmt.Sprintf(`<div class="as-section" id="%s"><div class="as-section__head"><span class="ico">%s</span><h3>%s</h3></div>%s</div>`,
			esc(modPanelID(p.Platform, p.ModuleID)), esc(icon), esc(title), p.HTML)
	}
	return renderModulePanels([]result.ModulePanel{p}, badge)
}

// wrapHTMLGroup frames a group of cards with its heading.
func wrapHTMLGroup(group, badge, inner string) string {
	icon, title := splitIcon(report.GroupTitles[group])
	switch group {
	case "methods":
		return fmt.Sprintf(`<div class="as-pm"><div class="as-pm__head">%s<span class="ico">%s</span><h3>%s</h3></div>%s</div>`, badge, esc(icon), esc(title), inner)
	default:
		return fmt.Sprintf(`<div class="as-insights"><div class="as-insights__head">%s<span class="ico">%s</span><h3>%s</h3></div><div class="as-insights-grid">%s</div></div>`,
			badge, esc(icon), esc(title), inner)
	}
}

// splitIcon splits "💡 Module Insights" into its emoji and its words.
func splitIcon(title string) (icon, text string) {
	if i := strings.IndexByte(title, ' '); i > 0 {
		return title[:i], title[i+1:]
	}
	return "", title
}

// renderArchitectureCard is the 🏛️ Architecture card: layers, components, versions.
func renderArchitectureCard(c report.Ctx) string {
	res, pg, files := c.Res, c.PG, c.Files
	lp := pg.LanguagePlatform
	if lp == "" {
		lp = pg.Platform
	}
	layersHTML := renderArchLayers(files)
	componentsHTML := renderArchComponents(files, buildTechSet(res, files))
	versionsHTML := renderArchVersions(res.Scan.Versions[lp])
	if layersHTML == "" && componentsHTML == "" && versionsHTML == "" {
		return ""
	}
	return fmt.Sprintf(`<div class="as-section" id="%s"><div class="as-section__head">%s<span class="ico">🏛️</span><h3>Architecture</h3></div>`,
		esc(cultAnchorID("arch", pg.Platform)), c.Badge) + layersHTML + componentsHTML + versionsHTML + `</div>`
}

// renderTrafficCard is the 🛜 Traffic card, with its SPEC COV column when the
// platform also has a spec-coverage panel.
func renderTrafficCard(c report.Ctx) string {
	var traffic []result.ModulePanel
	var specRes *speccoverage.Result
	for _, p := range c.Res.PanelsForPlatform(c.PG.Platform) {
		switch p.ModuleID {
		case "traffic":
			traffic = append(traffic, p)
		case "speccoverage":
			if r, ok := p.RawResult.(speccoverage.Result); ok && specRes == nil {
				specRes = &r
			}
		}
	}
	if len(traffic) == 0 {
		return ""
	}
	return renderTrafficWithSpec(traffic, specRes, c.Badge, langspec.Default.IsClientPlatform(c.PG.Platform))
}
