// Package arch is a universal architecture-pattern detector, generalized from
// ArchSwiftScope's ArchAnalyzer. It classifies files into layer roles by
// filename/path conventions (*ViewModel, *Repository, *UseCase, *Controller,
// *Reducer, …) — conventions shared across Swift, Kotlin, TS, Python, Go, Java,
// C#, … — and scores the common app architectures (MVVM and its variants,
// VIPER, VIP, RIBs, Clean, Redux, TCA, MVP, MVC, MV) from the populated roles.
//
// Language-specific import signals (e.g. ComposableArchitecture, SwiftUI) are
// kept as *additive* hints: present only for the languages that have them, they
// sharpen detection without making any pattern language-exclusive — except MV,
// which is intrinsically a SwiftUI idiom and stays gated on that import.
package arch

import (
	"fmt"
	"html"
	"sort"
	"strings"

	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
)

// confidenceThreshold is the minimum score for a pattern to be reported.
const confidenceThreshold = 0.15

func init() { modules.Default.Register(Module{}) }

// Module is the universal architecture detector.
type Module struct{}

func (Module) ID() string                       { return "architecture" }
func (Module) Title() string                    { return "Architecture" }
func (Module) AppliesTo(languageID string) bool { return true } // universal

// Health is how well-populated a role is.
type Health string

const (
	HealthPresent Health = "present"
	HealthWeak    Health = "weak"
	HealthMissing Health = "missing"
)

// RoleStats is the footprint of one architectural role.
type RoleStats struct {
	FileCount int
	LineCount int
	DeclCount int
	TopPaths  []string
}

func (r RoleStats) health() Health {
	if r.FileCount == 0 && r.DeclCount == 0 {
		return HealthMissing
	}
	if r.FileCount <= 1 && r.LineCount < 150 && r.DeclCount <= 1 {
		return HealthWeak
	}
	return HealthPresent
}

func (r RoleStats) total() int { return r.FileCount + r.DeclCount }

// Role is a labeled role within a detected pattern (for rendering).
type Role struct {
	Letter    string
	FullName  string
	FileCount int
	LineCount int
	DeclCount int
	Health    Health
	Detail    string
	Examples  []string
}

func role(letter, full string, s RoleStats, detail string) Role {
	return Role{
		Letter: letter, FullName: full,
		FileCount: s.FileCount, LineCount: s.LineCount, DeclCount: s.DeclCount,
		Health: s.health(), Detail: detail, Examples: s.TopPaths,
	}
}

// Pattern is one detected architecture pattern.
type Pattern struct {
	Name       string
	Confidence float64
	Roles      []Role
	Hint       string
}

// Component is a detected framework/library in use.
type Component struct {
	Name   string
	Detail string
	Icon   string
}

// LayerStat is one architectural layer in the backend (goscope-style) view.
type LayerStat struct {
	Name      string
	Icon      string
	FileCount int
	LineCount int
}

// Result is the module's analysis output. Mode is "client" (pattern detection)
// or "backend" (layered view), chosen from the language specs of the files.
type Result struct {
	Mode       string      // "client" | "backend"
	Patterns   []Pattern   // client mode
	Layers     []LayerStat // backend mode
	Components []Component
}

// HasDetection reports whether a pattern cleared the threshold (client mode) or
// any layer was classified (backend mode).
func (r Result) HasDetection() bool {
	if r.Mode == "backend" {
		return len(r.Layers) > 0
	}
	return len(r.Patterns) > 0 && r.Patterns[0].Confidence >= confidenceThreshold
}

// Analyze chooses the mode from the files' language specs, then either scores
// app-architecture patterns (client) or classifies layers (backend).
func (Module) Analyze(files []*parser.ParsedFile) any {
	imports := importSet(files)
	components := detectComponents(imports)
	if !clientFiles(files) {
		return Result{Mode: "backend", Layers: classifyLayers(files), Components: components}
	}

	rc := newRoleCounter(files)
	var pats []Pattern
	type cand struct {
		score float64
		build func() Pattern
	}
	cands := []cand{
		{rc.scoreTCA(imports), func() Pattern { return rc.buildTCA(imports) }},
		{rc.scoreVIP(), rc.buildVIP},
		{rc.scoreVIPER(), rc.buildVIPER},
		{rc.scoreRIBs(), rc.buildRIBs},
		{rc.scoreClean(), rc.buildClean},
		{rc.scoreRedux(imports), func() Pattern { return rc.buildRedux(imports) }},
		{rc.scoreMVVMC(), rc.buildMVVMC},
		{rc.scoreMVVMS(), rc.buildMVVMS},
		{rc.scoreMVVM(), rc.buildMVVM},
		{rc.scoreMVP(), rc.buildMVP},
		{rc.scoreMVC(imports), rc.buildMVC},
		{rc.scoreMV(imports), rc.buildMV},
	}
	for _, c := range cands {
		if c.score >= confidenceThreshold {
			p := c.build()
			p.Confidence = c.score
			pats = append(pats, p)
		}
	}
	sort.SliceStable(pats, func(i, j int) bool { return pats[i].Confidence > pats[j].Confidence })
	if len(pats) > 5 {
		pats = pats[:5]
	}
	return Result{Mode: "client", Patterns: pats, Components: components}
}

// clientFiles reports whether any file belongs to a client/UI language.
func clientFiles(files []*parser.ParsedFile) bool {
	for _, f := range files {
		if s := langspec.Default.Get(f.LanguageID); s != nil && s.Client {
			return true
		}
	}
	return false
}

// ── Backend layered view (goscope-style) ─────────────────────────────────────

const (
	layerAPI      = "API / Handlers"
	layerModels   = "Models / Schemas"
	layerServices = "Services / Domain"
	layerPersist  = "Persistence"
	layerAuth     = "Auth / Security"
	layerTasks    = "Jobs / Tasks"
	layerConfig   = "Config / Settings"
	layerCLI      = "CLI / Entry"
	layerInfra    = "Infrastructure / Utils"
	layerTests    = "Tests"
	layerOther    = "Other"
)

var layerOrder = []string{
	layerAPI, layerModels, layerServices, layerPersist, layerAuth,
	layerTasks, layerConfig, layerCLI, layerInfra, layerTests, layerOther,
}

var layerIcons = map[string]string{
	layerAPI: "🌐", layerModels: "📦", layerServices: "⚙️", layerPersist: "🗄️",
	layerAuth: "🔐", layerTasks: "⏱️", layerConfig: "🔧", layerCLI: "💻",
	layerInfra: "🧰", layerTests: "🧪", layerOther: "•",
}

// classifyLayers buckets backend files into architectural layers by path and
// filename conventions, returned in canonical order — a generalization of
// goscope's classifyGoFile across Go/Python/etc.
func classifyLayers(files []*parser.ParsedFile) []LayerStat {
	type bucket struct{ files, lines int }
	buckets := map[string]*bucket{}
	for _, f := range files {
		l := classifyLayer(f)
		b := buckets[l]
		if b == nil {
			b = &bucket{}
			buckets[l] = b
		}
		b.files++
		b.lines += f.LineCount
	}
	var out []LayerStat
	for _, name := range layerOrder {
		if b := buckets[name]; b != nil {
			out = append(out, LayerStat{Name: name, Icon: layerIcons[name], FileCount: b.files, LineCount: b.lines})
		}
	}
	return out
}

func classifyLayer(f *parser.ParsedFile) string {
	p := strings.ToLower(strings.ReplaceAll(f.FilePath, "\\", "/"))
	name := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		name = p[i+1:]
	}
	parts := strings.Split(p, "/")
	has := func(set ...string) bool {
		for _, part := range parts {
			for _, s := range set {
				if part == s {
					return true
				}
			}
		}
		return false
	}
	switch {
	case strings.Contains(name, "_test.") || strings.HasSuffix(name, ".test.ts") ||
		strings.HasSuffix(name, ".spec.ts") || has("test", "tests", "testdata", "__tests__"):
		return layerTests
	case f.LanguageID == "proto" || strings.HasSuffix(name, ".proto"):
		return layerAPI
	case name == "main.go" || name == "main.py" || name == "__main__.py" ||
		has("cmd", "cli", "command", "commands"):
		return layerCLI
	case has("config", "conf", "configuration", "settings", "constants"):
		return layerConfig
	case has("auth", "authentication", "authorization", "security", "jwt"):
		return layerAuth
	case has("handler", "handlers", "controller", "controllers", "api", "apis",
		"route", "routes", "router", "endpoint", "endpoints", "http", "rest",
		"transport", "views", "viewsets", "urls"):
		return layerAPI
	case has("model", "models", "entity", "entities", "domain", "schema",
		"schemas", "dto", "dtos"):
		return layerModels
	case has("repository", "repositories", "store", "stores", "dao", "persistence",
		"db", "database", "migrations", "orm"):
		return layerPersist
	case has("service", "services", "usecase", "usecases", "interactor", "logic"):
		return layerServices
	case has("task", "tasks", "job", "jobs", "worker", "workers", "queue", "celery"):
		return layerTasks
	case has("util", "utils", "helper", "helpers", "common", "pkg",
		"lib", "infra", "infrastructure", "middleware"):
		return layerInfra
	default:
		return layerOther
	}
}

// SummaryCards surfaces the top pattern (client) or layer count (backend) plus
// the framework count.
func (Module) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(Result)
	if !ok {
		return nil
	}
	var cards []modules.SummaryCard
	if r.Mode == "backend" {
		if len(r.Layers) > 0 {
			cards = append(cards, modules.SummaryCard{
				Num: fmt.Sprintf("%d", len(r.Layers)), Label: "layers",
			})
		}
	} else if r.HasDetection() {
		top := r.Patterns[0]
		cards = append(cards, modules.SummaryCard{
			Num: fmt.Sprintf("%d%%", int(top.Confidence*100+0.5)), Label: top.Name + " confidence",
		})
	}
	if len(r.Components) > 0 {
		cards = append(cards, modules.SummaryCard{
			Num: fmt.Sprintf("%d", len(r.Components)), Label: "frameworks",
		})
	}
	return cards
}

// RenderMarkdown renders the architecture result as markdown.
func (Module) RenderMarkdown(res any) string {
	r, ok := res.(Result)
	if !ok || !r.HasDetection() {
		return ""
	}
	var b strings.Builder
	if r.Mode == "backend" && len(r.Layers) > 0 {
		b.WriteString("#### Layers\n\n")
		b.WriteString("| Layer | Files | Lines |\n")
		b.WriteString("|-------|------:|------:|\n")
		for _, l := range r.Layers {
			fmt.Fprintf(&b, "| %s %s | %d | %s |\n",
				l.Icon, l.Name, l.FileCount, fmtNumMD(l.LineCount))
		}
		b.WriteString("\n")
	} else if r.Mode == "client" && len(r.Patterns) > 0 {
		b.WriteString("#### Patterns\n\n")
		b.WriteString("| Pattern | Confidence |\n")
		b.WriteString("|---------|----------:|\n")
		for _, p := range r.Patterns {
			if p.Confidence >= confidenceThreshold {
				fmt.Fprintf(&b, "| %s | %.0f%% |\n", p.Name, p.Confidence*100)
			}
		}
		b.WriteString("\n")
	}
	if len(r.Components) > 0 {
		b.WriteString("#### Components\n\n")
		for _, c := range r.Components {
			if c.Detail != "" {
				fmt.Fprintf(&b, "- %s **%s** — %s\n", c.Icon, c.Name, c.Detail)
			} else {
				fmt.Fprintf(&b, "- %s **%s**\n", c.Icon, c.Name)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

// fmtNumMD formats an integer with comma thousands separators.
func fmtNumMD(n int) string {
	s := fmt.Sprintf("%d", n)
	if n < 1000 {
		return s
	}
	var out []byte
	for i, ch := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(ch))
	}
	return string(out)
}

// RenderHTML renders the architecture panel: detected patterns with their
// role breakdown and a confidence bar, plus the framework component list.
func (Module) RenderHTML(res any) string {
	r, ok := res.(Result)
	if !ok {
		return ""
	}
	if r.Mode == "backend" {
		return renderBackend(r)
	}
	var b strings.Builder
	if !r.HasDetection() {
		b.WriteString(`<p class="as-empty">No dominant architecture pattern detected from file/role conventions.</p>`)
	}
	for i, p := range r.Patterns {
		if p.Confidence < confidenceThreshold {
			continue
		}
		primary := ""
		if i == 0 {
			primary = " as-arch__pattern--primary"
		}
		pct := int(p.Confidence*100 + 0.5)
		fmt.Fprintf(&b, `<div class="as-arch__pattern%s">`, primary)
		fmt.Fprintf(&b,
			`<div class="as-arch__head"><span class="as-arch__name">%s</span><span class="as-arch__pct">%d%%</span></div>`,
			esc(p.Name), pct)
		fmt.Fprintf(&b, `<div class="as-bar"><span class="as-bar__fill" style="width:%d%%"></span></div>`, pct)
		if p.Hint != "" {
			fmt.Fprintf(&b, `<p class="as-arch__hint">%s</p>`, esc(p.Hint))
		}
		if len(p.Roles) > 0 {
			b.WriteString(`<div class="as-arch__roles">`)
			for _, role := range p.Roles {
				fmt.Fprintf(&b, `<div class="as-arch__role" data-health="%s" title="%s">`,
					string(role.Health), esc(role.FullName))
				fmt.Fprintf(&b, `<span class="as-arch__letter">%s</span>`, esc(role.Letter))
				fmt.Fprintf(&b, `<span class="as-arch__role-name">%s</span>`, esc(role.FullName))
				fmt.Fprintf(&b, `<span class="as-arch__role-detail">%s</span>`, esc(role.Detail))
				b.WriteString(`</div>`)
			}
			b.WriteString(`</div>`)
		}
		b.WriteString(`</div>`)
	}
	if len(r.Components) > 0 {
		b.WriteString(`<div class="as-arch__components"><h5 class="as-sub">📚 Frameworks &amp; libraries</h5><div class="as-arch__component-grid">`)
		for _, c := range r.Components {
			fmt.Fprintf(&b,
				`<div class="as-arch__component"><span class="as-arch__component-icon">%s</span><span class="as-arch__component-body"><strong>%s</strong><em>%s</em></span></div>`,
				esc(c.Icon), esc(c.Name), esc(c.Detail))
		}
		b.WriteString(`</div></div>`)
	}
	return b.String()
}

func esc(s string) string { return html.EscapeString(s) }

// renderBackend renders the goscope-style layered architecture view: a Layers
// column (proportional bars) and a Components column (detected frameworks).
func renderBackend(r Result) string {
	if len(r.Layers) == 0 && len(r.Components) == 0 {
		return `<p class="as-empty">No backend layers detected from file conventions.</p>`
	}
	maxLines := 1
	for _, l := range r.Layers {
		if l.LineCount > maxLines {
			maxLines = l.LineCount
		}
	}
	var b strings.Builder
	b.WriteString(`<p class="as-arch__hint">Layered view (backend language): files grouped into architectural layers by path &amp; naming conventions.</p>`)
	b.WriteString(`<div class="as-archcols">`)

	// Layers column.
	b.WriteString(`<div class="as-archcol"><h5 class="as-sub">🥞 Layers</h5><div class="as-layers">`)
	for _, l := range r.Layers {
		pct := l.LineCount * 100 / maxLines
		if pct < 4 {
			pct = 4
		}
		fmt.Fprintf(&b,
			`<div class="as-layer"><div class="as-layer__row"><span class="as-layer__icon">%s</span><span class="as-layer__name">%s</span><span class="as-layer__count">%d files · %s loc</span></div><div class="as-bar"><span class="as-bar__fill" style="width:%d%%"></span></div></div>`,
			esc(l.Icon), esc(l.Name), l.FileCount, fmtNum(l.LineCount), pct)
	}
	b.WriteString(`</div></div>`)

	// Components column.
	b.WriteString(`<div class="as-archcol"><h5 class="as-sub">🧩 Components</h5>`)
	if len(r.Components) == 0 {
		b.WriteString(`<p class="as-empty">No frameworks detected.</p>`)
	} else {
		b.WriteString(`<div class="as-comps">`)
		for _, c := range r.Components {
			fmt.Fprintf(&b, `<div class="as-comp"><span class="as-comp__icon">%s</span><span><strong>%s</strong> <em>%s</em></span></div>`,
				esc(c.Icon), esc(c.Name), esc(c.Detail))
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div></div>`)
	return b.String()
}

func fmtNum(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	return fmt.Sprintf("%.1fk", float64(n)/1000.0)
}

// ── Role counter ─────────────────────────────────────────────────────────────

type roleCounter struct {
	model, view, viewController, viewModel, presenter, interactor RoleStats
	router, coordinator, entity, builder, feature, reducer        RoleStats
	service, useCase, repository, command                         RoleStats
	storeDecls, stateDecls, actionDecls                           int
	businessLogic, presentationLogic, displayLogic, routingLogic  int
}

func newRoleCounter(files []*parser.ParsedFile) *roleCounter {
	rc := &roleCounter{}
	stats := func(pred func(*parser.ParsedFile) bool, declSuffix string) RoleStats {
		var matching []*parser.ParsedFile
		for _, f := range files {
			if pred(f) {
				matching = append(matching, f)
			}
		}
		s := RoleStats{}
		for _, f := range matching {
			s.FileCount++
			s.LineCount += f.LineCount
		}
		if declSuffix != "" {
			for _, f := range files {
				for _, d := range f.Declarations {
					if d.Kind != parser.DeclExtension && strings.HasSuffix(strings.ToLower(d.Name), declSuffix) {
						s.DeclCount++
					}
				}
			}
		}
		sort.SliceStable(matching, func(i, j int) bool { return matching[i].LineCount > matching[j].LineCount })
		for i := 0; i < len(matching) && i < 3; i++ {
			s.TopPaths = append(s.TopPaths, matching[i].FilePath)
		}
		return s
	}

	rc.model = stats(func(f *parser.ParsedFile) bool {
		n, p := nameLower(f), pathLower(f)
		return strings.HasSuffix(n, "model") || strings.HasSuffix(n, "dto") ||
			strings.Contains(p, "/model/") || strings.Contains(p, "/models/")
	}, "model")
	rc.view = stats(func(f *parser.ParsedFile) bool {
		n, p := nameLower(f), pathLower(f)
		nameMatch := (strings.HasSuffix(n, "view") || strings.HasSuffix(n, "screen") ||
			strings.HasSuffix(n, "cell") || strings.HasSuffix(n, "component")) &&
			!strings.HasSuffix(n, "viewcontroller") && !strings.HasSuffix(n, "viewmodel")
		pathMatch := (strings.Contains(p, "/views/") || strings.Contains(p, "/view/")) &&
			!strings.Contains(p, "viewmodel") && !strings.Contains(p, "viewcontroller")
		return nameMatch || pathMatch
	}, "")
	rc.viewController = stats(func(f *parser.ParsedFile) bool {
		n := nameLower(f)
		if strings.HasSuffix(n, "viewcontroller") || strings.HasSuffix(n, "controller") {
			return true
		}
		for _, d := range f.Declarations {
			if d.Kind == parser.DeclClass && strings.HasSuffix(strings.ToLower(d.Name), "viewcontroller") {
				return true
			}
		}
		return false
	}, "")
	rc.viewModel = stats(func(f *parser.ParsedFile) bool {
		n, p := nameLower(f), pathLower(f)
		return strings.HasSuffix(n, "viewmodel") || strings.Contains(p, "/viewmodels/")
	}, "viewmodel")
	rc.presenter = stats(func(f *parser.ParsedFile) bool {
		n, p := nameLower(f), pathLower(f)
		return strings.HasSuffix(n, "presenter") || strings.Contains(p, "/presenters/")
	}, "presenter")
	rc.interactor = stats(func(f *parser.ParsedFile) bool {
		n, p := nameLower(f), pathLower(f)
		return strings.HasSuffix(n, "interactor") || strings.Contains(p, "/interactors/")
	}, "interactor")
	rc.router = stats(func(f *parser.ParsedFile) bool {
		n, p := nameLower(f), pathLower(f)
		return strings.HasSuffix(n, "router") || strings.HasSuffix(n, "wireframe") || strings.Contains(p, "/routers/")
	}, "router")
	rc.coordinator = stats(func(f *parser.ParsedFile) bool {
		n, p := nameLower(f), pathLower(f)
		return strings.HasSuffix(n, "coordinator") || strings.Contains(p, "/coordinators/")
	}, "coordinator")
	rc.entity = stats(func(f *parser.ParsedFile) bool {
		n, p := nameLower(f), pathLower(f)
		return strings.HasSuffix(n, "entity") || strings.Contains(p, "/entities/")
	}, "entity")
	rc.builder = stats(func(f *parser.ParsedFile) bool {
		n, p := nameLower(f), pathLower(f)
		return strings.HasSuffix(n, "builder") || strings.Contains(p, "/builders/")
	}, "builder")
	rc.feature = stats(func(f *parser.ParsedFile) bool {
		return strings.HasSuffix(nameLower(f), "feature")
	}, "feature")
	rc.reducer = stats(func(f *parser.ParsedFile) bool {
		n, p := nameLower(f), pathLower(f)
		return strings.HasSuffix(n, "reducer") || strings.Contains(p, "/reducers/")
	}, "reducer")
	rc.service = stats(func(f *parser.ParsedFile) bool {
		n, p := nameLower(f), pathLower(f)
		return strings.HasSuffix(n, "service") || strings.Contains(p, "/services/")
	}, "service")
	rc.useCase = stats(func(f *parser.ParsedFile) bool {
		n, p := nameLower(f), pathLower(f)
		return strings.HasSuffix(n, "usecase") || strings.Contains(p, "/usecases/") || strings.Contains(p, "/use-cases/")
	}, "")
	rc.repository = stats(func(f *parser.ParsedFile) bool {
		n, p := nameLower(f), pathLower(f)
		return strings.HasSuffix(n, "repository") || strings.Contains(p, "/repositories/") || strings.Contains(p, "/repository/")
	}, "")
	rc.command = stats(func(f *parser.ParsedFile) bool {
		n, p := nameLower(f), pathLower(f)
		return strings.HasSuffix(n, "command") || strings.Contains(p, "/commands/") || strings.Contains(p, "/command/")
	}, "command")

	// Declaration-suffix counters (interfaces/protocols for VIP; decls for Redux/TCA).
	countDecl := func(test func(string) bool) int {
		n := 0
		for _, f := range files {
			for _, d := range f.Declarations {
				if d.Kind != parser.DeclExtension && test(strings.ToLower(d.Name)) {
					n++
				}
			}
		}
		return n
	}
	countProto := func(suffix string) int {
		n := 0
		for _, f := range files {
			for _, d := range f.Declarations {
				if d.Kind == parser.DeclInterface && strings.HasSuffix(d.Name, suffix) {
					n++
				}
			}
		}
		return n
	}
	rc.businessLogic = countProto("BusinessLogic")
	rc.presentationLogic = countProto("PresentationLogic")
	rc.displayLogic = countProto("DisplayLogic")
	rc.routingLogic = countProto("RoutingLogic")
	rc.storeDecls = countDecl(func(s string) bool { return strings.HasSuffix(s, "store") })
	rc.stateDecls = countDecl(func(s string) bool {
		return strings.HasSuffix(s, "state") && !strings.HasSuffix(s, "uistate") &&
			!strings.HasSuffix(s, "viewstate") && s != "state"
	})
	rc.actionDecls = countDecl(func(s string) bool { return strings.HasSuffix(s, "action") && s != "action" })
	return rc
}

// ── Scoring (ported heuristics; numbers preserved from upstream) ──────────────

func (rc *roleCounter) scoreTCA(imp map[string]bool) float64 {
	s := 0.0
	if imp["ComposableArchitecture"] {
		s += 0.65
	}
	if rc.feature.FileCount >= 1 {
		s += pick(rc.feature.FileCount >= 2, 0.20, 0.10)
	}
	if rc.feature.DeclCount >= 1 {
		s += pick(rc.feature.DeclCount >= 2, 0.10, 0.05)
	}
	if rc.reducer.FileCount >= 1 {
		s += pick(rc.reducer.FileCount >= 2, 0.05, 0.02)
	}
	if rc.reducer.DeclCount >= 1 {
		s += pick(rc.reducer.DeclCount >= 2, 0.10, 0.05)
	}
	if rc.stateDecls >= 1 {
		s += pick(rc.stateDecls >= 2, 0.08, 0.04)
	}
	if rc.actionDecls >= 1 {
		s += pick(rc.actionDecls >= 2, 0.08, 0.04)
	}
	if rc.storeDecls >= 1 {
		s += 0.05
	}
	return min1(s)
}

func (rc *roleCounter) scoreVIP() float64 {
	s := 0.0
	if rc.businessLogic >= 1 {
		s += 0.30
	}
	if rc.presentationLogic >= 1 {
		s += 0.25
	}
	if rc.displayLogic >= 1 {
		s += 0.20
	}
	if rc.routingLogic >= 1 {
		s += 0.15
	}
	if rc.interactor.FileCount >= 1 {
		s += pick(rc.interactor.FileCount >= 2, 0.05, 0.02)
	}
	if rc.presenter.FileCount >= 1 {
		s += pick(rc.presenter.FileCount >= 2, 0.05, 0.02)
	}
	return min1(s)
}

func (rc *roleCounter) scoreVIPER() float64 {
	hits := 0
	if rc.view.FileCount+rc.viewController.FileCount >= 1 {
		hits++
	}
	if rc.interactor.total() >= 1 {
		hits++
	}
	if rc.presenter.total() >= 1 {
		hits++
	}
	if rc.entity.total() >= 1 {
		hits++
	}
	if rc.router.total() >= 1 {
		hits++
	}
	if hits < 2 {
		return 0
	}
	penalty := minF(float64(rc.businessLogic+rc.presentationLogic+rc.displayLogic)*0.05, 0.3)
	return maxF(0, float64(hits)/5.0*0.85-penalty)
}

func (rc *roleCounter) scoreRIBs() float64 {
	s := 0.0
	b := rc.builder.total()
	r := rc.router.total()
	i := rc.interactor.total()
	if b >= 1 {
		s += pick3(b >= 3, b >= 2, 0.35, 0.25, 0.15)
	}
	if r >= 1 {
		s += pick3(r >= 3, r >= 2, 0.30, 0.22, 0.12)
	}
	if i >= 1 {
		s += pick3(i >= 3, i >= 2, 0.25, 0.18, 0.10)
	}
	if s > 0 {
		s += 0.10
	}
	return min1(s)
}

func (rc *roleCounter) scoreClean() float64 {
	hits := 0
	s := 0.0
	if rc.useCase.FileCount >= 1 {
		hits++
		s += pick3(rc.useCase.FileCount >= 3, rc.useCase.FileCount >= 2, 0.35, 0.25, 0.15)
	}
	if rc.repository.FileCount >= 1 {
		hits++
		s += pick(rc.repository.FileCount >= 2, 0.30, 0.18)
	}
	if rc.entity.total() >= 2 {
		hits++
		s += 0.15
	}
	if rc.service.FileCount >= 1 {
		s += 0.08
	}
	if hits < 2 {
		return 0
	}
	return min1(s)
}

func (rc *roleCounter) scoreRedux(imp map[string]bool) float64 {
	if imp["ComposableArchitecture"] {
		return 0
	}
	s := 0.0
	if imp["ReSwift"] || imp["Redux"] || imp["redux"] || imp["@reduxjs/toolkit"] {
		s += 0.55
	}
	if rc.stateDecls >= 1 {
		s += pick(rc.stateDecls >= 2, 0.20, 0.10)
	}
	if rc.actionDecls >= 1 {
		s += pick(rc.actionDecls >= 2, 0.20, 0.10)
	}
	if rc.reducer.total() >= 1 {
		s += pick(rc.reducer.FileCount >= 2, 0.15, 0.08)
	}
	if rc.storeDecls >= 1 {
		s += 0.10
	}
	return min1(s)
}

func (rc *roleCounter) scoreMVVMC() float64 {
	if rc.viewModel.total() < 1 || rc.coordinator.total() < 1 {
		return 0
	}
	coord := rc.coordinator.total()
	svc := rc.service.total()
	if svc > coord && coord <= 1 {
		return 0
	}
	vm := rc.viewModel.total()
	s := pick(vm >= 2, 0.50, 0.35)
	if rc.viewModel.FileCount >= 3 {
		s += 0.20
	}
	if rc.coordinator.FileCount >= 2 {
		s += 0.15
	}
	if rc.model.FileCount >= 1 {
		s += 0.10
	}
	return min1(s)
}

func (rc *roleCounter) scoreMVVMS() float64 {
	if rc.viewModel.total() < 1 || rc.service.FileCount < 1 {
		return 0
	}
	coord := rc.coordinator.total()
	svc := rc.service.total()
	if svc < coord {
		return 0
	}
	vm := rc.viewModel.total()
	s := pick(vm >= 2, 0.45, 0.30)
	if rc.viewModel.FileCount >= 3 {
		s += 0.15
	}
	if svc >= 2 {
		s += 0.20
	}
	if svc >= 4 {
		s += 0.10
	}
	if rc.model.FileCount >= 1 {
		s += 0.10
	}
	return min1(s)
}

func (rc *roleCounter) scoreMVVM() float64 {
	if rc.viewModel.total() < 1 {
		return 0
	}
	vm := rc.viewModel.total()
	s := pick(vm >= 2, 0.40, 0.22)
	if rc.viewModel.FileCount >= 3 {
		s += 0.20
	}
	if rc.model.FileCount >= 2 {
		s += 0.15
	}
	if rc.view.FileCount+rc.viewController.FileCount >= 2 {
		s += 0.15
	}
	coordP := 0.0
	if rc.coordinator.total() > 0 {
		coordP = 0.20
	}
	svcP := 0.0
	if rc.service.total() >= 2 {
		svcP = 0.15
	}
	s -= minF(coordP+svcP, 0.25)
	return maxF(0, min1(s))
}

func (rc *roleCounter) scoreMVP() float64 {
	if rc.presenter.total() < 1 || rc.viewModel.total() != 0 {
		return 0
	}
	pres := rc.presenter.total()
	s := pick(pres >= 2, 0.50, 0.30)
	if rc.presenter.FileCount >= 3 {
		s += 0.20
	}
	if rc.view.FileCount+rc.viewController.FileCount >= 2 {
		s += 0.20
	}
	if rc.model.FileCount >= 1 {
		s += 0.10
	}
	return min1(s)
}

func (rc *roleCounter) scoreMVC(imp map[string]bool) float64 {
	if rc.viewController.FileCount < 1 || rc.viewModel.total() != 0 || rc.presenter.FileCount != 0 {
		return 0
	}
	if imp["ComposableArchitecture"] {
		return 0
	}
	s := pick(rc.viewController.FileCount >= 2, 0.40, 0.25)
	if imp["UIKit"] {
		s += 0.20
	}
	if rc.viewController.FileCount >= 5 {
		s += 0.20
	}
	if rc.model.FileCount >= 1 {
		s += 0.10
	}
	if rc.router.FileCount == 0 {
		s += 0.10
	}
	return min1(s)
}

func (rc *roleCounter) scoreMV(imp map[string]bool) float64 {
	if !imp["SwiftUI"] {
		return 0 // MV is intrinsically a SwiftUI idiom
	}
	if rc.viewModel.total() != 0 || rc.viewController.FileCount != 0 {
		return 0
	}
	s := 0.5
	if rc.view.FileCount >= 3 {
		s += 0.30
	}
	if rc.model.FileCount >= 1 {
		s += 0.20
	}
	return min1(s)
}

// ── Builders ─────────────────────────────────────────────────────────────────

func (rc *roleCounter) buildTCA(imp map[string]bool) Pattern {
	hint := ""
	if imp["ComposableArchitecture"] {
		hint = "ComposableArchitecture import"
	}
	return Pattern{Name: "TCA", Hint: hint, Roles: []Role{
		role("Feature", "Feature", rc.feature, roleDetail(rc.feature)),
		role("State", "State", RoleStats{DeclCount: rc.stateDecls}, declDetail(rc.stateDecls, "*State types")),
		role("Action", "Action", RoleStats{DeclCount: rc.actionDecls}, declDetail(rc.actionDecls, "*Action types")),
		role("Reducer", "Reducer", rc.reducer, roleDetail(rc.reducer)),
	}}
}

func (rc *roleCounter) buildVIP() Pattern {
	return Pattern{Name: "VIP", Roles: []Role{
		role("V", "View", merge(rc.view, rc.viewController), roleDetail(merge(rc.view, rc.viewController))),
		role("I", "Interactor", rc.interactor, roleDetail(rc.interactor)),
		role("P", "Presenter", rc.presenter, roleDetail(rc.presenter)),
	}}
}

func (rc *roleCounter) buildVIPER() Pattern {
	return Pattern{Name: "VIPER", Roles: []Role{
		role("V", "View", merge(rc.view, rc.viewController), roleDetail(merge(rc.view, rc.viewController))),
		role("I", "Interactor", rc.interactor, roleDetail(rc.interactor)),
		role("P", "Presenter", rc.presenter, roleDetail(rc.presenter)),
		role("E", "Entity", rc.entity, roleDetail(rc.entity)),
		role("R", "Router", rc.router, roleDetail(rc.router)),
	}}
}

func (rc *roleCounter) buildRIBs() Pattern {
	return Pattern{Name: "RIBs", Roles: []Role{
		role("R", "Router", rc.router, roleDetail(rc.router)),
		role("I", "Interactor", rc.interactor, roleDetail(rc.interactor)),
		role("B", "Builder", rc.builder, roleDetail(rc.builder)),
	}}
}

func (rc *roleCounter) buildClean() Pattern {
	return Pattern{Name: "Clean Architecture", Roles: []Role{
		role("UC", "Use Cases", rc.useCase, roleDetail(rc.useCase)),
		role("Repo", "Repositories", rc.repository, roleDetail(rc.repository)),
		role("E", "Entities", rc.entity, roleDetail(rc.entity)),
		role("Svc", "Services", rc.service, roleDetail(rc.service)),
	}}
}

func (rc *roleCounter) buildRedux(imp map[string]bool) Pattern {
	hint := ""
	if imp["ReSwift"] || imp["Redux"] || imp["@reduxjs/toolkit"] {
		hint = "Redux library import"
	}
	return Pattern{Name: "Redux", Hint: hint, Roles: []Role{
		role("State", "State", RoleStats{DeclCount: rc.stateDecls}, declDetail(rc.stateDecls, "*State types")),
		role("Action", "Action", RoleStats{DeclCount: rc.actionDecls}, declDetail(rc.actionDecls, "*Action types")),
		role("Reducer", "Reducer", rc.reducer, roleDetail(rc.reducer)),
		role("Store", "Store", RoleStats{DeclCount: rc.storeDecls}, declDetail(rc.storeDecls, "*Store types")),
	}}
}

func (rc *roleCounter) buildMVVMC() Pattern {
	return Pattern{Name: "MVVM+C", Roles: []Role{
		role("M", "Model", rc.model, roleDetail(rc.model)),
		role("V", "View", merge(rc.view, rc.viewController), roleDetail(merge(rc.view, rc.viewController))),
		role("VM", "ViewModel", rc.viewModel, roleDetail(rc.viewModel)),
		role("C", "Coordinator", rc.coordinator, roleDetail(rc.coordinator)),
	}}
}

func (rc *roleCounter) buildMVVMS() Pattern {
	return Pattern{Name: "MVVM+S", Roles: []Role{
		role("M", "Model", rc.model, roleDetail(rc.model)),
		role("V", "View", merge(rc.view, rc.viewController), roleDetail(merge(rc.view, rc.viewController))),
		role("VM", "ViewModel", rc.viewModel, roleDetail(rc.viewModel)),
		role("S", "Service", rc.service, roleDetail(rc.service)),
	}}
}

func (rc *roleCounter) buildMVVM() Pattern {
	return Pattern{Name: "MVVM", Roles: []Role{
		role("M", "Model", rc.model, roleDetail(rc.model)),
		role("V", "View", merge(rc.view, rc.viewController), roleDetail(merge(rc.view, rc.viewController))),
		role("VM", "ViewModel", rc.viewModel, roleDetail(rc.viewModel)),
	}}
}

func (rc *roleCounter) buildMVP() Pattern {
	return Pattern{Name: "MVP", Roles: []Role{
		role("M", "Model", rc.model, roleDetail(rc.model)),
		role("V", "View", merge(rc.view, rc.viewController), roleDetail(merge(rc.view, rc.viewController))),
		role("P", "Presenter", rc.presenter, roleDetail(rc.presenter)),
	}}
}

func (rc *roleCounter) buildMVC() Pattern {
	return Pattern{Name: "MVC", Roles: []Role{
		role("M", "Model", rc.model, roleDetail(rc.model)),
		role("V", "View", rc.view, roleDetail(rc.view)),
		role("C", "Controller", rc.viewController, roleDetail(rc.viewController)),
	}}
}

func (rc *roleCounter) buildMV() Pattern {
	return Pattern{Name: "MV (Model-View)", Roles: []Role{
		role("M", "Model", rc.model, roleDetail(rc.model)),
		role("V", "View", rc.view, roleDetail(rc.view)),
	}}
}

// ── Component (framework) detection ───────────────────────────────────────────

// componentChecks maps import names to a human framework label. This is the
// cross-language generalization of ArchAnalyzer's Apple-framework detector.
var componentChecks = []struct {
	imports []string
	name    string
	detail  string
	icon    string
}{
	{[]string{"SwiftUI"}, "SwiftUI", "Declarative UI", "🎨"},
	{[]string{"UIKit"}, "UIKit", "Imperative UI", "📱"},
	{[]string{"Combine"}, "Combine", "Reactive Streams", "🔄"},
	{[]string{"CoreData"}, "CoreData", "Object-Graph Persistence", "🗄️"},
	{[]string{"CryptoKit"}, "CryptoKit", "Cryptography", "🔑"},
	{[]string{"react", "React"}, "React", "Declarative UI", "⚛️"},
	{[]string{"next", "next/router"}, "Next.js", "React Framework", "▲"},
	{[]string{"vue"}, "Vue", "Declarative UI", "🟢"},
	{[]string{"@angular/core"}, "Angular", "SPA Framework", "🅰️"},
	{[]string{"express"}, "Express", "HTTP Server", "🚂"},
	{[]string{"@nestjs/core", "@nestjs/common"}, "NestJS", "Node Framework", "🐱"},
	{[]string{"django", "django.db"}, "Django", "Web Framework", "🎸"},
	{[]string{"flask"}, "Flask", "Micro Web Framework", "🧪"},
	{[]string{"fastapi"}, "FastAPI", "Async Web Framework", "⚡"},
	{[]string{"sqlalchemy"}, "SQLAlchemy", "ORM", "🗃️"},
	{[]string{"net/http"}, "net/http", "HTTP Server/Client", "🌐"},
	{[]string{"google.golang.org/grpc", "grpc"}, "gRPC", "RPC Framework", "📡"},
	{[]string{"graphql", "graphql-go"}, "GraphQL", "API Query Layer", "◼️"},
	{[]string{"gorm.io/gorm"}, "GORM", "ORM", "🗃️"},
}

func detectComponents(imp map[string]bool) []Component {
	var out []Component
	seen := map[string]bool{}
	for _, c := range componentChecks {
		for _, want := range c.imports {
			if imp[want] && !seen[c.name] {
				out = append(out, Component{Name: c.name, Detail: c.detail, Icon: strings.TrimSpace(c.icon)})
				seen[c.name] = true
				break
			}
		}
	}
	return out
}

// ── tiny helpers ─────────────────────────────────────────────────────────────

func importSet(files []*parser.ParsedFile) map[string]bool {
	m := map[string]bool{}
	for _, f := range files {
		for _, imp := range f.Imports {
			m[imp] = true
			m[lastSeg(imp)] = true
		}
	}
	return m
}

func nameLower(f *parser.ParsedFile) string { return strings.ToLower(f.FileNameWithoutExt()) }
func pathLower(f *parser.ParsedFile) string {
	return strings.ToLower(strings.ReplaceAll(f.FilePath, "\\", "/"))
}

func merge(a, b RoleStats) RoleStats {
	out := RoleStats{
		FileCount: a.FileCount + b.FileCount,
		LineCount: a.LineCount + b.LineCount,
		DeclCount: a.DeclCount + b.DeclCount,
	}
	out.TopPaths = append(append([]string{}, a.TopPaths...), b.TopPaths...)
	if len(out.TopPaths) > 3 {
		out.TopPaths = out.TopPaths[:3]
	}
	return out
}

func roleDetail(s RoleStats) string {
	if s.FileCount == 0 && s.DeclCount == 0 {
		return "—"
	}
	parts := []string{}
	if s.FileCount > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", s.FileCount, plural(s.FileCount, "file", "files")))
	}
	if s.DeclCount > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", s.DeclCount, plural(s.DeclCount, "type", "types")))
	}
	return strings.Join(parts, " · ")
}

func declDetail(n int, label string) string {
	if n == 0 {
		return "—"
	}
	return fmt.Sprintf("%d %s", n, label)
}

func lastSeg(s string) string {
	s = strings.ReplaceAll(s, "\\", "/")
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndexByte(s, '.'); i >= 0 && i < len(s)-1 {
		s = s[i+1:]
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func pick(cond bool, hi, lo float64) float64 {
	if cond {
		return hi
	}
	return lo
}

func pick3(hiCond, midCond bool, hi, mid, lo float64) float64 {
	if hiCond {
		return hi
	}
	if midCond {
		return mid
	}
	return lo
}

func min1(x float64) float64 { return minF(x, 1.0) }
func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
