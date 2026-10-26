package report

// cards.go is the single list of the report's cards. Every output — the HTML
// document, its "MD" buttons, and the --format md file — is assembled by walking
// this list, so a card cannot exist in one format and be forgotten in the other.
//
// # Adding a card
//
//  1. Add a Card to Cards, in the position it should appear (document order is
//     list order, in both formats).
//  2. A card backed by a report module (Card.Module) needs nothing else: the
//     module's panel already carries both renderings (modules.ReportModule has
//     RenderHTML *and* RenderMarkdown), and the emitters draw the heading.
//  3. Any other card is registered with report.Add(id, html, markdown) — in
//     report/html/cards.go, one call per card with both renderers side by side.
//     Both are required arguments (pass nil only for a card whose Card entry
//     carries a NoHTML / NoMarkdown reason), so a card cannot be added to one
//     format only; a Card with no Add at all is caught at the first render
//     (Verify), naming it, instead of silently producing a thinner export.
//
// The Markdown of a card whose numbers come from helpers in package html (the
// culture scores, the radar, traffic health …) is written next to its HTML there
// rather than re-derived in package markdown, so the two read the same data.

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/result"
	"github.com/exey/archscope/internal/scanner"
)

// Scope says where a card sits in the document.
type Scope int

const (
	// Global cards are repo-wide: they sit above the platform cards, and are
	// what the report header's "MD" button exports.
	Global Scope = iota
	// Platform cards are repeated inside each platform's card.
	Platform
)

// Style is how the HTML draws a module-backed card.
type Style int

const (
	// StylePanel: a titled panel with the module's summary chips (h4 head).
	StylePanel Style = iota
	// StyleInsight: a plain titled section, as in 💡 Module Insights (h3 head).
	StyleInsight
)

// Card describes one block of the report.
type Card struct {
	ID    string
	Scope Scope
	Title string // heading with its emoji, e.g. "💧 Memory Leaks" — also the Markdown heading

	// Module, when set, backs the card with that report module's panel: both
	// formats are drawn from panel.HTML / panel.MD with no per-card code.
	Module string
	Style  Style

	// Draws names report modules whose panels a hand-written card renders
	// itself, so they are not drawn a second time as unclaimed panels.
	Draws []string

	// HTMLGroup names a wrapper the HTML draws around consecutive cards that
	// share it ("methods", "insights"). Markdown has no wrappers; it lists the
	// members flat.
	HTMLGroup string

	// NoMarkdown / NoHTML explain, in a sentence, why the card legitimately
	// exists in one format only (an interactive control; a section kept for the
	// LLM export). Leaving the renderer out without a reason is an error.
	NoMarkdown string
	NoHTML     string
}

// Ctx is what a card renderer is handed.
type Ctx struct {
	Res   *result.AnalysisResult
	PG    *scanner.PlatformGroup // Platform cards only
	Files []*parser.ParsedFile   // the platform's files (Platform cards only)
	Badge string                 // HTML only: the platform pill for the card head
	Card  Card                   // the card being drawn
}

// Panel returns the platform's panel of the card's module, if the module ran.
func (c Ctx) Panel() (result.ModulePanel, bool) {
	if c.Card.Module == "" || c.PG == nil {
		return result.ModulePanel{}, false
	}
	for _, p := range c.Res.PanelsForPlatform(c.PG.Platform) {
		if p.ModuleID == c.Card.Module {
			return p, true
		}
	}
	return result.ModulePanel{}, false
}

// Renderer draws one card in one format. "" means "nothing to show".
type Renderer func(Ctx) string

// Cards lists every card, in document order.
var Cards = []Card{
	// ── Global ──────────────────────────────────────────────────────────────
	{ID: "summary", Scope: Global, Title: "📊 Summary"},
	{ID: "culture", Scope: Global, Title: "🔰 Programming Culture"},
	{ID: "stack", Scope: Global, Title: "🧰 Tech Stack & Modules"},
	{ID: "radar", Scope: Global, Title: "📡 Technical Radar"},
	{ID: "archgraph", Scope: Global, Title: "🗺️ Architecture Graph"},
	{ID: "danger", Scope: Global, Title: "🛡️ Danger Index"},
	{ID: "devops", Scope: Global, Title: "☁️ DevOps"},
	{ID: "openapi", Scope: Global, Title: "📜 OpenAPI"},
	{ID: "vscode", Scope: Global, Title: "🔗 VS Code Links",
		NoMarkdown: "an interactive path editor for the report's VS Code links"},
	{ID: "contributions", Scope: Global, Title: "📅 Contributions"},
	{ID: "infra", Scope: Global, Title: "☸️ Infrastructure Platforms"},

	// ── Per platform ────────────────────────────────────────────────────────
	{ID: "overview", Scope: Platform}, // the size cards / stats line; no heading of its own
	{ID: "architecture", Scope: Platform, Title: "🏛️ Architecture", Draws: []string{"architecture"}},
	{ID: "dddmodel", Scope: Platform, Module: "dddmodel", Title: "🍱 Domain Model"},
	{ID: "oopvspop", Scope: Platform, Module: "oopvspop", Title: "⚖️ OOP vs POP"},

	{ID: "couplingcohesion", Scope: Platform, Module: "couplingcohesion", Title: "🔗🧬 Coupling & Cohesion", HTMLGroup: "methods"},
	{ID: "designpattern", Scope: Platform, Module: "designpattern", Title: "🧩 Design Patterns", HTMLGroup: "methods"},
	{ID: "datastructures", Scope: Platform, Module: "datastructures", Title: "🌳 Data Structures", HTMLGroup: "methods"},
	{ID: "algorithms", Scope: Platform, Module: "algorithms", Title: "🔀 Algorithms", HTMLGroup: "methods"},
	{ID: "complexity", Scope: Platform, Module: "complexity", Title: "🧮 Complexity", HTMLGroup: "methods"},
	{ID: "magicconstants", Scope: Platform, Module: "magicconstants", Title: "🪄 Magic Constants", HTMLGroup: "methods"},

	{ID: "speccoverage", Scope: Platform, Module: "speccoverage", Title: "🧱 Spec Coverage"},
	{ID: "traffic", Scope: Platform, Title: "🛜 Traffic", Draws: []string{"traffic"}},

	{ID: "hotspots", Scope: Platform, Title: "🕸️ Dependency Hotspots", HTMLGroup: "insights"},
	{ID: "microservices", Scope: Platform, Title: "📦 Modules", HTMLGroup: "insights"},
	{ID: "langrichness", Scope: Platform, Module: "langrichness", Style: StyleInsight, Title: "🎖️ Language Richness", HTMLGroup: "insights"},
	{ID: "codestructure", Scope: Platform, Module: "codestructure", Style: StyleInsight, Title: "💻 Code Structure", HTMLGroup: "insights"},
	{ID: "memoryleaks", Scope: Platform, Module: "memoryleaks", Style: StyleInsight, Title: "💧 Memory Leaks", HTMLGroup: "insights"},
	{ID: "regex", Scope: Platform, Module: "regex", Style: StyleInsight, Title: "🔤🔎 Strings & Regex", HTMLGroup: "insights"},
	{ID: "deadcode", Scope: Platform, Module: "deadcode", Style: StyleInsight, Title: "🪦 Dead Code", HTMLGroup: "insights"},
	{ID: "concurrency", Scope: Platform, Module: "concurrency", Style: StyleInsight, Title: "🧵 Concurrency & API Misuse", HTMLGroup: "insights"},
	{ID: "todos", Scope: Platform, Title: "📝 TODOs & FIXMEs", HTMLGroup: "insights"},
	{ID: "longestfuncs", Scope: Platform, Title: "📏 Longest Functions", HTMLGroup: "insights"},
	{ID: "biggesttypes", Scope: Platform, Title: "📐 Biggest Types", HTMLGroup: "insights"},

	{ID: "git", Scope: Platform, Title: "🐙 Git Analysis"},
	{ID: "security", Scope: Platform, Title: "🛡️ Danger Details"},
	{ID: "moduledetails", Scope: Platform, Title: "📂 Modules & Microservices"},
	{ID: "penetration", Scope: Platform, Title: "🔗 Module Penetration",
		NoHTML: "retired from the HTML report; kept in the Markdown export for LLM review"},
}

// GroupTitles are the HTML wrapper headings of Card.HTMLGroup.
var GroupTitles = map[string]string{
	"methods":  "🧠 Programming Methods",
	"insights": "💡 Module Insights",
}

var (
	mu       sync.Mutex
	htmlFns  = map[string]Renderer{}
	mdFns    = map[string]Renderer{}
	added    = map[string]bool{}
	verified bool
)

// Add registers the two renderers of a card that is not module-backed. Both
// are required — nil is allowed only for the format the card's NoHTML /
// NoMarkdown reason exempts — so the compiler and the init-time check together
// keep a card from existing in one format only.
func Add(id string, html, markdown Renderer) {
	mu.Lock()
	defer mu.Unlock()
	c, ok := Find(id)
	if !ok {
		panic(fmt.Sprintf("report: Add for unknown card %q — add it to report.Cards first", id))
	}
	if c.Module != "" {
		panic(fmt.Sprintf("report: card %q is module-backed (Module %q); it needs no Add", id, c.Module))
	}
	if _, dup := htmlFns[id]; dup || added[id] {
		panic(fmt.Sprintf("report: card %q registered twice", id))
	}
	if html == nil && c.NoHTML == "" {
		panic(fmt.Sprintf("report: card %q has no HTML renderer and no NoHTML reason", id))
	}
	if markdown == nil && c.NoMarkdown == "" {
		panic(fmt.Sprintf("report: card %q has no Markdown renderer and no NoMarkdown reason", id))
	}
	if html != nil && c.NoHTML != "" {
		panic(fmt.Sprintf("report: card %q has an HTML renderer but is marked NoHTML", id))
	}
	if markdown != nil && c.NoMarkdown != "" {
		panic(fmt.Sprintf("report: card %q has a Markdown renderer but is marked NoMarkdown", id))
	}
	added[id] = true
	if html != nil {
		htmlFns[id] = html
	}
	if markdown != nil {
		mdFns[id] = markdown
	}
	verified = false
}

// Find returns the card with the given ID.
func Find(id string) (Card, bool) {
	for _, c := range Cards {
		if c.ID == id {
			return c, true
		}
	}
	return Card{}, false
}

// CardsOf lists the cards of one scope, in document order.
func CardsOf(s Scope) []Card {
	var out []Card
	for _, c := range Cards {
		if c.Scope == s {
			out = append(out, c)
		}
	}
	return out
}

// Missing lists every card that was never registered. Empty means every card
// has its renderers in both formats (Add itself rejects half-registered ones).
func Missing() []string {
	mu.Lock()
	defer mu.Unlock()
	var out []string
	for _, c := range Cards {
		if c.Module == "" && !added[c.ID] {
			out = append(out, fmt.Sprintf("card %q was never registered with report.Add", c.ID))
		}
		if c.NoHTML != "" && c.NoMarkdown != "" {
			out = append(out, fmt.Sprintf("card %q is exempt from both formats", c.ID))
		}
	}
	sort.Strings(out)
	return out
}

// Verify panics when the card table is incomplete. The emitters call it before
// rendering, so a card added in only one format fails loudly, at once, naming
// the card — rather than shipping a quietly thinner export.
func Verify() {
	mu.Lock()
	done := verified
	mu.Unlock()
	if done {
		return
	}
	if gaps := Missing(); len(gaps) > 0 {
		panic("report: incomplete card table:\n  " + strings.Join(gaps, "\n  ") +
			"\n(cards are registered by report/html — is it imported?)")
	}
	mu.Lock()
	verified = true
	mu.Unlock()
}

// HTML draws a non-module card in HTML ("" when it has no renderer or nothing to show).
func HTML(c Ctx) string {
	mu.Lock()
	fn := htmlFns[c.Card.ID]
	mu.Unlock()
	if fn == nil {
		return ""
	}
	return fn(c)
}

// titled marks a Markdown body that carries its own heading (see WithTitle).
const titled = "\x00title:"

// WithTitle gives a card's Markdown a heading of its own — for a card whose
// title depends on its data ("📝 TODOs & FIXMEs (22)", a platform's module
// noun, the repo's level). Without it the heading comes from Card.Title.
func WithTitle(title, body string) string {
	return titled + title + "\x00" + body
}

// Markdown draws a card in Markdown: a module-backed card from its panel, any
// other from its registered renderer. A renderer returns the card's body; the
// heading (## for a global card, ### for a platform one) is added here from
// Card.Title — or from WithTitle when the renderer set one, and not at all for
// a card without a Title. "" means the card has nothing to show.
func Markdown(c Ctx) string {
	var body string
	if c.Card.Module != "" {
		if p, ok := c.Panel(); ok {
			body = p.MD
		}
	} else {
		mu.Lock()
		fn := mdFns[c.Card.ID]
		mu.Unlock()
		if fn != nil {
			body = fn(c)
		}
	}
	title := c.Card.Title
	if strings.HasPrefix(body, titled) {
		rest := body[len(titled):]
		i := strings.IndexByte(rest, 0)
		title, body = rest[:i], rest[i+1:]
	}
	if strings.TrimSpace(body) == "" {
		return ""
	}
	body = strings.TrimRight(strings.TrimLeft(body, "\n"), "\n") + "\n\n"
	if title == "" {
		return body
	}
	level := 3
	if c.Card.Scope == Global {
		level = 2
	}
	return Heading(level, title) + body
}

// MarkdownGlobal is the Markdown of every Global card, separated by rules — what
// the report header's "MD" button downloads (under the document title).
func MarkdownGlobal(res *result.AnalysisResult) string {
	Verify()
	var b strings.Builder
	for _, card := range CardsOf(Global) {
		if md := Markdown(Ctx{Res: res, Card: card}); md != "" {
			b.WriteString(md)
			b.WriteString("---\n\n")
		}
	}
	return b.String()
}

// MarkdownPlatform is the Markdown of every Platform card of one platform, plus
// the panels of modules no card claims.
func MarkdownPlatform(res *result.AnalysisResult, pg *scanner.PlatformGroup, files []*parser.ParsedFile) string {
	Verify()
	var b strings.Builder
	for _, card := range CardsOf(Platform) {
		b.WriteString(Markdown(Ctx{Res: res, PG: pg, Files: files, Card: card}))
	}
	for _, p := range UnclaimedPanels(res, pg.Platform) {
		if strings.TrimSpace(p.MD) == "" {
			continue
		}
		b.WriteString(Heading(3, modIcon(p.ModuleID)+" "+p.Title))
		b.WriteString(strings.TrimRight(p.MD, "\n") + "\n\n")
	}
	return b.String()
}

// Heading is a Markdown heading line plus the blank line after it.
func Heading(level int, title string) string {
	return strings.Repeat("#", level) + " " + title + "\n\n"
}

// UnclaimedPanels returns the platform's module panels that no card claims —
// modules added without a Card still show up, in both formats, after the cards.
func UnclaimedPanels(res *result.AnalysisResult, plat langspec.Platform) []result.ModulePanel {
	claimed := map[string]bool{}
	for _, c := range Cards {
		if c.Module != "" {
			claimed[c.Module] = true
		}
		for _, m := range c.Draws {
			claimed[m] = true
		}
	}
	var out []result.ModulePanel
	for _, p := range res.PanelsForPlatform(plat) {
		if !claimed[p.ModuleID] {
			out = append(out, p)
		}
	}
	return out
}

// modIcon is a module's emoji, for the heading of a panel no card claims.
func modIcon(id string) string { return modules.MetaFor(id).Icon }
