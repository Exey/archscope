// Package traffic detects inbound and outbound connection signals in Go,
// Python, Java, Swift, Kotlin, C/C++, and TypeScript/JavaScript source files:
// HTTP routes, gRPC services, WebSocket, GraphQL, Redis, Kafka, NATS, AMQP,
// and raw-TCP/socket endpoints (Swift and C/C++) — from string literals only.
//
// Detection is a two-stage pipeline:
//
//  1. ParseHooks in internal/lang/{golang,python,java,swift,kotlin,typescript,c,cpp}.go
//     scan raw source lines and store results in pf.Extra["trafficInbound"]
//     and pf.Extra["trafficOutbound"] as []Entry.
//
//  2. This module's Analyze reads those slices from every ParsedFile, deduplicates
//     by (URI, Protocol), and returns a Result with sorted Inbound and Outbound slices.
//
// RenderHTML renders two tables (📥 Inbound / 📤 Outbound) with columns:
// URI/Pattern, Port, Protocol (coloured badge), Data format, File (vscode:// link).
package traffic

import (
	"fmt"
	"html"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/security"
)

func init() { modules.Default.Register(Module{}) }

// Module is the self-registering traffic analyser.
type Module struct{}

// ID is the module's stable identifier, "traffic", used to select and order its panel.
func (Module) ID() string { return "traffic" }

// Title is the heading of the module's panel, "Traffic".
func (Module) Title() string { return "Traffic" }

// AppliesTo runs the module for the languages that have a traffic extractor: Go, Python, Java, Swift, Kotlin, TypeScript, C and C++.
func (Module) AppliesTo(l string) bool {
	switch l {
	case "go", "python", "java", "swift", "kotlin", "ts", "c", "cpp":
		return true
	}
	return false
}

// Location is one file:line occurrence of an Entry, beyond its primary
// FilePath/Line — used when the same URI/pattern is registered in more than
// one file (a shared route constant, a re-exported client, …), so that
// information isn't silently dropped by cross-file deduplication.
type Location struct {
	FilePath string
	Line     int
}

// Entry is one detected inbound or outbound connection signal.
type Entry struct {
	URI      string // route path, URL, host:port, service name
	Port     string // extracted port, or ""
	Protocol string // REST, gRPC, WebSocket, GraphQL, Redis, Kafka, NATS, AMQP
	DataFmt  string // JSON, Protobuf, XML, or ""
	FilePath string // absolute path of the first occurrence, for vscode:// link
	Line     int    // approximate source line number of the first occurrence
	Module   string // module/microservice name the entry belongs to
	Extra    []Location
}

// Result aggregates traffic signals from all analysed files.
type Result struct {
	Inbound  []Entry
	Outbound []Entry
}

// HasData reports whether any inbound or outbound connection signal was found.
func (r Result) HasData() bool { return len(r.Inbound) > 0 || len(r.Outbound) > 0 }

// Analyze gathers the inbound and outbound connection signals each language extractor stored on the parsed files, de-duplicated and sorted.
func (Module) Analyze(files []*parser.ParsedFile) any {
	var r Result
	// Maps a (URI, Protocol) key to its index in r.Inbound/r.Outbound — a
	// repeat key doesn't get dropped, its file:line is folded into that
	// entry's Extra instead, so "the same route registered in N files" (even
	// across different modules) stays visible as one row rather than
	// splintering into a duplicate row per module.
	seenIn := map[string]int{}
	seenOut := map[string]int{}

	for _, f := range files {
		if f.Extra == nil || security.IsTestPath(f.FilePath) {
			continue
		}
		mod := f.ModuleName
		if mod == "" {
			mod = "root"
		}
		if in, ok := f.Extra["trafficInbound"].([]Entry); ok {
			for _, e := range in {
				e.Module = mod
				k := e.URI + "|" + e.Protocol
				if idx, ok := seenIn[k]; ok {
					r.Inbound[idx].Extra = append(r.Inbound[idx].Extra, Location{e.FilePath, e.Line})
				} else {
					seenIn[k] = len(r.Inbound)
					r.Inbound = append(r.Inbound, e)
				}
			}
		}
		if out, ok := f.Extra["trafficOutbound"].([]Entry); ok {
			for _, e := range out {
				e.Module = mod
				k := e.URI + "|" + e.Protocol
				if idx, ok := seenOut[k]; ok {
					r.Outbound[idx].Extra = append(r.Outbound[idx].Extra, Location{e.FilePath, e.Line})
				} else {
					seenOut[k] = len(r.Outbound)
					r.Outbound = append(r.Outbound, e)
				}
			}
		}
	}
	sortEntries(r.Inbound)
	sortEntries(r.Outbound)
	return r
}

func sortEntries(ee []Entry) {
	sort.Slice(ee, func(i, j int) bool {
		if ee[i].Protocol != ee[j].Protocol {
			return ee[i].Protocol < ee[j].Protocol
		}
		return ee[i].URI < ee[j].URI
	})
}

// SummaryCards returns the headline figures shown in the platform card's header for this module.
func (Module) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(Result)
	if !ok || !r.HasData() {
		return nil
	}
	label := "connections"
	if len(r.Inbound)+len(r.Outbound) == 1 {
		label = "connection"
	}
	return []modules.SummaryCard{
		{Num: fmt.Sprintf("%d in · %d out", len(r.Inbound), len(r.Outbound)), Label: label},
	}
}

// RenderMarkdown renders the traffic panel as markdown tables.
func (Module) RenderMarkdown(res any) string {
	r, ok := res.(Result)
	if !ok || !r.HasData() {
		return ""
	}
	return r.MarkdownTables(nil)
}

// MarkdownTables is the Inbound / Outbound pair of tables the HTML panel draws.
// spec, when non-nil, adds a "Spec" column to the inbound table: it returns the
// cell text for one route (✅ documented · ❓ not found in any spec).
func (r Result) MarkdownTables(spec func(Entry) string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d inbound · %d outbound connection signals detected from string literals\n\n", len(r.Inbound), len(r.Outbound))
	table := func(title string, entries []Entry, withSpec bool) {
		fmt.Fprintf(&b, "#### %s", title)
		if len(entries) > 0 {
			fmt.Fprintf(&b, " (%d)", len(entries))
		}
		b.WriteString("\n\n")
		if len(entries) == 0 {
			b.WriteString("— No signals detected\n\n")
			return
		}
		if withSpec {
			b.WriteString("| URI / Pattern | Protocol | Format | Spec | Module | File |\n|---------------|----------|--------|:----:|--------|------|\n")
		} else {
			b.WriteString("| URI / Pattern | Protocol | Format | Module | File |\n|---------------|----------|--------|--------|------|\n")
		}
		for _, e := range entries {
			uri := e.URI
			if e.Port != "" && !strings.Contains(uri, e.Port) {
				uri = uri + ":" + e.Port
			}
			mod := e.Module
			if mod == "" {
				mod = "root"
			}
			if withSpec {
				fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
					mdCell(uri), mdCell(e.Protocol), mdCell(e.DataFmt), spec(e), mdCell(mod), mdCell(fileCellMD(e)))
			} else {
				fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
					mdCell(uri), mdCell(e.Protocol), mdCell(e.DataFmt), mdCell(mod), mdCell(fileCellMD(e)))
			}
		}
		b.WriteString("\n")
	}
	table("📥 Inbound", r.Inbound, spec != nil)
	table("📤 Outbound", r.Outbound, false)
	return b.String()
}

// mdCell escapes pipe characters so they don't break markdown table cells.
func mdCell(s string) string {
	if s == "" {
		return ""
	}
	return strings.ReplaceAll(s, "|", "\\|")
}

// RenderHTML renders the traffic panel with two sorted tables.
func (Module) RenderHTML(res any) string {
	r, ok := res.(Result)
	if !ok || !r.HasData() {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="as-pop">`)
	fmt.Fprintf(&b,
		`<p class="as-pop__sub">%d inbound · %d outbound connection signals detected from string literals</p>`,
		len(r.Inbound), len(r.Outbound),
	)
	renderTable(&b, "📥 Inbound", r.Inbound)
	renderTable(&b, "📤 Outbound", r.Outbound)
	b.WriteString(`</div>`)
	return b.String()
}

func renderTable(b *strings.Builder, heading string, entries []Entry) {
	fmt.Fprintf(b, `<div class="as-sub" style="margin-top:16px">%s`, heading)
	if len(entries) > 0 {
		fmt.Fprintf(b,
			` <span style="color:var(--text-faint);font-weight:400">(%d)</span>`,
			len(entries),
		)
	}
	b.WriteString(`</div>`)
	if len(entries) == 0 {
		b.WriteString(`<p class="as-empty">— No signals detected</p>`)
		return
	}
	b.WriteString(`<table class="as-table"><thead><tr>`)
	b.WriteString(`<th>Protocol</th><th>URI / Pattern</th><th>Data</th><th>File</th><th>Module</th>`)
	b.WriteString(`</tr></thead><tbody>`)
	for _, e := range entries {
		uri := e.URI
		if e.Port != "" && !strings.Contains(uri, e.Port) {
			uri = uri + ":" + e.Port
		}
		dataCell := "—"
		if e.DataFmt != "" {
			dataCell = e.DataFmt
		}
		mod := e.Module
		if mod == "" {
			mod = "root"
		}
		fmt.Fprintf(b,
			`<tr><td>%s</td><td class="mono">%s</td><td class="mono">%s</td><td class="mono">%s</td><td class="mono">%s</td></tr>`,
			protoTag(e.Protocol), esc(uri), esc(dataCell), fileLinksFor(e), esc(mod),
		)
	}
	b.WriteString(`</tbody></table>`)
}

func protoTag(proto string) string {
	bg, fg := protoColors(proto)
	return fmt.Sprintf(
		`<span class="as-tag" style="background:%s;color:%s;font-size:11px">%s</span>`,
		bg, fg, esc(proto),
	)
}

func protoColors(proto string) (bg, fg string) {
	switch proto {
	case "REST", "REST/H2", "REST/TLS":
		return "#27ae60", "#fff"
	case "gRPC":
		return "#2980b9", "#fff"
	case "WebSocket":
		return "#e67e22", "#fff"
	case "GraphQL":
		return "#8e44ad", "#fff"
	case "Redis":
		return "#e74c3c", "#fff"
	case "Kafka":
		return "#d35400", "#fff"
	case "NATS":
		return "#16a085", "#fff"
	case "AMQP":
		return "#795548", "#fff"
	default:
		return "#7f8c8d", "#fff"
	}
}

func fileLink(filePath string, line int) string {
	if filePath == "" {
		return "—"
	}
	name := filepath.Base(filePath)
	href := "vscode://file" + filePath
	if line > 0 {
		href += ":" + strconv.Itoa(line)
		name += ":" + strconv.Itoa(line)
	}
	return fmt.Sprintf(`<a href="%s">%s</a>`, html.EscapeString(href), html.EscapeString(name))
}

// maxFileLinksShown caps how many file:line locations are rendered for one
// entry before collapsing the rest into "+N more" — a URI shared across
// dozens of files shouldn't blow out the table row.
const maxFileLinksShown = 4

// fileLinksFor renders every location a deduplicated Entry was seen at (its
// primary FilePath/Line plus any Extra occurrences) as a comma-separated list
// of vscode:// links, capped at maxFileLinksShown.
func fileLinksFor(e Entry) string {
	if e.FilePath == "" {
		return "—"
	}
	total := 1 + len(e.Extra)
	shown := min(total, maxFileLinksShown)
	links := make([]string, 0, shown)
	links = append(links, fileLink(e.FilePath, e.Line))
	for i := 0; i < len(e.Extra) && len(links) < shown; i++ {
		links = append(links, fileLink(e.Extra[i].FilePath, e.Extra[i].Line))
	}
	out := strings.Join(links, ", ")
	if total > shown {
		out += fmt.Sprintf(` <span style="color:var(--text-faint)">+%d more</span>`, total-shown)
	}
	return out
}

// fileCellMD renders the same locations as fileLinksFor, but as plain
// "name:line" text (no HTML) for the Markdown report.
func fileCellMD(e Entry) string {
	if e.FilePath == "" {
		return ""
	}
	locs := make([]Location, 0, 1+len(e.Extra))
	locs = append(locs, Location{e.FilePath, e.Line})
	locs = append(locs, e.Extra...)
	parts := make([]string, 0, len(locs))
	for _, l := range locs {
		name := filepath.Base(l.FilePath)
		if l.Line > 0 {
			name = fmt.Sprintf("%s:%d", name, l.Line)
		}
		parts = append(parts, name)
	}
	return strings.Join(parts, ", ")
}

func esc(s string) string { return html.EscapeString(s) }

// searchesText reports whether ln looks a literal up in text rather than using it.
func searchesText(ln string) bool { return parser.SearchesText(ln) }
