// Package traffic detects inbound and outbound connection signals in Go and
// Python source files: HTTP routes, gRPC services, WebSocket, GraphQL,
// Redis, Kafka, NATS, and AMQP endpoints — from string literals only.
//
// Detection is a two-stage pipeline:
//
//  1. ParseHooks in internal/lang/golang.go and internal/lang/python.go scan
//     raw source lines and store results in pf.Extra["trafficInbound"] and
//     pf.Extra["trafficOutbound"] as []Entry.
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
)

func init() { modules.Default.Register(Module{}) }

// Module is the self-registering traffic analyser.
type Module struct{}

func (Module) ID() string              { return "traffic" }
func (Module) Title() string           { return "Traffic" }
func (Module) AppliesTo(l string) bool { return l == "go" || l == "python" }

// Entry is one detected inbound or outbound connection signal.
type Entry struct {
	URI      string // route path, URL, host:port, service name
	Port     string // extracted port, or ""
	Protocol string // REST, gRPC, WebSocket, GraphQL, Redis, Kafka, NATS, AMQP
	DataFmt  string // JSON, Protobuf, XML, or ""
	FilePath string // absolute path for vscode:// link
	Line     int    // approximate source line number
}

// Result aggregates traffic signals from all analysed files.
type Result struct {
	Inbound  []Entry
	Outbound []Entry
}

func (r Result) HasData() bool { return len(r.Inbound) > 0 || len(r.Outbound) > 0 }

func (Module) Analyze(files []*parser.ParsedFile) any {
	var r Result
	seenIn := map[string]bool{}
	seenOut := map[string]bool{}

	for _, f := range files {
		if f.Extra == nil {
			continue
		}
		if in, ok := f.Extra["trafficInbound"].([]Entry); ok {
			for _, e := range in {
				k := e.URI + "|" + e.Protocol
				if !seenIn[k] {
					seenIn[k] = true
					r.Inbound = append(r.Inbound, e)
				}
			}
		}
		if out, ok := f.Extra["trafficOutbound"].([]Entry); ok {
			for _, e := range out {
				k := e.URI + "|" + e.Protocol
				if !seenOut[k] {
					seenOut[k] = true
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
	var b strings.Builder
	renderTrafficTableMD := func(title string, entries []Entry) {
		if len(entries) == 0 {
			return
		}
		fmt.Fprintf(&b, "#### %s\n\n", title)
		b.WriteString("| URI / Pattern | Port | Protocol | Format | File |\n")
		b.WriteString("|---------------|------|----------|--------|------|\n")
		for _, e := range entries {
			file := filepath.Base(e.FilePath)
			if e.Line > 0 {
				file = fmt.Sprintf("%s:%d", file, e.Line)
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
				mdCell(e.URI), mdCell(e.Port), mdCell(e.Protocol), mdCell(e.DataFmt), mdCell(file))
		}
		b.WriteString("\n")
	}
	renderTrafficTableMD("📥 Inbound", r.Inbound)
	renderTrafficTableMD("📤 Outbound", r.Outbound)
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
	b.WriteString(`<th>URI / Pattern</th><th>Port</th><th>Protocol</th><th>Data</th><th>File</th>`)
	b.WriteString(`</tr></thead><tbody>`)
	for _, e := range entries {
		portCell := "—"
		if e.Port != "" {
			portCell = e.Port
		}
		dataCell := "—"
		if e.DataFmt != "" {
			dataCell = e.DataFmt
		}
		fmt.Fprintf(b,
			`<tr><td class="mono">%s</td><td class="mono">%s</td><td>%s</td><td class="mono">%s</td><td class="mono">%s</td></tr>`,
			esc(e.URI), esc(portCell), protoTag(e.Protocol), esc(dataCell), fileLink(e.FilePath, e.Line),
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

func esc(s string) string { return html.EscapeString(s) }
