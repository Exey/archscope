// Package speccoverage measures the fraction of API operations defined in a
// spec file that are also implemented in source code.
//
// Three-stage pipeline:
//
//  1. Spec Extraction  – walk the project root for openapi.yaml/json, *.proto,
//     and *.graphql files; parse their API surface into SpecOps.
//  2. Code Analysis    – scan source files for registered route handlers and
//     gRPC/GraphQL resolver implementations (Go, Python, Java/Kotlin, TypeScript).
//  3. Comparison       – normalize paths, match spec ops to code ops, compute %.
//
// The panel is hidden when no spec files are found.
package speccoverage

import (
	"fmt"
	"html"
	"path/filepath"
	"sort"
	"strings"

	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
)

func init() { modules.Default.Register(Module{}) }

// Module implements spec-coverage analysis.
type Module struct{}

func (Module) ID() string    { return "speccoverage" }
func (Module) Title() string { return "Spec Coverage" }

// AppliesTo runs for backend languages that own HTTP/gRPC/GraphQL routes.
func (Module) AppliesTo(l string) bool {
	switch l {
	case "go", "python", "java", "kotlin", "typescript":
		return true
	}
	return false
}

// SpecOp is a single API operation — from a spec file or from source code.
type SpecOp struct {
	Method   string // HTTP verb (GET/POST/…), "rpc", or "field"
	Path     string // URL path, RPC name, or GraphQL field
	SpecType string // "OpenAPI", "gRPC", "GraphQL"
	File     string // display path (relative to project root)
}

// Result is the full output of the spec-coverage analysis.
type Result struct {
	SpecOps   []SpecOp // operations defined in spec files
	ImplOps   []SpecOp // operations found in source code
	Covered   []SpecOp // SpecOps matched in code
	Missing   []SpecOp // SpecOps NOT found in code
	Extra     []SpecOp // code ops not covered by any spec
	Coverage  int      // 0–100: len(Covered) / len(SpecOps) * 100
	SpecTypes []string // e.g. ["OpenAPI", "gRPC"]
	HasSpec   bool
	HasRoutes bool
	FileCount int // number of spec files found
}

// HasData controls whether the panel is rendered.
func (r Result) HasData() bool { return r.HasSpec }

// ─── Analyze ──────────────────────────────────────────────────────────────────

func (Module) Analyze(files []*parser.ParsedFile) any {
	var r Result
	if len(files) == 0 {
		return r
	}

	srcRoot := commonRoot(files)
	projRoot := findProjectRoot(srcRoot)

	// Stage 1 – discover and parse spec files.
	r.SpecOps, r.FileCount = scanSpecFiles(projRoot)
	r.HasSpec = len(r.SpecOps) > 0
	if !r.HasSpec {
		return r
	}

	// Stage 2 – extract route implementations from source.
	r.ImplOps = extractCodeOps(files, projRoot)
	r.HasRoutes = len(r.ImplOps) > 0

	// Stage 3 – compare spec ops against code ops.
	implSet := map[string]bool{}     // "verb path" keys for verb-specific code ops
	implAnyPath := map[string]bool{} // normalized paths handled by a catch-all op
	for _, op := range r.ImplOps {
		implSet[normKey(op)] = true
		if op.Method == "" { // HandleFunc / .Any / @RequestMapping w/o verb → any method
			implAnyPath[normPath(op)] = true
		}
	}
	isCovered := func(op SpecOp) bool {
		if implSet[normKey(op)] {
			return true
		}
		return op.SpecType == "OpenAPI" && implAnyPath[normPath(op)]
	}
	specSet := map[string]bool{}
	specPath := map[string]bool{}
	for _, op := range r.SpecOps {
		k := normKey(op)
		specSet[k] = true
		if op.SpecType == "OpenAPI" {
			specPath[normPath(op)] = true
		}
		if isCovered(op) {
			r.Covered = append(r.Covered, op)
		} else {
			r.Missing = append(r.Missing, op)
		}
	}
	for _, op := range r.ImplOps {
		if specSet[normKey(op)] {
			continue
		}
		if op.Method == "" && specPath[normPath(op)] {
			continue // catch-all that documents an existing spec path
		}
		r.Extra = append(r.Extra, op)
	}
	if len(r.SpecOps) > 0 {
		r.Coverage = int(float64(len(r.Covered))/float64(len(r.SpecOps))*100 + 0.5)
	}

	typeSet := map[string]bool{}
	for _, op := range r.SpecOps {
		typeSet[op.SpecType] = true
	}
	for t := range typeSet {
		r.SpecTypes = append(r.SpecTypes, t)
	}
	sort.Strings(r.SpecTypes)
	return r
}

// ─── SummaryCards ─────────────────────────────────────────────────────────────

func (Module) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(Result)
	if !ok || !r.HasSpec {
		return nil
	}
	return []modules.SummaryCard{
		{Num: fmt.Sprintf("%d%%", r.Coverage), Label: "API coverage"},
	}
}

// ─── RenderHTML ───────────────────────────────────────────────────────────────

func (Module) RenderHTML(res any) string {
	r, ok := res.(Result)
	if !ok || !r.HasData() {
		return ""
	}

	var b strings.Builder
	b.WriteString(`<div class="as-pop">`)

	// Subtitle: spec type badges + operation counts.
	b.WriteString(`<p class="as-pop__sub">`)
	for _, st := range r.SpecTypes {
		fmt.Fprintf(&b, `<span class="as-tag tag-tech" style="margin-right:4px">%s</span>`, esc(st))
	}
	fmt.Fprintf(&b, `%d operation(s) across %d file(s) · %d implemented · %d missing`,
		len(r.SpecOps), r.FileCount, len(r.Covered), len(r.Missing))
	if len(r.Extra) > 0 {
		fmt.Fprintf(&b, ` · <span style="color:var(--text-faint)">%d undocumented ↓ Traffic</span>`, len(r.Extra))
	}
	b.WriteString(`</p>`)

	// Coverage verdict and gradient bar.
	pct := r.Coverage
	verdict := coverageVerdict(pct, len(r.Extra))
	fmt.Fprintf(&b, `<div class="as-pop__verdict">%d%% — %s</div>`, pct, esc(verdict))

	fillCls := "fill-crit"
	if pct >= 80 {
		fillCls = "fill-good"
	} else if pct >= 50 {
		fillCls = "fill-warn"
	}
	b.WriteString(`<div class="as-pop__scale"><span class="as-pop__end">0%</span>`)
	fmt.Fprintf(&b,
		`<div class="as-pop__track" style="background:var(--bg-card)"><span class="as-bar__fill %s" style="height:100%%;width:%d%%"></span></div>`,
		fillCls, pct,
	)
	b.WriteString(`<span class="as-pop__end">100%</span></div>`)

	// Missing — shown prominently (most actionable).
	if len(r.Missing) > 0 {
		fmt.Fprintf(&b,
			`<div class="as-sub" style="margin-top:16px">Missing implementations <span style="color:var(--crit);font-weight:700">(%d)</span></div>`,
			len(r.Missing),
		)
		b.WriteString(`<table class="as-table"><thead><tr>`)
		b.WriteString(`<th>Method</th><th>Path / Operation</th><th>Spec</th><th>File</th>`)
		b.WriteString(`</tr></thead><tbody>`)
		for _, op := range r.Missing {
			m := op.Method
			if m == "" {
				m = "ANY"
			}
			fmt.Fprintf(&b,
				`<tr><td>%s</td><td class="mono">%s</td><td>%s</td><td class="mono">%s</td></tr>`,
				methodBadge(m), esc(op.Path), esc(op.SpecType), esc(filepath.Base(op.File)),
			)
		}
		b.WriteString(`</tbody></table>`)
	}

	// Implemented — always open (no details toggle).
	if len(r.Covered) > 0 {
		fmt.Fprintf(&b,
			`<div class="as-sub" style="margin-top:12px">Implemented (%d)</div>`,
			len(r.Covered),
		)
		b.WriteString(`<table class="as-table"><thead><tr>`)
		b.WriteString(`<th>Method</th><th>Path / Operation</th><th>File</th>`)
		b.WriteString(`</tr></thead><tbody>`)
		for _, op := range r.Covered {
			m := op.Method
			if m == "" {
				m = "ANY"
			}
			fmt.Fprintf(&b,
				`<tr><td>%s</td><td class="mono">%s</td><td class="mono">%s</td></tr>`,
				methodBadge(m), esc(op.Path), esc(filepath.Base(op.File)),
			)
		}
		b.WriteString(`</tbody></table>`)
	}

	// Undocumented routes are shown in the Traffic panel (SPEC COV column).

	b.WriteString(`</div>`)
	return b.String()
}

// ─── Rendering helpers ────────────────────────────────────────────────────────

func coverageVerdict(pct, extraCount int) string {
	switch {
	case pct >= 90 && extraCount == 0:
		return "Full API coverage"
	case pct >= 90:
		return "Spec covered"
	case pct >= 70:
		return "Good coverage"
	case pct >= 40:
		return "Partial coverage"
	default:
		return "Low coverage"
	}
}

func methodBadge(m string) string {
	bg, fg := methodColors(m)
	return fmt.Sprintf(
		`<span class="as-tag" style="background:%s;color:%s;font-size:11px">%s</span>`,
		bg, fg, esc(m),
	)
}

func methodColors(m string) (bg, fg string) {
	switch strings.ToUpper(m) {
	case "GET":
		return "#27ae60", "#fff"
	case "POST":
		return "#2980b9", "#fff"
	case "PUT":
		return "#f39c12", "#fff"
	case "DELETE":
		return "#e74c3c", "#fff"
	case "PATCH":
		return "#8e44ad", "#fff"
	case "RPC":
		return "#16a085", "#fff"
	case "FIELD":
		return "#795548", "#fff"
	default:
		return "#7f8c8d", "#fff"
	}
}

func esc(s string) string { return html.EscapeString(s) }
