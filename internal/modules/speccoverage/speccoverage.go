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
	case "go", "python", "java", "kotlin", "typescript", "rust":
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
	SpecOps    []SpecOp // operations defined in spec files
	ImplOps    []SpecOp // operations found in source code
	Covered    []SpecOp // SpecOps matched in code
	Missing    []SpecOp // SpecOps NOT found in code
	Extra      []SpecOp // code ops not covered by any spec ("spec not located")
	Coverage   int      // 0–100: len(Covered) / len(SpecOps) * 100  (spec → code)
	SpecReady  int      // 0–100: len(Covered) / len(ImplOps) * 100  (code → spec)
	SpecTypes  []string // e.g. ["OpenAPI", "gRPC"]
	Generators []string // e.g. ["swaggo", "oapi-codegen"]
	HasSpec    bool
	HasRoutes  bool
	FileCount  int // number of spec files found
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
	projRoot := srcRoot // never walk above the analyzed source tree

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
	// code→spec: fraction of code routes that appear in at least one spec file.
	if len(r.ImplOps) > 0 {
		r.SpecReady = int(float64(len(r.ImplOps)-len(r.Extra))/float64(len(r.ImplOps))*100 + 0.5)
	}

	typeSet := map[string]bool{}
	for _, op := range r.SpecOps {
		typeSet[op.SpecType] = true
	}
	for t := range typeSet {
		r.SpecTypes = append(r.SpecTypes, t)
	}
	sort.Strings(r.SpecTypes)

	r.Generators = detectGenerators(files, r.SpecTypes)
	return r
}

// ─── Generator detection ──────────────────────────────────────────────────────

var generatorPatterns = []struct{ needle, label string }{
	// Go
	{"swaggo/swag", "swaggo"},
	{"swaggo/gin-swagger", "swaggo"},
	{"swaggo/echo-swagger", "swaggo"},
	{"swaggo/fiber-swagger", "swaggo"},
	{"deepmap/oapi-codegen", "oapi-codegen"},
	{"ogen-go/ogen", "ogen"},
	{"99designs/gqlgen", "gqlgen"},
	{"grpc-ecosystem/grpc-gateway", "grpc-gateway"},
	// TypeScript / JS
	{"@nestjs/swagger", "nestjs-swagger"},
	{"swagger-jsdoc", "swagger-jsdoc"},
	{"openapi-typescript-codegen", "ts-codegen"},
	// Java / Kotlin
	{"springdoc", "springdoc"},
	{"io.swagger.v3", "swagger3"},
}

// detectGenerators scans source file imports for known spec generation tools.
// If gRPC specs are present, "protoc" is always included.
func detectGenerators(files []*parser.ParsedFile, specTypes []string) []string {
	found := map[string]bool{}
	for _, f := range files {
		for _, imp := range f.Imports {
			low := strings.ToLower(imp)
			for _, g := range generatorPatterns {
				if strings.Contains(low, g.needle) {
					found[g.label] = true
				}
			}
		}
	}
	for _, st := range specTypes {
		if st == "gRPC" {
			found["protoc"] = true
		}
	}
	if len(found) == 0 {
		return nil
	}
	var result []string
	for label := range found {
		result = append(result, label)
	}
	sort.Strings(result)
	return result
}

// ─── SummaryCards ─────────────────────────────────────────────────────────────

func (Module) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(Result)
	if !ok || !r.HasSpec {
		return nil
	}
	cards := []modules.SummaryCard{
		{Num: fmt.Sprintf("%d%%", r.SpecReady), Label: "API coverage"},
	}
	if len(r.Generators) > 0 {
		cards = append(cards, modules.SummaryCard{
			Num:   strings.Join(r.Generators, " · "),
			Label: "generators",
		})
	}
	return cards
}

// ─── RenderMarkdown ───────────────────────────────────────────────────────────

func (Module) RenderMarkdown(res any) string {
	r, ok := res.(Result)
	if !ok || !r.HasData() {
		return ""
	}
	var b strings.Builder

	if len(r.SpecTypes) > 0 {
		fmt.Fprintf(&b, "**Spec types:** %s\n\n", strings.Join(r.SpecTypes, " · "))
	}
	if len(r.Generators) > 0 {
		fmt.Fprintf(&b, "**Generators:** %s\n\n", strings.Join(r.Generators, " · "))
	}

	missing := len(r.Extra)
	implemented := len(r.ImplOps) - len(r.Extra)
	fmt.Fprintf(&b, "**%d%% code→spec** · %d endpoint in spec · %d missing spec entries · %d spec files\n\n",
		r.SpecReady, implemented, missing, r.FileCount)

	if len(r.SpecOps) > 0 {
		seen := map[string]string{}
		var specFiles []string
		for _, op := range r.SpecOps {
			if _, ok := seen[op.File]; !ok {
				seen[op.File] = op.SpecType
				specFiles = append(specFiles, op.File)
			}
		}
		sort.Strings(specFiles)
		b.WriteString("**Spec Locations**\n\n")
		b.WriteString("| Type | File |\n")
		b.WriteString("|------|------|\n")
		for _, f := range specFiles {
			fmt.Fprintf(&b, "| %s | %s |\n", seen[f], f)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ─── RenderHTML ───────────────────────────────────────────────────────────────

func (Module) RenderHTML(res any) string {
	r, ok := res.(Result)
	if !ok || !r.HasData() {
		return ""
	}

	var b strings.Builder
	b.WriteString(`<div class="as-pop">`)

	// Subtitle: spec type badges + generator badges.
	b.WriteString(`<p class="as-pop__sub">`)
	for _, st := range r.SpecTypes {
		fmt.Fprintf(&b, `<span class="as-tag tag-tech" style="margin-right:4px">%s</span>`, esc(st))
	}
	for _, g := range r.Generators {
		fmt.Fprintf(&b, `<span class="as-tag" style="background:var(--accent-dim);color:var(--accent);margin-right:4px" title="detected generator">%s</span>`, esc(g))
	}
	b.WriteString(`</p>`)

	// Main metric: API Coverage bar (code → spec).
	pct := r.SpecReady
	fmt.Fprintf(&b, `<div class="as-pop__verdict">%d%% — %s</div>`, pct, esc(coverageVerdict(pct, len(r.Extra))))
	b.WriteString(`<div style="font-size:11px;color:var(--text-faint);margin-bottom:8px">code→spec · what % of code routes have a spec entry</div>`)
	b.WriteString(`<div class="as-pop__scale"><span class="as-pop__end">0%</span>`)
	fmt.Fprintf(&b, `<div class="as-pop__track" style="background:var(--bg-card)"><span class="as-bar__fill %s" style="height:100%%;width:%d%%"></span></div>`, barFillClass(pct), pct)
	b.WriteString(`<span class="as-pop__end">100%</span></div>`)

	// Stats row as card columns: Missing / Implemented / Spec files.
	missing := len(r.Extra)
	implemented := len(r.ImplOps) - len(r.Extra)
	b.WriteString(`<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:14px">`)
	specStatCard(&b, fmt.Sprintf("%d", missing), "Missing spec entries for endpoint", "var(--crit)")
	specStatCard(&b, fmt.Sprintf("%d", implemented), "Endpoint in spec", "var(--good)")
	specStatCard(&b, fmt.Sprintf("%d", r.FileCount), "Spec files", "var(--text)")
	b.WriteString(`</div>`)

	// Spec Locations + Generators side by side.
	if len(r.SpecOps) > 0 || len(r.Generators) > 0 {
		hasGen := len(r.Generators) > 0
		if hasGen {
			b.WriteString(`<div style="display:grid;grid-template-columns:1fr auto;gap:20px;margin-top:14px">`)
		} else {
			b.WriteString(`<div style="margin-top:14px">`)
		}

		// Spec file locations.
		if len(r.SpecOps) > 0 {
			seen := map[string]string{}
			var specFiles []string
			for _, op := range r.SpecOps {
				if _, ok := seen[op.File]; !ok {
					seen[op.File] = op.SpecType
					specFiles = append(specFiles, op.File)
				}
			}
			sort.Strings(specFiles)
			b.WriteString(`<div>`)
			b.WriteString(`<div class="as-sub">Spec Locations</div>`)
			b.WriteString(`<div style="display:flex;flex-direction:column;gap:4px;margin-top:4px">`)
			for _, f := range specFiles {
				fmt.Fprintf(&b,
					`<div style="display:flex;align-items:center;gap:8px">`+
						`<span class="as-tag tag-tech" style="font-size:10px;padding:1px 6px">%s</span>`+
						`<span class="mono" style="font-size:11px;color:var(--text-dim)">%s</span>`+
						`</div>`,
					esc(seen[f]), esc(f))
			}
			b.WriteString(`</div></div>`)
		}

		// Detected generators column.
		if hasGen {
			b.WriteString(`<div>`)
			b.WriteString(`<div class="as-sub">Generators</div>`)
			b.WriteString(`<div style="display:flex;flex-direction:column;gap:4px;margin-top:4px">`)
			for _, g := range r.Generators {
				fmt.Fprintf(&b,
					`<span class="as-tag" style="background:var(--accent-dim);color:var(--accent);white-space:nowrap">%s</span>`,
					esc(g))
			}
			b.WriteString(`</div></div>`)
		}

		b.WriteString(`</div>`)
	}

	b.WriteString(`</div>`)
	return b.String()
}

func specStatCard(b *strings.Builder, num, label, color string) {
	fmt.Fprintf(b,
		`<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:10px 12px;text-align:center">`+
			`<div style="font-size:22px;font-weight:700;font-family:var(--mono);color:%s;line-height:1.1">%s</div>`+
			`<div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.04em;margin-top:2px">%s</div>`+
			`</div>`,
		color, esc(num), esc(label))
}

// ─── Rendering helpers ────────────────────────────────────────────────────────

func barFillClass(pct int) string {
	if pct >= 80 {
		return "fill-good"
	} else if pct >= 50 {
		return "fill-warn"
	}
	return "fill-crit"
}

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

func esc(s string) string { return html.EscapeString(s) }
