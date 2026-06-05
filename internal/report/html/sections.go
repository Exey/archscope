package html

import (
	"fmt"
	"html"
	"math"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/exey/archscope/internal/git"
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/result"
	"github.com/exey/archscope/internal/scanner"
	"github.com/exey/archscope/internal/security"
)

// ── Tech Stack + Packages & Modules (goscope-style global section) ──────────

// techImportMap maps an import substring (case-insensitive) to a framework /
// library label surfaced in the tech-stack cloud. Cross-language, like
// goscope's detectTechFromImport generalized.
var techImportMap = []struct{ needle, label string }{
	{"swiftui", "SwiftUI"}, {"uikit", "UIKit"}, {"combine", "Combine"},
	{"coredata", "Core Data"}, {"foundation", "Foundation"}, {"xctest", "XCTest"},
	{"react", "React"}, {"next", "Next.js"}, {"vue", "Vue"}, {"angular", "Angular"},
	{"express", "Express"}, {"@nestjs", "NestJS"}, {"redux", "Redux"}, {"rxjs", "RxJS"},
	{"django", "Django"}, {"flask", "Flask"}, {"fastapi", "FastAPI"},
	{"sqlalchemy", "SQLAlchemy"}, {"pytest", "pytest"}, {"numpy", "NumPy"},
	{"pandas", "pandas"}, {"tensorflow", "TensorFlow"}, {"torch", "PyTorch"},
	{"net/http", "net/http"}, {"gin-gonic", "Gin"}, {"gorilla", "Gorilla"},
	{"gorm.io", "GORM"}, {"grpc", "gRPC"}, {"graphql", "GraphQL"}, {"cobra", "Cobra"},
}

var langLabels = map[string]string{
	"swift": "Swift", "objc": "Objective-C", "python": "Python",
	"typescript": "TypeScript / JS", "go": "Go",
}

func renderStackAndModules(res *result.AnalysisResult) string {
	// Tech stack: languages present + frameworks detected from imports + scanner.
	langSet := map[string]bool{}
	frameworkSet := map[string]bool{}
	for _, f := range res.Files {
		if lbl, ok := langLabels[f.LanguageID]; ok {
			langSet[lbl] = true
		}
		for _, imp := range f.Imports {
			low := strings.ToLower(imp)
			for _, t := range techImportMap {
				if strings.Contains(low, t.needle) {
					frameworkSet[t.label] = true
				}
			}
		}
	}
	// Merge in Technologies from docker-compose / go.mod / Makefile.
	for _, t := range res.Technologies {
		frameworkSet[t] = true
	}
	if len(langSet)+len(frameworkSet) == 0 && len(res.Scan.Modules) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString(`<div class="as-section"><div class="as-section__head"><span class="ico">🧰</span><h2>Tech Stack &amp; Modules</h2></div>`)

	// Tech stack tag cloud.
	b.WriteString(`<div class="as-sub">Tech stack</div><div class="as-tagcloud">`)
	for _, l := range sortedKeys(langSet) {
		fmt.Fprintf(&b, `<span class="as-tag tag-local">%s</span>`, esc(l))
	}
	for _, fw := range sortedKeys(frameworkSet) {
		fmt.Fprintf(&b, `<span class="as-tag tag-tech">%s</span>`, esc(fw))
	}
	if len(langSet)+len(frameworkSet) == 0 {
		b.WriteString(`<span class="as-empty">No technologies detected.</span>`)
	}
	b.WriteString(`</div>`)

	// Packages & modules grid, sized by LOC.
	type modAgg struct {
		name      string
		loc       int
		platforms map[langspec.Platform]bool
	}
	aggs := map[string]*modAgg{}
	for _, f := range res.Files {
		a := aggs[f.ModuleName]
		if a == nil {
			a = &modAgg{name: f.ModuleName, platforms: map[langspec.Platform]bool{}}
			aggs[f.ModuleName] = a
		}
		a.loc += f.LineCount
		a.platforms[langspec.Platform(f.Platform)] = true
	}
	var list []*modAgg
	for _, a := range aggs {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].loc != list[j].loc {
			return list[i].loc > list[j].loc
		}
		return list[i].name < list[j].name
	})
	fmt.Fprintf(&b, `<div class="as-sub" style="margin-top:16px">Packages &amp; modules <span style="color:var(--text-faint);font-weight:400;text-transform:none;letter-spacing:0">(%d)</span></div>`, len(list))
	if len(list) == 0 {
		b.WriteString(`<p class="as-empty">No modules detected.</p>`)
	} else {
		b.WriteString(`<div class="as-pkggrid">`)
		for _, a := range list {
			name := a.name
			if name == "" {
				name = "(root)"
			}
			platBadges := platformBadges(a.platforms)
			fmt.Fprintf(&b, `<div class="as-pkg"><span class="as-pkg__name">📦 %s</span><span class="as-pkg__meta">%s<span class="as-pkg__loc">%s loc</span></span></div>`,
				esc(name), platBadges, fmtNum(a.loc))
		}
		b.WriteString(`</div>`)
	}

	// DevOps card
	if devops := renderDevOpsCard(res); devops != "" {
		b.WriteString(devops)
	}

	b.WriteString(`</div>`)
	return b.String()
}

func renderDevOpsCard(res *result.AnalysisResult) string {
	if len(res.DevOpsTools) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="as-sub" style="margin-top:16px">DevOps</div><div class="arch-components">`)
	for _, t := range res.DevOpsTools {
		fmt.Fprintf(&b, `<span class="arch-component"><span class="comp-icon">%s</span><span>%s</span></span>`, t.Icon, esc(t.Name))
	}
	b.WriteString(`</div>`)
	return b.String()
}

// platformBadges renders compact language label chips for a set of platforms.
func platformBadges(platforms map[langspec.Platform]bool) string {
	order := []langspec.Platform{
		langspec.PlatformSwiftObjC,
		langspec.PlatformKotlin,
		langspec.PlatformTSJS,
		langspec.PlatformPython,
		langspec.PlatformGo,
	}
	short := map[langspec.Platform]string{
		langspec.PlatformSwiftObjC: "Swift",
		langspec.PlatformKotlin:    "Kotlin",
		langspec.PlatformTSJS:      "JS",
		langspec.PlatformPython:    "Python",
		langspec.PlatformGo:        "Go",
	}
	var b strings.Builder
	for _, p := range order {
		if platforms[p] {
			fmt.Fprintf(&b, `<span class="as-plat-badge as-plat-%s">%s</span>`, string(p), short[p])
		}
	}
	return b.String()
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fmtNum(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	return fmt.Sprintf("%.1fk", float64(n)/1000.0)
}

func esc(s string) string { return html.EscapeString(s) }

// bandClass maps a security band label to its color class.
func bandClass(band string) string {
	switch band {
	case "Hardened":
		return "band-good"
	case "Minor exposure":
		return "band-warn"
	case "Elevated risk":
		return "band-bad"
	default: // Critical exposure
		return "band-crit"
	}
}

// fillClass picks a bar color from a 0..100 risk percentage.
func fillClass(pct int) string {
	switch {
	case pct >= 75:
		return "fill-crit"
	case pct >= 45:
		return "fill-bad"
	case pct >= 20:
		return "fill-warn"
	default:
		return "fill-good"
	}
}

func sevClass(s security.Severity) string {
	switch s {
	case security.SevHigh:
		return "sev-high"
	case security.SevMedium:
		return "sev-medium"
	default:
		return "sev-low"
	}
}

// ── Global cards ─────────────────────────────────────────────────────────────

func renderGlobalCards(res *result.AnalysisResult) string {
	decls := 0
	for _, f := range res.Files {
		decls += len(f.Declarations)
	}
	platforms := res.Scan.PlatformsOrdered()
	moduleIDs := map[string]bool{}
	for _, p := range res.ModulePanels {
		moduleIDs[p.ModuleID] = true
	}
	var b strings.Builder
	b.WriteString(`<div class="as-cards">`)
	card(&b, fmt.Sprintf("%d", res.TotalLines()), "lines of code", false)
	card(&b, fmt.Sprintf("%d", len(res.Files)), "source files", false)
	card(&b, fmt.Sprintf("%d", decls), "declarations", false)
	card(&b, fmt.Sprintf("%d", len(res.Scan.Modules)), "modules", false)
	cardDangerIndex(&b, fmt.Sprintf("%d/1000", res.SecurityScore.Total))
	card(&b, fmt.Sprintf("%d", len(platforms)), plural(len(platforms), "platform", "platforms"), false)
	b.WriteString(`</div>`)
	return b.String()
}

func card(b *strings.Builder, num, label string, accent bool) {
	cls := "as-card"
	if accent {
		cls += " as-card--accent"
	}
	fmt.Fprintf(b, `<div class="%s"><span class="as-card__num">%s</span><span class="as-card__label">%s</span></div>`,
		cls, esc(num), esc(label))
}

// cardDangerIndex renders the accented Danger Index summary card.
func cardDangerIndex(b *strings.Builder, score string) {
	b.WriteString(`<div class="as-card as-card--accent">`)
	fmt.Fprintf(b, `<span class="as-card__num">%s</span>`, esc(score))
	b.WriteString(`<span class="as-card__label">danger index</span>`)
	b.WriteString(`</div>`)
}

// ── Security index (global gauge + category breakdown) ──────────────────────

func renderSecurityIndex(res *result.AnalysisResult) string {
	sc := res.SecurityScore
	var b strings.Builder
	b.WriteString(`<div class="as-section">`)
	b.WriteString(`<div class="as-section__head"><span class="ico">🛡️</span><h2>Danger Index</h2></div>`)
	b.WriteString(`<p class="as-section__sub">Weighted exposure across 14 categories (0 = hardened, 1000 = critical). Risk per category saturates with finding density.</p>`)

	gaugeID := "as-sec-gauge"
	descID := "as-sec-gauge-desc"

	// ── Top row: gauge (left) + weight bars (right) ──
	b.WriteString(`<div class="as-sec-toprow">`)

	// Gauge
	fmt.Fprintf(&b, `<div class="as-sec-gauge-wrap">`+
		`<svg class="as-sec-gauge-svg" id="%s" viewBox="0 0 200 124"></svg>`+
		`<div class="as-sec-gauge-label">DANGER INDEX</div>`+
		`<div class="as-sec-gauge-val">%d / 1000</div>`+
		`<div class="as-sec-gauge-band %s">%s</div>`+
		`<div class="as-sec-gauge-desc" id="%s"></div>`+
		`</div>`, gaugeID, sc.Total, bandClass(sc.Band), esc(sc.Band), descID)

	// Category weight bars
	b.WriteString(`<div class="as-sec-weight-bars"><div class="as-sec-weight-title">Category Weights · 1000 Index</div>`)
	for _, cs := range sc.Categories {
		rp := cs.RiskPercent()
		col := secRiskColor(rp)
		var fill, valHTML string
		if cs.NotAssessed() {
			fill = `<div class="as-sec-wb-fill as-sec-wb-na" style="width:100%"></div>`
			valHTML = `<span class="as-sec-wb-na">not assessed</span>`
		} else {
			fill = fmt.Sprintf(`<div class="as-sec-wb-fill" style="width:%d%%;background:%s"></div>`, rp, col)
			valHTML = fmt.Sprintf(`<span class="as-sec-wb-pts" style="color:%s">%d/%d</span>`, col, cs.Points, cs.Category.Weight)
		}
		fmt.Fprintf(&b,
			`<div class="as-sec-wb-row">`+
				`<span class="as-sec-wb-name"><span class="as-sec-wb-num">%d</span>%s %s</span>`+
				`<div class="as-sec-wb-track">%s</div>`+
				`%s<span class="as-sec-wb-w">W%d</span>`+
				`</div>`,
			cs.Category.ID, esc(cs.Category.Icon), esc(cs.Category.Title),
			fill, valHTML, cs.Category.Weight)
	}
	b.WriteString(`</div>`) // weight-bars
	b.WriteString(`</div>`) // toprow

	// ── Per-platform security breakdown ──
	filePlatform := map[string]langspec.Platform{}
	for _, f := range res.Files {
		filePlatform[f.FilePath] = langspec.Platform(f.Platform)
	}
	platFindings := map[langspec.Platform]int{}
	platHigh := map[langspec.Platform]int{}
	for _, rr := range res.Security {
		if rr.Passed() {
			continue
		}
		for _, f := range rr.Findings {
			p := filePlatform[f.FullPath]
			if p != "" {
				platFindings[p]++
				if rr.Rule.Severity == security.SevHigh {
					platHigh[p]++
				}
			}
		}
	}
	// ── Security rules / CWE reference ──
	b.WriteString(renderSecurityRules(res.Security))

	if len(platFindings) > 0 {
		b.WriteString(`<div class="as-sub" style="margin-bottom:8px">Findings by Platform</div>`)
		b.WriteString(`<div class="as-sec-plat-row">`)
		for _, pg := range res.Scan.PlatformsOrdered() {
			total := platFindings[pg.Platform]
			if total == 0 {
				continue
			}
			hi := platHigh[pg.Platform]
			hiHTML := ""
			if hi > 0 {
				fmt.Fprintf(&b, ``)
				hiHTML = fmt.Sprintf(` <span class="as-sev sev-high" style="font-size:10px">%d HIGH</span>`, hi)
			}
			fmt.Fprintf(&b,
				`<div class="as-sec-plat-card">`+
					`<div class="as-sec-plat-name">%s</div>`+
					`<div class="as-sec-plat-count">%d%s</div>`+
					`</div>`,
				esc(langspec.PlatformTitle(pg.Platform)), total, hiHTML)
		}
		b.WriteString(`</div>`)
	}

	// ── Gauge JS ──
	fmt.Fprintf(&b, `<script>(function(){`+
		`var score=%d;`+
		`var svg=document.getElementById('%s');`+
		`if(!svg)return;`+
		`var ns='http://www.w3.org/2000/svg',r=80,cx=100,cy=104;`+
		`var bg=document.createElementNS(ns,'path');`+
		`bg.setAttribute('d','M '+(cx-r)+','+cy+' A '+r+','+r+' 0 0 1 '+(cx+r)+','+cy);`+
		`bg.setAttribute('fill','none');bg.setAttribute('stroke','rgba(128,128,128,0.25)');`+
		`bg.setAttribute('stroke-width','16');bg.setAttribute('stroke-linecap','round');`+
		`svg.appendChild(bg);`+
		`var pct=Math.min(Math.max(score/1000,0.001),0.999);`+
		`var ang=Math.PI*(1-pct);`+
		`var ex=cx+r*Math.cos(ang),ey=cy-r*Math.sin(ang);`+
		`var col=pct<0.2?'#5a8a7a':pct<0.5?'#a0a030':pct<0.8?'#c0a030':'#c05040';`+
		`var fg=document.createElementNS(ns,'path');`+
		`fg.setAttribute('d','M '+(cx-r)+','+cy+' A '+r+','+r+' 0 0 1 '+ex.toFixed(2)+','+ey.toFixed(2));`+
		`fg.setAttribute('fill','none');fg.setAttribute('stroke',col);`+
		`fg.setAttribute('stroke-width','16');fg.setAttribute('stroke-linecap','round');`+
		`svg.appendChild(fg);`+
		`var ranges=[{lo:0,hi:199,col:'#5a8a7a',label:'Hardened'},{lo:200,hi:499,col:'#a0a030',label:'Minor exposure'},{lo:500,hi:799,col:'#c0a030',label:'Elevated risk'},{lo:800,hi:1000,col:'#c05040',label:'Critical exposure'}];`+
		`var desc='',cur;`+
		`for(var i=0;i<ranges.length;i++){cur=score>=ranges[i].lo&&score<=ranges[i].hi;`+
		`desc+='<div'+(cur?' style="font-weight:600;color:var(--text)"':' style="color:var(--text-faint)"')+'>'`+
		`+'<span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:'+ranges[i].col+';margin-right:5px;vertical-align:middle"></span>'`+
		`+ranges[i].lo+'–'+ranges[i].hi+': '+ranges[i].label+(cur?' ◀':'')+'</div>';}`+
		`var el=document.getElementById('%s');if(el)el.innerHTML=desc;`+
		`})()</script>`,
		sc.Total, gaugeID, descID)

	b.WriteString(`</div>`)
	return b.String()
}

// renderSecurityRules derives the CWE reference grid directly from the live
// rule set. Each rule's Rule.CWE field provides the primary CWE ID; the grid
// aggregates counts automatically so it stays in sync when rules are added.
func renderSecurityRules(results []security.RuleResult) string {
	// Display names for known CWE IDs. Unknown IDs fall back to "CWE-NNN".
	cweNames := map[string]string{
		"16":   "Security Misconfiguration",
		"22":   "Path Traversal",
		"78":   "Command Injection",
		"79":   "Cross-Site Scripting",
		"89":   "SQL Injection",
		"94":   "Code Injection",
		"119":  "Memory Corruption",
		"272":  "Least Privilege Violation",
		"295":  "Certificate Validation",
		"311":  "Missing Encryption",
		"319":  "Cleartext Transmission",
		"321":  "Hard-coded Crypto Key",
		"327":  "Broken Crypto Algorithm",
		"328":  "Weak Hash Algorithm",
		"329":  "Hardcoded IV / Nonce",
		"338":  "Weak PRNG",
		"346":  "WebView Isolation",
		"477":  "Deprecated API",
		"489":  "Active Debug Code",
		"502":  "Insecure Deserialization",
		"522":  "Insecure Credentials",
		"532":  "Sensitive Data in Logs",
		"798":  "Hardcoded Credentials",
		"922":  "Insecure Web Storage",
		"926":  "Exported Android Component",
		"942":  "CORS Wildcard",
		"943":  "NoSQL Injection",
		"476":  "Null Pointer Dereference",
		"611":  "XML External Entity (XXE)",
		"614":  "Insecure Cookie — No Secure Flag",
		"918":  "Server-Side Request Forgery",
		"1004": "HttpOnly Cookie",
		"1321": "Prototype Pollution",
		"117":  "Log Injection",
		"235":  "HTTP Parameter Pollution",
		"347":  "Improper JWT Verification",
		"362":  "Race Condition (TOCTOU)",
		"434":  "Unrestricted File Upload",
		"530":  "Android Backup Enabled",
		"616":  "Incomplete Instruction",
		"749":  "WebView JS Interface",
		"916":  "Weak Password Hash",
		"1333": "ReDoS — Catastrophic Backtracking",
		"1336": "Server-Side Template Injection",
	}

	// Language display order and their platform-badge CSS classes.
	type langMeta struct{ id, cls, label string }
	langOrder := []langMeta{
		{"go", "as-plat-go", "Go"},
		{"swift", "as-plat-swift_objc", "Swift"},
		{"python", "as-plat-python", "Python"},
		{"ts", "as-plat-ts_js", "JS/TS"},
		{"kotlin", "as-plat-kotlin", "Kotlin"},
	}

	// Aggregate per CWE: check count + which language IDs cover it.
	type cweInfo struct {
		n           int
		isUniversal bool
		langs       map[string]bool
	}
	info := map[string]*cweInfo{}
	for _, rr := range results {
		if rr.Rule.CWE == "" {
			continue
		}
		ci := info[rr.Rule.CWE]
		if ci == nil {
			ci = &cweInfo{langs: map[string]bool{}}
			info[rr.Rule.CWE] = ci
		}
		ci.n++
		if len(rr.Rule.Languages) == 0 {
			ci.isUniversal = true
		} else {
			for _, l := range rr.Rule.Languages {
				ci.langs[l] = true
			}
		}
	}

	type entry struct{ id string; ci *cweInfo }
	list := make([]entry, 0, len(info))
	for id, ci := range info {
		list = append(list, entry{id, ci})
	}
	sort.Slice(list, func(i, j int) bool {
		ni, _ := strconv.Atoi(list[i].id)
		nj, _ := strconv.Atoi(list[j].id)
		return ni < nj
	})

	var b strings.Builder
	fmt.Fprintf(&b,
		`<div class="as-sub" style="margin-top:18px;margin-bottom:8px">`+
			`Security Rules <span style="color:var(--text-faint);font-weight:400;text-transform:none;letter-spacing:0">(%d total checks)</span>`+
			`</div>`,
		len(results))
	if len(list) == 0 {
		return b.String()
	}
	b.WriteString(`<div class="as-cwe-grid">`)
	for _, e := range list {
		name, ok := cweNames[e.id]
		if !ok {
			name = "CWE-" + e.id
		}
		url := fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", e.id)
		word := "check"
		if e.ci.n != 1 {
			word = "checks"
		}
		// Build language badge HTML.
		var langHTML strings.Builder
		if e.ci.isUniversal {
			langHTML.WriteString(`<span class="as-plat-badge as-plat-universal">All</span>`)
		} else {
			for _, lm := range langOrder {
				if e.ci.langs[lm.id] {
					fmt.Fprintf(&langHTML, `<span class="as-plat-badge %s">%s</span>`, lm.cls, lm.label)
				}
			}
		}
		fmt.Fprintf(&b,
			`<div class="as-cwe-item">`+
				`<div class="as-cwe-top"><a class="as-cwe-item-id" href="%s" target="_blank" rel="noopener noreferrer">CWE-%s</a>%s</div>`+
				`<span class="as-cwe-item-name">%s <span class="as-cwe-count">(%d %s)</span></span>`+
				`</div>`,
			url, e.id, langHTML.String(), esc(name), e.ci.n, word)
	}
	b.WriteString(`</div>`)
	return b.String()
}

func secRiskColor(pct int) string {
	switch {
	case pct < 25:
		return "#5a8a7a"
	case pct < 50:
		return "#a0a030"
	case pct < 75:
		return "#c0a030"
	default:
		return "#c05040"
	}
}

// ── Tabs ─────────────────────────────────────────────────────────────────────

func renderTabs(res *result.AnalysisResult) string {
	platforms := res.Scan.PlatformsOrdered()
	if len(platforms) == 0 {
		return `<p class="as-empty">No source files matched any registered language.</p>`
	}
	// Sort tabs by total lines of code, largest first (most-left).
	loc := map[langspec.Platform]int{}
	for _, f := range res.Files {
		loc[langspec.Platform(f.Platform)] += f.LineCount
	}
	platforms = append([]*scanner.PlatformGroup(nil), platforms...)
	sort.SliceStable(platforms, func(i, j int) bool {
		li, lj := loc[platforms[i].Platform], loc[platforms[j].Platform]
		if li != lj {
			return li > lj
		}
		return platforms[i].FileCount > platforms[j].FileCount
	})
	var b strings.Builder
	b.WriteString(`<div class="as-tabs">`)
	// radios
	for i := range platforms {
		checked := ""
		if i == 0 {
			checked = " checked"
		}
		fmt.Fprintf(&b, `<input class="as-tabs__radios" type="radio" name="astab" id="t%d"%s>`, i, checked)
	}
	// tab bar
	b.WriteString(`<div class="as-tabbar">`)
	for i, pg := range platforms {
		fmt.Fprintf(&b, `<label class="as-tab" for="t%d">%s<span class="as-tab__count">%d</span></label>`,
			i, esc(langspec.PlatformTitle(pg.Platform)), pg.FileCount)
	}
	b.WriteString(`</div>`)
	// panels
	b.WriteString(`<div class="as-panels">`)
	for i, pg := range platforms {
		fmt.Fprintf(&b, `<div class="as-tabpanel" id="p%d">`, i)
		b.WriteString(renderPlatformPanel(res, pg))
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div></div>`)
	return b.String()
}

func renderPlatformPanel(res *result.AnalysisResult, pg *scanner.PlatformGroup) string {
	files := res.FilesForPlatform(pg.Platform)
	lines, decls := 0, 0
	langCount := map[string]bool{}
	for _, f := range files {
		lines += f.LineCount
		decls += len(f.Declarations)
		langCount[f.LanguageID] = true
	}

	var b strings.Builder
	// per-platform cards
	b.WriteString(`<div class="as-cards">`)
	card(&b, fmt.Sprintf("%d", pg.FileCount), "files", false)
	card(&b, fmt.Sprintf("%d", lines), "lines", false)
	card(&b, fmt.Sprintf("%d", decls), "declarations", false)
	card(&b, fmt.Sprintf("%d", len(pg.Modules)), plural(len(pg.Modules), "module", "modules"), false)
	b.WriteString(`</div>`)

	// Architecture layers + tech components (all platforms)
	if layersHTML := renderArchLayers(files); layersHTML != "" {
		techSet := buildTechSet(res, files)
		componentsHTML := renderArchComponents(files, techSet)
		b.WriteString(`<div class="as-section"><div class="as-section__head"><span class="ico">🏛️</span><h3>Architecture</h3></div>`)
		b.WriteString(layersHTML)
		b.WriteString(componentsHTML)
		b.WriteString(`</div>`)
	}

	// 1. 🛡️ Danger Details — security findings for this platform
	b.WriteString(renderPlatformSecurity(res, pg.Platform))

	// 2. 📝 TODOs & FIXMEs
	b.WriteString(renderPenetrationMatrix(files))
	b.WriteString(renderTodosFixmes(files))

	// 3. 🕸️ Dependency Hotspots
	b.WriteString(renderHotspots(res, pg))

	// 4. 📏 Longest Functions
	b.WriteString(renderLongestFunctions(files, res.RootPath))

	// 5. 🔧 Microservices / 📦 Packages & Modules — module/package grid (last)
	if len(pg.Modules) > 0 {
		icon, label := langspec.Default.ModuleNoun(pg.Platform)
		fmt.Fprintf(&b, `<div class="as-section"><div class="as-section__head"><span class="ico">%s</span><h3>%s <span class="as-count">(%d)</span></h3></div><div class="as-modgrid">`,
			esc(icon), esc(label), len(pg.Modules))
		counts := map[string]int{}
		mloc := map[string]int{}
		for _, f := range files {
			counts[f.ModuleName]++
			mloc[f.ModuleName] += f.LineCount
		}
		for _, m := range pg.Modules {
			name := m
			if name == "" {
				name = "(root)"
			}
			fmt.Fprintf(&b, `<a class="as-mod" href="#mod-%s"><div class="as-mod__name">%s</div><div class="as-mod__meta">%d %s · %s loc</div></a>`,
				esc(anchorID(m)), esc(name), counts[m], plural(counts[m], "file", "files"), fmtNum(mloc[m]))
		}
		b.WriteString(`</div></div>`)
	}

	// language-scoped + universal report-module panels
	b.WriteString(renderModulePanels(res.PanelsForPlatform(pg.Platform)))
	return b.String()
}

// buildTechSet builds a technology set from the result and a file list.
func buildTechSet(res *result.AnalysisResult, files []*parser.ParsedFile) map[string]bool {
	ts := map[string]bool{}
	for _, t := range res.Technologies {
		ts[t] = true
	}
	for _, f := range files {
		for _, imp := range f.Imports {
			low := strings.ToLower(imp)
			for _, t := range techImportMap {
				if strings.Contains(low, t.needle) {
					ts[t.label] = true
				}
			}
		}
	}
	return ts
}

func renderHotspots(res *result.AnalysisResult, pg *scanner.PlatformGroup) string {
	inPlatform := map[string]bool{}
	for _, m := range pg.Modules {
		inPlatform[m] = true
	}
	// Per-module Lines / Decl tallies for this platform.
	mloc := map[string]int{}
	mdecl := map[string]int{}
	for _, f := range res.FilesForPlatform(pg.Platform) {
		name := f.ModuleName
		if name == "" {
			name = "root"
		}
		mloc[name] += f.LineCount
		mdecl[name] += len(f.Declarations)
	}

	type row struct {
		name  string
		uses  int // in-degree: modules depending on this one
		lines int
		decl  int
	}
	var rows []row
	for _, h := range res.Hotspots {
		if !inPlatform[h.Name] && !(h.Name == "root" && inPlatform[""]) {
			continue
		}
		rows = append(rows, row{h.Name, h.InDeg, mloc[h.Name], mdecl[h.Name]})
	}
	if len(rows) == 0 {
		return ""
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].uses != rows[j].uses {
			return rows[i].uses > rows[j].uses
		}
		return rows[i].lines > rows[j].lines
	})
	if len(rows) > 12 {
		rows = rows[:12]
	}

	var b strings.Builder
	b.WriteString(`<div class="as-section"><div class="as-section__head"><span class="ico">🕸️</span><h3>Dependency Hotspots</h3></div>`)
	b.WriteString(`<p class="as-section__sub">Modules imported or referenced by the most others — the highest-leverage nodes in the codebase.</p>`)

	// Backend platforms additionally get an inline module dependency graph.
	if !langspec.Default.IsClientPlatform(pg.Platform) {
		if g := renderModuleGraphSVG(res, inPlatform); g != "" {
			b.WriteString(g)
		}
	}

	b.WriteString(`<table class="as-table as-hot__table"><thead><tr><th>Module</th><th>Uses</th><th>Lines</th><th>Decl</th></tr></thead><tbody>`)
	for _, r := range rows {
		name := r.name
		if name == "root" {
			name = "(root)"
		}
		fmt.Fprintf(&b, `<tr><td class="mono">%s</td><td class="mono">%d</td><td class="mono">%s</td><td class="mono">%d</td></tr>`,
			esc(name), r.uses, fmtNum(r.lines), r.decl)
	}
	b.WriteString(`</tbody></table></div>`)
	return b.String()
}

// renderModuleGraphSVG draws a compact, self-contained circular dependency
// graph of the platform's modules: node radius scales with in-degree, edges are
// drawn as arrows from dependent → dependency. Pure inline SVG (no JS/CDN), so
// the report stays a single self-contained file.
func renderModuleGraphSVG(res *result.AnalysisResult, inPlatform map[string]bool) string {
	if res.Graph == nil {
		return ""
	}
	keep := func(m string) bool {
		return inPlatform[m] || (m == "root" && inPlatform[""])
	}
	// Collect nodes present in this platform with their in-degree.
	indeg := map[string]int{}
	for _, h := range res.Hotspots {
		if keep(h.Name) {
			indeg[h.Name] = h.InDeg
		}
	}
	var nodes []string
	for _, h := range res.Hotspots {
		if keep(h.Name) {
			nodes = append(nodes, h.Name)
		}
	}
	if len(nodes) < 2 {
		return ""
	}
	sort.SliceStable(nodes, func(i, j int) bool { return indeg[nodes[i]] > indeg[nodes[j]] })
	if len(nodes) > 14 {
		nodes = nodes[:14]
	}
	idx := map[string]int{}
	for i, n := range nodes {
		idx[n] = i
	}
	var edges [][2]string
	for _, e := range res.Graph.Edges() {
		if _, ok := idx[e[0]]; !ok {
			continue
		}
		if _, ok := idx[e[1]]; !ok {
			continue
		}
		edges = append(edges, e)
	}

	const w, h = 660, 300
	cx, cy := float64(w)/2, float64(h)/2
	radius := 110.0
	type pt struct{ x, y float64 }
	pos := make([]pt, len(nodes))
	for i := range nodes {
		ang := 2 * math.Pi * float64(i) / float64(len(nodes))
		pos[i] = pt{cx + radius*math.Cos(ang), cy + radius*math.Sin(ang)}
	}
	maxIn := 1
	for _, n := range nodes {
		if indeg[n] > maxIn {
			maxIn = indeg[n]
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<div class="as-graph"><svg viewBox="0 0 %d %d" class="as-graph__svg" xmlns="http://www.w3.org/2000/svg">`, w, h)
	b.WriteString(`<defs><marker id="arw" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="var(--text-faint)"/></marker></defs>`)
	for _, e := range edges {
		a, c := pos[idx[e[0]]], pos[idx[e[1]]]
		// shorten toward target so the arrowhead sits at the node edge
		dx, dy := c.x-a.x, c.y-a.y
		d := math.Hypot(dx, dy)
		if d == 0 {
			continue
		}
		tr := 14.0
		ex, ey := c.x-dx/d*tr, c.y-dy/d*tr
		fmt.Fprintf(&b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="var(--border-strong)" stroke-width="1.2" marker-end="url(#arw)"/>`, a.x, a.y, ex, ey)
	}
	for i, n := range nodes {
		r := 7.0 + 13.0*float64(indeg[n])/float64(maxIn)
		label := n
		if label == "root" {
			label = "(root)"
		}
		fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="%.1f" fill="var(--accent)" fill-opacity="0.85" stroke="var(--bg-elev)" stroke-width="1.5"><title>%s — %d dependents</title></circle>`,
			pos[i].x, pos[i].y, r, esc(label), indeg[n])
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" text-anchor="middle" class="as-graph__lbl">%s</text>`,
			pos[i].x, pos[i].y+r+11, esc(label))
	}
	b.WriteString(`</svg></div>`)
	return b.String()
}

// renderPlatformSecurity shows findings whose file belongs to the platform.
func renderPlatformSecurity(res *result.AnalysisResult, plat langspec.Platform) string {
	pmap := map[string]langspec.Platform{}
	for _, f := range res.Files {
		pmap[f.FilePath] = langspec.Platform(f.Platform)
	}
	var filtered []security.RuleResult
	total := 0
	for _, rr := range res.Security {
		var fs []security.Finding
		for _, f := range rr.Findings {
			if pmap[f.FullPath] == plat {
				fs = append(fs, f)
			}
		}
		if len(fs) > 0 {
			filtered = append(filtered, security.RuleResult{Rule: rr.Rule, Findings: fs, TotalCount: len(fs)})
			total += len(fs)
		}
	}
	var b strings.Builder
	b.WriteString(`<div class="as-section"><div class="as-section__head"><span class="ico">🛡️</span><h3>Danger Details</h3></div>`)
	if total == 0 {
		b.WriteString(`<p class="as-clean">✓ No findings in this platform's sources.</p></div>`)
		return b.String()
	}
	// severity tally
	hi, med, lo := 0, 0, 0
	for _, rr := range filtered {
		switch rr.Rule.Severity {
		case security.SevHigh:
			hi += rr.TotalCount
		case security.SevMedium:
			med += rr.TotalCount
		default:
			lo += rr.TotalCount
		}
	}
	fmt.Fprintf(&b, `<p class="as-section__sub"><span class="as-sev sev-high">HIGH %d</span> <span class="as-sev sev-medium">MED %d</span> <span class="as-sev sev-low">LOW %d</span></p>`, hi, med, lo)
	b.WriteString(renderFindings(filtered))
	b.WriteString(`</div>`)
	return b.String()
}

func renderFindings(results []security.RuleResult) string {
	// order: HIGH→LOW then by id
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Rule.Severity.Rank() != results[j].Rule.Severity.Rank() {
			return results[i].Rule.Severity.Rank() > results[j].Rule.Severity.Rank()
		}
		return results[i].Rule.ID < results[j].Rule.ID
	})
	var b strings.Builder
	for _, rr := range results {
		b.WriteString(`<div class="as-rule">`)
		cweLink := ""
		if rr.Rule.CWE != "" {
			cweURL := fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", rr.Rule.CWE)
			cweLink = fmt.Sprintf(`<a class="as-rule__cwe" href="%s" target="_blank" rel="noopener noreferrer">[CWE-%s]</a>`,
				esc(cweURL), rr.Rule.CWE)
		}
		fmt.Fprintf(&b, `<div class="as-rule__head"><span class="as-sev %s">%s</span><span class="as-rule__name">%s</span><span class="as-rule__id">%s</span>%s<span class="as-rule__count">%d %s</span></div>`,
			sevClass(rr.Rule.Severity), esc(string(rr.Rule.Severity)), esc(rr.Rule.Name), esc(rr.Rule.ID), cweLink,
			rr.TotalCount, plural(rr.TotalCount, "finding", "findings"))
		if rr.Rule.Description != "" {
			fmt.Fprintf(&b, `<div class="as-rule__desc">%s</div>`, esc(rr.Rule.Description))
		}
		shown := rr.Findings
		const maxFindings = 15
		truncated := 0
		if len(shown) > maxFindings {
			truncated = len(shown) - maxFindings
			shown = shown[:maxFindings]
		}
		for _, f := range shown {
			author := ""
			if f.Author != "" {
				author = fmt.Sprintf(`<span class="as-find__author">— %s</span>`, esc(f.Author))
			}
			loc := fmt.Sprintf(`%s:%d`, esc(f.File), f.Line)
			if href := vscodeHref(f.FullPath, f.Line); href != "" {
				loc = fmt.Sprintf(`<a class="as-find__loc as-vs" href="%s" title="Open in VS Code">%s:%d</a>`, esc(href), esc(f.File), f.Line)
			} else {
				loc = fmt.Sprintf(`<span class="as-find__loc">%s:%d</span>`, esc(f.File), f.Line)
			}
			fmt.Fprintf(&b, `<div class="as-find">%s%s`, loc, author)
			if f.Snippet != "" {
				fmt.Fprintf(&b, `<span class="as-find__snip">%s</span>`, esc(f.Snippet))
			}
			b.WriteString(`</div>`)
		}
		if truncated > 0 {
			fmt.Fprintf(&b, `<div class="as-more">+ %d more %s</div>`, truncated, plural(truncated, "finding", "findings"))
		}
		b.WriteString(`</div>`)
	}
	return b.String()
}

func renderModulePanels(panels []result.ModulePanel) string {
	if len(panels) == 0 {
		return ""
	}
	var b strings.Builder
	for _, p := range panels {
		b.WriteString(`<div class="as-section as-modpanel">`)
		b.WriteString(`<div class="as-modpanel__head">`)
		fmt.Fprintf(&b, `<span class="ico">%s</span><h4>%s</h4>`, moduleIcon(p.ModuleID), esc(p.Title))
		for _, c := range p.Cards {
			fmt.Fprintf(&b, `<span class="as-rule__id">%s %s</span>`, esc(c.Num), esc(c.Label))
		}
		b.WriteString(`</div>`)
		b.WriteString(p.HTML) // module HTML is produced by trusted in-process modules
		b.WriteString(`</div>`)
	}
	return b.String()
}

func moduleIcon(id string) string {
	switch id {
	case "architecture":
		return "🏛️"
	case "designpattern":
		return "🧩"
	case "oopvspop":
		return "⚖️"
	default:
		return "📐"
	}
}

// ── Git section (repo-wide) ──────────────────────────────────────────────────

func renderGit(res *result.AnalysisResult) string {
	g := res.Git
	var b strings.Builder
	b.WriteString(`<div class="as-section"><div class="as-section__head"><span class="ico">🐙</span><h2>Git Analysis</h2></div>`)
	if !g.Available {
		b.WriteString(`<p class="as-empty">No git history available (the analyzed path is not a git repository, or git is not installed). Clone with full history to populate team, churn and branching insights.</p></div>`)
		return b.String()
	}
	b.WriteString(renderBranchingModel(g.Branch))
	b.WriteString(`<div class="as-grid2">`)
	b.WriteString(renderTeam(g.Authors))
	b.WriteString(renderChurn(g.Churn))
	b.WriteString(`</div>`)
	b.WriteString(`<div class="as-grid2">`)
	b.WriteString(renderTagsCommits(g.Tags, g.Commits))
	b.WriteString(renderBranches(g.Branch))
	b.WriteString(`</div>`)
	b.WriteString(`</div>`)
	return b.String()
}

func renderBranchingModel(bs git.BranchStats) string {
	m := bs.Model
	var b strings.Builder
	b.WriteString(`<div class="as-sub">Branching Model</div>`)
	b.WriteString(`<div class="as-model">`)
	fmt.Fprintf(&b, `<span class="as-model__ico">%s</span><div><div class="as-model__name">%s</div><div class="as-model__detail">%s</div></div>`,
		m.Model.Icon(), esc(string(m.Model)), esc(m.Model.Detail()))
	if m.Confidence > 0 {
		fmt.Fprintf(&b, `<span class="as-model__conf">%d%% confidence · primary: %s</span>`, int(m.Confidence*100+0.5), esc(bs.PrimaryBranch))
	}
	b.WriteString(`</div>`)
	if len(m.Signals) > 0 {
		b.WriteString(`<div class="as-signals">`)
		for _, s := range m.Signals {
			fmt.Fprintf(&b, `<span class="as-signal">%s</span>`, esc(s))
		}
		b.WriteString(`</div>`)
	}
	return b.String()
}

func renderTeam(authors map[string]*git.AuthorStats) string {
	type row struct {
		name    string
		commits int
		files   int
	}
	var rows []row
	for name, a := range authors {
		rows = append(rows, row{name, a.TotalCommits, a.FilesModified})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].commits != rows[j].commits {
			return rows[i].commits > rows[j].commits
		}
		return rows[i].name < rows[j].name
	})
	if len(rows) > 10 {
		rows = rows[:10]
	}
	var b strings.Builder
	b.WriteString(`<div><div class="as-sub">Top Contributors</div>`)
	if len(rows) == 0 {
		b.WriteString(`<p class="as-empty">No authors found.</p></div>`)
		return b.String()
	}
	b.WriteString(`<table class="as-table"><thead><tr><th>Author</th><th>Commits</th><th>Files</th></tr></thead><tbody>`)
	for _, r := range rows {
		fmt.Fprintf(&b, `<tr><td>%s</td><td class="mono">%d</td><td class="mono">%d</td></tr>`, esc(r.name), r.commits, r.files)
	}
	b.WriteString(`</tbody></table></div>`)
	return b.String()
}

func renderChurn(churn []git.FileChurnStat) string {
	var b strings.Builder
	b.WriteString(`<div><div class="as-sub">File Churn</div>`)
	if len(churn) == 0 {
		b.WriteString(`<p class="as-empty">No churn data.</p></div>`)
		return b.String()
	}
	if len(churn) > 10 {
		churn = churn[:10]
	}
	b.WriteString(`<table class="as-table"><thead><tr><th>File</th><th>Changes</th></tr></thead><tbody>`)
	for _, c := range churn {
		fmt.Fprintf(&b, `<tr><td class="mono">%s</td><td class="mono">%d</td></tr>`, esc(shortenPathFront(c.RelPath, 45)), c.ChangeCount)
	}
	b.WriteString(`</tbody></table></div>`)
	return b.String()
}

func renderTagsCommits(t git.TagStats, c git.CommitStats) string {
	var b strings.Builder
	b.WriteString(`<div><div class="as-sub">Releases &amp; Commit Hygiene</div>`)
	fmt.Fprintf(&b, `<p class="as-section__sub">%d tags · %d semver`, t.TotalTags, t.SemverTags)
	if t.LatestSemver != "" {
		fmt.Fprintf(&b, ` · latest %s`, esc(t.LatestSemver))
	}
	b.WriteString(`</p>`)
	if len(t.SemverList) > 0 {
		lim := t.SemverList
		if len(lim) > 12 {
			lim = lim[:12]
		}
		b.WriteString(`<div>`)
		for _, tag := range lim {
			fmt.Fprintf(&b, `<span class="as-tag">%s</span>`, esc(tag))
		}
		b.WriteString(`</div>`)
	}
	if c.Total > 0 {
		pct := c.Typed * 100 / c.Total
		fmt.Fprintf(&b, `<p class="as-section__sub" style="margin-top:10px">%d%% conventional commits (%d/%d typed)</p>`, pct, c.Typed, c.Total)
		if len(c.TypeCounts) > 0 {
			type kv struct {
				k string
				v int
			}
			var kvs []kv
			for k, v := range c.TypeCounts {
				kvs = append(kvs, kv{k, v})
			}
			sort.Slice(kvs, func(i, j int) bool { return kvs[i].v > kvs[j].v })
			b.WriteString(`<div>`)
			for _, p := range kvs {
				fmt.Fprintf(&b, `<span class="as-tag">%s · %d</span>`, esc(p.k), p.v)
			}
			b.WriteString(`</div>`)
		}
	}
	b.WriteString(`</div>`)
	return b.String()
}

func renderBranches(bs git.BranchStats) string {
	var b strings.Builder
	b.WriteString(`<div><div class="as-sub">Branches</div>`)
	fmt.Fprintf(&b, `<p class="as-section__sub">%d total`, bs.TotalBranches)
	if bs.AvgLifetimeDays > 0 {
		fmt.Fprintf(&b, ` · avg lifetime %.0f days`, bs.AvgLifetimeDays)
	}
	if bs.PeakCommitDay != "" {
		fmt.Fprintf(&b, ` · peak day %s`, esc(bs.PeakCommitDay))
	}
	b.WriteString(`</p>`)
	if len(bs.StaleBranches) > 0 {
		stale := bs.StaleBranches
		if len(stale) > 8 {
			stale = stale[:8]
		}
		b.WriteString(`<table class="as-table"><thead><tr><th>Stale branch</th><th>Days idle</th></tr></thead><tbody>`)
		for _, br := range stale {
			fmt.Fprintf(&b, `<tr><td class="mono">%s</td><td class="mono">%d</td></tr>`, esc(br.Name), br.DaysInactive)
		}
		b.WriteString(`</tbody></table>`)
	} else {
		b.WriteString(`<p class="as-empty">No stale branches.</p>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// isTestFile returns true for test files across all supported languages.
func isTestFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case strings.HasSuffix(base, "_test.go"):
		return true
	case strings.HasSuffix(base, "test.swift"), strings.HasSuffix(base, "tests.swift"),
		strings.HasSuffix(base, "spec.swift"):
		return true
	case strings.HasSuffix(base, "test.kt"), strings.HasSuffix(base, "tests.kt"),
		strings.HasSuffix(base, "spec.kt"):
		return true
	case strings.Contains(base, ".test.ts"), strings.Contains(base, ".spec.ts"),
		strings.Contains(base, ".test.tsx"), strings.Contains(base, ".spec.tsx"),
		strings.Contains(base, ".test.js"), strings.Contains(base, ".spec.js"):
		return true
	case strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py"):
		return true
	case strings.HasSuffix(base, "_test.py"):
		return true
	}
	return false
}

// isGeneratedFile returns true for Go files that are machine-generated:
// protobuf outputs (*.pb.go) and controller-gen outputs (zz_generated*.go).
func isGeneratedFile(path string) bool {
	base := filepath.Base(path)
	return strings.HasSuffix(base, ".pb.go") || strings.HasPrefix(base, "zz_generated")
}

// shortenPathFront shortens s to max chars by removing the beginning, e.g.
// "…cmd/server/handler.go" instead of "pkg/internal/cmd/server/handler.go".
func shortenPathFront(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return "…" + s[len(s)-(max-1):]
}

// ── vscode:// links + declaration icons ──────────────────────────────────────

// vscodeHref builds a "vscode://file/<abs path>[:line]" deep link so paths in
// the report open directly in VS Code (matches ArchSwiftScope). Returns "" if
// no absolute path is available.
func vscodeHref(absPath string, line int) string {
	if absPath == "" {
		return ""
	}
	p := strings.ReplaceAll(absPath, "\\", "/")
	if !strings.HasPrefix(p, "/") {
		return "" // not absolute → a deep link would be unreliable
	}
	h := "vscode://file" + p
	if line > 0 {
		h += fmt.Sprintf(":%d", line)
	}
	return h
}

// kindIcon maps a declaration kind to a colored marker (ArchSwiftScope/goscope
// palette: 🟢 struct · 🔵 class · 🟣 protocol · 🟡 enum · 🔴 actor/service ·
// 🔹 extension · 🟠 func).
func kindIcon(k parser.DeclKind) string {
	switch k {
	case parser.DeclStruct:
		return "🟢"
	case parser.DeclClass:
		return "🔵"
	case parser.DeclInterface:
		return "🟣"
	case parser.DeclEnum:
		return "🟡"
	case parser.DeclActor, parser.DeclService:
		return "🔴"
	case parser.DeclExtension:
		return "🔹"
	case parser.DeclFunc:
		return "🟠"
	case parser.DeclRPC:
		return "🔗"
	case parser.DeclMessage:
		return "📨"
	default:
		return "⚪"
	}
}

// kindOrder / kindLabel drive the per-module declaration breakdown line.
var kindOrder = []parser.DeclKind{
	parser.DeclStruct, parser.DeclClass, parser.DeclInterface, parser.DeclEnum,
	parser.DeclActor, parser.DeclExtension, parser.DeclFunc, parser.DeclService,
	parser.DeclRPC, parser.DeclMessage,
}

func kindLabel(k parser.DeclKind, n int) string {
	one, many := string(k), string(k)+"s"
	switch k {
	case parser.DeclInterface:
		one, many = "protocol", "protocols"
	case parser.DeclClass:
		one, many = "class", "classes"
	case parser.DeclFunc:
		one, many = "func", "funcs"
	}
	return fmt.Sprintf("%s %d %s", kindIcon(k), n, plural(n, one, many))
}

// ── Bottom: per-module / per-microservice detail (goscope + ArchSwiftScope) ──

func renderModuleDetails(res *result.AnalysisResult) string {
	type mod struct {
		name  string
		plat  langspec.Platform
		ptype string
		files []*parser.ParsedFile
		lines int
		decls int
		kinds map[parser.DeclKind]int
	}
	order := []string{}
	mods := map[string]*mod{}
	for _, f := range res.Files {
		m := mods[f.ModuleName]
		if m == nil {
			m = &mod{name: f.ModuleName, plat: langspec.Platform(f.Platform), ptype: f.ProjectType, kinds: map[parser.DeclKind]int{}}
			mods[f.ModuleName] = m
			order = append(order, f.ModuleName)
		}
		m.files = append(m.files, f)
		m.lines += f.LineCount
		m.decls += len(f.Declarations)
		if m.ptype == "" {
			m.ptype = f.ProjectType
		}
		for _, d := range f.Declarations {
			m.kinds[d.Kind]++
		}
	}
	if len(mods) == 0 {
		return ""
	}
	list := make([]*mod, 0, len(mods))
	for _, n := range order {
		list = append(list, mods[n])
	}
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].lines != list[j].lines {
			return list[i].lines > list[j].lines
		}
		return list[i].name < list[j].name
	})

	var b strings.Builder
	b.WriteString(`<div class="as-section"><div class="as-section__head"><span class="ico">📂</span><h2>Modules &amp; Microservices</h2></div>`)
	b.WriteString(`<p class="as-section__sub">Per-module file inventory with declarations. File names link into VS Code.</p>`)

	for _, m := range list {
		icon, _ := langspec.Default.ModuleNoun(m.plat)
		name := m.name
		if name == "" {
			name = "(root)"
		}
		badge := ""
		if m.ptype != "" {
			badge = fmt.Sprintf(` <span class="as-bs-badge">%s</span>`, esc(m.ptype))
		}
		fmt.Fprintf(&b, `<div class="as-pkg-section" id="mod-%s"><h3>%s %s%s <span class="as-pkg-stats">%d files · %s lines · %d declarations</span></h3>`,
			esc(anchorID(m.name)), esc(icon), esc(name), badge, len(m.files), fmtNum(m.lines), m.decls)

		// declaration breakdown line
		var parts []string
		for _, k := range kindOrder {
			if n := m.kinds[k]; n > 0 {
				parts = append(parts, kindLabel(k, n))
			}
		}
		if len(parts) > 0 {
			fmt.Fprintf(&b, `<p class="as-pkg-detail">%s</p>`, strings.Join(parts, " · "))
		}

		// per-module declaration graph
		if g := renderDeclGraph(m.name, m.files); g != "" {
			b.WriteString(g)
		}

		// Split files: generated (pb.go / zz_generated) vs regular.
		all := append([]*parser.ParsedFile(nil), m.files...)
		sort.SliceStable(all, func(i, j int) bool { return all[i].LineCount > all[j].LineCount })
		var files, genFiles []*parser.ParsedFile
		for _, f := range all {
			if isGeneratedFile(f.FilePath) {
				genFiles = append(genFiles, f)
				continue
			}
			if isTestFile(f.FilePath) {
				continue
			}
			if len(f.Declarations) == 0 && f.LineCount < 30 {
				continue
			}
			files = append(files, f)
		}
		if len(files) == 0 && len(genFiles) == 0 {
			b.WriteString(`</div>`)
			continue
		}
		if len(files) > 0 {
			b.WriteString(`<table class="as-table as-file-table"><thead><tr><th style="width:50%">File</th><th>Lines</th><th>Decl</th><th>Declarations</th></tr></thead><tbody>`)
			for _, f := range files {
				b.WriteString(fileTableRow(f, res.RootPath))
			}
			b.WriteString(`</tbody></table>`)
		}
		if len(genFiles) > 0 {
			b.WriteString(`<div class="as-sub as-gen-sub">Code Generated</div>`)
			b.WriteString(`<table class="as-table as-file-table"><thead><tr><th style="width:50%">File</th><th>Lines</th><th>Decl</th><th>Declarations</th></tr></thead><tbody>`)
			for _, f := range genFiles {
				b.WriteString(fileTableRow(f, res.RootPath))
			}
			b.WriteString(`</tbody></table>`)
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// fileTableRow renders one <tr> for the file inventory table.
func fileTableRow(f *parser.ParsedFile, rootPath string) string {
	dir, base := splitRel(f.FilePath, rootPath)
	fileCell := ""
	if dir != "" {
		fileCell = fmt.Sprintf(`<span class="as-file-dir">%s</span>`, esc(shortenPathFront(dir, 40)))
	}
	if href := vscodeHref(f.FilePath, 0); href != "" {
		fileCell += fmt.Sprintf(`<a class="as-vs" href="%s" title="Open in VS Code"><strong>%s</strong></a>`, esc(href), esc(base))
	} else {
		fileCell += fmt.Sprintf(`<strong>%s</strong>`, esc(base))
	}
	if f.Description != "" {
		d := f.Description
		if len(d) > 80 {
			d = d[:80] + "…"
		}
		fileCell += fmt.Sprintf(`<div class="as-file-desc">💡 %s</div>`, esc(d))
	}
	return fmt.Sprintf(`<tr><td>%s</td><td class="mono">%d</td><td class="mono">%d</td><td class="as-decl-tags">%s</td></tr>`,
		fileCell, f.LineCount, len(f.Declarations), declTags(f.FilePath, f.Declarations))
}

// declTags renders up to 14 declaration chips (icon + name) for a file.
// When absPath is non-empty each chip links directly to the declaration in VS Code.
func declTags(absPath string, decls []parser.Declaration) string {
	if len(decls) == 0 {
		return "—"
	}
	const limit = 14
	var parts []string
	for i, d := range decls {
		if i == limit {
			parts = append(parts, fmt.Sprintf(`<span class="as-decl-more">+%d</span>`, len(decls)-limit))
			break
		}
		chip := fmt.Sprintf(`%s&thinsp;%s`, kindIcon(d.Kind), esc(d.Name))
		if href := vscodeHref(absPath, d.Line); href != "" {
			chip = fmt.Sprintf(`<a class="as-vs as-decl-link" href="%s" title="Open in VS Code (line %d)">%s</a>`,
				esc(href), d.Line, chip)
		}
		parts = append(parts, chip)
	}
	return strings.Join(parts, "&ensp;")
}

// splitRel returns (dir, base) of path relative to root; dir keeps a trailing
// slash and is "" at the root.
func splitRel(path, root string) (string, string) {
	p := strings.ReplaceAll(path, "\\", "/")
	r := strings.ReplaceAll(root, "\\", "/")
	rel := strings.TrimPrefix(p, strings.TrimSuffix(r, "/")+"/")
	base := rel
	dir := ""
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		dir = rel[:i+1]
		base = rel[i+1:]
	}
	return dir, base
}

// anchorID sanitizes a module name into an HTML id fragment.
func anchorID(name string) string {
	if name == "" {
		return "root"
	}
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
