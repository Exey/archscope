package html

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/result"
)

// ── Graph data types (serialized as JSON for force-graph) ────────────────────

type gNode struct {
	ID       string  `json:"id"`
	Label    string  `json:"label"`
	Sublabel string  `json:"sublabel"`
	Kind     string  `json:"kind"`
	Score    float64 `json:"score"`
	Group    string  `json:"group,omitempty"`
}

type gLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind,omitempty"`
}

type gData struct {
	Nodes []gNode `json:"nodes"`
	Links []gLink `json:"links"`
}

var graphCounter int

func nextGraphID() string {
	graphCounter++
	return fmt.Sprintf("as-graph-%d", graphCounter)
}

// ── Global architecture graph ─────────────────────────────────────────────────

func renderGlobalArchGraph(res *result.AnalysisResult) string {
	type modInfo struct {
		key         string
		origName    string
		displayName string
		loc         int
		plat        langspec.Platform
	}
	mkKey := func(name string, p langspec.Platform) string { return name + "\x00" + string(p) }
	modMap := map[string]*modInfo{}
	for _, f := range res.Files {
		m := f.ModuleName
		if m == "" {
			m = "root"
		}
		k := mkKey(m, langspec.Platform(f.Platform))
		if modMap[k] == nil {
			modMap[k] = &modInfo{key: k, origName: m, displayName: m, plat: langspec.Platform(f.Platform)}
		}
		modMap[k].loc += f.LineCount
	}

	// Suffix display names when the same module name appears in multiple platforms.
	nameCount := map[string]int{}
	for _, mi := range modMap {
		nameCount[mi.origName]++
	}
	for _, mi := range modMap {
		if nameCount[mi.origName] > 1 {
			folder := string(tabFolder(mi.plat))
			if folder != string(mi.plat) {
				mi.displayName = mi.origName + "(" + folder + ")"
			} else {
				mi.displayName = mi.origName + "(" + shortLangLabel(mi.plat) + ")"
			}
		}
	}

	skipTech := map[string]bool{
		"Go": true, "Swift": true, "Kotlin": true, "Python": true,
		"TypeScript": true, "JavaScript": true, "Objective-C": true,
	}
	techSet := map[string]bool{}
	for _, t := range res.Technologies {
		if !skipTech[t] {
			techSet[t] = true
		}
	}

	// tech used per module (keyed by modKey)
	modTechs := map[string]map[string]bool{}
	for _, f := range res.Files {
		m := f.ModuleName
		if m == "" {
			m = "root"
		}
		k := mkKey(m, langspec.Platform(f.Platform))
		for _, imp := range f.Imports {
			ts := map[string]bool{}
			detectTechFromImportLocal(imp, ts)
			for t := range ts {
				if techSet[t] {
					if modTechs[k] == nil {
						modTechs[k] = map[string]bool{}
					}
					modTechs[k][t] = true
				}
			}
		}
	}

	var mods []*modInfo
	for _, mi := range modMap {
		mods = append(mods, mi)
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].loc > mods[j].loc })
	if len(mods) > 30 {
		mods = mods[:30]
	}

	maxLOC := 1
	for _, mi := range mods {
		if mi.loc > maxLOC {
			maxLOC = mi.loc
		}
	}

	var nodes []gNode
	var links []gLink
	nodeSet := map[string]bool{}

	// Determine group per module: folder name (FolderAsTab) or short lang label.
	modGroup := func(plat langspec.Platform) string {
		folder := string(tabFolder(plat))
		if folder != string(plat) {
			return folder
		}
		return shortLangLabel(plat)
	}
	for _, mi := range mods {
		id := "m:" + mi.displayName
		grp := modGroup(mi.plat)
		nodes = append(nodes, gNode{
			ID:    id,
			Label: mi.displayName,
			Kind:  "module",
			Score: float64(mi.loc) / float64(maxLOC),
			Group: grp,
		})
		nodeSet[id] = true
	}

	var techList []string
	for t := range techSet {
		techList = append(techList, t)
	}
	sort.Strings(techList)
	for _, t := range techList {
		id := "t:" + t
		nodes = append(nodes, gNode{ID: id, Label: t, Kind: "technology", Score: 0.4})
		nodeSet[id] = true
	}

	// module → tech edges
	for _, mi := range mods {
		for t := range modTechs[mi.key] {
			if techSet[t] {
				links = append(links, gLink{Source: "m:" + mi.displayName, Target: "t:" + t, Kind: "tech"})
			}
		}
	}
	// module → module edges.
	// Pass 1: edges from graph.Build (coarse first/last-segment heuristic).
	origToDisplay := map[string][]string{}
	for _, mi := range mods {
		origToDisplay[mi.origName] = append(origToDisplay[mi.origName], mi.displayName)
	}
	seenLinks := map[[2]string]bool{}
	addModLink := func(s, d string) {
		if s == d || !nodeSet["m:"+s] || !nodeSet["m:"+d] {
			return
		}
		k := [2]string{s, d}
		if seenLinks[k] {
			return
		}
		seenLinks[k] = true
		links = append(links, gLink{Source: "m:" + s, Target: "m:" + d, Kind: "mod"})
	}
	if res.Graph != nil {
		for _, e := range res.Graph.Edges() {
			src, dst := e[0], e[1]
			if src == "" {
				src = "root"
			}
			if dst == "" {
				dst = "root"
			}
			for _, sd := range origToDisplay[src] {
				for _, dd := range origToDisplay[dst] {
					addModLink(sd, dd)
				}
			}
		}
	}
	// Pass 2: supplemental edges by scanning all import path segments.
	// This catches Go-style full-path imports (e.g. github.com/co/repo/backend/api)
	// that graph.Build's first/last-segment heuristic misses.
	knownOrigLow := map[string][]string{} // lowercase origName → []displayName
	for _, mi := range mods {
		low := strings.ToLower(mi.origName)
		knownOrigLow[low] = append(knownOrigLow[low], mi.displayName)
	}
	for _, f := range res.Files {
		fromName := f.ModuleName
		if fromName == "" {
			fromName = "root"
		}
		fromMI := modMap[mkKey(fromName, langspec.Platform(f.Platform))]
		if fromMI == nil {
			continue
		}
		for _, imp := range f.Imports {
			segs := strings.FieldsFunc(strings.ToLower(imp), func(r rune) bool {
				return r == '/' || r == '@'
			})
			for _, seg := range segs {
				for _, toDisplay := range knownOrigLow[seg] {
					addModLink(fromMI.displayName, toDisplay)
				}
			}
		}
	}

	if len(nodes) < 2 {
		return ""
	}
	if nodes == nil {
		nodes = []gNode{}
	}
	if links == nil {
		links = []gLink{}
	}

	d := gData{Nodes: nodes, Links: links}
	dj, _ := json.Marshal(d)
	id := nextGraphID()

	var b strings.Builder
	b.WriteString(`<div class="as-section"><div class="as-section__head"><span class="ico">🗺️</span><h2>Architecture Graph</h2></div>`)
	b.WriteString(`<p class="as-section__sub">Modules and detected technologies. <span style="color:#0a84ff">●</span> module &nbsp;<span style="color:#30d158">●</span> technology</p>`)
	fmt.Fprintf(&b, `<div id="%s" class="as-fg-container"></div>`, id)
	fmt.Fprintf(&b, `<script>{const d=%s;(window.__asgq=window.__asgq||[]).push([`+
		// ── init: called when ForceGraph + d3 are available ──────────────────
		`function(){`+
		`const el=document.getElementById('%s');`+
		`if(!d.nodes.length||!el)return;`+
		`const kc={'module':'#0a84ff','technology':'#30d158','foreign':'#ff9f0a'};`+
		`const dark=()=>document.documentElement.getAttribute('data-theme')!=='light';`+
		// group → color palette
		`const pal=['#0a84ff','#ff9f0a','#ff375f','#bf5af2','#64d2ff','#ac8e68','#30d158','#ff6961','#5e5ce6','#ffd60a'];`+
		`const grps=[...new Set(d.nodes.filter(n=>n.group).map(n=>n.group))];`+
		`const gc={};grps.forEach((g,i)=>{gc[g]=pal[i%%pal.length];});`+
		`const nodeCol=n=>(n.kind==='module'&&n.group&&gc[n.group])?gc[n.group]:(kc[n.kind]||'#8e8e93');`+
		`const g=ForceGraph()(el).graphData(d)`+
		`.nodeLabel(n=>n.label+(n.sublabel?' · '+n.sublabel:''))`+
		`.nodeVal(n=>n.kind==='module'?Math.max(n.score*80,3):3)`+
		`.nodeColor(nodeCol)`+
		`.nodeCanvasObject((node,ctx,gs)=>{`+
		`const r=node.kind==='module'?Math.max(Math.sqrt(Math.max(node.score*80,3))*0.9,3):4;`+
		`const col=nodeCol(node);`+
		// halo: semi-transparent circle in group color — overlapping halos create cloud
		`if(node.kind==='module'&&node.group){`+
		`ctx.beginPath();ctx.arc(node.x,node.y,r*2.8,0,2*Math.PI);`+
		`ctx.fillStyle=col+'28';ctx.fill();}`+
		// node circle
		`ctx.beginPath();ctx.arc(node.x,node.y,r,0,2*Math.PI);`+
		`ctx.fillStyle=col;ctx.fill();`+
		// label + sublabel
		`if(gs>0.4){`+
		`ctx.textAlign='center';`+
		`ctx.fillStyle=dark()?'rgba(240,240,240,0.9)':'rgba(0,0,0,0.85)';`+
		`ctx.font='bold '+Math.max(10/gs,3)+'px -apple-system,sans-serif';`+
		`ctx.fillText(node.label,node.x,node.y+r+10/gs);`+
		`if(node.sublabel&&gs>0.7){`+
		`ctx.font=Math.max(8/gs,2)+'px -apple-system,sans-serif';`+
		`ctx.fillStyle=dark()?'rgba(180,180,180,0.7)':'rgba(80,80,80,0.65)';`+
		`ctx.fillText(node.sublabel,node.x,node.y+r+18/gs);}}})`+
		`.linkColor(l=>l.kind==='mod'?(dark()?'rgba(100,180,255,0.55)':'rgba(10,100,210,0.4)'):(dark()?'rgba(48,209,88,0.45)':'rgba(0,140,60,0.35)'))`+
		`.linkWidth(l=>l.kind==='mod'?1.6:1.1)`+
		`.linkDirectionalArrowLength(l=>l.kind==='mod'?5:0)`+
		`.linkDirectionalArrowRelPos(1)`+
		`.linkDirectionalArrowColor(l=>dark()?'rgba(100,180,255,0.8)':'rgba(10,100,210,0.7)')`+
		`.width(el.offsetWidth||800).height(460)`+
		`.onEngineStop(()=>g.zoomToFit(400,40));`+
		`g.d3Force('charge').strength(-250);`+
		`g.d3Force('link').distance(120);`+
		`g.d3Force('x',d3.forceX().strength(0.04));`+
		`g.d3Force('y',d3.forceY().strength(0.04));`+
		// cluster force: pull same-group nodes toward their group centroid
		`g.d3Force('cluster',(function(){`+
		`let ns;`+
		`const f=function(a){`+
		`if(!ns)return;`+
		`const cx={},cy={},cn={};`+
		`ns.forEach(n=>{if(!n.group)return;cx[n.group]=(cx[n.group]||0)+(n.x||0);cy[n.group]=(cy[n.group]||0)+(n.y||0);cn[n.group]=(cn[n.group]||0)+1;});`+
		`Object.keys(cn).forEach(k=>{cx[k]/=cn[k];cy[k]/=cn[k];});`+
		`ns.forEach(n=>{if(!n.group)return;n.vx=(n.vx||0)+(cx[n.group]-(n.x||0))*a*0.25;n.vy=(n.vy||0)+(cy[n.group]-(n.y||0))*a*0.25;});`+
		`};f.initialize=function(nodes){ns=nodes;};return f;`+
		`})());`+
		`},`+
		// ── fallback: rendered when CDN is unreachable ─────────────────────
		`function(){`+
		`const el=document.getElementById('%s');`+
		`if(!el)return;`+
		`el.style.height='auto';el.style.padding='12px';`+
		`var rows=d.nodes.filter(n=>n.kind==='module').slice(0,20)`+
		`.map(n=>'<tr><td class="mono">'+n.label+'</td><td class="mono">'+(n.sublabel||'')+'</td></tr>').join('');`+
		`el.innerHTML='<table class="as-table"><thead><tr><th>Module</th><th>Size</th></tr></thead><tbody>'+rows+'</tbody></table>'`+
		`+'<p class="as-graph-offline">&#x26A1; Interactive graph requires an internet connection</p>';`+
		`}`+
		`]);}</script>`,
		string(dj), id, id)
	b.WriteString(`</div>`)
	return b.String()
}

// detectTechFromImportLocal avoids a cyclic import from scanner.
func detectTechFromImportLocal(imp string, techSet map[string]bool) {
	m := map[string]string{
		"google.golang.org/grpc":              "gRPC",
		"github.com/gin-gonic/gin":            "Gin",
		"github.com/labstack/echo":            "Echo",
		"github.com/gofiber/fiber":            "Fiber",
		"github.com/gorilla/mux":              "Gorilla Mux",
		"github.com/go-chi/chi":               "Chi",
		"gorm.io/gorm":                        "GORM",
		"github.com/jackc/pgx":                "PostgreSQL",
		"github.com/lib/pq":                   "PostgreSQL",
		"github.com/go-redis/redis":           "Redis",
		"github.com/redis/go-redis":           "Redis",
		"go.mongodb.org/mongo-driver":         "MongoDB",
		"github.com/segmentio/kafka-go":       "Kafka",
		"github.com/IBM/sarama":               "Kafka",
		"github.com/nats-io/nats.go":          "NATS",
		"github.com/streadway/amqp":           "RabbitMQ",
		"github.com/rabbitmq/amqp091-go":      "RabbitMQ",
		"go.opentelemetry.io/otel":            "OpenTelemetry",
		"github.com/prometheus/client_golang": "Prometheus",
		"github.com/aws/aws-sdk-go":           "AWS SDK",
		"cloud.google.com/go":                 "Google Cloud",
		"k8s.io/client-go":                    "Kubernetes Client",
		"github.com/golang-jwt/jwt":           "JWT",
		"github.com/spf13/cobra":              "Cobra CLI",
		"github.com/spf13/viper":              "Viper Config",
		"github.com/stretchr/testify":         "Testify",
	}
	for prefix, tech := range m {
		if strings.HasPrefix(imp, prefix) {
			techSet[tech] = true
			return
		}
	}
}

// ── Per-module declaration graph ──────────────────────────────────────────────

// renderDeclGraph renders a ForceGraph of module declarations using the same
// CDN loader as the global arch graph. Types (classes, interfaces, enums…)
// are larger nodes; functions are smaller. Same-file type nodes are connected.
// Falls back to inline chips when the CDN is unavailable.
func renderDeclGraph(modName string, files []*parser.ParsedFile) string {
	type di struct {
		name   string
		fp     string
		line   int
		kind   parser.DeclKind
		isType bool
	}
	typeKinds := map[parser.DeclKind]bool{
		parser.DeclStruct: true, parser.DeclClass: true, parser.DeclInterface: true,
		parser.DeclMessage: true, parser.DeclService: true, parser.DeclEnum: true,
		parser.DeclActor: true, parser.DeclExtension: true,
	}

	var types, funcs []di
	funcSeen := map[string]bool{}
	for _, f := range files {
		if isGeneratedFile(f.FilePath) {
			continue
		}
		for _, d := range f.Declarations {
			if typeKinds[d.Kind] && len(d.Name) >= 3 {
				types = append(types, di{d.Name, f.FilePath, d.Line, d.Kind, true})
			}
			if d.Kind == parser.DeclFunc && len(d.Name) >= 3 {
				key := f.FilePath + "::" + d.Name
				if !funcSeen[key] {
					funcs = append(funcs, di{d.Name, f.FilePath, d.Line, parser.DeclFunc, false})
					funcSeen[key] = true
				}
			}
		}
		for _, bf := range f.BigFunctions {
			key := bf.FilePath + "::" + bf.Name
			if !funcSeen[key] && len(bf.Name) >= 3 {
				funcs = append(funcs, di{bf.Name, bf.FilePath, bf.StartLine, parser.DeclFunc, false})
				funcSeen[key] = true
			}
		}
	}

	const maxTypes, maxFuncs = 40, 20
	if len(types) > maxTypes {
		types = types[:maxTypes]
	}
	if len(funcs) > maxFuncs {
		funcs = funcs[:maxFuncs]
	}
	all := append(types, funcs...)
	if len(all) < 2 {
		return ""
	}

	// Same-file edges between type nodes only.
	type edge struct{ s, t int }
	fileIdx := map[string][]int{}
	for i, d := range all {
		if d.isType {
			fileIdx[d.fp] = append(fileIdx[d.fp], i)
		}
	}
	var edges []edge
	edgeSeen := map[[2]int]bool{}
	for _, idxs := range fileIdx {
		if len(idxs) < 2 || len(idxs) > 12 {
			continue
		}
		for a := 0; a < len(idxs); a++ {
			for b := a + 1; b < len(idxs); b++ {
				k := [2]int{idxs[a], idxs[b]}
				if !edgeSeen[k] {
					edges = append(edges, edge{idxs[a], idxs[b]})
					edgeSeen[k] = true
				}
			}
		}
	}
	if len(edges) > 40 {
		edges = edges[:40]
	}

	// ForceGraph-compatible data: nodes need numeric id, links use id references.
	type jsNode struct {
		ID int    `json:"id"`
		L  string `json:"l"`
		K  string `json:"k"`
		T  bool   `json:"t"`
	}
	type jsEdge struct {
		Source int `json:"source"`
		Target int `json:"target"`
	}
	jNodes := make([]jsNode, len(all))
	for i, d := range all {
		jNodes[i] = jsNode{i, d.name, string(d.kind), d.isType}
	}
	jEdges := make([]jsEdge, len(edges))
	for i, e := range edges {
		jEdges[i] = jsEdge{e.s, e.t}
	}

	type gdata struct {
		Nodes []jsNode `json:"nodes"`
		Links []jsEdge `json:"links"`
	}
	dj, _ := json.Marshal(gdata{jNodes, jEdges})

	id := nextGraphID()
	const kc = `{'struct':'#34c759','class':'#0a84ff','interface':'#007aff','message':'#ff9f0a','service':'#ff453a','enum':'#bf5af2','func':'#ff9f0a','actor':'#ff453a','extension':'#64d2ff'}`

	var b strings.Builder
	fmt.Fprintf(&b, `<div id="%s" class="as-fg-container as-fg-container--decl"></div>`, id)
	fmt.Fprintf(&b, `<script>{const d=%s;(window.__asgq=window.__asgq||[]).push([`+
		// ── ForceGraph init ───────────────────────────────────────────────────
		`function(){`+
		`const el=document.getElementById('%s');`+
		`if(!d.nodes.length||!el)return;`+
		`const kc=%s;`+
		`const dark=()=>document.documentElement.getAttribute('data-theme')!=='light';`+
		`const g=ForceGraph()(el).graphData(d)`+
		`.nodeLabel(n=>n.l+' · '+n.k)`+
		`.nodeVal(n=>n.t?8:3)`+
		`.nodeColor(n=>kc[n.k]||'#8e8e93')`+
		`.nodeCanvasObject((node,ctx,gs)=>{`+
		`const col=kc[node.k]||'#8e8e93',r=node.t?5:3.5;`+
		`ctx.beginPath();ctx.arc(node.x,node.y,r*2.2,0,2*Math.PI);ctx.fillStyle=col+'22';ctx.fill();`+
		`ctx.beginPath();ctx.arc(node.x,node.y,r,0,2*Math.PI);ctx.fillStyle=col;ctx.fill();`+
		`if(gs>0.5){ctx.font='9px -apple-system,sans-serif';ctx.textAlign='center';`+
		`ctx.fillStyle=dark()?'rgba(210,210,210,0.85)':'rgba(30,30,30,0.75)';`+
		`const lbl=node.l.length>14?node.l.slice(0,12)+'…':node.l;`+
		`ctx.fillText(lbl,node.x,node.y+r+9);}})`+
		`.linkColor(()=>dark()?'rgba(255,255,255,0.15)':'rgba(0,0,0,0.1)')`+
		`.linkWidth(1)`+
		`.width(el.offsetWidth||800).height(el.offsetHeight||280)`+
		`.onEngineStop(()=>g.zoomToFit(400,30));`+
		`g.d3Force('charge').strength(-150);`+
		`g.d3Force('link').distance(70);`+
		`g.d3Force('x',d3.forceX().strength(0.06));`+
		`g.d3Force('y',d3.forceY().strength(0.06));`+
		`if(window.ResizeObserver){const ro=new ResizeObserver(function(es){`+
		`const w=es[0].contentRect.width,h=es[0].contentRect.height;`+
		`if(w>0){g.width(w).height(h||280);setTimeout(function(){g.zoomToFit(400,30);},100);}});`+
		`ro.observe(el);}},`+
		// ── Chip fallback ─────────────────────────────────────────────────────
		`function(){`+
		`const el=document.getElementById('%s');`+
		`if(!el)return;`+
		`const kc=%s;`+
		`el.style.height='auto';el.style.padding='8px';`+
		`el.innerHTML='<div style="line-height:2.4;padding:4px 0">'+`+
		`d.nodes.map(n=>'<span style="display:inline-block;margin:2px 3px;padding:2px 9px;border-radius:6px;font-size:11px;font-family:var(--mono);background:'+(kc[n.k]||'#8e8e93')+'22;color:'+(kc[n.k]||'#8e8e93')+'">'+n.l+'</span>').join('')+`+
		`'</div><p class="as-graph-offline">&#x26A1; Interactive graph requires internet</p>';}`+
		`]);}</script>`,
		string(dj), id, kc, id, kc)
	return b.String()
}


// ── Architecture layers ───────────────────────────────────────────────────────

const (
	layerAPI      = "API / Routes"
	layerModels   = "Models / Schemas"
	layerServices = "Services / Domain"
	layerPersist  = "Persistence / DB"
	layerAuth     = "Auth / Security"
	layerTasks    = "Background Tasks"
	layerConfig   = "Config / Settings"
	layerCLI      = "CLI / Entry"
	layerInfra    = "Infrastructure / Utils"
	layerTests    = "Tests"
	layerOther    = "Other"
)

var layerIcons = map[string]string{
	layerAPI: "🌐", layerModels: "📦", layerServices: "⚙️", layerPersist: "🗄️",
	layerAuth: "🔐", layerTasks: "⏱️", layerConfig: "🔧", layerCLI: "💻",
	layerInfra: "🧰", layerTests: "🧪", layerOther: "•",
}

var layerOrder = []string{
	layerAPI, layerModels, layerServices, layerPersist, layerAuth,
	layerTasks, layerConfig, layerCLI, layerInfra, layerTests, layerOther,
}

func classifyFile(f *parser.ParsedFile) string {
	path := strings.ReplaceAll(f.FilePath, "\\", "/")
	name := strings.ToLower(filepath.Base(path))
	parts := strings.Split(strings.ToLower(path), "/")

	if strings.HasSuffix(name, "_test.go") || strings.HasSuffix(name, "_test.swift") ||
		strings.HasSuffix(name, "spec.ts") || strings.HasSuffix(name, "test.py") ||
		strings.HasSuffix(name, ".test.ts") || strings.HasSuffix(name, "_test.kt") {
		return layerTests
	}
	for _, p := range parts {
		if p == "test" || p == "tests" || p == "testdata" || p == "__tests__" || p == "spec" {
			return layerTests
		}
	}
	if name == "main.go" || name == "main.swift" || name == "main.kt" || name == "main.py" {
		return layerCLI
	}
	for _, p := range parts {
		if p == "cmd" || p == "cli" || p == "command" || p == "commands" || p == "entry" {
			return layerCLI
		}
	}
	for _, p := range parts {
		if p == "config" || p == "conf" || p == "configuration" || p == "settings" || p == "constants" {
			return layerConfig
		}
	}
	for _, p := range parts {
		if p == "auth" || p == "authentication" || p == "authorization" || p == "security" || p == "jwt" {
			return layerAuth
		}
	}
	for _, p := range parts {
		if p == "handler" || p == "handlers" || p == "controller" || p == "controllers" ||
			p == "api" || p == "apis" || p == "route" || p == "routes" || p == "router" ||
			p == "endpoint" || p == "endpoints" || p == "http" || p == "rest" || p == "transport" {
			return layerAPI
		}
	}
	for _, p := range parts {
		if p == "model" || p == "models" || p == "entity" || p == "entities" ||
			p == "domain" || p == "schema" || p == "schemas" || p == "dto" || p == "dtos" {
			return layerModels
		}
	}
	for _, p := range parts {
		if p == "service" || p == "services" || p == "usecase" || p == "usecases" ||
			p == "business" || p == "core" || p == "logic" || p == "app" {
			return layerServices
		}
	}
	for _, p := range parts {
		if p == "repository" || p == "repo" || p == "repos" || p == "storage" ||
			p == "db" || p == "database" || p == "dao" || p == "migration" || p == "migrations" || p == "store" {
			return layerPersist
		}
	}
	for _, p := range parts {
		if p == "worker" || p == "workers" || p == "task" || p == "tasks" ||
			p == "job" || p == "jobs" || p == "consumer" || p == "consumers" ||
			p == "queue" || p == "queues" || p == "scheduler" || p == "cron" {
			return layerTasks
		}
	}
	for _, p := range parts {
		if p == "util" || p == "utils" || p == "helper" || p == "helpers" ||
			p == "common" || p == "shared" || p == "lib" || p == "middleware" ||
			p == "infrastructure" || p == "infra" {
			return layerInfra
		}
	}
	return layerOther
}

func renderArchLayers(files []*parser.ParsedFile) string {
	type bucket struct{ files, lines int }
	buckets := map[string]*bucket{}
	for _, f := range files {
		layer := classifyFile(f)
		b := buckets[layer]
		if b == nil {
			b = &bucket{}
			buckets[layer] = b
		}
		b.files++
		b.lines += f.LineCount
	}
	maxLines := 1
	for _, b := range buckets {
		if b.lines > maxLines {
			maxLines = b.lines
		}
	}
	if maxLines == 1 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(`<div class="as-sub" style="margin-top:16px">Architecture Layers</div><div class="arch-layers">`)
	for _, layer := range layerOrder {
		b := buckets[layer]
		if b == nil {
			continue
		}
		icon := layerIcons[layer]
		pct := b.lines * 100 / maxLines
		if pct < 4 {
			pct = 4
		}
		fmt.Fprintf(&sb,
			`<div class="arch-layer"><div class="layer-bar-row"><span class="layer-icon">%s</span><span class="layer-name">%s</span><span class="layer-count">%d files · %s loc</span></div><div class="layer-bar-track"><div class="layer-bar-fill" style="width:%d%%"></div></div></div>`,
			icon, esc(layer), b.files, fmtNum(b.lines), pct)
	}
	sb.WriteString(`</div>`)
	return sb.String()
}

// ── Tech components ───────────────────────────────────────────────────────────

type archComponent struct{ icon, summary string }

func detectComponents(files []*parser.ParsedFile, techSet map[string]bool) []archComponent {
	testFiles := 0
	for _, f := range files {
		if classifyFile(f) == layerTests {
			testFiles++
		}
	}
	var out []archComponent
	add := func(icon, summary string) { out = append(out, archComponent{icon, summary}) }

	if techSet["Gin"] {
		add("🌐", "Gin HTTP server")
	}
	if techSet["Echo"] {
		add("🌐", "Echo HTTP server")
	}
	if techSet["Fiber"] {
		add("🌐", "Fiber HTTP server")
	}
	if techSet["Chi"] {
		add("🌐", "Chi router")
	}
	if techSet["Gorilla Mux"] {
		add("🌐", "Gorilla Mux router")
	}
	if techSet["gRPC"] {
		add("📡", "gRPC")
	}
	if techSet["gRPC Gateway"] {
		add("🌐", "gRPC Gateway")
	}
	if techSet["gqlgen (GraphQL)"] {
		add("⬡", "GraphQL (gqlgen)")
	}
	if techSet["Swagger"] {
		add("📖", "Swagger / OpenAPI docs")
	}
	if techSet["GORM"] {
		add("🗄️", "GORM ORM")
	}
	if techSet["sqlx"] {
		add("🗄️", "sqlx")
	}
	if techSet["DB Migrations"] {
		add("🪣", "DB Migrations")
	}
	if techSet["Goose Migrations"] {
		add("🪣", "Goose Migrations")
	}
	if techSet["PostgreSQL"] {
		add("🐘", "PostgreSQL")
	}
	if techSet["MongoDB"] {
		add("🍃", "MongoDB")
	}
	if techSet["Redis"] {
		add("🟥", "Redis")
	}
	if techSet["Kafka"] {
		add("📨", "Kafka")
	}
	if techSet["RabbitMQ"] {
		add("🐇", "RabbitMQ")
	}
	if techSet["NATS"] {
		add("📡", "NATS")
	}
	if techSet["Elasticsearch"] {
		add("🔍", "Elasticsearch")
	}
	if techSet["ClickHouse"] {
		add("📊", "ClickHouse")
	}
	if techSet["MinIO"] {
		add("🪣", "MinIO")
	}
	if techSet["JWT"] {
		add("🔐", "JWT auth")
	}
	if techSet["OpenTelemetry"] {
		add("📡", "OpenTelemetry")
	}
	if techSet["Prometheus"] {
		add("📡", "Prometheus metrics")
	}
	if techSet["Cobra CLI"] {
		add("💻", "Cobra CLI")
	}
	if techSet["Viper Config"] {
		add("🔧", "Viper Config")
	}
	if techSet["AWS SDK"] {
		add("☁️", "AWS SDK")
	}
	if techSet["Google Cloud"] {
		add("☁️", "Google Cloud")
	}
	if techSet["Kubernetes Client"] {
		add("☸️", "Kubernetes Client")
	}
	if techSet["Consul"] {
		add("🔗", "Consul")
	}
	if techSet["HashiCorp Vault"] {
		add("🔐", "HashiCorp Vault")
	}
	if techSet["Testify"] {
		s := "Testify"
		if testFiles > 0 {
			s = fmt.Sprintf("Testify · %d test files", testFiles)
		}
		add("🧪", s)
	}
	if techSet["SwiftUI"] {
		add("📱", "SwiftUI")
	}
	if techSet["UIKit"] {
		add("📱", "UIKit")
	}
	if techSet["React"] {
		add("⚛️", "React")
	}
	if techSet["Next.js"] {
		add("▲", "Next.js")
	}
	if techSet["Django"] {
		add("🐍", "Django")
	}
	if techSet["FastAPI"] {
		add("⚡", "FastAPI")
	}
	return out
}

func renderArchComponents(files []*parser.ParsedFile, techSet map[string]bool) string {
	components := detectComponents(files, techSet)
	if len(components) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(`<div class="as-sub" style="margin-top:16px">Components</div><div class="arch-components">`)
	for _, c := range components {
		fmt.Fprintf(&sb, `<span class="arch-component"><span class="comp-icon">%s</span><span>%s</span></span>`, c.icon, esc(c.summary))
	}
	sb.WriteString(`</div>`)
	return sb.String()
}

// ── Longest functions ─────────────────────────────────────────────────────────

func renderLongestFunctions(files []*parser.ParsedFile, rootPath string) string {
	type entry struct {
		fn  *parser.FunctionInfo
		mod string
	}
	var fns []entry
	for _, f := range files {
		if f.LongestFunc != nil && !isTestFile(f.FilePath) {
			fns = append(fns, entry{f.LongestFunc, f.ModuleName})
		}
	}
	if len(fns) == 0 {
		return ""
	}
	sort.Slice(fns, func(i, j int) bool { return fns[i].fn.LineCount > fns[j].fn.LineCount })
	if len(fns) > 20 {
		fns = fns[:20]
	}
	var b strings.Builder
	b.WriteString(`<div class="as-section"><div class="as-section__head"><span class="ico">📏</span><h3>Longest Functions</h3></div>`)
	b.WriteString(`<table class="as-table"><thead><tr><th>Function</th><th>Lines</th><th>File</th></tr></thead><tbody>`)
	for _, e := range fns {
		fn := e.fn
		_, base := splitRel(fn.FilePath, rootPath)

		// Function column: VS Code link on the function name at its start line
		funcCell := esc(fn.Name)
		if href := vscodeHref(fn.FilePath, fn.StartLine); href != "" {
			funcCell = fmt.Sprintf(`<a class="as-vs" href="%s" title="Open in VS Code">%s</a>`, esc(href), esc(fn.Name))
		}

		// File column: link to the file
		fileCell := esc(base)
		if href := vscodeHref(fn.FilePath, 0); href != "" {
			fileCell = fmt.Sprintf(`<a class="as-vs" href="%s">%s</a>`, esc(href), esc(base))
		}

		fmt.Fprintf(&b, `<tr><td class="mono">%s</td><td class="mono">%d</td><td class="mono">%s</td></tr>`,
			funcCell, fn.LineCount, fileCell)
	}
	b.WriteString(`</tbody></table></div>`)
	return b.String()
}

// ── Penetration matrix ────────────────────────────────────────────────────────

func renderPenetrationMatrix(files []*parser.ParsedFile) string {
	allMods := map[string]bool{}
	for _, f := range files {
		m := f.ModuleName
		if m == "" {
			m = "root"
		}
		allMods[m] = true
	}
	if len(allMods) < 2 {
		return ""
	}
	importedBy := map[string]map[string]bool{}
	for _, f := range files {
		src := f.ModuleName
		if src == "" {
			src = "root"
		}
		impLow := strings.ToLower(strings.Join(f.Imports, "\n"))
		for target := range allMods {
			if target == src {
				continue
			}
			if strings.Contains(impLow, strings.ToLower(target)) {
				if importedBy[target] == nil {
					importedBy[target] = map[string]bool{}
				}
				importedBy[target][src] = true
			}
		}
	}
	type row struct {
		name  string
		count int
		deps  []string
	}
	var rows []row
	for mod, deps := range importedBy {
		if len(deps) == 0 {
			continue
		}
		var dl []string
		for d := range deps {
			dl = append(dl, d)
		}
		sort.Strings(dl)
		rows = append(rows, row{mod, len(deps), dl})
	}
	if len(rows) == 0 {
		return ""
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].count > rows[j].count })
	if len(rows) > 20 {
		rows = rows[:20]
	}
	var b strings.Builder
	b.WriteString(`<div class="as-section"><div class="as-section__head"><span class="ico">🔗</span><h3>Module Penetration</h3></div>`)
	b.WriteString(`<p class="as-section__sub">Modules imported by the most others — shared dependencies.</p>`)
	b.WriteString(`<table class="as-table"><thead><tr><th>Module</th><th>Used by</th><th>Dependents</th></tr></thead><tbody>`)
	for _, r := range rows {
		deps := strings.Join(r.deps, ", ")
		if len(deps) > 80 {
			deps = deps[:77] + "…"
		}
		fmt.Fprintf(&b, `<tr><td class="mono">%s</td><td class="mono">%d</td><td class="mono" style="font-size:11px;color:var(--text-faint)">%s</td></tr>`,
			esc(r.name), r.count, esc(deps))
	}
	b.WriteString(`</tbody></table></div>`)
	return b.String()
}

// ── TODO / FIXME per module ───────────────────────────────────────────────────

func renderTodosFixmes(files []*parser.ParsedFile) string {
	const limit = 50
	var items []parser.TodoItem
	for _, f := range files {
		items = append(items, f.Todos...)
	}
	if len(items) == 0 {
		return ""
	}
	// Sort: FIXME before TODO, then by file path + line.
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind == "FIXME"
		}
		if items[i].FilePath != items[j].FilePath {
			return items[i].FilePath < items[j].FilePath
		}
		return items[i].Line < items[j].Line
	})
	total := len(items)
	truncated := 0
	if total > limit {
		truncated = total - limit
		items = items[:limit]
	}
	var headCount string
	if truncated > 0 {
		headCount = fmt.Sprintf("(showed %d from %d)", limit, total)
	} else {
		headCount = fmt.Sprintf("(%d)", total)
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<div class="as-section"><div class="as-section__head"><span class="ico">📝</span><h3>TODOs &amp; FIXMEs <span style="font-weight:400;opacity:.7">%s</span></h3></div>`, headCount)
	b.WriteString(`<table class="as-table"><thead><tr><th>Kind</th><th>File</th><th>Note</th></tr></thead><tbody>`)
	for _, it := range items {
		kindCls := "sev-low"
		if it.Kind == "FIXME" {
			kindCls = "sev-medium"
		}
		fileCell := esc(shortenPathFront(it.FilePath, 45))
		if href := vscodeHref(it.FilePath, it.Line); href != "" {
			fileCell = fmt.Sprintf(`<a class="as-vs" href="%s" title="Open in VS Code">%s:%d</a>`,
				esc(href), esc(shortenPathFront(it.FilePath, 40)), it.Line)
		} else {
			fileCell = fmt.Sprintf(`%s:%d`, fileCell, it.Line)
		}
		fmt.Fprintf(&b, `<tr><td><span class="as-sev %s">%s</span></td><td class="mono">%s</td><td class="mono">%s</td></tr>`,
			kindCls, esc(it.Kind), fileCell, esc(it.Text))
	}
	b.WriteString(`</tbody></table>`)
	if truncated > 0 {
		fmt.Fprintf(&b, `<p class="as-section__sub">… and %d more</p>`, truncated)
	}
	b.WriteString(`</div>`)
	return b.String()
}
