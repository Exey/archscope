package html

import (
	"fmt"
	"html"
	"math"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/exey/archscope/internal/git"
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules/speccoverage"
	"github.com/exey/archscope/internal/modules/traffic"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/result"
	"github.com/exey/archscope/internal/scanner"
	"github.com/exey/archscope/internal/security"
)

// ── Tech Stack + Packages & Modules (goscope-style global section) ──────────

// techImportMap maps an import substring (case-insensitive) to a framework /
// library label and category.
// Categories: "frontend", "backend", "data", "brokers", "linters"
var techImportMap = []struct{ needle, label, cat string }{
	// ── Swift / Apple ──────────────────────────────────────────────────────────
	// Frontend
	{"swiftui", "SwiftUI", "frontend"}, {"uikit", "UIKit", "frontend"},
	{"combine", "Combine", "frontend"}, {"observation", "Observation", "frontend"},
	{"appintents", "AppIntents", "frontend"}, {"widgetkit", "WidgetKit", "frontend"},
	{"mapkit", "MapKit", "frontend"}, {"arkit", "ARKit", "frontend"},
	{"snapkit", "SnapKit", "frontend"}, {"kingfisher", "Kingfisher", "frontend"},
	{"rxswift", "RxSwift", "frontend"}, {"sdwebimage", "SDWebImage", "frontend"},
	{"lottie", "Lottie", "frontend"}, {"charts", "Charts", "frontend"},
	// Backend
	{"foundation", "Foundation", "backend"}, {"healthkit", "HealthKit", "backend"}, {"storekit", "StoreKit", "backend"},
	{"alamofire", "Alamofire", "backend"}, {"moya", "Moya", "backend"},
	{"promisekit", "PromiseKit", "backend"}, {"swiftprotobuf", "SwiftProtobuf", "backend"},
	{"keychainaccess", "KeychainAccess", "backend"},
	// Data
	{"coredata", "Core Data", "data"}, {"swiftdata", "SwiftData", "data"},
	{"realmswift", "Realm", "data"}, {"grdb", "GRDB", "data"},
	// Logs & Tests
	{"xctest", "XCTest", "linters"},
	{"swiftlint", "SwiftLint", "linters"}, {"swiftgen", "SwiftGen", "linters"},
	{"cocoalumberjack", "CocoaLumberjack", "linters"},

	// ── JavaScript / TypeScript ────────────────────────────────────────────────
	// Frontend
	{"react-native", "React Native", "frontend"}, {"expo", "Expo", "frontend"},
	{"react", "React", "frontend"}, {"next/", "Next.js", "frontend"},
	{"vue", "Vue", "frontend"}, {"nuxt", "Nuxt", "frontend"}, {"angular", "Angular", "frontend"},
	{"svelte", "Svelte", "frontend"}, {"solid-js", "SolidJS", "frontend"}, {"astro", "Astro", "frontend"},
	{"redux", "Redux", "frontend"}, {"rxjs", "RxJS", "frontend"},
	{"@apollo/client", "Apollo Client", "frontend"}, {"relay", "Relay", "frontend"},
	{"tailwindcss", "Tailwind CSS", "frontend"}, {"bootstrap", "Bootstrap", "frontend"},
	{"@mui/", "MUI", "frontend"}, {"@chakra-ui/", "Chakra UI", "frontend"}, {"antd", "Ant Design", "frontend"},
	{"jquery", "jQuery", "frontend"}, {"d3-", "D3.js", "frontend"}, {"three", "Three.js", "frontend"},
	// Backend
	{"express", "Express", "backend"}, {"@nestjs", "NestJS", "backend"},
	{"axios", "Axios", "backend"}, {"lodash", "Lodash", "backend"},
	{"moment", "Moment.js", "backend"}, {"dayjs", "Day.js", "backend"},
	{"graphql", "GraphQL", "backend"},
	// Data
	{"prisma", "Prisma", "data"}, {"typeorm", "TypeORM", "data"},
	{"sequelize", "Sequelize", "data"}, {"mongoose", "Mongoose", "data"},
	// Linters
	{"webpack", "Webpack", "linters"}, {"vite", "Vite", "linters"},
	{"eslint", "ESLint", "linters"}, {"prettier", "Prettier", "linters"},

	// ── Python ─────────────────────────────────────────────────────────────────
	// Frontend
	{"streamlit", "Streamlit", "frontend"}, {"dash", "Dash", "frontend"},
	// Backend
	{"djangorestframework", "Django REST Framework", "backend"}, {"django", "Django", "backend"},
	{"flask", "Flask", "backend"}, {"fastapi", "FastAPI", "backend"},
	{"beautifulsoup4", "Beautiful Soup", "backend"}, {"scrapy", "Scrapy", "backend"},
	{"requests", "Requests", "backend"}, {"httpx", "HTTPx", "backend"},
	{"jinja2", "Jinja2", "backend"}, {"click", "Click", "backend"},
	{"uvicorn", "Uvicorn", "backend"}, {"starlette", "Starlette", "backend"}, {"aiohttp", "aiohttp", "backend"},
	{"pydantic", "Pydantic", "backend"},
	// Data
	{"sqlalchemy", "SQLAlchemy", "data"}, {"sqlmodel", "SQLModel", "data"},
	{"scikit-learn", "scikit-learn", "data"}, {"scipy", "SciPy", "data"},
	{"numpy", "NumPy", "data"}, {"pandas", "pandas", "data"},
	{"matplotlib", "Matplotlib", "data"}, {"seaborn", "Seaborn", "data"}, {"plotly", "Plotly", "data"},
	{"tensorflow", "TensorFlow", "data"}, {"torch", "PyTorch", "data"},
	// Message brokers
	{"celery", "Celery", "brokers"}, {"dramatiq", "Dramatiq", "brokers"},
	// Linters
	{"pytest", "pytest", "linters"},

	// ── Go ─────────────────────────────────────────────────────────────────────
	// Backend
	{"net/http", "net/http", "backend"}, {"gin-gonic", "Gin", "backend"},
	{"github.com/labstack/echo", "Echo", "backend"}, {"github.com/go-chi/chi", "Chi", "backend"},
	{"github.com/gofiber/fiber", "Fiber", "backend"}, {"github.com/gorilla/mux", "Gorilla Mux", "backend"},
	{"github.com/spf13/viper", "Viper", "backend"},
	{"grpc", "gRPC", "backend"}, {"google.golang.org/protobuf", "Protobuf", "backend"},
	{"cobra", "Cobra", "backend"},
	// Data
	{"gorm.io", "GORM", "data"},
	{"github.com/go-sql-driver/mysql", "MySQL driver", "data"},
	{"jackc/pgx", "PostgreSQL", "data"}, {"lib/pq", "PostgreSQL", "data"}, {"gorm.io/driver/postgres", "PostgreSQL", "data"},
	{"go.mongodb.org/mongo-driver", "MongoDB", "data"},
	{"go-redis/redis", "Redis", "data"}, {"redis/go-redis", "Redis", "data"},
	{"minio/minio-go", "MinIO", "data"},
	// Logs & Tests
	{"go.uber.org/zap", "Zap", "linters"}, {"github.com/sirupsen/logrus", "Logrus", "linters"},
	{"log/slog", "slog", "linters"},
	{"testify", "Testify", "linters"},

	// ── Java ───────────────────────────────────────────────────────────────────
	// Backend
	{"springframework.boot", "Spring Boot", "backend"}, {"org.springframework", "Spring", "backend"},
	{"lombok", "Lombok", "backend"}, {"retrofit2", "Retrofit", "backend"}, {"okhttp3", "OkHttp", "backend"},
	{"javax.servlet", "Java Servlet", "backend"}, {"jakarta.servlet", "Jakarta Servlet", "backend"},
	{"java.util", "Java Standard Library", "backend"},
	{"google.guava", "Guava", "backend"}, {"apache.commons", "Apache Commons", "backend"},
	{"jackson", "Jackson", "backend"},
	// Data
	{"hibernate", "Hibernate", "data"},
	// Message brokers
	{"spring.kafka", "Spring Kafka", "brokers"}, {"spring.amqp", "Spring AMQP", "brokers"},
	// Logs & Tests
	{"junit", "JUnit", "linters"}, {"mockito", "Mockito", "linters"},
	{"org.slf4j", "SLF4J", "linters"}, {"log4j", "Log4j", "linters"},
	{"ch.qos.logback", "Logback", "linters"},

	// ── Kotlin ─────────────────────────────────────────────────────────────────
	// Frontend
	{"androidx.compose", "Jetpack Compose", "frontend"},
	// Backend
	{"kotlinx.coroutines", "Kotlin Coroutines", "backend"}, {"kotlinx.serialization", "Kotlin Serialization", "backend"},
	{"io.ktor", "Ktor", "backend"}, {"com.google.dagger", "Dagger (Kotlin)", "backend"},
	{"kotlinx.datetime", "Kotlinx Datetime", "backend"}, {"kotlinx.html", "Kotlinx HTML", "backend"},
	// Data
	{"org.jetbrains.exposed", "Exposed", "data"},
	// Linters
	{"kotlin.test", "Kotlin Test", "linters"},

	// ── Universal message brokers (detected from scanner / config) ─────────────
	{"kafka", "Kafka", "brokers"}, {"rabbitmq", "RabbitMQ", "brokers"},
	{"nats", "NATS", "brokers"}, {"redis.pubsub", "Redis Pub/Sub", "brokers"},
	{"amqp", "AMQP", "brokers"}, {"apache.pulsar", "Apache Pulsar", "brokers"},
	{"aws.sqs", "AWS SQS", "brokers"}, {"aws.sns", "AWS SNS", "brokers"},
	{"google.pubsub", "Google Pub/Sub", "brokers"},

	// ── Universal data stores (scanner: docker-compose / go.mod / Makefile) ────
	{"postgresql", "PostgreSQL", "data"}, {"mongodb", "MongoDB", "data"},
	{"redis", "Redis", "data"}, {"minio", "MinIO", "data"},
	{"elasticsearch", "Elasticsearch", "data"}, {"elastic/go-elasticsearch", "Elasticsearch", "data"},
	{"olivere/elastic", "Elasticsearch", "data"},

	// ── Universal metrics / observability ─────────────────────────────────────
	{"opentelemetry", "OpenTelemetry", "linters"}, {"go.opentelemetry.io", "OpenTelemetry", "linters"},
	{"open-telemetry", "OpenTelemetry", "linters"},
	{"prometheus", "Prometheus", "linters"}, {"client_golang/prometheus", "Prometheus", "linters"},
	{"grafana", "Grafana", "linters"}, {"datadog", "Datadog", "linters"},
	{"jaeger", "Jaeger", "linters"}, {"zipkin", "Zipkin", "linters"},
	{"newrelic", "New Relic", "linters"},
}

var langLabels = map[string]string{
	"swift": "Swift", "objc": "Objective-C", "python": "Python",
	"typescript": "TypeScript / JS", "go": "Go",
}

func renderStackAndModules(res *result.AnalysisResult) string {
	// Tech stack: languages present + frameworks detected from imports + scanner.
	langSet := map[string]bool{}
	for _, f := range res.Files {
		if lbl, ok := langLabels[f.LanguageID]; ok {
			langSet[lbl] = true
		}
	}
	if len(langSet) == 0 && len(res.Technologies) == 0 && len(res.Scan.Modules) == 0 {
		return ""
	}

	// Categorize detected frameworks.
	catSets := map[string]map[string]bool{
		"frontend": {},
		"backend":  {},
		"data":     {},
		"brokers":  {},
		"linters":  {},
	}
	for _, f := range res.Files {
		for _, imp := range f.Imports {
			low := strings.ToLower(imp)
			for _, t := range techImportMap {
				if strings.Contains(low, t.needle) {
					catSets[t.cat][t.label] = true
				}
			}
		}
	}
	// Classify scanner-detected technologies (docker-compose, go.mod, Makefile…).
	labelCat := map[string]string{}
	for _, t := range techImportMap {
		labelCat[t.label] = t.cat
	}
	for _, t := range res.Technologies {
		if cat, ok := labelCat[t]; ok {
			catSets[cat][t] = true
		} else {
			catSets["backend"][t] = true // unknown → backend
		}
	}

	var b strings.Builder
	b.WriteString(`<div class="as-section"><div class="as-section__head"><span class="ico">🧰</span><h2>Tech Stack &amp; Modules</h2></div>`)

	// Languages row.
	if len(langSet) > 0 {
		b.WriteString(`<div class="as-sub">Languages</div><div class="as-tagcloud">`)
		for _, l := range sortedKeys(langSet) {
			fmt.Fprintf(&b, `<span class="as-tag tag-local">%s</span>`, esc(l))
		}
		b.WriteString(`</div>`)
	}

	// 5-column tech stack with adaptive widths (flex-grow ∝ item count).
	type col struct {
		cat, label, icon string
	}
	cols := []col{
		{"frontend", "Frontend", "🖥️"},
		{"backend", "Backend", "⚙️"},
		{"data", "Data", "🗄️"},
		{"brokers", "Message Brokers", "📨"},
		{"linters", "Metrics", "📊"},
	}
	hasAny := false
	for _, c := range cols {
		if len(catSets[c.cat]) > 0 {
			hasAny = true
			break
		}
	}
	if hasAny {
		b.WriteString(`<div style="display:flex;flex-wrap:wrap;gap:12px 20px;margin-top:10px;align-items:flex-start">`)
		for _, c := range cols {
			n := len(catSets[c.cat])
			if n == 0 {
				continue
			}
			// flex-grow proportional to item count (min 1), flex-basis 140px.
			fmt.Fprintf(&b, `<div style="flex:%d 0 140px;min-width:120px">`, n)
			fmt.Fprintf(&b, `<div class="as-sub" style="margin-bottom:4px">%s %s</div>`, c.icon, c.label)
			b.WriteString(`<div class="as-tagcloud" style="margin-top:0">`)
			for _, fw := range sortedKeys(catSets[c.cat]) {
				fmt.Fprintf(&b, `<span class="as-tag tag-tech">%s</span>`, esc(fw))
			}
			b.WriteString(`</div></div>`)
		}
		b.WriteString(`</div>`)
	} else if len(langSet) == 0 {
		b.WriteString(`<p class="as-empty">No technologies detected.</p>`)
	}

	// Packages & modules grid, sized by LOC.
	// Key by (moduleName, platform) so same-named modules in different languages
	// are not merged.
	type modAgg struct {
		name string
		plat langspec.Platform
		loc  int
	}
	aggKey := func(name string, p langspec.Platform) string { return name + "\x00" + string(p) }
	aggs := map[string]*modAgg{}
	for _, f := range res.Files {
		k := aggKey(f.ModuleName, langspec.Platform(f.Platform))
		a := aggs[k]
		if a == nil {
			a = &modAgg{name: f.ModuleName, plat: langspec.Platform(f.Platform)}
			aggs[k] = a
		}
		a.loc += f.LineCount
	}
	var list []*modAgg
	for _, a := range aggs {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].loc != list[j].loc {
			return list[i].loc > list[j].loc
		}
		if list[i].name != list[j].name {
			return list[i].name < list[j].name
		}
		return string(list[i].plat) < string(list[j].plat)
	})
	// Check if the project has multiple languages — if so, always show lang badge.
	platSet := map[langspec.Platform]bool{}
	for _, a := range list {
		platSet[a.plat] = true
	}
	multiLang := len(platSet) > 1
	// For same-name conflicts across platforms, always badge regardless.
	namePlatCount := map[string]int{}
	for _, a := range list {
		namePlatCount[a.name]++
	}
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
			badge := ""
			if multiLang || namePlatCount[a.name] > 1 {
				badge = shortLangBadge(a.plat)
			}
			fmt.Fprintf(&b,
				`<div class="as-pkg as-pkg--link" data-mod="%s" style="cursor:pointer" title="Open in Modules &amp; Microservices">`+
					`<span class="as-pkg__name">📦 %s</span>`+
					`<span class="as-pkg__meta">%s<span class="as-pkg__loc">%s loc</span></span>`+
					`</div>`,
				esc(anchorID(a.name)), esc(name), badge, fmtNum(a.loc))
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

// shortLangLabel returns a short display label ("Go", "Py", "TS", "Swift", "Kt")
// for a platform, stripping the ":folder" suffix used in FolderAsTab mode.
func shortLangLabel(plat langspec.Platform) string {
	s := string(plat)
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	switch langspec.Platform(s) {
	case langspec.PlatformGo:
		return "Go"
	case langspec.PlatformPython:
		return "Py"
	case langspec.PlatformTSJS:
		return "TS"
	case langspec.PlatformSwiftObjC:
		return "Swift"
	case langspec.PlatformKotlin:
		return "Kt"
	}
	return s
}

// shortLangBadge renders a single compact language pill for module cards.
func shortLangBadge(plat langspec.Platform) string {
	label := shortLangLabel(plat)
	if label == "" {
		return ""
	}
	cls := string(plat)
	if i := strings.IndexByte(cls, ':'); i >= 0 {
		cls = cls[:i]
	}
	return fmt.Sprintf(`<span class="as-plat-badge as-plat-%s" style="font-size:10px;margin-right:4px">%s</span>`, cls, label)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// fmtNum is an alias kept for plain-text / SVG contexts.
func fmtNum(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	start := len(s) % 3
	if start > 0 {
		b.WriteString(s[:start])
	}
	for i := start; i < len(s); i += 3 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// fmtNumHTML formats n as HTML with an inline-block <span class="as-g"> as
// thousands separator. The span's CSS width gives a reliable half-space in
// any font. Output must NOT be passed through html.EscapeString.
func fmtNumHTML(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	const sep = `<span class="as-g"></span>`
	var b strings.Builder
	start := len(s) % 3
	if start > 0 {
		b.WriteString(s[:start])
	}
	for i := start; i < len(s); i += 3 {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
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
	card(&b, fmtNum(res.TotalLines()), "lines of code", false)
	card(&b, fmtNum(len(res.Files)), "source files", false)
	card(&b, fmtNum(decls), "declarations", false)
	card(&b, fmtNum(len(res.Scan.Modules)), "modules", false)
	cardDangerIndex(&b, fmt.Sprintf("%.1f%%", float64(res.SecurityScore.Total)/10.0))
	card(&b, fmtNum(len(platforms)), plural(len(platforms), "platform", "platforms"), false)
	b.WriteString(`</div>`)
	return b.String()
}

func card(b *strings.Builder, num, label string, accent bool) {
	cls := "as-card"
	if accent {
		cls += " as-card--accent"
	}
	fmt.Fprintf(b, `<div class="%s"><span class="as-card__num">%s</span><span class="as-card__label">%s</span></div>`,
		cls, num, esc(label))
}

// cardDangerIndex renders the accented Danger Index summary card.
func cardDangerIndex(b *strings.Builder, score string) {
	b.WriteString(`<div class="as-card as-card--accent">`)
	fmt.Fprintf(b, `<span class="as-card__num">%s</span>`, esc(score))
	b.WriteString(`<span class="as-card__label">Danger rate</span>`)
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
		// Mirror the exact sort used in renderTabs so order matches the tab bar.
		platLOC := map[langspec.Platform]int{}
		for _, f := range res.Files {
			platLOC[langspec.Platform(f.Platform)] += f.LineCount
		}
		orderedPlats := append([]*scanner.PlatformGroup(nil), res.Scan.PlatformsOrdered()...)
		if res.Scan.FolderAsTab {
			folderLOC := map[string]int{}
			for _, pg := range orderedPlats {
				folderLOC[tabFolder(pg.Platform)] += platLOC[pg.Platform]
			}
			sort.SliceStable(orderedPlats, func(i, j int) bool {
				fi, fj := tabFolder(orderedPlats[i].Platform), tabFolder(orderedPlats[j].Platform)
				if fi != fj {
					li, lj := folderLOC[fi], folderLOC[fj]
					if li != lj {
						return li > lj
					}
					return fi < fj
				}
				return orderedPlats[i].TabLabel() < orderedPlats[j].TabLabel()
			})
		} else {
			sort.SliceStable(orderedPlats, func(i, j int) bool {
				li, lj := platLOC[orderedPlats[i].Platform], platLOC[orderedPlats[j].Platform]
				if li != lj {
					return li > lj
				}
				return orderedPlats[i].FileCount > orderedPlats[j].FileCount
			})
		}
		b.WriteString(`<div class="as-sub" style="margin-bottom:8px">Findings by Platform</div>`)
		b.WriteString(`<div class="as-sec-plat-row">`)
		for i, pg := range orderedPlats {
			total := platFindings[pg.Platform]
			if total == 0 {
				continue
			}
			hi := platHigh[pg.Platform]
			hiHTML := ""
			if hi > 0 {
				hiHTML = fmt.Sprintf(` <span class="as-sev sev-high" style="font-size:10px">%d HIGH</span>`, hi)
			}
			fmt.Fprintf(&b,
				`<div class="as-sec-plat-card" data-tab="%d" style="cursor:pointer">`+
					`<div class="as-sec-plat-name">%s</div>`+
					`<div class="as-sec-plat-count">%d%s</div>`+
					`</div>`,
				i, esc(pg.TabLabel()), total, hiHTML)
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
		"16":   "Security Configuration Errors",
		"22":   "Path Traversal",
		"78":   "OS Command Injection",
		"79":   "Cross-Site Scripting",
		"89":   "SQL Injection",
		"94":   "Code Injection",
		"117":  "Log Output Neutralization",
		"119":  "Buffer Overflow",
		"272":  "Least Privilege Violation",
		"276":  "Incorrect Default Permissions",
		"295":  "Improper Certificate Validation",
		"311":  "Missing Encryption of Sensitive Data",
		"319":  "Cleartext Transmission",
		"321":  "Hard-coded Cryptographic Key",
		"327":  "Broken or Risky Crypto Algorithm",
		"328":  "Weak Hash",
		"329":  "Not Using Random IV with CBC Mode",
		"338":  "Cryptographically Weak PRNG",
		"346":  "Origin Validation Error",
		"347":  "Improper Cryptographic Signature Check",
		"352":  "Cross-Site Request Forgery",
		"362":  "Race Condition (TOCTOU)",
		"400":  "Uncontrolled Resource Consumption",
		"434":  "Unrestricted File Upload",
		"476":  "NULL Pointer Dereference",
		"477":  "Use of Obsolete Function",
		"489":  "Active Debug Code",
		"502":  "Deserialization of Untrusted Data",
		"522":  "Insufficiently Protected Credentials",
		"530":  "Exposure of Backup File",
		"532":  "Sensitive Info in Log File",
		"601":  "URL Redirection to Untrusted Site",
		"611":  "XML External Entity (XXE)",
		"614":  "Sensitive Cookie Without Secure Flag",
		"693":  "Protection Mechanism Failure",
		"732":  "Incorrect Permission Assign for Crit. Resource",
		"749":  "Exposed Dangerous Method",
		"770":  "Allocation of Resources Without Limits",
		"798":  "Hard-coded Credentials",
		"913":  "Improper Control of Dynamic-Managed Code",
		"916":  "Weak Password Hash Algorithm",
		"918":  "Server-Side Request Forgery",
		"922":  "Insecure Storage of Sensitive Info",
		"926":  "Improper Export of Android Components",
		"942":  "Permissive CORS Policy",
		"943":  "NoSQL Injection",
		"1004": "Sensitive Cookie Without HttpOnly Flag",
		"1299": "Missing Protection for Alternate Hardware",
		"1321": "Prototype Pollution",
		"1333": "Regular Expression DoS",
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
	// Also track which CWEs have actual findings (not passed) for red border.
	type cweInfo struct {
		n           int
		isUniversal bool
		langs       map[string]bool
	}
	info := map[string]*cweInfo{}
	failedCWEs := map[string]bool{}
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
		if !rr.Passed() {
			failedCWEs[rr.Rule.CWE] = true
		}
	}

	type entry struct {
		id string
		ci *cweInfo
	}
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
		itemStyle := ""
		if failedCWEs[e.id] {
			itemStyle = ` style="border:1px solid #c05040;"`
		}
		fmt.Fprintf(&b,
			`<div class="as-cwe-item"%s>`+
				`<div class="as-cwe-top"><a class="as-cwe-item-id" href="%s" target="_blank" rel="noopener noreferrer">CWE-%s</a>%s</div>`+
				`<span class="as-cwe-item-name">%s <span class="as-cwe-count">(%d %s)</span></span>`+
				`</div>`,
			itemStyle, url, e.id, langHTML.String(), esc(name), e.ci.n, word)
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

	// Compute per-tab LOC from parsed files.
	loc := map[langspec.Platform]int{}
	for _, f := range res.Files {
		loc[langspec.Platform(f.Platform)] += f.LineCount
	}
	platforms = append([]*scanner.PlatformGroup(nil), platforms...)

	if res.Scan.FolderAsTab {
		// Folder-as-tab: group by folder, sort folder groups by total LOC desc,
		// within each folder sort alphabetically by language label.
		folderLOC := map[string]int{}
		for _, pg := range platforms {
			folderLOC[tabFolder(pg.Platform)] += loc[pg.Platform]
		}
		sort.SliceStable(platforms, func(i, j int) bool {
			fi, fj := tabFolder(platforms[i].Platform), tabFolder(platforms[j].Platform)
			if fi != fj {
				li, lj := folderLOC[fi], folderLOC[fj]
				if li != lj {
					return li > lj
				}
				return fi < fj
			}
			return platforms[i].TabLabel() < platforms[j].TabLabel()
		})
	} else {
		sort.SliceStable(platforms, func(i, j int) bool {
			li, lj := loc[platforms[i].Platform], loc[platforms[j].Platform]
			if li != lj {
				return li > lj
			}
			return platforms[i].FileCount > platforms[j].FileCount
		})
	}

	outerClass := "as-tabs"
	if res.Scan.FolderAsTab {
		outerClass = "as-tabs as-tabs--folders"
	}

	var b strings.Builder
	b.WriteString(`<div class="as-sub" style="margin-top:16px;margin-bottom:4px">Platforms</div>`)
	fmt.Fprintf(&b, `<div class="%s">`, outerClass)
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
	prevFolder := ""
	for i, pg := range platforms {
		folder := tabFolder(pg.Platform)
		if res.Scan.FolderAsTab && i > 0 && folder != prevFolder {
			b.WriteString(`<span class="as-tab-sep"></span>`)
		}
		prevFolder = folder
		if pg.Label != "" {
			fmt.Fprintf(&b, `<label class="as-tab" for="t%d">%s</label>`, i, esc(pg.TabLabel()))
		} else {
			fmt.Fprintf(&b, `<label class="as-tab" for="t%d">%s<span class="as-tab__count">%d</span></label>`,
				i, esc(pg.TabLabel()), pg.FileCount)
		}
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

// tabFolder extracts the folder name from a synthetic platform key "lang:folder".
// For non-synthetic keys returns the platform string itself (used as group key).
func tabFolder(p langspec.Platform) string {
	s := string(p)
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// platBadgeHTML returns a small colored pill showing the tab label,
// placed before the section icon in every platform-tab card header.
func platBadgeHTML(pg *scanner.PlatformGroup) string {
	cls := string(pg.LanguagePlatform)
	if cls == "" {
		cls = string(pg.Platform)
	}
	return fmt.Sprintf(`<span class="as-plat-badge as-plat-%s" style="margin-right:6px;font-size:11px;vertical-align:middle">%s</span>`,
		esc(cls), esc(pg.TabLabel()))
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

	// Split panels: architecture dropped (rendered above), ddd, spec coverage,
	// traffic, design patterns (move into Module Insights), rest.
	var dddPanels, specPanels, trafficPanels, designPanels, otherPanels []result.ModulePanel
	for _, p := range res.PanelsForPlatform(pg.Platform) {
		switch p.ModuleID {
		case "architecture":
			// rendered in the dedicated Architecture section above; skip
		case "dddmodel", "oopvspop":
			dddPanels = append(dddPanels, p)
		case "speccoverage":
			specPanels = append(specPanels, p)
		case "traffic":
			trafficPanels = append(trafficPanels, p)
		case "designpattern":
			designPanels = append(designPanels, p)
		default:
			otherPanels = append(otherPanels, p)
		}
	}

	var b strings.Builder
	b.WriteString(`<div class="as-cards">`)
	card(&b, fmtNum(pg.FileCount), "files", false)
	card(&b, fmtNum(lines), "lines", false)
	card(&b, fmtNum(decls), "declarations", false)
	card(&b, fmtNum(len(pg.Modules)), plural(len(pg.Modules), "module", "modules"), false)
	b.WriteString(`</div>`)

	badge := platBadgeHTML(pg)

	// 1. 🏛️ Architecture
	if layersHTML := renderArchLayers(files); layersHTML != "" {
		techSet := buildTechSet(res, files)
		componentsHTML := renderArchComponents(files, techSet)
		fmt.Fprintf(&b, `<div class="as-section"><div class="as-section__head">%s<span class="ico">🏛️</span><h3>Architecture</h3></div>`, badge)
		b.WriteString(layersHTML)
		b.WriteString(componentsHTML)
		b.WriteString(`</div>`)
	}

	// 2. 🎯 Domain Model
	b.WriteString(renderModulePanels(dddPanels, badge))

	// 3. 🧱 Spec Coverage
	b.WriteString(renderModulePanels(specPanels, badge))

	// 4. 🛜 Traffic — with SPEC COV column when spec coverage data is available.
	var specRes *speccoverage.Result
	for _, p := range specPanels {
		if r, ok := p.RawResult.(speccoverage.Result); ok {
			specRes = &r
			break
		}
	}
	if specRes != nil && len(trafficPanels) > 0 {
		b.WriteString(renderTrafficWithSpec(trafficPanels, specRes, badge))
	} else {
		b.WriteString(renderModulePanels(trafficPanels, badge))
	}

	// 5. 💡 Module Insights — Hotspots · Modules · Design Patterns · TODOs · Longest Functions
	b.WriteString(renderModuleInsights(res, pg, files, designPanels, res.RootPath, badge))

	// 6. 🐙 Git Analysis — per-platform churn + contributors
	b.WriteString(renderPlatformGit(res, pg, files, badge))

	// 7. 🛡️ Danger Details
	b.WriteString(renderPlatformSecurity(res, pg.Platform, badge))

	// 8. 📂 Modules & Microservices — per-platform file inventory
	b.WriteString(renderModuleDetailsPlatform(res.RootPath, files, badge))

	// Remaining panels
	b.WriteString(renderModulePanels(otherPanels))
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

	// When rendering a folder-as-tab platform, qualify module names with the
	// folder so that "backend(pharmen)" and "backend(pharmzakaz)" are distinct.
	folder := platformFolderSuffix(pg.Platform)
	qualify := func(name string) string {
		if folder == "" || name == "(root)" {
			return name
		}
		return name + "(" + folder + ")"
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
		if g := renderModuleGraphSVG(res, inPlatform, folder); g != "" {
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
			esc(qualify(name)), r.uses, fmtNum(r.lines), r.decl)
	}
	b.WriteString(`</tbody></table></div>`)
	return b.String()
}

// platformFolderSuffix extracts the folder from a synthetic platform key
// "lang:folder", returning "" for plain (non-folder-as-tab) platform keys.
func platformFolderSuffix(p langspec.Platform) string {
	s := string(p)
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[i+1:]
	}
	return ""
}

// renderMicroservicesSection renders the module/package grid card.
func renderMicroservicesSection(pg *scanner.PlatformGroup, files []*parser.ParsedFile) string {
	if len(pg.Modules) == 0 {
		return ""
	}
	icon, label := langspec.Default.ModuleNoun(pg.Platform)
	counts := map[string]int{}
	mloc := map[string]int{}
	for _, f := range files {
		counts[f.ModuleName]++
		mloc[f.ModuleName] += f.LineCount
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<div class="as-section"><div class="as-section__head"><span class="ico">%s</span><h3>%s <span class="as-count">(%d)</span></h3></div><div class="as-modgrid">`,
		esc(icon), esc(label), len(pg.Modules))
	for _, m := range pg.Modules {
		name := m
		if name == "" {
			name = "(root)"
		}
		fmt.Fprintf(&b, `<a class="as-mod" href="#mod-%s"><div class="as-mod__name">%s</div><div class="as-mod__meta">%d %s · %s loc</div></a>`,
			esc(anchorID(m)), esc(name), counts[m], plural(counts[m], "file", "files"), fmtNum(mloc[m]))
	}
	b.WriteString(`</div></div>`)
	return b.String()
}

// renderModuleInsights groups Dependency Hotspots, Modules, Design Patterns,
// TODOs & FIXMEs, and Longest Functions under a single "💡 Module Insights" header.
func renderModuleInsights(res *result.AnalysisResult, pg *scanner.PlatformGroup, files []*parser.ParsedFile, designPanels []result.ModulePanel, rootPath string, headBadge string) string {
	var parts []string
	if h := renderHotspots(res, pg); h != "" {
		parts = append(parts, h)
	}
	if m := renderMicroservicesSection(pg, files); m != "" {
		parts = append(parts, m)
	}
	if dp := renderModulePanels(designPanels); dp != "" {
		parts = append(parts, dp)
	}
	if t := renderTodosFixmes(files); t != "" {
		parts = append(parts, t)
	}
	if lf := renderLongestFunctions(files, rootPath); lf != "" {
		parts = append(parts, lf)
	}
	if len(parts) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<div class="as-insights"><div class="as-insights__head">%s<span class="ico">💡</span><h3>Module Insights</h3></div>`, headBadge)
	b.WriteString(`<div class="as-insights-grid">`)
	for _, p := range parts {
		b.WriteString(p)
	}
	b.WriteString(`</div></div>`)
	return b.String()
}

// renderModuleGraphSVG draws a compact, self-contained circular dependency
// graph of the platform's modules: node radius scales with in-degree, edges are
// drawn as arrows from dependent → dependency. Pure inline SVG (no JS/CDN), so
// the report stays a single self-contained file.
func renderModuleGraphSVG(res *result.AnalysisResult, inPlatform map[string]bool, folder string) string {
	if res.Graph == nil {
		return ""
	}
	keep := func(m string) bool {
		return inPlatform[m] || (m == "root" && inPlatform[""])
	}
	qualifyNode := func(name string) string {
		if folder == "" {
			return name
		}
		return name + "(" + folder + ")"
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
		} else {
			label = qualifyNode(label)
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
func renderPlatformSecurity(res *result.AnalysisResult, plat langspec.Platform, headBadge string) string {
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
	var b strings.Builder
	if total == 0 {
		fmt.Fprintf(&b, `<div class="as-section as-danger-section"><div class="as-section__head">%s<span class="ico">🛡️</span><h3>Danger Details</h3></div>`, headBadge)
		b.WriteString(`<p class="as-clean">✓ No findings in this platform's sources.</p></div>`)
		return b.String()
	}
	fmt.Fprintf(&b,
		`<div class="as-section as-danger-section"><div class="as-section__head">%s<span class="ico">🛡️</span><h3>Danger Details</h3>`+
			`<span style="margin-left:10px;font-size:12px;font-weight:400">`+
			`<span class="as-sev sev-high">HIGH %d</span> `+
			`<span class="as-sev sev-medium">MED %d</span> `+
			`<span class="as-sev sev-low">LOW %d</span>`+
			`</span></div>`,
		headBadge, hi, med, lo)
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

func renderModulePanels(panels []result.ModulePanel, headBadge ...string) string {
	if len(panels) == 0 {
		return ""
	}
	badge := ""
	if len(headBadge) > 0 {
		badge = headBadge[0]
	}
	var b strings.Builder
	for _, p := range panels {
		b.WriteString(`<div class="as-section as-modpanel">`)
		b.WriteString(`<div class="as-modpanel__head">`)
		fmt.Fprintf(&b, `%s<span class="ico">%s</span><h4>%s</h4>`, badge, moduleIcon(p.ModuleID), esc(p.Title))
		for _, c := range p.Cards {
			fmt.Fprintf(&b, `<span class="as-rule__id">%s %s</span>`, esc(c.Num), esc(c.Label))
		}
		b.WriteString(`</div>`)
		b.WriteString(p.HTML)
		b.WriteString(`</div>`)
	}
	return b.String()
}

// reSpecParam matches URL path parameters in {id}, :id, or <id> forms.
var reSpecParam = regexp.MustCompile(`\{[^}]*\}|:[a-zA-Z_]\w*|<[^>]*>`)

// normSpecURI normalises a traffic URI for comparison against spec op paths.
func normSpecURI(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		uri = uri[:i]
	}
	uri = reSpecParam.ReplaceAllString(uri, "{}")
	uri = strings.TrimRight(uri, "/")
	if uri == "" {
		uri = "/"
	}
	return strings.ToLower(uri)
}

// renderTrafficWithSpec renders the traffic panels with an extra SPEC COV
// column (✅ in spec · ❓ undocumented) on inbound routes.
func renderTrafficWithSpec(panels []result.ModulePanel, spec *speccoverage.Result, badge string) string {
	// Build a set of normalised paths for spec-covered operations.
	coveredPaths := map[string]bool{}
	for _, op := range spec.Covered {
		coveredPaths[normSpecURI(op.Path)] = true
	}

	var b strings.Builder
	for _, p := range panels {
		tr, ok := p.RawResult.(traffic.Result)
		if !ok {
			// Fallback: render without SPEC COV column.
			b.WriteString(`<div class="as-section as-modpanel">`)
			b.WriteString(`<div class="as-modpanel__head">`)
			fmt.Fprintf(&b, `%s<span class="ico">🛜</span><h4>%s</h4>`, badge, esc(p.Title))
			for _, c := range p.Cards {
				fmt.Fprintf(&b, `<span class="as-rule__id">%s %s</span>`, esc(c.Num), esc(c.Label))
			}
			b.WriteString(`</div>`)
			b.WriteString(p.HTML)
			b.WriteString(`</div>`)
			continue
		}

		b.WriteString(`<div class="as-section as-modpanel">`)
		b.WriteString(`<div class="as-modpanel__head">`)
		fmt.Fprintf(&b, `%s<span class="ico">🛜</span><h4>%s</h4>`, badge, esc(p.Title))
		for _, c := range p.Cards {
			fmt.Fprintf(&b, `<span class="as-rule__id">%s %s</span>`, esc(c.Num), esc(c.Label))
		}
		b.WriteString(`</div>`)

		b.WriteString(`<div class="as-pop">`)
		fmt.Fprintf(&b,
			`<p class="as-pop__sub">%d inbound · %d outbound connection signals detected from string literals</p>`,
			len(tr.Inbound), len(tr.Outbound),
		)

		// Inbound with SPEC COV column.
		renderSpecTrafficTable(&b, "📥 Inbound", tr.Inbound, coveredPaths, true)
		// Outbound has no spec ops to compare (outbound = external calls).
		renderSpecTrafficTable(&b, "📤 Outbound", tr.Outbound, nil, false)

		b.WriteString(`</div>`)
		b.WriteString(`</div>`)
	}
	return b.String()
}

func renderSpecTrafficTable(b *strings.Builder, heading string, entries []traffic.Entry, coveredPaths map[string]bool, showSpecCov bool) {
	fmt.Fprintf(b, `<div class="as-sub" style="margin-top:16px">%s`, heading)
	if len(entries) > 0 {
		fmt.Fprintf(b, ` <span style="color:var(--text-faint);font-weight:400">(%d)</span>`, len(entries))
	}
	b.WriteString(`</div>`)
	if len(entries) == 0 {
		b.WriteString(`<p class="as-empty">— No signals detected</p>`)
		return
	}
	b.WriteString(`<table class="as-table"><thead><tr>`)
	if showSpecCov {
		b.WriteString(`<th>Spec</th>`)
	}
	b.WriteString(`<th>URI / Pattern</th><th>Protocol</th><th>Data</th><th>Module</th><th>File</th>`)
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
		if showSpecCov {
			specIcon := "❓"
			if coveredPaths[normSpecURI(e.URI)] {
				specIcon = "✅"
			}
			fmt.Fprintf(b, `<tr><td style="text-align:center">%s</td>`, specIcon)
			fmt.Fprintf(b,
				`<td class="mono">%s</td><td>%s</td><td class="mono">%s</td><td class="mono">%s</td><td class="mono">%s</td></tr>`,
				esc(uri), trafficProtoTag(e.Protocol), esc(dataCell), esc(mod), trafficFileLink(e.FilePath, e.Line),
			)
		} else {
			fmt.Fprintf(b,
				`<tr><td class="mono">%s</td><td>%s</td><td class="mono">%s</td><td class="mono">%s</td><td class="mono">%s</td></tr>`,
				esc(uri), trafficProtoTag(e.Protocol), esc(dataCell), esc(mod), trafficFileLink(e.FilePath, e.Line),
			)
		}
	}
	b.WriteString(`</tbody></table>`)
}

// trafficProtoTag and trafficFileLink mirror the private helpers in the traffic
// package so the HTML writer can render traffic entries directly.
func trafficProtoTag(proto string) string {
	bg, fg := trafficProtoColors(proto)
	return fmt.Sprintf(`<span class="as-tag" style="background:%s;color:%s;font-size:11px">%s</span>`, bg, fg, esc(proto))
}

func trafficProtoColors(proto string) (bg, fg string) {
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

func trafficFileLink(filePath string, line int) string {
	if filePath == "" {
		return "—"
	}
	name := filepath.Base(filePath)
	href := "vscode://file" + filePath
	if line > 0 {
		href += ":" + strconv.Itoa(line)
		name += ":" + strconv.Itoa(line)
	}
	return fmt.Sprintf(`<a href="%s">%s</a>`, esc(href), esc(name))
}

func moduleIcon(id string) string {
	switch id {
	case "architecture":
		return "🏛️"
	case "designpattern":
		return "🧩"
	case "oopvspop":
		return "⚖️"
	case "traffic":
		return "🛜"
	case "dddmodel":
		return "🍱"
	case "speccoverage":
		return "🧱"
	default:
		return "📐"
	}
}

// ── Per-platform git (churn + contributors filtered to platform files) ───────

// platformLangExts maps a LanguagePlatform to its canonical file extensions.
func platformLangExts(lp langspec.Platform) map[string]bool {
	table := map[langspec.Platform][]string{
		"go":         {".go"},
		"python":     {".py"},
		"ts_js":      {".ts", ".tsx", ".js", ".jsx"},
		"swift_objc": {".swift", ".m", ".mm"},
		"kotlin":     {".kt", ".kts"},
		"java":       {".java"},
		"ruby":       {".rb"},
		"rust":       {".rs"},
		"csharp":     {".cs"},
		"cpp":        {".cpp", ".cc", ".cxx", ".hpp", ".h"},
	}
	exts, ok := table[lp]
	if !ok {
		return nil
	}
	m := make(map[string]bool, len(exts))
	for _, e := range exts {
		m[e] = true
	}
	return m
}

func renderPlatformGit(res *result.AnalysisResult, pg *scanner.PlatformGroup, files []*parser.ParsedFile, headBadge string) string {
	g := res.Git
	if !g.Available {
		var b strings.Builder
		fmt.Fprintf(&b, `<div class="as-section"><div class="as-section__head">%s<span class="ico">🐙</span><h3>Git Analysis</h3></div>`, headBadge)
		b.WriteString(`<p class="as-empty">No git history available.</p></div>`)
		return b.String()
	}

	// Each sub-project may have its own .git root. git log --name-only outputs
	// paths relative to that repo root, not to res.RootPath. Find the deepest
	// matching repo root for each file so the relative paths align with RelPath
	// in the churn stats.
	repoRoot := func(fp string) string {
		best := res.RootPath
		for _, repo := range g.Repos {
			if len(repo) > len(best) &&
				(strings.HasPrefix(fp, repo+string(filepath.Separator)) || fp == repo) {
				best = repo
			}
		}
		return best
	}

	platRel := map[string]bool{}
	for _, f := range files {
		root := repoRoot(f.FilePath)
		if r, err := filepath.Rel(root, f.FilePath); err == nil {
			platRel[r] = true
		}
	}

	// Filter churn to this platform's files; fall back to language-extension
	// match when path matching yields nothing (single .git + small topN).
	var platChurn []git.FileChurnStat
	for _, c := range g.Churn {
		if platRel[c.RelPath] {
			platChurn = append(platChurn, c)
		}
	}
	if len(platChurn) == 0 {
		exts := platformLangExts(pg.LanguagePlatform)
		for _, c := range g.Churn {
			if exts[strings.ToLower(filepath.Ext(c.RelPath))] {
				platChurn = append(platChurn, c)
			}
		}
	}

	// Contributors: derive from platform churn (language-accurate).
	// Fall back to module-name matching (works for per-folder git repos).
	platAuthors := map[string]*git.AuthorStats{}
	for _, c := range platChurn {
		for _, authorName := range c.TopAuthors {
			if a, ok := g.Authors[authorName]; ok {
				platAuthors[authorName] = a
			}
		}
	}
	if len(platAuthors) == 0 {
		platMods := map[string]bool{}
		for _, m := range pg.Modules {
			platMods[m] = true
			if m == "" {
				platMods["root"] = true
			}
		}
		for name, a := range g.Authors {
			for mod := range a.MicroserviceCounts {
				if platMods[mod] {
					platAuthors[name] = a
					break
				}
			}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<div class="as-section"><div class="as-section__head">%s<span class="ico">🐙</span><h3>Git Analysis</h3></div>`, headBadge)
	b.WriteString(`<div class="as-grid2">`)
	b.WriteString(renderTeam(platAuthors))
	b.WriteString(renderChurn(platChurn))
	b.WriteString(`</div>`)
	b.WriteString(`<div class="as-grid2">`)
	b.WriteString(renderTagsCommits(g.Tags, g.Commits))
	b.WriteString(renderBranches(g.Branch))
	b.WriteString(`</div>`)
	b.WriteString(`</div>`)
	return b.String()
}

// ── Per-platform module/microservice detail ───────────────────────────────────

func renderModuleDetailsPlatform(rootPath string, files []*parser.ParsedFile, headBadge string) string {
	type mod struct {
		name  string
		plat  langspec.Platform
		ptype string
		files []*parser.ParsedFile
		lines int
		decls int
		kinds map[parser.DeclKind]int
	}
	var order []string
	mods := map[string]*mod{}
	for _, f := range files {
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
	fmt.Fprintf(&b, `<div class="as-section"><div class="as-section__head">%s<span class="ico">📂</span><h3>Modules &amp; Microservices</h3></div>`, headBadge)
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

		var parts []string
		for _, k := range kindOrder {
			if n := m.kinds[k]; n > 0 {
				parts = append(parts, kindLabel(k, n))
			}
		}
		if len(parts) > 0 {
			fmt.Fprintf(&b, `<p class="as-pkg-detail">%s</p>`, strings.Join(parts, " · "))
		}

		if g := renderDeclGraph(m.name, m.files); g != "" {
			b.WriteString(g)
		}

		all := append([]*parser.ParsedFile(nil), m.files...)
		sort.SliceStable(all, func(i, j int) bool { return all[i].LineCount > all[j].LineCount })
		var keep, genFiles []*parser.ParsedFile
		for _, f := range all {
			if isGeneratedFile(f.FilePath) {
				if f.LineCount >= 90 {
					genFiles = append(genFiles, f)
				}
				continue
			}
			if isTestFile(f.FilePath) {
				continue
			}
			if f.LanguageID == "ts" && f.LineCount < 15 {
				continue
			}
			if len(f.Declarations) == 0 && f.LineCount < 30 {
				continue
			}
			keep = append(keep, f)
		}
		if len(keep) == 0 && len(genFiles) == 0 {
			b.WriteString(`</div>`)
			continue
		}
		if len(keep) > 0 {
			b.WriteString(`<table class="as-table as-file-table"><thead><tr><th style="width:50%">File</th><th>Lines</th><th>Decl</th><th>Declarations</th></tr></thead><tbody>`)
			for _, f := range keep {
				b.WriteString(fileTableRow(f, rootPath))
			}
			b.WriteString(`</tbody></table>`)
		}
		if len(genFiles) > 0 {
			b.WriteString(`<div class="as-sub as-gen-sub">Code Generated</div>`)
			b.WriteString(`<table class="as-table as-file-table"><thead><tr><th style="width:50%">File</th><th>Lines</th><th>Decl</th><th>Declarations</th></tr></thead><tbody>`)
			for _, f := range genFiles {
				b.WriteString(fileTableRow(f, rootPath))
			}
			b.WriteString(`</tbody></table>`)
		}
		b.WriteString(`</div>`)
	}
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
	if strings.HasSuffix(base, ".pb.go") ||
		strings.HasSuffix(base, ".pb.gw.go") ||
		strings.HasPrefix(base, "zz_generated") {
		return true
	}
	// Django migrations: digit-prefixed .py files inside a migrations/ directory.
	if strings.HasSuffix(base, ".py") && len(base) > 0 && base[0] >= '0' && base[0] <= '9' {
		if filepath.Base(filepath.Dir(path)) == "migrations" {
			return true
		}
	}
	return false
}

// shortenPathFront shortens s to max chars by removing the beginning, e.g.
// "…cmd/server/handler.go" instead of "pkg/internal/cmd/server/handler.go".
func shortenPathFront(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return "…" + s[len(s)-(max-1):]
}

// ── VS Code path settings card ───────────────────────────────────────────────

// renderVSCodePathCard renders a one-time global card that lets the user
// update the vscode:// link prefix when sharing a report with someone whose
// project lives at a different path.
func renderVSCodePathCard(rootPath string) string {
	if rootPath == "" {
		return ""
	}
	p := strings.ReplaceAll(rootPath, "\\", "/")
	return fmt.Sprintf(
		`<div class="as-section" id="as-vs-card" style="margin-bottom:14px">`+
			`<div class="as-section__head"><span class="ico">🔗</span><h3>VS Code Links</h3></div>`+
			`<p class="as-section__sub">Edit the path prefix for <code>vscode://</code> links — useful when sharing this report with someone whose project is at a different location.</p>`+
			`<div style="display:flex;gap:8px;align-items:center;margin-top:10px;flex-wrap:wrap">`+
			`<input id="as-vs-path" type="text" value="%s" data-orig="%s"`+
			` style="flex:1;min-width:200px;padding:6px 10px;background:var(--bg-ele);border:1px solid var(--border);`+
			`border-radius:6px;color:var(--text);font-family:var(--mono);font-size:12px;outline:none">`+
			`<button id="as-vs-btn" class="as-toggle" style="white-space:nowrap">Change Path</button>`+
			`<span id="as-vs-msg" style="font-size:12px;color:var(--text-faint)"></span>`+
			`</div></div>`,
		esc(p), esc(p))
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
