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
	"time"

	"github.com/exey/archscope/internal/git"
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/modules/arch"
	"github.com/exey/archscope/internal/modules/constructs"
	"github.com/exey/archscope/internal/modules/dddmodel"
	"github.com/exey/archscope/internal/modules/speccoverage"
	"github.com/exey/archscope/internal/modules/traffic"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/report/markdown"
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
	{"foundation", "Foundation", "frontend"}, {"healthkit", "HealthKit", "frontend"}, {"storekit", "StoreKit", "frontend"},
	// Backend

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

	// ── Rust ───────────────────────────────────────────────────────────────────
	// Frontend / HTTP
	{"actix-web", "Actix-web", "frontend"}, {"actix_web", "Actix-web", "frontend"},
	{"axum", "Axum", "frontend"}, {"rocket", "Rocket", "frontend"},
	{"warp", "Warp", "frontend"}, {"hyper", "Hyper", "frontend"},
	// Backend
	{"tokio", "Tokio", "backend"}, {"async-std", "async-std", "backend"},
	{"serde", "Serde", "backend"}, {"serde_json", "serde_json", "backend"},
	{"reqwest", "Reqwest", "backend"},
	{"tonic", "Tonic", "backend"}, {"prost", "Prost", "backend"},
	{"async-graphql", "async-graphql", "backend"},
	{"tower", "Tower", "backend"}, {"tower-http", "tower-http", "backend"},
	{"clap", "Clap", "backend"}, {"rayon", "Rayon", "backend"},
	{"anyhow", "anyhow", "backend"}, {"thiserror", "thiserror", "backend"},
	{"tracing", "Tracing", "backend"}, {"log", "log", "backend"},
	// Data
	{"sqlx", "SQLx", "data"}, {"diesel", "Diesel", "data"}, {"sea-orm", "SeaORM", "data"},

	// ── C / C++ ────────────────────────────────────────────────────────────────
	// Frontend / GUI
	{"qt/q", "Qt", "frontend"}, {"gtk/gtk", "GTK", "frontend"}, {"sfml/", "SFML", "frontend"},
	{"imgui", "Dear ImGui", "frontend"},
	// Backend / networking
	{"boost/asio", "Boost.Asio", "backend"}, {"boost/", "Boost", "backend"},
	{"grpcpp/", "gRPC (C++)", "backend"}, {"curl/curl", "libcurl", "backend"},
	{"libevent", "libevent", "backend"}, {"libuv", "libuv", "backend"},
	{"poco/", "POCO", "backend"},
	// Data / serialization
	{"google/protobuf", "Protobuf", "data"}, {"nlohmann/json", "nlohmann/json", "data"},
	{"rapidjson/", "RapidJSON", "data"}, {"sqlite3", "SQLite", "data"},
	{"libpq-fe", "PostgreSQL (libpq)", "data"}, {"mysql/mysql", "MySQL", "data"},
	// Crypto / TLS
	{"openssl/", "OpenSSL", "backend"},
	// Build / test
	{"gtest/gtest", "Google Test", "linters"}, {"catch2/", "Catch2", "linters"},
	{"cmake", "CMake", "linters"},

	// ── Universal metrics / observability ─────────────────────────────────────
	{"opentelemetry", "OpenTelemetry", "linters"}, {"go.opentelemetry.io", "OpenTelemetry", "linters"},
	{"open-telemetry", "OpenTelemetry", "linters"},
	{"prometheus", "Prometheus", "linters"}, {"client_golang/prometheus", "Prometheus", "linters"},
	{"grafana", "Grafana", "linters"}, {"datadog", "Datadog", "linters"},
	{"jaeger", "Jaeger", "linters"}, {"zipkin", "Zipkin", "linters"},
	{"newrelic", "New Relic", "linters"},
}

var langLabels = map[string]string{
	"swift": "Swift", "objc": "Objective-C",
	"kotlin": "Kotlin", "java": "Java",
	"python":     "Python",
	"typescript": "TypeScript / JS", "javascript": "JavaScript",
	"go":   "Go",
	"rust": "Rust",
	"c":    "C", "cpp": "C++",
}

// renderContributionsCard renders a GitHub-style contribution calendar.
// Shows ~15 months of history (65 past weeks) plus enough future weeks to complete
// the next calendar month. One row per git repo, sorted most-active first.
func renderContributionsCard(res *result.AnalysisResult) string {
	if !res.Git.Available || len(res.Git.Repos) == 0 {
		return ""
	}

	extAbbr := map[string]string{
		"swift": "Sw", "m": "Sw", "mm": "Sw",
		"kt": "Kt", "kts": "Kt",
		"py": "Py", "pyi": "Py",
		"ts": "TS", "tsx": "TS", "js": "TS", "jsx": "TS", "mjs": "TS", "cjs": "TS",
		"go":   "Go",
		"java": "Ja", "groovy": "Ja",
		"rs":  "Rs",
		"rb":  "Rb",
		"php": "PHP",
		"cs":  "C#",
		"cpp": "C++", "cc": "C++", "cxx": "C++", "c": "C",
		"dart": "Dt",
		"ex":   "Ex", "exs": "Ex",
		"scala": "Sc",
	}
	abbrOrder := []string{"Sw", "Kt", "Py", "TS", "Go", "Ja", "Rs", "Rb", "PHP", "C#", "C++", "C", "Dt", "Ex", "Sc"}

	const pastWeeks = 61 // ~14 months of history fetched from git
	const cellPx = 11
	const gapPx = 2
	const padPx = 186 // abbr(80)+gap(8)+name(90)+gap(8)

	now := time.Now()

	// Week i date: now + (i - (pastWeeks-1)) * 7 days.
	// i=0           → oldest (about 15 months ago)
	// i=pastWeeks-1 → current week
	// i=nWeeks-1    → last week of next calendar month
	weekDate := func(i int) time.Time {
		return now.AddDate(0, 0, (i-(pastWeeks-1))*7)
	}

	// Compute future weeks dynamically: extend to the last day of the NEXT calendar
	// month so that month is always shown completely, never cut off mid-month.
	nextMonthLastDay := time.Date(now.Year(), now.Month()+2, 0, 0, 0, 0, 0, now.Location())
	daysToEnd := int(nextMonthLastDay.Sub(now).Hours()/24) + 1
	futureWeeks := (daysToEnd + 6) / 7
	if futureWeeks < 1 {
		futureWeeks = 1
	}
	maxFuture := git.NCalWeeks - pastWeeks
	if futureWeeks > maxFuture {
		futureWeeks = maxFuture
	}
	nWeeks := pastWeeks + futureWeeks

	// Rounding up to whole 7-day weeks above can overshoot a few days past
	// nextMonthLastDay into the month after next (e.g. today in July stepping
	// into September instead of stopping in August); trim any such trailing
	// weeks so the calendar never shows more than one month of future dates.
	for nWeeks > pastWeeks && weekDate(nWeeks-1).After(nextMonthLastDay) {
		nWeeks--
	}

	// Build month spans; monthOf[i] tells which month slot week i belongs to.
	type monthSpan struct {
		label string
		weeks int
	}
	var months []monthSpan
	monthOf := make([]int, git.NCalWeeks)
	for i := 0; i < nWeeks; i++ {
		label := weekDate(i).Format("Jan'06")
		if len(months) == 0 || months[len(months)-1].label != label {
			months = append(months, monthSpan{label: label, weeks: 1})
		} else {
			months[len(months)-1].weeks++
		}
		monthOf[i] = len(months) - 1
	}

	// Month label row: gap:2px between labels, each label width = N*13-2 px.
	monthRowHTML := func() string {
		var mb strings.Builder
		mb.WriteString(`<div class="as-contributions__month-row">`)
		mb.WriteString(`<span class="as-contributions__mon-pad"></span>`)
		for _, ms := range months {
			w := ms.weeks*(cellPx+gapPx) - gapPx
			fmt.Fprintf(&mb, `<span class="as-contributions__mon" style="width:%dpx">%s</span>`, w, ms.label)
		}
		mb.WriteString(`</div>`)
		return mb.String()
	}

	weeklyByRepo := res.Git.WeeklyByRepo
	if weeklyByRepo == nil {
		weeklyByRepo = map[string]map[string][git.NCalWeeks]int{}
	}

	type repoRow struct {
		name    string
		abbrs   string
		weekly  [git.NCalWeeks]int
		anomaly [git.NCalWeeks]bool
		total   int
	}

	var rows []repoRow
	for _, repoRoot := range res.Git.Repos {
		extMap := weeklyByRepo[repoRoot]
		var weekly [git.NCalWeeks]int
		seenAbbr := map[string]bool{}
		total := 0
		for ext, arr := range extMap {
			for i := 0; i < nWeeks; i++ {
				weekly[i] += arr[i]
				total += arr[i]
			}
			if a := extAbbr[ext]; a != "" {
				seenAbbr[a] = true
			}
		}

		// Anomaly detection: Tukey extreme fence (Q3 + 3×IQR).
		var anomaly [git.NCalWeeks]bool
		{
			var vals []int
			for i := 0; i < nWeeks; i++ {
				if weekly[i] > 0 {
					vals = append(vals, weekly[i])
				}
			}
			sort.Ints(vals)
			if len(vals) >= 4 {
				q1 := vals[len(vals)/4]
				q3 := vals[3*len(vals)/4]
				iqr := q3 - q1
				if iqr > 0 {
					thr := q3 + 3*iqr
					for i := 0; i < nWeeks; i++ {
						if weekly[i] > thr {
							anomaly[i] = true
						}
					}
				}
			}
		}

		var abbrParts []string
		for _, a := range abbrOrder {
			if seenAbbr[a] {
				abbrParts = append(abbrParts, a)
			}
		}
		for a := range seenAbbr {
			found := false
			for _, o := range abbrOrder {
				if o == a {
					found = true
					break
				}
			}
			if !found {
				abbrParts = append(abbrParts, a)
			}
		}
		abbrStr := strings.Join(abbrParts, " ")
		if abbrStr == "" {
			abbrStr = "?"
		}

		name := filepath.Base(repoRoot)
		runes := []rune(name)
		if len(runes) > 20 {
			name = string(runes[:17]) + "…"
		}

		rows = append(rows, repoRow{
			name:    name,
			abbrs:   abbrStr,
			weekly:  weekly,
			anomaly: anomaly,
			total:   total,
		})
	}
	if len(rows) == 0 {
		return ""
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].total > rows[j].total })

	maxNorm := 1
	for _, r := range rows {
		for i := 0; i < nWeeks; i++ {
			if !r.anomaly[i] && r.weekly[i] > maxNorm {
				maxNorm = r.weekly[i]
			}
		}
	}
	level := func(v int, isAnomaly bool) int {
		if isAnomaly {
			return 4
		}
		if v == 0 {
			return 0
		}
		p := float64(v) / float64(maxNorm)
		switch {
		case p < 0.15:
			return 1
		case p < 0.40:
			return 2
		case p < 0.70:
			return 3
		default:
			return 4
		}
	}

	var b strings.Builder
	b.WriteString(`<div class="as-card as-contributions">`)
	b.WriteString(`<div class="as-card__head"><span class="as-card__icon">📅</span> Contribution Calendar <span class="as-head-badge">last 14 months</span></div>`)
	b.WriteString(`<div class="as-contributions__wrap">`)
	b.WriteString(monthRowHTML())
	b.WriteString(`<div class="as-contributions__grid">`)
	for _, row := range rows {
		b.WriteString(`<div class="as-contributions__row">`)
		fmt.Fprintf(&b, `<span class="as-contributions__abbr" title="%s">%s</span>`, esc(row.name), esc(row.abbrs))
		fmt.Fprintf(&b, `<span class="as-contributions__name">%s</span>`, esc(row.name))
		b.WriteString(`<div class="as-contributions__weeks">`)
		for i := 0; i < nWeeks; i++ {
			lv := level(row.weekly[i], row.anomaly[i])
			wkStart := weekDate(i)
			wkEnd := weekDate(i).AddDate(0, 0, 6)
			cnt := row.weekly[i]
			dateRange := wkStart.Format("2 Jan") + "–" + wkEnd.Format("2 Jan 2006")
			tip := fmt.Sprintf("%s · %d commit", dateRange, cnt)
			if cnt != 1 {
				tip += "s"
			}
			if row.anomaly[i] {
				tip += " (!)"
			}
			anomalyAttr := ""
			if row.anomaly[i] {
				anomalyAttr = ` data-anomaly="1"`
			}
			fmt.Fprintf(&b, `<span class="as-contributions__cell" data-level="%d" data-tip="%s"%s></span>`,
				lv, esc(tip), anomalyAttr)
		}
		b.WriteString(`</div></div>`)
	}
	b.WriteString(`</div>`) // end grid
	b.WriteString(monthRowHTML())

	// Vertical separator lines at month boundaries, anchored to .as-contributions__wrap.
	cumWeeks := 0
	for k, ms := range months {
		cumWeeks += ms.weeks
		if k == len(months)-1 {
			break
		}
		lineX := padPx + cumWeeks*(cellPx+gapPx)
		fmt.Fprintf(&b, `<div class="as-contrib-line" style="left:%dpx"></div>`, lineX)
	}

	b.WriteString(`</div>`) // end wrap
	b.WriteString(`</div>`) // end card
	return b.String()
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
	catSets := techCategorySets(res)

	var b strings.Builder
	b.WriteString(`<div class="as-section"><div class="as-section__head"><span class="ico">🧰</span><h2>Tech Stack &amp; Modules</h2></div>`)

	// Languages row.
	if len(langSet) > 0 {
		b.WriteString(`<div class="as-sub">🔤 Languages</div><div class="as-tagcloud">`)
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
	fmt.Fprintf(&b, `<div class="as-sub" style="margin-top:16px">📦 Packages &amp; modules <span style="color:var(--text-faint);font-weight:400;text-transform:none;letter-spacing:0">(%d)</span></div>`, len(list))
	if len(list) == 0 {
		b.WriteString(`<p class="as-empty">No modules detected.</p>`)
	} else {
		b.WriteString(`<div class="as-pkggrid">`)
		for _, a := range list {
			name := a.name
			if name == "" {
				name = "(root)"
			}
			// The click-to-scroll target only exists when the Modules &
			// Microservices section is actually rendered; without
			// --render-modules these are plain, non-clickable chips.
			if !res.Scan.RenderModules {
				fmt.Fprintf(&b,
					`<div class="as-pkg">`+
						`<span class="as-pkg__name">%s %s</span>`+
						`<span class="as-pkg__meta"><span class="as-pkg__loc">%s loc</span></span>`+
						`</div>`,
					shortLangBadge(a.plat), esc(name), fmtNum(a.loc))
				continue
			}
			fmt.Fprintf(&b,
				`<div class="as-pkg as-pkg--link" data-mod="%s" style="cursor:pointer" title="Open in Modules &amp; Microservices">`+
					`<span class="as-pkg__name">%s %s</span>`+
					`<span class="as-pkg__meta"><span class="as-pkg__loc">%s loc</span></span>`+
					`</div>`,
				esc(anchorID(a.name)), shortLangBadge(a.plat), esc(name), fmtNum(a.loc))
		}
		b.WriteString(`</div>`)
	}

	b.WriteString(`</div>`)
	return b.String()
}

// techCategorySets classifies detected frameworks / technologies into the
// five stack categories. Shared by the Tech Stack card and the Technical
// Radar section.
func techCategorySets(res *result.AnalysisResult) map[string]map[string]bool {
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
	return catSets
}

// ── ☁️ DevOps (own top-level card) ──────────────────────────────────────────

// renderDevOpsSection renders the standalone DevOps card: detected tool chips
// plus a compact static-analysis matrix (Hadolint/Dockle/KubeLinter-style
// metrics) for Dockerfiles, Helm charts, and docker-compose files.
func renderDevOpsSection(res *result.AnalysisResult) string {
	lint := res.DevOpsLint
	k8s := res.K8sLint
	// A single lone Dockerfile with nothing else (no compose, no Helm) isn't
	// enough evidence of a real DevOps setup to display or score — could just
	// be a throwaway dev container. Downstream, treat lint as absent.
	if !lint.HasEnoughSignal() {
		lint = nil
	}
	if len(res.DevOpsTools) == 0 && lint.Empty() && k8s.Empty() {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="as-section"><div class="as-section__head"><span class="ico">☁️</span><h2>DevOps</h2>`)
	if score, ok := lint.Score(); ok {
		fmt.Fprintf(&b, `<span class="as-dvo-score as-dvo-score--%s" title="Static-analysis hygiene score (pass=1, warn=½, fail=0)">%d%%</span>`, dvoScoreClass(score), score)
	}
	b.WriteString(`</div>`)

	// Detected tools chips.
	if len(res.DevOpsTools) > 0 {
		b.WriteString(`<div class="arch-components">`)
		for _, t := range res.DevOpsTools {
			fmt.Fprintf(&b, `<span class="arch-component"><span class="comp-icon">%s</span><span>%s</span></span>`, t.Icon, esc(t.Name))
		}
		b.WriteString(`</div>`)
	}

	// Compliance radar, defect-density, and health-score charts.
	if !lint.Empty() || !k8s.Empty() {
		b.WriteString(renderDevOpsCharts(lint, k8s))
	}

	// Compact static-analysis matrix.
	if !lint.Empty() {
		b.WriteString(`<div class="as-sub" style="margin-top:14px">🔬 Static Analysis <span style="color:var(--text-faint);font-weight:400;text-transform:none;letter-spacing:0">(Hadolint · Dockle · KubeLinter · Checkov-style checks)</span></div>`)
		b.WriteString(`<div class="as-dvo-grid">`)
		for _, a := range []*scanner.DevOpsArtifactLint{lint.Dockerfiles, lint.Helm, lint.Compose} {
			if a == nil {
				continue
			}
			b.WriteString(renderDevOpsColumn(a))
		}
		b.WriteString(`</div>`)
	}

	b.WriteString(`</div>`)
	return b.String()
}

// dvoScoreClass grades a 0-100 pass-rate score into the good/warn/crit
// palette shared by the DevOps score badges.
func dvoScoreClass(score int) string {
	switch {
	case score >= 75:
		return "good"
	case score >= 50:
		return "warn"
	default:
		return "crit"
	}
}

// devopsDocLink is one reference source for a static-analysis check (the
// tool/rule that inspired it, e.g. "Hadolint DL3006") plus its docs URL.
type devopsDocLink struct {
	Label string
	URL   string
}

// devopsDocLinks maps a DevOpsCheck.Metric to the docs it was modeled after.
// A check may cite more than one source (e.g. both Hadolint and Dockle catch
// the same non-root-USER practice); the first is rendered as the metric's own
// link, any further ones as small secondary references underneath.
var devopsDocLinks = map[string][]devopsDocLink{
	// 🐳 Dockerfile — Hadolint / Dockle / Checkov / Docker docs
	"Pinned digest (no :latest)": {
		{"Hadolint DL3006", "https://github.com/hadolint/hadolint/wiki/DL3006"},
		{"Docker best practice: FROM", "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#from"},
	},
	"Base image CVE count": {{"Trivy / Docker Scout", "https://docs.docker.com/scout/"}},
	"RUN instructions":     {{"Docker best practice: minimize layers", "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#minimize-the-number-of-layers"}},
	"ADD instead of COPY":  {{"Hadolint DL3020", "https://github.com/hadolint/hadolint/wiki/DL3020"}},
	"HEALTHCHECK present":  {{"Hadolint DL3018", "https://github.com/hadolint/hadolint/wiki/DL3018"}},
	"Secrets in ARG/ENV":   {{"Checkov CKV_DOCKER_5", "https://docs.bridgecrew.io/docs/ensure-that-build-arguments-do-not-contain-secrets"}},
	"Non-root USER": {
		{"Hadolint DL3002", "https://github.com/hadolint/hadolint/wiki/DL3002"},
		{"Dockle CIS-DI-0001", "https://github.com/goodwithtech/dockle#CIS-DI-0001"},
	},
	"Numeric UID":                {{"Checkov CKV_DOCKER_7", "https://docs.bridgecrew.io/docs/ensure-that-the-user-instruction-sets-a-non-root-user"}},
	"chmod 777 / world-writable": {{"Checkov CKV_DOCKER_8", "https://docs.bridgecrew.io/docs/ensure-that-files-and-directories-are-not-world-writable"}},
	"COPY --chown set": {
		{"Dockle DKL-DI-0002", "https://github.com/goodwithtech/dockle#DKL-DI-0002"},
		{"Docker best practice: --chown", "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy"},
	},
	"Absolute WORKDIR":            {{"Hadolint DL3000", "https://github.com/hadolint/hadolint/wiki/DL3000"}},
	"Privileged ports (<1024)":    {{"CIS Docker Benchmark", "https://www.cisecurity.org/benchmark/docker"}},
	"Multi-stage build":           {{"Docker best practice: multi-stage builds", "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#use-multi-stage-builds"}},
	"apt --no-install-recommends": {{"Hadolint DL3015", "https://github.com/hadolint/hadolint/wiki/DL3015"}},
	"apk --no-cache":              {{"Hadolint DL3019", "https://github.com/hadolint/hadolint/wiki/DL3019"}},
	"curl | sh pipes":             {{"Hadolint DL4006", "https://github.com/hadolint/hadolint/wiki/DL4006"}},
	"OCI LABELs present":          {{"Checkov CKV_DOCKER_15", "https://docs.bridgecrew.io/docs/ensure-that-the-image-has-oci-labels"}},

	// ⛵ Helm Chart — Helm best practices / KubeLinter / Checkov / Kubernetes docs
	"Chart.yaml required fields":  {{"Helm: Chart.yaml", "https://helm.sh/docs/topics/charts/#the-chartyaml-file"}},
	"values.schema.json":          {{"Helm: schema files", "https://helm.sh/docs/topics/charts/#schema-files"}},
	"Maintainers & icon metadata": {{"Helm: Chart.yaml fields", "https://helm.sh/docs/topics/charts/#the-chartyaml-file"}},
	"Deprecated K8s API versions": {
		{"KubeLinter no-extensions-v1beta", "https://docs.kubelinter.io/#/generated/checks?id=no-extensions-v1beta"},
		{"Kubernetes: deprecation guide", "https://kubernetes.io/docs/reference/using-api/deprecation-guide/"},
	},
	"Hardcoded namespace":        {{"Helm best practice: templates", "https://helm.sh/docs/chart_best_practices/templates/#namespaces"}},
	"resources.requests defined": {{"Kubernetes: managing resources", "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"}},
	"resources.limits defined": {
		{"KubeLinter unset-cpu-requirements", "https://docs.kubelinter.io/#/generated/checks?id=unset-cpu-requirements"},
		{"KubeLinter unset-memory-requirements", "https://docs.kubelinter.io/#/generated/checks?id=unset-memory-requirements"},
	},
	"runAsNonRoot enforced":  {{"KubeLinter run-as-non-root", "https://docs.kubelinter.io/#/generated/checks?id=run-as-non-root"}},
	"readOnlyRootFilesystem": {{"KubeLinter no-read-only-root-fs", "https://docs.kubelinter.io/#/generated/checks?id=no-read-only-root-fs"}},
	"allowPrivilegeEscalation: false": {
		{"KubeLinter privilege-escalation-container", "https://docs.kubelinter.io/#/generated/checks?id=privilege-escalation-container"},
	},
	"Privileged containers":        {{"KubeLinter privileged-container", "https://docs.kubelinter.io/#/generated/checks?id=privileged-container"}},
	"Dangerous capabilities added": {{"Kubernetes: Pod Security Standards", "https://kubernetes.io/docs/concepts/security/pod-security-standards/"}},
	"seccompProfile set":           {{"Kubernetes: seccomp", "https://kubernetes.io/docs/tutorials/security/seccomp/"}},
	"NetworkPolicy defined":        {{"KubeLinter non-isolated-pod", "https://docs.kubelinter.io/#/generated/checks?id=non-isolated-pod"}},
	"LoadBalancer services":        {{"Kubernetes: Service types", "https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer"}},
	"Ingress TLS configured":       {{"Kubernetes: Ingress TLS", "https://kubernetes.io/docs/concepts/services-networking/ingress/#tls"}},
	"PodDisruptionBudget defined":  {{"Kubernetes: PDB", "https://kubernetes.io/docs/tasks/run-application/configure-pdb/"}},
	"emptyDir sizeLimit":           {{"Kubernetes: emptyDir", "https://kubernetes.io/docs/concepts/storage/volumes/#emptydir"}},
	"Dedicated serviceAccountName": {{"Kubernetes: Service Accounts", "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/"}},
	"Wildcard ClusterRole rules":   {{"KubeLinter wildcard-in-rules", "https://docs.kubelinter.io/#/generated/checks?id=wildcard-in-rules"}},
	"Signed chart (*.prov)":        {{"Helm Provenance", "https://helm.sh/docs/topics/provenance/"}},
	"values.yaml documentation":    {{"Helm best practice: document values", "https://helm.sh/docs/chart_best_practices/values/#document-each-value"}},

	// ☸️ Kubernetes — kube-linter / Kubernetes docs
	"CPU/memory requests set": {{"Kubernetes: managing resources", "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"}},
	"CPU/memory limits set": {
		{"KubeLinter unset-cpu-requirements", "https://docs.kubelinter.io/#/generated/checks?id=unset-cpu-requirements"},
		{"KubeLinter unset-memory-requirements", "https://docs.kubelinter.io/#/generated/checks?id=unset-memory-requirements"},
	},
	"Privileged container": {{"KubeLinter privileged-container", "https://docs.kubelinter.io/#/generated/checks?id=privileged-container"}},
	"Liveness probe configured": {
		{"KubeLinter no-liveness-probe", "https://docs.kubelinter.io/#/generated/checks?id=no-liveness-probe"},
		{"Kubernetes: liveness probes", "https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/"},
	},
	"Readiness probe configured": {
		{"KubeLinter no-readiness-probe", "https://docs.kubelinter.io/#/generated/checks?id=no-readiness-probe"},
		{"Kubernetes: readiness probes", "https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/"},
	},
	"Pinned image tag (no :latest)": {
		{"KubeLinter latest-tag", "https://docs.kubelinter.io/#/generated/checks?id=latest-tag"},
		{"Hadolint DL3006", "https://github.com/hadolint/hadolint/wiki/DL3006"},
	},
	"hostNetwork/hostPID/hostIPC": {{"KubeLinter host-network / host-ipc / host-pid", "https://docs.kubelinter.io/#/generated/checks?id=host-network"}},
	"Dedicated service account":   {{"KubeLinter default-service-account", "https://docs.kubelinter.io/#/generated/checks?id=default-service-account"}},
	"hostPath volumes mounted":    {{"KubeLinter sensitive-host-mounts", "https://docs.kubelinter.io/#/generated/checks?id=sensitive-host-mounts"}},

	// 🐙 Docker Compose — Compose Spec / Docker docs
	"Obsolete compose version":  {{"Compose Spec: version (deprecated)", "https://docs.docker.com/compose/compose-file/#version-top-level-element"}},
	"privileged: true services": {{"Compose file reference: privileged", "https://docs.docker.com/compose/compose-file/#privileged"}},
	"Dangerous cap_add":         {{"Compose file reference: cap_add", "https://docs.docker.com/compose/compose-file/#cap_add-cap_drop"}},
	"docker.sock mounted":       {{"Checkov: docker socket", "https://docs.bridgecrew.io/docs/ensure-docker-socket-is-not-mounted-inside-any-containers"}},
	"Secrets in environment":    {{"Compose: environment variables", "https://docs.docker.com/compose/environment-variables/"}},
	"deploy.resources.limits":   {{"Compose deploy: resources", "https://docs.docker.com/compose/compose-file/#deploy"}},
	"restart: always usage":     {{"Compose: restart", "https://docs.docker.com/compose/compose-file/#restart"}},
	"Ports on 0.0.0.0":          {{"Compose: ports (long syntax)", "https://docs.docker.com/compose/compose-file/#ports"}},
	"Custom networks defined":   {{"Compose: networks", "https://docs.docker.com/compose/compose-file/#networks"}},
}

func renderDevOpsColumn(a *scanner.DevOpsArtifactLint) string {
	var b strings.Builder
	b.WriteString(`<div class="as-dvo-col">`)
	fmt.Fprintf(&b, `<div class="as-dvo-col__head">%s %s <span class="as-dvo-col__files" title="%s">%d file%s</span></div>`,
		a.Icon, esc(a.Kind), esc(strings.Join(a.Files, "\n")), len(a.Files), plural(len(a.Files), "", "s"))
	lastCat := ""
	for _, c := range a.Checks {
		if c.Category != lastCat {
			fmt.Fprintf(&b, `<div class="as-dvo-cat">%s</div>`, esc(c.Category))
			lastCat = c.Category
		}
		docs := devopsDocLinks[c.Metric]
		metricHTML := esc(c.Metric)
		if len(docs) > 0 {
			metricHTML = fmt.Sprintf(`<a class="as-dvo-m as-dvo-m--link" href="%s" target="_blank" rel="noopener" title="%s docs">%s</a>`,
				esc(docs[0].URL), esc(docs[0].Label), esc(c.Metric))
		} else {
			metricHTML = fmt.Sprintf(`<span class="as-dvo-m">%s</span>`, esc(c.Metric))
		}
		fmt.Fprintf(&b,
			`<div class="as-dvo-row"><span class="as-dvo-dot as-dvo-dot--%s"></span>%s<span class="as-dvo-v">%s</span></div>`,
			esc(c.Status), metricHTML, esc(c.Value))
		if len(docs) > 1 {
			for _, d := range docs[1:] {
				fmt.Fprintf(&b, `<div class="as-dvo-doc2">↳ <a href="%s" target="_blank" rel="noopener">%s</a></div>`,
					esc(d.URL), esc(d.Label))
			}
		}
	}
	b.WriteString(`</div>`)
	return b.String()
}

// ── ☸️ Kubernetes (DevOps sub-card) ─────────────────────────────────────

var k8sKindIcon = map[string]string{
	"Pod": "🔹", "Deployment": "🚀", "StatefulSet": "🗄️",
	"DaemonSet": "🛰️", "Job": "⏱️", "CronJob": "⏰",
}

// k8sMaxCardsPerKind caps how many workload cards are rendered per kind
// group — a cluster dump can contain hundreds of distinct workloads, and the
// report stays readable (and a reasonable file size) by showing only the
// biggest ones by resource footprint within each kind.
const k8sMaxCardsPerKind = 30

// k8sKindOrder fixes the display order of the per-kind subsections.
var k8sKindOrder = []string{"StatefulSet", "Pod", "DaemonSet", "Deployment", "Job", "CronJob"}

// renderInfraPlatforms renders the "🗄️ Infrastructure Platforms" section —
// one collapsible as-plat-card per detected K8sCluster, kept folded by
// default (unlike the language Platforms cards below it). It reuses the
// exact same accordion component/JS as those cards, so opening one closes
// any other open card — language or infrastructure — system-wide. Most
// repos have exactly one cluster (everything scanned merges together); a
// repo with several genuine "kubectl get everything" dumps gets one card
// per detected cluster (see k8sAnchorMinKinds in k8slint.go).
func renderInfraPlatforms(k8s *scanner.K8sLint) string {
	if k8s.Empty() {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div style="display:flex;align-items:center;justify-content:space-between;margin-top:16px;margin-bottom:8px">`)
	b.WriteString(`<span class="as-sub">🗄️ Infrastructure Platforms</span>`)
	b.WriteString(`</div>`)
	b.WriteString(`<div class="as-plat-cards" id="as-infra-platforms">`)
	for i, c := range k8s.Clusters {
		if len(c.Workloads) == 0 {
			continue
		}
		scoreSum := 0
		for _, w := range c.Workloads {
			scoreSum += w.Score
		}
		avg := scoreSum / len(c.Workloads)
		name := c.Name
		if name == "" {
			name = "Kubernetes"
		}

		fmt.Fprintf(&b, `<div class="as-plat-card" data-platcard="k%d">`, i)
		b.WriteString(`<div class="as-plat-card__head">`)
		b.WriteString(`<div class="as-plat-card__summary">`)
		b.WriteString(`<span class="as-plat-card__abbr as-plat-k8s">☸️</span>`)
		fmt.Fprintf(&b, `<span class="as-plat-card__name">%s</span>`, esc(name))
		fmt.Fprintf(&b, `<span class="as-plat-card__loc">%d workload%s</span>`, len(c.Workloads), plural(len(c.Workloads), "", "s"))
		fmt.Fprintf(&b, `<span class="as-plat-card__files">%d file%s</span>`, len(c.Files), plural(len(c.Files), "", "s"))
		fmt.Fprintf(&b, `<span class="as-plat-card__stat as-plat-card__stat--arch" title="Average check pass rate across %d workload(s) (pass=1, warn=½, fail=0)">%d%% PASSED</span>`, len(c.Workloads), avg)
		if n := len(c.ClusterFindings); n > 0 {
			fmt.Fprintf(&b, `<span class="as-plat-card__stat as-plat-card__stat--api">%d finding%s</span>`, n, plural(n, "", "s"))
		}
		b.WriteString(`</div>`) // .as-plat-card__summary
		b.WriteString(`<span class="as-plat-card__chevron">›</span>`)
		b.WriteString(`</div>`) // .as-plat-card__head

		b.WriteString(`<div class="as-plat-card__body">`)
		b.WriteString(renderK8sClusterCard(c))
		b.WriteString(`</div>`) // .as-plat-card__body
		b.WriteString(`</div>`) // .as-plat-card
	}
	b.WriteString(`</div>`) // .as-plat-cards
	return b.String()
}

// renderK8sClusterCard renders the full body for one detected K8sCluster: an
// overall pass-rate badge, then one subsection per workload kind (in
// k8sKindOrder, each titled with its icon and count), holding a responsive
// grid of small per-workload cards — sorted biggest resource footprint first
// and capped at k8sMaxCardsPerKind — each showing aggregate container
// resources and a kube-linter-inspired lint summary, followed by
// cross-cutting cluster findings and the Cluster Resources stat cards. This
// is the body of one 🗄️ Infrastructure Platforms card (renderInfraPlatforms).
func renderK8sClusterCard(c scanner.K8sCluster) string {
	scoreSum := 0
	byKind := map[string][]scanner.K8sWorkload{}
	for _, w := range c.Workloads {
		scoreSum += w.Score
		byKind[w.Kind] = append(byKind[w.Kind], w)
	}
	avg := scoreSum / len(c.Workloads)

	var b strings.Builder
	b.WriteString(`<div class="as-sub as-k8s-sub" style="margin-top:18px">`)
	b.WriteString(`<span>☸️ Kubernetes</span>`)
	fmt.Fprintf(&b, `<span class="as-dvo-score as-dvo-score--%s" title="Average check pass rate across %d workload(s) (pass=1, warn=½, fail=0)">%d%% PASSED</span>`,
		dvoScoreClass(avg), len(c.Workloads), avg)
	b.WriteString(`</div>`)

	fmt.Fprintf(&b, `<div class="as-section__sub" style="margin-top:2px">%d workload%s linted from %s — practices inspired by kube-linter (resource limits, security context, probes, image pinning, host access). Sorted by resource footprint (CPU + memory + storage), biggest first.</div>`,
		len(c.Workloads), plural(len(c.Workloads), "", "s"), esc(strings.Join(c.Files, ", ")))
	for _, kind := range k8sKindOrder {
		workloads := byKind[kind]
		if len(workloads) == 0 {
			continue
		}
		sort.Slice(workloads, func(i, j int) bool {
			return aggregateK8sResources(workloads[i]).footprint() > aggregateK8sResources(workloads[j]).footprint()
		})
		fmt.Fprintf(&b, `<div class="as-k8s-kind-sub">%s %s <span class="as-k8s-kind-count">(%d)</span></div>`,
			k8sKindIcon[kind], esc(kind), len(workloads))

		moreCount := 0
		if len(workloads) > k8sMaxCardsPerKind {
			moreCount = len(workloads) - k8sMaxCardsPerKind
			workloads = workloads[:k8sMaxCardsPerKind]
		}
		b.WriteString(`<div class="as-k8s-grid">`)
		for _, w := range workloads {
			b.WriteString(renderK8sWorkloadCard(w))
		}
		b.WriteString(`</div>`)
		if moreCount > 0 {
			fmt.Fprintf(&b, `<div class="as-more">+%d more %s%s not shown (showing the %d with the largest resource footprint)</div>`,
				moreCount, esc(kind), plural(moreCount, "", "s"), k8sMaxCardsPerKind)
		}
	}

	b.WriteString(renderK8sClusterFindings(c.ClusterFindings))
	b.WriteString(renderK8sClusterStats(c.Stats))
	return b.String()
}

// k8sCFGroup is a deduplicated cluster finding: one shared title/CWE header
// with all individual affected namespaces/resources listed underneath. The
// header shows the worst-case severity/tier/detail across its cases, since a
// single rule (e.g. "NetworkPolicy gap") commonly fires in several namespaces
// at different risk tiers.
type k8sCFGroup struct {
	RuleID   string
	Title    string
	Detail   string
	Severity string
	Tier     scanner.K8sNamespaceTier
	CWE      string
	Cases    []k8sCFCase
}
type k8sCFCase struct {
	Namespace string
	Kind      string
	Name      string
	Detail    string // this case's own Detail text, shown as a hover tooltip
	File      string // absolute path for VSCode deep link (may be empty)
	Line      int    // 1-based line within File; 0 = unknown
}

// k8sCFSevRank orders cluster-finding severities so the group header can show
// the worst case among its merged findings.
func k8sCFSevRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// renderK8sClusterFindings groups identical findings (same rule, across every
// namespace it fires in) into deduplicated cards shown in a two-column grid.
// Each card carries a mitre.org CWE link and per-case VSCode deep links when
// the source YAML path is known.
func renderK8sClusterFindings(findings []scanner.K8sClusterFinding) string {
	if len(findings) == 0 {
		return ""
	}

	// Group by (RuleID, Title) — same rule *and* same specific title (some
	// rules like k8s.secret_in_configmap embed the offending key name in the
	// title, so those stay distinct) firing across many namespaces is shown
	// once, with every namespace listed as a case underneath. This is what
	// collapses e.g. 7 separate "NetworkPolicy gap" cards (one per namespace)
	// into a single card listing all 7 namespaces as cases.
	type key struct{ ruleID, title string }
	order := []key{}
	groups := map[key]*k8sCFGroup{}
	for _, f := range findings {
		k := key{f.RuleID, f.Title}
		g, exists := groups[k]
		if !exists {
			g = &k8sCFGroup{
				RuleID:   f.RuleID,
				Title:    f.Title,
				Detail:   f.Detail,
				Severity: f.Severity,
				Tier:     f.Tier,
				CWE:      f.CWE,
			}
			groups[k] = g
			order = append(order, k)
		} else if k8sCFSevRank(f.Severity) > k8sCFSevRank(g.Severity) {
			// A later case is worse than what the header currently shows —
			// promote the header to reflect the worst case in the group.
			g.Detail = f.Detail
			g.Severity = f.Severity
			g.Tier = f.Tier
		}
		g.Cases = append(g.Cases, k8sCFCase{
			Namespace: f.Namespace, Kind: f.Kind, Name: f.Name,
			Detail: f.Detail, File: f.File, Line: f.Line,
		})
	}

	var b strings.Builder
	b.WriteString(`<div class="as-k8s-kind-sub" id="as-k8s-cf">⚠️ Weaknesses</div>`)
	b.WriteString(`<div class="as-k8s-cf-grid">`)

	for _, k := range order {
		g := groups[k]
		sevClass := "as-k8s-cf--" + g.Severity
		sevLabel := strings.ToUpper(g.Severity[:1]) + g.Severity[1:]

		// CWE badge — link to mitre.org when CWE is known.
		cweHTML := ""
		if g.CWE != "" {
			cweHTML = fmt.Sprintf(
				`<a class="as-k8s-cwe" href="https://cwe.mitre.org/data/definitions/%s.html" target="_blank" rel="noopener">CWE-%s ↗</a>`,
				esc(g.CWE), esc(g.CWE),
			)
		}

		// Tier badge.
		tierHTML := ""
		if g.Tier != "" {
			tierHTML = fmt.Sprintf(`<span class="as-k8s-tier">%s</span>`, esc(string(g.Tier)))
		}

		fmt.Fprintf(&b,
			`<div class="as-k8s-cf %s">`+
				`<div class="as-k8s-cf__head">`+
				`<span class="as-k8s-cf__sev">%s</span>`+
				`<span class="as-k8s-cf__title">%s</span>`+
				`<span class="as-k8s-cf__badges">%s%s</span>`+
				`</div>`+
				`<div class="as-k8s-cf__detail">%s</div>`,
			sevClass,
			esc(sevLabel), esc(g.Title), tierHTML, cweHTML,
			esc(g.Detail),
		)

		// Cases list — one chip per affected namespace/resource, with the
		// original per-case detail as a native tooltip.
		if len(g.Cases) > 0 {
			b.WriteString(`<div class="as-k8s-cf__cases">`)
			for _, c := range g.Cases {
				ns := c.Namespace
				if ns == "" {
					ns = "cluster"
				}
				label := ns + " / " + c.Kind
				if c.Name != "" {
					label += " " + c.Name
				}
				lineLabel := ""
				if c.Line > 0 {
					lineLabel = fmt.Sprintf(" :%d", c.Line)
				}
				href := vscodeHref(c.File, c.Line)
				if href != "" {
					fmt.Fprintf(&b,
						`<a class="as-k8s-cf__case" href="%s" title="%s">%s<span class="as-k8s-cf__line">%s</span></a>`,
						esc(href), esc(c.Detail), esc(label), esc(lineLabel),
					)
				} else {
					fmt.Fprintf(&b,
						`<span class="as-k8s-cf__case" title="%s">%s<span class="as-k8s-cf__line">%s</span></span>`,
						esc(c.Detail), esc(label), esc(lineLabel),
					)
				}
			}
			b.WriteString(`</div>`)
		}

		b.WriteString(`</div>`) // close as-k8s-cf
	}

	b.WriteString(`</div>`) // close as-k8s-cf-grid
	return b.String()
}

// k8sStatRow is one line item within a cluster-stats sub-card: a label, a
// display value, and an optional pass/warn/fail dot when the number itself
// is the finding (e.g. zero NetworkPolicies). Status "" renders a blank
// placeholder dot so labels stay aligned against rows that do have one.
type k8sStatRow struct {
	Label  string
	Value  string
	Status string // "", "pass", "warn", "fail"
}

func renderK8sStatCard(icon, title string, rows []k8sStatRow) string {
	if len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="as-k8s-stat-card">`)
	fmt.Fprintf(&b, `<div class="as-k8s-stat-card__head">%s %s</div>`, icon, esc(title))
	for _, r := range rows {
		dotClass := "as-k8s-dot--none"
		if r.Status != "" {
			dotClass = "as-k8s-dot--" + r.Status
		}
		fmt.Fprintf(&b, `<div class="as-k8s-stat-row"><span class="as-k8s-dot %s"></span><span class="as-k8s-stat-label">%s</span><span class="as-k8s-stat-val">%s</span></div>`,
			dotClass, esc(r.Label), esc(r.Value))
	}
	b.WriteString(`</div>`)
	return b.String()
}

func fallback(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func passWarn(good bool) string {
	if good {
		return "pass"
	}
	return "warn"
}

// renderK8sClusterStats renders the informational sub-cards that continue
// the ☸️ Kubernetes card past the workload grid — Networking & Exposure,
// Configuration & Storage, RBAC & Service Accounts, Autoscaling & Budgets,
// and Operators — summarizing the non-workload resources found alongside
// the linted Pods/Deployments/etc. Each card is omitted when its category
// has nothing to show, and the whole block is omitted when none do.
func renderK8sClusterStats(s scanner.K8sClusterStats) string {
	if s.Empty() {
		return ""
	}
	var cards []string

	if s.Services > 0 || s.Ingresses > 0 || s.NetworkPolicies > 0 {
		var rows []k8sStatRow
		if s.Services > 0 {
			rows = append(rows, k8sStatRow{"Services", strconv.Itoa(s.Services), ""})
			rows = append(rows, k8sStatRow{"Privileged ports (<1024)", strconv.Itoa(s.ServicesPrivPorts), passWarn(s.ServicesPrivPorts == 0)})
		}
		if s.Ingresses > 0 {
			rows = append(rows, k8sStatRow{"Ingresses", strconv.Itoa(s.Ingresses), ""})
			rows = append(rows, k8sStatRow{"...with TLS configured", fmt.Sprintf("%d/%d", s.IngressesTLS, s.Ingresses), passWarn(s.IngressesTLS == s.Ingresses)})
		}
		rows = append(rows, k8sStatRow{"NetworkPolicies", strconv.Itoa(s.NetworkPolicies), passWarn(s.NetworkPolicies > 0)})
		cards = append(cards, renderK8sStatCard("🌐", "Networking & Exposure", rows))
	}

	if s.ConfigMaps > 0 || s.PVCs > 0 || s.StorageClasses > 0 {
		var rows []k8sStatRow
		if s.ConfigMaps > 0 {
			rows = append(rows, k8sStatRow{"ConfigMaps (custom)", strconv.Itoa(s.ConfigMaps), ""})
		}
		if s.PVCs > 0 {
			rows = append(rows, k8sStatRow{"PersistentVolumeClaims", strconv.Itoa(s.PVCs), ""})
			rows = append(rows, k8sStatRow{"...with a StorageClass", fmt.Sprintf("%d/%d", s.PVCsWithStorageClass, s.PVCs), passWarn(s.PVCsWithStorageClass == s.PVCs)})
		}
		if s.StorageClasses > 0 {
			rows = append(rows, k8sStatRow{"StorageClasses", strconv.Itoa(s.StorageClasses), ""})
		}
		cards = append(cards, renderK8sStatCard("🗄️", "Configuration & Storage", rows))
	}

	if s.ServiceAccounts > 0 || s.Roles > 0 || s.RoleBindings > 0 || s.ClusterRoles > 0 || s.ClusterRoleBindings > 0 {
		var rows []k8sStatRow
		if s.ServiceAccounts > 0 {
			rows = append(rows, k8sStatRow{"ServiceAccounts (custom)", strconv.Itoa(s.ServiceAccounts), ""})
		}
		if s.Roles > 0 {
			rows = append(rows, k8sStatRow{"Roles", strconv.Itoa(s.Roles), ""})
			rows = append(rows, k8sStatRow{"...with wildcard rules", strconv.Itoa(s.RolesWildcard), passWarn(s.RolesWildcard == 0)})
		}
		if s.RoleBindings > 0 {
			rows = append(rows, k8sStatRow{"RoleBindings", strconv.Itoa(s.RoleBindings), ""})
		}
		if s.ClusterRoles > 0 {
			rows = append(rows, k8sStatRow{"ClusterRoles", strconv.Itoa(s.ClusterRoles), ""})
			rows = append(rows, k8sStatRow{"...with wildcard rules", strconv.Itoa(s.ClusterRolesWildcard), passWarn(s.ClusterRolesWildcard == 0)})
		}
		if s.ClusterRoleBindings > 0 {
			rows = append(rows, k8sStatRow{"ClusterRoleBindings", strconv.Itoa(s.ClusterRoleBindings), ""})
			if s.ClusterAdminBindings > 0 {
				rows = append(rows, k8sStatRow{"...custom SA to cluster-admin", strconv.Itoa(s.ClusterAdminBindings), passWarn(s.ClusterAdminBindings == 0)})
			}
		}
		cards = append(cards, renderK8sStatCard("🔐", "RBAC & Service Accounts", rows))
	}

	if s.HPAs > 0 || s.PDBs > 0 {
		rows := []k8sStatRow{
			{"HorizontalPodAutoscalers", strconv.Itoa(s.HPAs), passWarn(s.HPAs > 0)},
			{"PodDisruptionBudgets", strconv.Itoa(s.PDBs), passWarn(s.PDBs > 0)},
		}
		cards = append(cards, renderK8sStatCard("📈", "Autoscaling & Budgets", rows))
	}

	if len(s.Operators) > 0 {
		ops := append([]scanner.K8sOperatorResource(nil), s.Operators...)
		sort.Slice(ops, func(i, j int) bool { return ops[i].Kind < ops[j].Kind })
		var rows []k8sStatRow
		for _, op := range ops {
			val := strconv.Itoa(op.Count)
			if op.HasAvailableReplicas {
				val = fmt.Sprintf("%d (%d avail. replica%s)", op.Count, op.AvailableReplicas, plural(op.AvailableReplicas, "", "s"))
			}
			rows = append(rows, k8sStatRow{op.Kind, val, ""})
		}
		cards = append(cards, renderK8sStatCard("🧩", "Operators", rows))
	}

	if len(cards) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="as-k8s-kind-sub">📊 Cluster Resources</div>`)
	b.WriteString(`<div class="as-k8s-stats-grid">`)
	for _, c := range cards {
		b.WriteString(c)
	}
	b.WriteString(`</div>`)
	b.WriteString(renderK8sIngressDetail(s.IngressDetails))
	b.WriteString(renderK8sServiceDetail(s.ServiceDetails))
	return b.String()
}

// k8sMaxIngressCards/k8sMaxServiceCards cap how many Ingress/Service detail
// cards are rendered — same "biggest report, still readable" rationale as
// k8sMaxCardsPerKind. Services get a much higher ceiling since a dump
// legitimately has far more Services than Ingresses.
const (
	k8sMaxIngressCards = 40
	k8sMaxServiceCards = 150
)

// splitBackendPort splits a "service:port" backend string (as built by
// ingressBackend) into the service name and a ":port" suffix (empty if the
// backend has no port), so the port can be highlighted separately.
func splitBackendPort(backend string) (name, port string) {
	if idx := strings.LastIndex(backend, ":"); idx >= 0 {
		return backend[:idx], backend[idx:]
	}
	return backend, ""
}

// renderK8sIngressDetail renders one two-column card per Ingress — host,
// path, backend, TLS secret, and (best-effort) proxy timeout — the
// per-object detail the aggregate "N Ingresses, X/Y TLS" counts can't show.
func renderK8sIngressDetail(details []scanner.K8sIngressDetail) string {
	if len(details) == 0 {
		return ""
	}
	items := append([]scanner.K8sIngressDetail(nil), details...)
	sort.Slice(items, func(i, j int) bool {
		if items[i].Namespace != items[j].Namespace {
			return items[i].Namespace < items[j].Namespace
		}
		return items[i].Name < items[j].Name
	})
	moreCount := 0
	if len(items) > k8sMaxIngressCards {
		moreCount = len(items) - k8sMaxIngressCards
		items = items[:k8sMaxIngressCards]
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<div class="as-k8s-kind-sub">🚪 Ingresses <span class="as-k8s-kind-count">(%d)</span></div>`, len(details))
	b.WriteString(`<div class="as-k8s-detail-grid">`)
	for _, d := range items {
		b.WriteString(renderK8sIngressCard(d))
	}
	b.WriteString(`</div>`)
	if moreCount > 0 {
		fmt.Fprintf(&b, `<div class="as-more">+%d more Ingress%s not shown</div>`, moreCount, plural(moreCount, "", "es"))
	}
	return b.String()
}

func renderK8sIngressCard(d scanner.K8sIngressDetail) string {
	var b strings.Builder
	b.WriteString(`<div class="as-k8s-detail-card">`)
	fmt.Fprintf(&b, `<div class="as-k8s-detail-card__head">%s<span class="as-k8s-detail-card__ns">%s</span></div>`, esc(d.Name), esc(d.Namespace))
	if len(d.Rules) == 0 {
		b.WriteString(`<div class="as-k8s-detail-row as-k8s-detail-row--muted">no rules</div>`)
	}
	for _, r := range d.Rules {
		host := fallback(r.Host, "*")
		path := fallback(r.Path, "/")
		svcName, svcPort := splitBackendPort(fallback(r.Backend, "–"))
		portHTML := ""
		if svcPort != "" {
			portHTML = fmt.Sprintf(`<span class="as-k8s-detail-port">%s</span>`, esc(svcPort))
		}
		fmt.Fprintf(&b, `<div class="as-k8s-detail-row"><span class="as-k8s-detail-mono as-k8s-detail-mono--src">%s%s</span><span class="as-k8s-detail-arrow">→</span><span class="as-k8s-detail-mono as-k8s-detail-mono--dst">%s%s</span></div>`,
			esc(host), esc(path), esc(svcName), portHTML)
	}
	// Each entry is pre-escaped HTML, not plain text — the timeout entries
	// carry a label/value span pair with their own colors, so the whole
	// line can't be joined-then-escaped as one string.
	var meta []string
	switch {
	case len(d.TLSSecrets) > 0:
		meta = append(meta, "TLS: "+esc(strings.Join(d.TLSSecrets, ", ")))
	case d.TLS:
		meta = append(meta, "TLS: yes")
	default:
		meta = append(meta, "TLS: no")
	}
	for _, t := range d.Timeouts {
		meta = append(meta, fmt.Sprintf(`<span class="as-k8s-detail-meta-label">%s</span> <span class="as-k8s-detail-port">%s</span>`, esc(t.Label), esc(t.Value)))
	}
	if d.IngressClass != "" {
		meta = append(meta, "class: "+esc(d.IngressClass))
	}
	fmt.Fprintf(&b, `<div class="as-k8s-detail-meta">%s</div>`, strings.Join(meta, " · "))
	b.WriteString(`</div>`)
	return b.String()
}

// renderK8sServiceDetail renders one two-column card per Service — type and
// port→targetPort mappings.
func renderK8sServiceDetail(details []scanner.K8sServiceDetail) string {
	if len(details) == 0 {
		return ""
	}
	items := append([]scanner.K8sServiceDetail(nil), details...)
	sort.Slice(items, func(i, j int) bool {
		if items[i].Namespace != items[j].Namespace {
			return items[i].Namespace < items[j].Namespace
		}
		return items[i].Name < items[j].Name
	})
	moreCount := 0
	if len(items) > k8sMaxServiceCards {
		moreCount = len(items) - k8sMaxServiceCards
		items = items[:k8sMaxServiceCards]
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<div class="as-k8s-kind-sub">🔌 Services <span class="as-k8s-kind-count">(%d)</span></div>`, len(details))
	b.WriteString(`<div class="as-k8s-detail-grid as-k8s-detail-grid--3col">`)
	for _, d := range items {
		b.WriteString(renderK8sServiceCard(d))
	}
	b.WriteString(`</div>`)
	if moreCount > 0 {
		fmt.Fprintf(&b, `<div class="as-more">+%d more Service%s not shown</div>`, moreCount, plural(moreCount, "", "s"))
	}
	return b.String()
}

func renderK8sServiceCard(d scanner.K8sServiceDetail) string {
	var b strings.Builder
	b.WriteString(`<div class="as-k8s-detail-card">`)
	fmt.Fprintf(&b, `<div class="as-k8s-detail-card__head">%s<span class="as-k8s-detail-card__ns">%s</span></div>`, esc(d.Name), esc(d.Namespace))
	fmt.Fprintf(&b, `<div class="as-k8s-detail-row as-k8s-detail-row--muted">%s</div>`, esc(d.Type))
	if len(d.Ports) == 0 {
		b.WriteString(`<div class="as-k8s-detail-row as-k8s-detail-row--muted">no ports</div>`)
	}
	for _, p := range d.Ports {
		label := fallback(p.Name, p.Protocol)
		target := fallback(p.TargetPort, p.Port)
		fmt.Fprintf(&b, `<div class="as-k8s-detail-row"><span class="as-k8s-detail-mono as-k8s-detail-mono--src">%s %s</span><span class="as-k8s-detail-arrow">→</span><span class="as-k8s-detail-mono as-k8s-detail-mono--dst">%s</span></div>`,
			esc(label), esc(p.Port), esc(target))
	}
	b.WriteString(`</div>`)
	return b.String()
}

// k8sResAgg is a workload's container resources summed across all of its
// containers, request and limit tracked separately.
type k8sResAgg struct {
	cpuReq, cpuLim float64 // millicores
	memReq, memLim float64 // bytes
	stoReq, stoLim float64 // ephemeral-storage bytes
	hasCPUReq      bool
	hasCPULim      bool
	hasMemReq      bool
	hasMemLim      bool
	hasStoReq      bool
	hasStoLim      bool
}

func aggregateK8sResources(w scanner.K8sWorkload) k8sResAgg {
	var a k8sResAgg
	for _, c := range w.Containers {
		if v, ok := parseCPUMillis(c.CPURequest); ok {
			a.cpuReq += v
			a.hasCPUReq = true
		}
		if v, ok := parseCPUMillis(c.CPULimit); ok {
			a.cpuLim += v
			a.hasCPULim = true
		}
		if v, ok := parseMemBytes(c.MemRequest); ok {
			a.memReq += v
			a.hasMemReq = true
		}
		if v, ok := parseMemBytes(c.MemLimit); ok {
			a.memLim += v
			a.hasMemLim = true
		}
		if v, ok := parseMemBytes(c.StorageReq); ok {
			a.stoReq += v
			a.hasStoReq = true
		}
		if v, ok := parseMemBytes(c.StorageLim); ok {
			a.stoLim += v
			a.hasStoLim = true
		}
	}
	return a
}

// footprint blends CPU (cores), memory (GiB), and storage (GiB) — each
// preferring the limit (the workload's real ceiling) and falling back to the
// request — into one comparable "how big is this workload" number used to
// rank cards biggest-first.
func (a k8sResAgg) footprint() float64 {
	cpu := a.cpuLim
	if cpu == 0 {
		cpu = a.cpuReq
	}
	mem := a.memLim
	if mem == 0 {
		mem = a.memReq
	}
	sto := a.stoLim
	if sto == 0 {
		sto = a.stoReq
	}
	const gib = 1024 * 1024 * 1024
	return cpu/1000 + mem/gib + sto/gib
}

func renderK8sWorkloadCard(w scanner.K8sWorkload) string {
	agg := aggregateK8sResources(w)
	fmtCPU := func(v float64, has bool) string {
		if !has {
			return "–"
		}
		return formatCPUMillis(v)
	}
	fmtMem := func(v float64, has bool) string {
		if !has {
			return "–"
		}
		return formatMemBytes(v)
	}

	type issue struct {
		label  string
		metric string
	}
	pass, warn, fail := 0, 0, 0
	var failed, warned []issue
	var failedLabels, warnedLabels []string
	for _, c := range w.Checks {
		label := c.Metric
		if c.Category != "Pod" {
			label = c.Category + ": " + c.Metric
		}
		switch c.Status {
		case "pass":
			pass++
		case "warn":
			warn++
			warned = append(warned, issue{label, c.Metric})
			warnedLabels = append(warnedLabels, label)
		case "fail":
			fail++
			failed = append(failed, issue{label, c.Metric})
			failedLabels = append(failedLabels, label)
		}
	}
	tooltip := fmt.Sprintf("%d passed · %d warned · %d failed", pass, warn, fail)
	if len(failedLabels) > 0 {
		tooltip += "\n\nFailed:\n- " + strings.Join(failedLabels, "\n- ")
	}
	if len(warnedLabels) > 0 {
		tooltip += "\n\nWarned:\n- " + strings.Join(warnedLabels, "\n- ")
	}

	icon := k8sKindIcon[w.Kind]
	if icon == "" {
		icon = "☸️"
	}
	replicaBadge := ""
	if w.Replicas > 1 {
		replicaBadge = fmt.Sprintf(`<span class="as-k8s-replicas">×%d</span>`, w.Replicas)
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<div class="as-k8s-card" style="border-left-color:%s">`, gradeColor(w.Score))
	fmt.Fprintf(&b, `<div class="as-k8s-card__head"><span title="%s: %s">%s %s</span>%s</div>`,
		esc(w.Kind), esc(w.Name), icon, esc(w.Name), replicaBadge)
	fmt.Fprintf(&b, `<div class="as-k8s-card__ns" title="%s">%s</div>`, esc(w.Namespace), esc(w.Namespace))
	fmt.Fprintf(&b, `<div class="as-k8s-card__res">`+
		`<div title="CPU request → limit"><span class="as-k8s-res-label">CPU</span><span class="as-k8s-res-val">%s→%s</span></div>`+
		`<div title="Memory request → limit"><span class="as-k8s-res-label">MEM</span><span class="as-k8s-res-val">%s→%s</span></div>`+
		`<div title="Ephemeral storage request → limit"><span class="as-k8s-res-label">DISK</span><span class="as-k8s-res-val">%s→%s</span></div>`+
		`</div>`,
		fmtCPU(agg.cpuReq, agg.hasCPUReq), fmtCPU(agg.cpuLim, agg.hasCPULim),
		fmtMem(agg.memReq, agg.hasMemReq), fmtMem(agg.memLim, agg.hasMemLim),
		fmtMem(agg.stoReq, agg.hasStoReq), fmtMem(agg.stoLim, agg.hasStoLim))
	fmt.Fprintf(&b, `<div class="as-k8s-card__lint" title="%s"><span class="as-k8s-dot as-k8s-dot--pass"></span>%d<span class="as-k8s-dot as-k8s-dot--warn"></span>%d<span class="as-k8s-dot as-k8s-dot--fail"></span>%d`+
		`<span class="as-k8s-card__score" style="color:%s">%d%%</span></div>`,
		esc(tooltip), pass, warn, fail, gradeColor(w.Score), w.Score)
	if len(failed) > 0 || len(warned) > 0 {
		b.WriteString(`<div class="as-k8s-card__issues">`)
		for _, iss := range failed {
			b.WriteString(renderK8sIssue(iss.label, iss.metric, "fail", "✕"))
		}
		for _, iss := range warned {
			b.WriteString(renderK8sIssue(iss.label, iss.metric, "warn", "⚠"))
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// renderK8sIssue renders one visible fail/warn line under a Kubernetes
// workload card, linking the check name to its kube-linter/Kubernetes/Checkov
// documentation when devopsDocLinks has an entry for the raw metric.
func renderK8sIssue(label, metric, variant, mark string) string {
	name := esc(label)
	if docs := devopsDocLinks[metric]; len(docs) > 0 {
		name = fmt.Sprintf(`<a href="%s" target="_blank" rel="noopener" title="%s docs">%s</a>`,
			esc(docs[0].URL), esc(docs[0].Label), esc(label))
	}
	return fmt.Sprintf(`<div class="as-k8s-issue--%s">%s %s</div>`, variant, mark, name)
}

func parseCPUMillis(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if strings.HasSuffix(s, "m") {
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, "m"), 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return n * 1000, true
}

func formatCPUMillis(m float64) string {
	if m <= 0 {
		return "–"
	}
	mi := int64(m + 0.5)
	if mi < 1000 {
		return strconv.FormatInt(mi, 10) + "m"
	}
	cores := float64(mi) / 1000
	if cores == float64(int64(cores)) {
		return strconv.FormatInt(int64(cores), 10)
	}
	return strconv.FormatFloat(cores, 'f', 1, 64)
}

var k8sMemSuffixes = []struct {
	suffix string
	mult   float64
}{
	{"Ki", 1024}, {"Mi", 1024 * 1024}, {"Gi", 1024 * 1024 * 1024}, {"Ti", 1024 * 1024 * 1024 * 1024},
	{"K", 1000}, {"M", 1000 * 1000}, {"G", 1000 * 1000 * 1000}, {"T", 1000 * 1000 * 1000 * 1000},
}

func parseMemBytes(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	for _, u := range k8sMemSuffixes {
		if strings.HasSuffix(s, u.suffix) {
			n, err := strconv.ParseFloat(strings.TrimSuffix(s, u.suffix), 64)
			if err != nil {
				return 0, false
			}
			return n * u.mult, true
		}
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func formatMemBytes(b float64) string {
	switch {
	case b <= 0:
		return "–"
	case b >= 1024*1024*1024:
		return strconv.FormatFloat(b/(1024*1024*1024), 'f', 1, 64) + "Gi"
	case b >= 1024*1024:
		return strconv.FormatFloat(b/(1024*1024), 'f', 0, 64) + "Mi"
	case b >= 1024:
		return strconv.FormatFloat(b/1024, 'f', 0, 64) + "Ki"
	default:
		return strconv.FormatFloat(b, 'f', 0, 64)
	}
}

// ── ☁️ DevOps compliance charts (radar · defect density · health gauge) ─────

// devopsDomains are the six compliance domains scored by the radar chart.
var devopsDomains = [6]string{
	"Base Image Hygiene", "Build Best Practices", "Privilege & Isolation",
	"Runtime Security", "Resource Protection", "Network Exposure",
}

// devopsDomainAxisLines are the shortened, two-line-wrapped vertex labels
// drawn directly on the radar chart (SVG text has no auto-wrap, and the full
// devopsDomains names are too wide to sit on one line at the chart's scale).
var devopsDomainAxisLines = [6][2]string{
	{"Image", "Hygiene"},
	{"Best", "Practices"},
	{"Privilege &", "Isolation"},
	{"Runtime", "Security"},
	{"Resource", "Protection"},
	{"Network", "Exposure"},
}

// devopsDomainOf maps a "Kind::Category" check grouping onto a devopsDomains
// index, so checks from all three artifact kinds roll up into one shared set
// of domains.
var devopsDomainOf = map[string]int{
	"Dockerfile::Base Image Hygiene":        0,
	"Dockerfile::Build Best Practices":      1,
	"Dockerfile::Package Manager Hygiene":   1,
	"Dockerfile::Metadata & Labelling":      1,
	"Dockerfile::Image Size & Efficiency":   1,
	"Dockerfile::Privilege & Isolation":     2,
	"Dockerfile::File System & Permissions": 2,
	"Dockerfile::Network & Port Exposure":   5,

	"Docker Compose::Version & Syntax": 1,
	"Docker Compose::Security":         3,
	"Docker Compose::Resource Limits":  4,
	"Docker Compose::Network Hygiene":  5,

	"Helm Chart::Chart Structural Quality":    1,
	"Helm Chart::Template Correctness":        1,
	"Helm Chart::Values Best Practices":       1,
	"Helm Chart::Chart Provenance":            1,
	"Helm Chart::Resource Management":         4,
	"Helm Chart::Storage & Persistence":       4,
	"Helm Chart::Pod Disruption Budget":       4,
	"Helm Chart::Security Contexts":           3,
	"Helm Chart::RBAC & Service Accounts":     2,
	"Helm Chart::Network Policies & Exposure": 5,
}

// devopsSeverity classifies a check's Metric label for the defect-density
// chart and the health-score weighting. Metrics not listed default to
// "medium".
var devopsSeverity = map[string]string{
	// Critical — direct host-breakout or credential-exposure primitives.
	"Secrets in ARG/ENV":           "critical",
	"privileged: true services":    "critical",
	"Dangerous cap_add":            "critical",
	"docker.sock mounted":          "critical",
	"Secrets in environment":       "critical",
	"Privileged containers":        "critical",
	"Dangerous capabilities added": "critical",
	"Wildcard ClusterRole rules":   "critical",

	// High — privilege / supply-chain hygiene.
	"Pinned digest (no :latest)":      "high",
	"Non-root USER":                   "high",
	"Numeric UID":                     "high",
	"curl | sh pipes":                 "high",
	"chmod 777 / world-writable":      "high",
	"Deprecated K8s API versions":     "high",
	"runAsNonRoot enforced":           "high",
	"allowPrivilegeEscalation: false": "high",

	// Medium — build/runtime hardening practices.
	"RUN instructions":             "medium",
	"ADD instead of COPY":          "medium",
	"HEALTHCHECK present":          "medium",
	"Privileged ports (<1024)":     "medium",
	"deploy.resources.limits":      "medium",
	"Ports on 0.0.0.0":             "medium",
	"Hardcoded namespace":          "medium",
	"resources.requests defined":   "medium",
	"resources.limits defined":     "medium",
	"readOnlyRootFilesystem":       "medium",
	"seccompProfile set":           "medium",
	"NetworkPolicy defined":        "medium",
	"Ingress TLS configured":       "medium",
	"Dedicated serviceAccountName": "medium",

	// Low — cosmetic / documentation / efficiency.
	"COPY --chown set":            "low",
	"Absolute WORKDIR":            "low",
	"Multi-stage build":           "low",
	"Layers (RUN/COPY/ADD)":       "low",
	"apt --no-install-recommends": "low",
	"apk --no-cache":              "low",
	"OCI LABELs present":          "low",
	"Obsolete compose version":    "low",
	"restart: always usage":       "low",
	"Custom networks defined":     "low",
	"Chart.yaml required fields":  "low",
	"values.schema.json":          "low",
	"Maintainers & icon metadata": "low",
	"LoadBalancer services":       "low",
	"PodDisruptionBudget defined": "low",
	"emptyDir sizeLimit":          "low",
	"Signed chart (*.prov)":       "low",
	"values.yaml documentation":   "low",
}

func devopsSeverityOf(metric string) string {
	if s, ok := devopsSeverity[metric]; ok {
		return s
	}
	return "medium"
}

func devopsSeverityWeight(sev string) float64 {
	switch sev {
	case "critical":
		return 10
	case "high":
		return 5
	case "medium":
		return 2
	default:
		return 1
	}
}

// devopsComplianceDomains averages every evaluable check (pass=100, warn=50,
// fail=0; "na" excluded) into the six devopsDomains buckets. has[i] is false
// when no artifact contributed an evaluable check to that domain.
func devopsComplianceDomains(lint *scanner.DevOpsLint) (scores [6]int, has [6]bool) {
	if lint == nil {
		lint = &scanner.DevOpsLint{}
	}
	var pts, n [6]float64
	for _, a := range []*scanner.DevOpsArtifactLint{lint.Dockerfiles, lint.Compose, lint.Helm} {
		if a == nil {
			continue
		}
		for _, c := range a.Checks {
			d, ok := devopsDomainOf[a.Kind+"::"+c.Category]
			if !ok {
				continue
			}
			switch c.Status {
			case "pass":
				pts[d]++
				n[d]++
			case "warn":
				pts[d] += 0.5
				n[d]++
			case "fail":
				n[d]++
			}
		}
	}
	for i := range scores {
		if n[i] > 0 {
			scores[i] = int(pts[i]/n[i]*100 + 0.5)
			has[i] = true
		}
	}
	return
}

// k8sDefectKind is the synthetic artifact-kind label used to fold Kubernetes
// workload checks and cross-cutting Weaknesses into the DevOps defect-density
// and health-score charts alongside Dockerfile/Compose/Helm.
const k8sDefectKind = "Kubernetes"

var sevIdx = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

// devopsDefectCounts tallies non-passing (warn/fail) checks by artifact kind
// and severity, in [critical, high, medium, low] order. Kinds with zero
// violations are omitted from the returned order. Kubernetes workload checks
// and cross-cutting Weaknesses (NetworkPolicy gaps, RBAC over-grants, ...)
// are folded into a synthetic "Kubernetes" kind.
func devopsDefectCounts(lint *scanner.DevOpsLint, k8s *scanner.K8sLint) (order []string, counts map[string][4]int) {
	if lint == nil {
		lint = &scanner.DevOpsLint{}
	}
	counts = map[string][4]int{}
	for _, a := range []*scanner.DevOpsArtifactLint{lint.Dockerfiles, lint.Compose, lint.Helm} {
		if a == nil {
			continue
		}
		var c [4]int
		any := false
		for _, ch := range a.Checks {
			if ch.Status != "warn" && ch.Status != "fail" {
				continue
			}
			c[sevIdx[devopsSeverityOf(ch.Metric)]]++
			any = true
		}
		if any {
			order = append(order, a.Kind)
			counts[a.Kind] = c
		}
	}
	if k8s != nil {
		var c [4]int
		any := false
		for _, w := range k8s.Workloads {
			for _, ch := range w.Checks {
				if ch.Status != "warn" && ch.Status != "fail" {
					continue
				}
				c[sevIdx[devopsSeverityOf(ch.Metric)]]++
				any = true
			}
		}
		for _, f := range k8s.ClusterFindings {
			c[sevIdx[f.Severity]]++
			any = true
		}
		if any {
			order = append(order, k8sDefectKind)
			counts[k8sDefectKind] = c
		}
	}
	return
}

// devopsHealthScore rolls every evaluable check into one severity-weighted
// 0-100 score (pass=full weight, warn=half, fail=0; "na" excluded), so a
// mounted docker.sock (critical, weight 10) moves the needle far more than a
// missing OCI label (low, weight 1). Kubernetes workload checks are folded in
// the same way; cross-cutting Weaknesses have no "passed" counterpart (a
// Weakness only exists when something's wrong), so each one only adds its
// severity weight to the denominator, pulling the score down.
func devopsHealthScore(lint *scanner.DevOpsLint, k8s *scanner.K8sLint) (int, bool) {
	if lint == nil {
		lint = &scanner.DevOpsLint{}
	}
	var pts, total float64
	for _, a := range []*scanner.DevOpsArtifactLint{lint.Dockerfiles, lint.Compose, lint.Helm} {
		if a == nil {
			continue
		}
		for _, c := range a.Checks {
			if c.Status == "na" {
				continue
			}
			w := devopsSeverityWeight(devopsSeverityOf(c.Metric))
			total += w
			switch c.Status {
			case "pass":
				pts += w
			case "warn":
				pts += w / 2
			}
		}
	}
	if k8s != nil {
		for _, wl := range k8s.Workloads {
			for _, c := range wl.Checks {
				if c.Status == "na" {
					continue
				}
				w := devopsSeverityWeight(devopsSeverityOf(c.Metric))
				total += w
				switch c.Status {
				case "pass":
					pts += w
				case "warn":
					pts += w / 2
				}
			}
		}
		for _, f := range k8s.ClusterFindings {
			total += devopsSeverityWeight(f.Severity)
		}
	}
	if total == 0 {
		return 0, false
	}
	return int(pts/total*100 + 0.5), true
}

// gradeColor grades a 0-100 score into the shared good/warn/crit palette.
func gradeColor(score int) string {
	switch {
	case score >= 75:
		return "var(--good)"
	case score >= 50:
		return "var(--warn)"
	default:
		return "var(--crit)"
	}
}

// renderDevOpsCharts renders the three compliance charts (radar, defect
// density, health gauge) shown above the raw static-analysis matrix.
// Kubernetes workload checks and cross-cutting Weaknesses feed into the
// defect-density and health-score charts alongside Dockerfile/Compose/Helm.
func renderDevOpsCharts(lint *scanner.DevOpsLint, k8s *scanner.K8sLint) string {
	scores, has := devopsComplianceDomains(lint)
	kinds, defects := devopsDefectCounts(lint, k8s)
	health, healthOK := devopsHealthScore(lint, k8s)

	anyDomain := false
	for _, h := range has {
		if h {
			anyDomain = true
			break
		}
	}
	if !anyDomain && len(kinds) == 0 && !healthOK {
		return ""
	}

	var b strings.Builder
	b.WriteString(`<div class="as-dvo-charts">`)

	b.WriteString(`<div class="as-dvo-chart as-dvo-chart--health"><div class="as-dvo-chart__title">🩺 DevOps Health Score</div>`)
	if healthOK {
		b.WriteString(renderHealthGauge(health))
	} else {
		b.WriteString(`<p class="as-empty">Not enough evaluable checks.</p>`)
	}
	b.WriteString(`<div class="as-dvo-chart__note">Severity-weighted rollup of every evaluable check (critical ×10 … low ×1).</div></div>`)

	k8sTab := ""
	if !k8s.Empty() && len(k8s.Clusters) == 1 {
		k8sTab = "k0"
	}

	b.WriteString(`<div class="as-dvo-chart as-dvo-chart--defect"><div class="as-dvo-chart__title">📊 Defect Density by Artifact</div>`)
	if len(kinds) > 0 {
		b.WriteString(renderDefectDensityBars(lint, kinds, defects, k8sTab))
	} else {
		b.WriteString(`<p class="as-empty">No failing or warned checks — clean bill of health.</p>`)
	}
	b.WriteString(`<div class="as-dvo-chart__note">Non-passing checks per artifact type, stacked by severity.</div></div>`)

	b.WriteString(`<div class="as-dvo-chart as-dvo-chart--radar"><div class="as-dvo-chart__title">🎯 Security &amp; Compliance Radar</div>`)
	b.WriteString(renderComplianceRadarSVG(scores, has))
	b.WriteString(renderComplianceDomainList(scores, has))
	b.WriteString(`<div class="as-dvo-chart__note">Domain average of related checks (pass=100%, warn=50%, fail=0%).</div></div>`)

	b.WriteString(renderK8sSummaryChart(k8s, k8sTab))

	b.WriteString(`</div>`)
	return b.String()
}

// renderK8sSummaryChart renders a compact "☸️ Kubernetes" summary tile in
// the DevOps charts grid — total workload and other-resource counts plus
// the overall pass rate — as a clickable link into the full breakdown now
// living in 🗄️ Infrastructure Platforms (the detailed workload/resource
// cards moved there; this is what stays behind in DevOps).
func renderK8sSummaryChart(k8s *scanner.K8sLint, k8sTab string) string {
	if k8s.Empty() {
		return ""
	}
	scoreSum := 0
	podCount := 0
	var totalRAM float64
	for _, w := range k8s.Workloads {
		scoreSum += w.Score
		replicas := w.Replicas
		if replicas <= 0 {
			replicas = 1 // DaemonSet/Job/CronJob: replica count is unknown, count the template once
		}
		podCount += replicas
		agg := aggregateK8sResources(w)
		mem := agg.memLim
		if mem == 0 {
			mem = agg.memReq
		}
		totalRAM += mem * float64(replicas)
	}
	avg := scoreSum / len(k8s.Workloads)

	s := k8s.Stats
	totalResources := s.Services + s.Ingresses + s.NetworkPolicies + s.ConfigMaps + s.PVCs +
		s.StorageClasses + s.ServiceAccounts + s.Roles + s.RoleBindings + s.ClusterRoles +
		s.ClusterRoleBindings + s.HPAs + s.PDBs
	for _, op := range s.Operators {
		totalResources += op.Count
	}

	attrs := ""
	if k8sTab != "" {
		attrs = fmt.Sprintf(` data-platcard-link="%s"`, esc(k8sTab))
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<a class="as-dvo-chart as-dvo-chart--kube" href="#as-infra-platforms"%s>`, attrs)
	b.WriteString(`<div class="as-dvo-chart__title">☸️ Kubernetes</div>`)
	b.WriteString(`<div class="as-dvo-kube-stats">`)
	fmt.Fprintf(&b, `<div class="as-dvo-kube-stat"><span class="as-dvo-kube-stat__val">%d</span><span class="as-dvo-kube-stat__label">workload%s</span></div>`,
		len(k8s.Workloads), plural(len(k8s.Workloads), "", "s"))
	fmt.Fprintf(&b, `<div class="as-dvo-kube-stat"><span class="as-dvo-kube-stat__val">%d</span><span class="as-dvo-kube-stat__label">pod%s</span></div>`,
		podCount, plural(podCount, "", "s"))
	if totalRAM > 0 {
		fmt.Fprintf(&b, `<div class="as-dvo-kube-stat"><span class="as-dvo-kube-stat__val">%s</span><span class="as-dvo-kube-stat__label">RAM requested</span></div>`,
			esc(formatMemBytes(totalRAM)))
	}
	if s.PVCs > 0 {
		fmt.Fprintf(&b, `<div class="as-dvo-kube-stat"><span class="as-dvo-kube-stat__val">%d</span><span class="as-dvo-kube-stat__label">disk%s (PVC)</span></div>`,
			s.PVCs, plural(s.PVCs, "", "s"))
	}
	fmt.Fprintf(&b, `<div class="as-dvo-kube-stat"><span class="as-dvo-kube-stat__val">%d</span><span class="as-dvo-kube-stat__label">other resource%s</span></div>`,
		totalResources, plural(totalResources, "", "s"))
	fmt.Fprintf(&b, `<div class="as-dvo-kube-stat"><span class="as-dvo-kube-stat__val" style="color:%s">%d%%</span><span class="as-dvo-kube-stat__label">passed</span></div>`,
		gradeColor(avg), avg)
	if n := len(k8s.Clusters); n > 1 {
		fmt.Fprintf(&b, `<div class="as-dvo-kube-stat"><span class="as-dvo-kube-stat__val">%d</span><span class="as-dvo-kube-stat__label">clusters</span></div>`, n)
	}
	b.WriteString(`</div>`)
	b.WriteString(`<div class="as-dvo-chart__note">Click for the full per-workload breakdown in 🗄️ Infrastructure Platforms.</div>`)
	b.WriteString(`</a>`)
	return b.String()
}

// renderComplianceRadarSVG draws a static 6-axis spider chart (guide rings +
// spokes + a filled score polygon) with a shortened, color-graded label at
// each vertex; the full domain names and exact percentages are listed
// separately by renderComplianceDomainList.
func renderComplianceRadarSVG(scores [6]int, has [6]bool) string {
	const size = 360
	const cx, cy = size / 2, size/2 + 6
	const maxR = 94.0
	n := len(devopsDomains)

	point := func(i int, r float64) (float64, float64) {
		a := -math.Pi/2 + float64(i)*2*math.Pi/float64(n)
		return float64(cx) + r*math.Cos(a), float64(cy) + r*math.Sin(a)
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" class="as-dvo-radar-svg" role="img" aria-label="Security and compliance radar">`, size, size)

	for _, frac := range []float64{0.25, 0.5, 0.75, 1.0} {
		var pts []string
		for i := 0; i < n; i++ {
			x, y := point(i, maxR*frac)
			pts = append(pts, fmt.Sprintf("%.1f,%.1f", x, y))
		}
		fmt.Fprintf(&b, `<polygon points="%s" fill="none" stroke="var(--border)" stroke-width="1"/>`, strings.Join(pts, " "))
	}
	for i := 0; i < n; i++ {
		x, y := point(i, maxR)
		fmt.Fprintf(&b, `<line x1="%d" y1="%d" x2="%.1f" y2="%.1f" stroke="var(--border)" stroke-width="1"/>`, cx, cy, x, y)
	}

	avgSum, avgN := 0, 0
	var pts []string
	for i := 0; i < n; i++ {
		v := 0
		if has[i] {
			v = scores[i]
			avgSum += v
			avgN++
		}
		x, y := point(i, maxR*float64(v)/100)
		pts = append(pts, fmt.Sprintf("%.1f,%.1f", x, y))
	}
	col := "var(--text-faint)"
	if avgN > 0 {
		col = gradeColor(avgSum / avgN)
	}
	fmt.Fprintf(&b, `<polygon points="%s" fill="%s" fill-opacity="0.22" stroke="%s" stroke-width="2" stroke-linejoin="round"/>`,
		strings.Join(pts, " "), col, col)

	for i := 0; i < n; i++ {
		v := 0
		if has[i] {
			v = scores[i]
		}
		x, y := point(i, maxR*float64(v)/100)
		fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="3" fill="%s"><title>%d. %s%s</title></circle>`,
			x, y, col, i+1, esc(devopsDomains[i]), domainValueSuffix(scores[i], has[i]))
	}

	// Shortened vertex labels, color-graded per domain (muted when n/a).
	const labelR = maxR + 34
	for i := 0; i < n; i++ {
		lx, ly := point(i, labelR)
		anchor := "middle"
		if lx < float64(cx)-6 {
			anchor = "end"
		} else if lx > float64(cx)+6 {
			anchor = "start"
		}
		lcol := "var(--text-faint)"
		if has[i] {
			lcol = gradeColor(scores[i])
		}
		lines := devopsDomainAxisLines[i]
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" text-anchor="%s" class="as-dvo-radar-axis-label" fill="%s"><title>%s</title>%s</text>`,
			lx, ly-4, anchor, lcol, esc(devopsDomains[i]), esc(lines[0]))
		if lines[1] != "" {
			fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" text-anchor="%s" class="as-dvo-radar-axis-label" fill="%s">%s</text>`,
				lx, ly+9, anchor, lcol, esc(lines[1]))
		}
	}

	b.WriteString(`</svg>`)
	return b.String()
}

func domainValueSuffix(score int, has bool) string {
	if !has {
		return ": n/a"
	}
	return fmt.Sprintf(": %d%%", score)
}

// renderComplianceDomainList renders the six domains as a compact numbered
// bar list beneath the radar SVG (mirrors the Danger Index's category-weight
// list styling).
func renderComplianceDomainList(scores [6]int, has [6]bool) string {
	var b strings.Builder
	b.WriteString(`<div class="as-dvo-dom-list">`)
	for i, name := range devopsDomains {
		if !has[i] {
			fmt.Fprintf(&b, `<div class="as-dvo-dom-row"><span class="as-dvo-dom-num">%d</span>`+
				`<span class="as-dvo-dom-name" title="%s">%s</span>`+
				`<div class="as-dvo-dom-track"><div class="as-sec-wb-na" style="width:100%%"></div></div>`+
				`<span class="as-dvo-dom-val as-dvo-dom-val--na">n/a</span></div>`,
				i+1, esc(name), esc(name))
			continue
		}
		col := gradeColor(scores[i])
		fmt.Fprintf(&b, `<div class="as-dvo-dom-row"><span class="as-dvo-dom-num">%d</span>`+
			`<span class="as-dvo-dom-name" title="%s">%s</span>`+
			`<div class="as-dvo-dom-track"><div class="as-dvo-dom-fill" style="width:%d%%;background:%s"></div></div>`+
			`<span class="as-dvo-dom-val" style="color:%s">%d%%</span></div>`,
			i+1, esc(name), esc(name), scores[i], col, col, scores[i])
	}
	b.WriteString(`</div>`)
	return b.String()
}

// devopsKindIcon maps a DevOpsArtifactLint.Kind (or the synthetic
// k8sDefectKind) to its column icon.
func devopsKindIcon(lint *scanner.DevOpsLint, kind string) string {
	if kind == k8sDefectKind {
		return "☸️"
	}
	for _, a := range []*scanner.DevOpsArtifactLint{lint.Dockerfiles, lint.Compose, lint.Helm} {
		if a != nil && a.Kind == kind {
			return a.Icon
		}
	}
	return "•"
}

// renderDefectDensityBars renders one stacked horizontal bar per artifact
// kind: each bar always fills its full track, segmented by that kind's own
// severity mix (composition), since artifact kinds can differ by orders of
// magnitude in raw count (e.g. hundreds of per-workload Kubernetes checks vs.
// a handful of Dockerfile checks) — sizing segments relative to a shared max
// would flatten every smaller kind's bar into an unreadable sliver. The
// absolute count (relative volume) is still shown as a number after the bar.
// renderDefectDensityBars renders one bar per artifact kind. The Kubernetes
// row (if present) is a clickable link into 🗄️ Infrastructure Platforms —
// k8sTab is the target card's data-platcard value ("k0") when there's
// exactly one detected cluster, or "" when there are zero or several (in
// which case the link just scrolls to the section instead of forcing one
// specific card open).
func renderDefectDensityBars(lint *scanner.DevOpsLint, order []string, counts map[string][4]int, k8sTab string) string {
	sevClass := [4]string{"fill-crit", "fill-bad", "fill-warn", "as-dvo-sev-low"}
	sevLabel := [4]string{"Critical", "High", "Medium", "Low"}

	var b strings.Builder
	b.WriteString(`<div class="as-dvo-defect-list">`)
	for _, k := range order {
		c := counts[k]
		total := c[0] + c[1] + c[2] + c[3]

		tag, attrs := "div", ""
		if k == k8sDefectKind {
			tag = "a"
			attrs = ` href="#as-infra-platforms"`
			if k8sTab != "" {
				attrs += fmt.Sprintf(` data-platcard-link="%s"`, esc(k8sTab))
			}
		}
		fmt.Fprintf(&b, `<%s class="as-dvo-defect-row"%s><span class="as-dvo-defect-icon">%s</span>`+
			`<span class="as-dvo-defect-name" title="%s">%s</span><div class="as-dvo-defect-track">`,
			tag, attrs, devopsKindIcon(lint, k), esc(k), esc(k))
		for i, n := range c {
			if n == 0 {
				continue
			}
			pct := float64(n) / float64(total) * 100
			fmt.Fprintf(&b, `<div class="as-dvo-defect-seg %s" style="width:%.1f%%" title="%s: %d"></div>`,
				sevClass[i], pct, sevLabel[i], n)
		}
		fmt.Fprintf(&b, `</div><span class="as-dvo-defect-total">%d</span></%s>`, total, tag)
	}
	b.WriteString(`</div>`)
	b.WriteString(`<div class="as-dvo-defect-legend">`)
	for i, label := range sevLabel {
		fmt.Fprintf(&b, `<span><i class="%s"></i>%s</span>`, sevClass[i], label)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// renderHealthGauge draws a static semicircle gauge (0-100) for the
// severity-weighted DevOps health score.
func renderHealthGauge(score int) string {
	const w, h = 200, 116
	const r, cx, cy = 80.0, 100.0, 100.0
	pct := math.Min(math.Max(float64(score)/100, 0.001), 0.999)
	ang := math.Pi * (1 - pct)
	ex := cx + r*math.Cos(ang)
	ey := cy - r*math.Sin(ang)
	col := gradeColor(score)

	band, cls := "At Risk", "crit"
	switch {
	case score >= 80:
		band, cls = "Strong", "good"
	case score >= 50:
		band, cls = "Needs Attention", "warn"
	}

	var b strings.Builder
	b.WriteString(`<div class="as-dvo-gauge-wrap">`)
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" class="as-dvo-gauge-svg" role="img" aria-label="DevOps health score gauge">`, w, h)
	fmt.Fprintf(&b, `<path d="M %g,%g A %g,%g 0 0 1 %g,%g" fill="none" stroke="var(--border)" stroke-width="14" stroke-linecap="round"/>`,
		cx-r, cy, r, r, cx+r, cy)
	fmt.Fprintf(&b, `<path d="M %g,%g A %g,%g 0 0 1 %.2f,%.2f" fill="none" stroke="%s" stroke-width="14" stroke-linecap="round"/>`,
		cx-r, cy, r, r, ex, ey, col)
	fmt.Fprintf(&b, `<text x="%g" y="%g" text-anchor="middle" class="as-dvo-gauge-val" fill="%s">%d%%</text>`, cx, cy-8, col, score)
	b.WriteString(`</svg>`)
	fmt.Fprintf(&b, `<div class="as-dvo-gauge-band band-%s">%s</div>`, cls, esc(band))
	b.WriteString(`</div>`)
	return b.String()
}

// ── 📡 Technical Radar ───────────────────────────────────────────────────────

// radarRingColors are the fill/stroke colors for rings 0..3 (Adopt..Hold),
// matching the .as-radar-chip--N badge palette in theme.go.
var radarRingColors = [4]string{"var(--good)", "#00b8cc", "var(--warn)", "var(--crit)"}

// radarRings classifies known technology labels into radar rings:
// 0=Adopt (green), 1=Trial (teal), 2=Assess (yellow), 3=Hold (red).
// Technologies not listed default to Trial (1).
var radarRings = map[string]int{
	// Adopt — proven, use by default
	"Go": 0, "Python": 0, "Rust": 0, "Swift": 0, "Kotlin": 0, "Java": 0,
	"TypeScript / JS": 0, "JavaScript": 0,
	"React": 0, "React Native": 0,
	"net/http": 0, "gRPC": 0, "Protobuf": 0,
	"PostgreSQL": 0, "Redis": 0, "Elasticsearch": 0, "Kafka": 0,
	"OpenTelemetry": 0, "Prometheus": 0,
	"Django REST Framework": 0, "FastAPI": 0,
	"Testify": 0, "pytest": 0,
	"SwiftUI": 0, "UIKit": 0,
	"Jetpack Compose": 0,
	// Trial — try in a pilot project
	"Next.js": 1, "Tailwind CSS": 1, "Expo": 1, "Redux": 1,
	"Vue": 1, "Nuxt": 1, "Svelte": 1,
	"Gin": 1, "Chi": 1, "Echo": 1, "Fiber": 1, "Gorilla Mux": 1,
	"Cobra": 1,
	"MinIO": 1, "MongoDB": 1, "RabbitMQ": 1,
	"Grafana": 1, "Jaeger": 1,
	"Requests": 1, "Axios": 1, "HTTPx": 1,
	"Celery": 1, "Dramatiq": 1,
	"SQLAlchemy": 1, "SQLModel": 1, "GORM": 1,
	"NumPy": 1, "pandas": 1, "SciPy": 1,
	"Zap": 1, "slog": 1, "Logrus": 1,
	"Spring Boot": 1, "Spring": 1, "Ktor": 1,
	"Actix-web": 1, "Axum": 1, "Tokio": 1, "PyTorch": 1,
	// Assess — research before committing
	"Ant Design": 2, "Dash": 2, "MUI": 2, "Chakra UI": 2, "Streamlit": 2,
	"Django": 2, "Flask": 2, "Express": 2, "NestJS": 2,
	"Angular": 2, "SolidJS": 2, "Astro": 2,
	"Click": 2, "Uvicorn": 2, "Starlette": 2,
	"NATS": 2, "Redis Pub/Sub": 2, "Apache Pulsar": 2,
	"Matplotlib": 2, "Plotly": 2, "Seaborn": 2,
	"Day.js": 2, "Lodash": 2,
	"MySQL driver": 2, "Prisma": 2, "TypeORM": 2,
	"TensorFlow": 2,
	"Datadog":    2, "New Relic": 2, "Zipkin": 2,
	// Hold — avoid, plan to replace
	"Moment.js": 3, "jQuery": 3, "Bootstrap": 3,
	"log": 3, "Log4j": 3,
	"Objective-C":           3,
	"AMQP":                  3,
	"Java Standard Library": 3,
}

func radarRingFor(label string) int {
	if r, ok := radarRings[label]; ok {
		return r
	}
	return 1 // unknown technology → Trial
}

// radarChip is one detected technology or pattern placed on the radar.
type radarChip struct {
	label string
	ring  int
}

// radarCategory is one tech-stack category row (as-stack grouping key + its
// display title).
type radarCategory struct{ key, title string }

// radarQuadrants are the four aoe_technology_radar-style quadrants: a corner
// title plus an accent color used for its label and background corner glow.
// Order is fixed — index doubles as the quadrant position (0=top-left,
// 1=top-right, 2=bottom-left, 3=bottom-right).
var radarQuadrants = [4]struct{ title, color string }{
	{"Tools", "#4ea1ff"},
	{"Languages & Frameworks", "#a371f7"},
	{"Platforms & Operations", "#39c5cf"},
	{"Methods & Patterns", "#db61a2"},
}

// radarQuadLines is the (up to) two-line wrapped label drawn in each
// quadrant's outer corner (SVG text has no auto-wrap).
var radarQuadLines = [4][2]string{
	{"TOOLS", ""},
	{"LANGUAGES", "& FRAMEWORKS"},
	{"PLATFORMS", "& OPERATIONS"},
	{"METHODS", "& PATTERNS"},
}

// dispCatQuadrant maps a tech-stack category key onto a radarQuadrants index.
var dispCatQuadrant = map[string]int{
	"languages": 1, "frontend": 1, "backend": 1,
	"data": 2, "brokers": 2,
	"linters": 0,
}

// techPatternMatches merges Gang-of-Four design-pattern detections across
// every platform's module panel into one de-duplicated, repo-wide chip list
// for the Methods & Patterns quadrant. RawResult is the same opaque
// per-module result other cross-module joins already rely on (see the
// traffic/dddmodel/arch lookups above).
func techPatternMatches(res *result.AnalysisResult) []radarChip {
	counts := map[string]int{}
	var order []string
	for _, p := range res.ModulePanels {
		if p.ModuleID != "designpattern" {
			continue
		}
		r, ok := p.RawResult.(constructs.DesignPatternResult)
		if !ok {
			continue
		}
		for _, m := range r.Matches {
			if _, seen := counts[m.Pattern]; !seen {
				order = append(order, m.Pattern)
			}
			counts[m.Pattern] += m.Count
		}
	}
	sort.Strings(order)
	chips := make([]radarChip, 0, len(order))
	for _, name := range order {
		chips = append(chips, radarChip{label: name, ring: radarRingFor(name)})
	}
	return chips
}

// renderTechRadarSection renders a static, full-content-width SVG adoption
// radar in the aoe_technology_radar house style: cross-divided quadrants
// (Tools / Languages & Frameworks / Platforms & Operations / Methods &
// Patterns) with a corner accent glow, concentric Adopt→Hold rings, and every
// detected chip plotted as a small blip inside its quadrant at its ring's
// radius. The same chips are listed as text underneath, grouped by quadrant
// then category, for full legibility.
func renderTechRadarSection(res *result.AnalysisResult) string {
	catSets := techCategorySets(res)

	// Collect languages from parsed files.
	langs := map[string]bool{}
	for _, f := range res.Files {
		if lbl, ok := langLabels[f.LanguageID]; ok {
			langs[lbl] = true
		}
	}

	dispCats := []radarCategory{
		{"languages", "Languages"},
		{"frontend", "Frontend"},
		{"backend", "Backend"},
		{"data", "Data"},
		{"brokers", "Brokers"},
		{"linters", "Monitoring"},
	}
	catChips := map[string][]radarChip{}
	for lbl := range langs {
		catChips["languages"] = append(catChips["languages"], radarChip{lbl, radarRingFor(lbl)})
	}
	for cat, techs := range catSets {
		for tech := range techs {
			catChips[cat] = append(catChips[cat], radarChip{tech, radarRingFor(tech)})
		}
	}
	ringNames := [4]string{"Adopt", "Trial", "Assess", "Hold"}
	for cat := range catChips {
		sort.Slice(catChips[cat], func(i, j int) bool {
			if catChips[cat][i].ring != catChips[cat][j].ring {
				return catChips[cat][i].ring < catChips[cat][j].ring
			}
			return catChips[cat][i].label < catChips[cat][j].label
		})
	}
	patternChips := techPatternMatches(res)

	hasAnyChip := len(patternChips) > 0
	for _, dc := range dispCats {
		if len(catChips[dc.key]) > 0 {
			hasAnyChip = true
			break
		}
	}
	if !hasAnyChip {
		return ""
	}

	// Quadrant groups, each holding its category sub-rows — the same
	// grouping used to plot the blips on the radar, kept fully legible.
	var quadCats [4][]radarCategory
	for _, dc := range dispCats {
		q := dispCatQuadrant[dc.key]
		quadCats[q] = append(quadCats[q], dc)
	}

	renderQuadGroup := func(qi int) string {
		quad := radarQuadrants[qi]
		hasContent := qi == 3 && len(patternChips) > 0
		for _, dc := range quadCats[qi] {
			if len(catChips[dc.key]) > 0 {
				hasContent = true
			}
		}
		if !hasContent {
			return ""
		}
		var qb strings.Builder
		fmt.Fprintf(&qb, `<div class="as-radar-quad-group"><div class="as-radar-quad-group__title" style="color:%s">%s</div>`,
			quad.color, esc(quad.title))
		for _, dc := range quadCats[qi] {
			chips := catChips[dc.key]
			if len(chips) == 0 {
				continue
			}
			fmt.Fprintf(&qb, `<div class="as-radar-row"><span class="as-radar-row__label">%s</span><div class="as-radar-row__chips">`, esc(dc.title))
			for _, ch := range chips {
				fmt.Fprintf(&qb, `<span class="as-radar-chip as-radar-chip--%d" title="%s">%s</span>`, ch.ring, esc(ringNames[ch.ring]), esc(ch.label))
			}
			qb.WriteString(`</div></div>`)
		}
		if qi == 3 && len(patternChips) > 0 {
			qb.WriteString(`<div class="as-radar-row"><span class="as-radar-row__label">Design Patterns</span><div class="as-radar-row__chips">`)
			for _, ch := range patternChips {
				fmt.Fprintf(&qb, `<span class="as-radar-chip as-radar-chip--%d" title="%s">%s</span>`, ch.ring, esc(ringNames[ch.ring]), esc(ch.label))
			}
			qb.WriteString(`</div></div>`)
		}
		qb.WriteString(`</div>`)
		return qb.String()
	}

	// Sandwich layout: the top quadrants' (Tools, Languages & Frameworks)
	// chip rows sit above the radar, the bottom quadrants' (Platforms &
	// Operations, Methods & Patterns) sit below it — mirroring the radar's
	// own top/bottom quadrant split.
	top := renderQuadGroup(0) + renderQuadGroup(1)
	bottom := renderQuadGroup(2) + renderQuadGroup(3)

	var b strings.Builder
	b.WriteString(`<div class="as-section"><div class="as-section__head"><span class="ico">📡</span><h2>Technical Radar</h2></div>`)
	b.WriteString(`<div class="as-section__sub" style="margin-top:0">Detected technologies placed on an adoption radar — Adopt (center, safe default) to Hold (rim, avoid/replace) — across four quadrants: tools, languages &amp; frameworks, platforms &amp; operations, and methods &amp; patterns.</div>`)

	if top != "" {
		b.WriteString(`<div class="as-radar-quads">`)
		b.WriteString(top)
		b.WriteString(`</div>`)
	}

	b.WriteString(`<div class="as-radar">`)
	b.WriteString(renderTechRadarQuadrantSVG(catChips, dispCats, patternChips))
	b.WriteString(`</div>`)

	if bottom != "" {
		b.WriteString(`<div class="as-radar-quads">`)
		b.WriteString(bottom)
		b.WriteString(`</div>`)
	}

	b.WriteString(`</div>`)
	return b.String()
}

// renderTechRadarQuadrantSVG draws a full-width square radar: a per-quadrant
// corner glow + cross divider (aoe_technology_radar's gradient/quadrant
// style), neutral concentric Adopt→Hold guide rings, corner quadrant titles,
// and every chip plotted as a small ring-colored blip inside its quadrant at
// the radius for its ring. Chips within the same quadrant+ring band are
// spread evenly across that band's 90° arc so they don't stack exactly on
// top of one another.
func renderTechRadarQuadrantSVG(catChips map[string][]radarChip, dispCats []radarCategory, patternChips []radarChip) string {
	const size = 400.0
	const cx, cy = size / 2, size / 2
	const outerR = 186.0
	ringR := [4]float64{outerR * 0.34, outerR * 0.6, outerR * 0.82, outerR}
	ringInner := [4]float64{0, ringR[0], ringR[1], ringR[2]}
	stageNames := [4]string{"Adopt", "Trial", "Assess", "Hold"}

	// quadStart[i] is the starting angle (degrees; 0=+x/east, increasing
	// clockwise since SVG y grows downward) of radarQuadrants[i]'s 90° arc.
	quadStart := [4]float64{180, 270, 90, 0}
	// quadRect is the (x,y) top-left of the square housing that quadrant's
	// corner glow — same rect AOE's Chart.tsx anchors renderGlow to.
	quadRect := [4][2]float64{{0, 0}, {cx, 0}, {0, cy}, {cx, cy}}
	quadCorner := [4][2]string{{"0%", "0%"}, {"100%", "0%"}, {"0%", "100%"}, {"100%", "100%"}}

	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %g %g" class="as-radar-svg" role="img" `+
		`aria-label="Technology adoption radar with tools, languages and frameworks, platforms and operations, and methods and patterns quadrants">`, size, size)

	b.WriteString(`<defs>`)
	for i, q := range radarQuadrants {
		fmt.Fprintf(&b, `<radialGradient id="as-radar-q%d" cx="%s" cy="%s" r="80%%">`+
			`<stop offset="0%%" stop-color="%s" stop-opacity=".22"/>`+
			`<stop offset="100%%" stop-color="%s" stop-opacity="0"/></radialGradient>`,
			i, quadCorner[i][0], quadCorner[i][1], q.color, q.color)
	}
	b.WriteString(`</defs>`)
	for i := range radarQuadrants {
		fmt.Fprintf(&b, `<rect x="%g" y="%g" width="%g" height="%g" fill="url(#as-radar-q%d)"/>`,
			quadRect[i][0], quadRect[i][1], cx, cy, i)
	}

	// Concentric guide rings (neutral — maturity is carried by blip color).
	// vector-effect keeps the stroke a constant few px regardless of how
	// large the SVG is scaled up to; width tapers from the innermost ring
	// (thicker) to the outermost (thinner), echoing aoe_technology_radar's
	// own ring weight.
	ringStroke := [4]float64{2, 2, 2, 2}
	for i, r := range ringR {
		fmt.Fprintf(&b, `<circle cx="%g" cy="%g" r="%.1f" fill="none" stroke="var(--border-strong)" stroke-opacity="0.7" stroke-width="%g" vector-effect="non-scaling-stroke"/>`, cx, cy, r, ringStroke[i])
	}
	// Cross divider spanning the outer ring's diameter.
	fmt.Fprintf(&b, `<line x1="%g" y1="%g" x2="%g" y2="%g" stroke="var(--border-strong)" stroke-width="1" vector-effect="non-scaling-stroke"/>`, cx-outerR, cy, cx+outerR, cy)
	fmt.Fprintf(&b, `<line x1="%g" y1="%g" x2="%g" y2="%g" stroke="var(--border-strong)" stroke-width="1" vector-effect="non-scaling-stroke"/>`, cx, cy-outerR, cx, cy+outerR)

	// Ring labels on the horizontal axis (left/right mirrored, ADOPT nearest
	// center growing out to HOLD at the rim), colored by ring for quick
	// scanning, sitting just above the divider line.
	prev := 0.0
	for i, r := range ringR {
		mid := (prev + r) / 2
		prev = r
		fmt.Fprintf(&b, `<text x="%.1f" y="%g" class="as-radar-ring-label" fill="%s" text-anchor="middle">%s</text>`,
			cx-mid, cy-6, radarRingColors[i], strings.ToUpper(stageNames[i]))
		fmt.Fprintf(&b, `<text x="%.1f" y="%g" class="as-radar-ring-label" fill="%s" text-anchor="middle">%s</text>`,
			cx+mid, cy-6, radarRingColors[i], strings.ToUpper(stageNames[i]))
	}

	// Quadrant corner titles.
	labelX := [4]float64{14, size - 14, 14, size - 14}
	labelAnchor := [4]string{"start", "end", "start", "end"}
	labelY := [4][2]float64{{18, 30}, {18, 30}, {size - 30, size - 18}, {size - 30, size - 18}}
	for i, q := range radarQuadrants {
		lines := radarQuadLines[i]
		fmt.Fprintf(&b, `<text x="%g" y="%g" text-anchor="%s" class="as-radar-quad-label" fill="%s">%s</text>`,
			labelX[i], labelY[i][0], labelAnchor[i], q.color, lines[0])
		if lines[1] != "" {
			fmt.Fprintf(&b, `<text x="%g" y="%g" text-anchor="%s" class="as-radar-quad-label" fill="%s">%s</text>`,
				labelX[i], labelY[i][1], labelAnchor[i], q.color, lines[1])
		}
	}

	// Bucket every chip by (quadrant, ring) then spread each bucket evenly
	// across that ring band's 90° arc within the quadrant.
	type bucketKey struct{ quad, ring int }
	buckets := map[bucketKey][]string{}
	add := func(quad, ring int, label string) {
		buckets[bucketKey{quad, ring}] = append(buckets[bucketKey{quad, ring}], label)
	}
	for _, dc := range dispCats {
		quad := dispCatQuadrant[dc.key]
		for _, ch := range catChips[dc.key] {
			add(quad, ch.ring, ch.label)
		}
	}
	for _, ch := range patternChips {
		add(3, ch.ring, ch.label)
	}

	for quad := 0; quad < 4; quad++ {
		for ring := 0; ring < 4; ring++ {
			labels := buckets[bucketKey{quad, ring}]
			n := len(labels)
			if n == 0 {
				continue
			}
			bandMid := (ringInner[ring] + ringR[ring]) / 2
			for i, lbl := range labels {
				frac := (float64(i) + 0.5) / float64(n)
				angle := (quadStart[quad] + frac*90) * math.Pi / 180
				r := bandMid + bandMid*0.12*float64((i%3)-1)
				x := cx + r*math.Cos(angle)
				y := cy + r*math.Sin(angle)
				fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="2.4" fill="%s" stroke="var(--bg-elev)" stroke-width="1" vector-effect="non-scaling-stroke"><title>%s — %s</title></circle>`,
					x, y, radarRingColors[ring], esc(lbl), stageNames[ring])
				// Alternate the label above/below its dot (close to the dot
				// edge) so items packed into the same small ring band don't
				// all stack their text in a single overlapping line.
				ly := y + 5.5
				if i%2 == 1 {
					ly = y - 3.5
				}
				fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" text-anchor="middle" class="as-radar-blip-label" fill="var(--text-dim)">%s</text>`,
					x, ly, esc(lbl))
			}
		}
	}

	b.WriteString(`</svg>`)
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
		langspec.PlatformRust,
		langspec.PlatformC,
	}
	short := map[langspec.Platform]string{
		langspec.PlatformSwiftObjC: "Swift",
		langspec.PlatformKotlin:    "Kotlin",
		langspec.PlatformTSJS:      "JS",
		langspec.PlatformPython:    "Python",
		langspec.PlatformGo:        "Go",
		langspec.PlatformRust:      "Rust",
		langspec.PlatformC:         "C/C++",
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
	case langspec.PlatformRust:
		return "Rust"
	case langspec.PlatformC:
		return "C/C++"
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
	b.WriteString(renderSecurityRules(res.Security, res.K8sLint))

	hasK8sCF := res.Scan.K8sLint != nil && len(res.Scan.K8sLint.ClusterFindings) > 0
	if len(platFindings) > 0 || hasK8sCF {
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
		b.WriteString(`<div class="as-sub" style="margin-bottom:8px">🛡️ Findings by Platform</div>`)
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
		if hasK8sCF {
			cf := res.Scan.K8sLint.ClusterFindings
			critHigh := 0
			for _, f := range cf {
				if f.Severity == "critical" || f.Severity == "high" {
					critHigh++
				}
			}
			hiHTML := ""
			if critHigh > 0 {
				hiHTML = fmt.Sprintf(` <span class="as-sev sev-high" style="font-size:10px">%d HIGH</span>`, critHigh)
			}
			fmt.Fprintf(&b,
				`<a class="as-sec-plat-card as-sec-plat-card--link" href="#as-k8s-cf">`+
					`<div class="as-sec-plat-name">☁️ DevOps</div>`+
					`<div class="as-sec-plat-count">%d%s</div>`+
					`</a>`,
				len(cf), hiHTML)
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
func renderSecurityRules(results []security.RuleResult, k8sLint *scanner.K8sLint) string {
	// Display names for known CWE IDs. Unknown IDs fall back to "CWE-NNN".
	cweNames := map[string]string{
		"16":   "Security Configuration Errors",
		"269":  "Improper Privilege Management",
		"284":  "Improper Access Control",
		"306":  "Missing Authentication for Critical Function",
		"312":  "Cleartext Storage of Sensitive Information",
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
		{"k8s", "as-plat-k8s", "K8s"},
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

	// Fold in K8s cross-cutting findings (NetworkPolicy gaps, RBAC over-grants,
	// secrets in manifests, ...) so their CWEs surface here too, not only in
	// the Weaknesses cards below. Grouped by RuleID so e.g. the
	// same NetworkPolicy-gap check firing across 7 namespaces counts once.
	extraChecks := 0
	if k8sLint != nil {
		seenRule := map[string]bool{}
		for _, f := range k8sLint.ClusterFindings {
			if f.CWE == "" {
				continue
			}
			ci := info[f.CWE]
			if ci == nil {
				ci = &cweInfo{langs: map[string]bool{}}
				info[f.CWE] = ci
			}
			ci.langs["k8s"] = true
			failedCWEs[f.CWE] = true
			if !seenRule[f.RuleID] {
				seenRule[f.RuleID] = true
				ci.n++
				extraChecks++
			}
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
			`📋 Security Rules <span style="color:var(--text-faint);font-weight:400;text-transform:none;letter-spacing:0">(%d total checks)</span>`+
			`</div>`,
		len(results)+extraChecks)
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

// ── Platform accordion cards ─────────────────────────────────────────────────

// fmtLOC formats a line count as "1.2K", "74K", "1.2M" etc.
func fmtLOC(n int) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1000:
		return fmt.Sprintf("%.0fK", float64(n)/1000)
	default:
		return strconv.Itoa(n)
	}
}

// platAbbr returns a 2-letter abbreviation for a language platform.
func platAbbr(p langspec.Platform) string {
	switch p {
	case langspec.PlatformSwiftObjC:
		return "Sw"
	case langspec.PlatformKotlin:
		return "Kt"
	case langspec.PlatformPython:
		return "Py"
	case langspec.PlatformTSJS:
		return "TS"
	case langspec.PlatformGo:
		return "Go"
	case langspec.PlatformJava:
		return "Ja"
	case langspec.PlatformRust:
		return "Rs"
	default:
		s := string(p)
		if len(s) >= 2 {
			return strings.ToUpper(s[:2])
		}
		return strings.ToUpper(s)
	}
}

// renderTabs renders platforms as a vertical accordion of switchable cards.
// Each card header shows language, name, LOC, file count, and module summary
// stats. Clicking a header expands that card and collapses others.
// orderedPlatformTabs returns the platform groups that get a dedicated card in
// "🗂️ Platforms" — those with at least minCultureLOC lines, the same
// threshold that gates a 🔰 Programming Culture row, since a handful of files
// don't carry enough signal for either — in the exact display order renderTabs
// renders them. Exposed so other sections (Programming Culture) can link a
// platform to its tab index consistently.
func orderedPlatformTabs(res *result.AnalysisResult) []*scanner.PlatformGroup {
	all := res.Scan.PlatformsOrdered()
	if len(all) == 0 {
		return nil
	}

	loc := map[langspec.Platform]int{}
	for _, f := range res.Files {
		loc[langspec.Platform(f.Platform)] += f.LineCount
	}

	platforms := make([]*scanner.PlatformGroup, 0, len(all))
	for _, pg := range all {
		if loc[pg.Platform] >= minCultureLOC {
			platforms = append(platforms, pg)
		}
	}
	if len(platforms) == 0 {
		return nil
	}

	if res.Scan.FolderAsTab {
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
	return platforms
}

// platformCardIndex maps each platform tab's key to its data-platcard index,
// so other sections can deep-link into a specific 🗂️ Platforms card.
func platformCardIndex(res *result.AnalysisResult) map[langspec.Platform]int {
	platforms := orderedPlatformTabs(res)
	idx := make(map[langspec.Platform]int, len(platforms))
	for i, pg := range platforms {
		idx[pg.Platform] = i
	}
	return idx
}

// platformFolderNames returns the distinct top-level folders pg's files sit
// in (relative to rootPath), busiest (most files) first — used to hint at a
// language-grouped card's physical spread across a monorepo, since in that
// mode one card can span every folder in the tree.
func platformFolderNames(pg *scanner.PlatformGroup, rootPath string) []string {
	counts := map[string]int{}
	for _, f := range pg.Files {
		rel, err := filepath.Rel(rootPath, f.Path)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		if i := strings.IndexByte(rel, '/'); i > 0 {
			counts[rel[:i]]++
		}
	}
	if len(counts) == 0 {
		return nil
	}
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if counts[names[i]] != counts[names[j]] {
			return counts[names[i]] > counts[names[j]]
		}
		return names[i] < names[j]
	})
	return names
}

func renderTabs(res *result.AnalysisResult) string {
	platforms := orderedPlatformTabs(res)
	if len(platforms) == 0 {
		return `<p class="as-empty">No platform has enough code (&ge; 1,000 LOC) for a dedicated view.</p>`
	}

	loc := map[langspec.Platform]int{}
	for _, f := range res.Files {
		loc[langspec.Platform(f.Platform)] += f.LineCount
	}

	// Programming Culture level per platform, badged next to each card's stats.
	cultLevels := platformCultureLevels(res)

	// Collect summary cards from module panels for each platform.
	platCards := map[langspec.Platform][]modules.SummaryCard{}
	for _, panel := range res.ModulePanels {
		platCards[panel.Platform] = append(platCards[panel.Platform], panel.Cards...)
	}

	// Pre-compute per-platform stats shown in card headers: API count and
	// the dominant architecture signal. A detected client pattern (MVVM, MVI,
	// VIPER, …) is the most specific signal a platform can show, so it wins
	// over DDD% whenever both exist — e.g. Kotlin/Android has dddmodel data
	// (Domain Model covers Go/Python/Kotlin/Java) but its MVVM/MVI pattern is
	// the more informative headline, same as iOS/Swift (which has no
	// dddmodel at all) showing its client pattern today.
	type platHeaderStat struct {
		apiTotal     int    // -1 = no traffic data
		dddLabel     string // e.g. "78% DDD"
		patternLabel string // e.g. "90% VIPER" — a detected client arch pattern
	}
	headerStats := map[langspec.Platform]platHeaderStat{}
	for _, panel := range res.ModulePanels {
		hs := headerStats[panel.Platform]
		switch panel.ModuleID {
		case "traffic":
			if tr, ok := panel.RawResult.(traffic.Result); ok {
				n := len(tr.Inbound) + len(tr.Outbound)
				if n > hs.apiTotal {
					hs.apiTotal = n
				}
			}
		case "dddmodel":
			if r, ok := panel.RawResult.(dddmodel.Result); ok && r.HasData() && hs.dddLabel == "" {
				hs.dddLabel = fmt.Sprintf("%d%% DDD", r.DDDScore)
			}
		case "architecture":
			if r, ok := panel.RawResult.(arch.Result); ok && r.HasDetection() && hs.patternLabel == "" {
				if r.Mode == "client" && len(r.Patterns) > 0 {
					hs.patternLabel = fmt.Sprintf("%d%% %s", int(r.Patterns[0].Confidence*100+0.5), r.Patterns[0].Name)
				}
			}
		}
		headerStats[panel.Platform] = hs
	}

	autoOpen := len(platforms) <= 2

	var b strings.Builder
	b.WriteString(`<div style="display:flex;align-items:center;justify-content:space-between;margin-top:16px;margin-bottom:8px">`)
	b.WriteString(`<span class="as-sub">🗂️ Platforms</span>`)
	b.WriteString(`<button class="as-toggle" id="as-plat-unfold" style="font-size:12px;padding:4px 12px">Unfold All</button>`)
	b.WriteString(`</div>`)
	b.WriteString(`<div class="as-plat-cards">`)

	for i, pg := range platforms {
		lp := pg.LanguagePlatform
		if lp == "" {
			lp = pg.Platform
		}
		platLOC := loc[pg.Platform]
		abbr := platAbbr(lp)
		hs := headerStats[pg.Platform]

		openCls := ""
		if autoOpen {
			openCls = " as-plat-card--open"
		}
		fmt.Fprintf(&b, `<div class="as-plat-card%s" data-platcard="%d">`, openCls, i)

		// ── Card header (clickable summary row) ────────────────────────────
		// In folder-as-tab mode the tab IS a folder, so the pill carries the
		// folder name (the identifier that distinguishes tabs) and the name text
		// carries the language; otherwise the pill is the language abbreviation
		// and the name is the platform title.
		pillText, nameText := abbr, pg.TabLabel()
		if res.Scan.FolderAsTab && pg.Label != "" {
			pillText, nameText = pg.Label, langspec.PlatformTitle(lp)
		} else if folders := platformFolderNames(pg, res.RootPath); len(folders) > 0 {
			// Language grouping puts every file of this language in one card
			// regardless of folder, so — unlike the folder/gitrepo-as-tab case
			// above, where the pill already names the one folder — a card here
			// can span many folders. Name up to 3 (busiest first) so a huge
			// monorepo card still says roughly where its files live.
			shown := folders
			suffix := ""
			if len(shown) > 3 {
				shown, suffix = shown[:3], ", …"
			}
			nameText += " (" + strings.Join(shown, ", ") + suffix + ")"
		}
		b.WriteString(`<div class="as-plat-card__head">`)
		b.WriteString(`<div class="as-plat-card__summary">`)
		fmt.Fprintf(&b, `<span class="as-plat-card__abbr as-plat-%s">%s</span>`, esc(string(lp)), esc(pillText))
		fmt.Fprintf(&b, `<span class="as-plat-card__name">%s</span>`, esc(nameText))
		fmt.Fprintf(&b, `<span class="as-plat-card__loc">%s loc</span>`, fmtLOC(platLOC))
		fmt.Fprintf(&b, `<span class="as-plat-card__files">%d files</span>`, pg.FileCount)
		if hs.apiTotal > 0 {
			fmt.Fprintf(&b, `<span class="as-plat-card__stat as-plat-card__stat--api">%d APIs</span>`, hs.apiTotal)
		}
		archLabel := hs.patternLabel
		if archLabel == "" {
			archLabel = hs.dddLabel
		}
		if archLabel != "" {
			fmt.Fprintf(&b, `<span class="as-plat-card__stat as-plat-card__stat--arch">%s</span>`, esc(archLabel))
		}
		if lv, ok := cultLevels[pg.Platform]; ok {
			fmt.Fprintf(&b, `<span class="as-cult-lvl" style="background:%s22;color:%s;border-color:%s55" title="🔰 Programming Culture level">%s</span>`,
				lv.color, lv.color, lv.color, esc(lv.name))
		}
		b.WriteString(`</div>`) // .as-plat-card__summary
		b.WriteString(`<span class="as-plat-card__chevron">›</span>`)
		b.WriteString(`</div>`) // .as-plat-card__head

		// ── Card body (full platform panel) ───────────────────────────────
		// id="p{i}" keeps compatibility with existing JS that uses [id^="p"]
		fmt.Fprintf(&b, `<div class="as-plat-card__body" id="p%d">`, i)
		b.WriteString(`<div class="as-plat-view-toggle">` +
			`<button class="as-seg-btn as-seg-btn--active" data-view="html">HTML</button>` +
			`<button class="as-seg-btn" data-view="md">MD</button>` +
			`</div>`)
		b.WriteString(`<div class="as-plat-view as-plat-view--html">`)
		b.WriteString(renderPlatformPanel(res, pg))
		b.WriteString(`</div>`)
		fmt.Fprintf(&b, `<pre class="as-plat-view as-plat-view--md" style="display:none">%s</pre>`,
			esc(markdown.RenderPlatform(res, pg)))
		b.WriteString(`</div>`) // .as-plat-card__body
		b.WriteString(`</div>`) // .as-plat-card
	}

	b.WriteString(`</div>`) // .as-plat-cards
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
	// traffic, the "Programming Methods" constructs (design patterns, data
	// structures, algorithms — grouped after Domain Model), rest.
	var dddPanels, specPanels, trafficPanels, constructPanels, otherPanels []result.ModulePanel
	for _, p := range res.PanelsForPlatform(pg.Platform) {
		switch p.ModuleID {
		case "architecture":
			// rendered in the dedicated Architecture section above; skip
		case "codestructure", "langrichness", "memoryleaks":
			// rendered as their own subcards in 💡 Module Insights; skip
		case "dddmodel", "oopvspop":
			dddPanels = append(dddPanels, p)
		case "speccoverage":
			specPanels = append(specPanels, p)
		case "traffic":
			trafficPanels = append(trafficPanels, p)
		case "designpattern", "datastructures", "algorithms", "complexity", "magicconstants":
			constructPanels = append(constructPanels, p)
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
		fmt.Fprintf(&b, `<div class="as-section" id="%s"><div class="as-section__head">%s<span class="ico">🏛️</span><h3>Architecture</h3></div>`,
			esc(cultAnchorID("arch", pg.Platform)), badge)
		b.WriteString(layersHTML)
		b.WriteString(componentsHTML)
		b.WriteString(`</div>`)
	}

	// 2. 🎯 Domain Model
	b.WriteString(renderModulePanels(dddPanels, badge))

	// 2b. 🧠 Programming Methods — design patterns, data structures, algorithms
	b.WriteString(renderProgrammingMethods(constructPanels, badge))

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
	if len(trafficPanels) > 0 {
		b.WriteString(renderTrafficWithSpec(trafficPanels, specRes, badge, langspec.Default.IsClientPlatform(pg.Platform)))
	}

	// 5. 💡 Module Insights — Hotspots · Modules · TODOs · Longest Functions
	b.WriteString(renderModuleInsights(res, pg, files, res.RootPath, badge))

	// 7. 🐙 Git Analysis — per-platform churn + contributors
	b.WriteString(renderPlatformGit(res, pg, files, badge))

	// 8. 🛡️ Danger Details
	b.WriteString(renderPlatformSecurity(res, pg.Platform, badge))

	// 9. 📂 Modules & Microservices — per-platform file inventory. Only
	// included under --render-modules (its declaration graph is
	// CDN-loaded, and the section itself can be large for big platforms).
	if res.Scan.RenderModules {
		b.WriteString(renderModuleDetailsPlatform(res.RootPath, files, badge))
	}

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
func renderMicroservicesSection(pg *scanner.PlatformGroup, files []*parser.ParsedFile, renderModules bool) string {
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
		// #mod-<name> only exists when Modules & Microservices is actually
		// rendered; without --render-modules this is a plain, non-linking card.
		tag, attrs := "a", fmt.Sprintf(` href="#mod-%s"`, esc(anchorID(m)))
		if !renderModules {
			tag, attrs = "div", ""
		}
		fmt.Fprintf(&b, `<%s class="as-mod"%s><div class="as-mod__name">%s</div><div class="as-mod__meta">%d %s · %s loc</div></%s>`,
			tag, attrs, esc(name), counts[m], plural(counts[m], "file", "files"), fmtNum(mloc[m]), tag)
	}
	b.WriteString(`</div></div>`)
	return b.String()
}

// renderProgrammingMethods groups the language-agnostic "constructs" panels —
// Design Patterns, Data Structures, Algorithms — under a single "🧠 Programming
// Methods" header, rendered right after the Domain Model card. Panels arrive in
// module-Order sequence (designpattern → datastructures → algorithms).
func renderProgrammingMethods(panels []result.ModulePanel, headBadge string) string {
	if len(panels) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<div class="as-pm"><div class="as-pm__head">%s<span class="ico">🧠</span><h3>Programming Methods</h3></div>`, headBadge)
	b.WriteString(renderModulePanels(panels))
	b.WriteString(`</div>`)
	return b.String()
}

// renderModuleInsights groups Dependency Hotspots, Modules, TODOs & FIXMEs,
// and Longest Functions under a single "💡 Module Insights" header.
func renderModuleInsights(res *result.AnalysisResult, pg *scanner.PlatformGroup, files []*parser.ParsedFile, rootPath string, headBadge string) string {
	var parts []string
	if h := renderHotspots(res, pg); h != "" {
		parts = append(parts, h)
	}
	if m := renderMicroservicesSection(pg, files, res.Scan.RenderModules); m != "" {
		parts = append(parts, m)
	}
	if lr := renderLanguageRichnessInsight(res, pg); lr != "" {
		parts = append(parts, lr)
	}
	if cs := renderCodeStructureInsight(res, pg); cs != "" {
		parts = append(parts, cs)
	}
	if ml := renderMemoryLeaksInsight(res, pg); ml != "" {
		parts = append(parts, ml)
	}
	if t := renderTodosFixmes(files); t != "" {
		parts = append(parts, t)
	}
	if lf := renderLongestFunctions(files, rootPath, pg.Platform); lf != "" {
		parts = append(parts, lf)
	}
	if bt := renderBiggestTypes(files, rootPath, pg.Platform); bt != "" {
		parts = append(parts, bt)
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

// renderLanguageRichnessInsight renders the 🎖️ Language Richness module's
// panel — a simple keyword-coverage bar per language — as a Module Insights
// subcard, right before 💻 Code Structure.
func renderLanguageRichnessInsight(res *result.AnalysisResult, pg *scanner.PlatformGroup) string {
	for _, p := range res.PanelsForPlatform(pg.Platform) {
		if p.ModuleID != "langrichness" || strings.TrimSpace(p.HTML) == "" {
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, `<div class="as-section" id="%s"><div class="as-section__head"><span class="ico">🎖️</span><h3>Language Richness</h3></div>`,
			esc(modPanelID(p.Platform, p.ModuleID)))
		b.WriteString(p.HTML)
		b.WriteString(`</div>`)
		return b.String()
	}
	return ""
}

// renderCodeStructureInsight renders the 💻 Code Structure module's panel (low-
// level function/folder shape signals — parameter count, nesting depth,
// comment density, folder-layout smells) as a Module Insights subcard, right
// after 📦 Modules. Rendered here rather than through the generic per-platform
// module-panel walk (like Programming Methods) because Module Insights is
// hand-assembled to a fixed order.
func renderCodeStructureInsight(res *result.AnalysisResult, pg *scanner.PlatformGroup) string {
	for _, p := range res.PanelsForPlatform(pg.Platform) {
		if p.ModuleID != "codestructure" || strings.TrimSpace(p.HTML) == "" {
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, `<div class="as-section" id="%s"><div class="as-section__head"><span class="ico">💻</span><h3>Code Structure</h3></div>`,
			esc(modPanelID(p.Platform, p.ModuleID)))
		b.WriteString(p.HTML)
		b.WriteString(`</div>`)
		return b.String()
	}
	return ""
}

// renderMemoryLeaksInsight renders the 💧 Memory Leaks module's panel
// (unclosed handles, unstopped timers, unjoined threads, un-freed C
// allocations, leaked JS listeners/observers, Swift retain-cycle-prone
// closures) as a Module Insights subcard, right after 💻 Code Structure.
func renderMemoryLeaksInsight(res *result.AnalysisResult, pg *scanner.PlatformGroup) string {
	for _, p := range res.PanelsForPlatform(pg.Platform) {
		if p.ModuleID != "memoryleaks" || strings.TrimSpace(p.HTML) == "" {
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, `<div class="as-section" id="%s"><div class="as-section__head"><span class="ico">💧</span><h3>Memory Leaks</h3></div>`,
			esc(modPanelID(p.Platform, p.ModuleID)))
		b.WriteString(p.HTML)
		b.WriteString(`</div>`)
		return b.String()
	}
	return ""
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
			if pmap[f.FullPath] == plat && !security.IsTestPath(f.FullPath) {
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
		fmt.Fprintf(&b, `<div class="as-section as-danger-section" id="%s"><div class="as-section__head">%s<span class="ico">🛡️</span><h3>Danger Details</h3></div>`,
			esc(cultAnchorID("danger", plat)), headBadge)
		b.WriteString(`<p class="as-clean">✓ No findings in this platform's sources.</p></div>`)
		return b.String()
	}
	fmt.Fprintf(&b,
		`<div class="as-section as-danger-section" id="%s"><div class="as-section__head">%s<span class="ico">🛡️</span><h3>Danger Details</h3>`+
			`<span style="margin-left:10px;font-size:12px;font-weight:400">`+
			`<span class="as-sev sev-high">HIGH %d</span> `+
			`<span class="as-sev sev-medium">MED %d</span> `+
			`<span class="as-sev sev-low">LOW %d</span>`+
			`</span></div>`,
		esc(cultAnchorID("danger", plat)), headBadge, hi, med, lo)
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
		fmt.Fprintf(&b, `<div class="as-section as-modpanel" id="%s">`, esc(modPanelID(p.Platform, p.ModuleID)))
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

// renderTrafficWithSpec renders the traffic panels with a 🩺 Traffic Health
// summary on top and, when spec is available, an extra SPEC COV column (✅ in
// spec · ❓ undocumented) on inbound routes. spec may be nil (no spec files
// found) — the SPEC COV column and Traffic Health's Documentation sub-score
// are simply omitted in that case.
func renderTrafficWithSpec(panels []result.ModulePanel, spec *speccoverage.Result, badge string, isClientPlatform bool) string {
	// Build a set of normalised paths for spec-covered operations.
	var coveredPaths map[string]bool
	if spec != nil {
		coveredPaths = map[string]bool{}
		for _, op := range spec.Covered {
			coveredPaths[normSpecURI(op.Path)] = true
		}
	}

	var b strings.Builder
	for _, p := range panels {
		tr, ok := p.RawResult.(traffic.Result)
		if !ok {
			// Fallback: render without SPEC COV column or Traffic Health.
			fmt.Fprintf(&b, `<div class="as-section as-modpanel" id="%s">`, esc(modPanelID(p.Platform, p.ModuleID)))
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

		fmt.Fprintf(&b, `<div class="as-section as-modpanel" id="%s">`, esc(modPanelID(p.Platform, p.ModuleID)))
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

		th, thOK := computeTrafficHealth(tr, spec, isClientPlatform)
		b.WriteString(renderTrafficHealthBlock(th, thOK))

		// Inbound with SPEC COV column when spec data is available.
		renderSpecTrafficTable(&b, "📥 Inbound", tr.Inbound, coveredPaths, spec != nil)
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
	b.WriteString(`<th>Protocol</th><th>URI / Pattern</th><th>Data</th>`)
	if showSpecCov {
		b.WriteString(`<th>Spec</th>`)
	}
	b.WriteString(`<th>File</th><th>Module</th>`)
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
			specIcon := `<span title="Spec not located — this route has no matching entry in any spec file">❓</span>`
			if coveredPaths[normSpecURI(e.URI)] {
				specIcon = `<span title="Spec covered — this route is documented in a spec file">✅</span>`
			}
			fmt.Fprintf(b,
				`<tr><td>%s</td><td class="mono">%s</td><td class="mono">%s</td><td style="text-align:center">%s</td><td class="mono">%s</td><td class="mono">%s</td></tr>`,
				trafficProtoTag(e.Protocol), esc(uri), esc(dataCell), specIcon, trafficFileLinksFor(e), esc(mod),
			)
		} else {
			fmt.Fprintf(b,
				`<tr><td>%s</td><td class="mono">%s</td><td class="mono">%s</td><td class="mono">%s</td><td class="mono">%s</td></tr>`,
				trafficProtoTag(e.Protocol), esc(uri), esc(dataCell), trafficFileLinksFor(e), esc(mod),
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

// trafficMaxFileLinksShown mirrors traffic.maxFileLinksShown for this
// package's own copy of the file-links renderer.
const trafficMaxFileLinksShown = 4

// trafficFileLinksFor renders every location a deduplicated Entry was seen at
// (its primary FilePath/Line plus any Extra occurrences) as a comma-separated
// list of vscode:// links, capped at trafficMaxFileLinksShown. Mirrors
// traffic.fileLinksFor so the SPEC COV variant of the table reads the same
// data the same way.
func trafficFileLinksFor(e traffic.Entry) string {
	if e.FilePath == "" {
		return "—"
	}
	total := 1 + len(e.Extra)
	shown := min(total, trafficMaxFileLinksShown)
	links := make([]string, 0, shown)
	links = append(links, trafficFileLink(e.FilePath, e.Line))
	for i := 0; i < len(e.Extra) && len(links) < shown; i++ {
		links = append(links, trafficFileLink(e.Extra[i].FilePath, e.Extra[i].Line))
	}
	out := strings.Join(links, ", ")
	if total > shown {
		out += fmt.Sprintf(` <span style="color:var(--text-faint)">+%d more</span>`, total-shown)
	}
	return out
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
	case "datastructures":
		return "🌳"
	case "algorithms":
		return "🔀"
	case "complexity":
		return "🅾️"
	case "magicconstants":
		return "🪄"
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
				parts = append(parts, kindLabel(k, n, string(m.plat)))
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
			b.WriteString(`<table class="as-table as-file-table"><thead><tr><th style="width:50%">File</th><th>Lines</th><th>Tokens</th><th>Decl</th><th>Declarations</th></tr></thead><tbody>`)
			for _, f := range keep {
				b.WriteString(fileTableRow(f, rootPath))
			}
			b.WriteString(`</tbody></table>`)
		}
		if len(genFiles) > 0 {
			b.WriteString(`<div class="as-sub as-gen-sub">Code Generated</div>`)
			b.WriteString(`<table class="as-table as-file-table"><thead><tr><th style="width:50%">File</th><th>Lines</th><th>Tokens</th><th>Decl</th><th>Declarations</th></tr></thead><tbody>`)
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
	b.WriteString(`<div class="as-sub">🌿 Branching Model</div>`)
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
	b.WriteString(`<div><div class="as-sub">👥 Top Contributors</div>`)
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
	b.WriteString(`<div><div class="as-sub">🔥 File Churn</div>`)
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
	b.WriteString(`<div><div class="as-sub">🏷️ Releases &amp; Commit Hygiene</div>`)
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
	b.WriteString(`<div><div class="as-sub">🌳 Branches</div>`)
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
// isTestFile reports whether path is test or benchmark code — filename
// suffixes across every language ArchScope parses, plus directory components
// like "Tests/"/"Benchmarks/" that a filename suffix alone would miss (see
// security.IsTestOrBenchPath).
func isTestFile(path string) bool {
	if security.IsTestOrBenchPath(path) {
		return true
	}
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
			`<div class="as-section__head"><span class="ico">🔗</span><h3>VS Code Links</h3>`+
			`<button id="as-link-toggle" class="as-toggle" style="margin-left:auto;font-size:12px" title="Switch VS Code ↔ Git links">🔗 VS Code</button></div>`+
			`<p class="as-section__sub" id="as-vs-desc">Edit the path prefix for <code>vscode://</code> links — useful when sharing this report.</p>`+
			// VS Code path row (visible in VS Code mode)
			`<div id="as-vs-path-row" style="display:flex;gap:8px;align-items:center;margin-top:10px;flex-wrap:wrap">`+
			`<input id="as-vs-path" type="text" value="%s" data-orig="%s"`+
			` style="flex:1;min-width:200px;padding:6px 10px;background:var(--bg-inset);border:1px solid var(--border);`+
			`border-radius:6px;color:var(--text);font-family:var(--mono);font-size:12px;outline:none">`+
			`<button id="as-vs-btn" class="as-toggle" style="white-space:nowrap">Change Path</button>`+
			`<span id="as-vs-msg" style="font-size:12px;color:var(--text-faint)"></span>`+
			`</div>`+
			// Git URL row (visible in Git mode)
			`<div id="as-vs-git-row" style="display:none;margin-top:10px">`+
			`<span style="font-size:12px;color:var(--text-faint)">Remote URL: </span>`+
			`<a id="as-vs-git-url" href="#" target="_blank" style="font-family:var(--mono);font-size:12px"></a>`+
			`</div>`+
			`</div>`,
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

func kindLabel(k parser.DeclKind, n int, langID string) string {
	one, many := string(k), string(k)+"s"
	switch k {
	case parser.DeclInterface:
		if langID == "swift" || langID == "objc" {
			one, many = "protocol", "protocols"
		} else {
			one, many = "interface", "interfaces"
		}
	case parser.DeclClass:
		one, many = "class", "classes"
	case parser.DeclFunc:
		one, many = "func", "funcs"
	}
	return fmt.Sprintf("%s %d %s", kindIcon(k), n, plural(n, one, many))
}

// fmtTokens estimates LLM tokens for a file using ~12 tokens/line (≈48 chars/line ÷ 4).
func fmtTokens(lines int) string {
	n := lines * 12
	if n >= 1000 {
		return fmt.Sprintf("~%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("~%d", n)
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
	return fmt.Sprintf(`<tr><td>%s</td><td class="mono">%d</td><td class="mono">%s</td><td class="mono">%d</td><td class="as-decl-tags">%s</td></tr>`,
		fileCell, f.LineCount, fmtTokens(f.LineCount), len(f.Declarations), declTags(f.FilePath, f.Declarations))
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

// modPanelID builds the DOM id given to a per-platform report-module panel
// (renderModulePanels, renderTrafficWithSpec) — unique per (platform,
// moduleID) pair, since each report module runs at most once per platform.
// Programming Culture's dimension-detail links (see culture.go) target these
// ids via the generic "open ancestor platform card + scroll to id" JS handler
// (data-panel-target), so a click jumps straight to the specific card that
// produced the number, not just the platform tab in general.
func modPanelID(plat langspec.Platform, moduleID string) string {
	return "modpanel-" + anchorID(moduleID) + "-" + anchorID(string(plat))
}

// cultAnchorID builds the DOM id for a per-platform section that isn't a
// generic report-module panel (Architecture, 🎖️ Language Richness, 💻 Code
// Structure, 📏 Longest Functions, 📐 Biggest Types, 🛡️ Danger Details) —
// same purpose as modPanelID, for sections rendered by hand rather than
// through renderModulePanels.
func cultAnchorID(kind string, plat langspec.Platform) string {
	return "cult-" + anchorID(kind) + "-" + anchorID(string(plat))
}
