// Package dddmodel detects whether a codebase follows a Domain-Driven Design
// (DDD) rich domain model or an Anemic Domain Model — the data-bag + service-
// layer anti-pattern described by Martin Fowler.
//
// Two complementary detection strategies are combined so the module works for
// both Java/Kotlin-style (suffix conventions: *Entity, *Repository …) and
// Go/Python-style (package/directory conventions: aggregate/, entity/, vo/ …):
//
//  1. Directory-role detection — a file inside aggregate/, entity/, valueobject/,
//     event/, repository/, or usecase/ has ALL its type declarations attributed
//     to that DDD role without requiring a matching suffix.
//
//  2. Suffix-based detection — the classic Java/Kotlin/Python signals
//     (*Entity, *Repository, *DomainEvent, *Factory, *EventHandler …) are
//     checked for files not covered by a directory role.
//
// Weighted dimensions (configurable via Config):
//
//   - Rich Domain Types  40% — aggregates(×2) + entities + VOs vs DAO/DTO/Manager/BO/DO/PO
//   - Tactical Patterns  35% — up to 7 patterns (Repository, DomainEvent, DomainService,
//     Specification, UseCase, Factory, EventHandler); score capped at 100% so 5 of 7 = full
//   - Layer Separation   25% — /domain/, /infra/, /application/, port/adapter vs /dao/ paths
//
// Go monorepo paths /pkg/domain and /internal/domain are detected both via the
// single-segment "domain" entry in domainSegs and via explicit consecutive-pair
// matching (pathHas2), so neither spelling is ever missed.
//
// Test files (*_test.go, testdata/) are excluded from analysis to prevent
// test fixtures from distorting scores.
//
// # Custom configuration
//
//	modules.Default.Register(dddmodel.Module{Cfg: dddmodel.Config{
//	    WeightRichTypes: 0.50,
//	    WeightTactical:  0.30,
//	    WeightLayer:     0.20,
//	    ThresholdStrong: 70,
//	}})
package dddmodel

import (
	"fmt"
	"html"
	"strings"

	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
)

// Config tunes weights and verdict thresholds. Zero-value falls back to
// DefaultConfig via Module.cfg().
type Config struct {
	WeightRichTypes  float64 // default 0.40 — must sum to 1.0 with the other two
	WeightTactical   float64 // default 0.35
	WeightLayer      float64 // default 0.25
	ThresholdStrong  int     // ≥ → "Strong Rich Domain Model",  default 65
	ThresholdLeaning int     // ≥ → "Leaning DDD",              default 50
	ThresholdMixed   int     // ≥ → "Transitional / Mixed",     default 40
	ThresholdAnemic  int     // ≥ → "Leaning Anemic",           default 25
}

// DefaultConfig is the out-of-box configuration.
var DefaultConfig = Config{
	WeightRichTypes:  0.40,
	WeightTactical:   0.35,
	WeightLayer:      0.25,
	ThresholdStrong:  65,
	ThresholdLeaning: 50,
	ThresholdMixed:   40,
	ThresholdAnemic:  25,
}

func init() { modules.Default.Register(Module{Cfg: DefaultConfig}) }

// Module is the DDD vs. Anemic Domain Model analyzer.
type Module struct {
	Cfg Config
}

// cfg returns the effective config, falling back to defaults when the struct
// is zero-valued (i.e. all weights are 0.0).
func (m Module) cfg() Config {
	c := m.Cfg
	if c.WeightRichTypes == 0 && c.WeightTactical == 0 && c.WeightLayer == 0 {
		return DefaultConfig
	}
	if c.ThresholdStrong == 0 {
		c.ThresholdStrong = DefaultConfig.ThresholdStrong
	}
	if c.ThresholdLeaning == 0 {
		c.ThresholdLeaning = DefaultConfig.ThresholdLeaning
	}
	if c.ThresholdMixed == 0 {
		c.ThresholdMixed = DefaultConfig.ThresholdMixed
	}
	if c.ThresholdAnemic == 0 {
		c.ThresholdAnemic = DefaultConfig.ThresholdAnemic
	}
	return c
}

func (Module) ID() string    { return "dddmodel" }
func (Module) Title() string { return "Domain Model" }

// AppliesTo runs for backend languages only.
func (Module) AppliesTo(languageID string) bool {
	switch languageID {
	case "go", "python", "kotlin":
		return true
	}
	return false
}

// ── Path segment sets ──────────────────────────────────────────────────────

// domainSegs covers explicit domain layers AND role-named directories so that
// Go-style repos (percybolmer/ddd-go: top-level aggregate/, entity/, …) also
// get HasDomainPath = true.
//
// Note: /pkg/domain/ and /internal/domain/ are matched both via the "domain"
// entry here (pathHas checks each segment individually) AND via the explicit
// domainPairs list (pathHas2 checks consecutive pairs). The dual check is
// belt-and-suspenders — either mechanism alone would be sufficient.
var domainSegs = []string{
	"domain", "domains",
	"model",                   // common in Go DDD (singular only — avoids /models/ in Django)
	"core", "business", "biz", // go-kratos / Clean Architecture conventions
	"aggregate", "aggregates",
	"entity", "entities",
	"valueobject", "valueobjects", "value_object", "value_objects", "vo",
	// Note: "event" / "events" are intentionally absent — a top-level events/
	// directory is often a generic event-bus package, not a domain layer.
	// Types inside event/ are still classified via eventDirSegs + roleEvent;
	// they just don't set HasDomainPath on their own.
}

// domainPairs are consecutive two-segment path patterns common in Go monorepos.
// Checked in addition to domainSegs so the intent is explicit in the source.
var domainPairs = [][2]string{
	{"pkg", "domain"}, {"pkg", "domains"},
	{"internal", "domain"}, {"internal", "domains"},
}

var infraSegs = []string{
	"infrastructure", "infra",
	"persistence",
	"db",
	"data", // go-kratos: internal/data is the persistence layer
	"repo", // shorthand seen in many Go projects
	"repository", "repositories",
}

var appSegs = []string{"application", "app"}

var hexSegs = []string{
	"port", "ports",
	"adapter", "adapters",
	"primary", "secondary",
	"driving", "driven",
}

var anemicSegs = []string{"dao", "dto", "mapper", "assembler"}

// Role-specific directory sets used by detectDirRole (more precise than domainSegs).
var (
	aggregateDirSegs = []string{"aggregate", "aggregates"}
	entityDirSegs    = []string{"entity", "entities"}
	voDirSegs        = []string{"valueobject", "valueobjects", "value_object", "value_objects", "vo"}
	eventDirSegs     = []string{"event", "events", "domain_event", "domain_events"}
	repoDirSegs      = []string{"repository", "repositories"}
	usecaseDirSegs   = []string{"usecase", "usecases", "use_case", "use_cases"}
)

// Service directories where a plain *Service suffix is treated as a domain service.
var serviceDirSegs = []string{"service", "services"}

// ── Directory-role detection ───────────────────────────────────────────────

type dirRole uint8

const (
	roleNone      dirRole = iota
	roleAggregate         // files in aggregate/ → all types are aggregates
	roleEntity            // files in entity/    → all types are entities
	roleVO                // files in vo/        → all types are value objects
	roleEvent             // files in event/     → all types are domain events
	roleRepo              // files in repository/→ all types are repositories
	roleUseCase           // files in usecase/   → all types are use cases
)

// detectDirRole returns the DDD role implied by the file's directory, or
// roleNone when no known role directory is found. Aggregate is checked before
// entity so that an aggregate/ inside a domain/ directory wins.
func detectDirRole(pathL string) dirRole {
	switch {
	case pathHas(pathL, aggregateDirSegs...):
		return roleAggregate
	case pathHas(pathL, entityDirSegs...):
		return roleEntity
	case pathHas(pathL, voDirSegs...):
		return roleVO
	case pathHas(pathL, eventDirSegs...):
		return roleEvent
	case pathHas(pathL, repoDirSegs...):
		return roleRepo
	case pathHas(pathL, usecaseDirSegs...):
		return roleUseCase
	}
	return roleNone
}

// ── Result ─────────────────────────────────────────────────────────────────

// Result is the full analyzer output.
type Result struct {
	// Rich domain type markers — DDD-positive
	EntitiesCount  int // *Entity  or  file in entity/
	VOCount        int // *ValueObject / *VO  or  file in valueobject/vo/
	AggregateCount int // *AggregateRoot / *Aggregate  or  file in aggregate/

	// Tactical DDD patterns
	DomainEvtCount    int // *DomainEvent  or  file in event/
	RepositoryCount   int // *Repository   or  file in repository/
	DomainSvcCount    int // *DomainService, *Service in domain/service/ dir
	SpecCount         int // *Specification / *Spec
	UseCaseCount      int // *UseCase / *ApplicationService  or  file in usecase/
	FactoryCount      int // *Factory — DDD creation pattern
	EventHandlerCount int // *EventHandler — application-layer event subscriber

	// Anemic markers — DDD-negative (scored)
	DAOCount     int // *DAO, *Dao
	DTOCount     int // *DTO, *Dto
	ManagerCount int // *Manager
	BOCount      int // *BO  (Business Object — classic anemic layer)
	DOCount      int // *DO  (Data Object)
	POCount      int // *PO  (Persistence Object)

	// Informational only — not included in anemicW score
	// *Model is neutral-to-positive in Go/Python (domain model or ORM entity)
	ModelCount int

	// Layer structure (path-based)
	HasDomainPath bool // /domain/, /aggregate/, /entity/, /biz/, …
	HasInfraPath  bool // /infrastructure/, /persistence/, /db/, /data/, …
	HasAppPath    bool // /application/, /app/
	HasHexagonal  bool // /port/, /adapter/, /primary/, /secondary/, …
	HasDAOPath    bool // /dao/, /dto/, /mapper/, /assembler/

	// Evidence: up to 3 found type names per pattern (for report display)
	ExEntity       []string
	ExVO           []string
	ExAgg          []string
	ExEvent        []string
	ExRepo         []string
	ExDomSvc       []string
	ExSpec         []string
	ExUseCase      []string
	ExFactory      []string
	ExEventHandler []string
	ExDAO          []string
	ExDTO          []string
	ExManager      []string
	ExBO           []string
	ExDO           []string
	ExPO           []string
	ExModel        []string

	BackendFiles int
	TotalTypes   int

	// True when rich and anemic naming counts are BOTH zero — the 50% neutral
	// fallback is then displayed with an explanatory note instead of silently.
	NoNamingEvidence bool

	// Scores 0..100
	RichScore     int
	TacticalScore int
	LayerScore    int
	DDDScore      int

	Verdict string
}

// HasData reports whether there are non-test backend files to analyze.
func (r Result) HasData() bool { return r.BackendFiles > 0 }

// isTypeLike returns true for declaration kinds that represent named types.
func isTypeLike(k parser.DeclKind) bool {
	switch k {
	case parser.DeclStruct, parser.DeclClass, parser.DeclInterface,
		parser.DeclEnum, parser.DeclType:
		return true
	}
	return false
}

// isTestPath reports whether a (lowercased, forward-slashed) file path is a
// test artifact that should be excluded from DDD analysis.
func isTestPath(pathL string) bool {
	return strings.HasSuffix(pathL, "_test.go") ||
		strings.Contains(pathL, "/testdata/") ||
		strings.Contains(pathL, "/__tests__/") ||
		strings.Contains(pathL, "/test_") // Python test_ prefix at dir level
}

// ── Analyze ────────────────────────────────────────────────────────────────

// dirCtx bundles the per-directory signals computed once and reused for every
// file that lives in the same directory.
type dirCtx struct {
	role         dirRole
	inDomainFile bool
	inServiceDir bool
}

func (m Module) Analyze(files []*parser.ParsedFile) any {
	var r Result
	cfg := m.cfg()

	// Cache dirCtx keyed on the directory prefix of each lowercased file path.
	// Files in the same directory share identical path-based signals, so we
	// avoid recomputing pathHas / detectDirRole for every file.
	ctxCache := make(map[string]dirCtx)

	for _, f := range files {
		pathL := strings.ToLower(strings.ReplaceAll(f.FilePath, "\\", "/"))
		if isTestPath(pathL) {
			continue // skip test fixtures — they distort naming-based scores
		}
		r.BackendFiles++

		// ── Layer path signals ────────────────────────────────────────────────
		if pathHas(pathL, domainSegs...) || pathHas2(pathL, domainPairs...) {
			r.HasDomainPath = true
		}
		if pathHas(pathL, infraSegs...) {
			r.HasInfraPath = true
		}
		if pathHas(pathL, appSegs...) {
			r.HasAppPath = true
		}
		if pathHas(pathL, hexSegs...) {
			r.HasHexagonal = true
		}
		if pathHas(pathL, anemicSegs...) {
			r.HasDAOPath = true
		}

		// ── Per-directory context (cached) ────────────────────────────────────
		dir := pathL[:strings.LastIndex(pathL, "/")+1]
		ctx, cached := ctxCache[dir]
		if !cached {
			ctx = dirCtx{
				role:         detectDirRole(pathL),
				inDomainFile: pathHas(pathL, domainSegs...) || pathHas2(pathL, domainPairs...),
				inServiceDir: pathHas(pathL, serviceDirSegs...),
			}
			ctxCache[dir] = ctx
		}
		role := ctx.role
		inDomainFile := ctx.inDomainFile
		inServiceDir := ctx.inServiceDir

		// ── Declaration signals ───────────────────────────────────────────────
		for _, d := range f.Declarations {
			if !isTypeLike(d.Kind) {
				continue
			}
			r.TotalTypes++
			n := d.Name

			// ── 1. Directory-role detection (Go/Python package convention) ──
			// A type in aggregate/, entity/, etc. is attributed to that role
			// unless its name already carries an explicit anemic suffix
			// (e.g. OrderDTO inside entity/ stays DTO, not an entity).
			if role != roleNone && !hasAnemicSuffix(n) {
				switch role {
				case roleAggregate:
					r.AggregateCount++
					r.ExAgg = addEx(r.ExAgg, n)
				case roleEntity:
					r.EntitiesCount++
					r.ExEntity = addEx(r.ExEntity, n)
				case roleVO:
					r.VOCount++
					r.ExVO = addEx(r.ExVO, n)
				case roleEvent:
					r.DomainEvtCount++
					r.ExEvent = addEx(r.ExEvent, n)
				case roleRepo:
					r.RepositoryCount++
					r.ExRepo = addEx(r.ExRepo, n)
				case roleUseCase:
					r.UseCaseCount++
					r.ExUseCase = addEx(r.ExUseCase, n)
				}
				continue // directory role wins; skip suffix detection
			}

			// ── 2. Suffix-based detection (Java/Kotlin/Python convention) ───
			switch {
			// Rich domain types
			case ws(n, "Entity"):
				r.EntitiesCount++
				r.ExEntity = addEx(r.ExEntity, n)

			case ws(n, "ValueObject"), ws(n, "VO"):
				r.VOCount++
				r.ExVO = addEx(r.ExVO, n)

			case ws(n, "AggregateRoot"), ws(n, "Aggregate"):
				r.AggregateCount++
				r.ExAgg = addEx(r.ExAgg, n)

			// Tactical patterns — more-specific suffixes must come before generic ones
			case ws(n, "DomainEvent"):
				r.DomainEvtCount++
				r.ExEvent = addEx(r.ExEvent, n)

			case ws(n, "Repository"):
				r.RepositoryCount++
				r.ExRepo = addEx(r.ExRepo, n)

			case ws(n, "DomainService"):
				r.DomainSvcCount++
				r.ExDomSvc = addEx(r.ExDomSvc, n)

			case ws(n, "Specification"), ws(n, "Spec"):
				r.SpecCount++
				r.ExSpec = addEx(r.ExSpec, n)

			case ws(n, "UseCase"):
				r.UseCaseCount++
				r.ExUseCase = addEx(r.ExUseCase, n)

			case ws(n, "ApplicationService"):
				r.UseCaseCount++
				r.ExUseCase = addEx(r.ExUseCase, n)

			case ws(n, "Factory"):
				r.FactoryCount++
				r.ExFactory = addEx(r.ExFactory, n)

			case ws(n, "EventHandler"):
				r.EventHandlerCount++
				r.ExEventHandler = addEx(r.ExEventHandler, n)

			case ws(n, "Service"):
				// Ambiguous — count only when inside a domain or service directory.
				if inDomainFile || inServiceDir {
					r.DomainSvcCount++
					r.ExDomSvc = addEx(r.ExDomSvc, n)
				}

			// Anemic markers — only uppercase/mixed-case acronyms to avoid
			// false positives (ToDo → "Do", Combo → "Bo", Turbo → "bo" …).
			case ws(n, "DAO"), ws(n, "Dao"):
				r.DAOCount++
				r.ExDAO = addEx(r.ExDAO, n)

			case ws(n, "DTO"), ws(n, "Dto"):
				r.DTOCount++
				r.ExDTO = addEx(r.ExDTO, n)

			case ws(n, "Manager"):
				r.ManagerCount++
				r.ExManager = addEx(r.ExManager, n)

			case ws(n, "BO"): // uppercase only — avoids Combo, Turbo, etc.
				r.BOCount++
				r.ExBO = addEx(r.ExBO, n)

			case ws(n, "DO"): // uppercase only — avoids ToDo, etc.
				r.DOCount++
				r.ExDO = addEx(r.ExDO, n)

			case ws(n, "PO"): // uppercase only — avoids typo collision
				r.POCount++
				r.ExPO = addEx(r.ExPO, n)

			case ws(n, "Model"):
				// *Model is neutral-to-positive in Go/Python: tracked for
				// display but NOT included in anemicW scoring.
				r.ModelCount++
				r.ExModel = addEx(r.ExModel, n)
			}
		}
	}

	// ── Rich Domain Types (WeightRichTypes) ─────────────────────────────────
	// Aggregates weighted ×2 — the primary DDD consistency boundary.
	// Falls back to 0.5 (neutral) when NEITHER side has naming evidence; that
	// state is flagged via NoNamingEvidence so the report can note it.
	richW := r.EntitiesCount + r.VOCount + 2*r.AggregateCount
	anemicW := r.DAOCount + r.DTOCount + r.ManagerCount + r.BOCount + r.DOCount + r.POCount
	// Note: ModelCount intentionally excluded from anemicW.
	rich01 := 0.5
	if richW+anemicW > 0 {
		rich01 = float64(richW) / float64(richW+anemicW)
	} else {
		r.NoNamingEvidence = true
	}

	// ── Tactical DDD Patterns (WeightTactical) ──────────────────────────────
	// 7 patterns × 0.2 each; capped at 1.0 so 5-of-7 = full score.
	// Factory and EventHandler are positive extras — having any 5 of the 7
	// is considered complete tactical coverage.
	tactical01 := 0.0
	if r.RepositoryCount > 0 {
		tactical01 += 0.2
	}
	if r.DomainEvtCount > 0 {
		tactical01 += 0.2
	}
	if r.DomainSvcCount > 0 {
		tactical01 += 0.2
	}
	if r.SpecCount > 0 {
		tactical01 += 0.2
	}
	if r.UseCaseCount > 0 {
		tactical01 += 0.2
	}
	if r.FactoryCount > 0 {
		tactical01 += 0.2
	}
	if r.EventHandlerCount > 0 {
		tactical01 += 0.2
	}
	if tactical01 > 1.0 {
		tactical01 = 1.0
	}

	// ── Layer Separation (WeightLayer) ──────────────────────────────────────
	layer01 := 0.0
	if r.HasDomainPath {
		layer01 += 0.40
	}
	if r.HasInfraPath {
		layer01 += 0.30
	}
	if r.HasAppPath {
		layer01 += 0.20
	}
	if r.HasHexagonal {
		layer01 += 0.10
	}
	if !r.HasDAOPath {
		layer01 += 0.05 // bonus: absence of anemic path structure
	}
	if r.HasDAOPath {
		layer01 -= 0.30
	}
	// Penalty: no domain path AND no rich type names → likely no DDD intent.
	if !r.HasDomainPath && richW == 0 {
		layer01 -= 0.20
	}
	layer01 = clamp01(layer01)

	r.RichScore = pct(rich01)
	r.TacticalScore = pct(tactical01)
	r.LayerScore = pct(layer01)
	ddd := cfg.WeightRichTypes*rich01 + cfg.WeightTactical*tactical01 + cfg.WeightLayer*layer01
	r.DDDScore = pct(ddd)

	// "No Domain Model Detected" is distinct from "Strong Anemic Model":
	// the anemic verdict implies behavior-less entities with a service layer,
	// whereas no naming evidence + no domain path + no tactical patterns means
	// the codebase simply has no discernible domain model at all (e.g. a
	// framework, a utility library, or a project too small to classify).
	if r.NoNamingEvidence && !r.HasDomainPath && tactical01 == 0 {
		r.Verdict = "No Domain Model Detected"
	} else {
		switch {
		case r.DDDScore >= cfg.ThresholdStrong:
			r.Verdict = "Strong Rich Domain Model"
		case r.DDDScore >= cfg.ThresholdLeaning:
			r.Verdict = "Leaning DDD"
		case r.DDDScore >= cfg.ThresholdMixed:
			r.Verdict = "Transitional / Mixed"
		case r.DDDScore >= cfg.ThresholdAnemic:
			r.Verdict = "Leaning Anemic"
		default:
			r.Verdict = "Strong Anemic Model"
		}
	}
	return r
}

// ── SummaryCards ───────────────────────────────────────────────────────────

func (m Module) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(Result)
	if !ok || !r.HasData() {
		return nil
	}
	return []modules.SummaryCard{
		{Num: fmt.Sprintf("%d%%", r.DDDScore), Label: "domain richness"},
	}
}

// ── RenderMarkdown ─────────────────────────────────────────────────────────

func (m Module) RenderMarkdown(res any) string {
	r, ok := res.(Result)
	if !ok || !r.HasData() {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**DDD Score: %d%%** — %s\n\n", r.DDDScore, r.Verdict)

	type pat struct {
		label    string
		count    int
		examples []string
	}
	rows := []pat{
		{"Aggregates", r.AggregateCount, r.ExAgg},
		{"Entities", r.EntitiesCount, r.ExEntity},
		{"Value Objects", r.VOCount, r.ExVO},
		{"Domain Events", r.DomainEvtCount, r.ExEvent},
		{"Repositories", r.RepositoryCount, r.ExRepo},
		{"Domain Services", r.DomainSvcCount, r.ExDomSvc},
		{"Use Cases", r.UseCaseCount, r.ExUseCase},
		{"Factories", r.FactoryCount, r.ExFactory},
		{"Specifications", r.SpecCount, r.ExSpec},
		{"Event Handlers", r.EventHandlerCount, r.ExEventHandler},
	}
	b.WriteString("| Pattern | Count | Examples |\n")
	b.WriteString("|---------|------:|---------|\n")
	for _, row := range rows {
		if row.count == 0 {
			continue
		}
		ex := strings.Join(row.examples, ", ")
		fmt.Fprintf(&b, "| %s | %d | %s |\n", row.label, row.count, ex)
	}
	b.WriteString("\n")
	return b.String()
}

// ── RenderHTML ─────────────────────────────────────────────────────────────

func (m Module) RenderHTML(res any) string {
	r, ok := res.(Result)
	if !ok {
		return ""
	}
	if !r.HasData() {
		return `<p class="as-empty">No backend files found for Domain Model analysis.</p>`
	}

	cfg := m.cfg()
	ddd := r.DDDScore
	var b strings.Builder

	b.WriteString(`<div class="as-pop">`)
	fmt.Fprintf(&b,
		`<p class="as-pop__sub">Domain model signal across %d types · Rich Types %.0f%% · Tactical Patterns %.0f%% · Layer Separation %.0f%%</p>`,
		r.TotalTypes,
		cfg.WeightRichTypes*100, cfg.WeightTactical*100, cfg.WeightLayer*100)
	fmt.Fprintf(&b, `<div class="as-pop__verdict">%s</div>`, esc(r.Verdict))

	// Gradient spectrum bar: red (Anemic) → orange (Mixed) → green (DDD).
	b.WriteString(`<div class="as-pop__scale"><span class="as-pop__end">◀ Anemic</span>`)
	fmt.Fprintf(&b,
		`<div class="as-pop__track" style="background:linear-gradient(to right,#e74c3c,#f39c12 50%%,#27ae60)"><span class="as-pop__marker" style="left:%d%%"></span></div>`,
		ddd)
	b.WriteString(`<span class="as-pop__end">DDD ▶</span></div>`)
	fmt.Fprintf(&b,
		`<div class="as-pop__legend">%d%% domain richness · %d%% anemic tendency</div>`,
		ddd, 100-ddd)

	b.WriteString(`<div class="as-pop__cats">`)
	catBar(&b, "Rich Domain Types", r.RichScore, fmt.Sprintf("W %.0f%%", cfg.WeightRichTypes*100))
	catBar(&b, "Tactical Patterns", r.TacticalScore, fmt.Sprintf("W %.0f%%", cfg.WeightTactical*100))
	catBar(&b, "Layer Separation", r.LayerScore, fmt.Sprintf("W %.0f%%", cfg.WeightLayer*100))
	b.WriteString(`</div>`)

	// Anemic marker totals for the inverted row.
	anemicTotal := r.DAOCount + r.DTOCount + r.ManagerCount + r.BOCount + r.DOCount + r.POCount
	richTotal := r.EntitiesCount + r.VOCount + r.AggregateCount
	combined := richTotal + anemicTotal
	anemicInv := 1.0
	if combined > 0 {
		anemicInv = 1.0 - float64(anemicTotal)/float64(combined)
	}
	allAnemicEx := mergeEx(r.ExDAO, r.ExDTO, r.ExManager, r.ExBO, r.ExDO, r.ExPO)

	b.WriteString(`<table class="as-pop__metrics"><thead><tr><th>#</th><th>Metric</th><th>Value</th><th>DDD Score</th><th>Signal</th></tr></thead><tbody>`)
	n := 0

	// ── Rich Domain Types ─────────────────────────────────────────────────────
	sect(&b, "Rich Domain Types · 40%")

	richNote := ""
	if r.NoNamingEvidence {
		richNote = " (no naming or directory evidence — fallback 50%)"
	}
	metric(&b, &n,
		"Entities (<code>*Entity</code> or <code>entity/</code> dir)"+richNote,
		"Named entities (types with identity and lifecycle) detected by *Entity suffix or by living in an entity/ directory.",
		exVal(r.EntitiesCount, r.ExEntity), bool01(r.EntitiesCount > 0))
	metric(&b, &n,
		"Value Objects (<code>*ValueObject</code>, <code>*VO</code> or <code>valueobject/</code> dir)",
		"Immutable types defined by their attributes. Detected by suffix or by directory.",
		exVal(r.VOCount, r.ExVO), bool01(r.VOCount > 0))
	metric(&b, &n,
		"Aggregates (<code>*AggregateRoot</code>, <code>*Aggregate</code> or <code>aggregate/</code> dir) — weighted ×2",
		"Aggregate roots enforce consistency boundaries. Weighted double because they are the pivotal DDD building block.",
		exVal(r.AggregateCount, r.ExAgg), bool01(r.AggregateCount > 0))
	metric(&b, &n,
		`Anemic markers (<code>*DAO</code> <code>*DTO</code> <code>*Manager</code> <code>*BO</code> <code>*DO</code> <code>*PO</code>) <span class="as-pop__inv">↓ fewer = DDD</span>`,
		"Data-bag and service-layer suffixes. Classic signs of the Anemic Domain Model anti-pattern.",
		exVal(anemicTotal, allAnemicEx), anemicInv)

	// ── Tactical DDD Patterns ─────────────────────────────────────────────────
	sect(&b, "Tactical DDD Patterns · 35%")
	metric(&b, &n,
		"Repositories (<code>*Repository</code> or <code>repository/</code> dir)",
		"Collection-like interfaces that abstract aggregate persistence. Detected by suffix or by directory.",
		exVal(r.RepositoryCount, r.ExRepo), bool01(r.RepositoryCount > 0))
	metric(&b, &n,
		"Domain Events (<code>*DomainEvent</code> or <code>event/</code> dir)",
		"Immutable records of domain facts. Enable loose coupling between aggregates.",
		exVal(r.DomainEvtCount, r.ExEvent), bool01(r.DomainEvtCount > 0))
	metric(&b, &n,
		"Domain Services (<code>*DomainService</code>, <code>*Service</code> in domain or service dir)",
		"Stateless operations that don't naturally belong to an entity. Plain *Service counts only when inside a domain/ or service/ directory.",
		exVal(r.DomainSvcCount, r.ExDomSvc), bool01(r.DomainSvcCount > 0))
	metric(&b, &n,
		"Specifications (<code>*Specification</code>, <code>*Spec</code>)",
		"Encapsulated, combinable business rules. A powerful DDD pattern for query criteria.",
		exVal(r.SpecCount, r.ExSpec), bool01(r.SpecCount > 0))
	metric(&b, &n,
		"Use Cases (<code>*UseCase</code>, <code>*ApplicationService</code> or <code>usecase/</code> dir)",
		"Application-layer orchestrators that drive domain objects through a business scenario.",
		exVal(r.UseCaseCount, r.ExUseCase), bool01(r.UseCaseCount > 0))
	metric(&b, &n,
		"Factories (<code>*Factory</code>)",
		"DDD creation pattern — encapsulates complex aggregate construction so callers never see an invalid state.",
		exVal(r.FactoryCount, r.ExFactory), bool01(r.FactoryCount > 0))
	metric(&b, &n,
		"Event Handlers (<code>*EventHandler</code>)",
		"Application-layer subscribers that react to domain events, enabling loosely coupled cross-aggregate workflows.",
		exVal(r.EventHandlerCount, r.ExEventHandler), bool01(r.EventHandlerCount > 0))

	// ── Layer Separation ──────────────────────────────────────────────────────
	sect(&b, "Layer Separation · 25%")
	metric(&b, &n,
		"<code>/domain/</code>, <code>/aggregate/</code>, <code>/core/</code>, <code>/biz/</code> …",
		"An explicit domain layer. Triggered by: domain, domains, core, business, biz, aggregate(s), entity/ies, valueobject(s), vo, event(s), model.",
		presStr(r.HasDomainPath), bool01(r.HasDomainPath))
	metric(&b, &n,
		"<code>/infrastructure/</code>, <code>/persistence/</code>, <code>/data/</code>, <code>/db/</code> …",
		"A separate infrastructure layer keeps technical concerns out of the domain. Triggered by: infrastructure, infra, persistence, db, data, repo, repository/ies.",
		presStr(r.HasInfraPath), bool01(r.HasInfraPath))
	metric(&b, &n,
		"<code>/application/</code> or <code>/app/</code>",
		"An application layer orchestrates domain objects and separates use-case logic from the domain model.",
		presStr(r.HasAppPath), bool01(r.HasAppPath))
	metric(&b, &n,
		"Port/Adapter directories (<code>/port/</code>, <code>/primary/</code>, <code>/secondary/</code> …)",
		"Hexagonal architecture — ports and adapters enforce strict dependency inversion at the boundary.",
		presStr(r.HasHexagonal), bool01(r.HasHexagonal))
	metric(&b, &n,
		`<code>/dao/</code>, <code>/mapper/</code>, or <code>/assembler/</code> <span class="as-pop__inv">↓ absent = DDD</span>`,
		"These directories signal classic three-layer anemic architecture without an explicit domain model.",
		presStr(r.HasDAOPath), bool01(!r.HasDAOPath))

	// ── Informational (not scored) ────────────────────────────────────────────
	if r.ModelCount > 0 {
		infoRow(&b, &n,
			`<code>*Model</code> types <em>(informational — not scored)</em>`,
			exVal(r.ModelCount, r.ExModel)+` · neutral in Go/Python`)
	}

	b.WriteString(`</tbody></table></div>`)
	return b.String()
}

// ── Render helpers ─────────────────────────────────────────────────────────

func catBar(b *strings.Builder, label string, score int, weight string) {
	fmt.Fprintf(b,
		`<div class="as-pop__catbar"><span class="as-pop__catlabel">%s</span><div class="as-bar"><span class="as-bar__fill %s" style="width:%d%%"></span></div><span class="as-pop__catpct %s">%d%%</span><span class="as-pop__catw">%s</span></div>`,
		esc(label), fillClass(score), score, textClass(score), score, esc(weight))
}

func sect(b *strings.Builder, title string) {
	fmt.Fprintf(b, `<tr class="as-pop__sect"><td colspan="5">%s</td></tr>`, esc(title))
}

// metric renders one scored table row. tooltip is shown on hover.
func metric(b *strings.Builder, n *int, name, tooltip, value string, score01 float64) {
	*n++
	p := pct(score01)
	cell := name
	if tooltip != "" {
		cell = fmt.Sprintf(`<span title="%s">%s</span>`, esc(tooltip), name)
	}
	fmt.Fprintf(b,
		`<tr><td class="mono">%d</td><td>%s</td><td class="mono">%s</td><td><div class="as-mini"><span class="as-mini__fill %s" style="width:%d%%"></span></div></td><td>%s</td></tr>`,
		*n, cell, esc(value), fillClass(p), p, signalTag(p))
}

// infoRow renders a non-scored informational row.
func infoRow(b *strings.Builder, n *int, name, value string) {
	*n++
	fmt.Fprintf(b,
		`<tr><td class="mono">%d</td><td class="as-pop__infocell">%s</td><td class="mono as-pop__infocell">%s</td><td></td><td></td></tr>`,
		*n, name, esc(value))
}

func signalTag(p int) string {
	switch {
	case p >= 65:
		return `<span class="as-tag tag-pop">DDD</span>`
	case p >= 40:
		return `<span class="as-tag tag-mixed">Mixed</span>`
	default:
		return `<span class="as-tag tag-oop">Anemic</span>`
	}
}

func fillClass(p int) string {
	switch {
	case p >= 65:
		return "fill-good"
	case p >= 40:
		return "fill-warn"
	default:
		return "fill-crit"
	}
}

func textClass(p int) string {
	switch {
	case p >= 65:
		return "as-pop__t-good"
	case p >= 40:
		return "as-pop__t-warn"
	default:
		return "as-pop__t-crit"
	}
}

func presStr(b bool) string {
	if b {
		return "present"
	}
	return "absent"
}

// exVal formats the value cell: "N found · Ex1, Ex2, Ex3" or "—" for zero.
func exVal(count int, examples []string) string {
	if count == 0 {
		return "—"
	}
	s := fmt.Sprintf("%d found", count)
	if len(examples) > 0 {
		s += " · " + strings.Join(examples, ", ")
	}
	return s
}

// ── Analysis helpers ───────────────────────────────────────────────────────

// hasAnemicSuffix reports whether n carries an explicit anemic marker suffix.
// Used so that e.g. OrderDTO inside an entity/ directory is still counted as a
// DTO rather than being silently attributed to the entity role.
func hasAnemicSuffix(n string) bool {
	return ws(n, "DAO") || ws(n, "Dao") ||
		ws(n, "DTO") || ws(n, "Dto") ||
		ws(n, "Manager") ||
		ws(n, "BO") || ws(n, "DO") || ws(n, "PO")
}

// pathHas reports whether any slash-delimited segment of path equals one of segs.
func pathHas(path string, segs ...string) bool {
	for _, part := range strings.Split(path, "/") {
		for _, seg := range segs {
			if part == seg {
				return true
			}
		}
	}
	return false
}

// pathHas2 reports whether path contains any of the given consecutive segment
// pairs, e.g. pathHas2(p, [2]string{"pkg","domain"}) matches /pkg/domain/file.go.
func pathHas2(path string, pairs ...[2]string) bool {
	parts := strings.Split(path, "/")
	for i := 0; i+1 < len(parts); i++ {
		for _, pair := range pairs {
			if parts[i] == pair[0] && parts[i+1] == pair[1] {
				return true
			}
		}
	}
	return false
}

// ws (word-suffix) reports whether name ends in suffix as a whole word.
//
// CamelCase: the character before the suffix must be a lowercase letter OR
// any non-alphanumeric character (underscore, hyphen, …).
// Examples: "UserEntity" ✓, "user_Entity" ✓, "EntityManager" ✗ (doesn't end in "Entity").
//
// snake_case: also matches when the lowercase name ends in "_"+lowercase(suffix),
// so "user_entity" matches suffix "Entity".
//
// For two-letter uppercase acronyms (BO, DO, PO, VO) the caller passes only the
// uppercase form; the snake path handles "user_bo" → "_bo" etc.
func ws(name, suffix string) bool {
	// CamelCase / mixed-case path.
	if strings.HasSuffix(name, suffix) {
		if len(name) == len(suffix) {
			return true
		}
		prev := name[len(name)-len(suffix)-1]
		isAlpha := (prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z')
		isDigit := prev >= '0' && prev <= '9'
		if !isAlpha && !isDigit {
			return true // non-alphanumeric boundary (underscore, hyphen, …)
		}
		if prev >= 'a' && prev <= 'z' {
			return true // standard CamelCase lower→upper boundary
		}
	}
	// snake_case path: "user_entity" + suffix "Entity" → check "_entity".
	snake := "_" + strings.ToLower(suffix)
	return strings.HasSuffix(strings.ToLower(name), snake)
}

// addEx appends name to the example slice if it has fewer than 3 entries.
func addEx(list []string, name string) []string {
	if len(list) < 3 {
		return append(list, name)
	}
	return list
}

// mergeEx returns the first 3 unique names across multiple example slices.
func mergeEx(slices ...[]string) []string {
	var out []string
	for _, sl := range slices {
		for _, s := range sl {
			if len(out) >= 3 {
				return out
			}
			out = append(out, s)
		}
	}
	return out
}

func bool01(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func pct(v float64) int   { return int(v*100 + 0.5) }
func esc(s string) string { return html.EscapeString(s) }
