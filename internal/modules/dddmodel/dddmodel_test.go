package dddmodel

import (
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func TestAnalyze_DDDProject(t *testing.T) {
	files := []*parser.ParsedFile{
		goFile("/project/domain/order.go", "OrderEntity", "OrderDomainService"),
		goFile("/project/domain/money.go", "MoneyValueObject"),
		goFile("/project/domain/cart.go", "CartAggregate", "CartCreatedDomainEvent"),
		goFile("/project/application/checkout.go", "CheckoutUseCase"),
		goFile("/project/infrastructure/db.go", "OrderRepository"),
	}

	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)

	if res.DDDScore < 60 {
		t.Errorf("DDD project: expected DDDScore >= 60, got %d", res.DDDScore)
	}
	if res.EntitiesCount != 1 {
		t.Errorf("expected 1 entity, got %d", res.EntitiesCount)
	}
	if res.RepositoryCount != 1 {
		t.Errorf("expected 1 repository (*Repository suffix), got %d", res.RepositoryCount)
	}
	if res.AggregateCount != 1 {
		t.Errorf("expected 1 aggregate, got %d", res.AggregateCount)
	}
	if !res.HasDomainPath {
		t.Error("expected HasDomainPath = true")
	}
	if !res.HasAppPath {
		t.Error("expected HasAppPath = true")
	}
	if !res.HasInfraPath {
		t.Error("expected HasInfraPath = true")
	}
	if len(res.ExEntity) == 0 {
		t.Error("expected entity examples to be populated")
	}
}

// TestAnalyze_GoStyleDDDPackages verifies that types in role-named directories
// (Go/Python DDD convention: aggregate/, entity/, vo/) are classified by their
// directory even when their type names carry no suffix.
func TestAnalyze_GoStyleDDDPackages(t *testing.T) {
	files := []*parser.ParsedFile{
		goFile("/project/aggregate/customer.go", "Customer", "CartItem"),
		goFile("/project/entity/item.go", "Item", "Product"),
		goFile("/project/valueobject/money.go", "Money", "Currency"),
		goFile("/project/event/order_events.go", "OrderCreated", "OrderShipped"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)

	if res.AggregateCount != 2 {
		t.Errorf("aggregate dir: expected 2 aggregates, got %d", res.AggregateCount)
	}
	if res.EntitiesCount != 2 {
		t.Errorf("entity dir: expected 2 entities, got %d", res.EntitiesCount)
	}
	if res.VOCount != 2 {
		t.Errorf("valueobject dir: expected 2 VOs, got %d", res.VOCount)
	}
	if res.DomainEvtCount != 2 {
		t.Errorf("event dir: expected 2 domain events, got %d", res.DomainEvtCount)
	}
	// 58 is "Leaning DDD" — the fixture has rich types but no repository/service/use-case.
	if res.DDDScore < 50 {
		t.Errorf("Go-style DDD project: expected DDDScore >= 50, got %d", res.DDDScore)
	}
}

// TestAnalyze_TestFileExclusion verifies that *_test.go files are skipped so
// test fixtures (TestModel, FakeRepository, etc.) don't distort the score.
func TestAnalyze_TestFileExclusion(t *testing.T) {
	files := []*parser.ParsedFile{
		goFile("/project/domain/model_test.go", "TestModel", "FakeRepository"),
		goFile("/project/domain/order.go", "OrderEntity"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)

	if res.BackendFiles != 1 {
		t.Errorf("expected 1 non-test file, got %d", res.BackendFiles)
	}
	if res.EntitiesCount != 1 {
		t.Errorf("expected 1 entity from production file, got %d", res.EntitiesCount)
	}
	if res.RepositoryCount != 0 {
		t.Errorf("FakeRepository from test file should be excluded, got %d", res.RepositoryCount)
	}
	if res.ModelCount != 0 {
		t.Errorf("TestModel from test file should be excluded, got %d", res.ModelCount)
	}
}

func TestAnalyze_ContextualService(t *testing.T) {
	// *Service in domain path → counts as DomainService.
	inDomain := goFileIn("/project/domain/pricing.go", "PricingService")
	resDomain := Module{Cfg: DefaultConfig}.Analyze([]*parser.ParsedFile{inDomain}).(Result)
	if resDomain.DomainSvcCount != 1 {
		t.Errorf("*Service in domain path: expected DomainSvcCount 1, got %d", resDomain.DomainSvcCount)
	}

	// *Service in service/ dir → also counts (Go convention: percybolmer-style).
	inSvcDir := goFileIn("/project/service/order.go", "OrderService")
	resSvcDir := Module{Cfg: DefaultConfig}.Analyze([]*parser.ParsedFile{inSvcDir}).(Result)
	if resSvcDir.DomainSvcCount != 1 {
		t.Errorf("*Service in service/ dir: expected DomainSvcCount 1, got %d", resSvcDir.DomainSvcCount)
	}

	// *Service in an unrelated path (handler, controller) → NOT counted.
	inHandler := goFileIn("/project/handler/user.go", "UserService")
	resHandler := Module{Cfg: DefaultConfig}.Analyze([]*parser.ParsedFile{inHandler}).(Result)
	if resHandler.DomainSvcCount != 0 {
		t.Errorf("*Service in handler path: expected DomainSvcCount 0, got %d", resHandler.DomainSvcCount)
	}
}

func TestAnalyze_AnemicProject(t *testing.T) {
	files := []*parser.ParsedFile{
		goFile("/project/models/order.go", "OrderDAO", "OrderDTO"),
		goFile("/project/mgmt/order.go", "OrderManager", "OrderModel"),
		goFile("/project/dao/user.go", "UserDAO"),
	}

	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)

	if res.DDDScore > 30 {
		t.Errorf("anemic project: expected DDDScore <= 30, got %d", res.DDDScore)
	}
	if res.DAOCount != 2 {
		t.Errorf("expected 2 DAOs, got %d", res.DAOCount)
	}
	if res.ModelCount != 1 {
		t.Errorf("expected 1 Model (informational), got %d", res.ModelCount)
	}
	if !res.HasDAOPath {
		t.Error("expected HasDAOPath = true for /dao/ path")
	}
}

func TestAnalyze_NewAnemicMarkers(t *testing.T) {
	files := []*parser.ParsedFile{
		goFile("/project/objs/objects.go", "UserDO", "OrderPO"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)
	if res.DOCount != 1 {
		t.Errorf("expected DOCount=1, got %d", res.DOCount)
	}
	if res.POCount != 1 {
		t.Errorf("expected POCount=1, got %d", res.POCount)
	}
}

func TestAnalyze_WeightedAggregates(t *testing.T) {
	// 2 aggregates vs 2 DAOs: richWeighted = 0+0+4=4, anemicWeighted=2 → rich=0.67
	files := []*parser.ParsedFile{
		goFile("/project/domain/order.go", "OrderAggregate", "CartAggregate"),
		goFile("/project/dto/transfer.go", "OrderDTO", "CartDTO"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)
	if res.RichScore <= 50 {
		t.Errorf("weighted aggregates: expected RichScore > 50, got %d (2 Aggregates×2 vs 2 DTOs)", res.RichScore)
	}
}

func TestAnalyze_ExpandedPaths(t *testing.T) {
	files := []*parser.ParsedFile{
		goFileIn("/project/core/user.go"),
		goFileIn("/project/persistence/db.go"),
		goFileIn("/project/driving/handler.go"),
		goFileIn("/project/mapper/transform.go"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)
	if !res.HasDomainPath {
		t.Error("expected /core/ to trigger HasDomainPath")
	}
	if !res.HasInfraPath {
		t.Error("expected /persistence/ to trigger HasInfraPath")
	}
	if !res.HasHexagonal {
		t.Error("expected /driving/ to trigger HasHexagonal")
	}
	if !res.HasDAOPath {
		t.Error("expected /mapper/ to trigger HasDAOPath")
	}
}

// TestAnalyze_MonorepoDomainPaths verifies that /pkg/domain and /internal/domain
// (common Go monorepo layouts) trigger HasDomainPath via both pathHas and pathHas2.
func TestAnalyze_MonorepoDomainPaths(t *testing.T) {
	cases := []struct {
		path string
	}{
		{"/repo/pkg/domain/order.go"},
		{"/repo/internal/domain/order.go"},
		{"/repo/pkg/domains/order.go"},
		{"/repo/internal/domains/order.go"},
	}
	for _, c := range cases {
		res := Module{Cfg: DefaultConfig}.Analyze([]*parser.ParsedFile{goFileIn(c.path)}).(Result)
		if !res.HasDomainPath {
			t.Errorf("path %q: expected HasDomainPath = true", c.path)
		}
	}
}

// TestAnalyze_AnemicSuffixOverridesRoleDir verifies that an explicit anemic
// suffix (e.g. *DTO) is never silently attributed to a directory role.
func TestAnalyze_AnemicSuffixOverridesRoleDir(t *testing.T) {
	files := []*parser.ParsedFile{
		// OrderDTO sits inside entity/ — should be counted as DTO, not an entity.
		goFile("/project/entity/transfer.go", "OrderDTO", "UserEntity"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)
	if res.DTOCount != 1 {
		t.Errorf("OrderDTO in entity/: expected DTOCount=1, got %d", res.DTOCount)
	}
	if res.EntitiesCount != 1 {
		t.Errorf("UserEntity in entity/: expected EntitiesCount=1, got %d", res.EntitiesCount)
	}
}

// TestAnalyze_EventsDirNoHasDomainPath verifies that an events/ directory
// alone does not set HasDomainPath (event-bus utility, not a domain layer).
func TestAnalyze_EventsDirNoHasDomainPath(t *testing.T) {
	files := []*parser.ParsedFile{
		goFile("/project/events/bus.go", "EventBus", "Subscription"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)
	if res.HasDomainPath {
		t.Error("events/ alone should not set HasDomainPath")
	}
	// Types are still classified as domain events via roleEvent.
	if res.DomainEvtCount != 2 {
		t.Errorf("types in events/ still counted as domain events: expected 2, got %d", res.DomainEvtCount)
	}
}

// TestAnalyze_NoDomainModelVerdict verifies the dedicated verdict for
// codebases that have no naming evidence, no domain path, and no tactical
// patterns — rather than forcing them onto the Anemic end of the DDD spectrum.
func TestAnalyze_NoDomainModelVerdict(t *testing.T) {
	files := []*parser.ParsedFile{
		// A utility-only file: has a type declaration but no DDD signals at all.
		goFile("/project/cmd/main.go", "AppConfig"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)
	if res.Verdict != "No Domain Model Detected" {
		t.Errorf("no-domain project: expected 'No Domain Model Detected', got %q", res.Verdict)
	}
}

func TestAnalyze_FactoryAndEventHandler(t *testing.T) {
	files := []*parser.ParsedFile{
		goFile("/project/domain/order.go", "OrderFactory"),
		goFile("/project/application/events.go", "OrderCreatedEventHandler", "UserRegisteredEventHandler"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)
	if res.FactoryCount != 1 {
		t.Errorf("expected FactoryCount=1, got %d", res.FactoryCount)
	}
	if res.EventHandlerCount != 2 {
		t.Errorf("expected EventHandlerCount=2, got %d", res.EventHandlerCount)
	}
	if len(res.ExFactory) == 0 {
		t.Error("expected factory examples populated")
	}
}

func TestAnalyze_TacticalScoreCap(t *testing.T) {
	// All 7 tactical patterns present — score must be capped at 100, not 140.
	files := []*parser.ParsedFile{
		goFile("/project/domain/repo.go", "OrderRepository"),
		goFile("/project/domain/events.go", "OrderPlacedDomainEvent"),
		goFile("/project/domain/svc.go", "PricingDomainService"),
		goFile("/project/domain/spec.go", "ActiveCustomerSpec"),
		goFile("/project/application/uc.go", "PlaceOrderUseCase"),
		goFile("/project/domain/factory.go", "OrderFactory"),
		goFile("/project/application/eh.go", "OrderPlacedEventHandler"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)
	if res.TacticalScore != 100 {
		t.Errorf("all 7 tactical patterns: expected TacticalScore=100, got %d", res.TacticalScore)
	}
}

// TestAnalyze_BizAndDataPaths verifies go-kratos-style directory names.
func TestAnalyze_BizAndDataPaths(t *testing.T) {
	files := []*parser.ParsedFile{
		goFileIn("/app/internal/biz/order.go"),
		goFileIn("/app/internal/data/order.go"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)
	if !res.HasDomainPath {
		t.Error("expected /biz/ to trigger HasDomainPath")
	}
	if !res.HasInfraPath {
		t.Error("expected /data/ to trigger HasInfraPath")
	}
}

func TestAnalyze_EmptyFiles(t *testing.T) {
	res := Module{Cfg: DefaultConfig}.Analyze([]*parser.ParsedFile{}).(Result)
	if res.HasData() {
		t.Error("expected HasData() = false for empty file list")
	}
}

func TestAnalyze_CustomConfig(t *testing.T) {
	cfg := Config{
		WeightRichTypes:  0.60,
		WeightTactical:   0.25,
		WeightLayer:      0.15,
		ThresholdStrong:  80,
		ThresholdLeaning: 60,
		ThresholdMixed:   45,
		ThresholdAnemic:  30,
	}
	files := []*parser.ParsedFile{
		goFile("/project/domain/order.go", "OrderEntity"),
	}
	res := Module{Cfg: cfg}.Analyze(files).(Result)
	// With ThresholdStrong=80 a single entity should not reach "Strong Rich Domain Model".
	if res.Verdict == "Strong Rich Domain Model" {
		t.Errorf("custom high threshold: expected not 'Strong Rich Domain Model', got %q", res.Verdict)
	}
}

func TestAppliesTo(t *testing.T) {
	m := Module{Cfg: DefaultConfig}
	for _, id := range []string{"go", "python", "kotlin", "java"} {
		if !m.AppliesTo(id) {
			t.Errorf("AppliesTo(%q) = false, want true", id)
		}
	}
	for _, id := range []string{"swift", "typescript", "javascript"} {
		if m.AppliesTo(id) {
			t.Errorf("AppliesTo(%q) = true, want false", id)
		}
	}
}

func TestAnalyze_JavaSuffixConventions(t *testing.T) {
	files := []*parser.ParsedFile{
		javaFile("/project/domain/order/OrderEntity.java", "OrderEntity"),
		javaFile("/project/domain/money/MoneyValueObject.java", "MoneyValueObject"),
		javaFile("/project/domain/cart/CartAggregate.java", "CartAggregate"),
		javaFile("/project/domain/event/OrderPlacedDomainEvent.java", "OrderPlacedDomainEvent"),
		javaFile("/project/infrastructure/OrderRepository.java", "OrderRepository"),
		javaFile("/project/application/PlaceOrderUseCase.java", "PlaceOrderUseCase"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)

	if res.EntitiesCount != 1 {
		t.Errorf("expected 1 entity, got %d", res.EntitiesCount)
	}
	if res.VOCount != 1 {
		t.Errorf("expected 1 value object, got %d", res.VOCount)
	}
	if res.AggregateCount != 1 {
		t.Errorf("expected 1 aggregate, got %d", res.AggregateCount)
	}
	if res.DomainEvtCount != 1 {
		t.Errorf("expected 1 domain event, got %d", res.DomainEvtCount)
	}
	if res.RepositoryCount != 1 {
		t.Errorf("expected 1 repository, got %d", res.RepositoryCount)
	}
	if res.UseCaseCount != 1 {
		t.Errorf("expected 1 use case, got %d", res.UseCaseCount)
	}
	if res.DDDScore < 60 {
		t.Errorf("Java DDD project: expected DDDScore >= 60, got %d", res.DDDScore)
	}
}

func TestAnalyze_JavaTestFileExclusion(t *testing.T) {
	files := []*parser.ParsedFile{
		javaFile("/project/src/test/java/OrderTest.java", "FakeRepository", "OrderDTO"),
		javaFile("/project/src/main/java/OrderEntity.java", "OrderEntity"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)

	if res.BackendFiles != 1 {
		t.Errorf("expected 1 non-test file, got %d", res.BackendFiles)
	}
	if res.EntitiesCount != 1 {
		t.Errorf("expected 1 entity from production file, got %d", res.EntitiesCount)
	}
	if res.RepositoryCount != 0 {
		t.Errorf("FakeRepository from test file should be excluded, got %d", res.RepositoryCount)
	}
}

func TestAnalyze_JavaTestFileSuffix(t *testing.T) {
	// *Test.java, *Tests.java, *IT.java must all be excluded.
	files := []*parser.ParsedFile{
		javaFile("/project/OrderTest.java", "OrderRepository"),
		javaFile("/project/OrderTests.java", "CartAggregate"),
		javaFile("/project/OrderIT.java", "OrderEntity"),
		javaFile("/project/Order.java", "OrderFactory"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)

	if res.BackendFiles != 1 {
		t.Errorf("expected only 1 production file, got %d", res.BackendFiles)
	}
	if res.FactoryCount != 1 {
		t.Errorf("expected 1 factory from production file, got %d", res.FactoryCount)
	}
}

func TestAnalyze_JavaDirectoryConventions(t *testing.T) {
	// Java projects using DDD package names (no suffix needed).
	files := []*parser.ParsedFile{
		javaFile("/project/domain/entity/Order.java", "Order"),
		javaFile("/project/domain/valueobject/Money.java", "Money"),
		javaFile("/project/domain/aggregate/Cart.java", "Cart"),
		javaFile("/project/domain/repository/OrderRepo.java", "OrderRepo"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)

	if res.EntitiesCount != 1 {
		t.Errorf("entity dir: expected 1, got %d", res.EntitiesCount)
	}
	if res.VOCount != 1 {
		t.Errorf("valueobject dir: expected 1, got %d", res.VOCount)
	}
	if res.AggregateCount != 1 {
		t.Errorf("aggregate dir: expected 1, got %d", res.AggregateCount)
	}
	if res.RepositoryCount != 1 {
		t.Errorf("repository dir: expected 1, got %d", res.RepositoryCount)
	}
}

func TestRenderHTML_HasData(t *testing.T) {
	files := []*parser.ParsedFile{
		goFile("/project/domain/order.go", "OrderEntity"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)
	h := Module{Cfg: DefaultConfig}.RenderHTML(res)
	if !strings.Contains(h, "as-pop") {
		t.Error("expected DDD panel HTML to contain as-pop class")
	}
	if !strings.Contains(h, "Anemic") {
		t.Error("expected spectrum label 'Anemic' in HTML")
	}
	if !strings.Contains(h, "linear-gradient") {
		t.Error("expected gradient in spectrum bar")
	}
	if !strings.Contains(h, `title=`) {
		t.Error("expected title tooltip attributes in metrics table")
	}
	if !strings.Contains(h, "OrderEntity") {
		t.Error("expected example type names in value column")
	}
}

func TestRenderHTML_NamingEvidenceNote(t *testing.T) {
	// A file with no typed declarations produces NoNamingEvidence=true.
	// The report should note the fallback.
	files := []*parser.ParsedFile{
		goFileIn("/project/cmd/main.go"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)
	if !res.NoNamingEvidence {
		t.Skip("test requires a file with no typed declarations")
	}
	h := Module{Cfg: DefaultConfig}.RenderHTML(res)
	if !strings.Contains(h, "fallback") {
		t.Error("expected 'fallback' note in HTML when there is no naming evidence")
	}
}

func TestRenderHTML_NoData(t *testing.T) {
	res := Module{Cfg: DefaultConfig}.Analyze([]*parser.ParsedFile{}).(Result)
	h := Module{Cfg: DefaultConfig}.RenderHTML(res)
	if !strings.Contains(h, "as-empty") {
		t.Error("expected empty-state HTML for no backend files")
	}
}

func TestWordSuffix(t *testing.T) {
	cases := []struct {
		name, suffix string
		want         bool
	}{
		// Standard CamelCase boundaries
		{"OrderEntity", "Entity", true},
		{"Entity", "Entity", true},
		{"UserRepository", "Repository", true},
		{"OrderAggregate", "Aggregate", true},
		{"OrderAggregateRoot", "AggregateRoot", true},
		// Should NOT match (suffix is not at word boundary)
		{"EntityManager", "Entity", false},
		{"RepositoryHelper", "Repository", false},
		// Non-alphanumeric boundary (underscore)
		{"user_Entity", "Entity", true},
		// snake_case lowercase → matched via snake path
		{"user_entity", "Entity", true},
		{"order_repository", "Repository", true},
		{"user_dao", "DAO", true},
		// Snake suffix in wrong position should not match
		{"user_entity_old", "Entity", false},
		// Two-letter UPPERCASE acronyms — kept
		{"UserDAO", "DAO", true},
		{"UserDao", "Dao", true},
		{"UserVO", "VO", true},
		{"UserBO", "BO", true},
		{"UserDO", "DO", true},
		{"UserPO", "PO", true},
		// Collisions that drove the removal of lowercase two-letter variants:
		// ws("ToDo","DO") must be false — case-sensitive HasSuffix protects us.
		{"ToDo", "DO", false},
		// These collisions still exist in ws() itself, which is fine because
		// Analyze no longer calls ws(n,"Do"), ws(n,"Po"), or ws(n,"Bo").
		// Upper-case prefix test
		{"INVOICE", "VOICE", false},
	}
	for _, c := range cases {
		got := ws(c.name, c.suffix)
		if got != c.want {
			t.Errorf("ws(%q, %q) = %v, want %v", c.name, c.suffix, got, c.want)
		}
	}
}

func TestExamples(t *testing.T) {
	files := []*parser.ParsedFile{
		goFile("/project/domain/order.go", "OrderEntity", "UserEntity", "ProductEntity", "InvoiceEntity"),
	}
	res := Module{Cfg: DefaultConfig}.Analyze(files).(Result)
	if len(res.ExEntity) != 3 {
		t.Errorf("expected exactly 3 examples (cap), got %d: %v", len(res.ExEntity), res.ExEntity)
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

func goFile(path string, typeNames ...string) *parser.ParsedFile {
	pf := &parser.ParsedFile{
		FilePath:   path,
		LanguageID: "go",
		Platform:   "go",
	}
	for _, n := range typeNames {
		pf.Declarations = append(pf.Declarations, parser.Declaration{
			Name: n,
			Kind: parser.DeclStruct,
		})
	}
	return pf
}

// goFileIn is an alias for goFile that accepts optional type names, used to
// clarify intent when the test is about path structure rather than declarations.
func goFileIn(path string, typeNames ...string) *parser.ParsedFile {
	return goFile(path, typeNames...)
}

func javaFile(path string, typeNames ...string) *parser.ParsedFile {
	pf := &parser.ParsedFile{
		FilePath:   path,
		LanguageID: "java",
		Platform:   "java",
	}
	for _, n := range typeNames {
		pf.Declarations = append(pf.Declarations, parser.Declaration{
			Name: n,
			Kind: parser.DeclClass,
		})
	}
	return pf
}
