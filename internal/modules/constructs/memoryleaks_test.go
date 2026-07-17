package constructs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/security"
)

// mlFile writes src to a temp file and returns a ParsedFile tagged with the
// given LanguageID — memoryleaks rules key off LanguageID, not extension.
func mlFile(t *testing.T, langID, ext, src string) *parser.ParsedFile {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f"+ext)
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return &parser.ParsedFile{FilePath: p, LanguageID: langID}
}

func mlAnalyze(files []*parser.ParsedFile) MemoryLeaksReport {
	return (MemoryLeaks{}).Analyze(files).(MemoryLeaksReport)
}

func TestMemoryLeaks_GoContextCancel_Fires(t *testing.T) {
	src := "package p\nfunc f() {\n\tctx, cancel := context.WithCancel(context.Background())\n\t_ = ctx\n}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "go", ".go", src)})
	if r.High == 0 {
		t.Errorf("want a HIGH finding for context.WithCancel without cancel(), got %+v", r.Findings)
	}
}

func TestMemoryLeaks_GoContextCancel_DeferredSafe(t *testing.T) {
	src := "package p\nfunc f() {\n\tctx, cancel := context.WithCancel(context.Background())\n\tdefer cancel()\n\t_ = ctx\n}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "go", ".go", src)})
	if r.HasData() {
		t.Errorf("want 0 findings when cancel() is deferred, got %+v", r.Findings)
	}
}

func TestMemoryLeaks_GoFileHandle_Fires(t *testing.T) {
	src := "package p\nfunc f() {\n\tfh, _ := os.Open(\"x\")\n\t_ = fh\n}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "go", ".go", src)})
	if r.Medium == 0 {
		t.Errorf("want a MEDIUM finding for os.Open without Close(), got %+v", r.Findings)
	}
}

func TestMemoryLeaks_PythonOpenWithBlock_Safe(t *testing.T) {
	src := "def f():\n    with open('x') as fh:\n        pass\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "python", ".py", src)})
	if r.HasData() {
		t.Errorf("want 0 findings for `with open(...) as f`, got %+v", r.Findings)
	}
}

func TestMemoryLeaks_PythonOpenNoClose_Fires(t *testing.T) {
	src := "def f():\n    fh = open('x')\n    return fh.read()\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "python", ".py", src)})
	if !r.HasData() {
		t.Errorf("want a finding for open() without close(), got none")
	}
}

func TestMemoryLeaks_JavaJDBCTryWithResourcesSafe(t *testing.T) {
	src := "class C {\n  void f() {\n    try (Connection c = DriverManager.getConnection(url)) {\n    }\n  }\n}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "java", ".java", src)})
	if r.HasData() {
		t.Errorf("want 0 findings for try-with-resources JDBC connection, got %+v", r.Findings)
	}
}

func TestMemoryLeaks_JavaJDBCNoTryWithResources_Fires(t *testing.T) {
	src := "class C {\n  void f() {\n    Connection c = DriverManager.getConnection(url);\n  }\n}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "java", ".java", src)})
	if r.High == 0 {
		t.Errorf("want a HIGH finding for JDBC connection outside try-with-resources, got %+v", r.Findings)
	}
}

func TestMemoryLeaks_TSListenerRatio_ToleratesFewUnmatched(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 4; i++ {
		b.WriteString("el.addEventListener('click', fn);\n")
	}
	b.WriteString("el.removeEventListener('click', fn);\n")
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "ts", ".ts", b.String())})
	if r.HasData() {
		t.Errorf("want 0 findings within the 5x noise ratio (4 adds, 1 remove), got %+v", r.Findings)
	}
}

func TestMemoryLeaks_TSListenerRatio_FiresBeyondRatio(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 10; i++ {
		b.WriteString("el.addEventListener('click', fn);\n")
	}
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "ts", ".ts", b.String())})
	if !r.HasData() {
		t.Errorf("want findings for 10 addEventListener with 0 removeEventListener")
	}
}

func TestMemoryLeaks_CMallocFree_Fires(t *testing.T) {
	src := "void f() {\n    int *p = malloc(sizeof(int));\n    *p = 1;\n}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "c", ".c", src)})
	if r.High == 0 {
		t.Errorf("want a HIGH finding for malloc without free(), got %+v", r.Findings)
	}
}

func TestMemoryLeaks_CMallocFree_Safe(t *testing.T) {
	src := "void f() {\n    int *p = malloc(sizeof(int));\n    *p = 1;\n    free(p);\n}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "c", ".c", src)})
	if r.HasData() {
		t.Errorf("want 0 findings when free() is present, got %+v", r.Findings)
	}
}

func TestMemoryLeaks_RustMemForget_AlwaysFires(t *testing.T) {
	src := "fn f() {\n    let v = vec![1,2,3];\n    std::mem::forget(v);\n}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "rust", ".rs", src)})
	if r.Medium == 0 {
		t.Errorf("want a MEDIUM finding for std::mem::forget, got %+v", r.Findings)
	}
}

func TestMemoryLeaks_SwiftRetainCycle_Fires(t *testing.T) {
	src := "class C {\n" +
		"  func f() {\n" +
		"    URLSession.shared.dataTask(with: url) { data, resp, err in\n" +
		"      self.handle(data)\n" +
		"    }\n" +
		"  }\n" +
		"}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "swift", ".swift", src)})
	if r.HasData() == false {
		t.Errorf("want a retain-cycle finding for a strong self capture in a URLSession closure")
	}
}

func TestMemoryLeaks_SwiftWeakSelf_Safe(t *testing.T) {
	src := "class C {\n" +
		"  func f() {\n" +
		"    URLSession.shared.dataTask(with: url) { [weak self] data, resp, err in\n" +
		"      self?.handle(data)\n" +
		"    }\n" +
		"  }\n" +
		"}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "swift", ".swift", src)})
	if r.HasData() {
		t.Errorf("want 0 findings when [weak self] is present, got %+v", r.Findings)
	}
}

func TestMemoryLeaks_TestPathExcluded(t *testing.T) {
	p := filepath.Join(t.TempDir(), "widget_test.go")
	if err := os.WriteFile(p, []byte("package p\nfunc f() { fh, _ := os.Open(\"x\"); _ = fh }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := mlAnalyze([]*parser.ParsedFile{{FilePath: p, LanguageID: "go"}})
	if r.HasData() {
		t.Errorf("want test files excluded from memory-leak scanning, got %+v", r.Findings)
	}
}

// TestMemoryLeaks_RenderHTML_CleanStillRendersSubcard ensures a 0-finding
// result still produces non-empty HTML: the pipeline (module.Transformer.
// HTMLPanels) only attaches a platform's "memoryleaks" panel — and therefore
// only creates the anchor the ⚡ Performance tooltip's "💧 N Memory Leaks"
// line links to — when RenderHTML returns something. A "" here would make
// that link silently go nowhere on an otherwise-clean platform.
func TestMemoryLeaks_RenderHTML_CleanStillRendersSubcard(t *testing.T) {
	src := "package p\nfunc f() {\n\tfh, _ := os.Open(\"x\")\n\tdefer fh.Close()\n}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "go", ".go", src)})
	if r.HasData() {
		t.Fatalf("fixture should be clean, got %+v", r.Findings)
	}
	got := (MemoryLeaks{}).RenderHTML(r)
	if strings.TrimSpace(got) == "" {
		t.Fatal("RenderHTML returned empty string for a clean (0-finding) result; the Performance tooltip's 💧 link would be dead")
	}
	if !strings.Contains(got, "No potential memory leaks") {
		t.Errorf("expected a clean-state message, got %q", got)
	}
}

func TestMemoryLeaks_RenderHTML_EmptyWhenModuleDidNotApply(t *testing.T) {
	got := (MemoryLeaks{}).RenderHTML("not a MemoryLeaksReport")
	if got != "" {
		t.Errorf("RenderHTML with a non-MemoryLeaksReport result should stay empty, got %q", got)
	}
}

func TestMemoryLeaks_AppliesTo(t *testing.T) {
	m := MemoryLeaks{}
	for _, lang := range []string{"go", "python", "java", "ts", "rust", "swift", "objc", "c", "cpp"} {
		if !m.AppliesTo(lang) {
			t.Errorf("AppliesTo(%q) = false, want true", lang)
		}
	}
	if m.AppliesTo("kotlin") {
		t.Errorf("AppliesTo(\"kotlin\") = true, want false (no rules defined)")
	}
}

// ── Comment/string stripping (review point 1) ───────────────────────────────

func TestMemoryLeaks_CommentedAcquireDoesNotFire(t *testing.T) {
	src := "package p\nfunc f() {\n\t// fh, _ := os.Open(\"x\")\n}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "go", ".go", src)})
	if r.HasData() {
		t.Errorf("a commented-out os.Open should not fire, got %+v", r.Findings)
	}
}

func TestMemoryLeaks_StringLiteralAcquireDoesNotFire(t *testing.T) {
	src := "package p\nfunc f() {\n\tlog.Println(\"remember to call os.Open(path) and close it\")\n}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "go", ".go", src)})
	if r.HasData() {
		t.Errorf("os.Open mentioned only inside a string literal should not fire, got %+v", r.Findings)
	}
}

// ── Multi-line context lookback (review points 2 & 5) ───────────────────────

func TestMemoryLeaks_JavaMultiLineTryWithResources_Safe(t *testing.T) {
	src := "class C {\n" +
		"  void f() {\n" +
		"    try (\n" +
		"      Connection c = DriverManager.getConnection(url)\n" +
		"    ) {\n" +
		"    }\n" +
		"  }\n" +
		"}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "java", ".java", src)})
	if r.HasData() {
		t.Errorf("a multi-line try-with-resources declaration should not fire, got %+v", r.Findings)
	}
}

func TestMemoryLeaks_JavaMultiLineTryWithResources_TooFarBack_StillFires(t *testing.T) {
	// "try (" is more than skipWindow lines above the acquire — this remains
	// a known limitation (documented, not silently "fixed" by widening the
	// window indefinitely), so it should still fire.
	src := "class C {\n" +
		"  void f() {\n" +
		"    try (\n" +
		"      // a\n" +
		"      // b\n" +
		"      // c\n" +
		"      Connection c = DriverManager.getConnection(url)\n" +
		"    ) {\n" +
		"    }\n" +
		"  }\n" +
		"}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "java", ".java", src)})
	if !r.HasData() {
		t.Error("want a finding when 'try (' is further back than the lookback window")
	}
}

func TestMemoryLeaks_PythonMultiLineWith_Safe(t *testing.T) {
	src := "def f():\n" +
		"    with (\n" +
		"        open('x') as fh,\n" +
		"    ):\n" +
		"        pass\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "python", ".py", src)})
	if r.HasData() {
		t.Errorf("a parenthesized multi-line with-statement should not fire, got %+v", r.Findings)
	}
}

// ── Refined Java ResultSet rule (review point 6) ─────────────────────────────

func TestMemoryLeaks_JavaResultSet_NullDeclarationDoesNotFire(t *testing.T) {
	src := "class C {\n  void f() {\n    ResultSet rs = null;\n  }\n}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "java", ".java", src)})
	for _, f := range r.Findings {
		if f.RuleID == "java.resultset_leak" {
			t.Errorf("a bare 'ResultSet rs = null;' should not be treated as an acquire, got %+v", f)
		}
	}
}

func TestMemoryLeaks_JavaResultSet_ExecuteQueryFires(t *testing.T) {
	src := "class C {\n  void f() {\n    ResultSet rs = stmt.executeQuery(sql);\n  }\n}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "java", ".java", src)})
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "java.resultset_leak" {
			found = true
		}
	}
	if !found {
		t.Errorf("want a java.resultset_leak finding for executeQuery() outside try-with-resources, got %+v", r.Findings)
	}
}

// ── New rules (review point 3) ───────────────────────────────────────────────

func TestMemoryLeaks_GoSQLRows_Fires(t *testing.T) {
	src := "package p\nfunc f() {\n\trows, _ := db.Query(q)\n\t_ = rows\n}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "go", ".go", src)})
	if r.Medium == 0 {
		t.Errorf("want a MEDIUM finding for db.Query without rows.Close(), got %+v", r.Findings)
	}
}

func TestMemoryLeaks_GoSQLRows_Safe(t *testing.T) {
	src := "package p\nfunc f() {\n\trows, _ := db.Query(q)\n\tdefer rows.Close()\n}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "go", ".go", src)})
	if r.HasData() {
		t.Errorf("want 0 findings when rows.Close() is deferred, got %+v", r.Findings)
	}
}

func TestMemoryLeaks_PythonThreadingThread_Fires(t *testing.T) {
	src := "def f():\n    t = threading.Thread(target=work)\n    t.start()\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "python", ".py", src)})
	if !r.HasData() {
		t.Error("want a finding for threading.Thread without .join()")
	}
}

func TestMemoryLeaks_TSRequestAnimationFrame_Fires(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 10; i++ {
		b.WriteString("requestAnimationFrame(tick);\n")
	}
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "ts", ".ts", b.String())})
	if !r.HasData() {
		t.Error("want a finding for many requestAnimationFrame calls with 0 cancelAnimationFrame")
	}
}

func TestMemoryLeaks_JavaStatementLeak_Fires(t *testing.T) {
	src := "class C {\n  void f() {\n    Statement s = conn.createStatement();\n  }\n}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "java", ".java", src)})
	if !r.HasData() {
		t.Error("want a finding for createStatement() outside try-with-resources")
	}
}

func TestMemoryLeaks_JavaStatementLeak_TryWithResourcesSafe(t *testing.T) {
	src := "class C {\n  void f() {\n    try (Statement s = conn.createStatement()) {\n    }\n  }\n}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "java", ".java", src)})
	if r.HasData() {
		t.Errorf("want 0 findings for try-with-resources Statement, got %+v", r.Findings)
	}
}

// ── Swift closure brace-matching (review point 4) ───────────────────────────

func TestMemoryLeaks_SwiftRetainCycle_WeakSelfBeyondFixedWindow_Safe(t *testing.T) {
	// [weak self] is on the closure's own opening line, but "self?.handle"
	// (the actual self reference) is 4 lines below the danger site — beyond
	// the old fixed 4-line window, still inside the closure body
	// brace-matching now scans to find.
	src := "class C {\n" +
		"  func f() {\n" +
		"    URLSession.shared.dataTask(with: url) { [weak self]\n" +
		"      data, resp, err in\n" +
		"      // a comment\n" +
		"      // another comment\n" +
		"      self?.handle(data)\n" +
		"    }\n" +
		"  }\n" +
		"}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "swift", ".swift", src)})
	if r.HasData() {
		t.Errorf("want 0 findings when [weak self] is present anywhere in the closure body, got %+v", r.Findings)
	}
}

func TestMemoryLeaks_SwiftRetainCycle_LongClosureBody_Fires(t *testing.T) {
	// No weak/unowned self anywhere; the closure body spans many lines.
	src := "class C {\n" +
		"  func f() {\n" +
		"    URLSession.shared.dataTask(with: url) { data, resp, err in\n" +
		"      let x = 1\n" +
		"      let y = 2\n" +
		"      let z = 3\n" +
		"      self.handle(data)\n" +
		"    }\n" +
		"  }\n" +
		"}\n"
	r := mlAnalyze([]*parser.ParsedFile{mlFile(t, "swift", ".swift", src)})
	if !r.HasData() {
		t.Error("want a retain-cycle finding when self is captured strongly deep in the closure body")
	}
}

// ── Grouping: one row per reason, all locations listed ──────────────────────

func TestGroupMLFindings_CollapsesSameRuleAcrossFiles(t *testing.T) {
	findings := []MLFinding{
		{RuleID: "swift.notification_observer", Label: "NotificationCenter observer never removed",
			Advice: "Remove it in deinit.", Severity: security.SevHigh, FilePath: "/a.swift", Line: 10},
		{RuleID: "swift.notification_observer", Label: "NotificationCenter observer never removed",
			Advice: "Remove it in deinit.", Severity: security.SevHigh, FilePath: "/b.swift", Line: 20},
		{RuleID: "swift.notification_observer", Label: "NotificationCenter observer never removed",
			Advice: "Remove it in deinit.", Severity: security.SevHigh, FilePath: "/a.swift", Line: 30},
		{RuleID: "swift.timer_invalidate", Label: "Timer never invalidated",
			Advice: "Call .invalidate().", Severity: security.SevMedium, FilePath: "/a.swift", Line: 40},
	}
	groups := groupMLFindings(findings)
	if len(groups) != 2 {
		t.Fatalf("want 2 groups (one per RuleID), got %d: %+v", len(groups), groups)
	}
	// HIGH-severity group sorts first.
	notif := groups[0]
	if notif.RuleID != "swift.notification_observer" {
		t.Fatalf("want the HIGH-severity group first, got %+v", notif)
	}
	if len(notif.Locations) != 3 {
		t.Errorf("want all 3 occurrences collapsed into one group's Locations, got %d: %+v", len(notif.Locations), notif.Locations)
	}
	if notif.Label != "NotificationCenter observer never removed" {
		t.Errorf("want the reason written once via Label, got %q", notif.Label)
	}
}

func TestMemoryLeaks_RenderHTML_OneRowPerReasonAllLocationsListed(t *testing.T) {
	src := "class C {\n" +
		"  func a() {\n" +
		"    NotificationCenter.default.addObserver(self, selector: #selector(onA), name: n1, object: nil)\n" +
		"  }\n" +
		"  func b() {\n" +
		"    NotificationCenter.default.addObserver(self, selector: #selector(onB), name: n2, object: nil)\n" +
		"  }\n" +
		"  func c() {\n" +
		"    NotificationCenter.default.addObserver(self, selector: #selector(onC), name: n3, object: nil)\n" +
		"  }\n" +
		"}\n"
	f := mlFile(t, "swift", ".swift", src)
	r := mlAnalyze([]*parser.ParsedFile{f})
	if r.High < 3 {
		t.Fatalf("fixture should produce 3 HIGH findings for the same rule, got %+v", r.Findings)
	}
	got := (MemoryLeaks{}).RenderHTML(r)
	// The reason text should appear exactly once even though it fired 3 times.
	if n := strings.Count(got, "NotificationCenter observer never removed"); n != 1 {
		t.Errorf("want the label written exactly once, found %d times in:\n%s", n, got)
	}
	// All three locations should still be present and linked.
	for _, line := range []string{":3\"", ":6\"", ":9\""} {
		if !strings.Contains(got, line) {
			t.Errorf("want a location link for line ending %q, got:\n%s", line, got)
		}
	}
}

func TestMemoryLeaks_LocationsCappedAt200(t *testing.T) {
	locs := make([]mlLocation, 250)
	for i := range locs {
		locs[i] = mlLocation{FilePath: "/f.go", Line: i + 1}
	}
	htmlOut := mlLocationLinks(locs)
	if n := strings.Count(htmlOut, `class="as-vs"`); n != 200 {
		t.Errorf("want exactly 200 location links rendered, got %d", n)
	}
	if !strings.Contains(htmlOut, "+50 more") {
		t.Errorf("want a '+50 more' overflow marker, got:\n%s", htmlOut)
	}

	mdOut := mlLocationsMD(locs)
	if n := strings.Count(mdOut, "f.go:"); n != 200 {
		t.Errorf("want exactly 200 locations in the markdown rendering, got %d", n)
	}
	if !strings.Contains(mdOut, "+50 more") {
		t.Errorf("want a '+50 more' overflow marker in markdown, got:\n%s", mdOut)
	}
}
