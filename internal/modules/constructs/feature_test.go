package constructs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func detect(files []*parser.ParsedFile) map[string]PatternMatch {
	res := (DesignPatterns{}).Analyze(files).(DesignPatternResult)
	got := map[string]PatternMatch{}
	for _, m := range res.Matches {
		got[m.Pattern] = m
	}
	return got
}

// swiftFile writes src to a temp .swift file and returns a ParsedFile with
// LanguageID "swift" carrying decls.
func swiftFile(t *testing.T, src string, decls ...parser.Declaration) *parser.ParsedFile {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f.swift")
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return &parser.ParsedFile{FilePath: p, LanguageID: "swift", Declarations: decls}
}

func TestFeatureFlagBySuffix(t *testing.T) {
	files := []*parser.ParsedFile{
		file("a.go", ty("NewCheckoutFeatureFlag")),
		file("b.ts", ty("DarkModeFeatureToggle")),
	}
	got := detect(files)
	if got["Feature Flag"].Count != 2 {
		t.Errorf("want Feature Flag x2, got %+v", got["Feature Flag"])
	}
}

func TestFeatureFlagBySDKImport(t *testing.T) {
	f := &parser.ParsedFile{FilePath: "a.go", Imports: []string{"github.com/launchdarkly/go-server-sdk"}}
	got := detect([]*parser.ParsedFile{f})
	if got["Feature Flag"].Count != 1 {
		t.Errorf("want Feature Flag x1 from LaunchDarkly import, got %+v", got["Feature Flag"])
	}
	// A file with no matching import must not fire.
	clean := &parser.ParsedFile{FilePath: "b.go", Imports: []string{"net/http"}}
	if _, ok := detect([]*parser.ParsedFile{clean})["Feature Flag"]; ok {
		t.Error("unexpected Feature Flag on unrelated import")
	}
}

func TestDependencyInjectionBySuffix(t *testing.T) {
	files := []*parser.ParsedFile{file("a.kt", ty("AppServiceLocator"), ty("NetworkDIContainer"))}
	got := detect(files)
	if got["Dependency Injection"].Count != 2 {
		t.Errorf("want Dependency Injection x2, got %+v", got["Dependency Injection"])
	}
}

// ── Swift language-feature idioms (require real files: content-scanned) ─────

func TestExtensionIsLanguageIdiom(t *testing.T) {
	f := swiftFile(t, "extension String {}\n",
		parser.Declaration{Name: "String", Kind: parser.DeclExtension, Line: 1})
	got := detect([]*parser.ParsedFile{f})
	m, ok := got["Extension"]
	if !ok || m.Count != 1 {
		t.Fatalf("want Extension x1, got %+v", got)
	}
	if !m.IsIdiom {
		t.Error("Extension must be marked as a language idiom")
	}
}

func TestMonitorObjectFromActor(t *testing.T) {
	f := swiftFile(t, "actor Cache {}\n",
		parser.Declaration{Name: "Cache", Kind: parser.DeclActor, Line: 1})
	got := detect([]*parser.ParsedFile{f})
	m, ok := got["Monitor Object"]
	if !ok || m.Count != 1 || !m.IsIdiom {
		t.Fatalf("want Monitor Object x1 (idiom), got %+v", got)
	}
}

func TestLazyInitializationFromContent(t *testing.T) {
	f := swiftFile(t, "final class Foo {\n    lazy var bar: Int = compute()\n}\n")
	got := detect([]*parser.ParsedFile{f})
	m, ok := got["Lazy Initialization"]
	if !ok || m.Count != 1 || !m.IsIdiom {
		t.Fatalf("want Lazy Initialization x1 (idiom), got %+v", got)
	}
}

func TestReadWriteLockFromBarrierQueue(t *testing.T) {
	src := "final class Store {\n" +
		"    let queue = DispatchQueue(label: \"x\", attributes: .concurrent)\n" +
		"    func write() { queue.async(flags: .barrier) {} }\n" +
		"}\n"
	got := detect([]*parser.ParsedFile{swiftFile(t, src)})
	if got["Read–Write Lock"].Count != 1 {
		t.Errorf("want Read–Write Lock x1, got %+v", got["Read–Write Lock"])
	}
}

func TestThreadPoolRequiresConcurrencyAboveOne(t *testing.T) {
	pooled := "let q = OperationQueue()\nq.maxConcurrentOperationCount = 4\n"
	got := detect([]*parser.ParsedFile{swiftFile(t, pooled)})
	if got["Thread Pool"].Count != 1 {
		t.Errorf("want Thread Pool x1 for concurrency=4, got %+v", got["Thread Pool"])
	}

	serial := "let q = OperationQueue()\nq.maxConcurrentOperationCount = 1\n"
	if _, ok := detect([]*parser.ParsedFile{swiftFile(t, serial)})["Thread Pool"]; ok {
		t.Error("maxConcurrentOperationCount = 1 is serial, must not report Thread Pool")
	}
}

func TestFluentInterfaceRequiresAtLeastTwo(t *testing.T) {
	one := "func withName(_ n: String) -> Self { self }\n"
	if _, ok := detect([]*parser.ParsedFile{swiftFile(t, one)})["Fluent Interface"]; ok {
		t.Error("a single -> Self method must not report Fluent Interface")
	}
	two := "func withName(_ n: String) -> Self { self }\n" +
		"func withAge(_ a: Int) -> Self { self }\n"
	if got := detect([]*parser.ParsedFile{swiftFile(t, two)}); got["Fluent Interface"].Count != 1 {
		t.Errorf("want Fluent Interface x1 with 2 -> Self methods, got %+v", got["Fluent Interface"])
	}
}

func TestMultitonFromStaticInstancesDict(t *testing.T) {
	src := "final class Theme {\n    static var instances: [String: Theme] = [:]\n}\n"
	got := detect([]*parser.ParsedFile{swiftFile(t, src)})
	if got["Multiton"].Count != 1 {
		t.Errorf("want Multiton x1, got %+v", got["Multiton"])
	}
}

func TestDependencyInjectionFromSwinjectImport(t *testing.T) {
	got := detect([]*parser.ParsedFile{swiftFile(t, "import Swinject\n")})
	if got["Dependency Injection"].Count != 1 {
		t.Errorf("want Dependency Injection x1 from Swinject import, got %+v", got["Dependency Injection"])
	}
}

func TestObserverFromCombineSignal(t *testing.T) {
	got := detect([]*parser.ParsedFile{swiftFile(t, "final class VM: ObservableObject {\n    @Published var x = 0\n}\n")})
	if got["Observer"].Count != 1 {
		t.Errorf("want Observer x1 from @Published/ObservableObject, got %+v", got["Observer"])
	}
}

func TestDoubleCheckedLockingNeedsRepeatedNilCheck(t *testing.T) {
	src := "var lock = os_unfair_lock()\n" +
		"if cached == nil {\nos_unfair_lock_lock(&lock)\nif cached == nil { cached = make() }\nos_unfair_lock_unlock(&lock)\n}\n"
	got := detect([]*parser.ParsedFile{swiftFile(t, src)})
	if got["Double-Checked Locking"].Count != 1 {
		t.Errorf("want Double-Checked Locking x1, got %+v", got["Double-Checked Locking"])
	}
}

func TestSwiftIdiomsAreSwiftOnly(t *testing.T) {
	// The same shapes on a non-Swift-tagged file must not fire the Swift-only
	// content scan or the actor/extension idiom detection.
	f := &parser.ParsedFile{FilePath: "a.go", LanguageID: "go",
		Declarations: []parser.Declaration{{Name: "Foo", Kind: parser.DeclExtension}}}
	got := detect([]*parser.ParsedFile{f})
	if _, ok := got["Extension"]; ok {
		t.Error("Extension idiom must be gated to Swift files")
	}
}

func TestIdiomsExcludedFromSummaryCount(t *testing.T) {
	f := swiftFile(t, "extension String {}\n",
		parser.Declaration{Name: "String", Kind: parser.DeclExtension, Line: 1})
	res := (DesignPatterns{}).Analyze([]*parser.ParsedFile{f})
	cards := (DesignPatterns{}).SummaryCards(res)
	if len(cards) != 0 {
		t.Errorf("an idiom-only result must not surface a summary card, got %+v", cards)
	}
}

func TestRenderMarksIdiomRow(t *testing.T) {
	f := swiftFile(t, "extension String {}\n",
		parser.Declaration{Name: "String", Kind: parser.DeclExtension, Line: 1})
	out := (DesignPatterns{}).RenderHTML((DesignPatterns{}).Analyze([]*parser.ParsedFile{f}))
	if !strings.Contains(out, "language idiom") {
		t.Errorf("render missing idiom badge: %s", out)
	}
	if !strings.Contains(out, "Concurrency") && !strings.Contains(out, "Structural") {
		t.Errorf("render missing category heading: %s", out)
	}
}
