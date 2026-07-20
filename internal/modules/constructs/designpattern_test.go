package constructs

import (
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func patternNames(files []*parser.ParsedFile) map[string]int {
	res := (DesignPatterns{}).Analyze(files).(DesignPatternResult)
	got := map[string]int{}
	for _, m := range res.Matches {
		got[m.Pattern] = m.Count
	}
	return got
}

func TestDetectsSuffixPatterns(t *testing.T) {
	files := []*parser.ParsedFile{
		file("a.swift", ty("RequestBuilder")),
		file("b.swift", ty("ViewControllerFactory")),
		file("c.ts", ty("EventObserver")),
		file("d.go", ty("PaymentStrategy")),
	}
	res := (DesignPatterns{}).Analyze(files).(DesignPatternResult)
	if !res.HasDetection() {
		t.Fatal("expected detections")
	}
	got := map[string]bool{}
	for _, m := range res.Matches {
		got[m.Pattern] = true
	}
	for _, want := range []string{"Builder", "Factory Method", "Observer", "Strategy"} {
		if !got[want] {
			t.Errorf("missing pattern %q (got %v)", want, got)
		}
	}
}

func TestIgnoresNonBoundarySuffix(t *testing.T) {
	// "Factorial" must NOT match "Factory"; "Commander" must NOT match "Command".
	files := []*parser.ParsedFile{file("a.go", ty("Factorial"), ty("Commander"))}
	res := (DesignPatterns{}).Analyze(files).(DesignPatternResult)
	if res.HasDetection() {
		t.Errorf("expected no detections, got %+v", res.Matches)
	}
}

func TestScanSwiftFileIgnoresMultilineStringProse(t *testing.T) {
	// scanSwiftFile reads through the shared sourceCache (readSource), which
	// tracks multi-line string state across line boundaries — a per-line
	// stateless stripper can't know a line is still inside an unterminated
	// triple-quoted string, and would let this prose register as evidence.
	src := `class Docs {
    let help = """
    Remember to use lazy var for expensive properties.
    """
}
`
	f := writeFile(t, ".swift", src,
		parser.Declaration{Name: "Docs", Kind: parser.DeclClass, Line: 1})
	got := patternNames([]*parser.ParsedFile{f})
	if _, ok := got["Lazy Initialization"]; ok {
		t.Errorf("expected no Lazy Initialization from prose inside a multi-line string, got %v", got)
	}
}

func TestHandlerRequiresSuccessorLink(t *testing.T) {
	// A *Handler type only counts as Chain of Responsibility when its body
	// proves it holds a reference to the next link in the chain — otherwise
	// ordinary HTTP/completion/event handlers would all falsely report it.
	src := `class ErrorHandler {
    var next: ErrorHandler?
    func handle(_ e: Error) {
        next?.handle(e)
    }
}
`
	f := writeFile(t, ".swift", src,
		parser.Declaration{Name: "ErrorHandler", Kind: parser.DeclClass, Line: 1})
	got := patternNames([]*parser.ParsedFile{f})
	if got["Chain of Responsibility"] != 1 {
		t.Errorf("expected Chain of Responsibility from the next-field link, got %v", got)
	}
}

func TestHandlerWithoutSuccessorLinkNotCoR(t *testing.T) {
	src := `class URLRequestHandler {
    func handle(_ request: URLRequest) {
        print(request)
    }
}
`
	f := writeFile(t, ".swift", src,
		parser.Declaration{Name: "URLRequestHandler", Kind: parser.DeclClass, Line: 1})
	got := patternNames([]*parser.ParsedFile{f})
	if _, ok := got["Chain of Responsibility"]; ok {
		t.Errorf("expected no Chain of Responsibility without a successor link, got %v", got)
	}
}

func TestFactoryLabelSplitsMethodVsAbstract(t *testing.T) {
	// No protocol among the Factory-suffixed decls → Factory Method.
	got := patternNames([]*parser.ParsedFile{file("a.go", ty("WidgetFactory"))})
	if got["Factory Method"] != 1 {
		t.Errorf("expected Factory Method, got %v", got)
	}
	if _, ok := got["Abstract Factory"]; ok {
		t.Errorf("must not also report Abstract Factory: %v", got)
	}

	// A protocol/interface among the Factory-suffixed decls (anywhere in the
	// codebase) → the whole group relabels to Abstract Factory.
	files := []*parser.ParsedFile{
		file("a.swift", parser.Declaration{Name: "WidgetFactory", Kind: parser.DeclInterface, Line: 1}),
		file("b.swift", ty("ConcreteWidgetFactory")),
	}
	got = patternNames(files)
	if got["Abstract Factory"] != 2 {
		t.Errorf("expected Abstract Factory ×2, got %v", got)
	}
	if _, ok := got["Factory Method"]; ok {
		t.Errorf("must not also report Factory Method: %v", got)
	}
}

func TestDetectsMarkerInterface(t *testing.T) {
	f := writeFile(t, ".swift", "protocol Trashable {}\n",
		parser.Declaration{Name: "Trashable", Kind: parser.DeclInterface, Line: 1})
	got := patternNames([]*parser.ParsedFile{f})
	if got["Marker"] != 1 {
		t.Errorf("expected Marker, got %v", got)
	}
}

func TestMarkerRejectsNonEmptyProtocol(t *testing.T) {
	f := writeFile(t, ".swift", "protocol Greeter {\n    func greet()\n}\n",
		parser.Declaration{Name: "Greeter", Kind: parser.DeclInterface, Line: 1})
	got := patternNames([]*parser.ParsedFile{f})
	if _, ok := got["Marker"]; ok {
		t.Errorf("a protocol with a member must not be a Marker: %v", got)
	}
}

func TestDetectsDelegationOnlyOnProtocols(t *testing.T) {
	files := []*parser.ParsedFile{
		file("a.swift", parser.Declaration{Name: "AccountDelegate", Kind: parser.DeclInterface, Line: 1}),
		file("b.swift", ty("NotADelegateProtocolClass")), // a class, not a protocol
	}
	got := patternNames(files)
	if got["Delegation"] != 1 {
		t.Errorf("expected Delegation ×1 (protocol only), got %v", got)
	}
}

func TestDetectsNullObject(t *testing.T) {
	files := []*parser.ParsedFile{
		file("a.go", ty("NullUser")),
		file("b.go", ty("Nullable")), // must NOT match — no boundary after "Null"
	}
	got := patternNames(files)
	if got["Null Object"] != 1 {
		t.Errorf("expected Null Object ×1, got %v", got)
	}
}

func TestDetectsCaching(t *testing.T) {
	got := patternNames([]*parser.ParsedFile{file("a.go", ty("ImageCache"))})
	if got["Caching"] != 1 {
		t.Errorf("expected Caching, got %v", got)
	}
}

func TestDetectsMementoAndSnapshot(t *testing.T) {
	files := []*parser.ParsedFile{
		file("a.go", parser.Declaration{Name: "EditorMemento", Kind: parser.DeclStruct, Line: 1}),
		file("b.go", parser.Declaration{Name: "ChatSnapshot", Kind: parser.DeclStruct, Line: 1}),
	}
	got := patternNames(files)
	if got["Memento"] != 2 {
		t.Errorf("expected Memento ×2 (Memento + Snapshot suffixes), got %v", got)
	}
}

func TestDetectsPrototypeFromContent(t *testing.T) {
	f := swiftFile(t,
		"final class Node: NSCopying {\n    func copy(with zone: NSZone? = nil) -> Any { Node() }\n}\n",
		parser.Declaration{Name: "Node", Kind: parser.DeclClass, Line: 1})
	got := patternNames([]*parser.ParsedFile{f})
	if got["Prototype"] != 1 {
		t.Errorf("expected Prototype from NSCopying conformance, got %v", got)
	}
}

func TestPrototypeSuffixAloneIsNotEnough(t *testing.T) {
	// A type merely named "*Prototype" with no NSCopying/copy()/clone() must
	// not match — Prototype is content-based now, not suffix-based.
	f := swiftFile(t, "final class WidgetPrototype {\n    var value = 0\n}\n",
		parser.Declaration{Name: "WidgetPrototype", Kind: parser.DeclClass, Line: 1})
	got := patternNames([]*parser.ParsedFile{f})
	if _, ok := got["Prototype"]; ok {
		t.Errorf("name alone must not trigger Prototype: %v", got)
	}
}

func TestRenderGroupsByCategory(t *testing.T) {
	files := []*parser.ParsedFile{file("a.swift", ty("UserFactory"))}
	out := (DesignPatterns{}).RenderHTML((DesignPatterns{}).Analyze(files))
	if !strings.Contains(out, "Creational") || !strings.Contains(out, "Factory Method") {
		t.Errorf("render missing category/pattern: %s", out)
	}
}
