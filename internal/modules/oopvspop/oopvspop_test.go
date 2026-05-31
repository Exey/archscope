package oopvspop

import (
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func swiftFile(extra map[string]any, decls ...parser.Declaration) *parser.ParsedFile {
	return &parser.ParsedFile{LanguageID: "swift", Declarations: decls, Extra: extra}
}
func d(k parser.DeclKind) parser.Declaration { return parser.Declaration{Name: "X", Kind: k} }

func TestAppliesOnlyToSwift(t *testing.T) {
	if (Module{}).AppliesTo("go") {
		t.Errorf("should not apply to Go")
	}
	if !(Module{}).AppliesTo("swift") {
		t.Errorf("should apply to Swift")
	}
}

func TestPOPLeaning(t *testing.T) {
	// Protocol-rich, value-typed codebase with associatedtype/some/generics.
	files := []*parser.ParsedFile{
		swiftFile(map[string]any{"oopAssoc": 2, "oopSome": 3, "oopGenerics": 3},
			d(parser.DeclInterface), d(parser.DeclInterface), d(parser.DeclInterface), d(parser.DeclInterface),
			d(parser.DeclStruct), d(parser.DeclStruct), d(parser.DeclStruct), d(parser.DeclEnum),
			d(parser.DeclExtension), d(parser.DeclExtension), d(parser.DeclExtension), d(parser.DeclExtension)),
	}
	res := (Module{}).Analyze(files).(Result)
	if !res.HasData() {
		t.Fatal("expected data")
	}
	if res.POPPercent() < 55 {
		t.Errorf("POP percent = %d, want >= 55 (protocol-oriented)", res.POPPercent())
	}
	if !strings.Contains(res.Verdict, "protocol-oriented") {
		t.Errorf("verdict = %q, want protocol-oriented", res.Verdict)
	}
}

func TestOOPLeaning(t *testing.T) {
	// Class-heavy with overrides, NSObject inheritance and a singleton.
	files := []*parser.ParsedFile{
		swiftFile(map[string]any{"oopOverride": 6, "oopNSObject": 3, "oopSingletons": 1},
			d(parser.DeclClass), d(parser.DeclClass), d(parser.DeclClass), d(parser.DeclClass)),
	}
	res := (Module{}).Analyze(files).(Result)
	if res.POPPercent() > 40 {
		t.Errorf("POP percent = %d, want low (object-oriented)", res.POPPercent())
	}
	if !strings.Contains(res.Verdict, "object-oriented") {
		t.Errorf("verdict = %q, want object-oriented", res.Verdict)
	}
}

func TestRenderHasCategoryBarsAndTable(t *testing.T) {
	files := []*parser.ParsedFile{
		swiftFile(nil, d(parser.DeclStruct), d(parser.DeclInterface), d(parser.DeclClass)),
	}
	out := (Module{}).RenderHTML((Module{}).Analyze(files))
	for _, want := range []string{"as-pop__track", "as-pop__catbar", "as-pop__metrics", "Protocol Design"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q", want)
		}
	}
}

func TestIgnoresNonSwiftFiles(t *testing.T) {
	files := []*parser.ParsedFile{{LanguageID: "go", Declarations: []parser.Declaration{d(parser.DeclStruct)}}}
	res := (Module{}).Analyze(files).(Result)
	if res.HasData() {
		t.Errorf("non-swift files should be ignored")
	}
}
