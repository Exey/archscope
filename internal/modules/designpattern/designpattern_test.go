package designpattern

import (
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func file(name string, decls ...parser.Declaration) *parser.ParsedFile {
	return &parser.ParsedFile{FilePath: name, Declarations: decls}
}
func t(name string) parser.Declaration { return parser.Declaration{Name: name, Kind: parser.DeclClass} }

func TestDetectsSuffixPatterns(t_ *testing.T) {
	files := []*parser.ParsedFile{
		file("a.swift", t("RequestBuilder")),
		file("b.swift", t("ViewControllerFactory")),
		file("c.ts", t("EventObserver")),
		file("d.go", t("PaymentStrategy")),
	}
	res := (Module{}).Analyze(files).(Result)
	if !res.HasDetection() {
		t_.Fatal("expected detections")
	}
	got := map[string]bool{}
	for _, m := range res.Matches {
		got[m.Pattern] = true
	}
	for _, want := range []string{"Builder", "Factory Method", "Observer", "Strategy"} {
		if !got[want] {
			t_.Errorf("missing pattern %q (got %v)", want, got)
		}
	}
}

func TestIgnoresNonBoundarySuffix(t_ *testing.T) {
	// "Factorial" must NOT match "Factory"; "Commander" must NOT match "Command".
	files := []*parser.ParsedFile{file("a.go", t("Factorial"), t("Commander"))}
	res := (Module{}).Analyze(files).(Result)
	if res.HasDetection() {
		t_.Errorf("expected no detections, got %+v", res.Matches)
	}
}

func TestRenderGroupsByCategory(t_ *testing.T) {
	files := []*parser.ParsedFile{file("a.swift", t("UserFactory"))}
	out := (Module{}).RenderHTML((Module{}).Analyze(files))
	if !strings.Contains(out, "Creational") || !strings.Contains(out, "Factory Method") {
		t_.Errorf("render missing category/pattern: %s", out)
	}
}
