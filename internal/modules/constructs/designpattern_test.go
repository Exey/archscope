package constructs

import (
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

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

func TestRenderGroupsByCategory(t *testing.T) {
	files := []*parser.ParsedFile{file("a.swift", ty("UserFactory"))}
	out := (DesignPatterns{}).RenderHTML((DesignPatterns{}).Analyze(files))
	if !strings.Contains(out, "Creational") || !strings.Contains(out, "Factory Method") {
		t.Errorf("render missing category/pattern: %s", out)
	}
}
