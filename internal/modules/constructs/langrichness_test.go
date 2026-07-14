package constructs

import (
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func lrAnalyze(files []*parser.ParsedFile) LanguageRichnessReport {
	return (LanguageRichness{}).Analyze(files).(LanguageRichnessReport)
}

func TestLanguageRichnessCountsDistinctKeywords(t *testing.T) {
	src := "package p\nfunc Foo() {\n\tfor i := 0; i < 1; i++ {\n\t\tif i == 0 {\n\t\t\tbreak\n\t\t}\n\t}\n}\n"
	f := writeFile(t, ".go", src)
	f.LanguageID = "go"
	r := lrAnalyze([]*parser.ParsedFile{f})
	if len(r.Entries) != 1 {
		t.Fatalf("expected one entry, got %+v", r.Entries)
	}
	e := r.Entries[0]
	if e.Lang != "go" || e.Total != len(languageKeywords["go"]) {
		t.Errorf("unexpected entry: %+v", e)
	}
	// package, func, for, if, break — 5 distinct keywords used.
	if e.Found != 5 {
		t.Errorf("expected 5 keywords found, got %d", e.Found)
	}
	if e.Percent != e.Found*100/e.Total {
		t.Errorf("percent mismatch: %+v", e)
	}
}

func TestLanguageRichnessIgnoresKeywordInsideIdentifier(t *testing.T) {
	// "class" must not match inside "className" (word-boundary check).
	src := "const className = 1\n"
	f := writeFile(t, ".ts", src)
	f.LanguageID = "ts"
	r := lrAnalyze([]*parser.ParsedFile{f})
	e := r.Entries[0]
	if e.Found != 1 { // only "const" itself
		t.Errorf("expected only 'const' to match, got %d found", e.Found)
	}
}

func TestLanguageRichnessIgnoresKeywordInComment(t *testing.T) {
	src := "// switch case for while\npackage p\nfunc Foo() {}\n"
	f := writeFile(t, ".go", src)
	f.LanguageID = "go"
	r := lrAnalyze([]*parser.ParsedFile{f})
	e := r.Entries[0]
	if e.Found != 2 { // "package" and "func" from real code; the comment's switch/case/for/while must not count
		t.Errorf("comment keywords must not count, got %d found: %+v", e.Found, e)
	}
}

func TestLanguageRichnessSkipsUnknownLanguages(t *testing.T) {
	f := writeFile(t, ".rb", "def foo; end\n")
	f.LanguageID = "ruby"
	r := lrAnalyze([]*parser.ParsedFile{f})
	if r.HasData() {
		t.Errorf("expected no entries for an unknown language, got %+v", r.Entries)
	}
}

func TestLanguageRichnessAppliesToKnownLanguagesOnly(t *testing.T) {
	lr := LanguageRichness{}
	if !lr.AppliesTo("go") || !lr.AppliesTo("swift") {
		t.Error("expected AppliesTo true for known languages")
	}
	if lr.AppliesTo("ruby") {
		t.Error("expected AppliesTo false for an unknown language")
	}
}

func TestLanguageRichnessRenderHTML(t *testing.T) {
	src := "package p\nfunc Foo() { for {} }\n"
	f := writeFile(t, ".go", src)
	f.LanguageID = "go"
	out := (LanguageRichness{}).RenderHTML(lrAnalyze([]*parser.ParsedFile{f}))
	if !strings.Contains(out, "as-lr__bar") || !strings.Contains(out, "%") {
		t.Errorf("render missing bar/percentage: %s", out)
	}
}
