package security_test

import (
	"strings"
	"testing"

	"github.com/exey/archscope/internal/security"
	_ "github.com/exey/archscope/internal/security/universal"
)

// memLoader serves in-memory file contents so the test needs no disk fixtures.
type memLoader map[string][]string

func (m memLoader) Load(path string) ([]string, error) { return m[path], nil }

func TestHardcodedSecretsAcrossLanguages(t *testing.T) {
	files := memLoader{
		"/repo/a.swift":  {`let apiKey = "AIzaSyD-1234567890abcdef"`},
		"/repo/b.py":     {`password = "hunter2hunter2"`},
		"/repo/c.ts":     {`const secret = "abcdef0123456789";`},
		"/repo/clean.go": {`x := 1`},
		"/repo/skip.go":  {`token = "placeholder"`}, // skip word -> no finding
	}
	srcs := []security.SourceFile{
		{Path: "/repo/a.swift", LanguageID: "swift"},
		{Path: "/repo/b.py", LanguageID: "python"},
		{Path: "/repo/c.ts", LanguageID: "ts"},
		{Path: "/repo/clean.go", LanguageID: "go"},
		{Path: "/repo/skip.go", LanguageID: "go"},
	}

	eng := security.NewEngine()
	// Register only the universal rules under test by copying from Default.
	for _, r := range security.Default.Rules() {
		if strings.HasPrefix(r.ID, "universal.") {
			eng.RegisterRule(r)
		}
	}

	results, score := eng.RunWithScore(srcs, files, "")

	// The hardcoded-secrets rule should fire exactly 3 times (swift, py, ts).
	var secretCount int
	for _, rr := range results {
		if rr.Rule.ID == "universal.hardcoded_secrets" {
			secretCount = rr.TotalCount
		}
	}
	if secretCount != 3 {
		t.Errorf("hardcoded_secrets findings = %d, want 3", secretCount)
	}

	// Index should be > 0 and land in the data-storage category.
	if score.Total <= 0 {
		t.Errorf("security index = %d, want > 0", score.Total)
	}
	var dataStoragePoints int
	for _, cs := range score.Categories {
		if cs.Category.Key == "insecure_data_storage" {
			dataStoragePoints = cs.Points
		}
	}
	if dataStoragePoints <= 0 {
		t.Errorf("insecure_data_storage points = %d, want > 0", dataStoragePoints)
	}
	if score.Band == "" {
		t.Errorf("band empty")
	}
}

func TestLanguageScopedRuleFiltering(t *testing.T) {
	eng := security.NewEngine()
	eng.RegisterRule(security.Rule{
		ID:        "swift.only",
		Severity:  security.SevHigh,
		Category:  "crash_factors",
		Languages: []string{"swift"},
		Detect: func(_ string, lines []string) []security.Finding {
			return []security.Finding{{Line: 1}}
		},
	})

	files := memLoader{
		"/r/a.swift": {"x"},
		"/r/b.go":    {"x"},
	}
	srcs := []security.SourceFile{
		{Path: "/r/a.swift", LanguageID: "swift"},
		{Path: "/r/b.go", LanguageID: "go"},
	}
	results := eng.Run(srcs, files, "", nil)

	var count int
	for _, rr := range results {
		if rr.Rule.ID == "swift.only" {
			count = rr.TotalCount
		}
	}
	if count != 1 {
		t.Errorf("swift-only rule fired %d times, want 1 (swift file only)", count)
	}
}
