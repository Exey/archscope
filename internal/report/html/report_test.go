package html

import (
	"strings"
	"testing"

	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/result"
	"github.com/exey/archscope/internal/scanner"
	"github.com/exey/archscope/internal/security"
)

func minimalResult() *result.AnalysisResult {
	score := security.NewEngine().ComputeScore(nil, 1) // valid empty score + band
	pg := &scanner.PlatformGroup{
		Platform:  langspec.PlatformGo,
		FileCount: 1,
		Modules:   []string{"app"},
	}
	scan := &scanner.ScanResult{
		Root:      "/x",
		Platforms: map[langspec.Platform]*scanner.PlatformGroup{langspec.PlatformGo: pg},
		Modules:   map[string][]scanner.FileEntry{"app": {}},
	}
	return &result.AnalysisResult{
		ProjectName: "demo",
		RootPath:    "/x",
		Scan:        scan,
		Files: []*parser.ParsedFile{
			{FilePath: "/x/main.go", LanguageID: "go", Platform: string(langspec.PlatformGo),
				ModuleName: "app", LineCount: 10},
		},
		SecurityScore: score,
	}
}

func TestRenderContainsCoreSections(t *testing.T) {
	out := Render(minimalResult())
	for _, want := range []string{
		"<!doctype html>", "as-tabbar", "Danger Index", "as-gauge__num",
		"Git Analysis", `id="t0"`, `id="p0"`, "as-theme-toggle", "ArchScope",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered HTML missing %q", want)
		}
	}
}

func TestRenderShowsPlatformTab(t *testing.T) {
	out := Render(minimalResult())
	if !strings.Contains(out, langspec.PlatformTitle(langspec.PlatformGo)) {
		t.Errorf("expected a Go platform tab label")
	}
}

func TestRenderNoGitDegradesGracefully(t *testing.T) {
	out := Render(minimalResult())
	if !strings.Contains(out, "No git history available") {
		t.Errorf("expected graceful no-git message")
	}
}

func TestRenderIsSelfContained(t *testing.T) {
	out := Render(minimalResult())
	// No external stylesheet/script references — everything inlined.
	if strings.Contains(out, "<link ") || strings.Contains(out, "src=\"http") {
		t.Errorf("report should be self-contained (no external link/src)")
	}
}
