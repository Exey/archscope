package result_test

import (
	"testing"

	"github.com/exey/archscope/internal/config"
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/result"

	// Registration side effects: languages, universal rules, report modules.
	_ "github.com/exey/archscope/internal/lang"
	_ "github.com/exey/archscope/internal/modules/arch"
	_ "github.com/exey/archscope/internal/modules/constructs"
	_ "github.com/exey/archscope/internal/modules/dddmodel"
	_ "github.com/exey/archscope/internal/modules/oopvspop"
	_ "github.com/exey/archscope/internal/modules/traffic"
	_ "github.com/exey/archscope/internal/security/universal"
)

func TestPipelineOnArchSample(t *testing.T) {
	cfg := config.Default()
	res, err := result.Run("../../testdata/arch-sample", cfg)
	if err != nil {
		t.Fatalf("pipeline error: %v", err)
	}
	if len(res.Files) == 0 {
		t.Fatal("expected parsed files")
	}
	if res.SecurityScore.Band == "" {
		t.Errorf("expected a non-empty security band")
	}
	if res.ProjectName == "" {
		t.Errorf("expected a derived project name")
	}

	// The architecture + design-pattern modules are universal and should have
	// produced panels for the Swift platform tab.
	var archPanel, dpPanel bool
	for _, p := range res.PanelsForPlatform(langspec.PlatformSwiftObjC) {
		switch p.ModuleID {
		case "architecture":
			archPanel = true
		case "designpattern":
			dpPanel = true
		}
	}
	if !archPanel {
		t.Errorf("expected an architecture panel in the Swift tab")
	}
	if !dpPanel {
		t.Errorf("expected a design-pattern panel in the Swift tab")
	}
}

func TestPipelineOnMultiLanguage(t *testing.T) {
	cfg := config.Default()
	res, err := result.Run("../../testdata/multi", cfg)
	if err != nil {
		t.Fatalf("pipeline error: %v", err)
	}
	platforms := res.Scan.PlatformsOrdered()
	if len(platforms) < 4 {
		t.Errorf("expected all 4 platforms present, got %d", len(platforms))
	}
	// Universal hardcoded-secrets should fire across the planted secrets.
	if res.TotalFindings() == 0 {
		t.Errorf("expected security findings in the multi fixture")
	}
}
