package scanner_test

import (
	"path/filepath"
	"testing"

	"github.com/exey/archscope/internal/config"
	_ "github.com/exey/archscope/internal/lang"
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/scanner"
)

func TestScanMultiLanguage(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "multi")
	res, err := scanner.Scan(root, config.Default(), langspec.Default)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Four platforms present.
	wantPlatforms := map[langspec.Platform]int{
		langspec.PlatformSwiftObjC: 1, // Auth.swift (Package.swift counts too)
		langspec.PlatformPython:    1, // app.py
		langspec.PlatformTSJS:      1, // index.ts
		langspec.PlatformGo:        1, // main.go
	}
	for p, min := range wantPlatforms {
		g := res.Platforms[p]
		if g == nil {
			t.Errorf("platform %s missing", p)
			continue
		}
		if g.FileCount < min {
			t.Errorf("platform %s fileCount = %d, want >= %d", p, g.FileCount, min)
		}
	}

	// Module attribution via marker files.
	wantModule := map[string]string{ // a file substring -> expected module
		"main.go":    "backend",
		"app.py":     "web",
		"index.ts":   "web",
		"Auth.swift": "ios",
	}
	for _, fe := range res.Files {
		base := filepath.Base(fe.Path)
		if want, ok := wantModule[base]; ok {
			if fe.ModuleName != want {
				t.Errorf("%s module = %q, want %q", base, fe.ModuleName, want)
			}
		}
	}

	// Project types detected.
	wantPT := map[string]bool{"Go module": true, "Node": true, "SwiftPM": true, "Gradle": true}
	for _, pt := range res.ProjectTypes {
		if !wantPT[pt] {
			t.Errorf("unexpected project type %q", pt)
		}
		delete(wantPT, pt)
	}
	if len(wantPT) > 0 {
		t.Errorf("missing project types: %v", wantPT)
	}

	// Canonical tab order (Kotlin sits between Swift+ObjC and Python).
	ordered := res.PlatformsOrdered()
	if len(ordered) != 5 {
		t.Fatalf("ordered platforms = %d, want 5", len(ordered))
	}
	if ordered[0].Platform != langspec.PlatformSwiftObjC || ordered[len(ordered)-1].Platform != langspec.PlatformGo {
		t.Errorf("tab order wrong: %v", []langspec.Platform{ordered[0].Platform, ordered[len(ordered)-1].Platform})
	}
}
