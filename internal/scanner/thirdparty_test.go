package scanner_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/exey/archscope/internal/config"
	_ "github.com/exey/archscope/internal/lang"
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/scanner"
)

// TestScanSkipsThirdPartyBuildSystemAndScripts reproduces the folder layout
// found in large real-world monorepos (e.g. Telegram-iOS): a first-party
// "submodules" directory of the app's own modules sitting alongside
// "third-party" (vendored external libraries), "build-system" (build
// tooling), and "scripts" (CI/debugging helpers) — none of which are
// declared as git submodules, so ParseGitSubmodules alone can't catch them.
func TestScanSkipsThirdPartyBuildSystemAndScripts(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("submodules/Display/Display.swift", "import Foundation\nclass Display {}\n")
	write("Telegram/App/App.swift", "import UIKit\nclass App {}\n")
	write("third-party/webrtc/WebRTC.swift", "import Foundation\nclass WebRTC {}\n")
	write("build-system/Make/Make.swift", "import Foundation\nclass Make {}\n")
	write("scripts/helper.py", "print('hi')\n")

	cfg := config.Default()
	res, err := scanner.Scan(root, cfg, langspec.Default)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Files) != 2 {
		t.Fatalf("want 2 files (submodules + Telegram kept, third-party/build-system/scripts skipped), got %d: %v",
			len(res.Files), res.Files)
	}
	for _, f := range res.Files {
		for _, bad := range []string{"third-party", "build-system", "scripts"} {
			if filepath.Base(filepath.Dir(filepath.Dir(f.Path))) == bad {
				t.Errorf("file %s should have been skipped (lives under %q)", f.Path, bad)
			}
		}
	}
}
