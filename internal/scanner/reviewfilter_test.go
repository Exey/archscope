package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/exey/archscope/internal/config"
	"github.com/exey/archscope/internal/langspec"
)

func TestReviewPlatformFilter(t *testing.T) {
	dir := t.TempDir()
	for p, body := range map[string]string{"api/main.go": "package main\nfunc main() {}\n", "web/app.py": "def main():\n    return 1\n"} {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	scan, err := Scan(dir, config.Default(), langspec.Default)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Platforms) < 2 {
		t.Skipf("fixture produced %d platform(s)", len(scan.Platforms))
	}
	// a changed file that exists, and one the working tree doesn't have yet (added by the MR)
	keep := scan.PlatformsWithPaths([]string{filepath.Join(dir, "web", "app.py"), filepath.Join(dir, "web", "new_module.py"), filepath.Join(dir, "README.md")})
	if len(keep) != 1 {
		t.Fatalf("want exactly the python platform, got %v", keep)
	}
	scan.KeepPlatforms(keep)
	if len(scan.Platforms) != 1 || len(scan.Files) != 1 {
		t.Fatalf("after filtering: %d platforms, %d files", len(scan.Platforms), len(scan.Files))
	}
	if filepath.Ext(scan.Files[0].Path) != ".py" {
		t.Errorf("kept the wrong file: %s", scan.Files[0].Path)
	}
}
