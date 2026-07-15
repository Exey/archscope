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

// TestScanGitRepoAsTab verifies that with GitRepoAsTab enabled, files in
// separate git repositories land in separate platform tabs, even when they
// sit deeper than the first level (unlike FolderAsTab, which only looks at
// the top-level folder).
func TestScanGitRepoAsTab(t *testing.T) {
	root := t.TempDir()
	svcA := filepath.Join(root, "services", "a")
	svcB := filepath.Join(root, "services", "b")
	for _, dir := range []string{svcA, svcB} {
		if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cfg := config.Default()
	cfg.FolderAsTab = false
	cfg.GitRepoAsTab = true
	res, err := scanner.Scan(root, cfg, langspec.Default)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(res.GitRepos) != 2 {
		t.Fatalf("want 2 git repos, got %d: %v", len(res.GitRepos), res.GitRepos)
	}

	goGroups := 0
	for key, g := range res.Platforms {
		if g.LanguagePlatform == langspec.PlatformGo {
			goGroups++
			if string(key) == string(langspec.PlatformGo) {
				t.Errorf("expected a gitrepo-qualified key, got plain %q", key)
			}
		}
	}
	if goGroups != 2 {
		t.Errorf("want 2 separate Go tabs (one per repo), got %d", goGroups)
	}
	if !res.FolderAsTab {
		t.Error("expected res.FolderAsTab to report true when GitRepoAsTab is set (shared synthetic-key handling)")
	}
}
