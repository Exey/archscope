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

func TestParseGitSubmodules(t *testing.T) {
	root := t.TempDir()
	content := `[submodule "third_party/lib"]
	path = third_party/lib
	url = https://example.com/lib.git
[submodule "external/other"]
	path = external/other
	url = https://example.com/other.git
`
	if err := os.WriteFile(filepath.Join(root, ".gitmodules"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got := scanner.ParseGitSubmodules(root)
	want := map[string]bool{filepath.FromSlash("third_party/lib"): true, filepath.FromSlash("external/other"): true}
	if len(got) != 2 {
		t.Fatalf("want 2 submodule paths, got %v", got)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected submodule path %q", p)
		}
	}
}

func TestParseGitSubmodulesNoFile(t *testing.T) {
	root := t.TempDir()
	if got := scanner.ParseGitSubmodules(root); got != nil {
		t.Errorf("want nil for missing .gitmodules, got %v", got)
	}
}

// makeSubmoduleTree creates a root with a .gitmodules declaring
// "third_party/lib" as a submodule, one Go file inside it, and one Go file
// at the repo root. "third_party" isn't in config.Default()'s ExcludePaths,
// so any skip is attributable only to the new submodule detection.
func makeSubmoduleTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".gitmodules"), []byte(`[submodule "third_party/lib"]
	path = third_party/lib
	url = https://example.com/lib.git
`), 0o644); err != nil {
		t.Fatal(err)
	}
	subDir := filepath.Join(root, "third_party", "lib")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestScanSkipsSubmodulesByDefault(t *testing.T) {
	root := makeSubmoduleTree(t)
	cfg := config.Default()
	res, err := scanner.Scan(root, cfg, langspec.Default)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	subDir := filepath.Join(root, "third_party", "lib")
	for _, f := range res.Files {
		if filepath.Dir(f.Path) == subDir {
			t.Errorf("expected submodule file to be skipped, got %s", f.Path)
		}
	}
	if len(res.Files) != 1 {
		t.Errorf("want 1 file (submodule skipped), got %d: %v", len(res.Files), res.Files)
	}
}

func TestScanAllFilesIncludesSubmodules(t *testing.T) {
	root := makeSubmoduleTree(t)
	cfg := config.Default()
	cfg.ScanAllFiles = true
	res, err := scanner.Scan(root, cfg, langspec.Default)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	subDir := filepath.Join(root, "third_party", "lib")
	found := false
	for _, f := range res.Files {
		if filepath.Dir(f.Path) == subDir {
			found = true
		}
	}
	if !found {
		t.Error("expected submodule file to be scanned with ScanAllFiles=true")
	}
}
