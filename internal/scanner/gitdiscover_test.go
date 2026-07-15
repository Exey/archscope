package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func mkGitRepo(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverGitReposSingle(t *testing.T) {
	root := t.TempDir()
	mkGitRepo(t, root)
	repos := DiscoverGitRepos(root, nil)
	if len(repos) != 1 || repos[0] != root {
		t.Fatalf("want [%s], got %v", root, repos)
	}
}

func TestDiscoverGitReposMultiple(t *testing.T) {
	root := t.TempDir()
	svcA := filepath.Join(root, "services", "a")
	svcB := filepath.Join(root, "services", "b")
	if err := os.MkdirAll(svcA, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(svcB, 0o755); err != nil {
		t.Fatal(err)
	}
	mkGitRepo(t, svcA)
	mkGitRepo(t, svcB)
	repos := DiscoverGitRepos(root, nil)
	if len(repos) != 2 {
		t.Fatalf("want 2 repos, got %v", repos)
	}
}

func TestDiscoverGitReposNone(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	repos := DiscoverGitRepos(root, nil)
	if len(repos) != 0 {
		t.Fatalf("want 0 repos, got %v", repos)
	}
}

func TestNearestGitRepo(t *testing.T) {
	repos := []string{"/root/services/a", "/root/services/a/vendor/lib", "/root/services/b"}
	cases := map[string]string{
		"/root/services/a/main.go":            "/root/services/a",
		"/root/services/a/vendor/lib/util.go": "/root/services/a/vendor/lib",
		"/root/services/b/main.go":            "/root/services/b",
		"/root/other/main.go":                 "",
	}
	for path, want := range cases {
		if got := NearestGitRepo(repos, path); got != want {
			t.Errorf("NearestGitRepo(%q) = %q, want %q", path, got, want)
		}
	}
}
