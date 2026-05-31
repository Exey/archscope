package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// makeRepo initializes a throwaway git repo with two commits and returns its
// path. It skips the test if git is unavailable.
func makeRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Ada", "GIT_AUTHOR_EMAIL=ada@example.com",
			"GIT_COMMITTER_NAME=Ada", "GIT_COMMITTER_EMAIL=ada@example.com",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.name", "Ada")
	run("config", "user.email", "ada@example.com")
	run("checkout", "-q", "-b", "main")

	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("main.go", "package main\nfunc main() {}\n")
	run("add", ".")
	run("commit", "-q", "-m", "feat: initial commit")
	write("main.go", "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"hi\") }\n")
	run("add", ".")
	run("commit", "-q", "-m", "fix: print greeting")
	return dir
}

func TestAvailable(t *testing.T) {
	repo := makeRepo(t)
	if !Available(repo) {
		t.Errorf("Available should be true for a git work tree")
	}
	if Available(t.TempDir()) {
		t.Errorf("Available should be false for a non-repo dir")
	}
}

func TestAuthorStats(t *testing.T) {
	repo := makeRepo(t)
	authors := GetAuthorStatsMultiRepo([]string{repo}, 100)
	if len(authors) == 0 {
		t.Fatal("expected at least one author")
	}
	a, ok := authors["Ada"]
	if !ok {
		t.Fatalf("expected author Ada, got %v", keys(authors))
	}
	if a.TotalCommits < 2 {
		t.Errorf("Ada commits = %d, want >= 2", a.TotalCommits)
	}
}

func TestCommitMessageStats(t *testing.T) {
	repo := makeRepo(t)
	cs := GetCommitMessageStats([]string{repo}, 100)
	if cs.Total < 2 {
		t.Errorf("total commits = %d, want >= 2", cs.Total)
	}
	if cs.Typed < 2 {
		t.Errorf("typed (conventional) commits = %d, want >= 2", cs.Typed)
	}
}

func TestBranchStatsAndModel(t *testing.T) {
	repo := makeRepo(t)
	bs := GetBranchStats([]string{repo}, 90)
	if bs.TotalBranches < 1 {
		t.Errorf("total branches = %d, want >= 1", bs.TotalBranches)
	}
	if bs.PrimaryBranch == "" {
		t.Errorf("primary branch should be detected")
	}
	if string(bs.Model.Model) == "" {
		t.Errorf("a branching model verdict should be set")
	}
}

func TestBlameLinesSubset(t *testing.T) {
	repo := makeRepo(t)
	a := NewAnalyzer(repo, 100)
	got := a.BlameLinesSubset(filepath.Join(repo, "main.go"), map[int]bool{1: true})
	if len(got) == 0 {
		t.Fatal("expected blame to return an author for line 1")
	}
	if got[1] != "Ada" {
		t.Errorf("line 1 author = %q, want Ada", got[1])
	}
}

func keys(m map[string]*AuthorStats) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
