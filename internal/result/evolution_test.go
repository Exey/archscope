package result_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/exey/archscope/internal/config"
	"github.com/exey/archscope/internal/evolution"
	"github.com/exey/archscope/internal/result"
)

// TestRunEvolutionScoresThePastTree builds a repo whose Go file grows from 3 to
// 7 lines and checks that the baseline really is analysed from the old commit
// (LOC 3), not from the working tree, and that bad/duplicate specs are skipped.
func TestRunEvolutionScoresThePastTree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	run := func(date string, args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date,
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(src string) {
		if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("2026-01-01T00:00:00Z", "init", "-q")
	write("package main\n\nfunc main() {}\n")
	run("2026-01-02T00:00:00Z", "add", "-A")
	run("2026-01-02T00:00:00Z", "commit", "-q", "-m", "small")
	write("package main\n\nfunc main() {\n\ta()\n}\n\nfunc a() {}\n")
	run("2026-01-03T00:00:00Z", "add", "-A")
	run("2026-01-03T00:00:00Z", "commit", "-q", "-m", "grown")

	cfg := config.Default()
	now, err := result.Run(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	score := func(r *result.AnalysisResult) []evolution.Score {
		return []evolution.Score{{Key: "go", Label: "Go", LOC: r.TotalLines(), Level: "L"}}
	}
	var msgs []string
	first := "HEAD~1"
	cmp := result.RunEvolution(now, cfg, []string{first, "HEAD~1", "nosuchref"}, score, func(m string) { msgs = append(msgs, m) })

	if len(cmp) != 1 {
		t.Fatalf("want 1 comparison (duplicate + bad spec skipped), got %d; progress: %v", len(cmp), msgs)
	}
	row := cmp[0].Rows[0]
	if !row.Both() || row.Now.LOC <= row.Then.LOC {
		t.Errorf("baseline must be the smaller past tree: then=%+v now=%+v", row.Then, row.Now)
	}
	if row.Then.LOC > 4 {
		t.Errorf("baseline LOC = %d — it looks scanned from the working tree, not the old commit", row.Then.LOC)
	}
	joined := strings.Join(msgs, "\n")
	if !strings.Contains(joined, "nosuchref") || !strings.Contains(joined, "same commit") {
		t.Errorf("expected skip notices for the bad and duplicate specs, got:\n%s", joined)
	}
}

func TestRunEvolutionOutsideGitRepoIsSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	res, err := result.Run(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var msg string
	out := result.RunEvolution(res, cfg, []string{"2w"}, func(*result.AnalysisResult) []evolution.Score { return nil }, func(m string) { msg = m })
	if out != nil || !strings.Contains(msg, "not inside a git repository") {
		t.Errorf("want skipped with a clear message, got %v / %q", out, msg)
	}
}
