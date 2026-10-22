package evolution

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func sh(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.email=a@b.c", "-c", "user.name=n"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// syncFixture: a bare origin with dev and feat/x (one commit ahead of dev), cloned
// to a working copy that stands on a stale dev.
func syncFixture(t *testing.T) (work, origin string) {
	t.Helper()
	root := t.TempDir()
	origin = filepath.Join(root, "origin.git")
	seed := filepath.Join(root, "seed")
	work = filepath.Join(root, "work")
	for _, d := range []string{origin, seed} {
		os.MkdirAll(d, 0o755)
	}
	sh(t, origin, "init", "-q", "--bare", "-b", "dev")
	sh(t, seed, "init", "-q", "-b", "dev")
	os.WriteFile(filepath.Join(seed, "a.txt"), []byte("1\n"), 0o644)
	sh(t, seed, "add", ".")
	sh(t, seed, "commit", "-qm", "base")
	sh(t, seed, "remote", "add", "origin", origin)
	sh(t, seed, "push", "-q", "origin", "dev")
	sh(t, seed, "checkout", "-q", "-b", "feat/x")
	os.WriteFile(filepath.Join(seed, "b.txt"), []byte("new\n"), 0o644)
	sh(t, seed, "add", ".")
	sh(t, seed, "commit", "-qm", "feature")
	sh(t, seed, "push", "-q", "origin", "feat/x")
	if out, err := exec.Command("git", "clone", "-q", "-b", "dev", origin, work).CombinedOutput(); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	// dev moves on at the origin after the clone: the local dev is now stale
	sh(t, seed, "checkout", "-q", "dev")
	os.WriteFile(filepath.Join(seed, "c.txt"), []byte("dev moved\n"), 0o644)
	sh(t, seed, "add", ".")
	sh(t, seed, "commit", "-qm", "dev moved")
	sh(t, seed, "push", "-q", "origin", "dev")
	return work, origin
}

func TestSyncSwitchesToReviewedBranchAndUpdatesTarget(t *testing.T) {
	work, _ := syncFixture(t)
	var log []string
	res := SyncForReview(work, "feat/x", "", func(m string) { log = append(log, m) })
	if cur := sh(t, work, "rev-parse", "--abbrev-ref", "HEAD"); cur != "feat/x" {
		t.Fatalf("not switched, on %q; log %v", cur, log)
	}
	if res.Switched != "feat/x" || res.From != "dev" || res.Against != "dev" {
		t.Errorf("result %+v — the branch we left must become the base", res)
	}
	if got := sh(t, work, "rev-parse", "dev"); got != sh(t, work, "rev-parse", "origin/dev") {
		t.Errorf("local dev was not fast-forwarded to origin/dev (%s)", strings.Join(log, " | "))
	}
	if _, err := os.Stat(filepath.Join(work, "b.txt")); err != nil {
		t.Error("the feature's file must be in the working tree after the switch")
	}
}

func TestSyncDoesNotTouchADirtyTree(t *testing.T) {
	work, _ := syncFixture(t)
	os.WriteFile(filepath.Join(work, "a.txt"), []byte("edited\n"), 0o644)
	var log []string
	res := SyncForReview(work, "feat/x", "", func(m string) { log = append(log, m) })
	if cur := sh(t, work, "rev-parse", "--abbrev-ref", "HEAD"); cur != "dev" || res.Switched != "" {
		t.Errorf("must not switch with uncommitted changes: on %q, %+v", cur, res)
	}
	if !strings.Contains(strings.Join(log, "\n"), "uncommitted changes") {
		t.Errorf("the skip should be explained: %v", log)
	}
	if b, _ := os.ReadFile(filepath.Join(work, "a.txt")); string(b) != "edited\n" {
		t.Error("local edits were lost")
	}
}

func TestSyncWithoutRemoteIsANoOp(t *testing.T) {
	dir := t.TempDir()
	sh(t, dir, "init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(dir, "a"), []byte("x"), 0o644)
	sh(t, dir, "add", ".")
	sh(t, dir, "commit", "-qm", "c")
	var log []string
	if res := SyncForReview(dir, "main", "", func(m string) { log = append(log, m) }); res.Switched != "" || len(log) != 1 || !strings.Contains(log[0], "no remote") {
		t.Errorf("res %+v log %v", res, log)
	}
}

func TestGuessTargetBranchPicksTheClosestBase(t *testing.T) {
	root := t.TempDir()
	origin := filepath.Join(root, "origin.git")
	seed := filepath.Join(root, "seed")
	os.MkdirAll(origin, 0o755)
	os.MkdirAll(seed, 0o755)
	sh(t, origin, "init", "-q", "--bare", "-b", "main")
	sh(t, seed, "init", "-q", "-b", "main")
	commit := func(file, msg string) {
		os.WriteFile(filepath.Join(seed, file), []byte(msg), 0o644)
		sh(t, seed, "add", ".")
		sh(t, seed, "commit", "-qm", msg)
	}
	commit("a", "base")
	sh(t, seed, "remote", "add", "origin", origin)
	sh(t, seed, "checkout", "-q", "-b", "dev")
	commit("b", "dev work 1")
	commit("c", "dev work 2")
	sh(t, seed, "checkout", "-q", "-b", "feat/x")
	commit("d", "feature")
	sh(t, seed, "push", "-q", "origin", "main", "dev", "feat/x")
	if got := GuessTargetBranch(seed, sh(t, seed, "rev-parse", "feat/x")); got != "dev" {
		t.Errorf("feature cut from dev: guessed %q, want dev (main is 3 commits behind it)", got)
	}
	// a branch cut straight from main
	sh(t, seed, "checkout", "-q", "main")
	sh(t, seed, "checkout", "-q", "-b", "hotfix/y")
	commit("e", "fix")
	sh(t, seed, "push", "-q", "origin", "hotfix/y")
	if got := GuessTargetBranch(seed, sh(t, seed, "rev-parse", "hotfix/y")); got != "main" {
		t.Errorf("hotfix cut from main: guessed %q, want main", got)
	}
}
