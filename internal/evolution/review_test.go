package evolution

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseRemote(t *testing.T) {
	cases := map[string][2]string{
		"git@gitlab.example.com:group/sub/proj.git":        {"https://gitlab.example.com", "group/sub/proj"},
		"https://gitlab.example.com/group/proj.git":        {"https://gitlab.example.com", "group/proj"},
		"https://user:tok@gitlab.example.com/group/proj":   {"https://gitlab.example.com", "group/proj"},
		"ssh://git@gitlab.example.com:2222/group/proj.git": {"https://gitlab.example.com", "group/proj"},
		"https://github.com/Exey/archscope":                {"https://github.com", "Exey/archscope"},
		"/local/path/repo":                                 {"", ""},
	}
	for in, want := range cases {
		h, p := ParseRemote(in)
		if h != want[0] || p != want[1] {
			t.Errorf("ParseRemote(%q) = %q %q, want %q %q", in, h, p, want[0], want[1])
		}
	}
}

func TestFileHashIsSHA1OfPath(t *testing.T) {
	if got := FileHash("a.txt"); got != "cfc7b4885384957ae445bc14914d4588f607651c" {
		t.Errorf("FileHash(a.txt) = %q, want the SHA-1 of the path (GitLab's diff file anchor)", got)
	}
}

// reviewRepo: main has a.txt (3 lines); feature adds a line, replaces a line.
func reviewRepo(t *testing.T) (dir, mainSHA, featSHA string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir = t.TempDir()
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	run := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(s string) { os.WriteFile(filepath.Join(dir, "a.txt"), []byte(s), 0o644) }
	run("init", "-q", "-b", "main")
	write("l1\nl2\nl3\n")
	run("add", "-A")
	run("commit", "-q", "-m", "base")
	mainSHA = run("rev-parse", "HEAD")
	run("checkout", "-q", "-b", "feature")
	write("l1\nL2 changed\nl3\nl4 added\n")
	run("add", "-A")
	run("commit", "-q", "-m", "feature work")
	featSHA = run("rev-parse", "HEAD")
	return
}

func TestReviewResolvesMergeBase(t *testing.T) {
	repo, mainSHA, _ := reviewRepo(t)
	ref, err := Resolve(repo, ReviewPrefix+"main", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ref.SHA != mainSHA || ref.Label != "review: main" || !strings.Contains(ref.Title, "merge-base with main") {
		t.Errorf("review ref = %+v", ref)
	}
	last, err := Resolve(repo, ReviewPrefix+"last-commit", time.Now())
	if err != nil || last.SHA != mainSHA {
		t.Errorf("last-commit must be HEAD~1: %+v %v", last, err)
	}
	if _, err := Resolve(repo, ReviewPrefix+"nosuch", time.Now()); err == nil {
		t.Error("unknown ref must fail")
	}
}

func TestNewToOldMapsDiffLinesToGitLabPositions(t *testing.T) {
	repo, mainSHA, _ := reviewRepo(t)
	m := NewToOld(repo, mainSHA, "", "a.txt")
	// line 2 replaced (old line 2 removed): added row sits at old position 3.
	// line 4 pure insertion after old line 3: old position 4.
	if m[2] != 3 || m[4] != 4 {
		t.Errorf("NewToOld = %v, want 2→3 and 4→4", m)
	}
	if _, ok := m[1]; ok {
		t.Error("an unchanged line is not part of the diff")
	}
}

func TestDetectMRFromLocalRefs(t *testing.T) {
	repo, mainSHA, featSHA := reviewRepo(t)
	if n, _ := DetectMR(repo, mainSHA, featSHA); n != 0 {
		t.Fatalf("no MR refs yet, got !%d", n)
	}
	// An MR whose head is exactly HEAD, and an older unrelated one.
	for ref, sha := range map[string]string{"refs/merge-requests/7/head": featSHA, "refs/merge-requests/3/head": mainSHA} {
		if out, err := exec.Command("git", "-C", repo, "update-ref", ref, sha).CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	if n, src := DetectMR(repo, mainSHA, featSHA); n != 7 || src != "local refs" {
		t.Errorf("DetectMR = !%d via %q, want !7 via local refs", n, src)
	}
	// MR 3's head is the base itself (already in main) and must never be picked
	// for a range that excludes it.
	exec.Command("git", "-C", repo, "update-ref", "-d", "refs/merge-requests/7/head").Run()
	if n, _ := DetectMR(repo, mainSHA, featSHA); n != 0 {
		t.Errorf("an MR head contained in base must not match, got !%d", n)
	}
}

func TestEnrichReviewFillsLineAnchors(t *testing.T) {
	repo, mainSHA, _ := reviewRepo(t)
	c := Comparison{WorseDetails: []Detail{{Added: []Item{{Rel: "a.txt", Line: 4}, {Rel: "a.txt", Line: 1}}}}}
	EnrichReview(repo, "", mainSHA, "", &c)
	a := c.WorseDetails[0].Added
	if a[0].RepoPath != "a.txt" || a[0].OldPos != 4 {
		t.Errorf("added line anchor = %+v", a[0])
	}
	if a[1].OldPos != -1 {
		t.Errorf("a line outside the diff is marked -1, got %d", a[1].OldPos)
	}
}

func TestReviewAutoPicksLocalDefaultBranch(t *testing.T) {
	repo, mainSHA, _ := reviewRepo(t)
	if got := DefaultBranch(repo); got != "main" {
		t.Fatalf("DefaultBranch = %q, want main", got)
	}
	ref, err := Resolve(repo, ReviewPrefix+"auto", time.Now())
	if err != nil || ref.SHA != mainSHA || ref.Target != "main" || ref.Label != "review: main" {
		t.Errorf("auto review = %+v %v", ref, err)
	}
	if bare, err := Resolve(repo, ReviewPrefix, time.Now()); err != nil || bare.Target != "main" {
		t.Errorf("empty review value must mean auto: %+v %v", bare, err)
	}

	// Sitting on the default branch itself there is nothing to merge: review the last commit.
	if out, err := exec.Command("git", "-C", repo, "checkout", "-q", "main").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	exec.Command("git", "-C", repo, "commit", "-q", "--allow-empty", "-m", "x").Run()
	onMain, err := Resolve(repo, ReviewPrefix+"auto", time.Now())
	if err != nil || onMain.Target != "HEAD~1" || !strings.Contains(onMain.Title, "you are on main") {
		t.Errorf("on the default branch: %+v %v", onMain, err)
	}
	// An explicit target is never second-guessed.
	if exp, _ := Resolve(repo, ReviewPrefix+"main", time.Now()); exp.Target != "main" {
		t.Errorf("explicit target changed: %+v", exp)
	}
}

func TestDefaultBranchFallsBackToMaster(t *testing.T) {
	repo, _, _ := reviewRepo(t)
	exec.Command("git", "-C", repo, "branch", "-m", "main", "master").Run()
	if got := DefaultBranch(repo); got != "master" {
		t.Errorf("DefaultBranch = %q, want master", got)
	}
}

// remoteOnlyRepo: a clone-like repo where feature exists only as origin/feature.
func TestReviewResolvesBranchThatExistsOnlyOnTheRemote(t *testing.T) {
	repo, mainSHA, featSHA := reviewRepo(t)
	run := func(args ...string) {
		if out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	run("update-ref", "refs/remotes/origin/feature", featSHA)
	run("checkout", "-q", "main")
	run("branch", "-D", "feature")
	run("remote", "add", "origin", "git@gitlab.example.com:g/p.git")

	ref, err := Resolve(repo, ReviewPrefix+"feature", time.Now())
	if err != nil {
		t.Fatalf("a remote-only branch must resolve: %v", err)
	}
	// Not a default branch name and not merged: it is the branch UNDER review,
	// compared with where we are (main).
	if ref.HeadSHA != featSHA || ref.SHA != mainSHA || ref.Target != "origin/feature" || ref.Against != "main" {
		t.Errorf("review ref = %+v", ref)
	}
	if !strings.Contains(ref.Title, "origin/feature vs main") {
		t.Errorf("Title = %q", ref.Title)
	}
}

func TestReviewTargetVsSubjectRules(t *testing.T) {
	repo, mainSHA, featSHA := reviewRepo(t) // checked out on feature, 1 commit ahead of main
	// On the feature branch, `--review main`: main is the TARGET → review HEAD (working tree).
	ref, err := Resolve(repo, ReviewPrefix+"main", time.Now())
	if err != nil || ref.HeadSHA != "" || ref.SHA != mainSHA {
		t.Errorf("--review main on a feature branch: %+v %v", ref, err)
	}
	// Naming the checked-out branch reviews it against the default branch.
	self, err := Resolve(repo, ReviewPrefix+"feature", time.Now())
	if err != nil || self.SHA != mainSHA || self.Against != "main" || self.HeadSHA != "" {
		t.Errorf("--review <current branch>: %+v %v", self, err)
	}
	// --against forces the subject/base pairing.
	forced, err := Resolve(repo, ReviewPrefix+"feature@@main", time.Now())
	if err != nil || forced.SHA != mainSHA {
		t.Errorf("--against: %+v %v", forced, err)
	}
	_ = featSHA
	if _, err := Resolve(repo, ReviewPrefix+"nosuch", time.Now()); err == nil {
		t.Error("unknown ref must fail")
	}
}

func TestChangedFilesAndFileVerdicts(t *testing.T) {
	repo, mainSHA, _ := reviewRepo(t)
	files := ChangedFiles(repo, mainSHA, "")
	if len(files) != 1 || files[0].Path != "a.txt" || files[0].Add != 2 || files[0].Del != 1 {
		t.Fatalf("ChangedFiles = %+v", files)
	}
	c := Comparison{Introduced: []Item{{RepoPath: "a.txt", Kind: "HIGH security", Line: 2}, {RepoPath: "other.go"}}}
	r := Review{BaseSHA: mainSHA}
	r.AttachFiles(repo, c)
	if r.Adds != 2 || r.Dels != 1 || r.Files[0].OK() || len(r.Files[0].Issues) != 1 {
		t.Errorf("AttachFiles: %+v", r)
	}
	r2 := Review{BaseSHA: mainSHA}
	r2.AttachFiles(repo, Comparison{})
	if !r2.Files[0].OK() {
		t.Error("a file with no introduced issue is OK")
	}
}

func TestNewToOldNewFileUsesZero(t *testing.T) {
	repo, mainSHA, _ := reviewRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "fresh.go"), []byte("a\nb\nc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "-A"}, {"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "new file"}} {
		if out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	m := NewToOld(repo, mainSHA, "", "fresh.go")
	// GitLab's anchor for a line of a brand-new file is <hash>_0_<line>.
	if len(m) != 3 || m[1] != 0 || m[3] != 0 {
		t.Errorf("new file lines must map to old position 0, got %v", m)
	}
	if _, ok := m[1]; !ok {
		t.Error("line 1 of the new file must be present (it is in the diff)")
	}
}

func TestDetectMRFromGitHubPullRefsAndProvider(t *testing.T) {
	repo, mainSHA, featSHA := reviewRepo(t)
	for ref, sha := range map[string]string{"refs/remotes/origin/pull/12/head": featSHA, "refs/pull/5/head": mainSHA} {
		if out, err := exec.Command("git", "-C", repo, "update-ref", ref, sha).CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	if n, src := DetectMR(repo, mainSHA, featSHA); n != 12 || src != "local refs" {
		t.Errorf("DetectMR = #%d via %q, want #12 via local refs", n, src)
	}
	// the common `+refs/pull/*/head:refs/remotes/origin/pr/*` mapping
	exec.Command("git", "-C", repo, "update-ref", "-d", "refs/remotes/origin/pull/12/head").Run()
	exec.Command("git", "-C", repo, "update-ref", "refs/remotes/origin/pr/9", featSHA).Run()
	if n, _ := DetectMR(repo, mainSHA, featSHA); n != 9 {
		t.Errorf("origin/pr/N mapping: got #%d, want #9", n)
	}

	for host, want := range map[string]string{"https://github.com": "github", "https://github.example.org": "github", "https://gitlab.com": "gitlab", "https://git.corp.example": "github"} {
		if got := DetectProvider(repo, host); got != want {
			t.Errorf("DetectProvider(%q) = %q, want %q (this repo holds pull refs)", host, got, want)
		}
	}
	empty := t.TempDir()
	exec.Command("git", "-C", empty, "init", "-q").Run()
	if got := DetectProvider(empty, "https://git.corp.example"); got != "gitlab" {
		t.Errorf("unknown host with no pull refs defaults to gitlab, got %q", got)
	}
	if len(FileHash256("a/b.go")) != 64 {
		t.Error("GitHub anchors are 64-hex sha256")
	}
}

func TestRenderReviewMarkdownMirrorsTheHTMLChangesBlock(t *testing.T) {
	rv := &Review{Adds: 2556, Dels: 687, Files: []ReviewFile{
		{Path: "ok.go", Add: 71},
		{Path: "bad.go", Add: 33, Del: 81, Issues: []Item{{Kind: "Many parameters", Name: "New", Rel: "bad.go", Line: 48, Note: "11 params"}}},
		{Path: "img.png", Binary: true},
	}}
	md := RenderReviewMarkdown(rv)
	for _, want := range []string{"**Changes:** 3 files · +2,556 · −687 · ✓ 2 OK · ⚠ 1 with issues", "- ⚠ 1 issue `bad.go` (+33 −81)", "Many parameters `New` — `bad.go:48` · 11 params", "- ✓ OK `ok.go` (+71 −0)", "(binary)"} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in:\n%s", want, md)
		}
	}
	if strings.Index(md, "bad.go") > strings.Index(md, "ok.go") {
		t.Error("files with issues must come first")
	}
	if RenderReviewMarkdown(nil) != "" {
		t.Error("nil review renders nothing")
	}
}

func TestReviewMarkdownQuotesCode(t *testing.T) {
	dir := t.TempDir()
	var fn strings.Builder
	fn.WriteString("package p\n\nfunc Short(a int) int {\n\treturn a\n}\n\nfunc Long(a int) int {\n")
	for i := 0; i < 70; i++ {
		fn.WriteString("\ta++\n")
	}
	fn.WriteString("\treturn a\n}\n\nfunc Other() {\n\tx := 1\n\ty := 2\n\tz := bad(x, y)\n\tw := 4\n\tv := 5\n\tu := 6\n\tt := 7\n\t_ = z + w + v + u + t\n}\n")
	path := filepath.Join(dir, "a.go")
	os.WriteFile(path, []byte(fn.String()), 0o644)

	rv := &Review{Files: []ReviewFile{{Path: "a.go", Add: 1, Issues: []Item{
		{Kind: "Shape limit", Name: "Short", Rel: "a.go", RepoPath: "a.go", Path: path, Line: 3},
		{Kind: "Shape limit", Name: "Long", Rel: "a.go", RepoPath: "a.go", Path: path, Line: 7},
		{Kind: "Suspicious code", Name: "call", Rel: "a.go", RepoPath: "a.go", Path: path, Line: 84},
	}}}}
	md := RenderReviewMarkdown(rv)
	if !strings.Contains(md, "```go") || !strings.Contains(md, "→ 3 │ func Short(a int) int {") || !strings.Contains(md, "return a\n") {
		t.Errorf("a function-level issue must quote the whole function:\n%s", md)
	}
	if short := md[strings.Index(md, "→ 3 │"):strings.Index(md, "Long")]; strings.Contains(short, "func Long") {
		t.Error("the short function's snippet must stop at its closing brace")
	}
	// the long function is cut at 50 lines and says so
	if !strings.Contains(md, "(function continues)") || strings.Count(md, "a++") > 50 {
		t.Errorf("a long function is capped at 50 lines:\n%s", md)
	}
	// a statement-level issue gets a few lines either side, not the whole function
	if !strings.Contains(md, "→ 84 │ \tz := bad(x, y)") || !strings.Contains(md, "│ \tx := 1") || !strings.Contains(md, "│ \tu := 6") || strings.Contains(md, "│ \tt := 7") {
		t.Errorf("statement context:\n%s", md)
	}
}
