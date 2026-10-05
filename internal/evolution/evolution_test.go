package evolution

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sc(key string, design, quality, security, perf, overall, rank int) Score {
	return Score{Key: key, Label: key, Abbr: key, Lang: key, LOC: 5000,
		Design: design, Quality: quality, Security: security, Perf: perf, Overall: overall,
		Level: "L", LevelRank: rank}
}

func TestParseSpecs(t *testing.T) {
	got := ParseSpecs(" 2w, 1m ,2W,,abc1234 ")
	want := []string{"2w", "1m", "abc1234"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("ParseSpecs = %v, want %v", got, want)
	}
	auto := ParseSpecs("auto,2w")
	if strings.Join(auto, "|") != "2w|1m|last-tag" {
		t.Errorf("auto should expand and dedupe, got %v", auto)
	}
	if len(ParseSpecs("")) != 0 {
		t.Error("empty value must yield no specs")
	}
}

func TestCompareCountsAndMovers(t *testing.T) {
	then := []Score{sc("go", 60, 60, 90, 40, 62, 3), sc("py", 50, 50, 50, 50, 50, 2), sc("old", 70, 70, 70, 70, 70, 4)}
	now := []Score{sc("go", 70, 55, 90, 40, 64, 4), sc("py", 50, 50, 50, 50, 50, 2), sc("new", 80, 80, 80, 80, 80, 5)}
	c := Compare(Ref{Title: "t"}, now, then)

	// go: design +10 (better), quality −5 (worse), security/perf same. py: 4 same.
	if c.Better != 1 || c.Worse != 1 || c.Same != 2+4 {
		t.Errorf("better/worse/same = %d/%d/%d, want 1/1/6", c.Better, c.Worse, c.Same)
	}
	if c.BestMove == nil || c.BestMove.Dim != "Design" || c.BestMove.Delta != 10 {
		t.Errorf("BestMove = %+v", c.BestMove)
	}
	if c.WorstMove == nil || c.WorstMove.Dim != "Code Quality" || c.WorstMove.Delta != -5 {
		t.Errorf("WorstMove = %+v", c.WorstMove)
	}
	if len(c.Rows) != 4 || c.Rows[2].Key != "new" || c.Rows[3].Key != "old" {
		t.Errorf("rows should follow now then append then-only: %+v", c.Rows)
	}
	if c.Rows[2].Then != nil || c.Rows[3].Now != nil {
		t.Error("new/gone rows must have exactly one side")
	}
	if c.Rows[0].LevelShift() != 1 {
		t.Errorf("LevelShift = %d, want +1", c.Rows[0].LevelShift())
	}
	if c.Verdict() != "Mixed — improvements offset by declines" {
		t.Errorf("verdict = %q", c.Verdict())
	}
}

func TestRenderMarkdown(t *testing.T) {
	then := []Score{sc("go", 60, 60, 90, 40, 62, 3)}
	now := []Score{sc("go", 70, 60, 80, 40, 63, 3)}
	ref := Ref{Title: "2 weeks ago", SHA: "0123456789abcdef", Subject: "fix | pipe", Date: time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)}
	md := RenderMarkdown(Compare(ref, now, then))
	for _, want := range []string{"`0123456", "2026-09-21", "fix | pipe", "60 → 70 (▲ +10)", "90 → 80 (▼ −10)", "60 → 60 (= 0)"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}

// gitRepo builds a throwaway repo: a.txt committed on three dated days, a tag
// on the second commit, plus a sub/ directory for the subpath case.
func gitRepo(t *testing.T) (dir string, shas []string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir = t.TempDir()
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	run := func(date string, args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date,
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("2026-01-01T12:00:00Z", "init", "-q")
	commit := func(date, content, msg string) {
		if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, "a.txt"), []byte(content), 0o644)
		os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte(content), 0o644)
		run(date, "add", "-A")
		run(date, "commit", "-q", "-m", msg)
		shas = append(shas, run(date, "rev-parse", "HEAD"))
	}
	commit("2026-01-10T12:00:00Z", "one", "first")
	commit("2026-02-10T12:00:00Z", "two", "second")
	run("2026-02-10T12:00:00Z", "tag", "v1.0")
	commit("2026-03-10T12:00:00Z", "three", "third")
	return dir, shas
}

func TestResolve(t *testing.T) {
	repo, shas := gitRepo(t)
	now := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		spec, wantSHA, wantLabel string
	}{
		{"2w", shas[1], "2 weeks"},          // cutoff Mar 6 → last commit before it is the second (Feb 10)
		{"1m", shas[1], "1 month"},          // cutoff Feb 20 → second
		{"last-tag", shas[1], "since v1.0"}, // v1.0 is on second; HEAD (third) is not tagged
		{"2026-01-31", shas[0], "since 2026-01-31"},
		{shas[0][:8], shas[0], "since " + shas[0][:7]},
		{"HEAD", shas[2], "since HEAD"},
	}
	for _, c := range cases {
		ref, err := Resolve(repo, c.spec, now)
		if err != nil {
			t.Errorf("Resolve(%q): %v", c.spec, err)
			continue
		}
		if ref.SHA != c.wantSHA {
			t.Errorf("Resolve(%q).SHA = %s, want %s", c.spec, ref.SHA[:7], c.wantSHA[:7])
		}
		if ref.Label != c.wantLabel {
			t.Errorf("Resolve(%q).Label = %q, want %q", c.spec, ref.Label, c.wantLabel)
		}
		if ref.Subject == "" || ref.Date.IsZero() {
			t.Errorf("Resolve(%q) missing subject/date: %+v", c.spec, ref)
		}
	}

	if _, err := Resolve(repo, "3y", now); err == nil {
		t.Error("a window older than the history should fail")
	}
	if _, err := Resolve(repo, "nosuchref", now); err == nil {
		t.Error("an unknown ref should fail")
	}
}

func TestLastTagStepsBackWhenHeadIsTagged(t *testing.T) {
	repo, shas := gitRepo(t)
	cmd := exec.Command("git", "-C", repo, "tag", "v2.0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	ref, err := Resolve(repo, "last-tag", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ref.SHA != shas[1] || ref.Label != "since v1.0" {
		t.Errorf("HEAD is tagged v2.0, so last-tag must be the previous tag v1.0 (%s), got %s %q", shas[1][:7], ref.SHA[:7], ref.Label)
	}
}

func TestLastTagWithoutTags(t *testing.T) {
	repo, _ := gitRepo(t)
	exec.Command("git", "-C", repo, "tag", "-d", "v1.0").Run()
	if _, err := Resolve(repo, "last-tag", time.Now()); err != ErrNoTag {
		t.Errorf("err = %v, want ErrNoTag", err)
	}
}

func TestToplevelAndExtract(t *testing.T) {
	repo, shas := gitRepo(t)

	top, sub, err := Toplevel(filepath.Join(repo, "sub"))
	if err != nil || top != repo || sub != "sub" {
		t.Fatalf("Toplevel(sub) = %q %q %v", top, sub, err)
	}
	if _, sub, _ := Toplevel(repo); sub != "" {
		t.Errorf("Toplevel(root) sub = %q, want empty", sub)
	}
	if _, _, err := Toplevel(t.TempDir()); err == nil {
		t.Error("a non-repo directory must error")
	}

	dir, cleanup, err := Extract(repo, shas[0], "")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "a.txt"))
	if string(b) != "one" {
		t.Errorf("extracted a.txt = %q, want the first commit's content", b)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		t.Error("extracted tree must not contain .git")
	}
	cleanup()
	if _, err := os.Stat(dir); err == nil {
		t.Error("cleanup should remove the temp dir")
	}

	dir, cleanup, err = Extract(repo, shas[1], "sub")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if b, _ := os.ReadFile(filepath.Join(dir, "b.txt")); string(b) != "two" {
		t.Errorf("subpath extract b.txt = %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "a.txt")); err == nil {
		t.Error("subpath extract must not include files outside the subpath")
	}
}

func TestCompareExplainsWhatGotWorse(t *testing.T) {
	then := sc("py", 70, 66, 90, 80, 76, 3)
	now := sc("py", 70, 65, 90, 80, 75, 3)
	then.LOC, now.LOC = 1000, 1100
	then.Metrics = []Metric{{Dim: 2, Name: "Long functions", Value: 3}, {Dim: 2, Name: "Algorithms", Value: 4, HigherBetter: true}, {Dim: 3, Name: "HIGH", Value: 0}}
	now.Metrics = []Metric{{Dim: 2, Name: "Long functions", Value: 4}, {Dim: 2, Name: "Algorithms", Value: 6, HigherBetter: true}, {Dim: 3, Name: "HIGH", Value: 0}}
	keep := Item{Dim: 2, Kind: "Long function", Name: "keep", Key: "k", Size: 200}
	grew := Item{Dim: 2, Kind: "Long function", Name: "grow", Key: "g", Size: 220}
	gone := Item{Dim: 2, Kind: "Long function", Name: "gone", Key: "x", Size: 250}
	tiny := Item{Dim: 2, Kind: "Long function", Name: "tiny", Key: "t", Size: 205}
	then.Items = []Item{keep, grew, gone, tiny}
	nowGrew, nowTiny := grew, tiny
	nowGrew.Size, nowTiny.Size = 300, 206 // +80 grows; +1 is noise
	fresh := Item{Dim: 2, Kind: "Long function", Name: "fresh", Key: "f", Size: 400, Rel: "src/f.py", Line: 7}
	now.Items = []Item{keep, nowGrew, nowTiny, fresh}

	c := Compare(Ref{Title: "x", SHA: "abc1234"}, []Score{now}, []Score{then})
	if len(c.WorseDetails) != 1 || c.WorseDetails[0].Dim != 2 {
		t.Fatalf("want one worse detail on Code Quality, got %+v", c.WorseDetails)
	}
	d := c.WorseDetails[0]
	if len(d.Metrics) != 2 || d.Metrics[0].Name != "Long functions" || !d.Metrics[0].Worse() || d.Metrics[1].Worse() {
		t.Errorf("bad metrics must come first and unchanged ones be omitted: %+v", d.Metrics)
	}
	if len(d.Added) != 1 || d.Added[0].Name != "fresh" {
		t.Errorf("Added = %+v, want only the new offender", d.Added)
	}
	if len(d.Grew) != 1 || d.Grew[0].Item.Name != "grow" || d.Grew[0].ThenSize != 220 {
		t.Errorf("Grew = %+v, want only the function that really grew", d.Grew)
	}
	if d.Resolved != 1 {
		t.Errorf("Resolved = %d, want 1", d.Resolved)
	}
	md := RenderMarkdown(c)
	for _, want := range []string{"What got worse, and where", "Long functions: 3 → 4", "Introduced (1)", "`src/f.py:7`", "grow", "1 offender(s) resolved", "Code size: 1000 → 1100 LOC"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}

func TestNewTimeline(t *testing.T) {
	ref := func(title string, day int) Ref {
		return Ref{Title: title, SHA: "abcdef0", Date: time.Date(2026, 9, day, 0, 0, 0, 0, time.UTC)}
	}
	now := []Score{sc("go", 80, 60, 60, 60, 70, 3)}
	cNew := Compare(ref("2 weeks ago", 21), now, []Score{sc("go", 70, 60, 60, 60, 65, 3)})
	cOld := Compare(ref("1 month ago", 5), now, []Score{sc("go", 60, 60, 60, 60, 62, 3), sc("py", 50, 50, 50, 50, 50, 2)})

	if _, ok := NewTimeline([]Comparison{cNew}); ok {
		t.Error("one baseline is not a timeline")
	}
	tl, ok := NewTimeline([]Comparison{cNew, cOld}) // newest first on purpose
	if !ok {
		t.Fatal("two baselines must make a timeline")
	}
	if tl.Heading() != "1 month ago → 2 weeks ago → now" {
		t.Errorf("Heading = %q", tl.Heading())
	}
	if len(tl.Points) != 3 || !tl.Points[2].Now || len(tl.Steps) != 2 {
		t.Fatalf("points=%d steps=%d", len(tl.Points), len(tl.Steps))
	}
	vals, ok2 := tl.Rows[0].Series(1) // go Design: 60 → 70 → 80
	if tl.Rows[0].Key != "go" || vals[0] != 60 || vals[1] != 70 || vals[2] != 80 || !ok2[0] || !ok2[2] {
		t.Errorf("go design series = %v %v", vals, ok2)
	}
	var py *TLRow
	for i := range tl.Rows {
		if tl.Rows[i].Key == "py" {
			py = &tl.Rows[i]
		}
	}
	if py == nil || py.Scores[0] == nil || py.Scores[1] != nil || py.Scores[2] != nil {
		t.Errorf("py only existed at the first point: %+v", py)
	}
	// Step 1 (1 month → 2 weeks) improved Design by 10; step 2 (2 weeks → now) by another 10.
	if tl.Steps[0].Better == 0 || tl.Steps[1].Better == 0 {
		t.Errorf("each leg improved Design: %d / %d", tl.Steps[0].Better, tl.Steps[1].Better)
	}
	if tl.Steps[0].To == "" || tl.Steps[1].To != "" {
		t.Errorf("only the non-final leg names its end point: %q / %q", tl.Steps[0].To, tl.Steps[1].To)
	}
	md := RenderTimelineMarkdown(tl)
	for _, want := range []string{"3 points", "60 → 70 → 80 (▲ +20)", "Step 1: 1 month ago → 2 weeks ago", "Step 2: 2 weeks ago → now"} {
		if !strings.Contains(md, want) {
			t.Errorf("timeline markdown missing %q:\n%s", want, md)
		}
	}
}

func TestLooksLikeSpec(t *testing.T) {
	yes := []string{"2w", "1m", "14d", "1y", "3 months", "last-tag", "AUTO", "2026-09-01", "a1b2c3d", "0123456789abcdef0123456789abcdef01234567"}
	no := []string{"", "repo", "~/repo", "./x", "main", "v1.2.0", "HEAD~3", "abc", "release/1.4", "--open"}
	for _, s := range yes {
		if !LooksLikeSpec(s) {
			t.Errorf("LooksLikeSpec(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if LooksLikeSpec(s) {
			t.Errorf("LooksLikeSpec(%q) = true, want false", s)
		}
	}
}

func TestUnchangedDevOpsIsHiddenAndNotCounted(t *testing.T) {
	dev := sc("devops", 72, 72, 72, 72, 73, 4)
	dev.IsDevOps, dev.Label = true, "DevOps"
	go1 := sc("go", 60, 60, 60, 60, 60, 3)
	go2 := sc("go", 70, 60, 60, 60, 62, 3)

	c := Compare(Ref{Title: "x", SHA: "abc1234"}, []Score{go2, dev}, []Score{go1, dev})
	if rows := c.VisibleRows(); len(rows) != 1 || rows[0].Key != "go" {
		t.Errorf("unchanged DevOps must be hidden, got %+v", rows)
	}
	if c.Same != 3 || c.Better != 1 {
		t.Errorf("DevOps must not inflate the unchanged count: better=%d same=%d", c.Better, c.Same)
	}
	if strings.Contains(RenderMarkdown(c), "DevOps") {
		t.Error("markdown must not list unchanged DevOps")
	}

	dev2 := dev
	dev2.Security = 60
	c = Compare(Ref{Title: "x", SHA: "abc1234"}, []Score{go2, dev2}, []Score{go1, dev})
	if len(c.VisibleRows()) != 2 || c.Worse != 1 {
		t.Errorf("a changed DevOps row must show in the table and be counted: rows=%d worse=%d", len(c.VisibleRows()), c.Worse)
	}
}

func TestUnexplainedMoveGetsNoDetailCard(t *testing.T) {
	dev := sc("go", 71, 72, 72, 72, 73, 4)
	dev2 := dev
	dev2.Design = 70
	c := Compare(Ref{Title: "x", SHA: "abc1234"}, []Score{dev2}, []Score{dev})
	if len(c.WorseDetails) != 0 {
		t.Errorf("a move with no signals must not produce a detail card: %+v", c.WorseDetails)
	}
	if c.Worse != 1 || len(c.VisibleRows()) != 1 {
		t.Errorf("the change itself must still be counted and shown in the table: worse=%d rows=%d", c.Worse, len(c.VisibleRows()))
	}
	if strings.Contains(RenderMarkdown(c), "No tracked signal") {
		t.Error("no placeholder text expected")
	}
}

func TestDevOpsReweightNoiseIsIgnored(t *testing.T) {
	mk := func(d int) Score {
		s := sc("devops", 71+d, 71+d, 71+d, 71+d, 72+d, 4)
		s.IsDevOps = true
		return s
	}
	c := Compare(Ref{Title: "x", SHA: "abc1234"}, []Score{mk(-1)}, []Score{mk(0)})
	if len(c.VisibleRows()) != 0 || c.Worse != 0 || c.Same != 0 {
		t.Errorf("a uniform ±1 DevOps shift is noise: rows=%d worse=%d same=%d", len(c.VisibleRows()), c.Worse, c.Same)
	}
	c = Compare(Ref{Title: "x", SHA: "abc1234"}, []Score{mk(-3)}, []Score{mk(0)})
	if len(c.VisibleRows()) != 1 || c.Worse == 0 {
		t.Errorf("a real DevOps drop must show: rows=%d worse=%d", len(c.VisibleRows()), c.Worse)
	}
}
