package html

import (
	"fmt"
	"github.com/exey/archscope/internal/report"
	"strings"
	"testing"
	"time"

	"github.com/exey/archscope/internal/evolution"
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/security"
)

func evoScore(key string, design, quality, security, perf, overall int) evolution.Score {
	return evolution.Score{Key: key, Label: key, Abbr: "Go", Lang: "go", LOC: 5000,
		Design: design, Quality: quality, Security: security, Perf: perf, Overall: overall,
		Level: "Middle", LevelRank: 4}
}

func TestEvolutionHintWhenNoData(t *testing.T) {
	out := renderEvolution(minimalResult())
	if !strings.Contains(out, "--evolution") || strings.Contains(out, "as-evo__tab") {
		t.Errorf("without Evolution data the card must be just the CLI hint:\n%s", out)
	}
}

func TestEvolutionCardRendersTabsTableDumbbellsAndExport(t *testing.T) {
	res := minimalResult()
	ref := evolution.Ref{Label: "2 weeks", Title: "2 weeks ago", SHA: "abcdef0123456", Subject: `<b>x</b> "q"`,
		Date: time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)}
	res.Evolution = []evolution.Comparison{
		evolution.Compare(ref, []evolution.Score{evoScore("go", 70, 55, 90, 40, 64)}, []evolution.Score{evoScore("go", 60, 60, 90, 40, 62)}),
		evolution.Compare(evolution.Ref{Label: "since v1.0", Title: "last tag v1.0", SHA: "1234567abc"},
			[]evolution.Score{evoScore("go", 70, 55, 90, 40, 64)}, []evolution.Score{evoScore("go", 70, 55, 90, 40, 64)}),
	}
	out := renderEvolution(res)

	for _, want := range []string{
		`data-evo="0"`, `data-evo="1"`, `data-evo="2"`, "⏱ Timeline", "2 weeks", "since v1.0", // tabs: timeline leads
		"▲ 1 better", "▼ 1 worse", // banner
		"60</span>", "as-evo__d--up", "as-evo__d--down", // table deltas
		"as-evo__dot--then", "as-evo__link--up", // dumbbells
		"as-evo__export", "evolution-2-weeks.md", "evolution-since-v1.0.md", // export
		"No change in any dimension", // second pane verdict
	} {
		if !strings.Contains(out, want) {
			t.Errorf("evolution card missing %q", want)
		}
	}
	if strings.Contains(out, `<b>x</b>`) {
		t.Error("commit subject must be HTML-escaped")
	}
	if !strings.Contains(out, `data-evo-pane="2" data-evo-file="evolution-since-v1.0.md" style="display:none"`) {
		t.Error("only the first pane (the timeline) should be visible initially")
	}
}

func TestProgrammingCultureShowsEvolution(t *testing.T) {
	res := minimalResult()
	res.Evolution = []evolution.Comparison{evolution.Compare(evolution.Ref{Label: "2 weeks", Title: "2 weeks ago", SHA: "abc1234"},
		CultureScores(res), CultureScores(res))}
	out := renderProgrammingCulture(res)
	if !strings.Contains(out, "as-evo__pane") {
		t.Errorf("Programming Culture should embed the Evolution card")
	}
}

func TestCultureScoresMirrorTheTable(t *testing.T) {
	scores := CultureScores(minimalResult())
	if len(scores) == 0 {
		t.Fatal("expected a score row for the 12k-LOC Go platform")
	}
	s := scores[0]
	if s.Level == "" || s.Overall <= 0 || s.LOC != 12000 {
		t.Errorf("unexpected score %+v", s)
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{"2 weeks": "2-weeks", "since v1.0": "since-v1.0", " Since HEAD~25 ": "since-head-25"} {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func detailScores() (then, now evolution.Score) {
	then = evoScore("py", 70, 66, 90, 80, 76)
	now = evoScore("py", 70, 65, 90, 80, 76)
	then.LOC, now.LOC = 12000, 12400
	then.Metrics = []evolution.Metric{
		{Dim: 2, Name: "Long functions (>200 lines)", Value: 3},
		{Dim: 2, Name: "Data structures detected", Value: 5, HigherBetter: true},
	}
	now.Metrics = []evolution.Metric{
		{Dim: 2, Name: "Long functions (>200 lines)", Value: 4},
		{Dim: 2, Name: "Data structures detected", Value: 5, HigherBetter: true},
	}
	old := evolution.Item{Dim: 2, Kind: "Long function", Name: "legacy", Rel: "a/legacy.py", Key: "fn|a/legacy.py|legacy", Size: 210, Line: 10}
	grown := old
	grown.Size = 340
	fresh := evolution.Item{Dim: 2, Kind: "Long function", Name: "parse_all", Rel: "src/<b>x</b>.py", Key: "fn|src/x.py|parse_all",
		Path: "/repo/src/x.py", Line: 120, Size: 212, Note: "212 lines", Weight: 3}
	then.Items = []evolution.Item{old}
	now.Items = []evolution.Item{grown, fresh}
	return
}

func TestEvolutionDetailsShowWhereItGotWorse(t *testing.T) {
	then, now := detailScores()
	c := evolution.Compare(evolution.Ref{Label: "2 weeks", Title: "2 weeks ago", SHA: "abc1234"}, []evolution.Score{now}, []evolution.Score{then})
	res := minimalResult()
	res.Evolution = []evolution.Comparison{c}
	out := renderEvolution(res)

	for _, want := range []string{
		"What got worse, and where",
		"Long functions (&gt;200 lines)", // changed metric, escaped
		`<strong>4</strong>`,             // 3 → 4
		"Introduced since the baseline",
		"parse_all", "src/&lt;b&gt;x&lt;/b&gt;.py:120", // offender with file:line, escaped
		`href="vscode://file/repo/src/x.py:120"`, // linked into the working tree
		"Grew", "210 → 340",                      // the function that got bigger
		"Code size 12,000 → 12,400 LOC",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("details missing %q", want)
		}
	}
	if strings.Contains(out, "<b>x</b>") {
		t.Error("offender paths must be HTML-escaped")
	}
	if strings.Contains(out, "Data structures detected") {
		t.Error("an unchanged metric must not be listed")
	}
	if !strings.Contains(c.WorseDetails[0].Added[0].Name, "parse_all") || len(c.WorseDetails[0].Grew) != 1 {
		t.Errorf("unexpected detail: %+v", c.WorseDetails[0])
	}
}

func TestEvolutionNothingWorse(t *testing.T) {
	a := evoScore("go", 60, 60, 60, 60, 60)
	b := evoScore("go", 70, 60, 60, 60, 62)
	a.Metrics = []evolution.Metric{{Dim: 1, Name: "Design patterns", Value: 1, HigherBetter: true}}
	b.Metrics = []evolution.Metric{{Dim: 1, Name: "Design patterns", Value: 3, HigherBetter: true}}
	res := minimalResult()
	res.Evolution = []evolution.Comparison{evolution.Compare(evolution.Ref{Label: "x", Title: "x", SHA: "abc1234"}, []evolution.Score{b}, []evolution.Score{a})}
	out := renderEvolution(res)
	if !strings.Contains(out, "Nothing got worse") || !strings.Contains(out, "What got better") {
		t.Errorf("expected the all-clear plus a collapsed better section:\n%s", out)
	}
}

func TestEvolutionTimelineHasThreePoints(t *testing.T) {
	mk := func(label string, day int, design int) evolution.Comparison {
		then := evoScore("go", design, 60, 60, 60, 60)
		now := evoScore("go", 80, 60, 60, 60, 65)
		ref := evolution.Ref{Label: label, Title: label + " ago", SHA: fmt.Sprintf("%07d", day), Date: time.Date(2026, 9, day, 0, 0, 0, 0, time.UTC)}
		return evolution.Compare(ref, []evolution.Score{now}, []evolution.Score{then})
	}
	res := minimalResult()
	// Passed newest-first on purpose: the timeline must order by date.
	res.Evolution = []evolution.Comparison{mk("2 weeks", 21, 70), mk("1 month", 5, 60)}
	out := renderEvolution(res)

	for _, want := range []string{
		"3 points:", "1 month ago", "now",
		"Step 1", "Step 2", "Step by step",
		`<span class="as-evo__then">60</span><span class="as-evo__to">→</span><span class="as-evo__then">70</span><span class="as-evo__to">→</span><strong>80</strong>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("timeline missing %q", want)
		}
	}
	if strings.Index(out, "1 month ago") > strings.Index(out, "2 weeks ago") {
		t.Error("points must run oldest → newest")
	}
	if !strings.Contains(out, "evolution-timeline.md") {
		t.Error("timeline pane needs its own export file")
	}
}

func TestTestFilesAreNotScoredNorListed(t *testing.T) {
	res := minimalResult()
	res.Files = append(res.Files, &parser.ParsedFile{FilePath: "/x/main_test.go", LanguageID: "go",
		Platform: string(langspec.PlatformGo), ModuleName: "app", LineCount: 100,
		BigFunctions: []parser.FunctionInfo{{Name: "TestHuge", LineCount: 500, FilePath: "/x/main_test.go", StartLine: 1}}})
	rule := security.Rule{ID: "r1", Name: "Unrestricted File Upload", Severity: security.SevHigh}
	res.Security = []security.RuleResult{{Rule: rule, TotalCount: 2, Findings: []security.Finding{
		{RuleID: "r1", FullPath: "/x/main.go", Line: 3, Snippet: "prod"},
		{RuleID: "r1", FullPath: "/x/main_test.go", Line: 9, Snippet: "test"},
	}}}

	scores := CultureScores(res)
	if len(scores) == 0 {
		t.Fatal("no scores")
	}
	s := scores[0]
	for _, m := range s.Metrics {
		if m.Name == "HIGH findings" && m.Value != 1 {
			t.Errorf("HIGH findings = %d, want 1 (the test-file finding must not count)", m.Value)
		}
		if strings.HasPrefix(m.Name, "Long functions") && m.Value != 0 {
			t.Errorf("long functions = %d, a test function must not count", m.Value)
		}
	}
	for _, it := range s.Items {
		if strings.HasSuffix(it.Rel, "_test.go") {
			t.Errorf("test-file offender listed: %+v", it)
		}
	}
	if len(s.Items) != 1 || s.Items[0].Rel != "main.go" {
		t.Errorf("items = %+v, want just the production finding", s.Items)
	}
}

func TestReviewModeShowsGitLabCardAndMRButtons(t *testing.T) {
	then, now := detailScores()
	now.Items[1].RepoPath, now.Items[1].OldPos = "src/x.py", 118
	c := evolution.Compare(evolution.Ref{Label: "review: main", Title: "merge-base with main", SHA: "abc1234", Spec: evolution.ReviewPrefix + "main"},
		[]evolution.Score{now}, []evolution.Score{then})
	res := minimalResult()
	res.Evolution = []evolution.Comparison{c}

	if renderGitLabCard(res) != "" {
		t.Error("no GitLab card outside review mode")
	}
	if strings.Contains(renderEvolution(res), "as-evo__mr") {
		t.Error("no MR buttons outside review mode")
	}

	res.Review = &evolution.Review{Ref: "main", BaseSHA: "abc1234def", HeadSHA: "fff", Branch: "feature/x",
		MRIID: 42, MRSource: "local refs", Host: "https://gitlab.example.com", Project: "group/proj"}
	card := renderGitLabCard(res)
	for _, want := range []string{`id="as-gl-project"`, `value="group/proj"`, `id="as-gl-host"`, `value="https://gitlab.example.com"`,
		`id="as-gl-mr"`, `value="42"`, `data-ref="feature/x"`, "detected from local refs", "against <code>main</code>"} {
		if !strings.Contains(card, want) {
			t.Errorf("GitLab card missing %q", want)
		}
	}
	res.Review.Files = []evolution.ReviewFile{
		{Path: "src/x.py", Add: 12, Del: 3, Issues: []evolution.Item{now.Items[1]}},
		{Path: "README.md", Add: 5},
	}
	res.Review.Adds, res.Review.Dels = 17, 3
	out := renderEvolution(res)
	for _, want := range []string{"📈 Evolution (Review mode)", "Changes:</strong> 2 files", "+17", "✓ 1 OK", "⚠ 1 with issues",
		"⚠ 1 issue", "✓ OK", "README.md", `id="as-gl-host"`, // GitLab inputs live inside the Evolution card
		`class="as-evo__mr"`, `data-path="src/x.py"`, `data-line="120"`, `data-old="118"`,
		`data-hash="` + evolution.FileHash("src/x.py") + `"`, "MR ↗ L120"} {
		if !strings.Contains(out, want) {
			t.Errorf("MR button missing %q", want)
		}
	}
	if !strings.Contains(out, `id="as-evo"`) || strings.Index(out, `id="as-gl-host"`) < strings.Index(out, `id="as-evo"`) {
		t.Error("the GitLab inputs must be inside the 📈 Evolution card")
	}

	res.Review.MRIID = 0
	if !strings.Contains(renderGitLabCard(res), "No merge request found") {
		t.Error("missing-MR hint expected")
	}
}

func TestFailedReviewExplainsItself(t *testing.T) {
	res := minimalResult()
	res.ReviewNote = `Evolution "review:x" skipped: "x" is not a commit or branch`
	out := renderEvolution(res)
	if !strings.Contains(out, "Review mode") || !strings.Contains(out, "could not run") || !strings.Contains(out, "is not a commit or branch") {
		t.Errorf("a failed review must say why instead of the generic hint:\n%s", out)
	}
}

func TestMRButtonKeepsZeroOldPositionForNewFiles(t *testing.T) {
	it := evolution.Item{Kind: "O(N²)", Name: "f", Rel: "a/new.go", RepoPath: "a/new.go", Line: 61, OldPos: 0}
	if out := itemHTML(it, "", true); !strings.Contains(out, `data-old="0"`) {
		t.Errorf("old position 0 (new file) must reach the button:\n%s", out)
	}
	it.OldPos = -1
	if out := itemHTML(it, "", true); !strings.Contains(out, `data-old="-1"`) {
		t.Errorf("-1 marks a line outside the diff:\n%s", out)
	}
}

func TestReviewModeGitHubCardAndButtons(t *testing.T) {
	then, now := detailScores()
	now.Items[1].RepoPath, now.Items[1].OldPos = "src/x.py", 118
	c := evolution.Compare(evolution.Ref{Label: "review: main", Title: "merge-base with main", SHA: "abc1234", Spec: evolution.ReviewPrefix + "main"},
		[]evolution.Score{now}, []evolution.Score{then})
	res := minimalResult()
	res.Evolution = []evolution.Comparison{c}
	res.Review = &evolution.Review{Ref: "main", BaseSHA: "abc1234def", HeadSHA: "fff", Branch: "feature/x",
		MRIID: 42, MRSource: "local refs", Host: "https://github.com", Project: "owner/repo", Provider: "github"}
	res.Review.Files = []evolution.ReviewFile{{Path: "src/x.py", Add: 12, Del: 3, Issues: []evolution.Item{now.Items[1]}}}
	card := renderGitLabCard(res)
	for _, want := range []string{`data-provider="github"`, "🐙 GitHub PR links", `placeholder="owner/repo"`, `value="owner/repo"`, `value="https://github.com"`,
		`value="42"`, "Pull request detected from local refs"} {
		if !strings.Contains(card, want) {
			t.Errorf("GitHub card missing %q", want)
		}
	}
	if strings.Contains(card, "GitLab") || strings.Contains(card, "merge-requests") {
		t.Error("GitHub card must not mention GitLab")
	}
	out := renderEvolution(res)
	if !strings.Contains(out, `data-hash256="`+evolution.FileHash256("src/x.py")+`"`) {
		t.Error("buttons must carry the sha256 anchor GitHub needs")
	}
	if !strings.Contains(report.JS, `github=card.getAttribute('data-provider')==='github'`) || !strings.Contains(report.JS, "/pull/'+mr+'/files#diff-'+hash256+'R'") {
		t.Error("the page script must build GitHub pull-request URLs")
	}
	res.Review.MRIID = 0
	if hint := renderGitLabCard(res); !strings.Contains(hint, "No pull request found in refs/pull") {
		t.Error("missing-PR hint expected")
	}
}

func TestDuplicatedBlockItemLinksBothLocations(t *testing.T) {
	it := evolution.Item{Kind: "Duplicate code", Name: "Duplicated block", Rel: "a/x.go", Path: "/repo/a/x.go", Line: 48,
		AltRel: "b/y.go", AltPath: "/repo/b/y.go", AltLine: 125}
	out := itemHTML(it, "", false)
	if strings.Count(out, `class="as-vs"`) < 1 || !strings.Contains(out, "⇄") || !strings.Contains(out, "b/y.go:125") {
		t.Errorf("both locations expected:\n%s", out)
	}
	if !strings.Contains(out, "vscode://file/repo/b/y.go:125") && !strings.Contains(out, "b/y.go:125") {
		t.Errorf("twin link missing:\n%s", out)
	}
	if md := evolution.RenderReviewMarkdown(&evolution.Review{Files: []evolution.ReviewFile{{Path: "a/x.go", Issues: []evolution.Item{it}}}}); !strings.Contains(md, "⇄ `b/y.go:125`") {
		t.Errorf("markdown should name the twin: %s", md)
	}
}
