package constructs

import (
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTwrWeights(t *testing.T) {
	if w := twr(100, 0, 100); math.Abs(w-0.5) > 1e-9 {
		t.Errorf("newest commit weighs 0.5, got %v", w)
	}
	if w := twr(0, 0, 100); w > 1e-4 {
		t.Errorf("oldest commit weighs about nothing, got %v", w)
	}
	if twr(5, 5, 5) != 1 {
		t.Error("one timestamp is no range: each commit counts once")
	}
}

func TestCoverageParsers(t *testing.T) {
	gocov := parseGoCover([]byte("mode: set\nexample.com/m/pkg/a.go:3.10,5.2 2 1\nexample.com/m/pkg/a.go:6.2,7.2 1 0\n"), "cover.out")
	if len(gocov) != 1 || gocov[0].lines[4] != true || gocov[0].lines[6] != false {
		t.Errorf("go cover = %+v", gocov)
	}
	lcov := parseLcov([]byte("SF:src/a.ts\nDA:1,3\nDA:2,0\nend_of_record\n"), "lcov.info")
	if len(lcov) != 1 || !lcov[0].lines[1] || lcov[0].lines[2] {
		t.Errorf("lcov = %+v", lcov)
	}
	xmlcov := parseCobertura([]byte(`<coverage><packages><package><classes><class filename="app/a.py"><lines><line number="1" hits="2"/><line number="2" hits="0"/></lines></class></classes></package></packages></coverage>`), "coverage.xml")
	if len(xmlcov) != 1 || !xmlcov[0].lines[1] || xmlcov[0].lines[2] {
		t.Errorf("cobertura = %+v", xmlcov)
	}
	pyjson := parseCoverageJSON([]byte(`{"files":{"app/a.py":{"executed_lines":[1,2],"missing_lines":[3]}}}`), "coverage.json")
	if len(pyjson) != 1 || !pyjson[0].lines[2] || pyjson[0].lines[3] {
		t.Errorf("coverage.py json = %+v", pyjson)
	}
	ist := parseCoverageJSON([]byte(`{"/r/a.ts":{"statementMap":{"0":{"start":{"line":4}},"1":{"start":{"line":5}}},"s":{"0":1,"1":0}}}`), "coverage-final.json")
	if len(ist) != 1 || !ist[0].lines[4] || ist[0].lines[5] {
		t.Errorf("istanbul = %+v", ist)
	}
}

func TestCovIndexLookupBySuffix(t *testing.T) {
	ix := newCovIndex()
	ix.add(&fileCov{path: "example.com/m/pkg/a.go", lines: map[int]bool{1: true}, source: "cover.out"})
	ix.add(&fileCov{path: "other/a.go", lines: map[int]bool{1: false}, source: "x"})
	if f := ix.lookup("/work/m/pkg/a.go", false); f == nil || f.source != "cover.out" {
		t.Errorf("a Go import path matches by its trailing components: %+v", f)
	}
	if f := ix.lookup("/work/unrelated/b.go", false); f != nil {
		t.Errorf("no base-name match, got %+v", f)
	}
}

// A tiny repository: a complex function in a file that keeps changing, a complex one
// in a file touched once, and a coverage profile covering half of the first.
func TestBuildCrapRanksByRiskAndReadsCoverage(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	run := func(env []string, args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), append(env, "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run(nil, "init", "-q")
	hot, cold := filepath.Join(dir, "hot.go"), filepath.Join(dir, "cold.go")
	os.WriteFile(cold, []byte("package p\n\nfunc cold() {}\n"), 0o644)
	run([]string{"GIT_AUTHOR_DATE=2026-01-01T00:00:00", "GIT_COMMITTER_DATE=2026-01-01T00:00:00"}, "add", "-A")
	run([]string{"GIT_AUTHOR_DATE=2026-01-01T00:00:00", "GIT_COMMITTER_DATE=2026-01-01T00:00:00"}, "commit", "-q", "-m", "c")
	for i, d := range []string{"2026-08-01", "2026-08-02", "2026-08-03", "2026-08-04", "2026-08-05", "2026-08-06", "2026-08-07", "2026-08-08"} {
		os.WriteFile(hot, []byte("package p\n\nfunc hot() {\n\t// "+strings.Repeat("x", i+1)+"\n}\n"), 0o644)
		env := []string{"GIT_AUTHOR_DATE=" + d + "T00:00:00", "GIT_COMMITTER_DATE=" + d + "T00:00:00"}
		run(env, "add", "-A")
		run(env, "commit", "-q", "-m", "h")
	}
	os.WriteFile(filepath.Join(dir, "cover.out"), []byte("mode: set\nm/hot.go:3.1,3.9 1 1\nm/hot.go:4.2,5.2 1 0\n"), 0o644)

	rep := buildCrap([]crapRaw{
		{symbol: "cold", path: cold, line: 3, end: 3, ccn: 9},
		{symbol: "hot", path: hot, line: 3, end: 5, ccn: 12, doc: false},
	})
	if len(rep.Top) != 2 || rep.Top[0].Symbol != "hot" {
		t.Fatalf("the function in the churning file outranks the more complex one in a stable file: %+v", rep.Top)
	}
	hotF := rep.Top[0]
	if !hotF.ChurnKnown || hotF.Commits != 8 || hotF.Risk <= CrapRiskThreshold {
		t.Errorf("hot = %+v", hotF)
	}
	if hotF.CovState != "measured" || hotF.Cov < 0.3 || hotF.Cov > 0.7 {
		t.Errorf("hot coverage = %+v", hotF)
	}
	want := 144*math.Pow(1-hotF.Cov, 3) + 12
	if math.Abs(hotF.CRAP-want) > 1e-9 {
		t.Errorf("CRAP = %v, want %v", hotF.CRAP, want)
	}
	if rep.UndocRisky != 1 || len(rep.Risky) != 1 {
		t.Errorf("risky = %d undocumented = %d", len(rep.Risky), rep.UndocRisky)
	}
	if why := hotF.Why(); !strings.Contains(why, "Risk = 12") || !strings.Contains(why, "cover.out") || !strings.Contains(why, "needs a doc comment") {
		t.Errorf("tooltip missing the reasons:\n%s", why)
	}
	if rep.Top[1].CovState != "not in artifact" {
		t.Errorf("cold file is not in the profile: %+v", rep.Top[1])
	}
}
