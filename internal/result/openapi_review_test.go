package result

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/exey/archscope/internal/evolution"
	"github.com/exey/archscope/internal/openapi"
)

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir, "-c", "user.email=a@b.c", "-c", "user.name=n"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func TestReviewAttachesOnlyNewSpecFindings(t *testing.T) {
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q", "-b", "main")
	// the base already has a missing description on /b (an old problem)
	old := "openapi: 3.0.3\ninfo:\n  title: T\n  version: '1'\nsecurity:\n  - bearer: []\npaths:\n  /a:\n    get:\n      operationId: getA\n      summary: s\n      responses:\n        '200': {description: ok}\ncomponents:\n  securitySchemes:\n    bearer: {type: http, scheme: bearer}\n"
	os.WriteFile(filepath.Join(dir, "api.yaml"), []byte(old), 0o644)
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-qm", "base")
	baseSHA := gitIn(t, dir, "rev-parse", "HEAD")
	// the change adds a POST without operationId and drops the global security
	changed := "openapi: 3.0.3\ninfo:\n  title: T\n  version: '1'\npaths:\n  /a:\n    get:\n      operationId: getA\n      summary: s\n      responses:\n        '200': {description: ok}\n    post:\n      summary: make\n      responses:\n        '201': {description: c}\ncomponents:\n  securitySchemes:\n    bearer: {type: http, scheme: bearer}\n"
	os.WriteFile(filepath.Join(dir, "api.yaml"), []byte(changed), 0o644)
	gitIn(t, dir, "commit", "-qam", "change")

	rv := &evolution.Review{BaseSHA: strings.TrimSpace(baseSHA), Files: []evolution.ReviewFile{{Path: "api.yaml", Add: 6}, {Path: "main.go", Add: 1}}}
	res := &AnalysisResult{RootPath: dir}
	attachSpecFindings(res, dir, rv)
	var got []string
	for _, it := range rv.Files[0].Issues {
		got = append(got, it.Name)
		if it.Kind != "OpenAPI" || it.Line <= 0 || it.RepoPath != "api.yaml" {
			t.Errorf("bad item %+v", it)
		}
	}
	want := map[string]bool{"State-changing operation without security": true, "Operation without an operationId": true, "API change: Operation is no longer protected": true}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected issue %q (info.description was already missing at the base): %v", g, got)
		}
		delete(want, g)
	}
	for w := range want {
		t.Errorf("missing %q in %v", w, got)
	}
	if len(rv.Files[1].Issues) != 0 {
		t.Error("non-spec files get no spec issues")
	}
}

func TestReviewReportsBreakingSpecChanges(t *testing.T) {
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q", "-b", "main")
	head := "openapi: 3.0.3\ninfo:\n  title: T\n  description: d\n  version: '1'\nsecurity:\n  - bearer: []\npaths:\n"
	tail := "components:\n  securitySchemes:\n    bearer: {type: http, scheme: bearer}\n"
	op := func(path, extra string) string {
		return "  " + path + ":\n    get:\n      operationId: op" + strings.ReplaceAll(path, "/", "_") + "\n      summary: s\n      description: d\n      tags: [t]\n" + extra + "      responses:\n        '200': {description: ok}\n"
	}
	spec := filepath.Join(dir, "api.yaml")
	os.WriteFile(spec, []byte(head+op("/a", "")+op("/b", "")+tail), 0o644)
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-qm", "base")
	baseSHA := strings.TrimSpace(gitIn(t, dir, "rev-parse", "HEAD"))
	// /b disappears; /a gains a required query parameter; /c is new (compatible)
	os.WriteFile(spec, []byte(head+op("/a", "      parameters:\n        - {name: q, in: query, required: true, schema: {type: string}}\n")+op("/c", "")+tail), 0o644)
	gitIn(t, dir, "commit", "-qam", "change")

	rv := &evolution.Review{BaseSHA: baseSHA, Files: []evolution.ReviewFile{{Path: "api.yaml", Add: 6}}}
	res := &AnalysisResult{RootPath: dir, OpenAPI: []openapi.FileReport{{Path: spec, Version: "3.0.3"}}}
	attachSpecFindings(res, dir, rv)

	got := map[string]int{}
	for _, it := range rv.Files[0].Issues {
		got[it.Name] = it.Weight
	}
	for _, name := range []string{"Breaking API change: Path removed", "Breaking API change: Required parameter added"} {
		if got[name] != 7 {
			t.Errorf("want %q as a HIGH review item, got %v", name, got)
		}
	}
	for name := range got {
		if strings.Contains(name, "Operation added") {
			t.Errorf("compatible changes are not review items: %v", got)
		}
	}
	ch := res.OpenAPI[0].Changes
	if res.OpenAPI[0].Breaking() != 2 || len(ch) != 3 {
		t.Errorf("the OpenAPI card should list all 3 changes (2 breaking), got %+v", ch)
	}
}
