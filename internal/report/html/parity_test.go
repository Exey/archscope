package html

// parity_test.go keeps the HTML report and the Markdown export in step. It runs
// the real pipeline over a small multi-language project and checks, card by
// card, that whatever the HTML shows the Markdown shows too — and that the
// header's "MD" button and the per-platform downloads are wired up.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/exey/archscope/internal/config"
	"github.com/exey/archscope/internal/report"
	"github.com/exey/archscope/internal/report/markdown"
	"github.com/exey/archscope/internal/result"

	// Registration side effects: languages, universal rules, report modules.
	_ "github.com/exey/archscope/internal/lang"
	_ "github.com/exey/archscope/internal/modules/arch"
	_ "github.com/exey/archscope/internal/modules/constructs"
	_ "github.com/exey/archscope/internal/modules/dddmodel"
	_ "github.com/exey/archscope/internal/modules/oopvspop"
	_ "github.com/exey/archscope/internal/modules/speccoverage"
	_ "github.com/exey/archscope/internal/modules/traffic"
	_ "github.com/exey/archscope/internal/security/universal"
)

// writeProject lays out a project big enough for three platform cards plus the
// repo-wide ones: Go, Python and TypeScript sources, a Dockerfile and compose
// file, a Kubernetes Deployment, an OpenAPI spec and a git history with a tag.
func writeProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	put := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var goSrc strings.Builder
	goSrc.WriteString("package api\n\nimport (\n\t\"net/http\"\n\t\"os\"\n\t\"regexp\"\n\t\"strings\"\n)\n\n// TODO: split this file\n// FIXME: handlers share state\n")
	for i := 0; i < 70; i++ {
		fmt.Fprintf(&goSrc, `
// Handler%[1]d serves route %[1]d.
func Handler%[1]d(w http.ResponseWriter, r *http.Request) {
	name := ""
	for _, p := range strings.Split(r.URL.Path, "/") {
		name = name + "/" + p
	}
	re := regexp.MustCompile("^/v1/item%[1]d/[0-9]+$")
	if !re.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	f, _ := os.Open("/tmp/data%[1]d")
	_ = f
	w.WriteHeader(200)
}
`, i)
	}
	goSrc.WriteString(`
// CrossJoin compares every pair — quadratic.
func CrossJoin(a, b []string) int {
	n := 0
	for _, x := range a {
		for _, y := range b {
			if x == y {
				n++
			}
		}
	}
	return n
}
`)
	goSrc.WriteString("\nfunc Routes() {\n")
	for i := 0; i < 70; i++ {
		fmt.Fprintf(&goSrc, "\thttp.HandleFunc(\"/v1/item%d/\", Handler%d)\n", i, i)
	}
	goSrc.WriteString("}\n")
	put("backend/api/handlers.go", goSrc.String())
	put("backend/go.mod", "module example.com/demo\n\ngo 1.21\n")
	put("backend/domain/user.go", "package domain\n\n// UserRepository stores users.\ntype UserRepository interface{ Find(id int) string }\n\n// UserService is the domain service.\ntype UserService struct{ Repo UserRepository }\n")

	var py strings.Builder
	py.WriteString("import os\n\nPASSWORD = 'hunter2hunter2'  # TODO: move to env\n\n")
	for i := 0; i < 90; i++ {
		fmt.Fprintf(&py, `
def task_%[1]d(items=[], flag=False):
    """Task %[1]d."""
    total = 0
    for it in items:
        if it > %[1]d:
            total += it
        else:
            total -= 1
    try:
        os.remove("/tmp/x%[1]d")
    except:
        pass
    return total
`, i)
	}
	put("etl/tool.py", py.String())
	put("etl/requirements.txt", "requests==2.31.0\nflask==3.0.0\n")

	var ts strings.Builder
	ts.WriteString("import React, { useEffect, useState } from 'react';\n\n")
	for i := 0; i < 130; i++ {
		fmt.Fprintf(&ts, `
export function Widget%[1]d(props: any) {
  const [n, setN] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setN(n + 1), 1000);
    window.addEventListener('resize', () => setN(0));
  }, []);
  // TODO: cleanup
  return <div>{n} %[1]d</div>;
}
`, i)
	}
	put("web/app.tsx", ts.String())
	put("web/package.json", `{"name":"web","dependencies":{"react":"18.2.0"}}`)

	put("Dockerfile", "FROM golang:latest\nRUN apt-get update && apt-get install -y curl\nCOPY . /app\nCMD [\"/app/main\"]\n")
	put("docker-compose.yml", "version: '3'\nservices:\n  api:\n    build: .\n    privileged: true\n    ports:\n      - \"8080:8080\"\n")
	put("k8s/deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n  namespace: prod\nspec:\n  replicas: 2\n  selector:\n    matchLabels: {app: api}\n  template:\n    metadata:\n      labels: {app: api}\n    spec:\n      containers:\n        - name: api\n          image: example/api:latest\n          ports:\n            - containerPort: 8080\n")
	put("api/openapi.yaml", "openapi: 3.0.3\ninfo:\n  title: Demo\n  version: '1'\npaths:\n  /v1/item0/:\n    get:\n      summary: item\n      responses:\n        '200': {description: ok}\n")

	git := func(args ...string) {
		out, err := exec.Command("git", append([]string{"-C", dir, "-c", "user.email=a@b.c", "-c", "user.name=n"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q", "-b", "main")
	git("add", "-A")
	git("commit", "-qm", "feat: first")
	git("tag", "v1.0.0")
	put("backend/domain/extra.go", "package domain\n\n// Extra is here.\ntype Extra struct{}\n")
	git("add", "-A")
	git("commit", "-qm", "fix: second")
	return dir
}

var cachedProject *result.AnalysisResult

func projectResult(t *testing.T) *result.AnalysisResult {
	t.Helper()
	if cachedProject != nil {
		return cachedProject
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	res, err := result.Run(writeProject(t), config.Default())
	if err != nil {
		t.Fatal(err)
	}
	cachedProject = res
	return res
}

// htmlOf draws one card in HTML the way Render does.
func htmlOf(res *result.AnalysisResult, c report.Card, ctx report.Ctx) string {
	if c.Scope == report.Global {
		return report.HTML(ctx)
	}
	return renderPlatformCard(res, ctx.PG, ctx.Files, c, ctx.Badge)
}

// TestEveryCardIsInBothFormats: for every card of every scope, if the HTML draws
// something the Markdown draws something too, and vice versa — except where a
// Card says why not. This is the guard behind "add a card once, get both".
func TestEveryCardIsInBothFormats(t *testing.T) {
	res := projectResult(t)
	report.Verify()

	seenHTML, seenMD := map[string]bool{}, map[string]bool{}
	check := func(c report.Card, ctx report.Ctx, where string) {
		h := htmlOf(res, c, ctx)
		md := report.Markdown(ctx)
		if h != "" {
			seenHTML[c.ID] = true
		}
		if md != "" {
			seenMD[c.ID] = true
		}
		if h != "" && md == "" && c.NoMarkdown == "" {
			t.Errorf("%s: card %q has HTML but no Markdown", where, c.ID)
		}
		if md != "" && h == "" && c.NoHTML == "" {
			t.Errorf("%s: card %q has Markdown but no HTML", where, c.ID)
		}
	}
	for _, c := range report.CardsOf(report.Global) {
		check(c, report.Ctx{Res: res, Card: c}, "global")
	}
	tabs := res.PlatformTabs()
	if len(tabs) < 3 {
		t.Fatalf("the fixture should yield 3+ platform cards, got %d", len(tabs))
	}
	for _, pg := range tabs {
		files := res.FilesForPlatform(pg.Platform)
		for _, c := range report.CardsOf(report.Platform) {
			check(c, report.Ctx{Res: res, PG: pg, Files: files, Badge: platBadgeHTML(pg), Card: c}, string(pg.Platform))
		}
	}

	// The fixture is rich enough that most cards must have appeared somewhere;
	// a card that never renders would make the check above vacuous.
	for _, id := range []string{"summary", "culture", "stack", "radar", "danger", "devops", "openapi", "contributions", "infra",
		"overview", "architecture", "hotspots", "microservices", "todos", "longestfuncs", "biggesttypes", "git", "security",
		"dddmodel", "couplingcohesion", "complexity", "codestructure", "memoryleaks", "regex", "concurrency"} {
		if !seenHTML[id] || !seenMD[id] {
			t.Errorf("fixture never rendered card %q (html=%v md=%v) — extend writeProject", id, seenHTML[id], seenMD[id])
		}
	}
}

// TestModulePanelsCarryBothFormats: a module's panel has Markdown whenever it
// has HTML (RenderMarkdown is part of the module interface; this checks it is
// not silently empty where the HTML shows a "nothing found" state).
func TestModulePanelsCarryBothFormats(t *testing.T) {
	res := projectResult(t)
	for _, p := range res.ModulePanels {
		if strings.TrimSpace(p.HTML) != "" && strings.TrimSpace(p.MD) == "" {
			t.Errorf("%s/%s: HTML panel without Markdown", p.Platform, p.ModuleID)
		}
	}
}

// TestGlobalMDButton: the header "MD" button sits left of the theme toggle and
// carries the repo-wide report (title + every global card, no platform sections).
func TestGlobalMDButton(t *testing.T) {
	res := projectResult(t)
	doc := Render(res)

	btn := strings.Index(doc, `id="as-md-global"`)
	theme := strings.Index(doc, `id="as-theme-dark"`)
	if btn < 0 || theme < 0 || btn > theme {
		t.Fatalf("the MD button must come before the theme toggle (md=%d theme=%d)", btn, theme)
	}
	i := strings.Index(doc, `<textarea id="as-global-md" hidden readonly>`)
	if i < 0 {
		t.Fatal("global Markdown textarea missing")
	}
	body := doc[i+len(`<textarea id="as-global-md" hidden readonly>`):]
	body = body[:strings.Index(body, "</textarea>")]
	md := unescapeHTML(body)
	if md != markdown.RenderGlobal(res) {
		t.Error("the embedded Markdown differs from markdown.RenderGlobal")
	}
	if !strings.HasPrefix(md, "# ArchScope — ") {
		t.Errorf("global Markdown should start with the title, got %.40q", md)
	}
	for _, want := range []string{"## 📊 Summary", "## 🔰 Programming Culture", "## 🧰 Tech Stack", "## 📡 Technical Radar", "## 🛡️ Danger Index", "## ☁️ DevOps", "## 📜 OpenAPI", "## 📅 Contributions"} {
		if !strings.Contains(md, want) {
			t.Errorf("global Markdown lacks %q", want)
		}
	}
	for _, pg := range res.PlatformTabs() {
		if strings.Contains(md, "\n## "+pg.TabLabel()+"\n") {
			t.Errorf("global Markdown must not contain the %q platform section", pg.TabLabel())
		}
	}
	// the full document has them
	full := markdown.Render(res)
	if !strings.Contains(full, "## 🔰 Programming Culture") {
		t.Error("--format md lost the global cards")
	}
	for _, pg := range res.PlatformTabs() {
		if !strings.Contains(full, "\n## "+pg.TabLabel()+"\n") {
			t.Errorf("--format md lacks the %q platform section", pg.TabLabel())
		}
	}
	// every platform card has a download button for the Markdown view shown beside it
	if n := strings.Count(doc, `class="as-toggle as-md-dl"`); n != len(res.PlatformTabs()) {
		t.Errorf("want a download button per platform card (%d), got %d", len(res.PlatformTabs()), n)
	}
}

func unescapeHTML(s string) string {
	return strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&#34;", `"`, "&#39;", "'", "&amp;", "&").Replace(s)
}

// TestCardTableIsComplete: the card table has a renderer for both formats on
// every card (Verify panics otherwise) and every module card names a module
// that exists.
func TestCardTableIsComplete(t *testing.T) {
	if gaps := report.Missing(); len(gaps) > 0 {
		t.Fatalf("incomplete card table:\n  %s", strings.Join(gaps, "\n  "))
	}
	seen := map[string]bool{}
	for _, c := range report.Cards {
		if seen[c.ID] {
			t.Errorf("duplicate card id %q", c.ID)
		}
		seen[c.ID] = true
	}
}
