package html

// cards_md_global.go holds the Markdown twins of the repo-wide cards — what the
// report header's "MD" button downloads. Each mirrors the HTML card of the same
// name and reads the same view-builders (orderedCulture, buildRadar,
// packageAggs, buildArchGraph, buildContributions, …) so the two never disagree.
// Registered in cards.go, side by side with the HTML.

import (
	"fmt"
	"html"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/exey/archscope/internal/evolution"
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/openapi"
	"github.com/exey/archscope/internal/report"
	"github.com/exey/archscope/internal/report/markdown"
	"github.com/exey/archscope/internal/result"
	"github.com/exey/archscope/internal/scanner"
	"github.com/exey/archscope/internal/security"
)

// ── 📊 Summary ───────────────────────────────────────────────────────────────

func mdSummary(c report.Ctx) string {
	res := c.Res
	decls := 0
	for _, f := range res.Files {
		decls += len(f.Declarations)
	}
	platforms := res.Scan.PlatformsOrdered()
	var b strings.Builder
	b.WriteString("| Lines of code | Source files | Declarations | Modules | Danger rate | Platforms |\n")
	b.WriteString("|--------------:|-------------:|-------------:|--------:|------------:|----------:|\n")
	fmt.Fprintf(&b, "| %s | %s | %s | %s | %.1f%% | %d |\n\n",
		fmtNum(res.TotalLines()), fmtNum(len(res.Files)), fmtNum(decls), fmtNum(len(res.Scan.Modules)),
		float64(res.SecurityScore.Total)/10.0, len(platforms))
	if len(res.Technologies) > 0 {
		fmt.Fprintf(&b, "**Technologies:** %s\n\n", strings.Join(res.Technologies, " · "))
	}
	if len(res.DockerServices) > 0 {
		fmt.Fprintf(&b, "**Docker services:** %s\n\n", strings.Join(res.DockerServices, " · "))
	}
	return b.String()
}

// ── 🔰 Programming Culture ───────────────────────────────────────────────────

var (
	reHTMLClose = regexp.MustCompile(`(?i)</div>|<br\s*/?>`)
	reHTMLTag   = regexp.MustCompile(`<[^>]+>`)
)

// tipLines turns the small HTML a score-explanation (designTip, qualityTip …)
// is built from into plain lines — one per formula component.
func tipLines(h string) []string {
	h = strings.NewReplacer("<code>", "`", "</code>", "`", "<b>", "**", "</b>", "**", "<strong>", "**", "</strong>", "**").Replace(h)
	var out []string
	for _, part := range reHTMLClose.Split(h, -1) {
		t := strings.TrimSpace(html.UnescapeString(reHTMLTag.ReplaceAllString(part, "")))
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func mdCulture(c report.Ctx) string {
	res := c.Res
	var b strings.Builder
	title := "🔰 Programming Culture"
	if view, ok := orderedCulture(res); ok {
		title += " · " + view.repoLevel.name
		b.WriteString("Heuristic seniority signal per language & DevOps — read from Design/Architecture, Code Quality, Security, and Performance. A conversation starter, not a verdict. Sorted by level, highest first. Lead and Architect require strong scores across every dimension, not just a high average.\n\n")
		b.WriteString("| Platform | Code Level | 🏛️ Design | 🧹 Code Quality | 🛡️ Security | ⚡ Performance |\n|----------|------------|---------:|---------------:|-----------:|--------------:|\n")
		for _, r := range view.rows {
			fmt.Fprintf(&b, "| %s | %s | %d | %d | %d | %d |\n", mdc(r.label), mdc(view.rowLevel[r.key].name), r.design, r.quality, r.security, r.perf)
		}
		b.WriteString("\n**How each score is computed**\n\n")
		for _, r := range view.rows {
			fmt.Fprintf(&b, "- **%s**\n", r.label)
			for _, d := range []struct {
				name string
				v    int
				tip  string
			}{
				{"🏛️ Design", r.design, designTip(r)},
				{"🧹 Code Quality", r.quality, qualityTip(r)},
				{"🛡️ Security", r.security, securityTip(r)},
				{"⚡ Performance", r.perf, perfTip(r)},
			} {
				fmt.Fprintf(&b, "  - %s %d\n", d.name, d.v)
				for _, l := range tipLines(d.tip) {
					fmt.Fprintf(&b, "    - %s\n", l)
				}
			}
		}
		b.WriteString("\n")
	} else {
		b.WriteString("No platform has enough code to read.\n\n")
	}

	b.WriteString(mdEvolution(res))

	issues := cultureIssueList(res)
	if len(issues) == 0 {
		b.WriteString("### 🔎 Priority Issues\n\n✓ No O(N²)+ hotspots or credential/database security findings.\n")
		return report.WithTitle(title, b.String())
	}
	b.WriteString("### 🔎 Priority Issues (from Programming Methods · worst first)\n\n| Kind | Platform | Issue | Location |\n|------|----------|-------|----------|\n")
	for i, is := range issues {
		if i == maxCultureIssues {
			fmt.Fprintf(&b, "| | | … and %d more | |\n", len(issues)-maxCultureIssues)
			break
		}
		fmt.Fprintf(&b, "| %s %s | %s | %s | %s |\n", is.kind, mdc(is.badge), mdc(is.plat), mdc(is.desc), mdc(mdLoc(res.RootPath, is.path, is.line)))
	}
	return report.WithTitle(title, b.String())
}

// mdEvolution is the 📈 Evolution subcard of 🔰 Programming Culture: the
// timeline and every baseline-vs-now comparison (plus, in review mode, the
// merge request's changes), or the hint on how to ask for it.
func mdEvolution(res *result.AnalysisResult) string {
	var b strings.Builder
	if len(res.Evolution) == 0 {
		if res.ReviewNote != "" {
			return "### 📈 Evolution (Review mode)\n\n⚠ The review could not run — " + res.ReviewNote + "\n\n"
		}
		return "### 📈 Evolution\n\nWhat got better, what got worse since 2 weeks / 1 month / the last tag / any commit — regenerate with `--evolution 2w,1m,last-tag` (or `--evolution a1b2c3d`).\n\n"
	}
	title := "📈 Evolution — Programming Culture, then vs. now"
	if res.Review != nil {
		title = "📈 Evolution (Review mode) — Programming Culture, then vs. now"
	}
	fmt.Fprintf(&b, "### %s\n\n", title)
	if tl, ok := evolution.NewTimeline(res.Evolution); ok {
		fmt.Fprintf(&b, "**⏱ Timeline: %s**\n\n%s\n", tl.Heading(), evolution.RenderTimelineMarkdown(tl))
	}
	for _, cmp := range res.Evolution {
		changes := ""
		if res.Review != nil && cmp.IsReview() {
			changes = evolution.RenderReviewMarkdown(res.Review)
		}
		fmt.Fprintf(&b, "**%s**\n\n%s%s\n", cmp.Ref.Title, changes, evolution.RenderMarkdown(cmp))
	}
	return b.String()
}

// ── 🧰 Tech Stack & Modules ──────────────────────────────────────────────────

func mdStack(c report.Ctx) string {
	res := c.Res
	langSet := map[string]bool{}
	for _, f := range res.Files {
		if lbl, ok := langLabels[f.LanguageID]; ok {
			langSet[lbl] = true
		}
	}
	if len(langSet) == 0 && len(res.Technologies) == 0 && len(res.Scan.Modules) == 0 {
		return ""
	}
	catSets := techCategorySets(res)
	var b strings.Builder
	if len(langSet) > 0 {
		fmt.Fprintf(&b, "**🔤 Languages:** %s\n\n", strings.Join(sortedKeys(langSet), " · "))
	}
	for _, col := range []struct{ cat, label, icon string }{
		{"frontend", "Frontend", "🖥️"}, {"backend", "Backend", "⚙️"}, {"data", "Data", "🗄️"},
		{"brokers", "Message Brokers", "📨"}, {"linters", "Metrics", "📊"},
	} {
		if len(catSets[col.cat]) > 0 {
			fmt.Fprintf(&b, "**%s %s:** %s\n\n", col.icon, col.label, strings.Join(sortedKeys(catSets[col.cat]), " · "))
		}
	}
	list := packageAggs(res)
	fmt.Fprintf(&b, "**📦 Packages & modules (%d)**\n\n", len(list))
	if len(list) == 0 {
		b.WriteString("No modules detected.\n")
		return b.String()
	}
	b.WriteString("| Module | Platform | Lines |\n|--------|----------|------:|\n")
	for _, a := range list {
		name := a.name
		if name == "" {
			name = "(root)"
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", mdc(name), mdc(shortLangLabel(a.plat)), fmtNum(a.loc))
	}
	return b.String()
}

// ── 📡 Technical Radar ───────────────────────────────────────────────────────

func mdRadar(c report.Ctx) string {
	m, ok := buildRadar(c.Res)
	if !ok {
		return ""
	}
	var b strings.Builder
	b.WriteString("Detected technologies placed on an adoption radar — Adopt (center, safe default) to Hold (rim, avoid/replace) — across four quadrants: tools, languages & frameworks, platforms & operations, and methods & patterns.\n\n")
	chips := func(cs []radarChip) string {
		parts := make([]string, 0, len(cs))
		for _, ch := range cs {
			parts = append(parts, fmt.Sprintf("%s (%s)", ch.label, radarRingNames[ch.ring]))
		}
		return strings.Join(parts, " · ")
	}
	for qi, quad := range radarQuadrants {
		var rows []string
		for _, dc := range m.quadCats[qi] {
			if cs := m.catChips[dc.key]; len(cs) > 0 {
				rows = append(rows, fmt.Sprintf("| %s | %s |", dc.title, mdc(chips(cs))))
			}
		}
		if qi == 3 && len(m.patternChips) > 0 {
			rows = append(rows, fmt.Sprintf("| Design Patterns | %s |", mdc(chips(m.patternChips))))
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(&b, "**%s**\n\n| Category | Technologies (ring) |\n|----------|---------------------|\n%s\n\n", quad.title, strings.Join(rows, "\n"))
	}
	return b.String()
}

// ── 🗺️ Architecture Graph ────────────────────────────────────────────────────

func mdArchGraph(c report.Ctx) string {
	g, ok := buildArchGraph(c.Res)
	if !ok {
		return ""
	}
	label := map[string]string{}
	var mods, techs []gNode
	for _, n := range g.Nodes {
		label[n.ID] = n.Label
		if n.Kind == "technology" {
			techs = append(techs, n)
		} else {
			mods = append(mods, n)
		}
	}
	deps := map[string][]string{}
	uses := map[string][]string{}
	for _, l := range g.Links {
		if l.Kind == "tech" {
			uses[l.Source] = append(uses[l.Source], label[l.Target])
		} else {
			deps[l.Source] = append(deps[l.Source], label[l.Target])
		}
	}
	var b strings.Builder
	b.WriteString("Modules and detected technologies; an arrow reads \"depends on\".\n\n")
	b.WriteString("| Module | Group | Size | Depends on | Technologies |\n|--------|-------|-----:|------------|--------------|\n")
	for _, n := range mods {
		d, u := deps[n.ID], uses[n.ID]
		sort.Strings(d)
		sort.Strings(u)
		fmt.Fprintf(&b, "| %s | %s | %d%% | %s | %s |\n", mdc(n.Label), mdc(n.Group), int(n.Score*100+0.5), mdc(strings.Join(d, ", ")), mdc(strings.Join(u, ", ")))
	}
	if len(techs) > 0 {
		names := make([]string, 0, len(techs))
		for _, t := range techs {
			names = append(names, t.Label)
		}
		fmt.Fprintf(&b, "\n**Technologies:** %s\n", strings.Join(names, " · "))
	}
	return b.String()
}

// ── 🛡️ Danger Index ──────────────────────────────────────────────────────────

func mdDanger(c report.Ctx) string {
	res := c.Res
	sc := res.SecurityScore
	var b strings.Builder
	b.WriteString("Weighted exposure across 14 categories (0 = hardened, 1000 = critical). Risk per category saturates with finding density.\n\n")
	fmt.Fprintf(&b, "**Danger Index: %d / 1000 — %s**\n\n", sc.Total, sc.Band)
	b.WriteString("| # | Category | Points | Weight |\n|--:|----------|-------:|-------:|\n")
	for _, cs := range sc.Categories {
		pts := fmt.Sprintf("%d", cs.Points)
		if cs.NotAssessed() {
			pts = "not assessed"
		}
		fmt.Fprintf(&b, "| %d | %s %s | %s | %d |\n", cs.Category.ID, cs.Category.Icon, mdc(cs.Category.Title), pts, cs.Category.Weight)
	}
	b.WriteString("\n")

	// 🛡️ Findings by Platform
	filePlatform := map[string]langspec.Platform{}
	for _, f := range res.Files {
		filePlatform[f.FilePath] = langspec.Platform(f.Platform)
	}
	platFindings := map[langspec.Platform]int{}
	platHigh := map[langspec.Platform]int{}
	for _, rr := range res.Security {
		if rr.Passed() {
			continue
		}
		for _, f := range rr.Findings {
			if p := filePlatform[f.FullPath]; p != "" {
				platFindings[p]++
				if rr.Rule.Severity == security.SevHigh {
					platHigh[p]++
				}
			}
		}
	}
	var rows []string
	for _, pg := range res.PlatformTabs() {
		if n := platFindings[pg.Platform]; n > 0 {
			rows = append(rows, fmt.Sprintf("| %s | %d | %d |", mdc(pg.TabLabel()), n, platHigh[pg.Platform]))
		}
	}
	if res.Scan.K8sLint != nil && len(res.Scan.K8sLint.ClusterFindings) > 0 {
		cf := res.Scan.K8sLint.ClusterFindings
		critHigh := 0
		for _, f := range cf {
			if f.Severity == "critical" || f.Severity == "high" {
				critHigh++
			}
		}
		rows = append(rows, fmt.Sprintf("| ☁️ DevOps | %d | %d |", len(cf), critHigh))
	}
	if len(rows) > 0 {
		b.WriteString("**🛡️ Findings by Platform**\n\n| Platform | Findings | HIGH |\n|----------|---------:|-----:|\n" + strings.Join(rows, "\n") + "\n\n")
	}
	b.WriteString(markdown.CWEIndex())
	return b.String()
}

// ── ☁️ DevOps ────────────────────────────────────────────────────────────────

func mdDevOps(c report.Ctx) string {
	res := c.Res
	lint, k8s := res.DevOpsLint, res.K8sLint
	if !lint.HasEnoughSignal() {
		lint = nil
	}
	if len(res.DevOpsTools) == 0 && lint.Empty() && k8s.Empty() {
		return ""
	}
	var b strings.Builder
	if score, ok := lint.Score(); ok {
		fmt.Fprintf(&b, "**Static-analysis hygiene score: %d%%** (pass=1, warn=½, fail=0)\n\n", score)
	}
	if len(res.DevOpsTools) > 0 {
		names := make([]string, 0, len(res.DevOpsTools))
		for _, t := range res.DevOpsTools {
			names = append(names, t.Icon+" "+t.Name)
		}
		fmt.Fprintf(&b, "**Detected tools:** %s\n\n", strings.Join(names, " · "))
	}
	if !lint.Empty() || !k8s.Empty() {
		if health, ok := devopsHealthScore(lint, k8s); ok {
			band, _ := healthBand(health)
			fmt.Fprintf(&b, "**🩺 DevOps Health Score: %d%% — %s** — severity-weighted rollup of every evaluable check (critical ×10 … low ×1).\n\n", health, band)
		}
		kinds, defects := devopsDefectCounts(lint, k8s)
		if len(kinds) > 0 {
			b.WriteString("**📊 Defect Density by Artifact** — non-passing checks, by severity\n\n| Artifact | Critical | High | Medium | Low |\n|----------|---------:|-----:|-------:|----:|\n")
			for _, k := range kinds {
				d := defects[k]
				fmt.Fprintf(&b, "| %s | %d | %d | %d | %d |\n", mdc(k), d[0], d[1], d[2], d[3])
			}
			b.WriteString("\n")
		} else {
			b.WriteString("**📊 Defect Density by Artifact** — no failing or warned checks; clean bill of health.\n\n")
		}
		scores, has := devopsComplianceDomains(lint)
		anyDomain := false
		for _, h := range has {
			anyDomain = anyDomain || h
		}
		if anyDomain {
			b.WriteString("**🎯 Security & Compliance Radar** — domain average of related checks (pass=100%, warn=50%, fail=0%)\n\n| # | Domain | Score |\n|--:|--------|------:|\n")
			for i, name := range devopsDomains {
				if has[i] {
					fmt.Fprintf(&b, "| %d | %s | %d%% |\n", i+1, name, scores[i])
				} else {
					fmt.Fprintf(&b, "| %d | %s | n/a |\n", i+1, name)
				}
			}
			b.WriteString("\n")
		}
		if !k8s.Empty() {
			b.WriteString(mdK8sSummary(k8s))
		}
	}
	if !lint.Empty() {
		b.WriteString("**🔬 Static Analysis** (Hadolint · Dockle · KubeLinter · Checkov-style checks)\n\n")
		for _, a := range []*scanner.DevOpsArtifactLint{lint.Dockerfiles, lint.Helm, lint.Compose} {
			if a == nil {
				continue
			}
			fmt.Fprintf(&b, "#### %s %s — %d file%s\n\n%s\n\n| Category | Check | Status | Value | Reference |\n|----------|-------|:------:|-------|-----------|\n",
				a.Icon, a.Kind, len(a.Files), plural(len(a.Files), "", "s"), mdc(strings.Join(a.Files, ", ")))
			for _, ch := range a.Checks {
				ref := ""
				if docs := devopsDocLinks[ch.Metric]; len(docs) > 0 {
					ref = fmt.Sprintf("[%s](%s)", docs[0].Label, docs[0].URL)
				}
				fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", mdc(ch.Category), mdc(ch.Metric), statusMark(ch.Status), mdc(ch.Value), ref)
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

// statusMark is a check status as a single mark.
func statusMark(s string) string {
	switch s {
	case "pass":
		return "✅"
	case "warn":
		return "⚠️"
	case "fail":
		return "❌"
	}
	return "—"
}

// mdK8sSummary is the "☸️ Kubernetes" tile of the DevOps charts.
func mdK8sSummary(k8s *scanner.K8sLint) string {
	scoreSum, podCount := 0, 0
	var totalRAM float64
	for _, w := range k8s.Workloads {
		scoreSum += w.Score
		replicas := w.Replicas
		if replicas <= 0 {
			replicas = 1
		}
		podCount += replicas
		agg := aggregateK8sResources(w)
		mem := agg.memLim
		if mem == 0 {
			mem = agg.memReq
		}
		totalRAM += mem * float64(replicas)
	}
	s := k8s.Stats
	other := s.Services + s.Ingresses + s.NetworkPolicies + s.ConfigMaps + s.PVCs + s.StorageClasses +
		s.ServiceAccounts + s.Roles + s.RoleBindings + s.ClusterRoles + s.ClusterRoleBindings + s.HPAs + s.PDBs
	for _, op := range s.Operators {
		other += op.Count
	}
	parts := []string{
		fmt.Sprintf("%d workload%s", len(k8s.Workloads), plural(len(k8s.Workloads), "", "s")),
		fmt.Sprintf("%d pod%s", podCount, plural(podCount, "", "s")),
	}
	if totalRAM > 0 {
		parts = append(parts, formatMemBytes(totalRAM)+" RAM requested")
	}
	if s.PVCs > 0 {
		parts = append(parts, fmt.Sprintf("%d disk%s (PVC)", s.PVCs, plural(s.PVCs, "", "s")))
	}
	parts = append(parts, fmt.Sprintf("%d other resource%s", other, plural(other, "", "s")),
		fmt.Sprintf("%d%% passed", scoreSum/len(k8s.Workloads)))
	if n := len(k8s.Clusters); n > 1 {
		parts = append(parts, fmt.Sprintf("%d clusters", n))
	}
	return "**☸️ Kubernetes** — " + strings.Join(parts, " · ") + " (full breakdown in Infrastructure Platforms)\n\n"
}

// ── 📜 OpenAPI ───────────────────────────────────────────────────────────────

func mdOpenAPI(c report.Ctx) string {
	md := openapi.RenderMarkdown(c.Res.OpenAPI, func(p string) string { return mdRel(c.Res.RootPath, p) })
	// The card heading comes from report.Cards; drop the renderer's own.
	return strings.TrimPrefix(md, "## 📜 OpenAPI\n\n")
}

// ── 📅 Contributions ─────────────────────────────────────────────────────────

func mdContributions(c report.Ctx) string {
	d, ok := buildContributions(c.Res)
	if !ok {
		return ""
	}
	// Week index range of each month span.
	type span struct {
		label      string
		start, end int
	}
	var spans []span
	i := 0
	for _, m := range d.months {
		spans = append(spans, span{m.label, i, i + m.weeks})
		i += m.weeks
	}
	var b strings.Builder
	b.WriteString("Commits per month over the last 14 months, one row per git repository (most active first). Weeks flagged ‼ are anomalies (more than Q3 + 3×IQR).\n\n")
	b.WriteString("| Repository | Languages | Total |")
	for _, sp := range spans {
		b.WriteString(" " + sp.label + " |")
	}
	b.WriteString("\n|------------|-----------|------:|" + strings.Repeat("-----:|", len(spans)) + "\n")
	for _, r := range d.rows {
		fmt.Fprintf(&b, "| %s | %s | %d |", mdc(r.name), mdc(r.abbrs), r.total)
		for _, sp := range spans {
			n := 0
			for w := sp.start; w < sp.end; w++ {
				n += r.weekly[w]
			}
			fmt.Fprintf(&b, " %d |", n)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	for _, r := range d.rows {
		var busiest, anomalies []string
		type wk struct{ i, n int }
		var weeks []wk
		for w := 0; w < d.nWeeks; w++ {
			if r.weekly[w] > 0 {
				weeks = append(weeks, wk{w, r.weekly[w]})
			}
			if r.anomaly[w] {
				anomalies = append(anomalies, weekRange(d.weekDate(w))+fmt.Sprintf(" · %d commits", r.weekly[w]))
			}
		}
		sort.SliceStable(weeks, func(i, j int) bool { return weeks[i].n > weeks[j].n })
		for k := 0; k < len(weeks) && k < 3; k++ {
			busiest = append(busiest, weekRange(d.weekDate(weeks[k].i))+fmt.Sprintf(" · %d commits", weeks[k].n))
		}
		if len(busiest) > 0 {
			fmt.Fprintf(&b, "- **%s** — busiest weeks: %s", r.name, strings.Join(busiest, "; "))
			if len(anomalies) > 0 {
				fmt.Fprintf(&b, " — ‼ anomalous: %s", strings.Join(anomalies, "; "))
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

func weekRange(start time.Time) string {
	return start.Format("2 Jan") + "–" + start.AddDate(0, 0, 6).Format("2 Jan 2006")
}

// ── ☸️ Infrastructure Platforms ──────────────────────────────────────────────

func mdInfra(c report.Ctx) string {
	k8s := c.Res.K8sLint
	if k8s.Empty() {
		return ""
	}
	var b strings.Builder
	for _, cl := range k8s.Clusters {
		if len(cl.Workloads) == 0 {
			continue
		}
		name := cl.Name
		if name == "" {
			name = "Kubernetes"
		}
		scoreSum := 0
		byKind := map[string][]scanner.K8sWorkload{}
		for _, w := range cl.Workloads {
			scoreSum += w.Score
			byKind[w.Kind] = append(byKind[w.Kind], w)
		}
		fmt.Fprintf(&b, "### ☸️ %s — %d workload%s · %d file%s · %d%% passed", name, len(cl.Workloads), plural(len(cl.Workloads), "", "s"),
			len(cl.Files), plural(len(cl.Files), "", "s"), scoreSum/len(cl.Workloads))
		if n := len(cl.ClusterFindings); n > 0 {
			fmt.Fprintf(&b, " · %d finding%s", n, plural(n, "", "s"))
		}
		fmt.Fprintf(&b, "\n\nLinted from %s — practices inspired by kube-linter (resource limits, security context, probes, image pinning, host access). Sorted by resource footprint, biggest first.\n\n", strings.Join(cl.Files, ", "))
		for _, kind := range k8sKindOrder {
			workloads := byKind[kind]
			if len(workloads) == 0 {
				continue
			}
			sort.SliceStable(workloads, func(i, j int) bool {
				return aggregateK8sResources(workloads[i]).footprint() > aggregateK8sResources(workloads[j]).footprint()
			})
			more := 0
			if len(workloads) > k8sMaxCardsPerKind {
				more = len(workloads) - k8sMaxCardsPerKind
				workloads = workloads[:k8sMaxCardsPerKind]
			}
			fmt.Fprintf(&b, "#### %s %s (%d)\n\n| Workload | Namespace | Replicas | CPU req→lim | Memory req→lim | Passed | Failed / warned checks |\n|----------|-----------|---------:|-------------|----------------|-------:|------------------------|\n",
				k8sKindIcon[kind], kind, len(byKind[kind]))
			for _, w := range workloads {
				agg := aggregateK8sResources(w)
				cpu := func(v float64, has bool) string {
					if !has {
						return "–"
					}
					return formatCPUMillis(v)
				}
				mem := func(v float64, has bool) string {
					if !has {
						return "–"
					}
					return formatMemBytes(v)
				}
				var issues []string
				for _, ch := range w.Checks {
					label := ch.Metric
					if ch.Category != "Pod" {
						label = ch.Category + ": " + ch.Metric
					}
					switch ch.Status {
					case "fail":
						issues = append(issues, "✕ "+label)
					case "warn":
						issues = append(issues, "⚠ "+label)
					}
				}
				replicas := "–"
				if w.Replicas > 0 {
					replicas = fmt.Sprintf("%d", w.Replicas)
				}
				fmt.Fprintf(&b, "| %s | %s | %s | %s→%s | %s→%s | %d%% | %s |\n", mdc(w.Name), mdc(w.Namespace), replicas,
					cpu(agg.cpuReq, agg.hasCPUReq), cpu(agg.cpuLim, agg.hasCPULim),
					mem(agg.memReq, agg.hasMemReq), mem(agg.memLim, agg.hasMemLim), w.Score, mdc(strings.Join(issues, "; ")))
			}
			if more > 0 {
				fmt.Fprintf(&b, "\n+%d more %s%s not shown (showing the %d with the largest resource footprint)\n", more, kind, plural(more, "", "s"), k8sMaxCardsPerKind)
			}
			b.WriteString("\n")
		}
		b.WriteString(mdK8sFindings(cl.ClusterFindings))
		b.WriteString(mdK8sStats(cl.Stats))
	}
	return b.String()
}

func mdK8sFindings(findings []scanner.K8sClusterFinding) string {
	groups := groupK8sFindings(findings)
	if len(groups) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("#### ⚠️ Weaknesses\n\n")
	for _, g := range groups {
		cwe := ""
		if g.CWE != "" {
			cwe = fmt.Sprintf(" · [CWE-%s](https://cwe.mitre.org/data/definitions/%s.html)", g.CWE, g.CWE)
		}
		tier := ""
		if g.Tier != "" {
			tier = " · " + string(g.Tier)
		}
		fmt.Fprintf(&b, "- **[%s] %s**%s%s — %s\n", strings.ToUpper(g.Severity), g.Title, tier, cwe, g.Detail)
		for _, cs := range g.Cases {
			ns := cs.Namespace
			if ns == "" {
				ns = "cluster"
			}
			label := ns + " / " + cs.Kind
			if cs.Name != "" {
				label += " " + cs.Name
			}
			if cs.Line > 0 {
				label += fmt.Sprintf(" (%s:%d)", baseFile(cs.File), cs.Line)
			}
			fmt.Fprintf(&b, "  - %s\n", label)
		}
	}
	b.WriteString("\n")
	return b.String()
}

func mdK8sStats(s scanner.K8sClusterStats) string {
	if s.Empty() {
		return ""
	}
	var b strings.Builder
	b.WriteString("#### Cluster resources\n\n| Resource | Count | Note |\n|----------|------:|------|\n")
	row := func(name string, n int, note string) {
		if n > 0 {
			fmt.Fprintf(&b, "| %s | %d | %s |\n", name, n, mdc(note))
		}
	}
	row("Services", s.Services, fmt.Sprintf("%d port(s) below 1024", s.ServicesPrivPorts))
	row("Ingresses", s.Ingresses, fmt.Sprintf("%d with TLS", s.IngressesTLS))
	row("NetworkPolicies", s.NetworkPolicies, "")
	row("ConfigMaps", s.ConfigMaps, "")
	row("PersistentVolumeClaims", s.PVCs, fmt.Sprintf("%d with a storage class", s.PVCsWithStorageClass))
	row("StorageClasses", s.StorageClasses, "")
	row("ServiceAccounts", s.ServiceAccounts, "")
	row("Roles", s.Roles, fmt.Sprintf("%d with wildcard rules", s.RolesWildcard))
	row("RoleBindings", s.RoleBindings, "")
	row("ClusterRoles", s.ClusterRoles, fmt.Sprintf("%d with wildcard rules", s.ClusterRolesWildcard))
	row("ClusterRoleBindings", s.ClusterRoleBindings, fmt.Sprintf("%d cluster-admin bindings to custom accounts", s.ClusterAdminBindings))
	row("HorizontalPodAutoscalers", s.HPAs, "")
	row("PodDisruptionBudgets", s.PDBs, "")
	for _, op := range s.Operators {
		note := ""
		if op.HasAvailableReplicas {
			note = fmt.Sprintf("%d available replicas", op.AvailableReplicas)
		}
		row(op.Kind+" (operator CRD)", op.Count, note)
	}
	b.WriteString("\n")
	if len(s.IngressDetails) > 0 {
		b.WriteString("**Ingress routes**\n\n| Ingress | Namespace | TLS | Host | Path | Backend |\n|---------|-----------|:---:|------|------|---------|\n")
		for _, d := range s.IngressDetails {
			tls := "—"
			if d.TLS {
				tls = "✅"
			}
			if len(d.Rules) == 0 {
				fmt.Fprintf(&b, "| %s | %s | %s | | | |\n", mdc(d.Name), mdc(d.Namespace), tls)
			}
			for _, r := range d.Rules {
				host := r.Host
				if host == "" {
					host = "*"
				}
				fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", mdc(d.Name), mdc(d.Namespace), tls, mdc(host), mdc(r.Path), mdc(r.Backend))
			}
		}
		b.WriteString("\n")
	}
	if len(s.ServiceDetails) > 0 {
		b.WriteString("**Services**\n\n| Service | Namespace | Type | Ports |\n|---------|-----------|------|-------|\n")
		for _, d := range s.ServiceDetails {
			var ports []string
			for _, p := range d.Ports {
				ports = append(ports, fmt.Sprintf("%v→%s/%s", p.Port, p.TargetPort, p.Protocol))
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", mdc(d.Name), mdc(d.Namespace), mdc(d.Type), mdc(strings.Join(ports, ", ")))
		}
		b.WriteString("\n")
	}
	return b.String()
}
