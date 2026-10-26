package html

// cards_md_platform.go holds the Markdown twins of the per-platform cards. Each
// mirrors the HTML card next to it in graphs.go / sections.go — same data, same
// limits — and shares that card's row builders where there are any, so the two
// formats cannot drift apart. Registered in cards.go, side by side with the HTML.

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules/arch"
	"github.com/exey/archscope/internal/modules/speccoverage"
	"github.com/exey/archscope/internal/modules/traffic"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/report"
	"github.com/exey/archscope/internal/security"
)

// mdc keeps a value from breaking out of a Markdown table cell.
func mdc(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r", ""), "\n", " ")
}

// mdRel is p relative to the scan root, slash-separated.
func mdRel(root, p string) string {
	if root != "" {
		if r, err := filepath.Rel(root, p); err == nil && !strings.HasPrefix(r, "..") {
			return filepath.ToSlash(r)
		}
	}
	return filepath.ToSlash(p)
}

// mdLoc is "rel/path:line" (or just the path when there is no line).
func mdLoc(root, p string, line int) string {
	if line > 0 {
		return fmt.Sprintf("%s:%d", mdRel(root, p), line)
	}
	return mdRel(root, p)
}

// ── 🏛️ Architecture ──────────────────────────────────────────────────────────

func mdArchitecture(c report.Ctx) string {
	res, pg, files := c.Res, c.PG, c.Files
	lp := pg.LanguagePlatform
	if lp == "" {
		lp = pg.Platform
	}
	layers := archLayerRows(files)
	comps := detectComponents(files, buildTechSet(res, files))
	versions := res.Scan.Versions[lp]
	var patterns string
	for _, p := range res.PanelsForPlatform(pg.Platform) {
		if r, ok := p.RawResult.(arch.Result); ok && p.ModuleID == "architecture" {
			patterns = r.PatternsMarkdown()
		}
	}
	if len(layers) == 0 && len(comps) == 0 && len(versions) == 0 && patterns == "" {
		return ""
	}
	var b strings.Builder
	if len(layers) > 0 {
		b.WriteString("#### 🏗️ Architecture Layers\n\n| Layer | Files | Lines |\n|-------|------:|------:|\n")
		for _, l := range layers {
			fmt.Fprintf(&b, "| %s %s | %d | %s |\n", l.icon, mdc(l.name), l.files, fmtNum(l.loc))
		}
		b.WriteString("\n")
	}
	b.WriteString(patterns)
	if len(comps) > 0 {
		b.WriteString("#### 🧩 Components\n\n")
		for _, cp := range comps {
			fmt.Fprintf(&b, "- %s %s\n", cp.icon, cp.summary)
		}
		b.WriteString("\n")
	}
	if len(versions) > 0 {
		b.WriteString("#### 🔢 Versions\n\n| Technology | Version | Category | Source |\n|------------|---------|----------|--------|\n")
		for _, v := range versions {
			label := archVersionCategoryLabel[v.Category]
			if label == "" {
				label = v.Category
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", mdc(v.Name), mdc(v.Version), mdc(label), mdc(v.Source))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ── 🛜 Traffic ───────────────────────────────────────────────────────────────

func mdTraffic(c report.Ctx) string {
	var tr *traffic.Result
	var spec *speccoverage.Result
	for _, p := range c.Res.PanelsForPlatform(c.PG.Platform) {
		switch p.ModuleID {
		case "traffic":
			if r, ok := p.RawResult.(traffic.Result); ok && tr == nil {
				tr = &r
			}
		case "speccoverage":
			if r, ok := p.RawResult.(speccoverage.Result); ok && spec == nil {
				spec = &r
			}
		}
	}
	if tr == nil {
		return ""
	}
	var covered map[string]bool
	if spec != nil {
		covered = map[string]bool{}
		for _, op := range spec.Covered {
			covered[normSpecURI(op.Path)] = true
		}
	}
	var b strings.Builder
	th, ok := computeTrafficHealth(*tr, spec, langspec.Default.IsClientPlatform(c.PG.Platform))
	if ok {
		fmt.Fprintf(&b, "**🩺 Traffic Health: %d%%**\n\n| Check | Score | Detail |\n|-------|------:|--------|\n", th.overall)
		for _, cat := range th.cats {
			fmt.Fprintf(&b, "| %s %s | %d%% | %s |\n", cat.icon, mdc(cat.label), cat.score, mdc(cat.detail))
		}
		b.WriteString("\n")
		for _, cat := range th.cats {
			if how, ok := trafficHealthHowTo[cat.label]; ok {
				fmt.Fprintf(&b, "- **%s %s** — %s\n", cat.icon, cat.label, how)
			}
		}
		b.WriteString("\n")
	}
	var specCol func(traffic.Entry) string
	if spec != nil {
		specCol = func(e traffic.Entry) string {
			if covered[normSpecURI(e.URI)] {
				return "✅"
			}
			return "❓"
		}
	}
	b.WriteString(tr.MarkdownTables(specCol))
	return b.String()
}

// ── 💡 Module Insights ───────────────────────────────────────────────────────

func mdHotspots(c report.Ctx) string {
	rows := hotspotRows(c.Res, c.PG)
	if len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Modules imported or referenced by the most others — the highest-leverage nodes in the codebase.\n\n")
	b.WriteString("| Module | Uses | Lines | Decl |\n|--------|-----:|------:|-----:|\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %d | %s | %d |\n", mdc(r.name), r.uses, fmtNum(r.lines), r.decl)
	}
	return b.String()
}

func mdMicroservices(c report.Ctx) string {
	pg := c.PG
	if len(pg.Modules) == 0 {
		return ""
	}
	icon, label := langspec.Default.ModuleNoun(pg.Platform)
	counts := map[string]int{}
	mloc := map[string]int{}
	for _, f := range c.Files {
		counts[f.ModuleName]++
		mloc[f.ModuleName] += f.LineCount
	}
	var b strings.Builder
	b.WriteString("| Module | Files | Lines |\n|--------|------:|------:|\n")
	for _, m := range pg.Modules {
		name := m
		if name == "" {
			name = "(root)"
		}
		fmt.Fprintf(&b, "| %s | %d | %s |\n", mdc(name), counts[m], fmtNum(mloc[m]))
	}
	return report.WithTitle(fmt.Sprintf("%s %s (%d)", icon, label, len(pg.Modules)), b.String())
}

func mdTodos(c report.Ctx) string {
	items := todoItems(c.Files)
	if len(items) == 0 {
		return ""
	}
	total, shown := len(items), items
	head := fmt.Sprintf("(%d)", total)
	if total > todoLimit {
		shown = items[:todoLimit]
		head = fmt.Sprintf("(showed %d from %d)", todoLimit, total)
	}
	var b strings.Builder
	b.WriteString("| Kind | File | Note |\n|------|------|------|\n")
	for _, it := range shown {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", it.Kind, mdc(mdLoc(c.Res.RootPath, it.FilePath, it.Line)), mdc(it.Text))
	}
	if total > todoLimit {
		fmt.Fprintf(&b, "\n… and %d more\n", total-todoLimit)
	}
	return report.WithTitle("📝 TODOs & FIXMEs "+head, b.String())
}

func mdLongestFuncs(c report.Ctx) string {
	fns := longestFuncs(c.Files)
	if len(fns) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("| Function | Lines | File |\n|----------|------:|------|\n")
	for _, fn := range fns {
		fmt.Fprintf(&b, "| %s | %d | %s |\n", mdc(fn.Name), fn.LineCount, mdc(mdLoc(c.Res.RootPath, fn.FilePath, fn.StartLine)))
	}
	return b.String()
}

func mdBiggestTypes(c report.Ctx) string {
	types := biggestTypes(c.Files)
	if len(types) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("| Type | Kind | Lines | File | Module |\n|------|------|------:|------|--------|\n")
	for _, e := range types {
		mod := e.mod
		if mod == "" {
			mod = "root"
		}
		fmt.Fprintf(&b, "| %s | %s | %d | %s | %s |\n", mdc(e.ty.Name), mdc(string(e.ty.Kind)), e.ty.LineCount,
			mdc(mdLoc(c.Res.RootPath, e.ty.FilePath, e.ty.StartLine)), mdc(mod))
	}
	return b.String()
}

// ── 🐙 Git Analysis ──────────────────────────────────────────────────────────

func mdGit(c report.Ctx) string {
	g := c.Res.Git
	if !g.Available {
		return "No git history available.\n"
	}
	pgit := c.Res.PlatformGit(c.PG, c.Files)
	var b strings.Builder

	b.WriteString("#### 👥 Top Contributors\n\n")
	authors := topAuthors(pgit.Authors)
	if len(authors) == 0 {
		b.WriteString("No authors found.\n\n")
	} else {
		b.WriteString("| Author | Commits | Files |\n|--------|--------:|------:|\n")
		for _, a := range authors {
			fmt.Fprintf(&b, "| %s | %d | %d |\n", mdc(a.name), a.commits, a.files)
		}
		b.WriteString("\n")
	}

	b.WriteString("#### 🔥 File Churn\n\n")
	churn := pgit.Churn
	if len(churn) == 0 {
		b.WriteString("No churn data.\n\n")
	} else {
		if len(churn) > 10 {
			churn = churn[:10]
		}
		b.WriteString("| File | Changes |\n|------|--------:|\n")
		for _, ch := range churn {
			fmt.Fprintf(&b, "| %s | %d |\n", mdc(ch.RelPath), ch.ChangeCount)
		}
		b.WriteString("\n")
	}

	t, cm := g.Tags, g.Commits
	b.WriteString("#### 🏷️ Releases & Commit Hygiene\n\n")
	fmt.Fprintf(&b, "%d tags · %d semver", t.TotalTags, t.SemverTags)
	if t.LatestSemver != "" {
		fmt.Fprintf(&b, " · latest %s", t.LatestSemver)
	}
	b.WriteString("\n\n")
	if len(t.SemverList) > 0 {
		lim := t.SemverList
		if len(lim) > 12 {
			lim = lim[:12]
		}
		fmt.Fprintf(&b, "Tags: %s\n\n", strings.Join(lim, " · "))
	}
	if cm.Total > 0 {
		fmt.Fprintf(&b, "%d%% conventional commits (%d/%d typed)\n\n", cm.Typed*100/cm.Total, cm.Typed, cm.Total)
		if len(cm.TypeCounts) > 0 {
			type kv struct {
				k string
				v int
			}
			var kvs []kv
			for k, v := range cm.TypeCounts {
				kvs = append(kvs, kv{k, v})
			}
			sort.Slice(kvs, func(i, j int) bool {
				if kvs[i].v != kvs[j].v {
					return kvs[i].v > kvs[j].v
				}
				return kvs[i].k < kvs[j].k
			})
			parts := make([]string, 0, len(kvs))
			for _, p := range kvs {
				parts = append(parts, fmt.Sprintf("%s · %d", p.k, p.v))
			}
			fmt.Fprintf(&b, "Types: %s\n\n", strings.Join(parts, " · "))
		}
	}

	bs := g.Branch
	b.WriteString("#### 🌳 Branches\n\n")
	fmt.Fprintf(&b, "%d total", bs.TotalBranches)
	if bs.AvgLifetimeDays > 0 {
		fmt.Fprintf(&b, " · avg lifetime %.0f days", bs.AvgLifetimeDays)
	}
	if bs.PeakCommitDay != "" {
		fmt.Fprintf(&b, " · peak day %s", bs.PeakCommitDay)
	}
	b.WriteString("\n\n")
	if len(bs.StaleBranches) > 0 {
		stale := bs.StaleBranches
		if len(stale) > 8 {
			stale = stale[:8]
		}
		b.WriteString("| Stale branch | Days idle |\n|--------------|----------:|\n")
		for _, br := range stale {
			fmt.Fprintf(&b, "| %s | %d |\n", mdc(br.Name), br.DaysInactive)
		}
		b.WriteString("\n")
	} else {
		b.WriteString("No stale branches.\n\n")
	}
	return b.String()
}

// ── 🛡️ Danger Details ────────────────────────────────────────────────────────

func mdSecurity(c report.Ctx) string {
	sec := c.Res.PlatformSecurity(c.PG.Platform)
	if sec.Total == 0 {
		return "✓ No findings in this platform's sources.\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**HIGH %d · MED %d · LOW %d**\n\n", sec.High, sec.Medium, sec.Low)
	rules := append([]security.RuleResult(nil), sec.Rules...)
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Rule.Severity.Rank() != rules[j].Rule.Severity.Rank() {
			return rules[i].Rule.Severity.Rank() > rules[j].Rule.Severity.Rank()
		}
		return rules[i].Rule.ID < rules[j].Rule.ID
	})
	for _, rr := range rules {
		cwe := ""
		if rr.Rule.CWE != "" {
			cwe = fmt.Sprintf(" [CWE-%s](https://cwe.mitre.org/data/definitions/%s.html)", rr.Rule.CWE, rr.Rule.CWE)
		}
		fmt.Fprintf(&b, "#### [%s] %s — `%s`%s · %d %s\n\n", rr.Rule.Severity, rr.Rule.Name, rr.Rule.ID, cwe,
			rr.TotalCount, plural(rr.TotalCount, "finding", "findings"))
		if rr.Rule.Description != "" {
			b.WriteString(rr.Rule.Description + "\n\n")
		}
		shown := rr.Findings
		const maxFindings = 15
		if len(shown) > maxFindings {
			shown = shown[:maxFindings]
		}
		for _, f := range shown {
			fmt.Fprintf(&b, "- `%s:%d`", f.File, f.Line)
			if f.Author != "" {
				fmt.Fprintf(&b, " — %s", f.Author)
			}
			if f.Snippet != "" {
				fmt.Fprintf(&b, " — `%s`", strings.ReplaceAll(strings.TrimSpace(f.Snippet), "`", "'"))
			}
			b.WriteString("\n")
		}
		if n := len(rr.Findings) - len(shown); n > 0 {
			fmt.Fprintf(&b, "- + %d more %s\n", n, plural(n, "finding", "findings"))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ── 📂 Modules & Microservices ───────────────────────────────────────────────

func mdModuleDetails(c report.Ctx) string {
	if !c.Res.Scan.RenderModules {
		return ""
	}
	list := moduleInventory(c.Files)
	if len(list) == 0 {
		return ""
	}
	root := c.Res.RootPath
	var b strings.Builder
	b.WriteString("Per-module file inventory with declarations.\n\n")
	for _, m := range list {
		icon, _ := langspec.Default.ModuleNoun(m.plat)
		name := m.name
		if name == "" {
			name = "(root)"
		}
		badge := ""
		if m.ptype != "" {
			badge = " · " + m.ptype
		}
		fmt.Fprintf(&b, "#### %s %s%s\n\n%d files · %s lines · %d declarations\n\n", icon, name, badge, len(m.files), fmtNum(m.lines), m.decls)
		var parts []string
		for _, k := range kindOrder {
			if n := m.kinds[k]; n > 0 {
				parts = append(parts, kindLabel(k, n, string(m.plat)))
			}
		}
		if len(parts) > 0 {
			b.WriteString(strings.Join(parts, " · ") + "\n\n")
		}
		keep, gen := inventoryFiles(m.files)
		table := func(files []*parser.ParsedFile) {
			b.WriteString("| File | Lines | Tokens | Decl | Declarations |\n|------|------:|-------:|-----:|--------------|\n")
			for _, f := range files {
				decls := "—"
				if len(f.Declarations) > 0 {
					var ds []string
					for i, d := range f.Declarations {
						if i == 14 {
							ds = append(ds, fmt.Sprintf("+%d", len(f.Declarations)-14))
							break
						}
						ds = append(ds, kindIcon(d.Kind)+" "+d.Name)
					}
					decls = strings.Join(ds, ", ")
				}
				file := mdRel(root, f.FilePath)
				if f.Description != "" {
					d := f.Description
					if len(d) > 80 {
						d = d[:80] + "…"
					}
					file += " — 💡 " + d
				}
				fmt.Fprintf(&b, "| %s | %d | %s | %d | %s |\n", mdc(file), f.LineCount, fmtTokens(f.LineCount), len(f.Declarations), mdc(decls))
			}
			b.WriteString("\n")
		}
		if len(keep) > 0 {
			table(keep)
		}
		if len(gen) > 0 {
			b.WriteString("**Code Generated**\n\n")
			table(gen)
		}
	}
	return b.String()
}

// ── 🔗 Module Penetration (Markdown only) ────────────────────────────────────

func mdPenetration(c report.Ctx) string {
	files := c.Files
	allMods := map[string]bool{}
	for _, f := range files {
		m := f.ModuleName
		if m == "" {
			m = "root"
		}
		allMods[m] = true
	}
	if len(allMods) < 2 {
		return ""
	}
	importedBy := map[string]map[string]bool{}
	for _, f := range files {
		src := f.ModuleName
		if src == "" {
			src = "root"
		}
		impLow := strings.ToLower(strings.Join(f.Imports, "\n"))
		for target := range allMods {
			if target == src {
				continue
			}
			if strings.Contains(impLow, strings.ToLower(target)) {
				if importedBy[target] == nil {
					importedBy[target] = map[string]bool{}
				}
				importedBy[target][src] = true
			}
		}
	}
	type row struct {
		name  string
		count int
		deps  []string
	}
	var rows []row
	for mod, deps := range importedBy {
		if len(deps) == 0 {
			continue
		}
		var dl []string
		for d := range deps {
			dl = append(dl, d)
		}
		sort.Strings(dl)
		rows = append(rows, row{mod, len(deps), dl})
	}
	if len(rows) == 0 {
		return ""
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].count != rows[j].count {
			return rows[i].count > rows[j].count
		}
		return rows[i].name < rows[j].name
	})
	if len(rows) > 15 {
		rows = rows[:15]
	}
	var b strings.Builder
	b.WriteString("| Module | Used by | Dependents |\n|--------|--------:|------------|\n")
	for _, r := range rows {
		deps := strings.Join(r.deps, ", ")
		if len(deps) > 80 {
			deps = deps[:77] + "…"
		}
		fmt.Fprintf(&b, "| %s | %d | %s |\n", mdc(r.name), r.count, mdc(deps))
	}
	return b.String()
}
