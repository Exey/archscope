// Package result also hosts the pipeline that produces an AnalysisResult.
// Run wires the stages together: scan → parse → dependency graph → git history
// → security (with blame enrichment) → per-platform report modules → assemble.
package result

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/exey/archscope/internal/config"
	"github.com/exey/archscope/internal/git"
	"github.com/exey/archscope/internal/graph"
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/scanner"
	"github.com/exey/archscope/internal/security"
)

// cachingLoader reads each file's lines once and memoizes them. It satisfies
// both parser.SourceLoader and security.LineLoader, so the parse phase, the
// security phase and blame all share a single read per file.
//
// Load is safe for concurrent use: the mutex guards the cache map so multiple
// goroutines (e.g. the security engine's worker pool) can call it in parallel.
type cachingLoader struct {
	mu    sync.Mutex
	base  parser.FileLoader
	cache map[string][]string
}

func newCachingLoader() *cachingLoader {
	return &cachingLoader{cache: map[string][]string{}}
}

func (l *cachingLoader) Load(path string) ([]string, error) {
	l.mu.Lock()
	if v, ok := l.cache[path]; ok {
		l.mu.Unlock()
		return v, nil
	}
	l.mu.Unlock()

	lines, err := l.base.Load(path)
	if err != nil {
		return nil, err
	}

	l.mu.Lock()
	l.cache[path] = lines
	l.mu.Unlock()
	return lines, nil
}

// Run executes the full analysis over an already-local root path and returns
// the assembled AnalysisResult. Remote URLs are resolved by the caller (cmd)
// before this point, so the pipeline only ever sees a directory on disk.
func Run(rootPath string, cfg config.Config) (*AnalysisResult, error) {
	return RunWithProgress(rootPath, cfg, nil)
}

// RunWithProgress is Run with an optional progress callback invoked at the start
// of each stage (and with running counts), so a CLI can report progress.
func RunWithProgress(rootPath string, cfg config.Config, progress func(string)) (*AnalysisResult, error) {
	step := func(msg string) {
		if progress != nil {
			progress(msg)
		}
	}
	reg := langspec.Default
	loader := newCachingLoader()

	// 1) Scan.
	step("Scanning source tree…")
	scan, err := scanner.Scan(rootPath, cfg, reg)
	if err != nil {
		return nil, err
	}
	step(fmt.Sprintf("Found %d files across %d platform(s), %d module(s)",
		len(scan.Files), len(scan.PlatformsOrdered()), len(scan.Modules)))

	// 2) Parse every owned file once (shared loader).
	step(fmt.Sprintf("Parsing %d files…", len(scan.Files)))
	p := &parser.Parser{Reg: reg, Loader: loader}
	var files []*parser.ParsedFile
	for _, fe := range scan.Files {
		pf, err := p.Parse(fe.Path, fe.ModuleName, fe.ProjectType)
		if err != nil || pf == nil {
			continue
		}
		// Override the parser's default platform with the scanner's tab key so
		// that folder-as-tab synthetic keys ("go:pharmen") propagate correctly.
		pf.Platform = string(fe.Platform)
		files = append(files, pf)
	}

	// 3) Dependency graph + hotspots.
	step("Building dependency graph…")
	g := graph.New()
	g.Build(files)
	g.Analyze()
	hotspots := g.GetTopHotspots(hotspotCount(cfg))

	// 4) Git history (repo-wide), degrading gracefully when absent.
	if len(scan.GitRepos) > 0 {
		step(fmt.Sprintf("Analyzing git history (%d repo(s))…", len(scan.GitRepos)))
	} else {
		step("No git repository — skipping history")
	}
	gitBundle := buildGitBundle(scan.GitRepos, cfg)

	// 5) Security + score.
	var results []security.RuleResult
	var score security.Score
	if cfg.Security.Enabled {
		step(fmt.Sprintf("Running %d security rules…", len(security.Default.Rules())))
		eng := security.Default
		eng.MaxFindingsPerRule = cfg.Security.MaxFindingsPerRule
		eng.MinSeverity = security.Severity(strings.ToUpper(cfg.Security.MinSeverity))
		eng.DisabledRules = toSet(cfg.Security.DisabledRules)

		srcs := make([]security.SourceFile, 0, len(files))
		for _, f := range files {
			srcs = append(srcs, security.SourceFile{Path: f.FilePath, LanguageID: f.LanguageID})
		}
		results, score = eng.RunWithScore(srcs, loader, rootPath)
		if scan.K8sLint != nil && len(scan.K8sLint.ClusterFindings) > 0 {
			// Fold K8s cross-cutting findings (NetworkPolicy gaps, RBAC
			// over-grants, secrets in manifests, ...) into the Danger Index so
			// infra misconfigurations count alongside source-level findings.
			// Kept out of `results`/AnalysisResult.Security itself — these are
			// synthetic, file-less entries and would confuse SARIF/markdown/the
			// findings list, which expect real per-file Findings.
			withK8s := append(append([]security.RuleResult{}, results...),
				k8sClusterFindingResults(scan.K8sLint.ClusterFindings)...)
			score = eng.ComputeScore(withK8s, len(files))
		}
		if gitBundle.Available {
			step("Attributing findings via git blame…")
			enrichWithBlame(results, scan.GitRepos, cfg)
		}
	}

	// 6) Report modules, run per platform tab.
	step("Running report modules…")
	panels := runModules(scan, files, step)

	projectName := cfg.ProjectName
	if projectName == "" {
		projectName = filepath.Base(rootPath)
	}

	// 7) Merge tech: docker/go.mod/Makefile hits + import-level hits.
	techSet := make(map[string]bool)
	for _, t := range scan.Technologies {
		techSet[t] = true
	}
	for _, f := range files {
		for _, imp := range f.Imports {
			scanner.DetectTechFromImport(imp, techSet)
		}
	}
	var technologies []string
	for t := range techSet {
		technologies = append(technologies, t)
	}
	sort.Strings(technologies)

	return &AnalysisResult{
		ProjectName:    projectName,
		RootPath:       rootPath,
		Files:          files,
		Scan:           scan,
		Graph:          g,
		Hotspots:       hotspots,
		Security:       results,
		SecurityScore:  score,
		Git:            gitBundle,
		ModulePanels:   panels,
		Technologies:   technologies,
		DockerServices: scan.DockerServices,
		DevOpsTools:    scan.DevOpsTools,
		DevOpsLint:     scan.DevOpsLint,
		K8sLint:        scan.K8sLint,
	}, nil
}

// runModules executes each registered report module against every platform tab
// whose files include a language the module applies to, rendering its panel.
func runModules(scan *scanner.ScanResult, files []*parser.ParsedFile, step func(string)) []ModulePanel {
	byPlatform := map[langspec.Platform][]*parser.ParsedFile{}
	for _, f := range files {
		byPlatform[langspec.Platform(f.Platform)] = append(byPlatform[langspec.Platform(f.Platform)], f)
	}
	var panels []ModulePanel
	for _, pg := range scan.PlatformsOrdered() {
		plat := pg.Platform
		pfs := byPlatform[plat]
		if len(pfs) == 0 {
			continue
		}
		langIDs := map[string]bool{}
		for _, f := range pfs {
			langIDs[f.LanguageID] = true
		}
		type analyzed struct {
			m       modules.ReportModule
			res     any
			elapsed time.Duration
		}
		var runs []analyzed
		for _, m := range modules.Default.All() {
			applies := false
			for id := range langIDs {
				if m.AppliesTo(id) {
					applies = true
					break
				}
			}
			if !applies {
				continue
			}
			t0 := time.Now()
			res := m.Analyze(pfs)
			runs = append(runs, analyzed{m, res, time.Since(t0)})
		}
		xfm := modules.NewTransformer()
		for _, a := range runs {
			xfm.Add(a.m, a.res)
		}
		rendered := xfm.HTMLPanels()
		renderedSet := map[string]bool{}
		for _, rp := range rendered {
			renderedSet[rp.ModuleID] = true
		}
		// Log in canonical order with ✓ (has content) or — (empty/no data).
		sort.Slice(runs, func(i, j int) bool {
			return modules.MetaFor(runs[i].m.ID()).Order < modules.MetaFor(runs[j].m.ID()).Order
		})
		for _, a := range runs {
			status := "—"
			if renderedSet[a.m.ID()] {
				status = "✓"
			}
			step(fmt.Sprintf("  [%s] %s (%dms) %s", plat, a.m.ID(), a.elapsed.Milliseconds(), status))
		}
		for _, rp := range rendered {
			panels = append(panels, ModulePanel{
				Platform:  plat,
				ModuleID:  rp.ModuleID,
				Title:     rp.Title,
				HTML:      rp.HTML,
				Cards:     rp.Cards,
				RawResult: rp.Result,
			})
		}
	}
	return panels
}

// buildGitBundle gathers the repo-wide git surface, or an empty (Available:false)
// bundle when git or history is absent.
func buildGitBundle(repos []string, cfg config.Config) GitBundle {
	if len(repos) == 0 {
		return GitBundle{}
	}
	anyAvailable := false
	for _, r := range repos {
		if git.Available(r) {
			anyAvailable = true
			break
		}
	}
	if !anyAvailable {
		return GitBundle{Repos: repos}
	}
	limit := cfg.GitCommitLimit
	if limit <= 0 {
		limit = 1000
	}
	return GitBundle{
		Available:    true,
		Authors:      git.GetAuthorStatsMultiRepo(repos, limit),
		Churn:        git.GetChurnStats(repos, limit, hotspotCount(cfg)),
		Tags:         git.GetTagStats(repos),
		Commits:      git.GetCommitMessageStats(repos, limit),
		Branch:       git.GetBranchStats(repos, 90),
		Repos:        repos,
		WeeklyByExt:  git.GetWeeklyActivity(repos),
		WeeklyByRepo: git.GetWeeklyActivityPerRepo(repos),
		RemoteURL:    git.GetRemoteURL(repos),
	}
}

// enrichWithBlame fills Finding.Author by running git blame for the exact lines
// that produced findings, grouped per file and per enclosing repository.
func enrichWithBlame(results []security.RuleResult, repos []string, cfg config.Config) {
	if len(repos) == 0 {
		return
	}
	// Collect finding line numbers per file path.
	wantByFile := map[string]map[int]bool{}
	for i := range results {
		for _, f := range results[i].Findings {
			if f.FullPath == "" || f.Line <= 0 {
				continue
			}
			if wantByFile[f.FullPath] == nil {
				wantByFile[f.FullPath] = map[int]bool{}
			}
			wantByFile[f.FullPath][f.Line] = true
		}
	}
	if len(wantByFile) == 0 {
		return
	}
	limit := cfg.GitCommitLimit
	if limit <= 0 {
		limit = 1000
	}
	// Resolve author per (file,line).
	authorByFileLine := map[string]map[int]string{}
	for path, want := range wantByFile {
		repo := enclosingRepo(path, repos)
		if repo == "" || !git.Available(repo) {
			continue
		}
		a := git.NewAnalyzer(repo, limit)
		if got := a.BlameLinesSubset(path, want); len(got) > 0 {
			authorByFileLine[path] = got
		}
	}
	if len(authorByFileLine) == 0 {
		return
	}
	for i := range results {
		for j := range results[i].Findings {
			f := &results[i].Findings[j]
			if m := authorByFileLine[f.FullPath]; m != nil {
				if author, ok := m[f.Line]; ok {
					f.Author = author
				}
			}
		}
	}
}

// enclosingRepo returns the longest repo path that contains file.
func enclosingRepo(file string, repos []string) string {
	best := ""
	for _, r := range repos {
		if r == file || strings.HasPrefix(file, ensureSep(r)) {
			if len(r) > len(best) {
				best = r
			}
		}
	}
	return best
}

func ensureSep(dir string) string {
	if strings.HasSuffix(dir, string(filepath.Separator)) {
		return dir
	}
	return dir + string(filepath.Separator)
}

func hotspotCount(cfg config.Config) int {
	if cfg.HotspotCount > 0 {
		return cfg.HotspotCount
	}
	return 15
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// k8sClusterFindingResults converts K8s cross-cutting findings into synthetic
// security.RuleResult entries (grouped by RuleID) so they flow through
// Engine.ComputeScore the same way per-file language findings do. The
// resulting entries carry no Findings (they're namespace/cluster-scoped, not
// file:line) — only Rule metadata and TotalCount, which is all ComputeScore
// (and the HTML "Security Rules" CWE grid) needs.
func k8sClusterFindingResults(findings []scanner.K8sClusterFinding) []security.RuleResult {
	byRule := map[string]*security.RuleResult{}
	var order []string
	for _, f := range findings {
		if f.CWE == "" {
			continue
		}
		rr, ok := byRule[f.RuleID]
		if !ok {
			rr = &security.RuleResult{Rule: security.Rule{
				ID:        f.RuleID,
				Name:      f.Title,
				Category:  k8sFindingCategory(f.CWE),
				Severity:  k8sFindingSeverity(f.Severity),
				CWE:       f.CWE,
				Languages: []string{"k8s"},
			}}
			byRule[f.RuleID] = rr
			order = append(order, f.RuleID)
		}
		rr.TotalCount++
	}
	out := make([]security.RuleResult, 0, len(order))
	for _, id := range order {
		out = append(out, *byRule[id])
	}
	return out
}

// k8sFindingSeverity maps a K8sClusterFinding's lowercase severity string
// onto the security engine's three-level scale; "critical" folds into HIGH
// since Severity has no separate critical tier.
func k8sFindingSeverity(s string) security.Severity {
	switch s {
	case "critical", "high":
		return security.SevHigh
	case "medium":
		return security.SevMedium
	default:
		return security.SevLow
	}
}

// k8sFindingCategory maps a K8s cross-cutting finding's CWE onto one of the
// 14 Danger Index categories, reusing the same CWE→category convention the
// language rule packages already use for shared CWEs (e.g. 798 and 319).
func k8sFindingCategory(cwe string) string {
	switch cwe {
	case "284", "269", "306": // access control / privilege management / missing auth
		return "authentication"
	case "749": // exposed dangerous method (matches kotlin.add_javascript_interface)
		return "io_validation"
	case "312", "798": // cleartext/hardcoded secret storage (matches rust.hardcoded_credential)
		return "insecure_data_storage"
	case "319": // cleartext transmission (matches javascript.insecure_transport)
		return "network_security"
	default:
		return "platform_config"
	}
}
