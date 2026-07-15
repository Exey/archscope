// Package scanner walks a repository tree, decides which files each registered
// language owns, groups files into modules and into report-tab platform
// buckets, and locates git repositories and project types.
package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/exey/archscope/internal/config"
	"github.com/exey/archscope/internal/langspec"
)

// FileEntry is one source file the scanner decided to analyze.
type FileEntry struct {
	Path        string            // absolute path
	LanguageID  string            // owning LanguageSpec.ID
	Platform    langspec.Platform // report-tab bucket
	ModuleName  string            // package / module / microservice
	ProjectType string            // "Go module", "SwiftPM", ... ("" if unknown)
}

// PlatformGroup buckets files for one report tab.
type PlatformGroup struct {
	Platform         langspec.Platform // unique tab key (may be synthetic in folder-as-tab mode)
	LanguagePlatform langspec.Platform // actual language platform, for module routing
	Label            string            // display label, e.g. "pharmen Py" (empty → PlatformTitle)
	Files            []FileEntry
	FileCount        int
	Modules          []string // distinct module names in this platform, sorted
}

// TabLabel returns the display string for the HTML tab button.
func (pg *PlatformGroup) TabLabel() string {
	if pg.Label != "" {
		return pg.Label
	}
	p := pg.LanguagePlatform
	if p == "" {
		p = pg.Platform
	}
	return langspec.PlatformTitle(p)
}

// ScanResult is the scanner's product.
type ScanResult struct {
	Root           string
	Files          []FileEntry
	Platforms      map[langspec.Platform]*PlatformGroup
	Modules        map[string][]FileEntry // moduleName -> files
	GitRepos       []string               // dirs containing .git
	ProjectTypes   []string               // distinct detected project types, sorted
	Technologies   []string               // tech detected from docker-compose/go.mod/Makefile
	DockerServices []string               // service names from docker-compose files
	DevOpsTools    []DevOpsTool           // CI/CD, container, orchestration tools
	DevOpsLint     *DevOpsLint            // static analysis of Dockerfiles / compose / Helm (nil when none found)
	K8sLint        *K8sLint               // static analysis of Kubernetes manifests/cluster dumps (nil when none found)
	FolderAsTab    bool                   // true when --folder-as-tab was used
	RenderModules  bool                   // true when --render-modules was used
}

// moduleRoot records a detected module-root directory and the language/project
// type that claimed it, so files beneath it can be attributed.
type moduleRoot struct {
	dir         string
	name        string
	languageID  string
	projectType string
}

// Scan walks rootPath and produces a ScanResult. It consults the registry to
// decide file ownership and module detection, skips cfg.ExcludePaths and dotted
// dirs, and respects cfg.MaxFilesAnalyze. Files no language owns are ignored.
func Scan(rootPath string, cfg config.Config, reg *langspec.Registry) (*ScanResult, error) {
	abs, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, &os.PathError{Op: "scan", Path: abs, Err: os.ErrInvalid}
	}

	excl := make(map[string]bool, len(cfg.ExcludePaths))
	for _, p := range cfg.ExcludePaths {
		excl[p] = true
	}
	enabled := enabledSet(cfg, reg)

	// Git submodules are vendored, externally-owned code — skip them (like
	// .git itself) unless the caller explicitly asked to scan everything.
	submodules := map[string]bool{}
	if !cfg.ScanAllFiles {
		for _, p := range ParseGitSubmodules(abs) {
			submodules[filepath.Join(abs, p)] = true
		}
	}

	res := &ScanResult{
		Root:      abs,
		Platforms: map[langspec.Platform]*PlatformGroup{},
		Modules:   map[string][]FileEntry{},
	}

	// ── Phase 1: discover module roots and git repos ──
	roots := discoverModuleRoots(abs, reg, excl, submodules)
	res.GitRepos = DiscoverGitRepos(abs, cfg.ExcludePaths)
	projTypeSet := map[string]bool{}
	for _, r := range roots {
		if r.projectType != "" {
			projTypeSet[r.projectType] = true
		}
	}

	// ── Phase 2: walk files, attribute each to a module + platform ──
	count := 0
	walkErr := filepath.WalkDir(abs, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if name == ".git" {
				return filepath.SkipDir
			}
			if strings.HasPrefix(name, ".") || excl[name] || skipDirs[name] || submodules[path] {
				return filepath.SkipDir
			}
			return nil
		}
		if cfg.MaxFilesAnalyze > 0 && count >= cfg.MaxFilesAnalyze {
			return filepath.SkipDir
		}

		ext := strings.ToLower(filepath.Ext(name))
		spec := reg.Lookup(ext)
		if spec == nil || !enabled[spec.ID] {
			return nil
		}

		mod, projType := attributeModule(abs, path, spec, roots)

		// In gitrepo-as-tab mode each (language, containing repo) pair becomes
		// its own tab; in folder-as-tab mode each (language, top-level folder)
		// pair does; otherwise all files of a language share one tab.
		tabPlatform := spec.Platform
		tabLabel := ""
		switch {
		case cfg.GitRepoAsTab:
			if repo := NearestGitRepo(res.GitRepos, path); repo != "" {
				if label := filepath.ToSlash(relOrBase(abs, repo)); label != "" {
					tabPlatform = langspec.Platform(string(spec.Platform) + ":" + label)
					tabLabel = label
				}
			}
		case cfg.FolderAsTab:
			if folder := topFolder(abs, path); folder != "" {
				tabPlatform = langspec.Platform(string(spec.Platform) + ":" + folder)
				tabLabel = folder
			}
		}

		entry := FileEntry{
			Path:        path,
			LanguageID:  spec.ID,
			Platform:    tabPlatform,
			ModuleName:  mod,
			ProjectType: projType,
		}
		res.Files = append(res.Files, entry)
		res.Modules[mod] = append(res.Modules[mod], entry)

		g := res.Platforms[tabPlatform]
		if g == nil {
			g = &PlatformGroup{
				Platform:         tabPlatform,
				LanguagePlatform: spec.Platform,
				Label:            tabLabel,
			}
			res.Platforms[tabPlatform] = g
		}
		g.Files = append(g.Files, entry)

		count++
		return nil
	})
	if walkErr != nil {
		return res, walkErr
	}

	// ── Phase 3: finalize derived fields ──
	for _, g := range res.Platforms {
		g.FileCount = len(g.Files)
		seen := map[string]bool{}
		for _, f := range g.Files {
			if !seen[f.ModuleName] {
				seen[f.ModuleName] = true
				g.Modules = append(g.Modules, f.ModuleName)
			}
		}
		sort.Strings(g.Modules)
	}
	for t := range projTypeSet {
		res.ProjectTypes = append(res.ProjectTypes, t)
	}
	sort.Strings(res.ProjectTypes)

	res.DockerServices, res.Technologies = ScanDockerCompose(abs)
	res.DevOpsTools = ScanDevOps(abs)
	res.DevOpsLint = ScanDevOpsLint(abs)
	res.K8sLint = ScanK8sLint(abs)
	// Gitrepo-as-tab produces the same "platform:label" synthetic keys
	// folder-as-tab does (just keyed by containing repo instead of top-level
	// folder), so every report-layer check gated on FolderAsTab still applies.
	res.FolderAsTab = cfg.FolderAsTab || cfg.GitRepoAsTab
	res.RenderModules = cfg.RenderModules

	return res, nil
}

// PlatformsOrdered returns the platform groups in canonical tab order.
// In folder-as-tab mode groups are sorted by language order first, then
// alphabetically by label within each language.
func (r *ScanResult) PlatformsOrdered() []*PlatformGroup {
	var out []*PlatformGroup
	seen := map[langspec.Platform]bool{}

	// For each canonical language, collect all tab groups whose effective
	// language matches (handles both plain and synthetic platform keys).
	for _, langP := range langspec.PlatformOrder {
		var groups []*PlatformGroup
		for key, g := range r.Platforms {
			if seen[key] {
				continue
			}
			effLang := g.LanguagePlatform
			if effLang == "" {
				effLang = g.Platform
			}
			if effLang == langP {
				groups = append(groups, g)
				seen[key] = true
			}
		}
		sort.Slice(groups, func(i, j int) bool {
			return groups[i].TabLabel() < groups[j].TabLabel()
		})
		out = append(out, groups...)
	}

	// Remaining platforms not in canonical order, alphabetically.
	var rest []*PlatformGroup
	for key, g := range r.Platforms {
		if !seen[key] {
			rest = append(rest, g)
		}
	}
	sort.Slice(rest, func(i, j int) bool {
		return rest[i].TabLabel() < rest[j].TabLabel()
	})
	return append(out, rest...)
}

// topFolder returns the first path component of filePath relative to rootPath,
// or "" if the file sits directly in rootPath.
func topFolder(rootPath, filePath string) string {
	rel, err := filepath.Rel(rootPath, filePath)
	if err != nil {
		return ""
	}
	rel = filepath.ToSlash(rel)
	if i := strings.IndexByte(rel, '/'); i > 0 {
		return rel[:i]
	}
	return ""
}

// relOrBase returns repo's path relative to rootPath, for use as a gitrepo-
// as-tab label — or repo's base name when repo IS rootPath (a single
// top-level repo) or the relative path can't be computed.
func relOrBase(rootPath, repo string) string {
	if repo == rootPath {
		return filepath.Base(repo)
	}
	rel, err := filepath.Rel(rootPath, repo)
	if err != nil || rel == "." || rel == "" {
		return filepath.Base(repo)
	}
	return rel
}

// platformShortLabel returns the abbreviated language name used in folder-as-tab
// tab labels: "pharmen Py", "gptzakaz TS", etc.
func platformShortLabel(p langspec.Platform) string {
	switch p {
	case langspec.PlatformPython:
		return "Py"
	case langspec.PlatformTSJS:
		return "TS"
	case langspec.PlatformKotlin:
		return "Kt"
	case langspec.PlatformSwiftObjC:
		return "Swift"
	case langspec.PlatformGo:
		return "Go"
	case langspec.PlatformRust:
		return "Rust"
	default:
		return string(p)
	}
}

func enabledSet(cfg config.Config, reg *langspec.Registry) map[string]bool {
	disabled := map[string]bool{}
	for _, id := range cfg.Languages.Disabled {
		disabled[id] = true
	}
	enabled := map[string]bool{}
	if len(cfg.Languages.Enabled) > 0 {
		for _, id := range cfg.Languages.Enabled {
			if !disabled[id] {
				enabled[id] = true
			}
		}
		return enabled
	}
	// empty Enabled = all registered (minus disabled)
	for _, s := range reg.All() {
		if !disabled[s.ID] {
			enabled[s.ID] = true
		}
	}
	return enabled
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
