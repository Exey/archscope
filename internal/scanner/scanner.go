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
	Platform  langspec.Platform
	Files     []FileEntry
	FileCount int
	Modules   []string // distinct module names in this platform, sorted
}

// ScanResult is the scanner's product.
type ScanResult struct {
	Root          string
	Files         []FileEntry
	Platforms     map[langspec.Platform]*PlatformGroup
	Modules       map[string][]FileEntry // moduleName -> files
	GitRepos      []string               // dirs containing .git
	ProjectTypes  []string               // distinct detected project types, sorted
	Technologies   []string               // tech detected from docker-compose/go.mod/Makefile
	DockerServices []string               // service names from docker-compose files
	DevOpsTools    []DevOpsTool           // CI/CD, container, orchestration tools
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

	res := &ScanResult{
		Root:      abs,
		Platforms: map[langspec.Platform]*PlatformGroup{},
		Modules:   map[string][]FileEntry{},
	}

	// ── Phase 1: discover module roots and git repos ──
	roots := discoverModuleRoots(abs, reg, excl)
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
				res.GitRepos = append(res.GitRepos, filepath.Dir(path))
				return filepath.SkipDir
			}
			if strings.HasPrefix(name, ".") || excl[name] {
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
		entry := FileEntry{
			Path:        path,
			LanguageID:  spec.ID,
			Platform:    spec.Platform,
			ModuleName:  mod,
			ProjectType: projType,
		}
		res.Files = append(res.Files, entry)
		res.Modules[mod] = append(res.Modules[mod], entry)

		g := res.Platforms[spec.Platform]
		if g == nil {
			g = &PlatformGroup{Platform: spec.Platform}
			res.Platforms[spec.Platform] = g
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
	sort.Strings(res.GitRepos)
	res.GitRepos = dedupeSorted(res.GitRepos)

	res.DockerServices, res.Technologies = ScanDockerCompose(abs)
	res.DevOpsTools = ScanDevOps(abs)

	return res, nil
}

// PlatformsOrdered returns the platform groups in canonical tab order.
func (r *ScanResult) PlatformsOrdered() []*PlatformGroup {
	var out []*PlatformGroup
	seen := map[langspec.Platform]bool{}
	for _, p := range langspec.PlatformOrder {
		if g := r.Platforms[p]; g != nil {
			out = append(out, g)
			seen[p] = true
		}
	}
	// any platforms not in canonical order, appended alphabetically
	var rest []langspec.Platform
	for p := range r.Platforms {
		if !seen[p] {
			rest = append(rest, p)
		}
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i] < rest[j] })
	for _, p := range rest {
		out = append(out, r.Platforms[p])
	}
	return out
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
