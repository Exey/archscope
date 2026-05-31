package scanner

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/exey/archscope/internal/langspec"
)

// maxRootDepth bounds how deep below the repo root we look for module markers,
// matching goscope's 3-level service discovery.
const maxRootDepth = 3

// discoverModuleRoots finds directories that hold a module for some language,
// identified by that language's ModuleDetection.MarkerFiles (and ProjectTypes).
// It searches up to maxRootDepth levels below rootPath. Deeper, more specific
// roots are kept so attributeModule can pick the nearest one.
func discoverModuleRoots(rootPath string, reg *langspec.Registry, excl map[string]bool) []moduleRoot {
	// Build marker -> (languageID) and marker -> projectType indexes once.
	type markerInfo struct {
		languageID  string
		glob        bool // marker begins with "*." (e.g. *.xcodeproj)
		projectType string
	}
	markers := map[string]markerInfo{} // exact filename -> info
	globMarkers := []struct {          // suffix-glob markers (*.csproj)
		suffix      string
		languageID  string
		projectType string
	}{}

	for _, spec := range reg.All() {
		// project-type markers give us a label
		ptByMarker := map[string]string{}
		for _, pt := range spec.ProjectTypes {
			for _, mf := range pt.MarkerFiles {
				ptByMarker[mf] = pt.Name
			}
		}
		add := func(mf string) {
			if strings.HasPrefix(mf, "*.") {
				globMarkers = append(globMarkers, struct {
					suffix      string
					languageID  string
					projectType string
				}{strings.TrimPrefix(mf, "*"), spec.ID, ptByMarker[mf]})
				return
			}
			// don't overwrite a more specific earlier mapping
			if _, ok := markers[mf]; !ok {
				markers[mf] = markerInfo{languageID: spec.ID, projectType: ptByMarker[mf]}
			}
		}
		for _, mf := range spec.Modules.MarkerFiles {
			add(mf)
		}
		for _, pt := range spec.ProjectTypes {
			for _, mf := range pt.MarkerFiles {
				add(mf)
			}
		}
	}

	var roots []moduleRoot
	seen := map[string]bool{}

	var visit func(dir string, depth int)
	visit = func(dir string, depth int) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		// check this dir for any marker
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			fn := e.Name()
			if mi, ok := markers[fn]; ok && !seen[dir] {
				roots = append(roots, moduleRoot{
					dir:         dir,
					name:        filepath.Base(dir),
					languageID:  mi.languageID,
					projectType: mi.projectType,
				})
				seen[dir] = true
			}
			for _, gm := range globMarkers {
				if strings.HasSuffix(fn, gm.suffix) && !seen[dir] {
					roots = append(roots, moduleRoot{
						dir:         dir,
						name:        filepath.Base(dir),
						languageID:  gm.languageID,
						projectType: gm.projectType,
					})
					seen[dir] = true
				}
			}
		}
		if depth >= maxRootDepth {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if name == ".git" || strings.HasPrefix(name, ".") || excl[name] {
				continue
			}
			visit(filepath.Join(dir, name), depth+1)
		}
	}
	visit(rootPath, 0)
	return roots
}

// attributeModule assigns a file to the nearest enclosing module root. If none
// applies, it derives a module name from the path using the owning language's
// ModuleNameFromPath hook, then container-dir heuristics, then the first path
// segment (or "root").
func attributeModule(rootPath, filePath string, spec *langspec.LanguageSpec, roots []moduleRoot) (module, projectType string) {
	// nearest (deepest) module root whose dir is a prefix of filePath
	best := ""
	var bestRoot *moduleRoot
	for i := range roots {
		r := &roots[i]
		prefix := r.dir + string(filepath.Separator)
		if strings.HasPrefix(filePath, prefix) {
			if len(r.dir) > len(best) {
				best = r.dir
				bestRoot = r
			}
		}
	}
	if bestRoot != nil {
		return bestRoot.name, bestRoot.projectType
	}

	// language-supplied derivation
	if spec.Modules.ModuleNameFromPath != nil {
		if n := spec.Modules.ModuleNameFromPath(rootPath, filePath); n != "" {
			return n, ""
		}
	}

	rel, err := filepath.Rel(rootPath, filePath)
	if err != nil {
		return "root", ""
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) < 2 {
		return "root", ""
	}

	// container-dir heuristic: name is the segment AFTER a known container dir
	containers := map[string]bool{}
	for _, c := range spec.Modules.ContainerDirs {
		containers[strings.ToLower(c)] = true
	}
	for i, p := range parts {
		if containers[strings.ToLower(p)] && i+1 < len(parts) {
			return parts[i+1], ""
		}
	}
	return parts[0], ""
}
