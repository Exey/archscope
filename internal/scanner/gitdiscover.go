package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DiscoverGitRepos walks rootPath looking for ".git" directories, returning
// the deduplicated, sorted list of directories that contain one — one entry
// per git repository found in the tree. It mirrors the .git discovery Scan()
// does internally (Phase 1), exposed standalone so callers (the CLI) can
// decide how to group platform tabs *before* running a full Scan, since that
// decision has to be baked into the config Scan is called with.
func DiscoverGitRepos(rootPath string, excludePaths []string) []string {
	excl := make(map[string]bool, len(excludePaths))
	for _, p := range excludePaths {
		excl[p] = true
	}
	var repos []string
	_ = filepath.WalkDir(rootPath, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		name := d.Name()
		if name == ".git" {
			repos = append(repos, filepath.Dir(path))
			return filepath.SkipDir
		}
		if strings.HasPrefix(name, ".") || excl[name] || skipDirs[name] {
			return filepath.SkipDir
		}
		return nil
	})
	sort.Strings(repos)
	return dedupeSorted(repos)
}

// NearestGitRepo returns whichever entry in gitRepos (absolute directory
// paths) most closely contains filePath — the deepest matching ancestor —
// or "" when filePath isn't inside any of them. Used by gitrepo-as-tab
// grouping to attribute a file to its containing repository.
func NearestGitRepo(gitRepos []string, filePath string) string {
	best := ""
	for _, repo := range gitRepos {
		if repo == filePath {
			continue // a repo root itself isn't "inside" the repo for this purpose
		}
		if !strings.HasPrefix(filePath, repo+string(filepath.Separator)) {
			continue
		}
		if len(repo) > len(best) {
			best = repo
		}
	}
	return best
}
