package result

import (
	"path/filepath"
	"strings"

	"github.com/exey/archscope/internal/git"
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/scanner"
)

// PlatformGit is the slice of the repository's history that belongs to one
// platform: the churn of its files and the people who changed them. Both the
// HTML card and the Markdown export draw from it, so they cannot disagree.
type PlatformGit struct {
	Churn   []git.FileChurnStat
	Authors map[string]*git.AuthorStats
}

// PlatformGit filters the repo-wide history down to one platform's files.
func (r *AnalysisResult) PlatformGit(pg *scanner.PlatformGroup, files []*parser.ParsedFile) PlatformGit {
	res := r
	g := res.Git
	// Each sub-project may have its own .git root. git log --name-only outputs
	// paths relative to that repo root, not to res.RootPath. Find the deepest
	// matching repo root for each file so the relative paths align with RelPath
	// in the churn stats.
	repoRoot := func(fp string) string {
		best := res.RootPath
		for _, repo := range g.Repos {
			if len(repo) > len(best) &&
				(strings.HasPrefix(fp, repo+string(filepath.Separator)) || fp == repo) {
				best = repo
			}
		}
		return best
	}

	platRel := map[string]bool{}
	for _, f := range files {
		root := repoRoot(f.FilePath)
		if r, err := filepath.Rel(root, f.FilePath); err == nil {
			platRel[r] = true
		}
	}

	// Filter churn to this platform's files; fall back to language-extension
	// match when path matching yields nothing (single .git + small topN).
	var platChurn []git.FileChurnStat
	for _, c := range g.Churn {
		if platRel[c.RelPath] {
			platChurn = append(platChurn, c)
		}
	}
	if len(platChurn) == 0 {
		exts := platformLangExts(pg.LanguagePlatform)
		for _, c := range g.Churn {
			if exts[strings.ToLower(filepath.Ext(c.RelPath))] {
				platChurn = append(platChurn, c)
			}
		}
	}

	// Contributors: derive from platform churn (language-accurate).
	// Fall back to module-name matching (works for per-folder git repos).
	platAuthors := map[string]*git.AuthorStats{}
	for _, c := range platChurn {
		for _, authorName := range c.TopAuthors {
			if a, ok := g.Authors[authorName]; ok {
				platAuthors[authorName] = a
			}
		}
	}
	if len(platAuthors) == 0 {
		platMods := map[string]bool{}
		for _, m := range pg.Modules {
			platMods[m] = true
			if m == "" {
				platMods["root"] = true
			}
		}
		for name, a := range g.Authors {
			for mod := range a.MicroserviceCounts {
				if platMods[mod] {
					platAuthors[name] = a
					break
				}
			}
		}
	}

	return PlatformGit{Churn: platChurn, Authors: platAuthors}
}

func platformLangExts(lp langspec.Platform) map[string]bool {
	table := map[langspec.Platform][]string{
		"go":         {".go"},
		"python":     {".py"},
		"ts_js":      {".ts", ".tsx", ".js", ".jsx"},
		"swift_objc": {".swift", ".m", ".mm"},
		"kotlin":     {".kt", ".kts"},
		"java":       {".java"},
		"ruby":       {".rb"},
		"rust":       {".rs"},
		"csharp":     {".cs"},
		"cpp":        {".cpp", ".cc", ".cxx", ".hpp", ".h"},
	}
	exts, ok := table[lp]
	if !ok {
		return nil
	}
	m := make(map[string]bool, len(exts))
	for _, e := range exts {
		m[e] = true
	}
	return m
}
