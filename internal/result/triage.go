package result

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/exey/archscope/internal/evolution"
)

var triageSourceExt = map[string]bool{".go": true, ".py": true, ".kt": true, ".java": true, ".swift": true, ".ts": true, ".tsx": true,
	".js": true, ".jsx": true, ".rs": true, ".rb": true, ".cs": true, ".php": true, ".scala": true}

// attachTriage fills rv.Triage: the files to read first (from the review items
// already attached to each file) and flags for production changes without test
// changes, new dependencies and risky migrations. Call it after every other
// attach*, so the ranking sees all the issues.
func attachTriage(res *AnalysisResult, repo string, rv *evolution.Review) {
	head := rv.HeadSHA
	if rv.Subject == "" {
		head = ""
	}
	t := &evolution.Triage{ReadFirst: evolution.RankFiles(rv.Files)}

	parsed := map[string]bool{}
	for _, f := range res.Files {
		parsed[filepath.Clean(f.FilePath)] = true
	}
	isSource := func(p string) bool {
		return parsed[filepath.Clean(filepath.Join(repo, filepath.FromSlash(p)))] || triageSourceExt[strings.ToLower(filepath.Ext(p))]
	}
	flag := func(f evolution.ReviewFile, line int, title, note string) {
		abs := filepath.Join(repo, filepath.FromSlash(f.Path))
		rel := f.Path
		if r, err := filepath.Rel(res.RootPath, abs); err == nil && !strings.HasPrefix(r, "..") {
			rel = filepath.ToSlash(r)
		}
		if line <= 0 {
			line = 1
		}
		pos := -1
		if p, ok := evolution.NewToOld(repo, rv.BaseSHA, head, f.Path)[line]; ok {
			pos = p
		}
		t.Flags = append(t.Flags, evolution.Item{Kind: "Review flag", Name: title, Note: note, Rel: rel, Path: abs, Line: line,
			RepoPath: f.Path, OldPos: pos, Key: fmt.Sprintf("flag|%s|%s|%d", title, f.Path, line)})
	}

	// production code changed, tests did not
	if un := evolution.UntestedChanges(rv.Files, isSource); len(un) > 0 {
		sort.SliceStable(un, func(i, j int) bool { return un[i].Add > un[j].Add })
		for i, f := range un {
			if i == 8 {
				break
			}
			flag(f, 1, "No test change", fmt.Sprintf("+%d lines of production code, and no test file next to it changed", f.Add))
		}
	}

	for _, f := range rv.Files {
		if f.Binary {
			continue
		}
		kind := evolution.DependencyManifest(f.Path)
		mig := evolution.IsMigrationPath(f.Path)
		if kind == "" && !mig {
			continue
		}
		added := addedText(repo, rv, head, f.Path)
		if kind != "" {
			base, _ := evolution.FileAt(repo, rv.BaseSHA, f.Path)
			if names, line := evolution.NewDependencies(kind, added, base); len(names) > 0 {
				flag(f, line, "New dependency", strings.Join(names, ", ")+" — check its licence, maintenance and size")
			}
		}
		if mig {
			for _, r := range evolution.RiskyMigrationLines(added) {
				flag(f, r.Line, "Risky migration", r.What)
			}
		}
	}
	if !t.Empty() {
		rv.Triage = t
	}
}

// addedText maps each new-side line the change adds to path to its text.
func addedText(repo string, rv *evolution.Review, head, p string) map[int]string {
	var src string
	if head != "" {
		src, _ = evolution.FileAt(repo, head, p)
	} else if b, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(p))); err == nil {
		src = string(b)
	}
	lines := strings.Split(src, "\n")
	out := map[int]string{}
	for n := range evolution.AddedLines(repo, rv.BaseSHA, head, p) {
		if n >= 1 && n <= len(lines) {
			out[n] = lines[n-1]
		}
	}
	return out
}
