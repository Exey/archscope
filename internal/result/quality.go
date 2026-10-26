package result

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/evolution"
	"github.com/exey/archscope/internal/modules/constructs"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/security"
)

const (
	qualityComplexLines = 50 // a new function this long counts as complex, whatever its branching
	qualityMaxRead      = 1 << 20
)

var reIdent = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// attachQuality measures the code the merge request adds: how many new
// functions carry a doc comment, how many a test file refers to, and which
// complex new ones lack documentation. The latter also become review items on
// their file (HIGHer weight than style nits: "every complex method gets a doc").
func attachQuality(res *AnalysisResult, repo string, rv *evolution.Review) {
	head := rv.HeadSHA
	if rv.Subject == "" {
		head = ""
	}
	read := func(repoPath string) []string {
		var src string
		if head != "" {
			src, _ = evolution.FileAt(repo, head, repoPath)
		} else if b, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(repoPath))); err == nil {
			src = string(b)
		}
		return strings.Split(src, "\n")
	}

	// complex functions by file, from Code Structure (cyclomatic > 10) and the big-function list.
	type cx struct {
		name  string
		line  int
		cc    int
		lines int
	}
	complexByFile := map[string][]cx{}
	for _, p := range res.ModulePanels {
		if r, ok := p.RawResult.(constructs.CodeStructureReport); ok {
			for _, o := range r.HighComplexity {
				k := filepath.Clean(o.FilePath)
				complexByFile[k] = append(complexByFile[k], cx{name: o.Symbol, line: o.Line, cc: o.Value})
			}
		}
	}
	parsed := map[string]*parser.ParsedFile{}
	for _, f := range res.Files {
		parsed[filepath.Clean(f.FilePath)] = f
		for _, fn := range f.BigFunctions {
			if fn.LineCount >= qualityComplexLines {
				complexByFile[filepath.Clean(f.FilePath)] = append(complexByFile[filepath.Clean(f.FilePath)], cx{name: fn.Name, line: fn.StartLine, lines: fn.LineCount})
			}
		}
	}

	// every identifier a test file mentions: a new function is "referenced" when its name is among them
	testIdents := map[string]bool{}
	addTest := func(text string) {
		for _, id := range reIdent.FindAllString(text, -1) {
			testIdents[id] = true
		}
	}
	for _, f := range res.Files {
		if security.IsTestOrBenchPath(f.FilePath) {
			if b, err := os.ReadFile(f.FilePath); err == nil && len(b) < qualityMaxRead {
				addTest(string(b))
			}
		}
	}

	q := &evolution.Quality{}
	seenCx := map[string]bool{}
	for i := range rv.Files {
		f := &rv.Files[i]
		if f.Binary {
			continue
		}
		abs := filepath.Clean(filepath.Join(repo, filepath.FromSlash(f.Path)))
		isTest := security.IsTestOrBenchPath(f.Path)
		pf := parsed[abs]
		if isTest {
			q.AddedTest += f.Add
			if head != "" {
				addTest(strings.Join(read(f.Path), "\n"))
			}
			continue
		}
		if pf == nil {
			continue // not a source file ArchScope reads
		}
		q.AddedSrc += f.Add
		added := evolution.AddedLines(repo, rv.BaseSHA, head, f.Path)
		if len(added) == 0 {
			continue
		}
		lines := read(f.Path)
		for _, d := range pf.Declarations {
			if d.Kind == parser.DeclFunc && added[d.Line] && measurableFunc(d.Name) {
				q.Funcs++
				if hasDocComment(lines, d.Line, pf.LanguageID) {
					q.Documented++
				}
				if testIdents[d.Name] {
					q.Tested++
				}
			}
		}
		oldPos := evolution.NewToOld(repo, rv.BaseSHA, head, f.Path)
		rel := f.Path
		if r, err := filepath.Rel(res.RootPath, abs); err == nil && !strings.HasPrefix(r, "..") {
			rel = filepath.ToSlash(r)
		}
		for _, c := range complexByFile[abs] {
			key := fmt.Sprintf("%s:%d", abs, c.line)
			if !added[c.line] || seenCx[key] {
				continue
			}
			seenCx[key] = true
			q.Complex++
			if hasDocComment(lines, c.line, pf.LanguageID) {
				q.ComplexDocumented++
				continue
			}
			why := fmt.Sprintf("%d lines", c.lines)
			if c.cc > 0 {
				why = fmt.Sprintf("complexity %d", c.cc)
			}
			pos := -1
			if p, ok := oldPos[c.line]; ok {
				pos = p
			}
			it := evolution.Item{Dim: 2, Kind: "Complex function without doc", Name: c.name, Note: why + " · add a doc comment explaining what and why",
				Rel: rel, Path: abs, Line: c.line, Weight: 2, RepoPath: f.Path, OldPos: pos, Key: "nodoc|" + key}
			q.Undocumented = append(q.Undocumented, it)
			f.Issues = append(f.Issues, it)
		}
	}
	if !q.Empty() {
		rv.Quality = q
	}
}

// measurableFunc skips names that say nothing about documentation or tests.
func measurableFunc(name string) bool {
	switch name {
	case "main", "init", "__init__", "constructor", "":
		return false
	}
	return len(name) > 2
}

// hasDocComment reports whether the function starting at line (1-based) has a
// doc comment directly above it (decorators and attributes in between are
// skipped), or — for Python — a docstring as its first statement.
func hasDocComment(lines []string, line int, lang string) bool {
	for i := line - 2; i >= 0 && i < len(lines); i-- {
		t := strings.TrimSpace(lines[i])
		switch {
		case t == "":
			return false
		case strings.HasPrefix(t, "@"), strings.HasPrefix(t, "#["), strings.HasPrefix(t, "#["):
			continue
		case strings.HasPrefix(t, "//"), strings.HasPrefix(t, "/*"), strings.HasPrefix(t, "*"), strings.HasSuffix(t, "*/"),
			strings.HasPrefix(t, "--"), strings.HasPrefix(t, "///"):
			return true
		case strings.HasPrefix(t, "#") && lang != "python":
			return strings.HasPrefix(t, "# ") || lang == "ruby"
		case strings.HasPrefix(t, "#"):
			return true
		}
		break
	}
	if lang == "python" {
		i := line - 1
		for ; i < len(lines) && i < line+8 && !strings.HasSuffix(strings.TrimSpace(lines[i]), ":"); i++ {
		}
		for i++; i < len(lines) && i < line+12; i++ {
			if t := strings.TrimSpace(lines[i]); t != "" {
				return strings.HasPrefix(t, `"""`) || strings.HasPrefix(t, `'''`) || strings.HasPrefix(t, `r"""`)
			}
		}
	}
	return false
}
