package result

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
		docs := constructs.NewDocIndex(f.Path, read(f.Path))
		lengths := constructs.FuncLengths(f.Path, read(f.Path))
		oldPos := evolution.NewToOld(repo, rv.BaseSHA, head, f.Path)
		rel := f.Path
		if r, err := filepath.Rel(res.RootPath, abs); err == nil && !strings.HasPrefix(r, "..") {
			rel = filepath.ToSlash(r)
		}
		for _, d := range pf.Declarations {
			if d.Kind == parser.DeclFunc && added[d.Line] && measurableFunc(d.Name) {
				q.Funcs++
				if docs.Has(d.Line) {
					q.Documented++
				}
				if isSQLFunc(read(f.Path), d.Line, lengths[d.Line]) {
					continue // needs a database, not a unit test
				}
				q.Testable++
				if testIdents[d.Name] {
					q.Tested++
					continue
				}
				pos := -1
				if p, ok := oldPos[d.Line]; ok {
					pos = p
				}
				q.Untested = append(q.Untested, evolution.Item{Dim: 2, Kind: "Untested function", Name: d.Name, Size: lengths[d.Line], Note: untestedNote(lengths[d.Line]),
					Rel: rel, Path: abs, Line: d.Line, Weight: 1, RepoPath: f.Path, OldPos: pos, Key: fmt.Sprintf("untested|%s:%d", abs, d.Line)})
			}
		}
		for _, c := range complexByFile[abs] {
			key := fmt.Sprintf("%s:%d", abs, c.line)
			if !added[c.line] || seenCx[key] {
				continue
			}
			seenCx[key] = true
			q.Complex++
			if docs.Has(c.line) {
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
	sort.SliceStable(q.Untested, func(i, j int) bool { return q.Untested[i].Size > q.Untested[j].Size })
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

// untestedNote labels an untested function with its size, so the biggest stand out.
func untestedNote(loc int) string {
	if loc <= 0 {
		return "no test file mentions it"
	}
	return fmt.Sprintf("%d LOC · no test file mentions it", loc)
}

var reSQLFunc = regexp.MustCompile(`(?is)\bselect\b.{0,300}?\bfrom\b|\binsert\s+into\b|\bupdate\s+\w+\s+set\b|\bdelete\s+from\b|\bunion\s+all\b|\b(?:create|alter|drop)\s+table\b|\bsquirrel\.|\bsq\.(?:Select|Insert|Update|Delete)\b|\.(?:QueryRow|QueryContext|ExecContext|QueryRowContext|Queryx|Getx|NamedExec)\(|\bcursor\.execute\(|\bsession\.(?:query|execute)\(`)

// isSQLFunc: the function (declared on 1-based line, loc lines long; 0 = unknown, then
// 12 lines) builds or runs SQL — covering it takes a database, so it is not "testable".
func isSQLFunc(lines []string, line, loc int) bool {
	if loc <= 0 {
		loc = 12
	}
	end := line - 1 + loc
	if line < 1 || line > len(lines) {
		return false
	}
	if end > len(lines) {
		end = len(lines)
	}
	return reSQLFunc.MatchString(strings.Join(lines[line-1:end], "\n"))
}
