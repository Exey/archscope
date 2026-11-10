package result

import (
	"github.com/exey/archscope/internal/langprofile"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/exey/archscope/internal/evolution"
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules/constructs"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/security"
)

// attachSummary counts what the merge request does to declarations: functions
// added / updated (a changed line inside the body) / deleted, types and
// constants added or removed, new files and new test functions. The base and
// the reviewed side are both parsed from their own text.
func attachSummary(repo string, rv *evolution.Review) {
	head := rv.HeadSHA
	if rv.Subject == "" {
		head = ""
	}
	ps := parser.New(langspec.Default)
	sum := &evolution.ChangeSummary{}
	typeKinds := map[parser.DeclKind]bool{parser.DeclStruct: true, parser.DeclClass: true, parser.DeclInterface: true, parser.DeclEnum: true,
		parser.DeclActor: true, parser.DeclType: true, parser.DeclMessage: true, parser.DeclService: true}

	for _, f := range rv.Files {
		if f.Binary {
			continue
		}
		var now []string
		var haveNow bool
		if head != "" {
			if src, err := evolution.FileAt(repo, head, f.Path); err == nil {
				now, haveNow = strings.Split(src, "\n"), true
			}
		} else if b, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(f.Path))); err == nil {
			now, haveNow = strings.Split(string(b), "\n"), true
		}
		var base []string
		haveBase := false
		if src, err := evolution.FileAt(repo, rv.BaseSHA, f.Path); err == nil {
			base, haveBase = strings.Split(src, "\n"), true
		}
		switch {
		case haveNow && !haveBase:
			sum.FilesNew++
		case !haveNow && haveBase:
			sum.FilesDeleted++
		default:
			sum.FilesChanged++
		}
		if langprofile.IsGenerated(f.Path, nil) {
			continue // generated stubs are not the change's own declarations
		}
		isTest := security.IsTestOrBenchPath(f.Path)
		at := " (" + filepath.Base(f.Path) + ")" // the same name recurs across files
		after, before := decls(ps, f.Path, now, haveNow), decls(ps, f.Path, base, haveBase)
		if len(after.funcs)+len(after.other)+len(after.values)+len(before.funcs)+len(before.other)+len(before.values) == 0 {
			continue
		}
		added := evolution.AddedLines(repo, rv.BaseSHA, head, f.Path)
		for name, d := range after.funcs {
			_, existed := before.funcs[name]
			switch {
			case !existed && isTest:
				sum.TestsAdded++
			case !existed:
				sum.FuncsNew = append(sum.FuncsNew, name+at)
			case !isTest && touched(added, d[0], d[1]):
				sum.FuncsUpdated = append(sum.FuncsUpdated, name+at)
			}
		}
		if isTest {
			continue
		}
		for name := range before.funcs {
			if _, ok := after.funcs[name]; !ok {
				sum.FuncsDeleted = append(sum.FuncsDeleted, name+at)
			}
		}
		for k, kind := range after.other {
			if _, ok := before.other[k]; !ok && typeKinds[kind] {
				sum.TypesNew = append(sum.TypesNew, k+at)
			}
		}
		for k, kind := range before.other {
			if _, ok := after.other[k]; !ok && typeKinds[kind] {
				sum.TypesDeleted = append(sum.TypesDeleted, k+at)
			}
		}
		for k := range after.values {
			if _, ok := before.values[k]; !ok {
				sum.ValuesNew = append(sum.ValuesNew, k+at)
			}
		}
		for k := range before.values {
			if _, ok := after.values[k]; !ok {
				sum.ValuesDeleted = append(sum.ValuesDeleted, k+at)
			}
		}
	}
	for _, l := range [][]string{sum.FuncsNew, sum.FuncsUpdated, sum.FuncsDeleted, sum.TypesNew, sum.TypesDeleted, sum.ValuesNew, sum.ValuesDeleted} {
		sort.Strings(l)
	}
	if !sum.Empty() {
		rv.Summary = sum
	}
}

// fileDecls: a file's functions (name → [start, end] 1-based) and other declarations.
type fileDecls struct {
	funcs  map[string][2]int
	other  map[string]parser.DeclKind // types and the like
	values map[string]string          // named constants and variables → "const" | "var"
}

// decls parses lines as path; the zero value (empty maps) when the file is absent or unknown.
func decls(ps *parser.Parser, path string, lines []string, ok bool) *fileDecls {
	d := &fileDecls{funcs: map[string][2]int{}, other: map[string]parser.DeclKind{}, values: map[string]string{}}
	if !ok {
		return d
	}
	for _, v := range langprofile.ScanValues(path, lines) {
		d.values[v.Name] = v.Kind
	}
	pf := ps.ParseLines(path, lines)
	if pf == nil {
		return d
	}
	lens := constructs.FuncLengths(path, lines)
	for _, x := range pf.Declarations {
		if x.Kind == parser.DeclFunc {
			if n := lens[x.Line]; n > 0 {
				d.funcs[x.Name] = [2]int{x.Line, x.Line + n - 1}
			} else {
				d.funcs[x.Name] = [2]int{x.Line, x.Line}
			}
			continue
		}
		if x.Kind != parser.DeclConst && x.Kind != parser.DeclVar { // values come from the language profile
			d.other[x.Name] = x.Kind
		}
	}
	return d
}

func touched(added map[int]bool, from, to int) bool {
	for l := from; l <= to; l++ {
		if added[l] {
			return true
		}
	}
	return false
}
