package constructs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func csAnalyze(files []*parser.ParsedFile) CodeStructureReport {
	return (CodeStructure{}).Analyze(files).(CodeStructureReport)
}

func TestHighParamCountFlagged(t *testing.T) {
	src := "package p\nfunc Sum(a, b, c, d, e, f int) int {\n\treturn a + b + c + d + e + f\n}\n"
	f := writeFile(t, ".go", src)
	r := csAnalyze([]*parser.ParsedFile{f})
	if len(r.HighParamFuncs) != 1 || r.HighParamFuncs[0].Symbol != "Sum" {
		t.Fatalf("expected Sum flagged for high param count, got %+v", r.HighParamFuncs)
	}
	if r.HighParamFuncs[0].Value != 6 {
		t.Errorf("expected 6 params, got %d", r.HighParamFuncs[0].Value)
	}
}

func TestGoMethodWithReceiverIsDetected(t *testing.T) {
	// The shared magicconstants reFuncDecl can't see receiver methods; this
	// module's own reFuncSig must.
	src := "package p\ntype T struct{}\nfunc (t *T) Do(a, b, c, d, e, f, g int) int {\n\treturn a\n}\n"
	f := writeFile(t, ".go", src)
	r := csAnalyze([]*parser.ParsedFile{f})
	if len(r.HighParamFuncs) != 1 || r.HighParamFuncs[0].Symbol != "Do" {
		t.Fatalf("expected receiver method Do flagged, got %+v", r.HighParamFuncs)
	}
}

func TestLowParamCountNotFlagged(t *testing.T) {
	src := "package p\nfunc Add(a, b int) int {\n\treturn a + b\n}\n"
	f := writeFile(t, ".go", src)
	r := csAnalyze([]*parser.ParsedFile{f})
	if len(r.HighParamFuncs) != 0 {
		t.Errorf("expected no offenders, got %+v", r.HighParamFuncs)
	}
}

func TestDeepNestingFlagged(t *testing.T) {
	src := "package p\nfunc Deep() {\n" +
		"\tif true {\n\t\tif true {\n\t\t\tif true {\n\t\t\t\tif true {\n\t\t\t\t\tif true {\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t}\n}\n"
	f := writeFile(t, ".go", src)
	r := csAnalyze([]*parser.ParsedFile{f})
	if len(r.DeepNestFuncs) != 1 || r.DeepNestFuncs[0].Symbol != "Deep" {
		t.Fatalf("expected Deep flagged for nesting, got %+v", r.DeepNestFuncs)
	}
	if r.WorstNest.Value != r.DeepNestFuncs[0].Value {
		t.Errorf("WorstNest should track the deepest function: %+v vs %+v", r.WorstNest, r.DeepNestFuncs[0])
	}
}

func TestFlatFunctionNotFlagged(t *testing.T) {
	src := "package p\nfunc Flat() {\n\tx := 1\n\ty := 2\n\t_ = x + y\n}\n"
	f := writeFile(t, ".go", src)
	r := csAnalyze([]*parser.ParsedFile{f})
	if len(r.DeepNestFuncs) != 0 {
		t.Errorf("expected no nesting offenders, got %+v", r.DeepNestFuncs)
	}
}

func TestCommentPercentageComputed(t *testing.T) {
	src := "// comment one\n// comment two\nfunc Foo() {}\n"
	f := writeFile(t, ".go", src)
	r := csAnalyze([]*parser.ParsedFile{f})
	// 2 comment lines out of 4 (raw split includes the trailing empty line
	// after the final "\n") = 50%.
	if r.CommentPercent < 45 || r.CommentPercent > 55 {
		t.Errorf("expected ~50%% comments, got %d%%", r.CommentPercent)
	}
}

func TestPreprocessorDirectivesCountedForCButNotPython(t *testing.T) {
	c := writeFile(t, ".c", "#include <stdio.h>\n#define MAX 10\nint main() { return 0; }\n")
	rc := csAnalyze([]*parser.ParsedFile{c})
	if rc.PreprocDirectives != 2 {
		t.Errorf("expected 2 preprocessor directives in C file, got %d", rc.PreprocDirectives)
	}

	py := writeFile(t, ".py", "# just a comment\ndef foo():\n    pass\n")
	rp := csAnalyze([]*parser.ParsedFile{py})
	if rp.PreprocDirectives != 0 {
		t.Errorf("Python '#' comments must not count as directives, got %d", rp.PreprocDirectives)
	}
}

func TestOvercrowdedFolderFlagged(t *testing.T) {
	dir := t.TempDir()
	var files []*parser.ParsedFile
	for i := 0; i < csOvercrowdedFolder+1; i++ {
		p := filepath.Join(dir, fmt.Sprintf("f%d.go", i))
		if err := os.WriteFile(p, []byte("package p\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, &parser.ParsedFile{FilePath: p})
	}
	r := csAnalyze(files)
	if len(r.OvercrowdedFolders) != 1 || r.OvercrowdedFolders[0].Path != dir {
		t.Fatalf("expected %s flagged as overcrowded, got %+v", dir, r.OvercrowdedFolders)
	}
}

func TestManySingleFileFoldersFlagged(t *testing.T) {
	root := t.TempDir()
	var files []*parser.ParsedFile
	for i := 0; i < csManySingleFileDirs+1; i++ {
		sub := filepath.Join(root, fmt.Sprintf("d%d", i))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(sub, "only.go")
		if err := os.WriteFile(p, []byte("package p\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, &parser.ParsedFile{FilePath: p})
	}
	r := csAnalyze(files)
	if len(r.SingleFileFolders) != csManySingleFileDirs+1 {
		t.Errorf("expected %d single-file folders flagged, got %d", csManySingleFileDirs+1, len(r.SingleFileFolders))
	}
}

func TestFewSingleFileFoldersNotFlagged(t *testing.T) {
	root := t.TempDir()
	var files []*parser.ParsedFile
	for i := 0; i < 3; i++ {
		sub := filepath.Join(root, fmt.Sprintf("d%d", i))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(sub, "only.go")
		if err := os.WriteFile(p, []byte("package p\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, &parser.ParsedFile{FilePath: p})
	}
	r := csAnalyze(files)
	if len(r.SingleFileFolders) != 0 {
		t.Errorf("expected no single-file-folder smell below threshold, got %+v", r.SingleFileFolders)
	}
}

func TestContainerOnlyFoldersFlagged(t *testing.T) {
	root := t.TempDir()
	var files []*parser.ParsedFile
	// Three container-only wrapper folders, each holding one populated
	// grandchild folder and no files of their own.
	for i := 0; i < csManyEmptyFolders; i++ {
		wrapper := filepath.Join(root, fmt.Sprintf("wrap%d", i))
		leaf := filepath.Join(wrapper, "inner")
		if err := os.MkdirAll(leaf, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(leaf, "f.go")
		if err := os.WriteFile(p, []byte("package p\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, &parser.ParsedFile{FilePath: p})
	}
	r := csAnalyze(files)
	if len(r.EmptyFolders) != csManyEmptyFolders {
		t.Errorf("expected %d container-only folders flagged, got %+v", csManyEmptyFolders, r.EmptyFolders)
	}
}

func TestRenderHTMLIncludesOffendersAndFolderSmells(t *testing.T) {
	src := "package p\nfunc Sum(a, b, c, d, e, f int) int {\n\treturn a\n}\n"
	f := writeFile(t, ".go", src)
	out := (CodeStructure{}).RenderHTML(csAnalyze([]*parser.ParsedFile{f}))
	if !strings.Contains(out, "Sum") {
		t.Errorf("render missing offending function name: %s", out)
	}
	if !strings.Contains(out, "comments") {
		t.Errorf("render missing comment-percentage stat: %s", out)
	}
}

func TestEmptyInputHasNoData(t *testing.T) {
	r := csAnalyze(nil)
	if r.HasData() {
		t.Error("expected HasData() false for no files")
	}
	if (CodeStructure{}).RenderHTML(r) != "" {
		t.Error("expected empty render for no data")
	}
}
