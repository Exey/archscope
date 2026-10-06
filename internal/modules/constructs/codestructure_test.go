package constructs

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

func TestLooseAnyObjectTypesCountedForTS(t *testing.T) {
	src := "export function f(x: any): void {}\n" +
		"const g = (v: unknown) => v as any;\n" + // "as any"
		"type R = Record<string, any>;\n" + // ", any"
		"let m: WeakMap<object, any>;\n" + // "<object" + ", any"
		"const o = { a: 1 };\n" + // no type -> not counted
		"function many() { return company; }\n" // "many"/"company" must NOT match
	f := writeFile(t, ".ts", src)
	r := csAnalyze([]*parser.ParsedFile{f})
	if len(r.LooseTypeFiles) != 1 {
		t.Fatalf("expected 1 file with loose types, got %+v", r.LooseTypeFiles)
	}
	u := r.LooseTypeFiles[0]
	if u.AnyCount != 4 {
		t.Errorf("any count = %d, want 4 (: any, as any, ,any, ,any)", u.AnyCount)
	}
	if u.ObjCount != 1 {
		t.Errorf("object count = %d, want 1 (<object)", u.ObjCount)
	}
	if r.LooseTypeTotal != 5 {
		t.Errorf("LooseTypeTotal = %d, want 5", r.LooseTypeTotal)
	}
	if u.FirstLine != 1 {
		t.Errorf("FirstLine = %d, want 1", u.FirstLine)
	}
}

func TestLooseTypesIgnoredForNonTS(t *testing.T) {
	// A Go file with ": any" (Go 1.18+ alias) must not feed the TS-only stat.
	f := writeFile(t, ".go", "package p\nfunc f(x any) {}\nvar m map[string]any\n")
	r := csAnalyze([]*parser.ParsedFile{f})
	if r.LooseTypeTotal != 0 || len(r.LooseTypeFiles) != 0 {
		t.Errorf("Go file should not contribute loose-type stat, got total=%d files=%+v", r.LooseTypeTotal, r.LooseTypeFiles)
	}
}

func TestLooseTypesRenderedInHTMLAndMarkdown(t *testing.T) {
	f := writeFile(t, ".tsx", "const a: any = 1;\nconst b = x as object;\n")
	r := csAnalyze([]*parser.ParsedFile{f})
	html := (CodeStructure{}).RenderHTML(r)
	if !strings.Contains(html, "any / object types") || !strings.Contains(html, "as-cs__table") {
		t.Errorf("HTML missing loose-type stat/table:\n%s", html)
	}
	md := (CodeStructure{}).RenderMarkdown(r)
	if !strings.Contains(md, "`any` / `object` types:** 2") {
		t.Errorf("markdown missing loose-type headline:\n%s", md)
	}
	cards := (CodeStructure{}).SummaryCards(r)
	found := false
	for _, c := range cards {
		if c.Label == "any / object types" && c.Num == "2" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'any / object types' summary card, got %+v", cards)
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

// strIssues returns the rule IDs flagged in one source file.
func strIssues(t *testing.T, ext, src string) []string {
	t.Helper()
	f := writeFile(t, ext, src)
	var ids []string
	for _, is := range (Regex{}).Analyze([]*parser.ParsedFile{f}).(RegexReport).Issues {
		if is.Group == stringsGroup {
			ids = append(ids, is.RuleID)
		}
	}
	return ids
}

func hasRule(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func TestStringConcatInLoop(t *testing.T) {
	cases := map[string]string{
		".go":    "package p\nfunc F(xs []string) string {\n\ts := \"\"\n\tfor _, x := range xs {\n\t\ts += x\n\t}\n\treturn s\n}\n",
		".java":  "class A {\n String f(String[] xs) {\n  String s = \"\";\n  for (String x : xs) {\n   s += x;\n  }\n  return s;\n }\n}\n",
		".kt":    "fun f(xs: List<String>): String {\n    var s = \"\"\n    for (x in xs) {\n        s += x\n    }\n    return s\n}\n",
		".swift": "func f(xs: [String]) -> String {\n    var s = \"\"\n    for x in xs {\n        s += x\n    }\n    return s\n}\n",
		".rs":    "fn f(xs: &[&str]) -> String {\n    let mut s = String::new();\n    for x in xs {\n        s += x;\n    }\n    s\n}\n",
		".py":    "def f(xs):\n    s = ''\n    for x in xs:\n        s += x\n    return s\n",
	}
	for e, src := range cases {
		if ids := strIssues(t, e, src); !hasRule(ids, "concat-in-loop") {
			t.Errorf("%s: concat-in-loop not flagged, got %v", e, ids)
		}
	}
}

func TestStringConcatOutsideLoopOrNumericNotFlagged(t *testing.T) {
	for e, src := range map[string]string{
		".go":  "package p\nfunc F(a, b string) string {\n\ts := a\n\ts += b\n\treturn s\n}\n",
		".py":  "def f(xs):\n    n = 0\n    for x in xs:\n        n += x\n    return n\n",
		".go2": "",
	} {
		if e == ".go2" {
			continue
		}
		if ids := strIssues(t, e, src); hasRule(ids, "concat-in-loop") {
			t.Errorf("%s: false positive %v", e, ids)
		}
	}
	// a loop followed by an unrelated block must not leak the loop range
	src := "package p\nfunc F(xs []string) {\n\tfor range xs {\n\t}\n\ts := \"\"\n\ts += \"x\"\n\t_ = s\n}\n"
	if ids := strIssues(t, ".go", src); hasRule(ids, "concat-in-loop") {
		t.Errorf("flagged concat after loop: %v", ids)
	}
}

func TestGoCriticStringChecks(t *testing.T) {
	src := "package p\n" +
		"func F(a, b, w string) {\n" +
		"\t_ = strings.Join([]string{a, b}, \"_\")\n" +
		"\t_ = strings.Compare(a, b) == 0\n" +
		"\t_ = strings.ToLower(a) == strings.ToLower(b)\n" +
		"\t_ = fmt.Sprintf(\"%s\", a)\n" +
		"\t_ = fmt.Errorf(a)\n" +
		"\tio.WriteString(os.Stdout, fmt.Sprintf(\"%d\", 1))\n" +
		"\t_ = string([]byte(a))\n" +
		"\t_ = strings.Index(a, b) >= 0\n" +
		"\t_ = fmt.Sprintf(\"\\\"%s\\\"\", a)\n" +
		"}\n"
	ids := strIssues(t, ".go", src)
	for _, want := range []string{"join-small", "strings-compare", "equal-fold", "redundant-sprintf", "dynamic-errorf", "sprint-then-write", "string-bytes-roundtrip", "index-as-contains", "manual-quote"} {
		if !hasRule(ids, want) {
			t.Errorf("missing %s in %v", want, ids)
		}
	}
	clean := "package p\nfunc F(a, b string) string {\n\treturn a + b + fmt.Sprintf(\"%d\", 1)\n}\n"
	if ids := strIssues(t, ".go", clean); len(ids) != 0 {
		t.Errorf("clean Go flagged: %v", ids)
	}
}

func TestConcatChainSuggestsInterpolation(t *testing.T) {
	for e, src := range map[string]string{
		".kt":    "fun f(x: String) = \"a \" + x + \" b\"\n",
		".py":    "def f(x):\n    return 'a ' + str(x) + ' b'\n",
		".ts":    "const f = (x: string) => 'a ' + x + ' b';\n",
		".swift": "func f(x: String) -> String { return \"a \" + x + \" b\" }\n",
	} {
		if ids := strIssues(t, e, src); !hasRule(ids, "concat-chain") {
			t.Errorf("%s: concat-chain not flagged: %v", e, ids)
		}
	}
	if ids := strIssues(t, ".ts", "const n = a + b + c;\n"); hasRule(ids, "concat-chain") {
		t.Error("numeric chain flagged")
	}
}

func TestCaseCompareAndEmptyLength(t *testing.T) {
	if ids := strIssues(t, ".java", "class A { boolean f(String a, String b) { return a.toLowerCase().equals(b) || a.length() == 0; } }\n"); !hasRule(ids, "case-compare") {
		t.Errorf("java: %v", ids)
	}
	if ids := strIssues(t, ".py", "def f(a, b):\n    return a.lower() == b.lower()\n"); !hasRule(ids, "case-compare") {
		t.Errorf("py: %v", ids)
	}
	if ids := strIssues(t, ".swift", "func f(a: String) -> Bool { return a.count == 0 }\n"); !hasRule(ids, "length-zero") {
		t.Errorf("swift: %v", ids)
	}
}

func issueIDs(is []CSIssue) []string {
	var ids []string
	for _, x := range is {
		ids = append(ids, x.RuleID)
	}
	return ids
}

func goReport(t *testing.T, src string) CodeStructureReport {
	t.Helper()
	return csAnalyze([]*parser.ParsedFile{writeFile(t, ".go", src)})
}

func TestGoBugClassChecks(t *testing.T) {
	src := "package p\n" +
		"import (\n\t\"io\"\n\t\"net/http\"\n\t\"os\"\n\t\"log\"\n\t\"sync\"\n)\n" +
		"func F(a, b int, s []int, str string, mu *sync.Mutex, w http.ResponseWriter) {\n" +
		"\tif a == a {\n\t}\n" +
		"\tif a < 10 && a > 20 {\n\t}\n" +
		"\t_ = s[len(s)]\n" +
		"\tio.EOF = nil\n" +
		"\tmu.Lock()\n\tmu.Unlock()\n" +
		"\tmu.Lock()\n\tdefer mu.RUnlock()\n" +
		"\tif err := os.Remove(str); err2 != nil {\n\t}\n" +
		"\tif err = os.Remove(str); err != nil {\n\t}\n" +
		"\tdefer os.Remove(str)\n" +
		"\tif a > 1 {\n\t\thttp.Error(w, \"bad\", 400)\n\t}\n" +
		"\tlog.Fatal(\"x\")\n" +
		"}\n"
	got := goReport(t, src).BugIssues
	ids := issueIDs(got)
	for _, want := range []string{"dup-subexpr", "bad-cond", "off-by-one", "external-error-reassign", "bad-lock", "unchecked-inline-err", "sloppy-reassign", "http-error-no-return", "exit-after-defer"} {
		if !hasRule(ids, want) {
			t.Errorf("missing %s in %v", want, ids)
		}
	}
}

func TestGoBugClassNoFalsePositives(t *testing.T) {
	src := "package p\n" +
		"import \"net/http\"\n" +
		"func F(a, b int, s []int, x, y float64, w http.ResponseWriter) int {\n" +
		"\tif a == b || x < y {\n\t}\n" +
		"\tz := a - b - b\n" + // (a-b)-b is not a dup
		"\t_ = s[len(s)-1]\n" +
		"\tif a > 5 && a < 10 {\n\t}\n" +
		"\tif a < 5 || a > 10 {\n\t}\n" +
		"\tif a == a+1 {\n\t}\n" +
		"\tif a > 1 {\n\t\thttp.Error(w, \"bad\", 400)\n\t\treturn z\n\t}\n" +
		"\treturn z\n}\n"
	if ids := issueIDs(goReport(t, src).BugIssues); len(ids) != 0 {
		t.Errorf("false positives: %v", ids)
	}
}

func TestCaseOrderInTypeSwitch(t *testing.T) {
	src := "package p\nfunc F(v any) {\n\tswitch v.(type) {\n\tcase any:\n\tcase int:\n\t}\n\tswitch v.(type) {\n\tcase error:\n\tcase *MyError:\n\t}\n}\n"
	n := 0
	for _, id := range issueIDs(goReport(t, src).BugIssues) {
		if id == "case-order" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("want 2 case-order hits, got %d", n)
	}
}

func TestDuplicateBranchBodies(t *testing.T) {
	dup := "package p\nfunc F(a, b bool) {\n\tif a {\n\t\tdoSomething(first, second, third)\n\t} else if b {\n\t\tdoSomething(first, second, third)\n\t} else {\n\t\tother()\n\t}\n}\n"
	if ids := issueIDs(goReport(t, dup).DupIssues); !hasRule(ids, "dup-branch") {
		t.Errorf("dup-branch missed: %v", ids)
	}
	// same shape, different string literal: not a duplicate
	diff := "package p\nfunc F(a bool) {\n\tif a {\n\t\tlogMessage(\"first branch text\")\n\t} else {\n\t\tlogMessage(\"other branch text\")\n\t}\n}\n"
	if ids := issueIDs(goReport(t, diff).DupIssues); len(ids) != 0 {
		t.Errorf("literal difference treated as duplicate: %v", ids)
	}
	// trivial identical bodies are tolerated
	triv := "package p\nfunc F(a, b bool) bool {\n\tif a {\n\t\treturn true\n\t} else if b {\n\t\treturn true\n\t}\n\treturn false\n}\n"
	if ids := issueIDs(goReport(t, triv).DupIssues); len(ids) != 0 {
		t.Errorf("trivial return flagged: %v", ids)
	}
}

func TestDuplicateBranchBodiesJavaAndKotlinStyle(t *testing.T) {
	src := "class A {\n void f(boolean a) {\n  if (a) {\n   service.process(item, 1, 2);\n  } else {\n   service.process(item, 1, 2);\n  }\n }\n}\n"
	f := writeFile(t, ".java", src)
	if ids := issueIDs(csAnalyze([]*parser.ParsedFile{f}).DupIssues); !hasRule(ids, "dup-branch") {
		t.Errorf("java dup-branch missed: %v", ids)
	}
}

func TestDuplicateCaseLabels(t *testing.T) {
	src := "package p\nfunc F(x int, s string) {\n\tswitch x {\n\tcase 1, 2:\n\t\ta()\n\tcase 3, 1:\n\t\tb()\n\t}\n\tswitch s {\n\tcase \"a\":\n\tcase \"b\":\n\t}\n}\n"
	n := 0
	for _, id := range issueIDs(goReport(t, src).DupIssues) {
		if id == "dup-case" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("want exactly 1 dup-case, got %d", n)
	}
	c := "int f(int x) {\n switch (x) {\n  case 1: return 1;\n  case 1: return 2;\n }\n return 0;\n}\n"
	if ids := issueIDs(csAnalyze([]*parser.ParsedFile{writeFile(t, ".c", c)}).DupIssues); !hasRule(ids, "dup-case") {
		t.Errorf("C dup-case missed: %v", ids)
	}
}

func TestBraceInStringDoesNotBreakWalk(t *testing.T) {
	src := "package p\nfunc F(a bool) {\n\tif a {\n\t\tprint(\"}{\")\n\t} else {\n\t\tprint(\"{\")\n\t}\n}\n"
	if ids := issueIDs(goReport(t, src).DupIssues); len(ids) != 0 {
		t.Errorf("unexpected: %v", ids)
	}
}

func regexIssues(t *testing.T, ext, src string) []CSIssue {
	t.Helper()
	return (Regex{}).Analyze([]*parser.ParsedFile{writeFile(t, ext, src)}).(RegexReport).Issues
}

func TestRegexCompileInLoop(t *testing.T) {
	cases := map[string]string{
		".go":   "package p\nimport \"regexp\"\nfunc F(xs []string) {\n\tfor _, x := range xs {\n\t\tre := regexp.MustCompile(`^a+$`)\n\t\t_ = re.MatchString(x)\n\t}\n}\n",
		".java": "class A {\n void f(String[] xs) {\n  for (String x : xs) {\n   Pattern p = Pattern.compile(\"a+\");\n  }\n }\n}\n",
		".py":   "import re\ndef f(xs):\n    for x in xs:\n        p = re.compile('a+')\n",
		".ts":   "function f(xs: string[]) {\n  for (const x of xs) {\n    const r = new RegExp('a+');\n  }\n}\n",
		".rs":   "fn f(xs: &[&str]) {\n    for x in xs {\n        let r = Regex::new(\"a+\").unwrap();\n    }\n}\n",
	}
	for e, src := range cases {
		if ids := issueIDs(regexIssues(t, e, src)); !hasRule(ids, "regex-in-loop") {
			t.Errorf("%s: regex-in-loop missed: %v", e, ids)
		}
	}
}

func TestRegexGoInvalidAndMust(t *testing.T) {
	bad := "package p\nimport \"regexp\"\nvar re = regexp.MustCompile(`(?=a)b`)\n"
	var sev string
	for _, is := range regexIssues(t, ".go", bad) {
		if is.RuleID == "regex-invalid" {
			sev = string(is.Severity)
		}
	}
	if sev != "HIGH" {
		t.Errorf("MustCompile of invalid RE2 should be HIGH, got %q", sev)
	}
	if ids := issueIDs(regexIssues(t, ".go", "package p\nimport \"regexp\"\nvar re, _ = regexp.Compile(`^a+$`)\n")); !hasRule(ids, "regex-must") {
		t.Errorf("regex-must missed: %v", ids)
	}
	if ids := issueIDs(regexIssues(t, ".go", "package p\nimport \"regexp\"\nvar re = regexp.MustCompile(`^a+$`)\n")); len(ids) != 0 {
		t.Errorf("clean pattern flagged: %v", ids)
	}
}

func TestRegexRedosSimplifyBad(t *testing.T) {
	if ids := issueIDs(regexIssues(t, ".py", "import re\np = re.compile(r'^(a+)+$')\n")); !hasRule(ids, "regex-redos") {
		t.Errorf("redos missed: %v", ids)
	}
	if ids := issueIDs(regexIssues(t, ".go", "package p\nimport \"regexp\"\nvar re = regexp.MustCompile(`^(a+)+$`)\n")); hasRule(ids, "regex-redos") {
		t.Errorf("RE2 is not vulnerable to ReDoS: %v", ids)
	}
	if ids := issueIDs(regexIssues(t, ".go", "package p\nimport \"regexp\"\nvar re = regexp.MustCompile(`[0-9]{1,}x`)\n")); !hasRule(ids, "regex-simplify") {
		t.Errorf("simplify missed: %v", ids)
	}
	if ids := issueIDs(regexIssues(t, ".go", "package p\nimport \"regexp\"\nvar re = regexp.MustCompile(`[A-z]+|[a|b]`)\n")); !hasRule(ids, "regex-bad") {
		t.Errorf("bad regexp missed: %v", ids)
	}
}

func TestGoPerfIdioms(t *testing.T) {
	src := "package p\nimport \"strings\"\nfunc F(xs, ys []int, bs []byte, w *Buf, s string, a []string) {\n" +
		"\tys = append(ys, 1)\n\tys = append(ys, 2)\n" +
		"\tfor _, x := range xs {\n\t\tys = append(ys, xs...)\n\t\t_ = x\n\t}\n" +
		"\tfor i := 0; i < len(xs); i++ {\n\t\txs[i] = 0\n\t}\n" +
		"\t_ = strings.Index(string(bs), s)\n" +
		"\tw.WriteRune('x')\n" +
		"\tw.Write([]byte(s))\n}\n"
	ids := issueIDs(regexIssues(t, ".go", src))
	for _, want := range []string{"perf-append-combine", "perf-range-append-all", "perf-slice-clear", "perf-index-alloc", "perf-write-byte", "perf-string-writer"} {
		if !hasRule(ids, want) {
			t.Errorf("missing %s in %v", want, ids)
		}
	}
}

func TestConcurrencyChecks(t *testing.T) {
	src := "package p\nimport (\n\t\"net/http\"\n\t\"sync\"\n\t\"time\"\n)\n" +
		"type Cache struct {\n\tsync.Mutex\n\tm sync.Map\n}\n" +
		"func F(c *Cache, k string, t time.Time, wg *sync.WaitGroup) {\n" +
		"\tv, ok := c.m.Load(k)\n\tif ok {\n\t\tc.m.Delete(k)\n\t}\n\t_ = v\n" +
		"\tsync.OnceFunc(g)()\n" +
		"\treq, _ := http.NewRequest(\"GET\", \"/x\", nil)\n\t_ = req\n" +
		"\t_ = t.UnixNano() / 1000000\n" +
		"\twg.Add(-1)\n}\n"
	rep := (Concurrency{}).Analyze([]*parser.ParsedFile{writeFile(t, ".go", src)}).(ConcurrencyReport)
	ids := issueIDs(rep.Issues)
	for _, want := range []string{"sync-map-load-delete", "exposed-mutex", "once-func-misuse", "http-no-body", "time-expr", "wg-add-negative"} {
		if !hasRule(ids, want) {
			t.Errorf("missing %s in %v", want, ids)
		}
	}
	clean := "package p\nimport \"net/http\"\nfunc F(wg interface{ Done() }) {\n\t_, _ = http.NewRequest(\"GET\", \"/x\", http.NoBody)\n\twg.Done()\n}\n"
	if r := (Concurrency{}).Analyze([]*parser.ParsedFile{writeFile(t, ".go", clean)}).(ConcurrencyReport); r.Total() != 0 {
		t.Errorf("clean flagged: %v", issueIDs(r.Issues))
	}
}

func TestIssueCardRendersCleanAndDirty(t *testing.T) {
	clean := (Regex{}).RenderHTML(RegexReport{})
	if !strings.Contains(clean, "No string & regex issues") {
		t.Errorf("clean Regex card should confirm, got %q", clean)
	}
	rep := (Regex{}).Analyze([]*parser.ParsedFile{writeFile(t, ".go", "package p\nimport \"regexp\"\nfunc F(xs []string) {\n\tfor range xs {\n\t\t_ = regexp.MustCompile(`a+`)\n\t}\n}\n")}).(RegexReport)
	out := (Regex{}).RenderHTML(rep)
	for _, want := range []string{"Regex compiled inside a loop", "as-sev", "vscode://", "as-cs__sub", "Strings & Regex"[:0] + "Regex"} {
		if !strings.Contains(out, want) {
			t.Errorf("Regex card missing %q", want)
		}
	}
	if md := (Regex{}).RenderMarkdown(rep); !strings.Contains(md, "Regex compiled inside a loop") {
		t.Errorf("markdown missing the rule: %s", md)
	}
	if got := inlineCode("use `x` now"); got != `use <code class="mono">x</code> now` {
		t.Errorf("inlineCode = %q", got)
	}
}

func TestStringLoopResetNotFlagged(t *testing.T) {
	src := "package p\nfunc F(xs []string) {\n\tfor _, x := range xs {\n\t\turi := x\n\t\turi += \":\"\n\t\t_ = uri\n\t}\n}\n"
	if ids := strIssues(t, ".go", src); hasRule(ids, "concat-in-loop") {
		t.Errorf("per-iteration string flagged: %v", ids)
	}
}

func TestDupBranchWithScopedInitNotFlagged(t *testing.T) {
	src := "package p\nfunc F(a, b string) {\n\tif m := find(a); m != nil {\n\t\tuse(\"Kotlin\", m[1], \"language\")\n\t} else if m := find(b); m != nil {\n\t\tuse(\"Kotlin\", m[1], \"language\")\n\t}\n}\n"
	if ids := issueIDs(goReport(t, src).DupIssues); len(ids) != 0 {
		t.Errorf("scoped-init branches flagged: %v", ids)
	}
}

func TestCharLiteralCommaCaseNotDuplicate(t *testing.T) {
	src := "package p\nfunc F(c byte) {\n\tswitch c {\n\tcase ',':\n\tcase '(':\n\tcase ')':\n\t}\n}\n"
	if ids := issueIDs(goReport(t, src).DupIssues); len(ids) != 0 {
		t.Errorf("char-literal cases flagged: %v", ids)
	}
}

func TestConcatWithConditionalSeedStillFlagged(t *testing.T) {
	src := "package p\nfunc F(segs []seg) string {\n\tname := \"\"\n\tfor _, seg := range segs {\n\t\tif name == \"\" {\n\t\t\tname = seg.tag\n\t\t} else {\n\t\t\tname = name + \"/\" + seg.tag + \"/\" + seg.id\n\t\t}\n\t}\n\treturn name\n}\n"
	if ids := strIssues(t, ".go", src); !hasRule(ids, "concat-in-loop") {
		t.Errorf("conditional seed hid the concat: %v", ids)
	}
}

// Every header minicard that links somewhere must point at a subcard that exists.
func TestCodeStructureMinicardsTargetExistingSubcards(t *testing.T) {
	var src strings.Builder
	src.WriteString("package p\nfunc Many(a, b, c, d, e, f, g int) int {\n\tif a == a {\n\t\tfor {\n\t\t\tfor {\n\t\t\t\tfor {\n\t\t\t\t\tif b > 0 {\n\t\t\t\t\t\treturn 1\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t}\n\treturn 0\n}\n")
	rep := csAnalyze([]*parser.ParsedFile{writeFile(t, ".go", src.String())})
	out := (CodeStructure{}).RenderHTML(rep)
	targets := regexp.MustCompile(`data-target="([a-z]+)"`).FindAllStringSubmatch(out, -1)
	if len(targets) == 0 {
		t.Fatal("expected linked minicards")
	}
	for _, m := range targets {
		if !strings.Contains(out, `data-sub="`+m[1]+`"`) {
			t.Errorf("minicard targets %q but no such subcard", m[1])
		}
	}
	if strings.Contains(out, "as-cs__viol-title") {
		t.Error("offender tables should be subcards, not bare viol-title blocks")
	}
}
