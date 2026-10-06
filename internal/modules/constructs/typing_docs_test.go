package constructs

import (
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func TestPythonTypingHealth(t *testing.T) {
	src := "from typing import Any, List\n\ndef typed(a: int, b: str = 'x') -> int:\n    return a\n\ndef untyped(a, b):\n    return a\n\ndef half(a: int):\n    return a\n\nclass C:\n    def __init__(self, x: int):\n        self.x = x\n\n    def m(self, y: Any) -> List[int]:  # type: ignore\n        return []\n"
	rep := pyReport(t, src)
	if rep.PyFuncs != 5 || rep.PyTyped != 3 {
		t.Errorf("typed %d of %d, want 3 of 5 (typed, __init__, m)", rep.PyTyped, rep.PyFuncs)
	}
	if rep.PyAny != 1 || rep.TypeIgnores != 1 {
		t.Errorf("Any=%d ignores=%d", rep.PyAny, rep.TypeIgnores)
	}
	ts := csAnalyze([]*parser.ParsedFile{writeFile(t, ".ts", "// @ts-ignore\nconst a: number = 'x';\n/* @ts-expect-error */\nlet b = 1;\n")})
	if ts.TypeIgnores != 2 {
		t.Errorf("ts ignores = %d", ts.TypeIgnores)
	}
}

func TestDocumentationCoverage(t *testing.T) {
	py := "def pub():\n    \"\"\"Documented.\"\"\"\n    return 1\n\ndef bare():\n    return 2\n\ndef _private():\n    return 3\n\nclass K:\n    '''Doc.'''\n    def method(self):\n        return 4\n"
	rep := pyReport(t, py)
	if rep.DocPublic != 4 || rep.DocDocumented != 2 {
		t.Errorf("python docs %d/%d, want 2/4", rep.DocDocumented, rep.DocPublic)
	}
	goSrc := "package p\n\n// Exported is documented.\nfunc Exported() {}\n\nfunc Undocumented() {}\n\nfunc hidden() {}\n\n// T is a type.\ntype T struct{}\n"
	grep := goReport(t, goSrc)
	if grep.DocPublic != 3 || grep.DocDocumented != 2 {
		t.Errorf("go docs %d/%d, want 2/3", grep.DocDocumented, grep.DocPublic)
	}
	java := "/** Doc. */\npublic class A {\n  /** m */\n  public void m() {}\n  @Override\n  public String toString() { return \"\"; }\n  public void bare() {}\n  private void p() {}\n}\n"
	jrep := csAnalyze([]*parser.ParsedFile{writeFile(t, ".java", java)})
	if jrep.DocPublic != 4 || jrep.DocDocumented != 2 {
		t.Errorf("java docs %d/%d, want 2/4", jrep.DocDocumented, jrep.DocPublic)
	}
}
