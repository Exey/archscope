package constructs

import (
	"fmt"
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func pyMasked(src string) maskedFile { return maskSource(strings.Split(src, "\n"), ".py") }

func TestPyParseFunctionsAndClasses(t *testing.T) {
	src := "import os\n\n@decorator\n@other(1)\ndef top(a, b=(1, 2), *args, **kw):\n    '''doc: with colon\n    def fake(): pass\n    '''\n    x = {'k': 1}  # def comment():\n    return x\n\nclass Foo(Base, metaclass=Meta):\n    attr = 1\n\n    def method(self, a,\n               b: Dict[str, int] = None) -> Dict[str, int]:\n        def inner(q): return q\n        return inner(a)\n\n    async def amethod(self):\n        pass\n\nlast = 1\n"
	fs, cs := pyParse(pyMasked(src))
	if len(cs) != 1 || cs[0].name != "Foo" || !strings.Contains(cs[0].bases, "Base") {
		t.Fatalf("classes: %+v", cs)
	}
	byName := map[string]pyFunc{}
	for _, f := range fs {
		byName[f.name] = f
	}
	for _, n := range []string{"top", "method", "inner", "amethod"} {
		if _, ok := byName[n]; !ok {
			t.Fatalf("missing %s in %+v", n, fs)
		}
	}
	if _, ok := byName["fake"]; ok {
		t.Error("def inside a docstring was parsed")
	}
	if got := len(byName["top"].decorators); got != 2 {
		t.Errorf("decorators = %d", got)
	}
	if n := pyParamCount(byName["top"].params); n != 4 {
		t.Errorf("top params = %d, want 4 (a, b, *args, **kw)", n)
	}
	m := byName["method"]
	if m.class != "Foo" || pyParamCount(m.params) != 2 {
		t.Errorf("method: class=%q params=%d", m.class, pyParamCount(m.params))
	}
	if m.sigEnd != m.start+1 || m.bodyStart != m.sigEnd+1 {
		t.Errorf("method signature lines: %+v", m)
	}
	if !byName["inner"].oneLiner || !byName["inner"].enclosedDef || byName["inner"].class != "" {
		t.Errorf("inner: %+v", byName["inner"])
	}
	if !byName["amethod"].async {
		t.Error("async not detected")
	}
	if byName["top"].end != byName["top"].start+5 {
		t.Errorf("top end = %d (start %d)", byName["top"].end, byName["top"].start)
	}
}

func TestPyNestDepth(t *testing.T) {
	src := "def f(a):\n    if a:\n        for i in a:\n            while i:\n                try:\n                    pass\n                except E:\n                    pass\n    else:\n        pass\n    x = [i for i in a if i]\n    return x\n"
	m := pyMasked(src)
	fs, _ := pyParse(m)
	if d := pyNestDepth(m.code, pyLogicalStarts(m.code), fs[0]); d != 4 {
		t.Errorf("nest depth = %d, want 4 (if > for > while > try)", d)
	}
	flat := "def g():\n    x = 1\n    return x\n"
	m2 := pyMasked(flat)
	fs2, _ := pyParse(m2)
	if d := pyNestDepth(m2.code, pyLogicalStarts(m2.code), fs2[0]); d != 0 {
		t.Errorf("flat depth = %d", d)
	}
}

func pyReport(t *testing.T, src string) CodeStructureReport {
	t.Helper()
	return csAnalyze([]*parser.ParsedFile{writeFile(t, ".py", src)})
}

func TestPythonCodeStructureSubcards(t *testing.T) {
	var b strings.Builder
	b.WriteString("class Svc(A, B, C, D, E):\n    def __init__(self):\n")
	for i := 0; i < 9; i++ {
		fmt.Fprintf(&b, "        self.a%d = %d\n", i, i)
	}
	b.WriteString("\n    def busy(self, a, b, c, d, e, f, g):\n        x1 = 1\n        if a:\n            for i in b:\n                while c:\n                    try:\n                        if d and e or f:\n                            return 1\n                    except E:\n                        return 2\n        elif b:\n            return 3\n        elif c:\n            return 4\n        elif d:\n            return 5\n        elif e:\n            return 6\n        elif f:\n            return 7\n        elif g:\n            return 8\n        return 9\n")
	rep := pyReport(t, b.String())
	if len(rep.HighParamFuncs) != 1 || rep.HighParamFuncs[0].Value != 7 || rep.HighParamFuncs[0].Symbol != "Svc.busy" {
		t.Errorf("params: %+v", rep.HighParamFuncs)
	}
	if rep.WorstNest.Value != 5 || len(rep.DeepNestFuncs) != 1 {
		t.Errorf("nesting: worst=%+v deep=%+v", rep.WorstNest, rep.DeepNestFuncs)
	}
	if len(rep.HighComplexity) != 1 || rep.HighComplexity[0].Value < 14 {
		t.Errorf("cyclomatic: %+v", rep.HighComplexity)
	}
	ids := issueIDs(rep.ShapeIssues)
	for _, want := range []string{"shape-returns", "shape-class-attrs", "shape-class-bases"} {
		if !hasRule(ids, want) {
			t.Errorf("missing %s in %v", want, ids)
		}
	}
}

func TestCyclomaticOnBraceLanguages(t *testing.T) {
	var b strings.Builder
	b.WriteString("package p\nfunc Big(a, b, c int) int {\n")
	for i := 0; i < 11; i++ {
		fmt.Fprintf(&b, "\tif a == %d && b > c {\n\t\ta++\n\t}\n", i)
	}
	b.WriteString("\treturn a\n}\nfunc Small(a int) int {\n\tif a > 0 {\n\t\treturn 1\n\t}\n\treturn 0\n}\n")
	rep := csAnalyze([]*parser.ParsedFile{writeFile(t, ".go", b.String())})
	if len(rep.HighComplexity) != 1 || rep.HighComplexity[0].Symbol != "Big" || rep.HighComplexity[0].Value != 23 {
		t.Errorf("go cyclomatic: %+v", rep.HighComplexity)
	}
}
