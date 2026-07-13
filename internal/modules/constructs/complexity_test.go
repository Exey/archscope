package constructs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

// cxFile writes src to a temp file and returns a ParsedFile pointing at it.
func cxFile(t *testing.T, ext, src string) *parser.ParsedFile {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f"+ext)
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return &parser.ParsedFile{FilePath: p, ModuleName: "m", Declarations: nil}
}

func report(files ...*parser.ParsedFile) ComplexityReport {
	return (Complexity{}).Analyze(files).(ComplexityReport)
}

func TestNestedLoopsAreQuadratic(t *testing.T) {
	src := `func crossJoin(a []int, b []int) {
    for i := range a {
        for j := range b {
            _ = a[i] + b[j]
        }
    }
}
`
	r := report(cxFile(t, ".go", src))
	if len(r.TimeViolations) != 1 {
		t.Fatalf("want 1 time violation, got %d: %+v", len(r.TimeViolations), r.TimeViolations)
	}
	v := r.TimeViolations[0]
	if v.Order != 2 || v.bigO() != "O(N²)" {
		t.Errorf("want O(N²), got %s (order %d)", v.bigO(), v.Order)
	}
	if v.Symbol != "crossJoin" {
		t.Errorf("want symbol crossJoin, got %q", v.Symbol)
	}
	if r.TimeHealth != 0 {
		t.Errorf("one loop-scope, all violating → time health 0, got %d", r.TimeHealth)
	}
}

func TestSingleLoopIsClean(t *testing.T) {
	src := `func sum(a []int) int {
    total := 0
    for i := range a {
        total += a[i]
    }
    return total
}
`
	r := report(cxFile(t, ".go", src))
	if len(r.TimeViolations) != 0 {
		t.Errorf("single loop must not violate: %+v", r.TimeViolations)
	}
	if r.TimeHealth != 100 {
		t.Errorf("clean loop → time health 100, got %d", r.TimeHealth)
	}
}

func TestLinearOpInsideLoopViolates(t *testing.T) {
	// A .sorted() inside a single loop is charged one level deeper → O(N²).
	src := `func f(rows []Row) {
    for r in rows {
        let top = r.items.sorted(by: <)
        use(top)
    }
}
`
	r := report(cxFile(t, ".swift", src))
	found := false
	for _, v := range r.TimeViolations {
		if strings.Contains(v.Reason, ".sorted()") && v.Order == 2 {
			found = true
		}
	}
	if !found {
		t.Errorf("want a .sorted()-inside-loop O(N²) violation, got %+v", r.TimeViolations)
	}
}

func TestAllocationInsideLoopIsSpaceViolation(t *testing.T) {
	src := `func build(rows []Row) {
    for r in rows {
        var scratch = [Int]()
        scratch.append(r.id)
    }
}
`
	r := report(cxFile(t, ".swift", src))
	if len(r.SpaceViolations) == 0 {
		t.Fatalf("want a space violation for allocation inside loop, got none")
	}
	if !strings.Contains(r.SpaceViolations[0].Reason, "allocates") {
		t.Errorf("space reason should mention allocation: %q", r.SpaceViolations[0].Reason)
	}
}

func TestNestedHOFClosureIsQuadratic(t *testing.T) {
	// map { … filter { … } } — two nested higher-order closures → O(N²).
	src := `func f(xs: [[Int]]) {
    let r = xs.map { row in
        row.filter { v in
            v > 0
        }
    }
    _ = r
}
`
	r := report(cxFile(t, ".swift", src))
	got := 0
	for _, v := range r.TimeViolations {
		if v.Order >= 2 {
			got++
		}
	}
	if got == 0 {
		t.Errorf("nested HOF closures should be O(N²)+, got %+v", r.TimeViolations)
	}
}

func TestCollectionUsageCounted(t *testing.T) {
	src := `struct S {
    var a: [Int] = []
    var d: [String: Int] = [:]
    let s = Set<Int>()
    func lazyChain(xs: Array<Int>) { _ = xs.lazy.map { $0 } }
}
`
	u := report(cxFile(t, ".swift", src)).Usage
	if u.Array == 0 {
		t.Errorf("expected Array usage counted, got %+v", u)
	}
	if u.Dictionary == 0 {
		t.Errorf("expected Dictionary usage counted, got %+v", u)
	}
	if u.Set == 0 {
		t.Errorf("expected Set usage counted, got %+v", u)
	}
	if u.Lazy == 0 {
		t.Errorf("expected .lazy usage counted, got %+v", u)
	}
}

func TestControlFlowIsNotALoop(t *testing.T) {
	// if / guard / switch braces must not count as loops.
	src := `func f(x: Int) {
    if x > 0 {
        guard x < 10 else { return }
        switch x {
        case 1: break
        default: break
        }
    }
}
`
	r := report(cxFile(t, ".swift", src))
	if len(r.TimeViolations) != 0 {
		t.Errorf("control-flow braces must not be loops: %+v", r.TimeViolations)
	}
}

func TestAssignmentArrayLiteralVsComparison(t *testing.T) {
	if !containsAssignmentArrayLiteral("arr = [1, 2, 3]") {
		t.Error("assignment to array literal should be detected")
	}
	if containsAssignmentArrayLiteral("if x == [] { return }") {
		t.Error("== [] comparison must not read as assignment")
	}
	if containsAssignmentArrayLiteral("if x >= [] { return }") {
		t.Error(">= [] comparison must not read as assignment")
	}
}

func TestRenderHasHealthAndViolations(t *testing.T) {
	src := `func crossJoin(a []int, b []int) {
    for i := range a {
        for j := range b {
            _ = a[i] + b[j]
        }
    }
}
`
	out := (Complexity{}).RenderHTML(report(cxFile(t, ".go", src)))
	for _, want := range []string{"Time O-Health", "Space O-Health", "O(N²)", "crossJoin", "vscode://file"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q:\n%s", want, out)
		}
	}
}

func TestEmptyReportRendersNothing(t *testing.T) {
	src := "package p\nvar x = 1\n"
	if out := (Complexity{}).RenderHTML(report(cxFile(t, ".go", src))); out != "" {
		t.Errorf("no collections/loops → empty render, got %q", out)
	}
}
