package constructs

import (
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func cloneIssues(t *testing.T, files ...*parser.ParsedFile) []CSIssue {
	t.Helper()
	rep := csAnalyze(files)
	var out []CSIssue
	for _, is := range rep.DupIssues {
		if is.RuleID == "dup-clone" {
			out = append(out, is)
		}
	}
	return out
}

func TestCloneDetectionAcrossFiles(t *testing.T) {
	extra := ""
	for i := 0; i < 8; i++ {
		extra += "\tstep" + string(rune('A'+i)) + " := process(input, options.Level" + string(rune('A'+i)) + ", cache)\n\tlogger.Printf(\"step %v\", step" + string(rune('A'+i)) + ")\n"
	}
	block := extra + "\tvalue := compute(input, options)\n\tif value == nil {\n\t\treturn nil, errors.New(\"no value computed\")\n\t}\n\tresult := transform(value, options.Mode)\n\tlogger.Printf(\"computed %v\", result)\n\tcache.Store(input.Key, result)\n\tmetrics.Observe(\"compute\", time.Since(start))\n"
	a := writeFile(t, ".go", "package a\nimport \"x\"\nfunc A(input In, options Opt) (*Out, error) {\n\tstart := time.Now()\n"+block+"\treturn result, nil\n}\n")
	b := writeFile(t, ".go", "package b\nimport \"y\"\nfunc B(input In, options Opt) (*Out, error) {\n\tstart := time.Now()\n\tprepare()\n"+block+"\treturn result, nil\n}\n")
	got := cloneIssues(t, a, b)
	if len(got) != 1 {
		t.Fatalf("want 1 clone, got %d: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Detail, "also in") {
		t.Errorf("detail should point at the twin: %q", got[0].Detail)
	}
}

func TestCloneIgnoresImportsBoilerplateAndShortRuns(t *testing.T) {
	imports := "package a\nimport (\n\t\"fmt\"\n\t\"os\"\n\t\"strings\"\n\t\"errors\"\n\t\"time\"\n\t\"sync\"\n)\n"
	x := writeFile(t, ".go", imports+"func X() int {\n\treturn 1\n}\n")
	y := writeFile(t, ".go", imports+"func Y() int {\n\treturn 2\n}\n")
	if got := cloneIssues(t, x, y); len(got) != 0 {
		t.Errorf("shared imports/boilerplate flagged: %+v", got)
	}
	short := writeFile(t, ".go", "package a\nfunc S() {\n\ta()\n\tb()\n\tc()\n}\n")
	short2 := writeFile(t, ".go", "package b\nfunc T() {\n\ta()\n\tb()\n\tc()\n}\n")
	if got := cloneIssues(t, short, short2); len(got) != 0 {
		t.Errorf("tiny runs flagged: %+v", got)
	}
}

func TestCloneWorksOnPythonAndIsSuppressible(t *testing.T) {
	pad := ""
	for i := 0; i < 8; i++ {
		pad += "    stage" + string(rune('a'+i)) + " = run_stage(connection, \"stage" + string(rune('a'+i)) + "\", parameters, retries=3)\n    record(stage" + string(rune('a'+i)) + ", destination)\n"
	}
	body := pad + "    rows = fetch_rows(connection, query, parameters)\n    cleaned = [normalise(r) for r in rows if r is not None]\n    grouped = group_by_key(cleaned, key_function)\n    totals = {k: sum(v) for k, v in grouped.items()}\n    report = build_report(totals, title, formatter)\n    publish(report, destination, retries=3)\n"
	a := writeFile(t, ".py", "def a(connection, query, parameters, key_function, title, formatter, destination):\n"+body+"    return report\n")
	b := writeFile(t, ".py", "def b(connection, query, parameters, key_function, title, formatter, destination):\n"+body+"    return None\n")
	if got := cloneIssues(t, a, b); len(got) != 1 {
		t.Fatalf("python clone: %+v", got)
	}
	c := writeFile(t, ".py", "def a(connection, query, parameters, key_function, title, formatter, destination):  # noqa: R0801\n"+body+"    return report\n")
	d := writeFile(t, ".py", "def b(connection, query, parameters, key_function, title, formatter, destination):\n"+body+"    return None\n")
	got := cloneIssues(t, c, d)
	if len(got) > 1 {
		t.Errorf("unexpected: %+v", got)
	}
}

func TestCloneBelowFifteenLinesIsNotReported(t *testing.T) {
	block := ""
	for i := 0; i < 6; i++ {
		block += "\tstep" + string(rune('A'+i)) + " := process(input, options.Level" + string(rune('A'+i)) + ", cache)\n\tlogger.Printf(\"step %v\", step" + string(rune('A'+i)) + ")\n"
	}
	a := writeFile(t, ".go", "package a\nfunc A(input In, options Opt) {\n"+block+"}\n")
	b := writeFile(t, ".go", "package b\nfunc B(input In, options Opt) {\n"+block+"}\n")
	if got := cloneIssues(t, a, b); len(got) != 0 {
		t.Errorf("a 12-line repeat must not be reported: %+v", got)
	}
}
