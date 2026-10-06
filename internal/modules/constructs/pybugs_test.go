package constructs

import (
	"strings"
	"testing"
)

func pyBugIDs(t *testing.T, src string) []string {
	t.Helper()
	return issueIDs(pyReport(t, src).BugIssues)
}

func TestPythonBugClassChecks(t *testing.T) {
	src := "import time\n" +
		"def f(a, items=[], opts={}, n=None):\n    return items\n\n" +
		"def g(x):\n    try:\n        risky()\n    except:\n        pass\n    try:\n        risky()\n    except Exception:\n        pass\n" +
		"    try:\n        risky()\n    except ValueError as e:\n        raise RuntimeError('bad')\n" +
		"    if x is 'a' or x is not 3:\n        pass\n    assert (x, 'message')\n    if x == None:\n        pass\n" +
		"    name = f'plain text'\n    d = {'a': 1, 'b': 2, 'a': 3}\n    return d\n\n" +
		"def h():\n    try:\n        run()\n    finally:\n        return 1\n\n" +
		"def k(xs):\n    fs = []\n    for i in xs:\n        fs.append(lambda: i * 2)\n    return fs\n\n" +
		"async def a():\n    time.sleep(1)\n    return 1\n\n" +
		"def cmp(a):\n    return a == a\n\n" +
		"from os import *\nlist = []\n"
	ids := pyBugIDs(t, src)
	for _, want := range []string{"py-mutable-default", "py-bare-except", "py-except-pass", "py-raise-no-from", "py-is-literal", "py-assert-tuple", "py-singleton-compare", "py-fstring-no-placeholder", "py-dup-dict-key", "py-finally-return", "py-lambda-loop-var", "py-blocking-async", "py-dup-operand", "py-wildcard-import", "py-redefined-builtin"} {
		if !hasRule(ids, want) {
			t.Errorf("missing %s in %v", want, ids)
		}
	}
	n := 0
	for _, id := range ids {
		if id == "py-mutable-default" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("want 2 mutable defaults (items, opts), got %d", n)
	}
}

func TestPythonBugClassNoFalsePositives(t *testing.T) {
	src := "import asyncio\n" +
		"def f(a, items=None, n=(1, 2), s='x'):\n    items = items or []\n    return items\n\n" +
		"def g(x):\n    try:\n        risky()\n    except ValueError:\n        pass\n" +
		"    try:\n        risky()\n    except KeyError as e:\n        raise RuntimeError('bad') from e\n" +
		"    if x is None or x is not True:\n        pass\n    assert x, 'message'\n" +
		"    name = f'{x} items'\n    d = {'a': 1, 'b': 2}\n    s = {1, 2, 3}\n    v = {k: 1 for k in x}\n" +
		"    fs = sorted(x, key=lambda y: y.i)\n    for i in x:\n        fs.append(lambda i=i: i)\n    return d\n\n" +
		"async def a():\n    await asyncio.sleep(1)\n    def inner():\n        import time\n        time.sleep(1)\n    return inner\n\n" +
		"def cmp(a, b):\n    return a == b or a - b\n"
	if ids := pyBugIDs(t, src); len(ids) != 0 {
		t.Errorf("false positives: %v", ids)
	}
}

func TestPythonFStringKeepsRealPlaceholders(t *testing.T) {
	src := "def f(x):\n    a = f'{x}'\n    b = rf'{x}\\d'\n    c = 'f' + \"f'plain'\"\n    d = f\"\"\"multi {x}\"\"\"\n    return a, b, c, d\n"
	if ids := pyBugIDs(t, src); hasRule(ids, "py-fstring-no-placeholder") {
		t.Errorf("flagged a real f-string: %v", ids)
	}
}

func TestSuppressionCommentsSilenceReviewChecks(t *testing.T) {
	src := "def f(a=[]):  # noqa: B006\n    return a\n\ndef g(b={}):  # pylint: disable=dangerous-default-value\n    return b\n\ndef h(c=[]):\n    return c\n"
	got := pyBugIDs(t, src)
	n := 0
	for _, id := range got {
		if id == "py-mutable-default" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("only the unsuppressed def h should be flagged, got %d: %v", n, got)
	}
	// `# noqa` with a code that isn't ours must not hide it
	other := "def f(a=[]):  # noqa: E501\n    return a\n"
	if ids := pyBugIDs(t, other); !hasRule(ids, "py-mutable-default") {
		t.Errorf("unrelated noqa code hid the finding: %v", ids)
	}
	// a go-critic style //nolint above a function silences its Go bug-class issues
	goSrc := "package p\n//nolint:gocritic\nfunc F(a int) bool {\n\treturn a == a\n}\n"
	if ids := issueIDs(goReport(t, goSrc).BugIssues); len(ids) != 0 {
		t.Errorf("//nolint:gocritic ignored: %v", ids)
	}
	// complexity offenders honour nolint:gocyclo
	var b strings.Builder
	b.WriteString("package p\n//nolint:gocyclo\nfunc Big(a int) int {\n")
	for i := 0; i < 12; i++ {
		b.WriteString("\tif a > 1 && a < 5 {\n\t\ta++\n\t}\n")
	}
	b.WriteString("\treturn a\n}\n")
	if rep := goReport(t, b.String()); len(rep.HighComplexity) != 0 {
		t.Errorf("nolint:gocyclo ignored: %+v", rep.HighComplexity)
	}
}

func TestPythonDictWithLambdaValuesIsNotSplitOnLambdaCommas(t *testing.T) {
	src := "FMT = {\n    A: lambda e, _: (1, 2),\n    B: lambda _, t: (3, 4),\n}\n"
	if ids := pyBugIDs(t, src); hasRule(ids, "py-dup-dict-key") {
		t.Errorf("lambda parameter commas split dict entries: %v", ids)
	}
}
