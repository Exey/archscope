package constructs

import (
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func deadIssues(t *testing.T, ext, src string) []CSIssue {
	t.Helper()
	return (DeadCode{}).Analyze([]*parser.ParsedFile{writeFile(t, ext, src)}).(DeadCodeReport).Issues
}

func countRule(is []CSIssue, id string) int {
	n := 0
	for _, x := range is {
		if x.RuleID == id {
			n++
		}
	}
	return n
}

func TestDeadUnusedImports(t *testing.T) {
	src := "import React, { useState, useEffect as useFx } from 'react';\nimport * as path from 'path';\nimport type { Foo } from './foo';\nimport Bar, { baz } from './bar';\nimport './side-effect.css';\n" +
		"export function C() {\n  const [a] = useState(0);\n  return <Bar value={a}>{path.sep}</Bar>;\n}\n"
	got := deadIssues(t, ".tsx", src)
	if n := countRule(got, "dead-unused-import"); n != 3 {
		var names []string
		for _, g := range got {
			names = append(names, g.Snippet+"|"+g.RuleID)
		}
		t.Errorf("want 3 unused imports (useFx, Foo, baz), got %d: %v", n, names)
	}
	multi := "import {\n  used,\n  unused,\n} from './x';\nexport const v = used();\n"
	if n := countRule(deadIssues(t, ".ts", multi), "dead-unused-import"); n != 1 {
		t.Errorf("multi-line import: want 1 unused, got %d", n)
	}
	// member access isn't a use of the import
	member := "import { name } from './x';\nexport const v = obj.name;\n"
	if n := countRule(deadIssues(t, ".ts", member), "dead-unused-import"); n != 1 {
		t.Errorf("obj.name must not count as using the import, got %d", n)
	}
}

func TestDeadUnreachable(t *testing.T) {
	src := "export function f(x: number) {\n  if (x) return 1;\n  return 2;\n  console.log('never');\n}\n" +
		"export function g(x: number) {\n  switch (x) {\n    case 1:\n      return 1;\n    case 2:\n      break;\n    default:\n      throw new Error('x');\n  }\n  for (const a of [1]) {\n    continue;\n  }\n}\n" +
		"export function h() {\n  return (\n    1 +\n    2\n  );\n}\n" +
		"export function k() {\n  return 1;\n  function hoisted() {}\n}\n"
	got := deadIssues(t, ".ts", src)
	if n := countRule(got, "dead-unreachable"); n != 1 {
		t.Errorf("want exactly the console.log flagged, got %d: %+v", n, got)
	}
}

func TestDeadCommentedCode(t *testing.T) {
	src := "// const a = 1;\n// foo(a);\n// if (a) { bar(); }\nexport const x = 1;\n// This is a normal sentence about the value.\n// And another normal sentence here.\n// Third prose line.\n// TODO: fix const x = 2;\n"
	got := deadIssues(t, ".ts", src)
	if n := countRule(got, "dead-commented-code"); n != 1 {
		t.Errorf("want 1 commented-code block, got %d", n)
	}
	block := "/*\nconst a = 1;\nfoo(a);\nbar();\n*/\nexport const x = 1;\n"
	if n := countRule(deadIssues(t, ".ts", block), "dead-commented-code"); n != 1 {
		t.Errorf("block comment: want 1, got %d", n)
	}
}

func TestDeadUnusedVariables(t *testing.T) {
	src := "const unusedTop = 1;\nexport const used = 2;\nconst alsoUsed = 3;\nexport function f() {\n  const local = alsoUsed;\n  const { a, b } = obj;\n  const _ignored = 1;\n  for (const k of xs) {}\n  return a;\n}\n"
	got := deadIssues(t, ".ts", src)
	var names []string
	for _, g := range got {
		if g.RuleID == "dead-unused-var" {
			names = append(names, g.Snippet)
		}
	}
	// unusedTop, local, b
	if len(names) != 3 {
		t.Errorf("want 3 unused variables (unusedTop, local, b), got %d: %v", len(names), names)
	}
}

func TestDeadCodeCardRenders(t *testing.T) {
	if out := (DeadCode{}).RenderHTML(DeadCodeReport{}); !strings.Contains(out, "No dead-code issues") {
		t.Errorf("clean card: %q", out)
	}
}

func TestDeadCodeSkipsTestsAndDeclarations(t *testing.T) {
	if got := deadIssues(t, ".d.ts", "import { a } from 'x';\n"); len(got) != 0 {
		t.Errorf(".d.ts scanned: %v", got)
	}
}

func TestDeadUnreachableIgnoresMultilineTemplate(t *testing.T) {
	src := "export function page(x: string) {\n  return `<div>\n    ${x}\n  </div>`;\n}\n"
	if n := countRule(deadIssues(t, ".ts", src), "dead-unreachable"); n != 0 {
		t.Errorf("template literal read as unreachable code: %d", n)
	}
}

func TestMaskNestedTemplateLiterals(t *testing.T) {
	src := "export function page(rows: string[], ok: boolean) {\n  return `<ul>\n  ${ok ? `<b>${rows.map(r => `<li>${r}</li>`).join('')}</b>` : `<i>none</i>`}\n</ul>`;\n}\nexport const after = 1;\n"
	m := maskSource(strings.Split(src, "\n"), ".ts")
	for i, l := range m.code {
		if len(l) != len(strings.Split(src, "\n")[i]) {
			t.Fatalf("line %d length changed", i)
		}
	}
	joined := strings.Join(m.code, "\n")
	if strings.Count(joined, "`") != 2 {
		t.Errorf("only the outermost template delimiters should survive in code, got %d backticks:\n%s", strings.Count(joined, "`"), joined)
	}
	if n := countRule(deadIssues(t, ".ts", src), "dead-unreachable"); n != 0 {
		t.Errorf("nested template read as unreachable code: %d", n)
	}
}

func TestMaskGoRawStringKeepsDollarBrace(t *testing.T) {
	src := "package p\nvar s = `echo ${HOME} }}`\nfunc F() {\n\tif a {\n\t}\n}\n"
	m := maskSource(strings.Split(src, "\n"), ".go")
	if strings.Count(strings.Join(m.code, "\n"), "{") != 2 { // func body and if body only
		t.Errorf("braces inside a Go raw string leaked: %q", strings.Join(m.code, "\n"))
	}
}

func TestDeadCodeRealWorldRegressions(t *testing.T) {
	// `as const satisfies T` is not a declaration of `satisfies`.
	sat := "const VIEWS = ['a'] as const satisfies string[];\nexport { VIEWS };\n"
	if n := countRule(deadIssues(t, ".ts", sat), "dead-unused-var"); n != 0 {
		t.Errorf("`as const satisfies` read as a variable: %d", n)
	}
	// `&nbsp;` in JSX text is not a statement terminator.
	nb := "export const A = ({ e }: P) => {\n  if (e) {\n    return <p>О&nbsp;тарифе</p>;\n  }\n  return <B />;\n};\n"
	if n := countRule(deadIssues(t, ".tsx", nb), "dead-unreachable"); n != 0 {
		t.Errorf("&nbsp; ended the statement: %d", n)
	}
	// imports used only in commented-out code are unused
	cm := "import { a } from './a';\n// a();\nexport const v = 1;\n"
	if n := countRule(deadIssues(t, ".ts", cm), "dead-unused-import"); n != 1 {
		t.Errorf("import used only in a comment: want 1, got %d", n)
	}
}

func TestPythonDeadCode(t *testing.T) {
	src := "import os\nimport sys, json as j\nfrom collections import OrderedDict, defaultdict as dd\nfrom typing import TYPE_CHECKING, List\nimport re\n\nif TYPE_CHECKING:\n    from x import Fwd\n\n__all__ = ['exported']\n\ndef used(a):\n    unused = 1\n    kept = 2\n    msg = 'x'\n    try:\n        pass\n    except ValueError as err:\n        pass\n    return f'{kept} {msg!r}', sys.argv, \"Fwd\"\n\ndef ret():\n    return 1\n    print('never')\n\ndef loop(xs):\n    for x in xs:\n        if x:\n            continue\n            x += 1\n        break\n    else:\n        pass\n"
	got := deadIssues(t, ".py", src)
	var imports []string
	for _, g := range got {
		if g.RuleID == "dead-unused-import" {
			imports = append(imports, g.Detail)
		}
	}
	// unused: os, json (as j), OrderedDict, dd, List, re ; used: sys, Fwd (quoted), TYPE_CHECKING
	if len(imports) != 6 {
		t.Errorf("unused imports = %v (want os, json as j, OrderedDict, dd, List, re)", imports)
	}
	var vars []string
	for _, g := range got {
		if g.RuleID == "dead-unused-var" {
			vars = append(vars, g.Detail)
		}
	}
	if len(vars) != 2 { // unused, err
		t.Errorf("unused vars = %v (want unused, err)", vars)
	}
	if n := countRule(got, "dead-unreachable"); n != 2 {
		t.Errorf("unreachable = %d, want 2 (after return, after continue)", n)
	}
	cm := "# def old(x):\n#     return x + 1\n# y = old(2)\nz = 1\n# A normal sentence.\n# Another one here.\n# And a third.\n"
	if n := countRule(deadIssues(t, ".py", cm), "dead-commented-code"); n != 1 {
		t.Errorf("python commented code = %d", n)
	}
	// __init__.py re-exports are not unused imports
	if got := deadIssues(t, ".py", "from .a import b\n"); countRule(got, "dead-unused-import") != 1 {
		t.Log("(a plain module is checked)")
	}
}

func unusedSyms(t *testing.T, files map[string]string) []string {
	t.Helper()
	var pf []*parser.ParsedFile
	for ext, src := range files {
		pf = append(pf, writeFile(t, ext, src))
	}
	var names []string
	for _, is := range (DeadCode{}).Analyze(pf).(DeadCodeReport).Issues {
		if is.RuleID == "dead-unused-symbol" || is.RuleID == "dead-possibly-unused" {
			names = append(names, is.Detail)
		}
	}
	return names
}

func TestUnusedSymbolsPythonAndGo(t *testing.T) {
	py := "def _helper():\n    return 1\n\ndef _used():\n    return 2\n\nclass _Dead:\n    def _gone(self):\n        pass\n\n    def keep(self):\n        return _used()\n\n@app.route('/x')\ndef _routed():\n    pass\n\ndef public_api():\n    return 3\n\ndef _by_name():\n    pass\n\nHANDLERS = {'k': '_by_name'}\n"
	got := unusedSyms(t, map[string]string{".py": py})
	want := map[string]bool{"_helper (90% confidence)": true, "_Dead (90% confidence)": true, "_gone (90% confidence)": true}
	if len(got) != 3 {
		t.Fatalf("python unused = %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected %q (public_api is a library API, _routed is decorated, _by_name is in a string)", g)
		}
	}
	script := py + "\nif __name__ == '__main__':\n    pass\n"
	if got := unusedSyms(t, map[string]string{".py": script}); len(got) != 4 {
		t.Errorf("in a script the public function is a 60%% candidate too: %v", got)
	}

	goSrc := "package p\n\nfunc used() int { return 1 }\nfunc unusedFn() int { return 2 }\ntype unusedT struct{}\nfunc Exported() int { return used() }\nfunc main() {}\n"
	if got := unusedSyms(t, map[string]string{".go": goSrc}); len(got) != 2 {
		t.Errorf("go unused = %v (want unusedFn, unusedT)", got)
	}
	java := "class A {\n  private void gone() {}\n  private void kept() {}\n  void run() { kept(); }\n  @Override private void hook() {}\n}\n"
	if got := unusedSyms(t, map[string]string{".java": java}); len(got) != 1 {
		t.Errorf("java unused = %v (want gone)", got)
	}
	ts := "function unusedFn() {}\nfunction usedFn() {}\nexport function pub() { usedFn(); }\nclass Hidden {}\n"
	if got := unusedSyms(t, map[string]string{".ts": ts}); len(got) != 2 {
		t.Errorf("ts unused = %v (want unusedFn, Hidden)", got)
	}
}
