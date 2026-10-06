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
