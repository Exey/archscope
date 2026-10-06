package constructs

import (
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func tsxReport(t *testing.T, src string) CodeStructureReport {
	t.Helper()
	return csAnalyze([]*parser.ParsedFile{writeFile(t, ".tsx", src)})
}

func TestReactSetStateInEffectWithoutDeps(t *testing.T) {
	src := "import { useState, useEffect } from 'react';\n" +
		"export function Counter() {\n  const [n, setN] = useState(0);\n  useEffect(() => {\n    setN(n + 1);\n  });\n  return <div>{n}</div>;\n}\n"
	ids := issueIDs(tsxReport(t, src).HookIssues)
	if !hasRule(ids, "react-setstate-effect-loop") {
		t.Errorf("effect loop missed: %v", ids)
	}
	if hasRule(ids, "react-missing-deps") {
		t.Errorf("the same call must not also report missing-deps: %v", ids)
	}
}

func TestReactMissingDeps(t *testing.T) {
	src := "export function Profile({ userId }: Props) {\n  const [data, setData] = useState(null);\n" +
		"  useEffect(() => {\n    fetchUser(userId).then(setData);\n  }, []);\n" +
		"  const cb = useCallback(() => { console.log(data); }, []);\n" +
		"  const memo = useMemo(() => compute(userId));\n" +
		"  useEffect(() => { track(); });\n" +
		"  return <div>{data}</div>;\n}\n"
	got := tsxReport(t, src).HookIssues
	n := 0
	for _, is := range got {
		if is.RuleID == "react-missing-deps" {
			n++
		}
	}
	if n != 4 {
		t.Errorf("want 4 missing-deps hits, got %d: %v", n, issueIDs(got))
	}
	ok := "export function P({ userId }: Props) {\n  const [d, setD] = useState(null);\n" +
		"  useEffect(() => {\n    fetchUser(userId).then(setD);\n  }, [userId]);\n  return <div>{d}</div>;\n}\n"
	if ids := issueIDs(tsxReport(t, ok).HookIssues); len(ids) != 0 {
		t.Errorf("complete deps flagged: %v", ids)
	}
}

func TestReactDirectMutation(t *testing.T) {
	src := "export function List() {\n  const [items, setItems] = useState<string[]>([]);\n  const [obj, setObj] = useState({ a: 1 });\n" +
		"  const add = () => {\n    items.push('x');\n    obj.a = 2;\n    setItems(items);\n  };\n" +
		"  const ok = () => setItems([...items, 'x']);\n  return <ul>{items.map(i => <li key={i}>{i}</li>)}</ul>;\n}\n"
	n := 0
	for _, is := range tsxReport(t, src).HookIssues {
		if is.RuleID == "react-direct-mutation" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("want 2 mutation hits (push + property assign), got %d", n)
	}
}

func TestReactDerivedStateAndEffectAsHandler(t *testing.T) {
	derived := "export function Form({ value }: P) {\n  const [v, setV] = useState(value);\n  useEffect(() => { setV(value); }, [value]);\n  return <input value={v} />;\n}\n"
	if ids := issueIDs(tsxReport(t, derived).HookIssues); !hasRule(ids, "react-derived-state") {
		t.Errorf("derived state missed: %v", ids)
	}
	handler := "export function Save() {\n  const [shouldSave, setShouldSave] = useState(false);\n  const [saved, setSaved] = useState(false);\n" +
		"  useEffect(() => {\n    if (shouldSave) {\n      setSaved(true);\n      setShouldSave(false);\n    }\n  }, [shouldSave]);\n  return <button onClick={() => setShouldSave(true)}>{String(saved)}</button>;\n}\n"
	if ids := issueIDs(tsxReport(t, handler).HookIssues); !hasRule(ids, "react-effect-as-handler") {
		t.Errorf("effect-as-handler missed: %v", ids)
	}
}

func TestReactStateInRef(t *testing.T) {
	src := "export function C() {\n  const countRef = useRef(0);\n  const inc = () => { countRef.current += 1; };\n" +
		"  return <div onClick={() => countRef.current++}><p>{countRef.current}</p></div>;\n}\n"
	got := tsxReport(t, src).HookIssues
	n := 0
	for _, is := range got {
		if is.RuleID == "react-state-in-ref" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("want exactly the JSX child read flagged, got %d: %v", n, issueIDs(got))
	}
}

func TestReactIndexKey(t *testing.T) {
	bad := "export const L = ({ xs }: P) => <ul>{xs.map((x, i) => <li key={i}>{x}</li>)}</ul>;\n"
	if ids := issueIDs(tsxReport(t, bad).HookIssues); !hasRule(ids, "react-index-key") {
		t.Errorf("index key missed: %v", ids)
	}
	tpl := "export const L = ({ xs }: P) => <ul>{xs.map((x, idx) => <li key={`row-${idx}`}>{x}</li>)}</ul>;\n"
	if ids := issueIDs(tsxReport(t, tpl).HookIssues); !hasRule(ids, "react-index-key") {
		t.Errorf("template index key missed: %v", ids)
	}
	good := "export const L = ({ xs }: P) => <ul>{xs.map((x, i) => <li key={x.id}>{i}</li>)}</ul>;\n"
	if ids := issueIDs(tsxReport(t, good).HookIssues); hasRule(ids, "react-index-key") {
		t.Errorf("stable key flagged: %v", ids)
	}
}

func TestReactComponentRules(t *testing.T) {
	var b strings.Builder
	b.WriteString("export function Big({ a, b, c, d, e, f, g, h }: P) {\n  return (\n    <div>\n")
	for i := 0; i < 260; i++ {
		b.WriteString("      <span>x</span>\n")
	}
	b.WriteString("    </div>\n  );\n}\n")
	ids := issueIDs(tsxReport(t, b.String()).ReactIssues)
	for _, want := range []string{"react-max-lines", "react-max-props"} {
		if !hasRule(ids, want) {
			t.Errorf("missing %s in %v", want, ids)
		}
	}

	deep := "export function Deep() {\n  return (\n    <A><B><C><D><E><F><G>x</G></F></E></D></C></B></A>\n  );\n}\n"
	if ids := issueIDs(tsxReport(t, deep).ReactIssues); !hasRule(ids, "react-deep-jsx") {
		t.Errorf("deep jsx missed: %v", ids)
	}
	shallow := "export function S() {\n  return <A><B><C>x</C></B></A>;\n}\n"
	if ids := issueIDs(tsxReport(t, shallow).ReactIssues); len(ids) != 0 {
		t.Errorf("shallow jsx flagged: %v", ids)
	}

	drill := "export function Parent({ user, theme, lang, extra }: P) {\n  return <Child user={user} theme={theme} lang={lang} other={extra} />;\n}\n"
	if ids := issueIDs(tsxReport(t, drill).ReactIssues); !hasRule(ids, "react-prop-drilling") {
		t.Errorf("prop drilling missed: %v", ids)
	}
}

func TestReactIgnoresNonComponentsAndGenerics(t *testing.T) {
	src := "export function helper(a: number, b: number) {\n  const m = new Map<string, Array<number>>();\n  if (a < b) { return m; }\n  return null;\n}\n"
	rep := tsxReport(t, src)
	if len(rep.HookIssues)+len(rep.ReactIssues) != 0 {
		t.Errorf("non-component flagged: %v %v", issueIDs(rep.HookIssues), issueIDs(rep.ReactIssues))
	}
}

func TestReactNoFalsePositivesFromRealCode(t *testing.T) {
	// JSX attribute `search={search}` is not an assignment to state `search`;
	// `className="…"` inside a memo callback is not a read of the className prop;
	// a guarded effect that resets state when a prop changes is intentional.
	src := "export function H({ className, open, to = 'a' }: P) {\n  const [search, setSearch] = useState('');\n  const [section, setSection] = useState(to);\n" +
		"  const content = useMemo(() => {\n    return <ul className=\"x\">y</ul>;\n  }, []);\n" +
		"  useEffect(() => {\n    if (open) setSection(to);\n  }, [open, to]);\n" +
		"  return <History onSearchChange={setSearch} search={search} className={className} />;\n}\n"
	rep := tsxReport(t, src)
	if ids := issueIDs(rep.HookIssues); len(ids) != 0 {
		t.Errorf("false positives: %v", ids)
	}
}

func TestDeadUnreachableArrowBodyOnNextLine(t *testing.T) {
	src := "const useX = () => {\n  const q = useQ();\n\n  return () =>\n    q.invalidate({\n      predicate: (x) => x.key,\n    });\n};\n\nexport { useX };\n"
	if n := countRule(deadIssues(t, ".ts", src), "dead-unreachable"); n != 0 {
		t.Errorf("arrow body on the next line read as unreachable: %d", n)
	}
}

func TestReactHonoursExhaustiveDepsDisableComment(t *testing.T) {
	src := "export function Q({ onChange }: P) {\n  const [key, setKey] = useState('a');\n  useEffect(() => {\n    onChange?.(key);\n    // eslint-disable-next-line react-hooks/exhaustive-deps\n  }, []);\n  return <div />;\n}\n"
	if ids := issueIDs(tsxReport(t, src).HookIssues); hasRule(ids, "react-missing-deps") {
		t.Errorf("deliberately silenced deps flagged: %v", ids)
	}
}
