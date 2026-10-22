package constructs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func TestGoConstFieldsAndParams(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) *parser.ParsedFile {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(src), 0o644)
		return &parser.ParsedFile{FilePath: p, LanguageID: "go"}
	}
	a := write("a.go", "package a\n\ntype Person struct {\n\t// Name is fixed.\n\t// +const\n\tName string\n\tAge  int\n\tEmail string // +const\n}\n\nfunc NewPerson(n string) *Person {\n\tp := &Person{}\n\tp.Name = n\n\treturn p\n}\n\nfunc (p *Person) Rename(n string) {\n\tp.Name = n\n}\n\nfunc (p *Person) Birthday() {\n\tp.Age++\n}\n\nfunc Update(p *Person) {\n\tp.Email = \"x\"\n}\n")
	b := write("b.go", "package a\n\n// Fill copies rows.\n// +const:[src]\nfunc Fill(dst, src []int) {\n\tdst[0] = src[0]\n\tsrc[1] = 5\n}\n\n// Read is fine.\n// +const:[in]\nfunc Read(in []int) int {\n\treturn in[0]\n}\n")
	rep := csAnalyze([]*parser.ParsedFile{a, b})
	var fields, params int
	for _, is := range rep.MutIssues {
		switch is.RuleID {
		case "mut-const-field":
			fields++
		case "mut-const-param":
			params++
		}
	}
	if fields != 2 { // Rename, Update — not the constructor, not the unmarked Age
		t.Errorf("const-field hits = %d, want 2: %+v", fields, rep.MutIssues)
	}
	if params != 1 {
		t.Errorf("const-param hits = %d, want 1 (src[1] = 5)", params)
	}
}

func TestGoGlobalMutationAndReassign(t *testing.T) {
	src := "package p\n\nvar counter int\nvar cache = map[string]int{}\nvar mu sync.Mutex\nvar (\n\tnames []string\n)\n\nfunc init() {\n\tcounter = 1\n}\n\nfunc Inc() {\n\tcounter++\n}\n\nfunc Put(k string) {\n\tcache[k] = 1\n}\n\nfunc Add(n string) {\n\tnames = append(names, n)\n}\n\nfunc Local() int {\n\tcounter := 5\n\tcounter = counter + 1\n\treturn counter\n}\n\nfunc Read() int { return counter }\n\nfunc Re() int {\n\tx := 1\n\tx = 2\n\tvar err error\n\terr = nil\n\treturn x\n}\n"
	rep := csAnalyze([]*parser.ParsedFile{writeFile(t, ".go", src)})
	var globals, reassigns int
	for _, is := range rep.MutIssues {
		switch is.RuleID {
		case "mut-global":
			globals++
		case "mut-reassign":
			reassigns++
			if !is.Advisory {
				t.Error("reassign must be advisory")
			}
		}
	}
	if globals != 3 { // Inc, Put, Add — not init(), not the shadowing local, not the mutex
		t.Errorf("global mutations = %d, want 3: %+v", globals, rep.MutIssues)
	}
	if reassigns < 2 { // Local's counter, Re's x
		t.Errorf("reassigns = %d", reassigns)
	}
	// advisory issues are not review items and not score input
	if n := rep.ReviewIssueCount(); n != 3 {
		t.Errorf("ReviewIssueCount = %d, want 3 (the advisory ones excluded)", n)
	}
}

func TestTSPreferConst(t *testing.T) {
	src := "export function f(xs: number[]) {\n  let a = 1;\n  let b = 2;\n  b += 1;\n  let c = [1];\n  [c] = [[2]];\n  for (let i = 0; i < 3; i++) {}\n  let d;\n  d = 5;\n  let e = 0;\n  e++;\n  return a + b + d + e;\n}\n"
	rep := csAnalyze([]*parser.ParsedFile{writeFile(t, ".ts", src)})
	var names []string
	for _, is := range rep.MutIssues {
		if is.RuleID == "mut-prefer-const" {
			names = append(names, is.Detail)
		}
	}
	if len(names) != 1 || names[0] != "a" {
		t.Errorf("prefer-const = %v, want just a", names)
	}
}

func TestPythonSharedState(t *testing.T) {
	src := "CACHE = {}\nITEMS = []\ncount = 0\n\ndef put(k, v):\n    CACHE[k] = v\n\ndef add(x):\n    ITEMS.append(x)\n\ndef bump():\n    global count\n    count += 1\n\ndef safe(ITEMS):\n    ITEMS.append(1)\n\nclass Registry:\n    handlers = []\n    name = 'x'\n\n    def __init__(self):\n        self.items = []\n"
	got := issueIDs(scanPyMutability("/x/m.py", pyMasked(src)))
	count := map[string]int{}
	for _, id := range got {
		count[id]++
	}
	if count["mut-py-module-state"] != 2 || count["mut-py-global"] != 1 || count["mut-py-class-attr"] != 1 {
		t.Errorf("python mutability = %v", count)
	}
}

func TestMutabilitySuppression(t *testing.T) {
	src := "package p\n\nvar counter int\n\n//nolint:funky\nfunc Inc() {\n\tcounter++\n}\n\nfunc Dec() {\n\tcounter--\n}\n"
	rep := csAnalyze([]*parser.ParsedFile{writeFile(t, ".go", src)})
	n := 0
	for _, is := range rep.MutIssues {
		if is.RuleID == "mut-global" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("only Dec should be reported: %+v", rep.MutIssues)
	}
}
