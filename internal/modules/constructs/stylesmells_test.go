package constructs

import (
	"strings"
	"testing"
)

func styleIDs(path, src string) map[string]int {
	lines := strings.Split(src, "\n")
	out := map[string]int{}
	for _, is := range scanStyle(path, ext(path), maskSource(lines, ext(path))) {
		out[is.RuleID]++
	}
	return out
}

func TestStyleChangeReferential(t *testing.T) {
	got := styleIDs("/x/a.go", `package x

// This used to be a map, but is a slice now.
func A() {}

// Reads the config. Before this change the loader ran twice.
func B() {}

// Registers the handlers once at startup.
func C() {}

// Раньше было два прохода; теперь один.
func D() {}

// Closes files that are used to write the log.
func E() {}

// Currently only supports gzip; will be extended.
func F() {}
`)
	if got["comment-change-ref"] != 3 {
		t.Errorf("want 3 change-referential comments (used to be, before this change, раньше было), got %v", got)
	}
	if got["doc-temporal"] != 1 {
		t.Errorf("want the 'Currently … will be' doc comment as advisory temporal wording, got %v", got)
	}
}

func TestStylePythonDocstringChangeRef(t *testing.T) {
	got := styleIDs("/x/a.py", `def f():
    """Считает итог. Раньше было два прохода, теперь один."""
    return 1


def g():
    """Computes the total of all items."""
    return 2
`)
	if got["comment-change-ref"] != 1 {
		t.Errorf("a docstring describing the change should be flagged once: %v", got)
	}
}

func TestStyleLazySuppressions(t *testing.T) {
	got := styleIDs("/x/a.py", `import os  # noqa
import sys  # noqa: F401
import re  # noqa: F401 — re-exported for plugins
x = foo()  # type: ignore
y = bar()  # type: ignore[arg-type]  # the stub is wrong for this overload
# the vendored API returns bytes here, not str
z = baz()  # pylint: disable=no-member
`)
	if got["lazy-ignore-blanket"] != 2 { // bare noqa, bare type: ignore
		t.Errorf("blanket: %v", got)
	}
	if got["lazy-ignore"] != 1 { // noqa: F401 with no reason ... plus pylint justified above
		t.Errorf("lazy: %v", got)
	}
	g := styleIDs("/x/a.go", `package x

func f() {
	a() //nolint
	b() //nolint:errcheck // best effort, nothing to do on failure
	c() //nolint:errcheck
}
`)
	if g["lazy-ignore-blanket"] != 1 || g["lazy-ignore"] != 1 {
		t.Errorf("go nolint: %v", g)
	}
	ts := styleIDs("/x/a.ts", "// @ts-ignore\nfoo();\n// @ts-expect-error legacy API typings are wrong\nbar();\n// eslint-disable-next-line no-console -- debug build only\nbaz();\n")
	if ts["lazy-ignore"] != 1 {
		t.Errorf("ts: %v", ts)
	}
}

func TestStyleStringlyTyped(t *testing.T) {
	got := styleIDs("/x/a.py", `def f(status):
    if status == "pending":
        return 1
    elif status in ("shipped", "delivered"):
        return 2


def g(order):
    return order.method == "GET"
`)
	if got["stringly-typed"] != 1 {
		t.Errorf("status vs 3 literals: %v", got)
	}
	g := styleIDs("/x/a.go", `package x

func f(s string) int {
	switch s {
	case "a", "b":
		return 1
	case "c":
		return 2
	}
	return 0
}
`)
	if g["stringly-typed"] != 1 {
		t.Errorf("go switch: %v", g)
	}
}

func TestStylePythonClassRules(t *testing.T) {
	got := styleIDs("/x/a.py", `class TokenHasher:
    def hash(self, t):
        return t

    def verify(self, t, h):
        return self.hash(t) == h


class Counter:
    def __init__(self):
        self.n = 0

    def inc(self):
        self.n += 1


class Config:
    DEBUG = False

    def a(self):
        return 1

    def b(self):
        return 2


class User:
    def __init__(self, name):
        self._name = name

    def get_name(self):
        return self._name

    def full(self):
        return f"{self._a} {self._b}"

    def get_total(self):
        return len(self._items)

    def get_id(self):
        self.log()
        return self._id

    @property
    def ok(self):
        return self._ok
`)
	if got["py-stateless-class"] != 1 {
		t.Errorf("only TokenHasher is stateless: %v", got)
	}
	if got["py-method-property"] != 2 { // get_name and get_total; not full(), not the one with side effect
		t.Errorf("property candidates: %v", got)
	}
}

func TestStylePythonLBYLAndLoops(t *testing.T) {
	got := styleIDs("/x/a.py", `import os


def f(d, k, obj, path, items, s, n):
    if k in d:
        v = d[k]
    if hasattr(obj, "name"):
        print(obj.name)
    if os.path.exists(path):
        h = open(path)
    if len(items) > 0:
        first = items[0]
    if s.isdigit():
        n = int(s)
    if n != 0:
        r = 10 / n
    for x in items:
        if x is None:
            continue
        use(x)
    for y in items:
        if not y: continue
        use(y)
    for z in items:
        if z:
            use(z)
`)
	for _, id := range []string{"py-lbyl-key", "py-lbyl-hasattr", "py-lbyl-file", "py-lbyl-len", "py-lbyl-parse", "py-lbyl-zero"} {
		if got[id] != 1 {
			t.Errorf("%s: %v", id, got)
		}
	}
	if got["py-loop-filter"] != 2 {
		t.Errorf("loop filter: %v", got)
	}
}

func TestStylePythonCQSAndPrint(t *testing.T) {
	got := styleIDs("/x/lib.py", `def process(user_id):
    data = fetch(user_id)
    result = validate(data)
    other = load(user_id)
    save(result)
    notify(user_id)
    audit(user_id)
    cache.put(user_id)
    return result


def show(x):
    print(x)
`)
	if got["py-cqs"] != 1 || got["py-print"] != 1 {
		t.Errorf("cqs/print: %v", got)
	}
	cli := styleIDs("/x/cli_tool.py", "import argparse\n\ndef main():\n    print('hi')\n")
	if cli["py-print"] != 0 {
		t.Errorf("a CLI may print: %v", cli)
	}
}

func TestStyleGoRules(t *testing.T) {
	got := styleIDs("/x/lib/a.go", `package lib

import (
	"fmt"
	"os"
)

type Config struct{ name string }

func (c *Config) GetName() string {
	return c.name
}

func (c *Config) GetID() string {
	return c.ID
}

func Lookup(m map[string]int, k string) int {
	if _, ok := m[k]; ok {
		return m[k]
	}
	return 0
}

func Read(p string) ([]byte, error) {
	if _, err := os.Stat(p); err == nil {
		return os.ReadFile(p)
	}
	return nil, nil
}

func Show() { fmt.Println("hi") }
`)
	for id, n := range map[string]int{"go-getter-prefix": 1, "go-lbyl-map": 1, "go-lbyl-file": 1, "go-print": 1} {
		if got[id] != n {
			t.Errorf("%s: want %d got %v", id, n, got)
		}
	}
	main := styleIDs("/x/cmd/tool/main.go", "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"ok\") }\n")
	if main["go-print"] != 0 {
		t.Errorf("a program may print: %v", main)
	}
	gen := styleIDs("/x/a.go", "// Code generated by protoc. DO NOT EDIT.\npackage x\n\n// used to be x\nfunc A() {}\n")
	if len(gen) != 0 {
		t.Errorf("generated code is skipped: %v", gen)
	}
}

func TestStyleRustRules(t *testing.T) {
	got := styleIDs("/x/src/lib.rs", `pub fn load(p: &str) -> String {
    std::fs::read_to_string(p).unwrap()
}

pub fn names(v: &Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for s in v {
        out.push(s.clone());
    }
    out
}

pub async fn fetch() {
    std::thread::sleep(std::time::Duration::from_secs(1));
    let x = cfg().expect("config");
}

#[cfg(test)]
mod tests {
    #[test]
    fn t() {
        let _ = load("x").unwrap();
    }
}
`)
	for id, n := range map[string]int{"rs-unwrap": 1, "rs-expect": 1, "rs-clone-loop": 1, "rs-blocking-async": 1} {
		if got[id] != n {
			t.Errorf("%s: want %d got %v", id, n, got)
		}
	}
}

func TestStyleStatSizeGuardAndQuotedPhrases(t *testing.T) {
	guard := "package p\n\nimport \"os\"\n\nfunc read(path string) ([]byte, error) {\n\tfi, err := os.Stat(path)\n\tif err != nil || fi.Size() > 1<<20 {\n\t\treturn nil, err\n\t}\n\treturn os.ReadFile(path)\n}\n"
	exists := "package p\n\nimport \"os\"\n\nfunc read(path string) ([]byte, error) {\n\tif _, err := os.Stat(path); err == nil {\n\t\treturn os.ReadFile(path)\n\t}\n\treturn nil, nil\n}\n"
	if n := styleIDs("/x/a.go", guard)["go-lbyl-file"]; n != 0 {
		t.Errorf("a Stat used for fi.Size() is a size guard, flagged %d", n)
	}
	if n := styleIDs("/x/a.go", exists)["go-lbyl-file"]; n != 1 {
		t.Errorf("a bare existence check must still be flagged, got %d", n)
	}
	for _, c := range []string{"// SetRule adds or replaces a rule.", `// Words like "currently" and "will be" date a comment.`} {
		if n := styleIDs("/x/a.go", "package p\n\n"+c+"\nfunc F() {}\n")["doc-temporal"]; n != 0 {
			t.Errorf("%q flagged as time-bound", c)
		}
	}
	if n := styleIDs("/x/a.go", "package p\n\n// This is currently unused.\nfunc F() {}\n")["doc-temporal"]; n != 1 {
		t.Errorf("a real time-bound doc must still be flagged, got %d", n)
	}
}
