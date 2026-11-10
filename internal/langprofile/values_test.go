package langprofile

import (
	"strings"
	"testing"
)

func scan(path, src string) map[string]Value {
	out := map[string]Value{}
	for _, v := range ScanValues(path, strings.Split(src, "\n")) {
		out[v.Name] = v
	}
	return out
}

func want(t *testing.T, lang string, got map[string]Value, exp map[string]string) {
	t.Helper()
	for name, kind := range exp {
		v, ok := got[name]
		if !ok || v.Kind != kind {
			t.Errorf("%s: %s = %+v (found %v), want %s", lang, name, v, ok, kind)
		}
	}
	if len(got) != len(exp) {
		t.Errorf("%s: found %d values %v, want %d", lang, len(got), got, len(exp))
	}
}

func TestScanValuesPerLanguage(t *testing.T) {
	want(t, "go", scan("a.go", "package p\n\nconst Max = 10\nvar cache = map[string]int{}\nconst (\n\tA = iota\n\tb int = 2 // two\n)\nvar (\n\tmu sync.Mutex\n)\n\nfunc f() {\n\tconst local = 1\n\tx := 2\n}\n"),
		map[string]string{"Max": "const", "cache": "var", "A": "const", "b": "const", "mu": "var"})
	want(t, "python", scan("a.py", "import os\nMAX_SIZE = 10\ntimeout: int = 5\n__all__ = ['x']\n\ndef f():\n    LOCAL = 1\n"),
		map[string]string{"MAX_SIZE": "const", "timeout": "var"})
	want(t, "typescript", scan("a.ts", "export const LIMIT = 5;\nlet counter: number = 0;\nconst fn = (a) => a;\nconst g = async () => 1;\nfunction h() {\n  const inner = 2\n}\n"),
		map[string]string{"LIMIT": "const", "counter": "var"})
	want(t, "java", scan("A.java", "class A {\n  public static final int MAX = 5;\n  private static int count = 0;\n  int field = 3;\n}\n"),
		map[string]string{"MAX": "const", "count": "var"})
	want(t, "kotlin", scan("a.kt", "const val MAX = 5\nval name = \"x\"\nvar n = 0\nfun f() {\n    val local = 1\n}\n"),
		map[string]string{"MAX": "const", "name": "const", "n": "var"})
	want(t, "swift", scan("a.swift", "let maxCount = 5\nvar total = 0\nstruct S {\n    static let id = 1\n    let x = 2\n}\n"),
		map[string]string{"maxCount": "const", "total": "var"})
	want(t, "rust", scan("a.rs", "pub const MAX: usize = 5;\nstatic mut COUNT: u32 = 0;\nstatic NAME: &str = \"x\";\nfn f() { let x = 1; }\n"),
		map[string]string{"MAX": "const", "COUNT": "var", "NAME": "const"})
	want(t, "csharp", scan("A.cs", "class A {\n  public const int Max = 5;\n  private static readonly string Name = \"x\";\n}\n"),
		map[string]string{"Max": "const", "Name": "const"})
	want(t, "dart", scan("a.dart", "const maxItems = 5;\nfinal name = 'x';\nvar n = 0;\nvoid f() {\n  var local = 1;\n}\n"),
		map[string]string{"maxItems": "const", "name": "const", "n": "var"})
	want(t, "ruby", scan("a.rb", "class A\n  LIMIT = 5\n  def f; x = 1; end\nend\n"), map[string]string{"LIMIT": "const"})
	want(t, "php", scan("a.php", "<?php\nconst MAX = 5;\ndefine('NAME', 'x');\nclass A {\n  public const ID = 1;\n}\n"),
		map[string]string{"MAX": "const", "NAME": "const", "ID": "const"})
	want(t, "c", scan("a.c", "#define BUF 256\nstatic const int LIMIT = 5;\nint main() { return 0; }\n"),
		map[string]string{"BUF": "const", "LIMIT": "const"})
}

func TestNamingPublic(t *testing.T) {
	cases := []struct {
		path, name, line string
		want             bool
	}{
		{"a.go", "Max", "const Max = 1", true}, {"a.go", "max", "const max = 1", false},
		{"a.py", "_x", "_x = 1", false}, {"a.py", "X", "X = 1", true},
		{"a.rs", "MAX", "pub const MAX: u8 = 1;", true}, {"a.rs", "MAX", "const MAX: u8 = 1;", false},
		{"A.java", "MAX", "private static final int MAX = 1;", false}, {"A.java", "MAX", "static final int MAX = 1;", true},
		{"a.ts", "X", "export const X = 1", true}, {"a.ts", "X", "const X = 1", false},
	}
	for _, c := range cases {
		if got := For(c.path).Naming.Public(c.name, c.line); got != c.want {
			t.Errorf("%s %q public = %v", c.path, c.line, got)
		}
	}
}

func TestFuncConventionsAndComments(t *testing.T) {
	if !IgnoredFunc("a.go", "main") || !IgnoredFunc("a.py", "__init__") || !IgnoredFunc("a.py", "__repr__") || IgnoredFunc("a.go", "Handle") {
		t.Error("IgnoredFunc")
	}
	if !IsTestFunc("a_test.go", "TestX") || !IsTestFunc("t.py", "test_x") || IsTestFunc("a.go", "Handle") {
		t.Error("IsTestFunc")
	}
	if !IsCommentLine(".py", "# x") || IsCommentLine(".py", "// x") || !IsCommentLine(".go", "// x") || !IsCommentLine(".ts", "* x") {
		t.Error("IsCommentLine")
	}
}
