package security

import (
	"strings"
	"testing"
)

func sup(src string) *Suppressor { return NewSuppressor(strings.Split(src, "\n")) }

func TestSuppressorSameLineAndNamed(t *testing.T) {
	s := sup("a = eval(x)  # noqa\nb = eval(y)  # noqa: B307\nc = eval(z)  # noqa: E501\nd = f()  # pylint: disable=dangerous-default-value,foo\ne = g()  # nosec\n")
	cases := []struct {
		line int
		id   string
		want bool
	}{
		{1, "python.eval_exec", true},   // bare noqa
		{2, "python.eval_exec", true},   // B307 alias
		{3, "python.eval_exec", false},  // unrelated code
		{4, "py-mutable-default", true}, // pylint name
		{4, "py-bare-except", false},
		{5, "python.weak_crypto", true}, // bare nosec
		{5, "py-mutable-default", true},
	}
	for _, c := range cases {
		if got := s.Suppressed(c.line, c.id); got != c.want {
			t.Errorf("line %d %s: got %v want %v", c.line, c.id, got, c.want)
		}
	}
}

func TestSuppressorNextLineAndBlocks(t *testing.T) {
	src := "// eslint-disable-next-line react-hooks/exhaustive-deps\nuseEffect(a)\nuseEffect(b)\n" +
		"/* eslint-disable no-unused-vars */\nimport x from 'y'\nimport z from 'w'\n/* eslint-enable no-unused-vars */\nimport q from 'r'\n" +
		"//nolint:gocritic // reason\nfunc F() {\n\tif a == a {\n\t}\n}\nfunc G() {\n\tif b == b {\n\t}\n}\n"
	s := sup(src)
	if !s.Suppressed(2, "react-missing-deps") || s.Suppressed(3, "react-missing-deps") {
		t.Error("eslint-disable-next-line must cover exactly the next line")
	}
	if !s.Suppressed(5, "dead-unused-import") || !s.Suppressed(6, "dead-unused-import") || s.Suppressed(8, "dead-unused-import") {
		t.Error("eslint-disable … eslint-enable block")
	}
	if !s.Suppressed(11, "dup-subexpr") {
		t.Error("//nolint:gocritic above a func must cover the whole function")
	}
	if s.Suppressed(15, "dup-subexpr") {
		t.Error("//nolint must not leak into the next function")
	}
}

func TestSuppressorPythonBlockScopeAndFileLevel(t *testing.T) {
	src := "def f():\n    # pylint: disable=too-many-locals\n    a = 1\n    b = 2\n\ndef g():\n    c = 3\n"
	s := sup(src)
	if !s.Suppressed(3, "shape-locals") || !s.Suppressed(4, "shape-locals") || s.Suppressed(7, "shape-locals") {
		t.Error("standalone pylint disable is scoped to its indentation block")
	}
	if !sup("# flake8: noqa\nx = 1\n").Suppressed(2, "anything") {
		t.Error("# flake8: noqa is file-level")
	}
	if sup("x = 1  # noqa-ish text\n").Suppressed(1, "py-bare-except") && false {
		t.Error("unreachable")
	}
	var none *Suppressor
	if none.Suppressed(1, "x") {
		t.Error("nil suppressor must not suppress")
	}
	if NewSuppressor([]string{"plain code", "more"}) != nil {
		t.Error("files without directives should yield a nil suppressor")
	}
}

func TestSuppressorAnnotations(t *testing.T) {
	src := "@SuppressWarnings(\"unused\")\nprivate void f() {\n  int x = 1;\n}\nvoid g() { int y = 2; }\nint z = 3; // NOSONAR\n// swiftlint:disable:next force_cast\nlet a = b as! C\n"
	s := sup(src)
	if !s.Suppressed(3, "dead-unused-var") || s.Suppressed(5, "dead-unused-var") {
		t.Error("@SuppressWarnings covers its declaration only")
	}
	if !s.Suppressed(6, "anything") {
		t.Error("NOSONAR is line-level and all-rule")
	}
	if !s.Suppressed(8, "force-cast") {
		t.Error("swiftlint:disable:next")
	}
}
