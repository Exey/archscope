package result

import "testing"

func TestHasDocComment(t *testing.T) {
	cases := []struct {
		lang string
		src  []string
		line int
		want bool
	}{
		{"go", []string{"// Foo does x.", "func Foo() {}"}, 2, true},
		{"go", []string{"", "func Foo() {}"}, 2, false},
		{"go", []string{"/** doc */", "@Deco", "func Foo() {}"}, 3, true},
		{"python", []string{"def f(a):", `    """Doc."""`, "    return a"}, 1, true},
		{"python", []string{"def f(a):", "    return a"}, 1, false},
		{"python", []string{"# explains", "def f(a):", "    return a"}, 2, true},
	}
	for i, c := range cases {
		if got := hasDocComment(c.src, c.line, c.lang); got != c.want {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
}
