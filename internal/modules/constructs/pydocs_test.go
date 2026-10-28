package constructs

import (
	"strings"
	"testing"
)

const docSample = `"""Модуль."""
import x


class FakeChannel:
    """Канал pika: basic_get по одному сообщению, запоминает ack."""

    def get(self):
        return 1

    def one(self): """Короткая."""

    def two(self): return 2


def get_unprocessed_images(
    *, created_from: datetime, untouched_since: Optional[datetime] = None
):
    """
    Необработанные изображения с файлом, загруженные начиная с created_from.

    untouched_since — только изображения, которые не обновлялись с этого момента.
    """
    return []


# explains the function, but is not a docstring
def commented(a):
    return a


@decorator(1)
async def deco(a, *args, b: int = 2, **kw):
    'single quoted'
    def inner():
        pass


def fstring():
    f"""not a doc"""


def late():
    x = 1
    """not a docstring either"""


class Bare:
    x = 1
`

func TestPyDocsModel(t *testing.T) {
	docs := pyDocs(maskSource(strings.Split(docSample, "\n"), ".py"))
	got := map[string]pyDoc{}
	for _, d := range docs {
		got[d.kind+":"+d.name] = d
	}
	for key, want := range map[string]bool{
		"module:(module)": true, "class:FakeChannel": true, "func:get": false, "func:one": true,
		"func:get_unprocessed_images": true, "func:commented": false, "func:deco": true,
		"func:fstring": false, "func:late": false, "class:Bare": false,
	} {
		d, ok := got[key]
		if !ok {
			t.Errorf("%s not found", key)
			continue
		}
		if d.has != want {
			t.Errorf("%s: has=%v want %v", key, d.has, want)
		}
	}
	if d := got["class:FakeChannel"]; !strings.HasPrefix(d.text, "Канал pika") {
		t.Errorf("class text = %q", d.text)
	}
	d := got["func:get_unprocessed_images"]
	if !strings.HasPrefix(d.text, "Необработанные изображения") || !strings.Contains(d.text, "untouched_since — только") || strings.Contains(d.text, `"""`) {
		t.Errorf("multi-line docstring read wrong: %q", d.text)
	}
	if strings.Join(d.params, ",") != "created_from,untouched_since" {
		t.Errorf("params = %v", d.params)
	}
	if got["func:deco"].text != "single quoted" || strings.Join(got["func:deco"].params, ",") != "a,args,b,kw" {
		t.Errorf("deco = %+v", got["func:deco"])
	}
}

// The two shapes from the review: documentation of a class, and of a function
// whose signature spans lines — both with a blank line above, both in Russian.
func TestDocIndexPython(t *testing.T) {
	lines := strings.Split(docSample, "\n")
	idx := NewDocIndex("/x/a.py", lines)
	at := func(prefix string) int {
		for i, l := range lines {
			if strings.HasPrefix(l, prefix) {
				return i + 1
			}
		}
		t.Fatalf("no line %q", prefix)
		return 0
	}
	for prefix, want := range map[string]bool{
		"class FakeChannel": true, "def get_unprocessed_images": true, "def commented": false,
		"@decorator(1)": true, "def late": false, "class Bare": false,
	} {
		if got := idx.Has(at(prefix)); got != want {
			t.Errorf("%s: documented=%v want %v", prefix, got, want)
		}
	}
	goLines := []string{"package x", "", "// Foo does x.", "func Foo() {}", "", "func Bar() {}"}
	gi := NewDocIndex("/x/a.go", goLines)
	if !gi.Has(4) || gi.Has(6) {
		t.Error("go doc comment above")
	}
}

func TestDocStatsPythonMatchesModel(t *testing.T) {
	m := maskSource(strings.Split(docSample, "\n"), ".py")
	d, ok := docStats("/x/a.py", m)
	// public, non-nested, non-one-liner-without-doc: FakeChannel, get, one(doc), get_unprocessed_images, commented, deco, fstring, late, Bare
	if !ok || d.Public != 9 || d.Documented != 4 {
		t.Errorf("public=%d documented=%d", d.Public, d.Documented)
	}
}

func TestDocStatsGoSkipsUnexportedReceivers(t *testing.T) {
	src := `package x

// Documented does a thing.
func Documented() {}

func Missing() {}

type Mod struct{}

func (Mod) ID() string { return "x" }

type hidden struct{}

func (h *hidden) Error() string { return "e" }

func (hidden) String() string { return "s" }
`
	m := maskSource(strings.Split(src, "\n"), ".go")
	d, ok := docStats("/x/a.go", m)
	if !ok || d.Public != 4 { // Documented, Missing, Mod, Mod.ID — the hidden receiver's methods don't count
		t.Fatalf("public = %d", d.Public)
	}
	var names []string
	for _, ms := range d.Missing {
		names = append(names, ms.Name)
	}
	if strings.Join(names, ",") != "Missing,Mod,ID" {
		t.Errorf("undocumented symbols = %v", names)
	}
}

func TestCountTypeIgnoresOnlyInRealComments(t *testing.T) {
	py := maskSource(strings.Split("x = f()  # type: ignore[assignment]\ny = 'type: ignore in a string'\n# just prose\n", "\n"), ".py")
	if n := countTypeIgnores(py, ".py"); n != 1 {
		t.Errorf("python: got %d", n)
	}
	ts := maskSource(strings.Split("// @ts-ignore\nfoo();\nconst s = \"@ts-ignore\";\n", "\n"), ".ts")
	if n := countTypeIgnores(ts, ".ts"); n != 1 {
		t.Errorf("ts: got %d", n)
	}
	// Go has no such checker; quoting the directive (a regexp, a doc comment) changes nothing
	goSrc := maskSource(strings.Split("// handles @ts-ignore and # type: ignore\nvar re = `@ts-ignore`\n", "\n"), ".go")
	if n := countTypeIgnores(goSrc, ".go"); n != 0 {
		t.Errorf("go: got %d", n)
	}
}
