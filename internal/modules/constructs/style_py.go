// style_py.go holds the Python rules of the 🧹 Style & design subcard, over the
// indentation-aware reader (pyparse.go): stateless classes, getters that should
// be properties, look-before-you-leap checks, filtering inside loops,
// command/query mixing, print() in libraries and Manager/Helper god-class names.
package constructs

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/security"
)

var (
	rePyIfContinue = regexp.MustCompile(`^if\s+.+:\s*continue\s*$`)
	rePySelfUse    = regexp.MustCompile(`\bself\.(\w+)`)
)

var (
	reSelfAssign   = regexp.MustCompile(`\bself\.\w+\s*(?::[^=\n]+)?=[^=]|\bself\.\w+\s*[+\-*/|&]=`)
	rePyReturnOnly = regexp.MustCompile(`^return\s+(.+)$`)
	rePyGodName    = regexp.MustCompile(`(?:Manager|Processor|Helpers?|Utils?|Utility|Utilities|Handler)$`)
	rePyPrint      = regexp.MustCompile(`^\s*print\s*\(`)
	rePyIf         = regexp.MustCompile(`^\s*(?:el)?if\s+(.+?)\s*:\s*$`)
	rePyFor        = regexp.MustCompile(`^\s*(?:async\s+)?for\s+.+\s+in\s+.+:\s*$`)
	rePyCaptured   = regexp.MustCompile(`^\s*[\w.,\s\[\]*()]+?\s*=\s*(?:await\s+)?[\w.]+\(.*\)\s*$`)
	rePyDiscarded  = regexp.MustCompile(`^\s*(?:await\s+)?([\w.]+)\(.*\)\s*$`)
	rePyPureCall   = regexp.MustCompile(`\b(?:len|str|int|float|bool|list|tuple|set|dict|sorted|sum|min|max|abs|round|repr|any|all)\(`)
	rePyCall       = regexp.MustCompile(`[\w\]\)]\(`)
)

// pyFirstIndent is the indentation of a block's first non-blank line.
func pyFirstIndent(code []string, from, to int) int {
	for i := from; i <= to && i < len(code); i++ {
		if strings.TrimSpace(code[i]) != "" {
			return pyIndent(code[i])
		}
	}
	return -1
}

// pySimpleBlockEnd is the last line of the block that follows a header at line i:
// every following line that is blank or indented deeper than the header.
func pySimpleBlockEnd(code []string, i int) int {
	ind := pyIndent(code[i])
	end := i
	for j := i + 1; j < len(code); j++ {
		if strings.TrimSpace(code[j]) == "" {
			continue
		}
		if pyIndent(code[j]) <= ind {
			break
		}
		end = j
	}
	return end
}

func (c *styleCtx) scanPython() {
	m := c.m
	funcs, classes := pyParse(m)
	base := baseName(c.path)

	methodsOf := func(cl pyClass) []pyFunc {
		var out []pyFunc
		for _, f := range funcs {
			if f.class == cl.name && !f.enclosedDef && f.start > cl.start && f.start <= cl.end && f.indent == pyIndent(m.code[cl.start])+pyBodyIndent(m.code, cl) {
				out = append(out, f)
			}
		}
		return out
	}

	for _, cl := range classes {
		ms := methodsOf(cl)
		decorated := false
		for j := cl.start - 1; j >= 0 && j >= cl.start-3; j-- {
			t := strings.TrimSpace(m.code[j])
			if t == "" {
				continue
			}
			decorated = strings.HasPrefix(t, "@")
			break
		}
		bases := strings.TrimSpace(cl.bases)
		// 🧱 stateless class: no base, no decorator, no state, 2+ instance methods
		if (bases == "" || bases == "object") && !decorated && !strings.HasPrefix(cl.name, "Test") && !strings.HasSuffix(cl.name, "Test") && !strings.HasSuffix(cl.name, "Tests") {
			inst, stateful := 0, false
			for _, f := range ms {
				switch f.name {
				case "__init__", "__new__", "__init_subclass__", "__slots__":
					stateful = true
				}
				if p := strings.TrimSpace(f.params); strings.HasPrefix(p, "self") && !hasDecorator(f, "staticmethod", "classmethod") {
					inst++
				}
			}
			if !stateful && inst >= 2 && !pyClassHasState(m, cl, funcs) && !pyUsesForeignSelf(m, ms) && !strings.HasSuffix(cl.name, "Mixin") && !strings.HasSuffix(cl.name, "Methods") {
				c.add(cl.start, security.SevLow, "py-stateless-class", "Class without state",
					fmt.Sprintf("`%s` has no constructor and no attributes, only %d methods: module-level functions say the same thing without the class.", cl.name, len(ms)),
					cl.name, false)
			}
		}
		// 👔 god-class name: Manager / Helper / Util … with a lot of methods
		if rePyGodName.MatchString(cl.name) && len(ms) >= 6 {
			c.add(cl.start, security.SevLow, "smell-srp-name", "Manager / Helper / Util class with many methods",
				"Names like Manager, Helper or Util tend to collect unrelated responsibilities. Split by what the methods are for and name each part for it.",
				fmt.Sprintf("%s · %d methods", cl.name, len(ms)), false)
		}
	}

	for _, f := range funcs {
		if f.enclosedDef {
			continue
		}
		c.pyProperty(f)
		c.pyCQS(f)
	}

	c.pyLBYL()
	c.pyLoopFilter()

	// 🖨 print() in library code
	if !pyIsScript(c.path, base, m) {
		for i, l := range m.code {
			if rePyPrint.MatchString(l) {
				c.add(i, security.SevLow, "py-print", "print() in library code",
					"Use the logging module: it can be silenced, levelled and routed; print writes to whatever stdout happens to be.", "print", false)
			}
		}
	}
}

func hasDecorator(f pyFunc, names ...string) bool {
	for _, d := range f.decorators {
		for _, n := range names {
			if strings.HasPrefix(d, n) {
				return true
			}
		}
	}
	return false
}

// pyUsesForeignSelf reports methods that read `self.<something>` which is not one
// of the class's own methods — the state lives elsewhere, which makes the class a
// mixin rather than a bag of functions.
func pyUsesForeignSelf(m maskedFile, ms []pyFunc) bool {
	own := map[string]bool{}
	for _, f := range ms {
		own[f.name] = true
	}
	for _, f := range ms {
		for i := f.bodyStart; i <= f.end && i < len(m.code); i++ {
			for _, g := range rePySelfUse.FindAllStringSubmatch(m.code[i], -1) {
				if !own[g[1]] {
					return true
				}
			}
		}
	}
	return false
}

// pyClassHasState reports class-level attributes or `self.x = …` in any method.
func pyClassHasState(m maskedFile, cl pyClass, funcs []pyFunc) bool {
	bi := pyFirstIndent(m.code, cl.start+1, cl.end)
	inMethod := func(i int) bool {
		for _, f := range funcs {
			if f.class == cl.name && i >= f.start && i <= f.end {
				return true
			}
		}
		return false
	}
	for i := cl.start + 1; i <= cl.end && i < len(m.code); i++ {
		l := m.code[i]
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		if reSelfAssign.MatchString(l) {
			return true
		}
		if pyIndent(l) == bi && !inMethod(i) && !strings.HasPrefix(t, "def ") && !strings.HasPrefix(t, "async def ") &&
			!strings.HasPrefix(t, "@") && !strings.HasPrefix(t, "pass") && !strings.HasPrefix(t, "...") && !strings.HasPrefix(t, "class ") &&
			(strings.Contains(t, "=") || strings.Contains(t, ":")) && !strings.HasPrefix(t, `"""`) && !strings.HasPrefix(t, `'''`) {
			// a docstring is blanked in code, so what is left with ':' or '=' is an attribute
			return true
		}
	}
	return false
}

// pyProperty flags trivial getters: `def get_name(self): return self._name`.
func (c *styleCtx) pyProperty(f pyFunc) {
	if f.class == "" || f.async || len(f.decorators) > 0 || f.oneLiner && false || strings.HasPrefix(f.name, "__") {
		return
	}
	if strings.TrimSpace(strings.Join(strings.Fields(f.params), "")) != "self" {
		return
	}
	var stmts []string
	for i := f.bodyStart; i <= f.end && i < len(c.m.code); i++ {
		if t := strings.TrimSpace(c.m.code[i]); t != "" {
			stmts = append(stmts, t)
		}
	}
	if f.oneLiner {
		return
	}
	if len(stmts) != 1 {
		return
	}
	g := rePyReturnOnly.FindStringSubmatch(stmts[0])
	if g == nil {
		return
	}
	expr := strings.TrimSpace(g[1])
	name := strings.TrimPrefix(f.name, "get_")
	// `get_x` returning self.x could not become a property x (the names clash);
	// the accessor of a private attribute can.
	trivial := expr == "self._"+f.name || expr == "self._"+name
	computed := strings.HasPrefix(f.name, "get_") && strings.Contains(expr, "self.") && expr != "self."+name && !rePyCall.MatchString(rePyPureCall.ReplaceAllString(expr, "("))
	if !trivial && !computed {
		return
	}
	if (c.pyClassHasBases(f.class)) && frameworkHooks[f.name] {
		return
	}
	prop := name
	c.add(f.start, security.SevLow, "py-method-property", "Getter that should be a @property",
		fmt.Sprintf("Replace `def %s(self)` with `@property def %s(self)`: callers then read it as an attribute, like every other attribute.", f.name, prop),
		f.name, false)
}

// pyCQS flags a function that both captures call results and calls for effect.
func (c *styleCtx) pyCQS(f pyFunc) {
	if f.oneLiner || strings.HasPrefix(f.name, "__") || f.name == "main" || strings.HasPrefix(f.name, "test") || f.end-f.start < 8 {
		return
	}
	captured, discarded := 0, 0
	for i := f.bodyStart; i <= f.end && i < len(c.m.code); i++ {
		l := c.m.code[i]
		if !strings.HasPrefix(strings.TrimSpace(l), "return") && rePyCaptured.MatchString(l) {
			captured++
			continue
		}
		if g := rePyDiscarded.FindStringSubmatch(l); g != nil {
			n := g[1]
			switch {
			case n == "print", strings.HasPrefix(n, "log"), strings.HasPrefix(n, "self.assert"), strings.HasPrefix(n, "super"):
			case strings.HasSuffix(n, ".append"), strings.HasSuffix(n, ".extend"), strings.HasSuffix(n, ".add"), strings.HasSuffix(n, ".update"),
				strings.HasSuffix(n, ".setdefault"), strings.HasSuffix(n, ".remove"), strings.HasSuffix(n, ".pop"), strings.HasSuffix(n, ".clear"),
				strings.HasSuffix(n, ".sort"), strings.HasSuffix(n, ".write"), strings.HasSuffix(n, ".close"), strings.HasSuffix(n, ".info"),
				strings.HasSuffix(n, ".debug"), strings.HasSuffix(n, ".warning"), strings.HasSuffix(n, ".error"):
			default:
				discarded++
			}
		}
	}
	if captured >= 3 && discarded >= 3 {
		c.add(f.start, security.SevLow, "py-cqs", "Function both queries and commands",
			"It captures results from some calls and calls others only for their effect. Splitting the reading from the writing makes each part testable and its name honest.",
			fmt.Sprintf("%s · %d queries, %d commands", f.name, captured, discarded), true)
	}
}

// pyIsScript reports files that are programs, where print() is the interface.
func pyIsScript(path, base string, m maskedFile) bool {
	switch base {
	case "__main__.py", "manage.py", "setup.py", "conftest.py", "cli.py", "main.py", "console.py", "app.py":
		return true
	}
	p := "/" + strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	for _, d := range []string{"/scripts/", "/script/", "/examples/", "/example/", "/bin/", "/tools/", "/demo/", "/docs/", "/cli/", "/management/commands/"} {
		if strings.Contains(p, d) {
			return true
		}
	}
	for _, l := range m.raw {
		if strings.Contains(l, "__main__") || strings.HasPrefix(l, "import argparse") || strings.HasPrefix(l, "import click") ||
			strings.HasPrefix(l, "import typer") || strings.HasPrefix(l, "import fire") || strings.HasPrefix(l, "from argparse") ||
			strings.HasPrefix(l, "from click") || strings.HasPrefix(l, "from typer") {
			return true
		}
	}
	return false
}

// ── look before you leap ─────────────────────────────────────────────────────

var (
	reLBYLKey   = regexp.MustCompile(`^\s*(?:el)?if\s+(.+?)\s+in\s+([A-Za-z_][\w.]*)\s*:\s*$`)
	reLBYLAttr  = regexp.MustCompile(`^\s*(?:el)?if\s+hasattr\(\s*([A-Za-z_][\w.]*)\s*,\s*["']([A-Za-z_]\w*)["']\s*\)\s*:\s*$`)
	reLBYLFile  = regexp.MustCompile(`^\s*(?:el)?if\s+(?:os\.path\.(?:exists|isfile|isdir)\(\s*(.+?)\s*\)|(?:pathlib\.)?Path\(\s*(.+?)\s*\)\.(?:exists|is_file)\(\)|([A-Za-z_][\w.]*)\.(?:exists|is_file)\(\))\s*:\s*$`)
	reLBYLLen   = regexp.MustCompile(`^\s*(?:el)?if\s+len\(\s*([A-Za-z_][\w.]*)\s*\)(?:\s*(?:>|>=|!=)\s*[01])?\s*:\s*$`)
	reLBYLDigit = regexp.MustCompile(`^\s*(?:el)?if\s+([A-Za-z_][\w.]*)\.(?:isdigit|isnumeric|isdecimal)\(\)\s*:\s*$`)
	reLBYLZero  = regexp.MustCompile(`^\s*(?:el)?if\s+([A-Za-z_][\w.]*)\s*!=\s*0\s*:\s*$`)
)

// pyLBYL flags an `if` whose body then performs the very operation the test
// guards — Python's EAFP idiom is to try it and handle the failure.
func (c *styleCtx) pyLBYL() {
	code := c.m.text
	for i, l := range code {
		if !strings.HasPrefix(strings.TrimSpace(l), "if ") && !strings.HasPrefix(strings.TrimSpace(l), "elif ") {
			continue
		}
		end := pySimpleBlockEnd(c.m.code, i)
		if end > i+8 {
			end = i + 8
		}
		body := strings.Join(code[i+1:end+1], "\n")
		flag := func(id, rule, msg string) {
			c.add(i, security.SevLow, id, rule, msg, "", false)
		}
		switch {
		case reLBYLAttr.MatchString(l):
			g := reLBYLAttr.FindStringSubmatch(l)
			if strings.Contains(body, g[1]+"."+g[2]) {
				flag("py-lbyl-hasattr", "hasattr() before using the attribute", "Access it in `try: … except AttributeError:` (or use getattr with a default) instead of testing first.")
			}
		case reLBYLFile.MatchString(l):
			g := reLBYLFile.FindStringSubmatch(l)
			f := firstNonEmpty(g[1], g[2], g[3])
			if f != "" && (strings.Contains(body, "open("+f) || strings.Contains(body, f+".open(") || strings.Contains(body, f+".read_text") || strings.Contains(body, "remove("+f) || strings.Contains(body, f+".unlink")) {
				flag("py-lbyl-file", "Existence check before opening the file", "The file can vanish between the check and the use. Open it in `try: … except FileNotFoundError:`.")
			}
		case reLBYLLen.MatchString(l):
			g := reLBYLLen.FindStringSubmatch(l)
			if strings.Contains(body, g[1]+"[0]") || strings.Contains(body, g[1]+"[-1]") {
				flag("py-lbyl-len", "len() check before indexing", "Use `if x:` for emptiness, or index inside `try: … except IndexError:`.")
			}
		case reLBYLDigit.MatchString(l):
			g := reLBYLDigit.FindStringSubmatch(l)
			if strings.Contains(body, "int("+g[1]) || strings.Contains(body, "float("+g[1]) {
				flag("py-lbyl-parse", "isdigit() before converting", "Convert in `try: int(s) … except ValueError:`: it also handles signs, spaces and non-ASCII digits the way the parser does.")
			}
		case reLBYLZero.MatchString(l):
			g := reLBYLZero.FindStringSubmatch(l)
			if strings.Contains(body, "/ "+g[1]) || strings.Contains(body, "// "+g[1]) || strings.Contains(body, "% "+g[1]) || strings.Contains(body, "/"+g[1]) {
				flag("py-lbyl-zero", "Zero check before dividing", "Divide in `try: … except ZeroDivisionError:` and handle the case where it happens.")
			}
		case reLBYLKey.MatchString(l):
			g := reLBYLKey.FindStringSubmatch(l)
			if !strings.Contains(g[1], " ") && rx(`(?:^|[^\w.])`+regexp.QuoteMeta(g[2]+"["+g[1]+"]")+`\s*(?:[^=\s]|==|$)`).MatchString(body) && !strings.Contains(body, "del "+g[2]+"["+g[1]+"]") {
				flag("py-lbyl-key", "Key membership test before indexing", "Use `d.get(key)` (with a default), or index inside `try: … except KeyError:`: one lookup instead of two.")
			}
		}
	}
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// ── filtering inside a loop ──────────────────────────────────────────────────

// pyLoopFilter flags `for x in xs:` whose body opens with `if …: continue`.
func (c *styleCtx) pyLoopFilter() {
	code := c.m.code
	for i, l := range code {
		if !rePyFor.MatchString(l) {
			continue
		}
		j := i + 1
		for j < len(code) && strings.TrimSpace(code[j]) == "" {
			j++
		}
		if j >= len(code) || pyIndent(code[j]) <= pyIndent(l) {
			continue
		}
		t := strings.TrimSpace(code[j])
		oneLine := rePyIfContinue.MatchString(t)
		twoLine := false
		if rePyIf.MatchString(code[j]) && !strings.HasPrefix(t, "elif") && j+1 < len(code) {
			twoLine = strings.TrimSpace(code[j+1]) == "continue"
		}
		if oneLine || twoLine {
			c.add(i, security.SevLow, "py-loop-filter", "Filtering inside a loop body",
				"Move the filter into the iterable — a generator expression `(x for x in xs if …)` — so the loop only handles what passed, and the filter can be named and tested.",
				"", false)
		}
	}
}

// frameworkHooks are get_* methods a framework calls by name (Django, DRF,
// unittest): they must stay methods.
var frameworkHooks = map[string]bool{
	"get_queryset": true, "get_object": true, "get_context_data": true, "get_serializer_class": true, "get_serializer": true,
	"get_permissions": true, "get_form": true, "get_form_class": true, "get_template_names": true, "get_success_url": true,
	"get_authenticators": true, "get_renderers": true, "get_parsers": true, "get_throttles": true, "get_paginated_response": true,
	"get_fields": true, "get_readonly_fields": true, "get_urls": true, "get_list_display": true, "get_search_results": true,
}

// pyClassHasBases reports whether the named class in this file inherits from anything.
func (c *styleCtx) pyClassHasBases(class string) bool {
	_, classes := pyParse(c.m)
	for _, cl := range classes {
		if cl.name == class {
			b := strings.TrimSpace(cl.bases)
			return b != "" && b != "object"
		}
	}
	return false
}
