package langprofile

import (
	"regexp"
	"strings"
)

// ValueSyntax is how a language declares a named value — what the "new consts /
// vars" count, the mutability checks and the magic-number checks read.
type ValueSyntax struct {
	// Re matches one declaration line. Named groups: kw (const / let / var / val / final /
	// static …), name, type (optional), value.
	Re          *regexp.Regexp
	ConstKW     []string       // values of kw that make it immutable
	AllConst    bool           // every match is a constant (C const / #define)
	ConstByName bool           // UPPER_SNAKE names are constants even without a keyword (Python, Ruby)
	TopLevel    bool           // only column-0 declarations (module level); false = any indent
	Blocks      bool           // Go-style `const ( … )` / `var ( … )` groups
	NotValue    *regexp.Regexp // values that are really functions, not data
}

// Value is one declared constant or variable.
type Value struct {
	Kind     string // "const" | "var"
	Name     string
	Type     string
	Value    string
	Line     int // 1-based
	Exported bool
}

var reGoValueOpen = regexp.MustCompile(`^(const|var)\s*\(\s*$`)
var reGoValueSingle = regexp.MustCompile(`^(?P<kw>const|var)\s+(?P<name>\w+)(?:\s+(?P<type>[^=\s][^=]*?))?\s*(?:=\s*(?P<value>.+))?$`)
var reGoValueInBlock = regexp.MustCompile(`^\s+(?P<name>[A-Za-z_]\w*)(?:\s+(?P<type>[^=\s/][^=/]*?))?\s*(?:=\s*(?P<value>[^/]+?))?\s*(?://.*)?$`)

var reArrowOrFunc = regexp.MustCompile(`^(?:async\s*)?(?:\([^)]*\)|\w+)\s*(?::[^=]+)?=>|^(?:async\s+)?function\b|^(?:async\s+)?\([^)]*\)\s*=>`)

var valuesByID = map[string]ValueSyntax{
	"go": {
		Blocks:   true,
		TopLevel: true,
		ConstKW:  []string{"const"},
	},
	"python": {
		Re:          re(`^(?P<name>[A-Za-z_]\w*)\s*(?::\s*(?P<type>[^=]+?))?\s*=\s*(?P<value>[^=].*)$`),
		ConstByName: true,
		TopLevel:    true,
	},
	"typescript": {
		Re:       re(`^(?:export\s+)?(?:declare\s+)?(?P<kw>const|let|var)\s+(?P<name>\w+)(?:\s*:\s*(?P<type>[^=]+?))?\s*=\s*(?P<value>.+?);?$`),
		ConstKW:  []string{"const"},
		TopLevel: true,
		NotValue: reArrowOrFunc,
	},
	"javascript": {
		Re:       re(`^(?:export\s+)?(?P<kw>const|let|var)\s+(?P<name>\w+)\s*=\s*(?P<value>.+?);?$`),
		ConstKW:  []string{"const"},
		TopLevel: true,
		NotValue: reArrowOrFunc,
	},
	"java": {
		Re:      re(`^\s*(?:(?:public|private|protected)\s+)?(?P<kw>static(?:\s+final)?)\s+(?P<type>[\w<>\[\],.? ]+?)\s+(?P<name>\w+)\s*=\s*(?P<value>.+?);`),
		ConstKW: []string{"static final"},
	},
	"kotlin": {
		Re:       re(`^\s*(?:(?:public|private|internal|protected)\s+)?(?P<kw>const\s+val|val|var)\s+(?P<name>\w+)(?:\s*:\s*(?P<type>[^=]+?))?\s*=\s*(?P<value>.+)$`),
		ConstKW:  []string{"const val", "val"},
		TopLevel: true,
	},
	"swift": {
		Re:       re(`^\s*(?:(?:public|private|fileprivate|internal|open)\s+)?(?:(?:static|class)\s+)?(?P<kw>let|var)\s+(?P<name>\w+)(?:\s*:\s*(?P<type>[^=]+?))?\s*=\s*(?P<value>.+)$`),
		ConstKW:  []string{"let"},
		TopLevel: true,
	},
	"rust": {
		Re:      re(`^\s*(?:pub(?:\([^)]*\))?\s+)?(?P<kw>const|static\s+mut|static)\s+(?P<name>\w+)\s*:\s*(?P<type>[^=]+?)\s*=\s*(?P<value>.+?);`),
		ConstKW: []string{"const", "static"},
	},
	"csharp": {
		Re:      re(`^\s*(?:(?:public|private|protected|internal)\s+)?(?:static\s+)?(?P<kw>const|readonly)\s+(?P<type>[\w<>\[\]?.]+)\s+(?P<name>\w+)\s*=\s*(?P<value>.+?);`),
		ConstKW: []string{"const", "readonly"},
	},
	"dart": {
		Re:       re(`^\s*(?:static\s+)?(?P<kw>const|final|var)\s+(?:(?P<type>[\w<>?.]+)\s+)?(?P<name>\w+)\s*=\s*(?P<value>.+?);`),
		ConstKW:  []string{"const", "final"},
		TopLevel: true,
	},
	"ruby": {
		Re:          re(`^\s*(?P<name>[A-Z][A-Z0-9_]*)\s*=\s*(?P<value>.+)$`),
		ConstByName: true,
	},
	"php": {
		Re:      re(`^\s*(?:(?:public|private|protected)\s+)?(?P<kw>const)\s+(?P<name>\w+)\s*=\s*(?P<value>.+?);|^\s*define\(\s*['"](?P<name2>\w+)['"]\s*,\s*(?P<value2>.+?)\);`),
		ConstKW: []string{"const"},
	},
	"c/c++": {
		AllConst: true,
		Re:       re(`^\s*(?:static\s+)?(?:constexpr|const)\s+(?P<type>[\w\s*:<>]+?)\s+(?P<name>\w+)\s*=\s*(?P<value>.+?);|^\s*#define\s+(?P<name2>\w+)\s+(?P<value2>.+)$`),
		ConstKW:  []string{"const"},
	},
}

func groups(re *regexp.Regexp, m []string) map[string]string {
	out := map[string]string{}
	for i, n := range re.SubexpNames() {
		if n != "" && i < len(m) && m[i] != "" {
			out[n] = strings.TrimSpace(m[i])
		}
	}
	return out
}

func isUpperSnake(s string) bool {
	if s == "" || strings.Trim(s, "_") == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

// ScanValues lists the named values a source file declares at the level its
// language declares them (module level, class-level constants, Go groups), in
// line order. Code only: pass comment/string-masked lines to avoid matches in text.
func ScanValues(path string, lines []string) []Value {
	pr := For(path)
	if pr == nil {
		return nil
	}
	v := pr.Values
	var out []Value
	add := func(i int, kind, name, typ, val string) {
		if name == "" || name == "_" {
			return
		}
		out = append(out, Value{Kind: kind, Name: name, Type: typ, Value: val, Line: i + 1, Exported: pr.Naming.Public(name, lines[i])})
	}
	if v.Blocks { // Go
		block := ""
		for i, l := range lines {
			t := strings.TrimRight(l, " \t\r")
			switch {
			case block != "":
				if strings.TrimSpace(t) == ")" {
					block = ""
					continue
				}
				if g := groups(reGoValueInBlock, reGoValueInBlock.FindStringSubmatch(t)); g["name"] != "" {
					add(i, block, g["name"], g["type"], g["value"])
				}
			case reGoValueOpen.MatchString(t):
				block = reGoValueOpen.FindStringSubmatch(t)[1]
			case reGoValueSingle.MatchString(t):
				g := groups(reGoValueSingle, reGoValueSingle.FindStringSubmatch(t))
				add(i, g["kw"], g["name"], g["type"], g["value"])
			}
		}
		return out
	}
	if v.Re == nil {
		return nil
	}
	for i, l := range lines {
		if v.TopLevel && (strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t")) {
			continue
		}
		m := v.Re.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		g := groups(v.Re, m)
		name, val := g["name"], g["value"]
		if name == "" { // alternative branch of the pattern
			name, val = g["name2"], g["value2"]
		}
		if v.NotValue != nil && v.NotValue.MatchString(val) {
			continue
		}
		kind := "var"
		for _, k := range v.ConstKW {
			if strings.Join(strings.Fields(g["kw"]), " ") == k {
				kind = "const"
			}
		}
		if g["kw"] == "" && g["name2"] != "" { // define(...) / #define
			kind = "const"
		}
		if v.AllConst || v.ConstByName && isUpperSnake(name) {
			kind = "const"
		}
		if pr.ID == "python" && (strings.HasPrefix(name, "__") && strings.HasSuffix(name, "__")) {
			continue // __all__, __version__ …
		}
		add(i, kind, name, g["type"], val)
	}
	return out
}
