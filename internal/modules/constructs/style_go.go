// style_go.go holds the Go rules of the 🧹 Style & design subcard: Get-prefixed
// getters, look-before-you-leap (double map lookups, Stat-then-open),
// fmt.Print in library packages and Manager/Helper god-type names.
package constructs

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/security"
)

var (
	reGoGetter   = regexp.MustCompile(`^func\s+\((\w+)\s+\*?(\w+)\)\s+Get([A-Z]\w*)\(\)\s+[^{]+\{\s*$`)
	reGoMapCheck = regexp.MustCompile(`^\s*(?:\}\s*else\s+)?if\s+_\s*,\s*(\w+)\s*:?=\s*([A-Za-z_][\w.]*)\[([^\]]+)\]\s*;\s*(\w+)\s*\{`)
	reGoStat     = regexp.MustCompile(`\bos\.L?[Ss]tat\(\s*([^)]+?)\s*\)`)
	reGoPkg      = regexp.MustCompile(`^package\s+(\w+)`)
	reGoPrint    = regexp.MustCompile(`\bfmt\.(?:Print|Printf|Println)\(`)
	reGoTypeName = regexp.MustCompile(`^type\s+(\w+)\s+struct\b\s*(\{\s*\})?`)
	reGoMethodOn = regexp.MustCompile(`^func\s+\((?:\w+\s+)?\*?(\w+)\)\s+\w+\(`)
	reGoGodName  = regexp.MustCompile(`(?:Manager|Processor|Helpers?|Utils?|Utility|Utilities)$`)
	goFileActsRe = `os\.(?:Open|ReadFile|Create|OpenFile|Remove|WriteFile|ReadDir)\(\s*`
)

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

func (c *styleCtx) scanGo() {
	code := c.m.code
	pkg := ""
	for _, l := range code {
		if g := reGoPkg.FindStringSubmatch(l); g != nil {
			pkg = g[1]
			break
		}
	}
	methods := map[string]int{}
	for _, l := range code {
		if g := reGoMethodOn.FindStringSubmatch(l); g != nil {
			methods[g[1]]++
		}
	}
	hasMain := false
	for _, l := range code {
		if strings.HasPrefix(l, "func main()") {
			hasMain = true
		}
	}
	base := baseName(c.path)
	p := "/" + strings.ToLower(strings.ReplaceAll(c.path, "\\", "/"))
	isProgram := pkg == "main" || hasMain || base == "main.go" || strings.Contains(p, "/cmd/") || strings.Contains(p, "/examples/") ||
		strings.Contains(p, "/tools/") || strings.Contains(p, "/scripts/") || strings.Contains(p, "/hack/") ||
		strings.Contains(p, "/tui/") || strings.Contains(p, "/cli/") || strings.Contains(p, "/ui/") || strings.Contains(p, "/console/")

	for i, l := range code {
		// getters: func (r *T) GetName() string { return r.name }
		if g := reGoGetter.FindStringSubmatch(l); g != nil && i+1 < len(code) {
			next := strings.TrimSpace(code[i+1])
			field := g[3]
			if next == "return "+g[1]+"."+lowerFirst(field) && lowerFirst(field) != field { // an exported field of the same name would clash with Field()
				c.add(i, security.SevLow, "go-getter-prefix", "Get-prefixed getter",
					fmt.Sprintf("Go getters drop the prefix: name it `%s()` (Effective Go) — `Get` adds nothing and makes call sites noisier.", field),
					"Get"+field, false)
			}
		}
		// double map lookup: if _, ok := m[k]; ok { … m[k] … }
		if g := reGoMapCheck.FindStringSubmatch(l); g != nil && g[1] == g[4] {
			if end := matchBraceEnd(code, i); end > i {
				body := strings.Join(c.m.text[i+1:end], "\n")
				if strings.Contains(body, g[2]+"["+g[3]+"]") {
					c.add(i, security.SevLow, "go-lbyl-map", "Map looked up twice",
						fmt.Sprintf("Read it once: `v, ok := %s[%s]` then use v — one lookup, and no chance of the two disagreeing.", g[2], g[3]), "", false)
				}
			}
		}
		// Stat then act: the file can change between the check and the use
		if g := reGoStat.FindStringSubmatch(l); g != nil && !statInfoUsed(l, code, i) {
			re := rx(goFileActsRe + regexp.QuoteMeta(strings.TrimSpace(g[1])))
			for j := i + 1; j < len(code) && j <= i+8; j++ {
				if re.MatchString(c.m.text[j]) {
					c.add(i, security.SevLow, "go-lbyl-file", "Stat before using the file",
						"The file can change between the check and the use. Just do the operation and handle `errors.Is(err, fs.ErrNotExist)`.", "", false)
					break
				}
			}
		}
		// fmt.Print in a library package
		if !isProgram && reGoPrint.MatchString(l) {
			c.add(i, security.SevLow, "go-print", "fmt.Print in library code",
				"A library should not write to stdout: return the value, take an io.Writer, or log through log/slog so the caller decides where it goes.", "fmt.Print", false)
		}
		if g := reGoTypeName.FindStringSubmatch(l); g != nil {
			name, n := g[1], methods[g[1]]
			if reGoGodName.MatchString(name) && n >= 6 {
				c.add(i, security.SevLow, "smell-srp-name", "Manager / Helper / Util type with many methods",
					"Names like Manager, Helper or Util tend to collect unrelated responsibilities. Split by what the methods are for and name each part for it.",
					fmt.Sprintf("%s · %d methods", name, n), false)
			}
		}
	}
}

var reGoStatAssign = regexp.MustCompile(`(?:^|[^\w.])(\w+)\s*,\s*\w+\s*:?=\s*os\.L?[Ss]tat\(`)

// statInfoUsed: the os.Stat on line i keeps its FileInfo and reads it afterwards
// (`fi.Size()`, `fi.IsDir()`) — a size or type guard, not an existence check.
func statInfoUsed(line string, code []string, i int) bool {
	m := reGoStatAssign.FindStringSubmatch(line)
	if m == nil || m[1] == "_" {
		return false
	}
	use := rx(`\b` + regexp.QuoteMeta(m[1]) + `\.`)
	for j := i; j < len(code) && j <= i+3; j++ {
		if use.MatchString(code[j]) {
			return true
		}
	}
	return false
}
