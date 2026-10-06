// deadcode_unused.go is the 🪦 Dead Code card's vulture-style pass: functions,
// methods and classes that nothing in the scanned code refers to by name. Names
// are matched against comment/string-free tokens repo-wide (Python, Go — where a
// private name can be used from a sibling file) or per file (Java, Kotlin, Swift,
// Rust, JS/TS — where private means file-local). Each finding carries a
// confidence: 90% for a private name no code and no string literal mentions, 60%
// for a public one in an application (a `__main__` / `package main` entry point
// exists, so there are no outside callers). Reflection, plugin registries and
// framework hooks reach code by string or convention, so a hit is a candidate to
// verify, not a verdict; `# noqa` / `//nolint` silences one.
package constructs

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/security"
)

var (
	reIdentTok   = regexp.MustCompile(`[A-Za-z_$][\w$]*`)
	reGoFuncDecl = regexp.MustCompile(`^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*[(\[]`)
	reGoTypeDecl = regexp.MustCompile(`^type\s+([A-Za-z_]\w*)\b`)
	reGoVarDecl  = regexp.MustCompile(`^(?:var|const)\s+([A-Za-z_]\w*)\b`)
	reJavaPriv   = regexp.MustCompile(`\bprivate\s+(?:static\s+)?(?:final\s+)?(?:synchronized\s+)?[\w<>\[\],.? ]+?\s+(\w+)\s*\(`)
	reKotlinPriv = regexp.MustCompile(`\bprivate\s+(?:suspend\s+|inline\s+|tailrec\s+|operator\s+)*fun\s+(?:<[^>]*>\s*)?(?:[\w.<>?]+\.)?(\w+)\s*\(`)
	reSwiftPriv  = regexp.MustCompile(`\b(?:private|fileprivate)\s+(?:static\s+|final\s+|override\s+|mutating\s+|@\w+\s+)*(?:func|class|struct|enum)\s+(\w+)`)
	reRustFn     = regexp.MustCompile(`^fn\s+(\w+)\s*[(<]`)
	reJSFuncDecl = regexp.MustCompile(`^(?:async\s+)?function\s*\*?\s*(\w+)\s*\(|^class\s+(\w+)\b`)
)

type symCand struct {
	name     string
	line     int // 0-based
	conf     int // 90 or 60
	fileWide bool
}

func tokenCounts(lines []string, into map[string]int) {
	for _, l := range lines {
		for _, t := range reIdentTok.FindAllString(l, -1) {
			into[t]++
		}
	}
}

// scanUnusedSymbols finds unreferenced private (and, in applications, public)
// functions and classes across the platform's files.
func scanUnusedSymbols(files []*parser.ParsedFile, cache *sourceCache) []CSIssue {
	// repo-wide token tables (all files, tests included: a test that calls it is a use)
	codeTok := map[string]int{}
	strTok := map[string]int{}
	for _, f := range files {
		fe := ext(f.FilePath)
		if fe != ".py" && fe != ".go" {
			continue
		}
		if st := cache.lines(f.FilePath); st != nil {
			tokenCounts(st, codeTok)
		}
		for _, lits := range cache.stringLiterals(f.FilePath) {
			for _, l := range lits {
				tokenCounts([]string{l}, strTok)
			}
		}
	}

	var out []CSIssue
	for _, f := range files {
		fe := ext(f.FilePath)
		if security.IsTestOrBenchPath(f.FilePath) || isConstructDetectorFile(f.FilePath) {
			continue
		}
		stripped, raw := cache.lines(f.FilePath), cache.rawLines(f.FilePath)
		if stripped == nil || raw == nil {
			continue
		}
		var cands []symCand
		switch fe {
		case ".py":
			cands = pyUnusedCands(maskSource(raw, fe), baseName(f.FilePath) == "__main__.py" || rawHas(raw, `__name__ == "__main__"`, `__name__ == '__main__'`))
		case ".go":
			cands = goUnusedCands(stripped, raw)
		case ".java":
			cands = lineCands(stripped, raw, reJavaPriv)
		case ".kt", ".kts":
			cands = lineCands(stripped, raw, reKotlinPriv)
		case ".swift":
			cands = lineCands(stripped, raw, reSwiftPriv)
		case ".rs":
			cands = lineCands(stripped, raw, reRustFn)
		default:
			if isJSFamily(fe) && !strings.HasSuffix(strings.ToLower(f.FilePath), ".d.ts") {
				cands = lineCands(stripped, raw, reJSFuncDecl)
			}
		}
		if len(cands) == 0 {
			continue
		}
		local := map[string]int{}
		if !(fe == ".py" || fe == ".go") {
			tokenCounts(stripped, local)
		}
		sup := security.NewSuppressor(raw)
		for _, c := range cands {
			if skipSymbol(c.name) {
				continue
			}
			var n, ns int
			if fe == ".py" || fe == ".go" {
				n, ns = codeTok[c.name], strTok[c.name]
			} else {
				n = local[c.name]
			}
			if n > 1 || ns > 0 {
				continue
			}
			sev, id, rule := security.SevMedium, "dead-unused-symbol", "Unused function / class"
			if c.conf < 90 {
				sev, id, rule = security.SevLow, "dead-possibly-unused", "Possibly unused public function / class"
			}
			snip := strings.TrimSpace(raw[c.line])
			if len(snip) > 100 {
				snip = snip[:100] + "…"
			}
			is := CSIssue{RuleID: id, Rule: rule, Detail: fmt.Sprintf("%s (%d%% confidence)", c.name, c.conf),
				Message:  "Nothing in the scanned code refers to it by name. Delete it, or — if it is reached dynamically (reflection, a plugin registry, a framework hook) — keep it and mark it `# noqa` / `//nolint`.",
				Severity: sev, FilePath: f.FilePath, Line: c.line + 1, Snippet: snip}
			if !sup.Suppressed(is.Line, is.RuleID) {
				out = append(out, is)
			}
		}
	}
	return out
}

func rawHas(raw []string, subs ...string) bool {
	for _, l := range raw {
		for _, s := range subs {
			if strings.Contains(l, s) {
				return true
			}
		}
	}
	return false
}

// skipSymbol drops names that are entry points or conventionally reached indirectly.
func skipSymbol(n string) bool {
	switch n {
	case "main", "init", "setUp", "tearDown", "setup", "teardown", "run", "_":
		return true
	}
	return strings.HasPrefix(n, "test") || strings.HasPrefix(n, "Test") || strings.HasPrefix(n, "__") && strings.HasSuffix(n, "__")
}

// pyUnusedCands lists private (and in apps, public module-level) defs and classes.
func pyUnusedCands(m maskedFile, script bool) []symCand {
	funcs, classes := pyParse(m)
	var out []symCand
	isPrivate := func(n string) bool {
		return strings.HasPrefix(n, "_") && !(strings.HasPrefix(n, "__") && strings.HasSuffix(n, "__"))
	}
	decorated := func(f pyFunc) bool {
		for _, d := range f.decorators {
			d = strings.TrimSpace(d)
			if !strings.HasPrefix(d, "staticmethod") && !strings.HasPrefix(d, "classmethod") && !strings.HasPrefix(d, "property") && !strings.HasPrefix(d, "functools.") && !strings.HasPrefix(d, "lru_cache") {
				return true // routes, fixtures, signals, registrations…
			}
		}
		return false
	}
	for _, f := range funcs {
		if f.enclosedDef || decorated(f) {
			continue
		}
		switch {
		case isPrivate(f.name):
			out = append(out, symCand{name: f.name, line: f.start, conf: 90, fileWide: true})
		case script && f.class == "" && !strings.HasPrefix(f.name, "_"):
			out = append(out, symCand{name: f.name, line: f.start, conf: 60, fileWide: true})
		}
	}
	for _, c := range classes {
		switch {
		case isPrivate(c.name):
			out = append(out, symCand{name: c.name, line: c.start, conf: 90, fileWide: true})
		case script && c.indent == 0:
			out = append(out, symCand{name: c.name, line: c.start, conf: 60, fileWide: true})
		}
	}
	return out
}

// goUnusedCands lists unexported package-level funcs, methods, types, vars and consts.
func goUnusedCands(stripped, raw []string) []symCand {
	var out []symCand
	for i, l := range stripped {
		var name string
		switch {
		case reGoFuncDecl.MatchString(l):
			name = reGoFuncDecl.FindStringSubmatch(l)[1]
		case reGoTypeDecl.MatchString(l):
			name = reGoTypeDecl.FindStringSubmatch(l)[1]
		case reGoVarDecl.MatchString(l):
			name = reGoVarDecl.FindStringSubmatch(l)[1]
		default:
			continue
		}
		if name == "" || (name[0] >= 'A' && name[0] <= 'Z') {
			continue // exported: reachable from other packages
		}
		if i > 0 && (strings.HasPrefix(raw[i-1], "//go:") || strings.HasPrefix(raw[i-1], "//export")) {
			continue
		}
		out = append(out, symCand{name: name, line: i, conf: 90, fileWide: true})
	}
	return out
}

// lineCands applies a one-name-per-line declaration regexp to the stripped lines,
// skipping declarations an annotation / attribute sits above (framework hooks).
func lineCands(stripped, raw []string, re *regexp.Regexp) []symCand {
	var out []symCand
	for i, l := range stripped {
		g := re.FindStringSubmatch(l)
		if g == nil || strings.Contains(l[:re.FindStringIndex(l)[0]], "@") {
			continue // an annotation on the same line marks a framework hook
		}
		name := ""
		for _, x := range g[1:] {
			if x != "" {
				name = x
			}
		}
		if name == "" {
			continue
		}
		if i > 0 {
			prev := strings.TrimSpace(raw[i-1])
			if strings.HasPrefix(prev, "@") || strings.HasPrefix(prev, "#[") || strings.HasPrefix(prev, "[") {
				continue
			}
		}
		if strings.Contains(l, "export ") || strings.Contains(l, "pub ") || strings.Contains(l, "default ") {
			continue
		}
		out = append(out, symCand{name: name, line: i, conf: 90})
	}
	return out
}
