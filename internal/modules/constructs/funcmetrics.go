// funcmetrics.go computes the per-function numbers behind two Code Structure
// subcards: 🌀 Cyclomatic complexity (McCabe's decision-point count) and 📐 Shape
// limits (pylint's too-many-returns / branches / locals, plus Python class and
// module-size limits). They run on Python (via pyparse.go) and on the brace
// languages' function ranges (csFuncRanges: Go, Rust, Kotlin, Swift and JS/TS
// `function` declarations). Lexical counts over comment/string-stripped lines.
package constructs

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/security"
)

// Thresholds: McCabe's "moderate risk" starts above 10; the shape limits are
// pylint's defaults (max-returns 6, max-branches 12, max-locals 15,
// max-attributes 7, max-public-methods 20, max-module-lines 1000).
const (
	csMaxCyclomatic   = 10
	csMaxReturns      = 6
	csMaxBranches     = 12
	csMaxLocals       = 15
	csMaxClassAttrs   = 7
	csMaxPublicMethod = 20
	csMaxClassBases   = 4
	csMaxModuleLines  = 1000
)

var (
	reCCBrace    = regexp.MustCompile(`\bif\b|\bfor\b|\bwhile\b|\bcatch\b|\bcase\b|\bforeach\b|\bguard\b|&&|\|\||\s\?\s`)
	reCCRust     = regexp.MustCompile(`\bif\b|\bfor\b|\bwhile\b|=>|&&|\|\||\bloop\b`)
	reCCPy       = regexp.MustCompile(`\bif\b|\belif\b|\bfor\b|\bwhile\b|\bexcept\b|\band\b|\bor\b|\bcase\b`)
	reReturnWord = regexp.MustCompile(`\breturn\b`)
	reBranchWord = regexp.MustCompile(`\bif\b|\bfor\b|\bwhile\b|\bcatch\b|\bexcept\b|\bcase\b|\belif\b|\belse\b`)
	reElseIf     = regexp.MustCompile(`\belse\s+if\b`)

	reLocalPy      = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=(?:[^=]|$)`)
	reLocalPyTuple = regexp.MustCompile(`^\s*\(?\s*([A-Za-z_*]\w*(?:\s*,\s*\*?[A-Za-z_]\w*)+)\s*\)?\s*=(?:[^=]|$)`)
	reLocalPyFor   = regexp.MustCompile(`\bfor\s+\(?\s*([A-Za-z_]\w*(?:\s*,\s*\*?[A-Za-z_]\w*)*)\s*\)?\s+in\b`)
	reLocalPyAs    = regexp.MustCompile(`\bas\s+([A-Za-z_]\w*)\s*[:,)]`)
	reLocalGo      = regexp.MustCompile(`^\s*(?:var\s+)?([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*:=`)
	reLocalDecl    = regexp.MustCompile(`\b(?:let|const|var|val|final|auto|mut)\s+(?:mut\s+)?([A-Za-z_$][\w$]*)`)
	reLocalTyped   = regexp.MustCompile(`^\s*(?:final\s+)?[A-Za-z_][\w<>\[\],.*&?:]*\s+([a-z_]\w*)\s*=(?:[^=]|$)`)
	localKeywords  = map[string]bool{"return": true, "else": true, "case": true, "throw": true, "yield": true, "await": true, "delete": true, "typeof": true, "import": true, "from": true, "print": true, "assert": true, "raise": true, "del": true, "pass": true, "with": true}
)

// funcStat is everything measured about one function.
type funcStat struct {
	name                          string
	line                          int // 1-based
	cc, returns, branches, locals int
}

// bodyStats measures a function body given as stripped (comment/string-free) lines.
func bodyStats(lang csStrLang, fe string, body []string, paramNames []string) funcStat {
	st := funcStat{cc: 1}
	names := map[string]bool{}
	for _, p := range paramNames {
		names[p] = true
	}
	ccRe := reCCBrace
	switch {
	case lang == csStrPython:
		ccRe = reCCPy
	case lang == csStrRust:
		ccRe = reCCRust
	}
	for _, l := range body {
		t := strings.TrimSpace(l)
		if t == "" || (lang != csStrPython && strings.HasPrefix(t, "#")) {
			continue
		}
		st.cc += len(ccRe.FindAllStringIndex(l, -1))
		st.returns += len(reReturnWord.FindAllStringIndex(l, -1))
		st.branches += len(reBranchWord.FindAllStringIndex(l, -1)) - len(reElseIf.FindAllStringIndex(l, -1))
		collectLocals(lang, l, names)
	}
	st.locals = len(names)
	return st
}

func collectLocals(lang csStrLang, l string, names map[string]bool) {
	addList := func(list string) {
		for _, n := range strings.Split(list, ",") {
			n = strings.TrimLeft(strings.TrimSpace(n), "*")
			if n != "" && n != "_" && n != "self" && n != "cls" && !localKeywords[n] {
				names[n] = true
			}
		}
	}
	switch lang {
	case csStrPython:
		if g := reLocalPyTuple.FindStringSubmatch(l); g != nil {
			addList(g[1])
		} else if g := reLocalPy.FindStringSubmatch(l); g != nil {
			addList(g[1])
		}
		for _, g := range reLocalPyFor.FindAllStringSubmatch(l, -1) {
			addList(g[1])
		}
		for _, g := range reLocalPyAs.FindAllStringSubmatch(l, -1) {
			addList(g[1])
		}
	case csStrGo:
		if g := reLocalGo.FindStringSubmatch(l); g != nil {
			addList(g[1])
		}
		for _, g := range reLocalDecl.FindAllStringSubmatch(l, -1) {
			addList(g[1])
		}
	default:
		for _, g := range reLocalDecl.FindAllStringSubmatch(l, -1) {
			addList(g[1])
		}
		if g := reLocalTyped.FindStringSubmatch(l); g != nil {
			addList(g[1])
		}
	}
}

// pyParamNames lists the parameter names of a def (self/cls excluded).
func pyParamNames(params string) []string {
	var out []string
	for _, p := range splitTopLevel(params, params, ',') {
		p = strings.TrimSpace(p)
		p = strings.TrimLeft(p, "*")
		if i := strings.IndexAny(p, ":="); i >= 0 {
			p = strings.TrimSpace(p[:i])
		}
		if p != "" && p != "self" && p != "cls" && p != "/" {
			out = append(out, p)
		}
	}
	return out
}

// shapeSeverity maps a value over its limit to LOW, or MEDIUM past twice the limit.
func shapeSeverity(v, limit int) security.Severity {
	if v > 2*limit {
		return security.SevMedium
	}
	return security.SevLow
}

// funcShapeIssues turns one function's stats into shape issues (each a separate rule).
func funcShapeIssues(filePath string, raw []string, st funcStat) []CSIssue {
	var out []CSIssue
	mk := func(id, rule, msg, detail string, sev security.Severity) {
		snip := ""
		if st.line-1 < len(raw) && st.line-1 >= 0 {
			snip = strings.TrimSpace(raw[st.line-1])
			if len(snip) > 100 {
				snip = snip[:100] + "…"
			}
		}
		out = append(out, CSIssue{RuleID: id, Rule: rule, Message: msg, Detail: detail, Severity: sev, FilePath: filePath, Line: st.line, Snippet: snip})
	}
	if st.returns > csMaxReturns {
		mk("shape-returns", "Too many return statements",
			fmt.Sprintf("More than %d exits make a function hard to follow; use guard clauses at the top, then one main path, or split it.", csMaxReturns),
			fmt.Sprintf("%s, %d returns", st.name, st.returns), shapeSeverity(st.returns, csMaxReturns))
	}
	if st.branches > csMaxBranches {
		mk("shape-branches", "Too many branches",
			fmt.Sprintf("More than %d if/else/loop/except branches; extract the branches into helpers or use a lookup table.", csMaxBranches),
			fmt.Sprintf("%s, %d branches", st.name, st.branches), shapeSeverity(st.branches, csMaxBranches))
	}
	if st.locals > csMaxLocals {
		mk("shape-locals", "Too many local variables",
			fmt.Sprintf("More than %d locals (arguments included in Python) — the function is holding too much state; split it.", csMaxLocals),
			fmt.Sprintf("%s, %d locals", st.name, st.locals), shapeSeverity(st.locals, csMaxLocals))
	}
	return out
}

// pyClassShape reports Python classes with too many instance attributes,
// public methods or direct bases.
func pyClassShape(filePath string, m maskedFile, classes []pyClass, funcs []pyFunc) []CSIssue {
	var out []CSIssue
	mk := func(c pyClass, id, rule, msg, detail string, sev security.Severity) {
		snip := strings.TrimSpace(m.raw[c.start])
		if len(snip) > 100 {
			snip = snip[:100] + "…"
		}
		out = append(out, CSIssue{RuleID: id, Rule: rule, Message: msg, Detail: detail, Severity: sev, FilePath: filePath, Line: c.start + 1, Snippet: snip})
	}
	reSelfAttr := regexp.MustCompile(`\bself\.([A-Za-z_]\w*)\s*(?::[^=]+)?=(?:[^=]|$)`)
	for _, c := range classes {
		attrs := map[string]bool{}
		for i := c.start; i <= c.end && i < len(m.code); i++ {
			for _, g := range reSelfAttr.FindAllStringSubmatch(m.code[i], -1) {
				attrs[g[1]] = true
			}
		}
		if n := len(attrs); n > csMaxClassAttrs {
			mk(c, "shape-class-attrs", "Too many instance attributes",
				fmt.Sprintf("More than %d attributes set on self — the class is doing too much; group related fields into smaller objects.", csMaxClassAttrs),
				fmt.Sprintf("%s, %d attributes", c.name, n), shapeSeverity(n, csMaxClassAttrs))
		}
		methods := 0
		for _, f := range funcs {
			if f.class == c.name && f.start > c.start && f.start <= c.end && !strings.HasPrefix(f.name, "_") {
				methods++
			}
		}
		if methods > csMaxPublicMethod {
			mk(c, "shape-class-methods", "Too many public methods",
				fmt.Sprintf("More than %d public methods — split the class by responsibility.", csMaxPublicMethod),
				fmt.Sprintf("%s, %d methods", c.name, methods), shapeSeverity(methods, csMaxPublicMethod))
		}
		if c.bases != "" {
			bases := 0
			for _, b := range splitTopLevel(c.bases, c.bases, ',') {
				b = strings.TrimSpace(b)
				if b != "" && !strings.Contains(b, "=") { // metaclass=…, total=… are keywords, not bases
					bases++
				}
			}
			if bases > csMaxClassBases {
				mk(c, "shape-class-bases", "Too many base classes",
					fmt.Sprintf("More than %d direct bases makes the method resolution order hard to reason about; prefer composition.", csMaxClassBases),
					fmt.Sprintf("%s, %d bases", c.name, bases), security.SevLow)
			}
		}
	}
	return out
}

// moduleSizeIssue flags a file over csMaxModuleLines (generated files excluded).
func moduleSizeIssue(filePath string, raw []string) []CSIssue {
	if len(raw) <= csMaxModuleLines || isGeneratedHeader(raw) {
		return nil
	}
	sev := security.SevLow
	if len(raw) > 2*csMaxModuleLines {
		sev = security.SevMedium
	}
	return []CSIssue{{RuleID: "shape-module-lines", Rule: "Module is too long",
		Message:  fmt.Sprintf("Files over %d lines are hard to navigate and review; split by responsibility.", csMaxModuleLines),
		Detail:   fmt.Sprintf("%d lines", len(raw)),
		Severity: sev, FilePath: filePath, Line: 1, Snippet: strings.TrimSpace(raw[0])}}
}

// isGeneratedHeader reports a "code generated" / "do not edit" marker in the first lines.
func isGeneratedHeader(raw []string) bool {
	for i := 0; i < len(raw) && i < 6; i++ {
		l := strings.ToLower(raw[i])
		if strings.Contains(l, "code generated") || strings.Contains(l, "do not edit") || strings.Contains(l, "auto-generated") || strings.Contains(l, "autogenerated") || strings.Contains(l, "@generated") {
			return true
		}
	}
	return false
}
