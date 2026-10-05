// bugsmells.go is Code Structure's "Suspicious code" subcard — the Go-only,
// bug-class checkers of ~/go-critic, ported to run lexically (no type checker)
// over the length-preserving masked source: dupSubExpr, badCond, caseOrder,
// offBy1, returnAfterHttpError, exitAfterDefer, badLock, uncheckedInlineErr,
// externalErrorReassign and sloppyReassign. go-critic proves most of these with
// types; here each is a deliberately narrow pattern that errs toward silence, so
// a hit is "read this line again", not a verdict.
package constructs

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/exey/archscope/internal/security"
)

const goOperand = `[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|\[[\w.]+\])*`

var (
	reDupBinary = regexp.MustCompile(`(` + goOperand + `)\s*(&&|\|\||==|!=|<=|>=|<|>|-|/|%)\s*(` + goOperand + `)`)

	reBadCond = regexp.MustCompile(`\b(` + goOperand + `)\s*(<=|>=|==|!=|<|>)\s*(-?\d+)\s*(&&|\|\|)\s*(` + goOperand + `)\s*(<=|>=|==|!=|<|>)\s*(-?\d+)\b`)

	reLenIndex    = regexp.MustCompile(`\b(` + goOperand + `)\[len\(\s*(` + goOperand + `)\s*\)\]`)
	reIndexSlice  = regexp.MustCompile(`\b(` + goOperand + `)\[(?::\s*)?(?:strings|bytes)\.Index\(\s*(` + goOperand + `)\s*,[^()]*\)\s*(?::)?\]`)
	reIndexAssign = regexp.MustCompile(`^\s*(\w+)\s*:=\s*(?:strings|bytes)\.Index\(\s*(` + goOperand + `)\s*,`)

	reHTTPError = regexp.MustCompile(`\bhttp\.Error\s*\(`)
	reExitCall  = regexp.MustCompile(`\b(?:os\.Exit|log\.Fatal(?:f|ln)?)\s*\(`)
	reDeferWord = regexp.MustCompile(`\bdefer\b`)

	reLockStmt  = regexp.MustCompile(`^\s*(` + goOperand + `)\.(Lock|RLock)\(\)\s*;?\s*$`)
	reLockNext  = regexp.MustCompile(`^\s*(defer\s+)?(` + goOperand + `)\.(Unlock|RUnlock|Lock|RLock)\(\)\s*;?\s*$`)
	reInlineErr = regexp.MustCompile(`\bif\s+([\w\s,]+?)\s*:?=\s*[^;=][^;]*;\s*(\w+)\s*!=\s*nil`)
	reSloppyRe  = regexp.MustCompile(`\bif\s+(\w+)\s*=\s*[^;=][^;]*;\s*(\w+)\s*!=\s*nil`)
	reErrAssign = regexp.MustCompile(`^\s*(\w+)\.(Err\w*|EOF|\w*Error)\s*=[^=]`)
	reImportRow = regexp.MustCompile(`^\s*(?:import\s+)?(?:(\w+|\.|_)\s+)?"([^"]+)"\s*$`)
	reErrName   = regexp.MustCompile(`(?i)err`)
	reTypeSw    = regexp.MustCompile(`\.\(\s*type\s*\)`)
	reMajorVer  = regexp.MustCompile(`^v\d+$`)
)

// scanBugSmells runs the Go bug-class checks on one masked file.
func scanBugSmells(filePath string, m maskedFile) []CSIssue {
	if ext(filePath) != ".go" {
		return nil
	}
	f := m.flat()
	var out []CSIssue
	add := func(li int, sev security.Severity, id, rule, msg string) {
		snip := strings.TrimSpace(m.raw[li])
		if len(snip) > 100 {
			snip = snip[:100] + "…"
		}
		out = append(out, CSIssue{RuleID: id, Rule: rule, Message: msg, Severity: sev, FilePath: filePath, Line: li + 1, Snippet: snip})
	}
	pkgs := goImportNames(m.text)

	for i, line := range m.code {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// dupSubExpr
		for _, loc := range reDupBinary.FindAllStringSubmatchIndex(line, -1) {
			l, op, r := line[loc[2]:loc[3]], line[loc[4]:loc[5]], line[loc[6]:loc[7]]
			if l != r || goKeywordOperand(l) || !dupPrevOK(line, loc[2]) || !dupNextOK(line, loc[7]) {
				continue
			}
			add(i, security.SevMedium, "dup-subexpr", "Identical operands",
				"Both sides of `"+op+"` are the same expression `"+l+"` — always the same result, so almost certainly a copy-paste slip (one side was meant to be a different variable).")
		}

		// badCond
		for _, g := range reBadCond.FindAllStringSubmatch(line, -1) {
			if g[1] != g[5] {
				continue
			}
			a, _ := strconv.Atoi(g[3])
			b, _ := strconv.Atoi(g[7])
			if a == b && g[2] == g[6] {
				continue
			}
			if verdict := condVerdict(g[2], a, g[4], g[6], b); verdict != "" {
				add(i, security.SevMedium, "bad-cond", "Condition is always "+verdict,
					"`"+g[0]+"` can never differ from "+verdict+" — the two comparisons contradict (or cover) each other; check the operators (&& vs ||) and bounds.")
			}
		}

		// offBy1: x[len(x)] always panics.
		for _, g := range reLenIndex.FindAllStringSubmatch(line, -1) {
			if g[1] == g[2] {
				add(i, security.SevHigh, "off-by-one", "Index one past the end",
					"`"+g[1]+"[len("+g[1]+")]` always panics: valid indexes end at len-1. Probably meant `"+g[1]+"[len("+g[1]+")-1]`.")
			}
		}
		// offBy1: s[strings.Index(s, x):] — Index returns -1 when absent.
		for _, g := range reIndexSlice.FindAllStringSubmatch(line, -1) {
			if g[1] == g[2] {
				add(i, security.SevMedium, "off-by-one", "Slicing at an unchecked Index()",
					"strings/bytes.Index returns -1 when not found, so slicing with it panics; check for -1 first (and remember the match itself is at [i:i+len(sep)]).")
			}
		}
		if g := reIndexAssign.FindStringSubmatch(line); g != nil {
			if j := nextSig(m.code, i); j >= 0 {
				n := m.code[j]
				if strings.Contains(n, g[2]+"["+g[1]+":]") || strings.Contains(n, g[2]+"[:"+g[1]+"]") {
					add(j, security.SevMedium, "off-by-one", "Slicing at an unchecked Index()",
						"`"+g[1]+"` comes from Index() and can be -1; slicing with it before checking panics.")
				}
			}
		}

		// uncheckedInlineErr
		if g := reInlineErr.FindStringSubmatch(line); g != nil {
			vars := strings.Split(g[1], ",")
			last := strings.TrimSpace(vars[len(vars)-1])
			if last != g[2] && reErrName.MatchString(last) && reErrName.MatchString(g[2]) && last != "_" {
				add(i, security.SevMedium, "unchecked-inline-err", "Inline error checked under another name",
					"`"+last+"` is assigned in the if-init but `"+g[2]+"` is what gets tested, so the new error is never checked.")
			}
		}

		// sloppyReassign
		if g := reSloppyRe.FindStringSubmatch(line); g != nil && g[1] == g[2] {
			add(i, security.SevLow, "sloppy-reassign", "Re-assignment in if-init",
				"`if "+g[1]+" = …; "+g[1]+" != nil` re-assigns an outer variable; use `:=` to scope it to the if (unless writing to a named result is intended).")
		}

		// externalErrorReassign
		if g := reErrAssign.FindStringSubmatch(line); g != nil && pkgs[g[1]] {
			add(i, security.SevMedium, "external-error-reassign", "Reassigning another package's error",
				"`"+g[1]+"."+g[2]+"` is a package-level error value; overwriting it changes behaviour for every other caller (and for errors.Is checks).")
		}

		// badLock
		if g := reLockStmt.FindStringSubmatch(line); g != nil {
			if j := nextSig(m.code, i); j >= 0 {
				if n := reLockNext.FindStringSubmatch(m.code[j]); n != nil && n[2] == g[1] {
					deferred, op, next := n[1] != "", g[2], n[3]
					switch {
					case !deferred && (next == "Unlock" || next == "RUnlock"):
						add(j, security.SevMedium, "bad-lock", "Mutex unlocked immediately",
							"`"+g[1]+"."+op+"()` is followed straight by an unlock without a defer, so the critical section is empty; use `defer "+g[1]+"."+unlockFor(op)+"()`.")
					case !deferred && (next == "Lock" || next == "RLock"):
						add(j, security.SevHigh, "bad-lock", "Mutex locked twice",
							"`"+g[1]+"` is locked again before being unlocked — this deadlocks.")
					case deferred && (next == "Lock" || next == "RLock"):
						add(j, security.SevHigh, "bad-lock", "Deferred lock instead of unlock",
							"`defer "+g[1]+"."+next+"()` re-locks at return; probably meant `defer "+g[1]+"."+unlockFor(op)+"()`.")
					case deferred && next != unlockFor(op):
						add(j, security.SevHigh, "bad-lock", "Mismatched lock/unlock",
							"`"+g[1]+"."+op+"()` is paired with `"+next+"`; use `"+unlockFor(op)+"`.")
					}
				}
			}
		}
	}

	// returnAfterHttpError: http.Error as the last statement of an if block.
	for _, loc := range reHTTPError.FindAllStringIndex(f.code, -1) {
		cl := f.matchClose(loc[1] - 1)
		if cl < 0 {
			continue
		}
		next := f.skipSpace(cl + 1)
		if next < len(f.code) && f.code[next] == ';' {
			next = f.skipSpace(next + 1)
		}
		if next >= len(f.code) || f.code[next] != '}' {
			continue
		}
		open := f.matchOpen(next)
		if open < 0 {
			continue
		}
		hdr := strings.TrimSpace(m.code[f.line(open)])
		if strings.HasPrefix(hdr, "if ") || strings.Contains(hdr, "else") {
			add(f.line(loc[0]), security.SevMedium, "http-error-no-return", "http.Error without return",
				"http.Error only writes the response; execution continues after the if block, so the handler may write twice or act on bad input. Add `return` after it.")
		}
	}

	// caseOrder in type switches.
	for _, loc := range reTypeSw.FindAllStringIndex(f.code, -1) {
		open := f.bodyStart(loc[1], true)
		if open < 0 {
			continue
		}
		cl := f.matchClose(open)
		if cl < 0 {
			continue
		}
		cases := switchCases(f, open, cl)
		for ci, c := range cases {
			rest := cases[ci+1:]
			if len(rest) == 0 {
				continue
			}
			switch c.label {
			case "any", "interface{}":
				add(f.line(c.off), security.SevMedium, "case-order", "Catch-all case before specific cases",
					"`case "+c.label+"` matches every type, so the cases after it can never run; move it last.")
			case "error":
				for _, r := range rest {
					if n := strings.TrimLeft(r.label, "*"); strings.HasSuffix(n, "Error") || strings.HasSuffix(n, "Err") {
						add(f.line(r.off), security.SevMedium, "case-order", "Specific error case after `case error`",
							"`case error` already matches `"+r.label+"` (it implements error), so this case is unreachable; put the concrete type first.")
						break
					}
				}
			}
		}
	}

	// exitAfterDefer
	for _, fr := range csFuncRanges(m.code) {
		deferAt := -1
		for i := fr.start; i <= fr.end && i < len(m.code); i++ {
			if deferAt < 0 && reDeferWord.MatchString(m.code[i]) {
				deferAt = i
				continue
			}
			if deferAt >= 0 && reExitCall.MatchString(m.code[i]) {
				add(i, security.SevMedium, "exit-after-defer", "Exit in a function that defers",
					"os.Exit / log.Fatal terminate immediately without running the deferred calls above (unlocks, closes, flushes). Return the error and exit from main instead.")
			}
		}
	}
	return out
}

// goKeywordOperand excludes literals-by-name that make a "same operand" test
// meaningless.
func goKeywordOperand(s string) bool {
	return s == "true" || s == "false" || s == "nil" || s == "iota"
}

// dupPrevOK reports whether the operand starting at start begins a fresh
// sub-expression (so `x - a - a` isn't misread as `a - a`).
func dupPrevOK(line string, start int) bool {
	i := start - 1
	if i >= 0 && (isIdentByte(line[i]) || line[i] == '.') {
		return false // mid-identifier
	}
	for i >= 0 && (line[i] == ' ' || line[i] == '\t') {
		i--
	}
	if i < 0 {
		return true
	}
	switch c := line[i]; c {
	case '(', ',', '{', ';', '[', ':':
		return true
	case '=':
		return i == 0 || !strings.ContainsRune("=!<>", rune(line[i-1]))
	case '&':
		return i > 0 && line[i-1] == '&'
	case '|':
		return i > 0 && line[i-1] == '|'
	default:
		return isIdentByte(c) // preceded by a keyword such as if / return
	}
}

// dupNextOK reports whether the operand ending at end closes its sub-expression.
func dupNextOK(line string, end int) bool {
	i := end
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i >= len(line) {
		return true
	}
	switch line[i] {
	case ')', ']', '}', ',', ';', '{', ':', '?':
		return true
	case '&':
		return strings.HasPrefix(line[i:], "&&")
	case '|':
		return strings.HasPrefix(line[i:], "||")
	}
	return false
}

func unlockFor(lockOp string) string {
	if lockOp == "RLock" {
		return "RUnlock"
	}
	return "Unlock"
}

// condVerdict evaluates `x op1 a (&&|||) x op2 b` over the integers around the
// constants and reports "false" when it can never hold, "true" when it always does.
func condVerdict(op1 string, a int, join, op2 string, b int) string {
	holds := func(op string, x, c int) bool {
		switch op {
		case "<":
			return x < c
		case "<=":
			return x <= c
		case ">":
			return x > c
		case ">=":
			return x >= c
		case "==":
			return x == c
		default: // !=
			return x != c
		}
	}
	always, never := true, true
	for _, c := range []int{a, b} {
		for d := -1; d <= 1; d++ {
			x := c + d
			var v bool
			if join == "&&" {
				v = holds(op1, x, a) && holds(op2, x, b)
			} else {
				v = holds(op1, x, a) || holds(op2, x, b)
			}
			if v {
				never = false
			} else {
				always = false
			}
		}
	}
	switch {
	case never:
		return "false"
	case always:
		return "true"
	}
	return ""
}

// nextSig returns the next line after i whose code is non-blank, or -1.
func nextSig(code []string, i int) int {
	for j := i + 1; j < len(code); j++ {
		if strings.TrimSpace(code[j]) != "" {
			return j
		}
	}
	return -1
}

// goImportNames returns the identifiers a Go file's imports bind (alias, or the
// last path element with a /vN major-version suffix skipped).
func goImportNames(text []string) map[string]bool {
	names := map[string]bool{}
	inBlock := false
	for _, l := range text {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "import ("):
			inBlock = true
			continue
		case inBlock && t == ")":
			inBlock = false
			continue
		case !inBlock && !strings.HasPrefix(t, "import "):
			continue
		}
		g := reImportRow.FindStringSubmatch(t)
		if g == nil {
			continue
		}
		if g[1] != "" && g[1] != "_" && g[1] != "." {
			names[g[1]] = true
			continue
		}
		parts := strings.Split(g[2], "/")
		name := parts[len(parts)-1]
		if len(parts) > 1 && reMajorVer.MatchString(name) {
			name = parts[len(parts)-2]
		}
		names[name] = true
	}
	return names
}

// caseLabel is one top-level case value of a switch.
type caseLabel struct {
	label string
	off   int
}

// switchCases lists every case label (comma-split) that sits directly in the
// switch body between open and cl, in order.
func switchCases(f flatSrc, open, cl int) []caseLabel {
	var out []caseLabel
	depth := 0
	for i := open + 1; i < cl; i++ {
		switch f.code[i] {
		case '{':
			depth++
			continue
		case '}':
			depth--
			continue
		}
		if depth != 0 || !f.wordAt(i, "case") || (i > 0 && isIdentByte(f.code[i-1])) {
			continue
		}
		colon := caseColon(f.code, i+4, cl)
		if colon < 0 {
			continue
		}
		for _, label := range splitTopLevel(f.code[i+4:colon], f.text[i+4:colon], ',') {
			if label = squash(label); label != "" {
				out = append(out, caseLabel{label: label, off: i})
			}
		}
		i = colon
	}
	return out
}

// matchOpen returns the offset of the '{' matching the '}' at closeOff, or -1.
func (f flatSrc) matchOpen(closeOff int) int {
	depth := 0
	for i := closeOff; i >= 0; i-- {
		switch f.code[i] {
		case '}':
			depth++
		case '{':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
