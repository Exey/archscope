// dupcode.go is Code Structure's Duplicate-code subcard: if/else-if/else chains
// whose neighbouring branches have the identical body (go-critic dupBranchBody)
// and switches that list the same case label twice (go-critic dupCase). Both
// read the length-preserving masked source (srcmask.go) so a brace in a string
// or comment can't unbalance the walk, and compare the *unmasked* text so two
// branches that differ only in a string literal are not called duplicates.
// Brace languages only (Go, Java, Kotlin, Swift, TS/JS, Rust, C-family); the
// indentation-based Python has no braces to walk.
package constructs

import (
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/security"
)

var (
	reIfWord      = regexp.MustCompile(`\bif\b`)
	reSwitchWord  = regexp.MustCompile(`\bswitch\b`)
	reCaseWord    = regexp.MustCompile(`\bcase\b`)
	reElsePrefix  = regexp.MustCompile(`\belse\s*$`)
	reTrivialBody = regexp.MustCompile(`^(?:return|break|continue|fallthrough|pass)\w*[\w.()"'\-]*;?$`)
)

// minDupBodyLen is the shortest normalised body worth calling a duplicate:
// two branches that both just `return nil` are usually deliberate.
const minDupBodyLen = 20

type ifBranch struct {
	open   int // offset of '{'
	body   string
	scoped bool // the header declares a variable (`if m := f(); m != nil`), so identical text can mean different things
}

// scanDuplicateCode returns the duplicate-branch and duplicate-case issues of one file.
func scanDuplicateCode(filePath string, m maskedFile) []CSIssue {
	fe := ext(filePath)
	if csStringLang(fe) == csStrPython || csStringLang(fe) == csStrNone {
		return nil
	}
	f := m.flat()
	bare := bareConditions(fe)
	var out []CSIssue
	add := func(off int, sev security.Severity, id, rule, msg string) {
		li := f.line(off)
		snip := strings.TrimSpace(m.raw[li])
		if len(snip) > 100 {
			snip = snip[:100] + "…"
		}
		out = append(out, CSIssue{RuleID: id, Rule: rule, Message: msg, Severity: sev, FilePath: filePath, Line: li + 1, Snippet: snip})
	}

	// dupBranchBody: walk each if-chain head.
	for _, loc := range reIfWord.FindAllStringIndex(f.code, -1) {
		if reElsePrefix.MatchString(f.code[:loc[0]]) {
			continue // `else if` continues a chain that its head already walked
		}
		var branches []ifBranch
		pos := loc[1]
		for {
			open := f.bodyStart(pos, bare)
			if open < 0 {
				break
			}
			cl := f.matchClose(open)
			if cl < 0 {
				break
			}
			branches = append(branches, ifBranch{open: open, body: squash(f.text[open+1 : cl]), scoped: strings.Contains(f.code[pos:open], ":=")})
			next := f.skipSpace(cl + 1)
			if !f.wordAt(next, "else") {
				break
			}
			next = f.skipSpace(next + 4)
			if next < len(f.code) && f.code[next] == '{' {
				cl2 := f.matchClose(next)
				if cl2 < 0 {
					break
				}
				branches = append(branches, ifBranch{open: next, body: squash(f.text[next+1 : cl2])})
				break
			}
			if !f.wordAt(next, "if") {
				break
			}
			pos = next + 2
		}
		for i := 1; i < len(branches); i++ {
			a, b := branches[i-1].body, branches[i].body
			if a == b && len(a) >= minDupBodyLen && !reTrivialBody.MatchString(a) && !branches[i-1].scoped && !branches[i].scoped {
				add(branches[i].open, security.SevLow, "dup-branch", "Identical if/else branch bodies",
					"Two neighbouring branches run the same code; merge the conditions (`a || b`) or drop the redundant branch — often a copy-paste bug where one body was meant to differ.")
			}
		}
	}

	// dupCase: the same label twice inside one switch.
	if fe == ".kt" || fe == ".kts" || fe == ".rs" {
		return out // `when` / `match` arms aren't `case` labels
	}
	for _, loc := range reSwitchWord.FindAllStringIndex(f.code, -1) {
		open := f.bodyStart(loc[1], bare)
		if open < 0 {
			continue
		}
		cl := f.matchClose(open)
		if cl < 0 {
			continue
		}
		seen := map[string]bool{}
		for _, c := range switchCases(f, open, cl) {
			if seen[c.label] {
				add(c.off, security.SevMedium, "dup-case", "Duplicate case label",
					"The same case value is listed twice in one switch; the second can never run. Remove it or fix the intended value.")
			}
			seen[c.label] = true
		}
	}
	return out
}

// caseColon finds the ':' ending a case label (not part of '::' or a ternary).
func caseColon(code string, from, limit int) int {
	depth, ternary := 0, 0
	for i := from; i < limit; i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '?':
			if depth == 0 {
				ternary++
			}
		case ':':
			if depth != 0 {
				continue
			}
			if i+1 < limit && code[i+1] == ':' {
				i++
				continue
			}
			if ternary > 0 {
				ternary--
				continue
			}
			return i
		}
	}
	return -1
}

// splitTopLevel splits text on sep wherever code (the masked twin of text, same
// length) has it outside any bracket pair — so a separator inside a string or
// char literal, which masking blanks, never splits.
func splitTopLevel(code, text string, sep byte) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(code); i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case sep:
			if depth == 0 {
				out = append(out, text[start:i])
				start = i + 1
			}
		}
	}
	return append(out, text[start:])
}
