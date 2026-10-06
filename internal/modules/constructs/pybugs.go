// pybugs.go is the Python half of Code Structure's 🐛 Suspicious code subcard:
// the bug-class checks of pylint and pyflakes that don't need a type checker or
// an import of any Python library — mutable default arguments, bare and
// swallowed `except`, `is` against a literal, `assert (a, b)`, duplicate dict
// keys, f-strings with no placeholder, lambdas that capture a loop variable,
// `return` inside `finally`, `raise` without `from`, blocking calls inside
// `async def`, and a few more. Read from the masked source (srcmask.go) with
// the indentation parser in pyparse.go.
package constructs

import (
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/security"
)

var (
	reMutableDefault = regexp.MustCompile(`^(?:\[|\{|(?:set|list|dict|defaultdict|OrderedDict|deque|Counter|bytearray)\s*\()`)
	rePyExcept       = regexp.MustCompile(`^except\b\s*(.*?)\s*(?:\bas\s+\w+\s*)?:(.*)$`)
	rePyIsLiteral    = regexp.MustCompile(`\bis\s+(?:not\s+)?(?:["'\[{]|-?\d)|(?:["']|\b\d+)\s+is\s`)
	rePyAssertTuple  = regexp.MustCompile(`^assert\s*\((.*)\)\s*;?$`)
	rePyFString      = regexp.MustCompile(`(?i)\b(?:rf|fr|f)(?:"([^"\\\n]*)"|'([^'\\\n]*)')`)
	rePyForTarget    = regexp.MustCompile(`^(?:async\s+)?for\s+\(?\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*\)?\s+in\b`)
	rePyLambda       = regexp.MustCompile(`\blambda\b([^:]*):`)
	rePyRaiseNew     = regexp.MustCompile(`^raise\s+[A-Za-z_(]`)
	rePySingleton    = regexp.MustCompile(`[!=]=\s*(?:None|True|False)\b|\b(?:None|True|False)\s*[!=]=`)
	rePyBlocking     = regexp.MustCompile(`\b(?:time\.sleep|requests\.(?:get|post|put|delete|patch|head|request)|urllib\.request\.urlopen|subprocess\.(?:run|call|check_output|check_call))\s*\(`)
	rePyBuiltinAssig = regexp.MustCompile(`^(list|dict|set|str|int|float|bytes|tuple|max|min|sum|len|all|any|map|filter|iter|next|open|print|range|sorted|zip|input|object|hash|bool|reversed|enumerate)\s*=[^=]`)
	rePyWildcard     = regexp.MustCompile(`^from\s+[\w.]+\s+import\s+\*`)
	rePyDupOperand   = regexp.MustCompile(`(` + goOperand + `)\s*(==|!=|<=|>=|<|>|-|/|%|\band\b|\bor\b)\s*(` + goOperand + `)`)
	rePyCaptureSafe  = regexp.MustCompile(`\b(?:sorted|min|max|map|filter|reduce|any|all|sum|groupby)\s*\(|\bkey\s*=\s*$`)
)

// pyLogical returns the logical statement starting at line i (continuation
// lines joined) and the index of its last line.
func pyLogical(code []string, starts []bool, i int) (string, int) {
	var sb strings.Builder
	end := i
	sb.WriteString(strings.TrimSpace(code[i]))
	for j := i + 1; j < len(code) && !starts[j]; j++ {
		if strings.TrimSpace(code[j]) == "" {
			continue
		}
		sb.WriteByte(' ')
		sb.WriteString(strings.TrimSpace(code[j]))
		end = j
	}
	return sb.String(), end
}

// pyBlockEnd is the last line of the block opened by the statement at line i.
func pyBlockEnd(code []string, starts []bool, i int) int {
	base := pyIndent(code[i])
	last := i
	for j := i + 1; j < len(code); j++ {
		if !starts[j] {
			if strings.TrimSpace(code[j]) != "" {
				last = j
			}
			continue
		}
		if pyIndent(code[j]) <= base {
			break
		}
		last = j
	}
	return last
}

// scanPyBugs runs the Python bug-class checks on one masked file.
func scanPyBugs(filePath string, m maskedFile) []CSIssue {
	code := m.code
	starts := pyLogicalStarts(code)
	funcs, _ := pyParse(m)
	var out []CSIssue
	add := func(li int, sev security.Severity, id, rule, detail, msg string) {
		snip := strings.TrimSpace(m.raw[li])
		if len(snip) > 100 {
			snip = snip[:100] + "…"
		}
		out = append(out, CSIssue{RuleID: id, Rule: rule, Message: msg, Detail: detail, Severity: sev, FilePath: filePath, Line: li + 1, Snippet: snip})
	}

	// mutable default arguments
	for _, f := range funcs {
		for _, p := range splitTopLevel(f.params, f.params, ',') {
			i := indexTop(p, '=')
			if i < 0 {
				continue
			}
			def := strings.TrimSpace(p[i+1:])
			if reMutableDefault.MatchString(def) {
				name := strings.TrimSpace(p[:i])
				if j := strings.IndexByte(name, ':'); j >= 0 {
					name = strings.TrimSpace(name[:j])
				}
				add(f.start, security.SevHigh, "py-mutable-default", "Mutable default argument", f.name+"("+name+")",
					"The default is created once and shared by every call, so mutations leak between calls. Use `None` and create the value inside the function.")
			}
		}
	}

	for i := 0; i < len(code); i++ {
		if !starts[i] {
			continue
		}
		stmt, end := pyLogical(code, starts, i)
		raw := stmt

		// except handlers
		if g := rePyExcept.FindStringSubmatch(raw); g != nil {
			exc, tail := strings.TrimSpace(g[1]), strings.TrimSpace(g[2])
			broad := exc == "" || exc == "Exception" || exc == "BaseException" || strings.Contains(exc, "BaseException") || strings.HasPrefix(exc, "(Exception")
			if exc == "" {
				add(i, security.SevMedium, "py-bare-except", "Bare except", "",
					"`except:` also catches KeyboardInterrupt and SystemExit and hides programming errors. Catch the specific exceptions you expect.")
			}
			swallowed := false
			if tail != "" {
				swallowed = tail == "pass" || tail == "..." || tail == "continue"
			} else if j := nextLogical(code, starts, end); j >= 0 && pyIndent(code[j]) > pyIndent(code[i]) {
				body, bend := pyLogical(code, starts, j)
				if body == "pass" || body == "..." || body == "continue" {
					if k := nextLogical(code, starts, bend); k < 0 || pyIndent(code[k]) <= pyIndent(code[i]) {
						swallowed = true
					}
				}
			}
			if swallowed && broad {
				add(i, security.SevMedium, "py-except-pass", "Broad exception swallowed", "",
					"A broad `except` whose body is just `pass`/`continue` silences every error, including real bugs. Log it, narrow the exception, or re-raise.")
			}
			// raise-missing-from inside the handler
			if tail == "" {
				bend := pyBlockEnd(code, starts, i)
				for j := end + 1; j <= bend && j < len(code); j++ {
					if !starts[j] {
						continue
					}
					body, _ := pyLogical(code, starts, j)
					if rePyRaiseNew.MatchString(body) && !strings.Contains(body, " from ") {
						add(j, security.SevLow, "py-raise-no-from", "raise without `from` in an except block", "",
							"Raising a new exception inside `except` loses the original cause; use `raise New(...) from err` (or `from None` to hide it on purpose).")
					}
				}
			}
		}

		// return inside finally
		if raw == "finally:" {
			bend := pyBlockEnd(code, starts, i)
			for j := i + 1; j <= bend && j < len(code); j++ {
				if starts[j] && strings.HasPrefix(strings.TrimSpace(code[j]), "return") {
					add(j, security.SevMedium, "py-finally-return", "return inside finally", "",
						"A `return` in `finally` overrides any exception in flight and silently discards it. Move it out of the `finally` block.")
				}
			}
		}

		// is-literal, singleton comparison, assert tuple, wildcard import, self-assign, builtin assign
		if rePyIsLiteral.MatchString(raw) {
			add(i, security.SevMedium, "py-is-literal", "`is` compared with a literal", "",
				"`is` tests identity, not equality; against a literal it depends on interning and is a SyntaxWarning on 3.8+. Use `==`.")
		}
		if rePySingleton.MatchString(raw) {
			add(i, security.SevLow, "py-singleton-compare", "Equality comparison with None/True/False", "",
				"Compare singletons with `is`/`is not` (`x is None`); `== None` can be fooled by __eq__, and `== True` rejects truthy values.")
		}
		if g := rePyAssertTuple.FindStringSubmatch(raw); g != nil && len(splitTopLevel(g[1], g[1], ',')) >= 2 && strings.TrimSpace(splitTopLevel(g[1], g[1], ',')[1]) != "" {
			add(i, security.SevMedium, "py-assert-tuple", "assert on a tuple", "",
				"`assert (cond, \"message\")` asserts a non-empty tuple, which is always true. Write `assert cond, \"message\"`.")
		}
		if rePyWildcard.MatchString(raw) {
			add(i, security.SevLow, "py-wildcard-import", "Wildcard import", "",
				"`from x import *` hides where names come from and can silently shadow earlier ones; import what you use.")
		}
		if g := rePyBuiltinAssig.FindStringSubmatch(raw); g != nil {
			add(i, security.SevLow, "py-redefined-builtin", "Builtin name reassigned", g[1],
				"Assigning to a builtin name hides it for the rest of the scope; pick another name.")
		}
		if l, r, ok := splitSelfAssign(raw); ok && l == r {
			add(i, security.SevLow, "py-self-assign", "Variable assigned to itself", l, "`x = x` does nothing; probably a typo for another name.")
		}
		// comparison of an expression with itself
		for _, loc := range rePyDupOperand.FindAllStringSubmatchIndex(raw, -1) {
			l, op, r := raw[loc[2]:loc[3]], raw[loc[4]:loc[5]], raw[loc[6]:loc[7]]
			if l == r && !goKeywordOperand(l) && !pyKeywordOperand(l) && pyDupPrevOK(raw, loc[2]) && pyDupNextOK(raw, loc[7]) {
				add(i, security.SevMedium, "py-dup-operand", "Identical operands", "`"+l+" "+op+" "+r+"`",
					"Both sides of the operator are the same expression, so the result never changes — almost certainly a copy-paste slip.")
			}
		}

		// lambda capturing a loop variable
		if g := rePyForTarget.FindStringSubmatch(raw); g != nil && strings.HasSuffix(raw, ":") {
			targets := splitNames(g[1])
			bend := pyBlockEnd(code, starts, i)
			for j := i + 1; j <= bend && j < len(code); j++ {
				if !starts[j] {
					continue
				}
				body, _ := pyLogical(code, starts, j)
				for _, lm := range rePyLambda.FindAllStringSubmatchIndex(body, -1) {
					before := body[:lm[0]]
					if rePyCaptureSafe.MatchString(before) {
						continue
					}
					params := body[lm[2]:lm[3]]
					rest := lambdaBody(body[lm[1]:])
					for _, tname := range targets {
						if hasWord(rest, tname) && !hasWord(params, tname) {
							add(j, security.SevMedium, "py-lambda-loop-var", "Lambda captures a loop variable", tname,
								"The lambda looks `"+tname+"` up when it is called, not when it is created, so every lambda sees the loop's last value. Bind it: `lambda x, "+tname+"="+tname+": …`.")
						}
					}
				}
			}
		}
	}

	// blocking calls inside async def (excluding nested sync defs)
	inAsync := make([]bool, len(code))
	for _, f := range funcs {
		if !f.async {
			continue
		}
		for l := f.bodyStart; l <= f.end && l < len(code); l++ {
			inAsync[l] = true
		}
	}
	for _, f := range funcs {
		if f.async || !f.enclosedDef {
			continue
		}
		for l := f.start; l <= f.end && l < len(code); l++ {
			inAsync[l] = false
		}
	}
	for i, l := range code {
		if inAsync[i] {
			if g := rePyBlocking.FindString(l); g != "" {
				add(i, security.SevMedium, "py-blocking-async", "Blocking call inside async def", strings.TrimSuffix(strings.TrimSpace(g), "("),
					"A synchronous call blocks the whole event loop. Use the async equivalent (`asyncio.sleep`, `aiohttp`/`httpx.AsyncClient`, `asyncio.create_subprocess_exec`) or run it in an executor.")
			}
		}
	}

	out = append(out, pyDupDictKeys(filePath, m)...)
	out = append(out, pyFStringNoPlaceholder(filePath, m)...)
	return dedupeIssues(out)
}

// nextLogical returns the next statement start after line i, or -1.
func nextLogical(code []string, starts []bool, i int) int {
	for j := i + 1; j < len(code); j++ {
		if starts[j] {
			return j
		}
	}
	return -1
}

func splitSelfAssign(stmt string) (l, r string, ok bool) {
	i := strings.Index(stmt, "=")
	if i <= 0 || i+1 >= len(stmt) || stmt[i+1] == '=' || strings.ContainsAny(stmt[i-1:i], "=!<>+-*/%&|^:") {
		return "", "", false
	}
	l, r = strings.TrimSpace(stmt[:i]), strings.TrimSpace(stmt[i+1:])
	if reJSXTagName.FindString(l) != l || strings.Contains(r, " ") {
		if !strings.Contains(l, ".") {
			return "", "", false
		}
	}
	if strings.ContainsAny(l, " ,()[]") || strings.ContainsAny(r, " ,()[]") {
		return "", "", false
	}
	return l, r, true
}

func pyKeywordOperand(s string) bool { return s == "None" || s == "True" || s == "False" }

func splitNames(s string) []string {
	var out []string
	for _, n := range strings.Split(s, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

func hasWord(s, w string) bool { return countIdent(s, w) > 0 }

// lambdaBody cuts a lambda's body at the bracket/comma that ends it.
func lambdaBody(rest string) string {
	depth := 0
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return rest[:i]
			}
			depth--
		case ',':
			if depth == 0 {
				return rest[:i]
			}
		}
	}
	return rest
}

// pyDupPrevOK / pyDupNextOK are dupPrevOK/dupNextOK for Python's `and`/`or`.
func pyDupPrevOK(line string, start int) bool {
	i := start - 1
	if i >= 0 && (isIdentByte(line[i]) || line[i] == '.') {
		return false
	}
	for i >= 0 && (line[i] == ' ' || line[i] == '\t') {
		i--
	}
	if i < 0 {
		return true
	}
	switch c := line[i]; c {
	case '(', ',', '[', '{', ':':
		return true
	case '=':
		return i == 0 || !strings.ContainsRune("=!<>", rune(line[i-1]))
	default:
		if isIdentByte(c) { // keyword before the operand: if / elif / while / return / and / or / not
			j := i
			for j >= 0 && isIdentByte(line[j]) {
				j--
			}
			switch line[j+1 : i+1] {
			case "if", "elif", "while", "return", "and", "or", "not", "assert", "in", "yield", "else":
				return true
			}
		}
		return false
	}
}

func pyDupNextOK(line string, end int) bool {
	i := end
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i >= len(line) {
		return true
	}
	switch line[i] {
	case ')', ']', '}', ',', ':':
		return true
	}
	rest := line[i:]
	for _, w := range []string{"and", "or", "if", "else", "for"} {
		if strings.HasPrefix(rest, w) && (len(rest) == len(w) || !isIdentByte(rest[len(w)])) {
			return true
		}
	}
	return false
}

// pyDupDictKeys flags a literal key written twice in one dict display.
func pyDupDictKeys(filePath string, m maskedFile) []CSIssue {
	f := m.flat()
	var out []CSIssue
	for i := 0; i < len(f.code); i++ {
		if f.code[i] != '{' {
			continue
		}
		cl := f.matchClose(i)
		if cl < 0 {
			continue
		}
		inner, innerText := f.code[i+1:cl], f.text[i+1:cl]
		entries := splitTopLevel(inner, innerText, ',')
		entriesCode := splitTopLevel(inner, inner, ',')
		if hasWord(inner, "lambda") {
			continue // commas in lambda parameter lists would split entries wrongly
		}
		isDict, seen := true, map[string]bool{}
		type ent struct {
			key string
			off int
		}
		var keys []ent
		pos := 0
		for k, ec := range entriesCode {
			if strings.TrimSpace(ec) == "" {
				pos += len(ec) + 1
				continue
			}
			ci := topColon(ec)
			if ci < 0 || strings.Contains(ec, "**") || hasWordFor(ec) {
				isDict = false
				break
			}
			lead := len(ec) - len(strings.TrimLeft(ec, " \t\r\n"))
			keys = append(keys, ent{key: squash(entries[k][:ci]), off: i + 1 + pos + lead})
			pos += len(ec) + 1
		}
		if !isDict {
			continue
		}
		for _, e := range keys {
			if e.key != "" && seen[e.key] {
				li := f.line(e.off)
				snip := strings.TrimSpace(m.raw[li])
				if len(snip) > 100 {
					snip = snip[:100] + "…"
				}
				out = append(out, CSIssue{RuleID: "py-dup-dict-key", Rule: "Duplicate dict key", Detail: e.key,
					Message:  "The same key appears twice in one dict literal; the later value silently wins. Remove one or fix the key.",
					Severity: security.SevMedium, FilePath: filePath, Line: li + 1, Snippet: snip})
			}
			seen[e.key] = true
		}
	}
	return out
}

func hasWordFor(s string) bool { return hasWord(s, "for") }

// pyFStringNoPlaceholder flags f"..." literals with nothing to interpolate.
func pyFStringNoPlaceholder(filePath string, m maskedFile) []CSIssue {
	var out []CSIssue
	for i, line := range m.text {
		for _, loc := range rePyFString.FindAllStringSubmatchIndex(line, -1) {
			// the prefix letter must survive in the code view (else it sits inside another string)
			if loc[0] >= len(m.code[i]) || m.code[i][loc[0]] == ' ' {
				continue
			}
			content := ""
			if loc[2] >= 0 {
				content = line[loc[2]:loc[3]]
			} else {
				content = line[loc[4]:loc[5]]
			}
			if strings.ContainsAny(content, "{}") {
				continue
			}
			if loc[1] < len(line) && (line[loc[1]] == '"' || line[loc[1]] == '\'') {
				continue // a triple-quoted string starting `f""" `
			}
			if loc[0] > 0 && (line[loc[0]-1] == '"' || line[loc[0]-1] == '\'') && content == "" {
				continue
			}
			snip := strings.TrimSpace(m.raw[i])
			if len(snip) > 100 {
				snip = snip[:100] + "…"
			}
			out = append(out, CSIssue{RuleID: "py-fstring-no-placeholder", Rule: "f-string without placeholders", Severity: security.SevLow,
				Message:  "The f prefix does nothing without a `{}` placeholder; drop the `f` (or add the value that was meant to be interpolated).",
				FilePath: filePath, Line: i + 1, Snippet: snip})
		}
	}
	return out
}

// dedupeIssues drops repeats of the same rule on the same line (nested handlers
// and overlapping blocks can find one statement twice).
func dedupeIssues(in []CSIssue) []CSIssue {
	type k struct {
		id     string
		line   int
		detail string
	}
	seen := map[k]bool{}
	out := in[:0:0]
	for _, is := range in {
		key := k{is.RuleID, is.Line, is.Detail}
		if !seen[key] {
			seen[key] = true
			out = append(out, is)
		}
	}
	return out
}
