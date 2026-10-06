// stringsmells.go is the 🔤 Strings subcard of the Strings & Regex card (regex.go). It ports the
// string-related checkers of go-critic (stringConcatSimplify, stringsCompare,
// equalFold, preferFprint, dynamicFmtString, sprintfQuotedString, stringXbytes,
// wrapperFunc's strings.Index idiom) and adds the cross-platform one go-critic
// has no equivalent for: `s += …` string building inside a loop, which is
// quadratic because every iteration copies the whole string (Go, Java, Kotlin,
// Swift, C#, Rust, C++, Python). Kotlin/Swift/Python/TS/JS also get "build the
// string with a template / interpolation / f-string instead of a `+` chain".
//
// Everything runs on the comment/string-stripped lines (so a prose comment can't
// trigger it) without a type checker, so each rule is a conservative lexical
// heuristic: a finding is a "worth a look" review item, not a verdict.
package constructs

import (
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/security"
)

// csStrLang groups file extensions into the language families the string rules
// are gated on.
type csStrLang int

const (
	csStrNone csStrLang = iota
	csStrGo
	csStrJava
	csStrKotlin
	csStrSwift
	csStrPython
	csStrJS
	csStrRust
	csStrCLike // C#, C, C++, Obj-C
)

func csStringLang(fileExt string) csStrLang {
	switch fileExt {
	case ".go":
		return csStrGo
	case ".java":
		return csStrJava
	case ".kt", ".kts":
		return csStrKotlin
	case ".swift":
		return csStrSwift
	case ".py":
		return csStrPython
	case ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs":
		return csStrJS
	case ".rs":
		return csStrRust
	case ".cs", ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".mm", ".m":
		return csStrCLike
	}
	return csStrNone
}

var (
	// loop headers for brace languages; the body is brace-matched.
	reStrLoopBrace = regexp.MustCompile(`^\s*\}?\s*(?:for|while|foreach|loop)\b|\.forEach\w*\s*[({]`)
	// loop headers for Python; the body is indentation-delimited.
	reStrLoopPy = regexp.MustCompile(`^\s*(?:async\s+)?(?:for|while)\b.*:\s*$`)

	// `s += rhs` and `s = s + rhs`.
	reStrAppend   = regexp.MustCompile(`^\s*([A-Za-z_][\w.]*)\s*\+=\s*(.+)$`)
	reStrSelfPlus = regexp.MustCompile(`^\s*([A-Za-z_][\w.]*)\s*=\s*([A-Za-z_][\w.]*)\s*\+\s*(.+)$`)

	// names declared as strings anywhere in the file (stripped, so "abc" is "").
	reStrDeclTyped = regexp.MustCompile(`\b(?:String|string|str|std::string|NSMutableString|NSString)\s+(\w+)\s*(?:=|;)`)
	reStrDeclInit  = regexp.MustCompile("(\\w+)\\s*(?::=|=)\\s*(?:\"\"|''|``|String::new\\(\\)|String::from\\(|\\.to_string\\(\\))")
	reStrDeclColon = regexp.MustCompile(`(\w+)\s*:\s*(?:String|string|str)\b`)

	// "a" + x + "b" style chains (stripped literals are "" / '').
	reStrChainA = regexp.MustCompile(`(?:""|'')\s*\+\s*[A-Za-z_(][^+]*\+`)
	reStrChainB = regexp.MustCompile(`\+\s*[A-Za-z_(][^+"']*\+\s*(?:""|'')`)
	reStrChainC = regexp.MustCompile(`[A-Za-z_)\]]\s*\+\s*(?:""|'')\s*\+\s*[A-Za-z_(]`)

	// Go: go-critic ports.
	reGoJoinSmall  = regexp.MustCompile(`strings\.Join\(\s*\[\]string\{\s*[^,{}]+(?:,\s*[^,{}]+){1,2},?\s*\}\s*,`)
	reGoCompare    = regexp.MustCompile(`\bstrings\.Compare\(`)
	reGoCaseEq     = regexp.MustCompile(`\bstrings\.To(?:Lower|Upper)\([^()]*\)\s*[!=]=|[!=]=\s*strings\.To(?:Lower|Upper)\(`)
	reGoSprintfS   = regexp.MustCompile(`\bfmt\.Sprintf\(\s*"%[sv]"\s*,`)
	reGoErrorfVar  = regexp.MustCompile(`\bfmt\.Errorf\(\s*[A-Za-z_][\w.]*(?:\([^()]*\))?\s*\)`)
	reGoSprintW    = regexp.MustCompile(`\.Write(?:String)?\(\s*(?:\[\]byte\(\s*)?fmt\.Sprint(?:f|ln)?\(|\bio\.WriteString\([^,]+,\s*fmt\.Sprint(?:f|ln)?\(|\bfmt\.Print(?:ln)?\(\s*fmt\.Sprint`)
	reGoRoundTrip  = regexp.MustCompile(`\bstring\(\s*\[\]byte\(|\[\]byte\(\s*string\(`)
	reGoIndexCmp   = regexp.MustCompile(`\bstrings\.Index(?:Any|Rune)?\(.*\)\s*(?:>=\s*0|!=\s*-1|<\s*0|==\s*-1)`)
	reGoQuotedS    = regexp.MustCompile(`\\"%s\\"`)
	reGoPrintfCall = regexp.MustCompile(`\b(?:Sprintf|Printf|Fprintf|Errorf|Fatalf|Panicf|Logf|Infof|Warnf|Debugf)\s*\(`)

	// case-insensitive comparison by lowering both sides (Java/Kotlin/Swift/JS/Python).
	reStrCaseCmp = regexp.MustCompile(`\.(?:toLowerCase|toUpperCase|lowercase|uppercase|lowercased|uppercased|lower|upper)\(\)\s*(?:===?|!==?|\.equals\()|(?:===?|!==?)\s*[\w.()\[\]"']+\.(?:toLowerCase|toUpperCase|lowercase|uppercase|lowercased|uppercased|lower|upper)\(\)`)
	// length/count compared with 0 where an isEmpty exists.
	reStrLenZero = regexp.MustCompile(`\.length\(\)\s*(?:==|!=|>)\s*0\b|\.length\s*(?:==|!=|>)\s*0\b|\.count\s*(?:==|!=|>)\s*0\b`)
	// Java: new String("…").
	reJavaNewString = regexp.MustCompile(`\bnew\s+String\(\s*(?:""|\w+)\s*\)`)
)

// scanStringSmells returns every string-handling issue in one file. stripped
// and raw are the file's comment/string-stripped and original lines.
func scanStringSmells(filePath string, stripped, raw []string) []CSIssue {
	lang := csStringLang(ext(filePath))
	if lang == csStrNone {
		return nil
	}
	for i := 0; i < len(raw) && i < 5; i++ {
		if strings.Contains(raw[i], "Code generated") || strings.Contains(raw[i], "DO NOT EDIT") {
			return nil // generated code isn't hand-fixable
		}
	}
	var out []CSIssue
	add := func(i int, id, rule, msg string) {
		snip := strings.TrimSpace(raw[i])
		if len(snip) > 100 {
			snip = snip[:100] + "…"
		}
		sev := security.SevLow
		if id == "concat-in-loop" {
			sev = security.SevMedium
		}
		out = append(out, CSIssue{RuleID: id, Rule: rule, Message: msg, Severity: sev, FilePath: filePath, Line: i + 1, Snippet: snip})
	}
	hit := func(re *regexp.Regexp, i int) bool { return i < len(raw) && re.MatchString(stripped[i]) }

	// String-building in a loop.
	if lang != csStrJS {
		known := csStringNames(stripped)
		for i, header := range csLoopLines(stripped, lang == csStrPython) {
			if header < 0 || i >= len(raw) {
				continue
			}
			if name, ok := csIsStringAppend(stripped[i], known); ok && !csResetInLoop(stripped, header, i, name) {
				add(i, "concat-in-loop", "String concatenation in a loop",
					"Every iteration copies the whole string (O(n²)); collect the parts and join them once — strings.Builder (Go), StringBuilder (Java/Kotlin/C#), String.reserve + push_str (Rust), \"\".join (Python).")
			}
		}
	}

	for i := range stripped {
		if i >= len(raw) {
			break
		}
		line := stripped[i]
		if strings.TrimSpace(line) == "" {
			continue
		}
		switch lang {
		case csStrGo:
			switch {
			case hit(reGoJoinSmall, i):
				add(i, "join-small", "strings.Join on a tiny literal slice", "Use plain `a + b + c` concatenation instead of strings.Join over a 2–3 element slice literal.")
			case hit(reGoCompare, i):
				add(i, "strings-compare", "strings.Compare", "Use the `==`, `<`, `>` operators; strings.Compare is slower and less readable.")
			case hit(reGoCaseEq, i):
				add(i, "equal-fold", "Case-insensitive compare via ToLower/ToUpper", "Use strings.EqualFold(a, b): it doesn't allocate two new strings.")
			case reGoSprintfS.MatchString(raw[i]) && strings.Contains(line, "Sprintf"):
				add(i, "redundant-sprintf", "Redundant fmt.Sprintf(\"%s\", x)", "Use x directly (or x.String()) instead of formatting it through Sprintf.")
			case hit(reGoErrorfVar, i):
				add(i, "dynamic-errorf", "fmt.Errorf with a non-constant format", "Use errors.New(msg) or fmt.Errorf(\"%s\", msg); a `%` in msg is parsed as a verb.")
			case hit(reGoSprintW, i):
				add(i, "sprint-then-write", "Sprintf result passed to a writer", "Use fmt.Fprintf / fmt.Fprint(w, …) directly and skip the intermediate string.")
			case hit(reGoRoundTrip, i):
				add(i, "string-bytes-roundtrip", "Redundant string ↔ []byte round trip", "The double conversion allocates and copies for nothing; use the value as-is.")
			case hit(reGoIndexCmp, i):
				add(i, "index-as-contains", "strings.Index compared with -1/0", "Use strings.Contains / ContainsAny / ContainsRune.")
			case csGoQuotedVerb(raw[i], line):
				add(i, "manual-quote", "Manually quoted %s", "Use %q: it quotes and escapes correctly.")
			}
		case csStrJava:
			switch {
			case hit(reStrCaseCmp, i):
				add(i, "case-compare", "Case-insensitive compare via toLowerCase/toUpperCase", "Use equalsIgnoreCase; lowering both sides allocates and breaks on locales (Turkish i).")
			case hit(reStrLenZero, i):
				add(i, "length-zero", "length() compared with 0", "Use isEmpty() (or isBlank()).")
			case hit(reJavaNewString, i):
				add(i, "new-string", "new String(…)", "Redundant copy; use the string itself.")
			}
		case csStrKotlin:
			switch {
			case hit(reStrCaseCmp, i):
				add(i, "case-compare", "Case-insensitive compare via lowercase()/uppercase()", "Use a.equals(b, ignoreCase = true).")
			case hit(reStrLenZero, i):
				add(i, "length-zero", "length compared with 0", "Use isEmpty() / isNotEmpty() / isBlank().")
			}
		case csStrSwift:
			switch {
			case hit(reStrCaseCmp, i):
				add(i, "case-compare", "Case-insensitive compare via lowercased()", "Use a.caseInsensitiveCompare(b) == .orderedSame or localizedCaseInsensitiveCompare.")
			case hit(reStrLenZero, i):
				add(i, "length-zero", "count compared with 0", "Use isEmpty — O(1) for every collection and string.")
			}
		case csStrPython:
			if hit(reStrCaseCmp, i) {
				add(i, "case-compare", "Case-insensitive compare via lower()/upper()", "Use a.casefold() == b.casefold() (handles non-ASCII correctly).")
			}
		case csStrJS:
			if hit(reStrCaseCmp, i) {
				add(i, "case-compare", "Case-insensitive compare via toLowerCase()", "Use a.localeCompare(b, undefined, { sensitivity: 'accent' }) === 0 or normalise once.")
			}
		}

		// `"a" + x + "b"` chains: prefer the language's own interpolation.
		if hint := csInterpolationHint(lang); hint != "" && csIsConcatChain(line) {
			add(i, "concat-chain", "String built with a `+` chain", hint)
		}
	}
	return out
}

// csInterpolationHint is the "use the built-in interpolation" advice for the
// languages that have one; "" for languages where `+` is the idiom.
func csInterpolationHint(l csStrLang) string {
	switch l {
	case csStrKotlin:
		return `Use a string template: "a$x b${y.z}".`
	case csStrSwift:
		return `Use string interpolation: "a\(x) b".`
	case csStrPython:
		return `Use an f-string: f"a{x} b".`
	case csStrJS:
		return "Use a template literal: `a${x} b`."
	}
	return ""
}

// csIsConcatChain reports a line that glues a string literal and at least one
// non-literal operand with two or more `+`.
func csIsConcatChain(line string) bool {
	if strings.Count(line, "+") < 2 || strings.Contains(line, "++") || strings.Contains(line, "+=") {
		return false
	}
	return reStrChainA.MatchString(line) || reStrChainB.MatchString(line) || reStrChainC.MatchString(line)
}

// csStringNames collects identifiers the file declares as strings, so
// `total += part` is recognised as string building even when the right side
// has no literal.
func csStringNames(stripped []string) map[string]bool {
	names := map[string]bool{}
	for _, l := range stripped {
		for _, re := range []*regexp.Regexp{reStrDeclTyped, reStrDeclInit, reStrDeclColon} {
			for _, m := range re.FindAllStringSubmatch(l, -1) {
				names[m[1]] = true
			}
		}
	}
	return names
}

// csIsStringAppend reports whether a stripped line appends to a string:
// `s += …` / `s = s + …` where s is a known string or the right side starts with
// (or adds) a string literal.
func csIsStringAppend(line string, known map[string]bool) (string, bool) {
	if m := reStrAppend.FindStringSubmatch(line); m != nil {
		return m[1], known[m[1]] || csStartsWithLiteral(m[2]) || csAddsLiteral(m[2])
	}
	if m := reStrSelfPlus.FindStringSubmatch(line); m != nil && m[1] == m[2] {
		return m[1], known[m[1]] || csStartsWithLiteral(m[3]) || csAddsLiteral(m[3])
	}
	return "", false
}

func csStartsWithLiteral(s string) bool {
	s = strings.TrimLeft(s, " &")
	return strings.HasPrefix(s, `"`) || strings.HasPrefix(s, "'") || strings.HasPrefix(s, "`")
}

func csAddsLiteral(s string) bool {
	return strings.Contains(s, `+ "`) || strings.Contains(s, `" +`) || strings.Contains(s, "+ '") || strings.Contains(s, "' +")
}

// csLoopLines gives, for every line, the index of the innermost loop header
// whose body contains it (-1 = not in a loop). Brace languages brace-match the
// body; Python uses indentation.
func csLoopLines(stripped []string, python bool) []int {
	in := make([]int, len(stripped))
	for i := range in {
		in[i] = -1
	}
	if python {
		indent := func(s string) int { return len(s) - len(strings.TrimLeft(s, " \t")) }
		for i, l := range stripped {
			if !reStrLoopPy.MatchString(l) {
				continue
			}
			base := indent(l)
			for j := i + 1; j < len(stripped); j++ {
				if strings.TrimSpace(stripped[j]) == "" {
					continue
				}
				if indent(stripped[j]) <= base {
					break
				}
				in[j] = i
			}
		}
		return in
	}
	for i, l := range stripped {
		if !reStrLoopBrace.MatchString(l) || !strings.Contains(l, "{") {
			continue
		}
		end := matchBraceEnd(stripped, i)
		if end < 0 {
			continue
		}
		// Only lines strictly after the header count (a one-line loop
		// `for … { s += "x" }` is rare and its header line is also the body).
		// Later (inner) headers overwrite earlier ones, so the innermost wins.
		for j := i + 1; j < end; j++ {
			in[j] = i
		}
	}
	return in
}

// csResetInLoop reports whether name is declared or re-assigned between the
// loop header and line i — then each iteration starts from a fresh string and
// the appends aren't quadratic.
func csResetInLoop(stripped []string, header, i int, name string) bool {
	q := regexp.QuoteMeta(name)
	// only a fresh declaration or an empty-string reset starts a new string; a
	// plain `name = seg.tag` inside an if still leaves the append quadratic.
	re := regexp.MustCompile(`(?:^|[^\w.])` + q + `\s*(?:\:=|=\s*(?:""|''|` + "``" + `)\s*;?\s*$)|\b(?:var|let|val|String|string|auto|str)\s+` + q + `\b`)
	for j := header; j < i; j++ {
		if re.MatchString(stripped[j]) {
			return true
		}
	}
	return false
}

// csGoQuotedVerb reports a printf-family call that wraps %s in quotes by hand.
func csGoQuotedVerb(rawLine, code string) bool {
	return reGoQuotedS.MatchString(rawLine) && reGoPrintfCall.MatchString(code)
}
