// regex.go is the 🔤🔎 Strings & Regex card (Strings come from stringsmells.go): regular-expression misuse across languages
// (compiling in a loop, patterns that can never compile, catastrophic-
// backtracking shapes, simplifiable or suspicious patterns — go-critic's
// regexpMust / regexpSimplify / badRegexp ported and extended to Java, Kotlin,
// Swift, Python, TS/JS, Rust, C# and C++), plus go-critic's Go performance
// idioms that cost allocations or quadratic copying (appendCombine,
// rangeAppendAll, sliceClear, indexAlloc, preferWriteByte, preferStringWriter).
// It feeds ⚡ Performance in Programming Culture.
//
// Lexical like every constructs module: the structure comes from the comment/
// string-stripped lines, the pattern text from the original line.
package constructs

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/security"
)

func init() { modules.Default.Register(Regex{}) }

// Regex is the regular-expression and Go-performance-idiom detector.
type Regex struct{}

func (Regex) ID() string    { return "regex" }
func (Regex) Title() string { return "Strings & Regex" }
func (Regex) AppliesTo(languageID string) bool {
	switch languageID {
	case "go", "java", "kotlin", "swift", "python", "ts", "js", "typescript", "javascript", "rust", "csharp", "c", "cpp", "objc":
		return true
	}
	return false
}

// RegexReport is the module output.
type RegexReport struct {
	Issues            []CSIssue
	High, Medium, Low int
}

func (r RegexReport) HasData() bool { return len(r.Issues) > 0 }
func (r RegexReport) Total() int    { return len(r.Issues) }

const (
	stringsGroup = "Strings"
	regexGroup   = "Regex"
	perfGroup    = "Go performance idioms"
)

var (
	// the call head that builds a regex, per language, on stripped lines.
	reRegexHead = map[csStrLang]*regexp.Regexp{
		csStrGo:     regexp.MustCompile(`\bregexp\.(?:Must)?Compile(?:POSIX)?\s*\(`),
		csStrJava:   regexp.MustCompile(`\bPattern\.compile\s*\(`),
		csStrKotlin: regexp.MustCompile(`\bRegex\s*\(|\.toRegex\s*\(|\bPattern\.compile\s*\(`),
		csStrSwift:  regexp.MustCompile(`\bNSRegularExpression\s*\(|\bRegex\s*\(`),
		csStrPython: regexp.MustCompile(`\bre\.compile\s*\(`),
		csStrJS:     regexp.MustCompile(`\bnew\s+RegExp\s*\(`),
		csStrRust:   regexp.MustCompile(`\bRegex(?:Builder|Set)?::new\s*\(`),
		csStrCLike:  regexp.MustCompile(`\bnew\s+Regex\s*\(|\bstd::(?:basic_)?regex\b\s*\w*\s*[({]`),
	}
	// Java's String helpers recompile the pattern on every call.
	reJavaStringRegex = regexp.MustCompile(`\.(?:matches|replaceAll|replaceFirst)\s*\(\s*"`)

	// a regex-API call and its string-literal pattern, on the raw line.
	reRegexLiteral  = regexp.MustCompile("(?:regexp\\.(?:Must)?Compile(?:POSIX)?|Pattern\\.compile|\\bre\\.(?:compile|match|search|fullmatch|sub|findall|finditer|split)|new\\s+RegExp|Regex(?:Builder|Set)?::new|new\\s+Regex|NSRegularExpression|\\bRegex|std::regex(?:\\s+\\w+)?)\\s*\\(\\s*(?:\\w+\\s*:\\s*)?(r#?|R)?(\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`|'(?:[^'\\\\]|\\\\.)*')\\s*[,)]")
	reKotlinToRegex = regexp.MustCompile(`^[^"]*("(?:[^"\\]|\\.)*")\.toRegex\(\)`)

	reGoMustCompile = regexp.MustCompile(`\bregexp\.MustCompile(?:POSIX)?\s*\(`)
	reGoCompile     = regexp.MustCompile(`\bregexp\.Compile(?:POSIX)?\s*\(`)

	reNestedQuant = regexp.MustCompile(`\((?:[^()]|\([^()]*\))*[+*](?:[^()]|\([^()]*\))*\)\s*(?:[+*]|\{\d+,\d*\})`)
	reClassPipe   = regexp.MustCompile(`\[[^\]\\]*\w\|\w[^\]\\]*\]`)
	reRangeAz     = regexp.MustCompile(`\[[^\]]*A-z[^\]]*\]`)

	reAppendSelf  = regexp.MustCompile(`^\s*(` + goOperand + `)\s*=\s*append\(\s*(` + goOperand + `)\s*,`)
	reRangeLoop   = regexp.MustCompile(`^\s*for\s+(?:[\w\s,]*:?=\s*)?range\s+(` + goOperand + `)\s*\{`)
	reAppendAll   = regexp.MustCompile(`=\s*append\(\s*(` + goOperand + `)\s*,\s*(` + goOperand + `)\.\.\.\s*\)`)
	reClearLoop   = regexp.MustCompile(`^\s*for\s+(\w+)\s*:=\s*0\s*;\s*(\w+)\s*<\s*len\(\s*(` + goOperand + `)\s*\)\s*;\s*(\w+)\+\+\s*\{`)
	reClearBody   = regexp.MustCompile(`^\s*(` + goOperand + `)\[(\w+)\]\s*=\s*(?:0|0\.0|""|nil|false)\s*$`)
	reIndexString = regexp.MustCompile(`\bstrings\.Index\(\s*string\(`)
	reWriteRune   = regexp.MustCompile(`\.WriteRune\(\s*'(?:[\x20-\x26\x28-\x5b\x5d-\x7e]|\\[nrt\\'"0])'\s*\)`)
	reWriteBytes  = regexp.MustCompile(`\.Write\(\s*\[\]byte\(`)
)

// regexLiteralPattern extracts the pattern a regex-API call on this raw line is
// built from, when it is a plain string literal.
func regexLiteralPattern(raw string) (string, bool) {
	var lit, prefix string
	if g := reRegexLiteral.FindStringSubmatch(raw); g != nil {
		prefix, lit = g[1], g[2]
	} else if g := reKotlinToRegex.FindStringSubmatch(raw); g != nil {
		lit = g[1]
	} else {
		return "", false
	}
	body := lit[1 : len(lit)-1]
	if prefix != "" || lit[0] == '`' || lit[0] == '\'' {
		return body, true // raw string
	}
	if u, err := strconv.Unquote(lit); err == nil {
		return u, true
	}
	return body, true
}

// simplifications are the go-critic regexpSimplify rewrites worth reporting.
var simplifications = []struct {
	re   *regexp.Regexp
	hint string
}{
	{regexp.MustCompile(`\[\^\\s\]`), "`[^\\s]` is `\\S`"},
	{regexp.MustCompile(`\[\^\\d\]`), "`[^\\d]` is `\\D`"},
	{regexp.MustCompile(`\[\^\\w\]`), "`[^\\w]` is `\\W`"},
	{regexp.MustCompile(`\{0,\}`), "`{0,}` is `*`"},
	{regexp.MustCompile(`\{1,\}`), "`{1,}` is `+`"},
	{regexp.MustCompile(`\{0,1\}`), "`{0,1}` is `?`"},
	{regexp.MustCompile(`(?:^|[^\\\[])\[[A-Za-z0-9]\](?:[^\]]|$)`), "a one-character class `[x]` is just `x`"},
}

// Analyze scans every non-test file of a regex-capable language.
func (Regex) Analyze(files []*parser.ParsedFile) any {
	cache := newSourceCache()
	var rep RegexReport
	for _, f := range files {
		if security.IsTestOrBenchPath(f.FilePath) || isConstructDetectorFile(f.FilePath) {
			continue
		}
		lang := csStringLang(ext(f.FilePath))
		if lang == csStrNone {
			continue
		}
		stripped, raw := cache.lines(f.FilePath), cache.rawLines(f.FilePath)
		if stripped == nil || raw == nil {
			continue
		}
		rep.Issues = append(rep.Issues, scanRegex(f.FilePath, lang, stripped, raw)...)
	}
	sortIssuesBySeverity(rep.Issues)
	rep.High, rep.Medium, rep.Low = issueSevCounts(rep.Issues)
	return rep
}

func scanRegex(filePath string, lang csStrLang, stripped, raw []string) []CSIssue {
	var out []CSIssue
	add := func(i int, sev security.Severity, group, id, rule, msg string) {
		snip := strings.TrimSpace(raw[i])
		if len(snip) > 100 {
			snip = snip[:100] + "…"
		}
		out = append(out, CSIssue{RuleID: id, Rule: rule, Message: msg, Group: group, Severity: sev, FilePath: filePath, Line: i + 1, Snippet: snip})
	}
	for _, is := range scanStringSmells(filePath, stripped, raw) {
		is.Group = stringsGroup
		out = append(out, is)
	}

	head := reRegexHead[lang]
	loop := csLoopLines(stripped, lang == csStrPython)
	var funcs []csFuncRange
	if lang == csStrGo || lang == csStrJava || lang == csStrRust {
		funcs = csFuncRanges(stripped)
	}
	inFunc := func(i int) (csFuncRange, bool) {
		for _, fr := range funcs {
			if fr.start < i && i <= fr.end {
				return fr, true
			}
		}
		return csFuncRange{}, false
	}

	for i, line := range stripped {
		if i >= len(raw) || strings.TrimSpace(line) == "" {
			continue
		}
		compiles := head != nil && head.MatchString(line)
		javaHelper := lang == csStrJava && reJavaStringRegex.MatchString(line)

		if (compiles || javaHelper) && loop[i] >= 0 {
			add(i, security.SevMedium, regexGroup, "regex-in-loop", "Regex compiled inside a loop",
				"Building a regex is far costlier than running it; compile it once outside the loop (package-level var / static final / lazy) and reuse it.")
		} else if compiles && !javaHelper {
			if fr, ok := inFunc(i); ok {
				if _, lit := regexLiteralPattern(raw[i]); lit && fr.name != "init" && fr.name != "main" {
					add(i, security.SevLow, regexGroup, "regex-in-func", "Constant regex compiled on every call",
						"The pattern is a constant, so compile it once at package/class level instead of on each call of "+fr.name+".")
				}
			}
		}

		if pat, ok := regexLiteralPattern(raw[i]); ok && (compiles || reRegexAPI.MatchString(line)) {
			if lang == csStrGo {
				if _, err := regexp.Compile(pat); err != nil {
					sev, what := security.SevMedium, "regexp.Compile returns this error every call"
					if reGoMustCompile.MatchString(line) {
						sev, what = security.SevHigh, "regexp.MustCompile panics when the package initialises"
					}
					add(i, sev, regexGroup, "regex-invalid", "Pattern does not compile (RE2)",
						what+": "+firstLine(err.Error())+". Go's RE2 has no lookaround or backreferences.")
				} else if reGoCompile.MatchString(line) {
					add(i, security.SevLow, regexGroup, "regex-must", "regexp.Compile on a constant pattern",
						"A constant pattern that compiles can't fail at run time; use regexp.MustCompile and skip the unreachable error handling.")
				}
			} else if reNestedQuant.MatchString(pat) {
				add(i, security.SevMedium, regexGroup, "regex-redos", "Nested quantifier (catastrophic backtracking)",
					"A repeated group that itself repeats — like `(a+)+` or `(\\w+\\s?)*$` — takes exponential time on a near-miss input. Make the inner part unambiguous or use an engine without backtracking.")
			}
			for _, s := range simplifications {
				if s.re.MatchString(pat) {
					add(i, security.SevLow, regexGroup, "regex-simplify", "Pattern can be simplified", "Rewrite for readability: "+s.hint+".")
					break
				}
			}
			switch {
			case reRangeAz.MatchString(pat):
				add(i, security.SevMedium, regexGroup, "regex-bad", "Suspicious regex",
					"`A-z` also matches `[ \\ ] ^ _` and the backtick; use `A-Za-z`.")
			case reClassPipe.MatchString(pat):
				add(i, security.SevMedium, regexGroup, "regex-bad", "Suspicious regex",
					"`|` inside a character class is a literal pipe, not alternation — `[a|b]` matches a, | or b.")
			}
		}
	}

	if lang == csStrGo {
		out = append(out, scanGoPerfIdioms(filePath, stripped, raw)...)
	}
	return out
}

// reRegexAPI matches the one-shot regex entry points that take a pattern but
// aren't a "compile" head (re.match(r"…", s), Java's String helpers…).
var reRegexAPI = regexp.MustCompile(`\bre\.(?:match|search|fullmatch|sub|findall|finditer|split)\s*\(|\.(?:matches|replaceAll|replaceFirst)\s*\(`)

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimPrefix(s, "error parsing regexp: ")
}

// scanGoPerfIdioms ports go-critic's allocation / copying idioms.
func scanGoPerfIdioms(filePath string, stripped, raw []string) []CSIssue {
	var out []CSIssue
	add := func(i int, sev security.Severity, id, rule, msg string) {
		snip := strings.TrimSpace(raw[i])
		if len(snip) > 100 {
			snip = snip[:100] + "…"
		}
		out = append(out, CSIssue{RuleID: id, Rule: rule, Message: msg, Group: perfGroup, Severity: sev, FilePath: filePath, Line: i + 1, Snippet: snip})
	}
	for i, line := range stripped {
		if i >= len(raw) || strings.TrimSpace(line) == "" {
			continue
		}
		// appendCombine: two consecutive appends to the same slice (reported once,
		// at the second append of a chain).
		if name, ok := appendTarget(line); ok {
			if j := nextSig(stripped, i); j >= 0 {
				if n, ok2 := appendTarget(stripped[j]); ok2 && n == name {
					if p := prevSig(stripped, i); p < 0 || func() bool { pn, okp := appendTarget(stripped[p]); return !okp || pn != name }() {
						add(j, security.SevLow, "perf-append-combine", "Consecutive appends to one slice",
							"Combine `x = append(x, a); x = append(x, b)` into `x = append(x, a, b)` — one growth check instead of several.")
					}
				}
			}
		}
		// rangeAppendAll: appending the whole ranged slice on every iteration.
		if g := reRangeLoop.FindStringSubmatch(line); g != nil {
			if end := matchBraceEnd(stripped, i); end > i {
				for j := i + 1; j < end; j++ {
					if a := reAppendAll.FindStringSubmatch(stripped[j]); a != nil && a[2] == g[1] {
						add(j, security.SevMedium, "perf-range-append-all", "Appends the whole slice on every iteration",
							"Inside `range "+g[1]+"` the loop appends all of `"+g[1]+"...` each time (quadratic growth, duplicated data); append the element `v` or hoist the append out of the loop.")
					}
				}
			}
		}
		// sliceClear
		if g := reClearLoop.FindStringSubmatch(line); g != nil && g[1] == g[2] && g[1] == g[4] {
			if j := nextSig(stripped, i); j >= 0 {
				if b := reClearBody.FindStringSubmatch(stripped[j]); b != nil && b[1] == g[3] && b[2] == g[1] {
					add(i, security.SevLow, "perf-slice-clear", "Hand-written slice clear loop",
						"Write it as `for i := range xs { xs[i] = zero }` (the compiler turns that into a memclr) or call clear(xs) on Go 1.21+.")
				}
			}
		}
		if reIndexString.MatchString(line) {
			add(i, security.SevLow, "perf-index-alloc", "strings.Index(string(b), …)",
				"Converting []byte to string just to search it allocates; use bytes.Index(b, []byte(sep)).")
		}
		if reWriteRune.MatchString(raw[i]) && strings.Contains(line, "WriteRune") {
			add(i, security.SevLow, "perf-write-byte", "WriteRune with a single-byte rune",
				"An ASCII rune literal fits in one byte; WriteByte skips the UTF-8 encoding step.")
		}
		if reWriteBytes.MatchString(line) {
			add(i, security.SevLow, "perf-string-writer", "Write([]byte(s)) on a writer",
				"If the writer has WriteString (strings.Builder, bytes.Buffer, bufio.Writer, os.File), call w.WriteString(s) and avoid the []byte copy.")
		}
	}
	return out
}

// appendTarget reports the slice of a plain `x = append(x, a, b)` statement
// (variadic `y...` appends can't be merged, so they don't count).
func appendTarget(line string) (string, bool) {
	g := reAppendSelf.FindStringSubmatch(line)
	if g == nil || g[1] != g[2] || strings.Contains(line, "...") {
		return "", false
	}
	return g[1], true
}

// prevSig returns the previous line before i with non-blank code, or -1.
func prevSig(code []string, i int) int {
	for j := i - 1; j >= 0; j-- {
		if strings.TrimSpace(code[j]) != "" {
			return j
		}
	}
	return -1
}

func (Regex) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(RegexReport)
	if !ok || !r.HasData() {
		return nil
	}
	return []modules.SummaryCard{{Num: strconv.Itoa(r.Total()), Label: "string & regex issues"}}
}

func (Regex) RenderMarkdown(res any) string {
	r, ok := res.(RegexReport)
	if !ok || !r.HasData() {
		return ""
	}
	var b strings.Builder
	issueCardMarkdown(&b, "string & regex", r.Issues)
	return b.String()
}

func (Regex) RenderHTML(res any) string {
	r, ok := res.(RegexReport)
	if !ok {
		return ""
	}
	var b strings.Builder
	writeIssueCard(&b, "🔤🔎", "string & regex", r.Issues)
	return b.String()
}
