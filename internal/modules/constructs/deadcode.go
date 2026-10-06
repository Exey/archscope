// deadcode.go is the 🪦 Dead Code card: code that can be deleted without
// changing behaviour — imports nothing uses, statements after a return / throw /
// break / continue, blocks of commented-out code and variables that are declared
// but never read. A lexical port of the dead-code rules of ~/react-code-audit,
// over the length-preserving masked source (srcmask.go).
//
// It runs on JS/TS (the "ts" language id, scanDeadCodeJS) and Python
// (deadcode_py.go); the rule bodies are keyed on a per-language scanner so other
// languages can be added next to them.
// It feeds 🧹 Code Quality in Programming Culture.
package constructs

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/security"
)

func init() { modules.Default.Register(DeadCode{}) }

// DeadCode is the dead-code detector.
type DeadCode struct{}

func (DeadCode) ID() string    { return "deadcode" }
func (DeadCode) Title() string { return "Dead Code" }
func (DeadCode) AppliesTo(languageID string) bool {
	return languageID == "ts" || languageID == "python"
}

// DeadCodeReport is the module output.
type DeadCodeReport struct {
	Issues            []CSIssue
	High, Medium, Low int
}

func (r DeadCodeReport) HasData() bool { return len(r.Issues) > 0 }
func (r DeadCodeReport) Total() int    { return len(r.Issues) }

// minCommentedCodeLines is react-code-audit's threshold for a commented-out block.
const minCommentedCodeLines = 3

var (
	reImportStmt  = regexp.MustCompile(`\bimport\b([^;'"(]*?)\bfrom\s*['"]`)
	reJumpWord    = regexp.MustCompile(`\b(return|throw|break|continue)\b`)
	reVarDecl     = regexp.MustCompile(`\b(const|let|var)\s+([A-Za-z_$][\w$]*|\{[^{}]*\}|\[[^\[\]]*\])`)
	reAsBinding   = regexp.MustCompile(`^(?:type\s+)?([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$`)
	reCommentKeep = regexp.MustCompile(`(?i)^(?:todo|fixme|note|hack|xxx|eslint|prettier|istanbul|@ts-|@flow|#region|#endregion|webpack|jshint|c8 )`)
	commentedCode = []*regexp.Regexp{
		regexp.MustCompile(`^\s*(?:const|let|var|function|class|import|export|return|if|else|for|while|switch)\b[\s({]`),
		regexp.MustCompile(`^\s*<[A-Z][A-Za-z]*`),
		regexp.MustCompile(`^\s*[A-Za-z_$][\w$]*\s*\(.*\)\s*[;{]?$`),
		regexp.MustCompile(`^\s*[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$.]*\(`),
		regexp.MustCompile(`^\s*\{.*\}\s*[;,]?$`),
		regexp.MustCompile(`=>`),
		regexp.MustCompile(`[;{}]\s*$`),
	}
)

// Analyze scans every non-test, non-declaration JS/TS file.
func (DeadCode) Analyze(files []*parser.ParsedFile) any {
	cache := newSourceCache()
	var rep DeadCodeReport
	for _, f := range files {
		fe := ext(f.FilePath)
		isPy := fe == ".py" || fe == ".pyi"
		if !(isJSFamily(fe) || isPy) || security.IsTestOrBenchPath(f.FilePath) || strings.HasSuffix(strings.ToLower(f.FilePath), ".d.ts") {
			continue
		}
		raw := cache.rawLines(f.FilePath)
		if raw == nil {
			continue
		}
		var found []CSIssue
		if isPy {
			found = scanDeadCodePy(f.FilePath, maskSource(raw, fe))
		} else {
			found = scanDeadCodeJS(f.FilePath, maskSource(raw, fe))
		}
		rep.Issues = append(rep.Issues, suppressIssues(security.NewSuppressor(raw), found)...)
	}
	rep.Issues = append(rep.Issues, scanUnusedSymbols(files, cache)...)
	sortIssuesBySeverity(rep.Issues)
	rep.High, rep.Medium, rep.Low = issueSevCounts(rep.Issues)
	return rep
}

// scanDeadCodeJS runs the four dead-code rules on one masked JS/TS file.
func scanDeadCodeJS(filePath string, m maskedFile) []CSIssue {
	f := m.flat()
	var out []CSIssue
	add := func(li int, sev security.Severity, id, rule, msg string) {
		snip := strings.TrimSpace(m.raw[li])
		if len(snip) > 100 {
			snip = snip[:100] + "…"
		}
		detail, msg := splitDetail(msg)
		out = append(out, CSIssue{RuleID: id, Rule: rule, Message: msg, Detail: detail, Severity: sev, FilePath: filePath, Line: li + 1, Snippet: snip})
	}

	// ---- unused imports ----
	usage := []byte(f.text)
	type imp struct {
		local, from string
		off         int
	}
	var imports []imp
	for _, mm := range reImportStmt.FindAllStringSubmatchIndex(f.code, -1) {
		qEnd := strings.IndexAny(f.code[mm[1]:], `'"`)
		stmtEnd := mm[1]
		if qEnd >= 0 {
			stmtEnd = mm[1] + qEnd + 1
		}
		clause := strings.TrimSpace(f.code[mm[2]:mm[3]])
		clause = strings.TrimSpace(strings.TrimPrefix(clause, "type "))
		src := strings.TrimSpace(f.text[mm[1] : stmtEnd-1])
		for _, local := range importLocals(clause) {
			imports = append(imports, imp{local: local, from: src, off: mm[0]})
		}
		for i := mm[0]; i < stmtEnd && i < len(usage); i++ { // blank the statement so it can't "use" itself
			if usage[i] != '\n' {
				usage[i] = ' '
			}
		}
	}
	for _, im := range imports {
		if im.local == "React" || strings.HasPrefix(im.local, "_") {
			continue
		}
		if !identUsed(string(usage), im.local) {
			add(f.line(im.off), security.SevMedium, "dead-unused-import", "Unused import",
				im.local+" from "+im.from+"\x00Imported but never used; remove it (the import also keeps the module in the bundle).")
		}
	}

	// ---- unreachable code ----
	for _, jm := range reJumpWord.FindAllStringIndex(f.code, -1) {
		off, end := jm[0], jm[1]
		if end < len(f.code) && (f.code[end] == '<' || f.code[end] == ':' || f.code[end] == '=' || f.code[end] == ',' || f.code[end] == '.') {
			continue // JSX text, object key or property access, not a statement
		}
		if p := prevSigByte(f.code, off); p != 0 && !strings.ContainsRune(";{}:", rune(p)) {
			continue // `if (x) return;`, `else return`, `a ? b : return` — not at statement start
		}
		stmt := stmtEnd(f.code, end)
		nxt := f.skipSpace(stmt)
		if nxt >= len(f.code) || f.code[nxt] == '}' || f.code[nxt] == ';' {
			continue
		}
		if w := wordAtStart(f.code, nxt); w == "case" || w == "default" || w == "function" || w == "class" || w == "interface" || w == "type" || w == "enum" || w == "export" || w == "declare" || w == "async" || w == "namespace" {
			continue // labels and hoisted declarations stay reachable
		}
		add(f.line(nxt), security.SevMedium, "dead-unreachable", "Unreachable code",
			"after "+f.code[off:end]+"\x00This statement follows a return/throw/break/continue in the same block, so it can never run. Delete it, or move it before the jump.")
	}

	// ---- commented-out code ----
	out = append(out, commentedOutCode(filePath, m)...)

	// ---- unused variables ----
	blocks := blockRanges(f.code)
	for _, dm := range reVarDecl.FindAllStringSubmatchIndex(f.code, -1) {
		pre := strings.TrimRight(f.code[max0(dm[0]-12):dm[0]], " \t")
		if strings.HasSuffix(pre, "export") || strings.HasSuffix(pre, "declare") || strings.HasSuffix(pre, "for") || strings.HasSuffix(pre, "(") || strings.HasSuffix(pre, "as") {
			continue
		}
		names := declNames(f.code[dm[4]:dm[5]])
		if len(names) == 0 {
			continue
		}
		lo, hi := scopeAround(blocks, dm[0], len(f.code))
		scope := f.text[lo:hi]
		for _, nm := range names {
			if strings.HasPrefix(nm, "_") || nm == "React" {
				continue
			}
			if countIdent(scope, nm) <= 1 {
				add(f.line(dm[0]), security.SevMedium, "dead-unused-var", "Unused variable",
					nm+"\x00Declared but never read. Remove it (and any side-effect-free initialiser), or prefix with `_` if it is intentionally ignored.")
			}
		}
	}
	return out
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// importLocals lists the local bindings an import clause introduces.
func importLocals(clause string) []string {
	var names []string
	rest := clause
	if i := strings.IndexByte(rest, '{'); i >= 0 {
		j := strings.IndexByte(rest, '}')
		if j < i {
			j = len(rest)
		}
		for _, e := range strings.Split(rest[i+1:j], ",") {
			if g := reAsBinding.FindStringSubmatch(strings.TrimSpace(e)); g != nil {
				if g[2] != "" {
					names = append(names, g[2])
				} else {
					names = append(names, g[1])
				}
			}
		}
		rest = rest[:i]
	}
	rest = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), ","))
	for _, part := range strings.Split(rest, ",") {
		part = strings.TrimSpace(part)
		switch {
		case part == "":
		case strings.HasPrefix(part, "*"):
			if g := strings.Fields(part); len(g) == 3 && g[1] == "as" {
				names = append(names, g[2])
			}
		default:
			if id := reJSXTagName.FindString(part); id == part {
				names = append(names, id)
			}
		}
	}
	return names
}

// identUsed reports whether name occurs as a free identifier in text.
func identUsed(text, name string) bool { return countIdent(text, name) > 0 }

// countIdent counts occurrences of name as a standalone identifier that isn't a
// property access (`x.name`).
func countIdent(text, name string) int {
	n := 0
	for i := 0; ; {
		j := strings.Index(text[i:], name)
		if j < 0 {
			return n
		}
		j += i
		i = j + len(name)
		if j > 0 && (isIdentByte(text[j-1]) || text[j-1] == '$') {
			continue
		}
		if i < len(text) && (isIdentByte(text[i]) || text[i] == '$') {
			continue
		}
		if k := j - 1; k >= 0 {
			for k >= 0 && (text[k] == ' ' || text[k] == '\t') {
				k--
			}
			if k >= 0 && text[k] == '.' && !(k > 0 && text[k-1] == '.') { // member access, not a spread
				continue
			}
		}
		n++
	}
}

// declNames lists the identifiers a declaration binds (simple or destructured).
func declNames(pattern string) []string {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil
	}
	if pattern[0] != '{' && pattern[0] != '[' {
		return []string{pattern}
	}
	inner := pattern[1 : len(pattern)-1]
	var names []string
	for _, e := range splitTopLevel(inner, inner, ',') {
		e = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(e), "..."))
		if e == "" || strings.ContainsAny(e, "{[") {
			continue // hole or nested pattern
		}
		if pattern[0] == '{' {
			if i := strings.IndexByte(e, ':'); i >= 0 {
				e = strings.TrimSpace(e[i+1:])
			}
		}
		if i := strings.IndexByte(e, '='); i >= 0 {
			e = strings.TrimSpace(e[:i])
		}
		if id := reJSXTagName.FindString(e); id != "" && id == e {
			names = append(names, id)
		}
	}
	return names
}

// blockRange is one matched {…} pair.
type blockRange struct{ open, close int }

func blockRanges(code string) []blockRange {
	var out []blockRange
	var stack []int
	for i := 0; i < len(code); i++ {
		switch code[i] {
		case '{':
			stack = append(stack, i)
		case '}':
			if n := len(stack); n > 0 {
				out = append(out, blockRange{stack[n-1], i})
				stack = stack[:n-1]
			}
		}
	}
	return out
}

// scopeAround returns the text range of the smallest block containing off
// (the whole file when it is at module level).
func scopeAround(blocks []blockRange, off, n int) (int, int) {
	lo, hi, best := 0, n, n+1
	for _, b := range blocks {
		if b.open < off && off < b.close && b.close-b.open < best {
			lo, hi, best = b.open, b.close, b.close-b.open
		}
	}
	return lo, hi
}

func prevSigByte(code string, off int) byte {
	for i := off - 1; i >= 0; i-- {
		if c := code[i]; c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			return c
		}
	}
	return 0
}

func wordAtStart(code string, off int) string {
	j := off
	for j < len(code) && (isIdentByte(code[j]) || code[j] == '$') {
		j++
	}
	return code[off:j]
}

// commentedOutCode finds runs of >= minCommentedCodeLines `//` lines (or one
// block comment) whose content reads as code.
func commentedOutCode(filePath string, m maskedFile) []CSIssue {
	var out []CSIssue
	run, start := 0, 0
	flush := func() {
		if run >= minCommentedCodeLines {
			snip := strings.TrimSpace(m.raw[start])
			if len(snip) > 100 {
				snip = snip[:100] + "…"
			}
			out = append(out, CSIssue{RuleID: "dead-commented-code", Rule: "Commented-out code",
				Message:  "Comment lines that look like code. Delete them — version control remembers — or turn them into a real explanation.",
				Detail:   fmt.Sprintf("%d lines", run),
				Severity: security.SevLow, FilePath: filePath, Line: start + 1, Snippet: snip})
		}
		run = 0
	}
	inBlock := false
	for i, line := range m.raw {
		t := strings.TrimSpace(line)
		var content string
		isComment := false
		switch {
		case inBlock:
			isComment = true
			if strings.Contains(t, "*/") {
				inBlock = false
				t = strings.TrimSpace(strings.Split(t, "*/")[0])
			}
			content = strings.TrimSpace(strings.TrimPrefix(t, "*"))
		case strings.HasPrefix(t, "//"):
			isComment = true
			content = strings.TrimSpace(strings.TrimLeft(t, "/"))
		case strings.HasPrefix(t, "/*") && !strings.HasPrefix(t, "/**"):
			isComment = true
			inner := strings.TrimPrefix(t, "/*")
			if strings.Contains(inner, "*/") {
				inner = strings.Split(inner, "*/")[0]
			} else {
				inBlock = true
			}
			content = strings.TrimSpace(inner)
		case strings.HasPrefix(t, "/**"):
			if !strings.Contains(t, "*/") {
				inBlock = true
			}
			flush()
			continue
		}
		if isComment && len(content) >= 3 && !reCommentKeep.MatchString(content) && looksLikeCode(content) {
			if run == 0 {
				start = i
			}
			run++
			continue
		}
		flush()
	}
	flush()
	return out
}

func looksLikeCode(s string) bool {
	for _, re := range commentedCode {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func (DeadCode) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(DeadCodeReport)
	if !ok || !r.HasData() {
		return nil
	}
	return []modules.SummaryCard{{Num: strconv.Itoa(r.Total()), Label: "dead-code issues"}}
}

func (DeadCode) RenderMarkdown(res any) string {
	r, ok := res.(DeadCodeReport)
	if !ok || !r.HasData() {
		return ""
	}
	var b strings.Builder
	issueCardMarkdown(&b, "dead code", r.Issues)
	return b.String()
}

func (DeadCode) RenderHTML(res any) string {
	r, ok := res.(DeadCodeReport)
	if !ok {
		return ""
	}
	var b strings.Builder
	writeIssueCard(&b, "🪦", "dead-code", r.Issues)
	return b.String()
}
