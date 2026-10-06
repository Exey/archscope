// deadcode_py.go is the Python half of the 🪦 Dead Code card — pyflakes' unused
// imports and variables, indentation-based unreachable code and commented-out
// code — read from the masked source (srcmask.go) and the indentation parser
// (pyparse.go). No Python libraries involved.
package constructs

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/security"
)

var (
	rePyImport      = regexp.MustCompile(`^import\s+(.+)$`)
	rePyFromImport  = regexp.MustCompile(`^from\s+([.\w]+)\s+import\s+(.+)$`)
	rePyAssignName  = regexp.MustCompile(`^([A-Za-z_]\w*)\s*(?::[^=]+)?=(?:[^=]|$)`)
	rePyAsName      = regexp.MustCompile(`\bas\s+([A-Za-z_]\w*)\s*[:,)]`)
	rePyFStringExpr = regexp.MustCompile(`(?i)\b(?:rf|fr|f)(?:"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)')`)
	rePyQuotedIdent = regexp.MustCompile(`["']\s*([A-Za-z_][\w.]*(?:\[[^"'\n]*\])?)\s*["']`)
	rePyJump        = regexp.MustCompile(`^(return|raise|continue|break)\b`)
	rePyDynamic     = regexp.MustCompile(`\b(?:locals|vars|globals|exec|eval)\s*\(`)
)

// pyVirtualUses collects text that uses names without being plain code:
// f-string `{expressions}` and quoted forward references / __all__ entries.
func pyVirtualUses(text []string) string {
	var sb strings.Builder
	for _, line := range text {
		for _, g := range rePyFStringExpr.FindAllStringSubmatch(line, -1) {
			body := g[1] + g[2]
			depth, start := 0, 0
			for i := 0; i < len(body); i++ {
				switch body[i] {
				case '{':
					if depth == 0 && i+1 < len(body) && body[i+1] == '{' {
						i++ // `{{` is a literal brace
						continue
					}
					if depth == 0 {
						start = i + 1
					}
					depth++
				case '}':
					if depth > 0 {
						depth--
						if depth == 0 {
							sb.WriteString(body[start:i])
							sb.WriteByte(' ')
						}
					}
				}
			}
		}
		for _, g := range rePyQuotedIdent.FindAllStringSubmatch(line, -1) {
			sb.WriteString(g[1])
			sb.WriteByte(' ')
		}
	}
	return sb.String()
}

// scanDeadCodePy runs the Python dead-code rules on one masked file.
func scanDeadCodePy(filePath string, m maskedFile) []CSIssue {
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

	// ---- unused imports ----
	isInit := strings.HasSuffix(filePath, "__init__.py") || strings.HasSuffix(filePath, "__init__.pyi")
	if !isInit {
		type imp struct {
			local, from string
			line        int
		}
		var imps []imp
		blank := make([]bool, len(code)) // import statement lines, excluded from usage
		for i := 0; i < len(code); i++ {
			if !starts[i] {
				continue
			}
			stmt, end := pyLogical(code, starts, i)
			stmt = strings.NewReplacer("(", " ", ")", " ", "\\", " ").Replace(stmt)
			stmt = strings.Join(strings.Fields(stmt), " ")
			var names []imp
			if g := rePyFromImport.FindStringSubmatch(stmt); g != nil && g[1] != "__future__" {
				for _, part := range strings.Split(g[2], ",") {
					part = strings.TrimSpace(part)
					if part == "" || part == "*" {
						continue
					}
					f := strings.Fields(part)
					local := f[0]
					if len(f) == 3 && f[1] == "as" {
						local = f[2]
					}
					names = append(names, imp{local: local, from: g[1], line: i})
				}
			} else if g := rePyImport.FindStringSubmatch(stmt); g != nil && !strings.HasPrefix(stmt, "import(") {
				for _, part := range strings.Split(g[1], ",") {
					f := strings.Fields(strings.TrimSpace(part))
					if len(f) == 0 {
						continue
					}
					local := strings.SplitN(f[0], ".", 2)[0]
					if len(f) == 3 && f[1] == "as" {
						local = f[2]
					}
					names = append(names, imp{local: local, from: f[0], line: i})
				}
			} else {
				continue
			}
			// optional-dependency imports live under `try:` — leave them alone
			if pyIndent(code[i]) > 0 && prevLogicalTrimmed(code, starts, i) == "try:" {
				for l := i; l <= end; l++ {
					blank[l] = true
				}
				continue
			}
			for l := i; l <= end; l++ {
				blank[l] = true
			}
			imps = append(imps, names...)
		}
		if len(imps) > 0 {
			var usage strings.Builder
			for l, c := range code {
				if !blank[l] {
					usage.WriteString(c)
					usage.WriteByte('\n')
				}
			}
			virt := pyVirtualUses(m.text)
			used := usage.String()
			for _, im := range imps {
				if im.local == "_" || strings.HasPrefix(im.local, "__") {
					continue
				}
				if countIdent(used, im.local) == 0 && countIdent(virt, im.local) == 0 {
					add(im.line, security.SevMedium, "dead-unused-import", "Unused import", im.local+" from "+im.from,
						"Imported but never used; remove it (it also slows start-up and can hide a circular import).")
				}
			}
		}
	}

	// ---- unused local variables (pyflakes F841) ----
	for _, f := range funcs {
		if f.oneLiner || f.end <= f.bodyStart {
			continue
		}
		region := strings.Join(code[f.bodyStart:min(f.end+1, len(code))], "\n")
		if rePyDynamic.MatchString(region) || strings.Contains(region, "global ") || strings.Contains(region, "nonlocal ") {
			continue
		}
		nested := map[int]bool{}
		for _, g := range funcs {
			if g.start > f.start && g.end <= f.end && g.start >= f.bodyStart {
				for l := g.start; l <= g.end; l++ {
					nested[l] = true
				}
			}
		}
		writes := map[string]int{}
		firstLine := map[string]int{}
		for i := f.bodyStart; i <= f.end && i < len(code); i++ {
			if !starts[i] || nested[i] {
				continue
			}
			stmt, _ := pyLogical(code, starts, i)
			if g := rePyAssignName.FindStringSubmatch(stmt); g != nil {
				writes[g[1]]++
				if _, ok := firstLine[g[1]]; !ok {
					firstLine[g[1]] = i
				}
			}
			for _, g := range rePyAsName.FindAllStringSubmatch(stmt, -1) {
				if strings.HasPrefix(stmt, "with ") || strings.HasPrefix(stmt, "except ") || strings.HasPrefix(stmt, "async with ") {
					writes[g[1]]++
					if _, ok := firstLine[g[1]]; !ok {
						firstLine[g[1]] = i
					}
				}
			}
		}
		if len(writes) == 0 {
			continue
		}
		virt := pyVirtualUses(m.text[f.bodyStart:min(f.end+1, len(m.text))])
		for name, w := range writes {
			if name == "_" || strings.HasPrefix(name, "_") || name == "self" || name == "cls" {
				continue
			}
			if countIdent(region, name)+countIdent(virt, name) <= w {
				add(firstLine[name], security.SevMedium, "dead-unused-var", "Unused variable", name,
					"Assigned but never read in this function. Remove it (keep a call's side effect without the assignment), or prefix with `_` if it is intentionally ignored.")
			}
		}
	}

	// ---- unreachable code (indentation-based) ----
	for i := 0; i < len(code); i++ {
		if !starts[i] {
			continue
		}
		stmt, end := pyLogical(code, starts, i)
		g := rePyJump.FindStringSubmatch(stmt)
		if g == nil {
			continue
		}
		j := nextLogical(code, starts, end)
		if j < 0 || pyIndent(code[j]) != pyIndent(code[i]) {
			continue
		}
		if w := strings.Fields(strings.TrimSpace(code[j])); len(w) > 0 {
			switch strings.TrimSuffix(w[0], ":") {
			case "else", "elif", "except", "finally", "case":
				continue
			}
		}
		add(j, security.SevMedium, "dead-unreachable", "Unreachable code", "after "+g[1],
			"This statement follows a return/raise/continue/break in the same block, so it can never run. Delete it, or move it before the jump.")
	}

	out = append(out, commentedOutCodeLang(filePath, m, "#", pyCommentedCode)...)
	return dedupeIssues(out)
}

// prevLogicalTrimmed returns the trimmed statement preceding line i.
func prevLogicalTrimmed(code []string, starts []bool, i int) string {
	for j := i - 1; j >= 0; j-- {
		if starts[j] {
			return strings.TrimSpace(code[j])
		}
	}
	return ""
}

var pyCommentedCode = []*regexp.Regexp{
	regexp.MustCompile(`^(?:def|class|import|from|return|if|elif|else|for|while|try|except|finally|with|raise|assert|print|yield|pass|break|continue|async|await|lambda)\b[\s(:]`),
	regexp.MustCompile(`^[A-Za-z_][\w.\[\]]*\s*(?:[-+*/]?=)\s*\S`),
	regexp.MustCompile(`^[A-Za-z_][\w.]*\(.*\)\s*$`),
	regexp.MustCompile(`^@\w+`),
	regexp.MustCompile(`:\s*$`),
}

var rePyCommentKeep = regexp.MustCompile(`(?i)^(?:todo|fixme|note|hack|xxx|noqa|pylint|type:|pragma|fmt:|isort|flake8|-\*-|coding[:=]|!|mypy|pyright|ruff|nosec|see\b|e\.g\.|i\.e\.)`)

// commentedOutCodeLang is commentedOutCode for a line-comment marker and a
// set of "reads as code" patterns (Python today).
func commentedOutCodeLang(filePath string, m maskedFile, marker string, pats []*regexp.Regexp) []CSIssue {
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
	for i, line := range m.raw {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, marker) && !strings.HasPrefix(t, marker+marker) && !strings.HasPrefix(t, "#!") {
			content := strings.TrimSpace(strings.TrimPrefix(t, marker))
			if len(content) >= 3 && !rePyCommentKeep.MatchString(content) {
				code := false
				for _, re := range pats {
					if re.MatchString(content) {
						code = true
						break
					}
				}
				if code {
					if run == 0 {
						start = i
					}
					run++
					continue
				}
			}
		}
		flush()
	}
	flush()
	return out
}
