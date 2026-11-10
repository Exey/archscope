package evolution

import (
	"fmt"
	"github.com/exey/archscope/internal/langprofile"
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Triage is what a reviewer should look at first and what the change forgot:
// a ranking of the changed files and flags for missing tests, new dependencies
// and risky database migrations.
type Triage struct {
	ReadFirst []ReadFirst
	Flags     []Item // Kind "Review flag"; Name is the headline, Note the detail
}

// ReadFirst is one ranked file with the reasons that put it there.
type ReadFirst struct {
	Path    string // repository-relative
	Score   int
	Reasons []string
}

// Empty reports whether there is nothing to show.
func (t *Triage) Empty() bool { return t == nil || (len(t.ReadFirst) == 0 && len(t.Flags) == 0) }

const readFirstMax = 5

var (
	securityKinds   = map[string]bool{"HIGH security": true, "Concurrency / API": true, "Memory leak": true}
	complexityKinds = map[string]bool{"High complexity": true, "O(N²)": true, "Deep nesting": true, "Long function": true, "Many parameters": true}
)

// RankFiles orders the changed production files by how much review they need:
// each issue counts by its weight (HIGH 7, MEDIUM 2, …), security findings and
// complexity findings add a bonus, and the size of the change adds a little —
// so a small risky change outranks a big mechanical one.
func RankFiles(files []ReviewFile) []ReadFirst {
	var out []ReadFirst
	for _, f := range files {
		if f.Binary || IsTestPath(f.Path) {
			continue
		}
		score, high, sec, cx := 0, 0, 0, 0
		for _, it := range f.Issues {
			score += it.Weight
			if it.Weight >= 7 {
				high++
			}
			if securityKinds[it.Kind] {
				sec++
				score += 3
			}
			if complexityKinds[it.Kind] {
				cx++
				score += 2
			}
		}
		if score == 0 {
			continue
		}
		churn := f.Add + f.Del
		score += int(math.Min(6, math.Log2(float64(churn+1))))
		var why []string
		if high > 0 {
			why = append(why, fmt.Sprintf("%d HIGH", high))
		}
		if sec > 0 {
			why = append(why, fmt.Sprintf("%d security/safety", sec))
		}
		if cx > 0 {
			why = append(why, fmt.Sprintf("%d complexity", cx))
		}
		if rest := len(f.Issues) - high - sec - cx; rest > 0 {
			why = append(why, fmt.Sprintf("%d other", rest))
		}
		why = append(why, fmt.Sprintf("+%d/−%d lines", f.Add, f.Del))
		out = append(out, ReadFirst{Path: f.Path, Score: score, Reasons: why})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	if len(out) > readFirstMax {
		out = out[:readFirstMax]
	}
	return out
}

// IsTestPath reports whether p looks like a test file (any language).
func IsTestPath(p string) bool { return langprofile.IsTest(p) }

// UntestedChanges lists the changed production source files that got real new
// code but no changed test file next to them (same directory or same stem).
func UntestedChanges(files []ReviewFile, isSource func(string) bool) []ReviewFile {
	testDirs, testStems := map[string]bool{}, map[string]bool{}
	for _, f := range files {
		if IsTestPath(f.Path) {
			testDirs[path.Dir(f.Path)] = true
			testStems[stem(f.Path)] = true
		}
	}
	var out []ReviewFile
	for _, f := range files {
		if f.Binary || f.Add < 10 || IsTestPath(f.Path) || langprofile.IsGeneratedPath(f.Path) || !isSource(f.Path) {
			continue
		}
		if testDirs[path.Dir(f.Path)] || testStems[stem(f.Path)] {
			continue
		}
		out = append(out, f)
	}
	return out
}

var reTestWords = regexp.MustCompile(`(?i)(?:^test_|_test$|\.test$|\.spec$|tests?$)`)

func stem(p string) string {
	b := path.Base(p)
	b = strings.TrimSuffix(b, path.Ext(b))
	return strings.ToLower(reTestWords.ReplaceAllString(b, ""))
}

// ── dependencies ─────────────────────────────────────────────────────────────

var depManifests = map[string]*regexp.Regexp{
	"go.mod":           regexp.MustCompile(`^\s*(?:require\s+)?([\w.\-]+\.[\w.\-]+/[\w.\-/~]+|[\w\-]+\.[\w.\-]+)\s+v\d`),
	"package.json":     regexp.MustCompile(`^\s*"(@?[\w.\-]+(?:/[\w.\-]+)?)"\s*:\s*"[\^~<>=*\d]|^\s*"(@?[\w.\-]+(?:/[\w.\-]+)?)"\s*:\s*"(?:latest|workspace:|npm:|git)`),
	"requirements.txt": regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9_.\-]+)\s*(?:[=<>~!]=?|\[|;|$)`),
	"Cargo.toml":       regexp.MustCompile(`^\s*([A-Za-z][\w\-]+)\s*=\s*(?:"|\{)`),
	"Gemfile":          regexp.MustCompile(`^\s*gem\s+['"]([\w\-]+)['"]`),
	"pyproject.toml":   regexp.MustCompile(`^\s*"([A-Za-z][A-Za-z0-9_.\-]+)\s*(?:[=<>~!\[;]|")`),
	"pom.xml":          regexp.MustCompile(`<artifactId>([^<]+)</artifactId>`),
	"build.gradle":     regexp.MustCompile(`(?:implementation|api|compileOnly|runtimeOnly|testImplementation|kapt)\s*\(?\s*['"]([^'"]+)['"]`),
	"build.gradle.kts": regexp.MustCompile(`(?:implementation|api|compileOnly|runtimeOnly|testImplementation|kapt)\s*\(?\s*['"]([^'"]+)['"]`),
	"Package.swift":    regexp.MustCompile(`\.package\s*\(\s*url:\s*"([^"]+)"`),
	"Podfile":          regexp.MustCompile(`^\s*pod\s+['"]([\w\-/+.]+)['"]`),
}

// DependencyManifest returns the manifest kind of p ("" = not a manifest).
func DependencyManifest(p string) string {
	b := path.Base(p)
	if _, ok := depManifests[b]; ok {
		return b
	}
	if strings.HasPrefix(b, "requirements") && strings.HasSuffix(b, ".txt") {
		return "requirements.txt"
	}
	return ""
}

// NewDependencies names the dependencies the added lines introduce that the base
// version of the manifest did not mention (a version bump is not a new dependency).
// added are the new-side lines (with numbers); base is the whole base file.
func NewDependencies(kind string, added map[int]string, base string) (names []string, firstLine int) {
	re := depManifests[kind]
	if re == nil {
		return nil, 0
	}
	var lines []int
	for n := range added {
		lines = append(lines, n)
	}
	sort.Ints(lines)
	seen := map[string]bool{}
	for _, n := range lines {
		l := added[n]
		if strings.HasPrefix(strings.TrimSpace(l), "//") || strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		m := re.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		name := ""
		for _, g := range m[1:] {
			if g != "" {
				name = g
				break
			}
		}
		if name == "" || seen[name] || strings.Contains(base, name) {
			continue
		}
		if kind == "package.json" && (name == "name" || name == "version" || name == "main" || name == "license" || name == "description") {
			continue
		}
		seen[name] = true
		names = append(names, name)
		if firstLine == 0 {
			firstLine = n
		}
	}
	return names, firstLine
}

// ── migrations ───────────────────────────────────────────────────────────────

// IsMigrationPath reports whether p is a database migration.
func IsMigrationPath(p string) bool {
	l := strings.ToLower(p)
	return strings.Contains(l, "migrat") && (strings.HasSuffix(l, ".sql") || strings.HasSuffix(l, ".py") || strings.HasSuffix(l, ".go") ||
		strings.HasSuffix(l, ".rb") || strings.HasSuffix(l, ".kt") || strings.HasSuffix(l, ".java") || strings.HasSuffix(l, ".xml") || strings.HasSuffix(l, ".ts") || strings.HasSuffix(l, ".js")) ||
		strings.HasSuffix(l, ".sql") && (strings.Contains(l, "/db/") || strings.Contains(l, "flyway") || strings.Contains(l, "liquibase"))
}

var riskyMigration = []struct {
	re   *regexp.Regexp
	not  *regexp.Regexp // the statement is fine when this also matches
	what string
}{
	{regexp.MustCompile(`(?i)\bDROP\s+(?:TABLE|COLUMN|SCHEMA|DATABASE)\b|\bop\.drop_(?:table|column)\b|migrations\.(?:DeleteModel|RemoveField)\b|\bdropTable\b|\bdropColumn\b`), nil, "drops a table or column — data is gone, and old code still running during the deploy breaks"},
	{regexp.MustCompile(`(?i)\bTRUNCATE\b`), nil, "truncates a table"},
	{regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+\w+\s*;?\s*$`), nil, "DELETE without WHERE removes every row"},
	{regexp.MustCompile(`(?i)\bUPDATE\s+\w+\s+SET\b[^;]*;?\s*$`), nil, "UPDATE of a whole table (check it has a WHERE and batches)"},
	{regexp.MustCompile(`(?i)\bRENAME\s+(?:COLUMN|TO)\b|migrations\.(?:RenameField|RenameModel)\b|\bop\.alter_column\b.*new_column_name`), nil, "renames a column or table — a rolling deploy runs old and new code against it"},
	{regexp.MustCompile(`(?i)\bALTER\s+COLUMN\b.*\bTYPE\b|migrations\.AlterField\b|\bop\.alter_column\b.*type_`), nil, "changes a column's type — may rewrite and lock the table"},
	{regexp.MustCompile(`(?i)\bADD\s+COLUMN\b[^;]*\bNOT\s+NULL\b`), regexp.MustCompile(`(?i)\bDEFAULT\b`), "adds a NOT NULL column without a DEFAULT — fails on a table that has rows"},
	{regexp.MustCompile(`(?i)\bCREATE\s+(?:UNIQUE\s+)?INDEX\b`), regexp.MustCompile(`(?i)\bCONCURRENTLY\b`), "creates an index without CONCURRENTLY — blocks writes on a big table (PostgreSQL)"},
	{regexp.MustCompile(`(?i)\bLOCK\s+TABLE\b`), nil, "takes a table lock"},
}

// RiskyMigrationLines returns, for the added lines of a migration, one
// (line, reason) per risky statement, in line order.
func RiskyMigrationLines(added map[int]string) []struct {
	Line int
	What string
} {
	var lines []int
	for n := range added {
		lines = append(lines, n)
	}
	sort.Ints(lines)
	var out []struct {
		Line int
		What string
	}
	for _, n := range lines {
		l := added[n]
		if strings.HasPrefix(strings.TrimSpace(l), "--") || strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		for _, r := range riskyMigration {
			if r.re.MatchString(l) && (r.not == nil || !r.not.MatchString(l)) {
				out = append(out, struct {
					Line int
					What string
				}{n, r.what})
				break
			}
		}
	}
	return out
}

// RenderTriageMarkdown mirrors the HTML triage block of a review.
func RenderTriageMarkdown(t *Triage) string {
	if t.Empty() {
		return ""
	}
	var b strings.Builder
	if len(t.ReadFirst) > 0 {
		b.WriteString("**📌 Read these first**\n\n_The changed files that need the most review, ranked by their issues (HIGH, security, complexity) and the size of the change._\n\n")
		for i, r := range t.ReadFirst {
			fmt.Fprintf(&b, "%d. `%s` — %s\n", i+1, r.Path, strings.Join(r.Reasons, " · "))
		}
		b.WriteString("\n")
	}
	if len(t.Flags) > 0 {
		b.WriteString("**🚩 Flags**\n\n_Things the change may have forgotten or that carry risk: production code with no test change, a new dependency, a risky database migration._\n\n")
		for _, it := range t.Flags {
			fmt.Fprintf(&b, "- %s\n", itemMD(it))
		}
		b.WriteString("\n")
	}
	return b.String()
}
