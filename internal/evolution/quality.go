package evolution

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Quality is how well the code a merge request ADDS is documented and tested:
// documentation of the new functions, whether the tests mention them, and which
// complex new functions have no doc comment (each also a review Item on its file,
// so it carries an MR link and a code quote).
type Quality struct {
	AddedSrc, AddedTest int // added lines in source files / in test files

	Funcs, Documented int            // new functions, and those with a doc comment
	Testable          int            // new functions a unit test could cover (SQL / query builders excluded)
	Tested            int            // testable new functions a test file refers to by name
	Integration       map[string]int // new functions left out as integration-test subjects, by technology
	Untested          []Item         // the testable new functions no test mentions

	Complex, ComplexDocumented int    // new complex functions (cyclomatic > 10 or 50+ lines), documented ones
	Undocumented               []Item // the complex ones without a doc comment
}

// Pct is n of d as a whole percent (100 when there is nothing to cover).
func Pct(n, d int) int {
	if d <= 0 {
		return 100
	}
	return n * 100 / d
}

// Empty reports whether the change adds no code worth measuring.
func (q *Quality) Empty() bool {
	return q == nil || (q.Funcs == 0 && q.AddedSrc == 0 && q.AddedTest == 0)
}

// AddedLines returns the new-side line numbers a diff of path adds
// (base..head; head "" = the working tree).
func AddedLines(repo, base, head, path string) map[int]bool {
	args := []string{"diff", "-U0", "--no-color", "--no-renames", base}
	if head != "" {
		args = append(args, head)
	}
	out, err := git(repo, append(args, "--", path)...)
	if err != nil {
		return nil
	}
	m := map[int]bool{}
	for _, line := range strings.Split(out, "\n") {
		h := hunkRe.FindStringSubmatch(line)
		if h == nil {
			continue
		}
		start, _ := strconv.Atoi(h[3])
		n := 1
		if h[4] != "" {
			n, _ = strconv.Atoi(h[4])
		}
		for i := 0; i < n; i++ {
			m[start+i] = true
		}
	}
	return m
}

// RenderQualityMarkdown mirrors the HTML "Quality of the added code" block.
func RenderQualityMarkdown(q *Quality) string {
	if q.Empty() {
		return ""
	}
	var b strings.Builder
	b.WriteString("**Quality of the added code**\n\n| Metric | Result |\n|--------|--------|\n")
	fmt.Fprintf(&b, "| 📝 New functions with a doc comment | %d of %d (%d%%) |\n", q.Documented, q.Funcs, Pct(q.Documented, q.Funcs))
	fmt.Fprintf(&b, "| 🧪 Testable new functions referenced by a test | %d of %d (%d%%) |\n", q.Tested, q.Testable, Pct(q.Tested, q.Testable))
	fmt.Fprintf(&b, "| 🧫 Testable new functions without tests | %d |\n", len(q.Untested))
	fmt.Fprintf(&b, "| 🌀 Complex new functions with a doc comment | %d of %d (%d%%) |\n", q.ComplexDocumented, q.Complex, Pct(q.ComplexDocumented, q.Complex))
	fmt.Fprintf(&b, "| ➕ Added lines | %s source · %s test |\n\n", commaInt(q.AddedSrc), commaInt(q.AddedTest))
	if note := q.IntegrationNote(); note != "" {
		fmt.Fprintf(&b, "_%s._\n\n", note)
	}
	if len(q.Untested) > 0 {
		b.WriteString("Testable functions without tests:\n\n")
		for i, it := range q.Untested {
			if i == 15 {
				fmt.Fprintf(&b, "- …and %d more\n", len(q.Untested)-15)
				break
			}
			fmt.Fprintf(&b, "- %s\n", itemMD(it))
		}
		b.WriteString("\n")
	}
	if len(q.Undocumented) > 0 {
		b.WriteString("Complex functions that need a doc comment:\n\n")
		for _, it := range q.Undocumented {
			fmt.Fprintf(&b, "- %s\n", itemMD(it))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// IntegrationNote says how many new functions were left out because they use SQL,
// the network, the filesystem …: "6 functions need integration tests, not unit
// tests (SQL ×4, network ×2)". "" when none.
func (q *Quality) IntegrationNote() string {
	if q == nil || len(q.Integration) == 0 {
		return ""
	}
	var names []string
	total := 0
	for k, n := range q.Integration {
		names = append(names, k)
		total += n
	}
	sort.Slice(names, func(i, j int) bool {
		if q.Integration[names[i]] != q.Integration[names[j]] {
			return q.Integration[names[i]] > q.Integration[names[j]]
		}
		return names[i] < names[j]
	})
	parts := make([]string, len(names))
	for i, k := range names {
		parts[i] = fmt.Sprintf("%s ×%d", k, q.Integration[k])
	}
	return fmt.Sprintf("%d %s integration tests, not unit tests, and are not counted (%s)", total, plural(total, "function needs", "functions need"), strings.Join(parts, ", "))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
