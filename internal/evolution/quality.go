package evolution

import (
	"fmt"
	"strconv"
	"strings"
)

// Quality is how well the code a merge request ADDS is documented and tested:
// documentation of the new functions, whether the tests mention them, and which
// complex new functions have no doc comment (each also a review Item on its file,
// so it carries an MR link and a code quote).
type Quality struct {
	AddedSrc, AddedTest int // added lines in source files / in test files

	Funcs, Documented int // new functions, and those with a doc comment
	Tested            int // new functions a test file refers to by name

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
	fmt.Fprintf(&b, "| 🧪 New functions referenced by a test | %d of %d (%d%%) |\n", q.Tested, q.Funcs, Pct(q.Tested, q.Funcs))
	fmt.Fprintf(&b, "| 🌀 Complex new functions with a doc comment | %d of %d (%d%%) |\n", q.ComplexDocumented, q.Complex, Pct(q.ComplexDocumented, q.Complex))
	fmt.Fprintf(&b, "| ➕ Added lines | %s source · %s test |\n\n", commaInt(q.AddedSrc), commaInt(q.AddedTest))
	if len(q.Undocumented) > 0 {
		b.WriteString("Complex functions that need a doc comment:\n\n")
		for _, it := range q.Undocumented {
			fmt.Fprintf(&b, "- %s\n", itemMD(it))
		}
		b.WriteString("\n")
	}
	return b.String()
}
