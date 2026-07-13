package constructs

import "testing"

// TestTripleQuoteSpansLines verifies a Python/Swift docstring's contents are
// blanked on every line it spans, not just its first — the exact bug ported
// detectors would otherwise inherit from a per-line-reset stripper.
func TestTripleQuoteSpansLines(t *testing.T) {
	src := "def f():\n" +
		"    \"\"\"\n" +
		"    for i in range(10): stack.push(i)\n" +
		"    \"\"\"\n" +
		"    return 1\n"
	stripped, _ := readSource(src, ".py")
	if got := stripped[2]; got != "" {
		t.Fatalf("line inside triple-quoted string should be blank, got %q", got)
	}
	if want := "    return 1"; stripped[4] != want {
		t.Fatalf("line after closing delimiter = %q, want %q", stripped[4], want)
	}
}

// TestBacktickSpansLines verifies a Go raw string / JS template literal's
// contents are blanked on every line it spans.
func TestBacktickSpansLines(t *testing.T) {
	src := "x := `\n" +
		"func quicksort() { pivot := arr[0] }\n" +
		"`\n" +
		"y := 2\n"
	stripped, _ := readSource(src, ".go")
	if got := stripped[1]; got != "" {
		t.Fatalf("line inside backtick string should be blank, got %q", got)
	}
	if want := "y := 2"; stripped[3] != want {
		t.Fatalf("line after closing backtick = %q, want %q", stripped[3], want)
	}
}

// TestTripleQuoteSameLineNotInStringLits matches Swift's documented
// decision: triple-quoted content is never attributed to stringLits, even
// when it closes on the same line.
func TestTripleQuoteSameLineNotInStringLits(t *testing.T) {
	_, lits := readSource(`x = """hello"""`, ".py")
	if len(lits[0]) != 0 {
		t.Fatalf("triple-quoted literal should not be collected, got %v", lits[0])
	}
}

// TestUnterminatedSingleQuoteResets confirms the defensive reset for a plain
// single/double-quoted string left open at end-of-line is unchanged — it must
// NOT swallow the rest of the file as "inside a string".
func TestUnterminatedSingleQuoteResets(t *testing.T) {
	src := "s := \"oops\n" +
		"real_code_here()\n"
	stripped, _ := readSource(src, ".go")
	if got := stripped[1]; got != "real_code_here()" {
		t.Fatalf("line after unterminated quote = %q, want unaffected code", got)
	}
}

// TestSingleLineStringLiteralsStillCollected is a regression check that the
// common single-line case (comments, strings, string literal collection)
// still behaves exactly as before this fix.
func TestSingleLineStringLiteralsStillCollected(t *testing.T) {
	stripped, lits := readSource(`x := "hello" // trailing comment`, ".go")
	if stripped[0] != `x := "" ` {
		t.Fatalf("stripped = %q", stripped[0])
	}
	if len(lits[0]) != 1 || lits[0][0] != "hello" {
		t.Fatalf("lits = %v", lits[0])
	}
}

// TestNestedBlockCommentSwift verifies Swift's nested /* */ comments: the
// inner "*/" only closes the inner level, so code after it is still inside
// the outer comment and gets stripped — only the "*/" that closes the outer
// level un-blanks the rest of the line.
func TestNestedBlockCommentSwift(t *testing.T) {
	stripped, _ := readSource(`/* outer /* inner */ still commented */ code_after`, ".swift")
	if want := " code_after"; stripped[0] != want {
		t.Fatalf("stripped = %q, want %q", stripped[0], want)
	}
}

// TestBlockCommentDoesNotNestInGo verifies C-family languages are unaffected:
// the first "*/" closes the block comment regardless of an earlier stray
// "/*", so text after it (including a leftover "*/") reads as real code.
func TestBlockCommentDoesNotNestInGo(t *testing.T) {
	stripped, _ := readSource(`/* outer /* inner */ still commented */ code_after`, ".go")
	if want := ` still commented */ code_after`; stripped[0] != want {
		t.Fatalf("stripped = %q, want %q", stripped[0], want)
	}
}
