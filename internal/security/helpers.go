package security

import "strings"

// Snippet trims and truncates a source line for display in a finding.
func Snippet(line string) string {
	s := strings.TrimSpace(line)
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

// IsComment reports whether a trimmed line is an obvious line/comment-only line
// across the common comment syntaxes (//, #, *, /*). It is intentionally
// conservative; rules that need language-exact comment handling can do their own.
func IsComment(line string) bool {
	t := strings.TrimSpace(line)
	switch {
	case t == "":
		return false
	case strings.HasPrefix(t, "//"):
		return true
	case strings.HasPrefix(t, "#"):
		return true
	case strings.HasPrefix(t, "*"):
		return true
	case strings.HasPrefix(t, "/*"):
		return true
	default:
		return false
	}
}

// NewFinding builds a Finding for a 0-based line index within lines. RuleID and
// FullPath are filled by the engine after Detect returns.
func NewFinding(displayPath string, lineIdx int, lines []string) Finding {
	snippet := ""
	if lineIdx >= 0 && lineIdx < len(lines) {
		snippet = Snippet(lines[lineIdx])
	}
	return Finding{
		File:    displayPath,
		Line:    lineIdx + 1,
		Snippet: snippet,
	}
}
