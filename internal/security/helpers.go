package security

import "strings"

// IsTestPath reports whether filePath belongs to a test, mock, fixture, e2e or
// other non-production context where security patterns are expected and safe
// (test TLS bypasses, test credentials, test command execution, etc.).
//
// Checks both directory components (split on / and \) and filename suffixes for
// the major language conventions across Go, Swift, Kotlin, TypeScript, Python.
func IsTestPath(filePath string) bool {
	low := strings.ToLower(filePath)
	for _, part := range strings.FieldsFunc(low, func(r rune) bool { return r == '/' || r == '\\' }) {
		switch part {
		case "test", "tests", "testdata", "testcerts", "testutil", "testutils",
			"testhelper", "testhelpers", "testinfra",
			"e2e", "e2e_node",
			"fixture", "fixtures",
			"mock", "mocks", "__mocks__",
			"spec", "specs", "__tests__",
			"example", "examples",
			"fuzz", "fuzzer", "fuzzers",
			"integration_test", "int_test":
			return true
		}
	}
	base := low
	if idx := strings.LastIndexAny(low, "/\\"); idx >= 0 {
		base = low[idx+1:]
	}
	return strings.HasSuffix(base, "_test.go") ||
		strings.HasSuffix(base, "test.swift") ||
		strings.HasSuffix(base, "test.kt") ||
		strings.HasSuffix(base, ".test.ts") ||
		strings.HasSuffix(base, ".spec.ts") ||
		strings.HasSuffix(base, ".test.tsx") ||
		strings.HasSuffix(base, ".spec.tsx") ||
		strings.HasSuffix(base, ".test.js") ||
		strings.HasSuffix(base, ".spec.js") ||
		strings.HasSuffix(base, "_test.py") ||
		(strings.HasPrefix(base, "test_") && strings.Contains(base, ".py"))
}

// StripStringsAndComments returns a copy of line with the contents of string
// literals blanked out and inline comments removed. The delimiters themselves
// are preserved so rules that match the opening of a literal (e.g. the import
// path `"crypto/md5"`) still fire, while patterns that only appear inside a
// longer string (description text, pattern arrays) do not.
//
// Supported syntaxes (single-line only):
//   - "…"        double-quoted strings with \" escaping
//   - '…'        single-quoted strings with \' escaping
//   - `…`        backtick raw strings (Go raw literals / JS template literals)
//   - #"…"#      Swift raw strings (one or more # delimiters, e.g. ##"…"##)
//   - //         C-style line comments
//   - #           hash line comments (Python / shell) — only when NOT followed
//     by " which would indicate a Swift raw string
func StripStringsAndComments(line string) string {
	var out strings.Builder
	out.Grow(len(line))
	i := 0
	for i < len(line) {
		c := line[i]
		// C-style // comment → stop
		if c == '/' && i+1 < len(line) && line[i+1] == '/' {
			break
		}
		// Swift raw strings: #"…"# or ##"…"## etc.
		// Heuristic: one or more '#' immediately followed by '"' → raw string.
		// Plain '#' not followed by '"' is treated as a hash line comment.
		if c == '#' {
			j := i
			for j < len(line) && line[j] == '#' {
				j++
			}
			if j < len(line) && line[j] == '"' {
				// Raw string: opening is j-i hashes + '"', closing is '"' + j-i hashes.
				nHash := j - i
				out.WriteByte('"') // placeholder for opening delimiter
				i = j + 1          // skip hashes + opening quote
				for i < len(line) {
					if line[i] == '"' {
						// Check for closing: '"' followed by exactly nHash '#'
						k, cnt := i+1, 0
						for k < len(line) && line[k] == '#' && cnt < nHash {
							k++
							cnt++
						}
						if cnt == nHash {
							out.WriteByte('"') // placeholder for closing delimiter
							i = k
							break
						}
					}
					i++ // skip content
				}
				continue
			}
			// No '"' after the '#' → hash line comment → stop
			break
		}
		// Double-quoted string: keep delimiters, blank content
		if c == '"' {
			out.WriteByte('"')
			i++
			for i < len(line) {
				if line[i] == '\\' && i+1 < len(line) {
					i += 2
					continue
				}
				if line[i] == '"' {
					out.WriteByte('"')
					i++
					break
				}
				i++
			}
			continue
		}
		// Single-quoted string
		if c == '\'' {
			out.WriteByte('\'')
			i++
			for i < len(line) {
				if line[i] == '\\' && i+1 < len(line) {
					i += 2
					continue
				}
				if line[i] == '\'' {
					out.WriteByte('\'')
					i++
					break
				}
				i++
			}
			continue
		}
		// Backtick string (no escape processing)
		if c == '`' {
			out.WriteByte('`')
			i++
			for i < len(line) {
				if line[i] == '`' {
					out.WriteByte('`')
					i++
					break
				}
				i++
			}
			continue
		}
		out.WriteByte(c)
		i++
	}
	return out.String()
}

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
