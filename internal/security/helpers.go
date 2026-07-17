package security

import "strings"

// IsTestPath reports whether filePath belongs to a test, mock, fixture, e2e or
// other non-production context where security patterns are expected and safe
// (test TLS bypasses, test credentials, test command execution, etc.).
//
// Checks both directory components (split on / and \) and filename suffixes for
// the major language conventions across Go, Swift, Kotlin, TypeScript, Python,
// Java, C/C++.
func IsTestPath(filePath string) bool {
	low := strings.ToLower(filePath)
	for _, part := range strings.FieldsFunc(low, func(r rune) bool { return r == '/' || r == '\\' }) {
		// Any directory component that starts with "test" is a test directory:
		// test, tests, testdata, testcerts, testutil, testutils, testhelper,
		// testing, testsuites, testingcert, testinfra, testserver, etc.
		if strings.HasPrefix(part, "test") {
			return true
		}
		// Any component starting with "e2e" covers e2e, e2e_node, e2e_node_windows, etc.
		if strings.HasPrefix(part, "e2e") {
			return true
		}
		// Any component *containing* "mock" — not just an exact "mock"/"mocks"
		// directory — covers filenames like "eval-mock-helpers.ts" too.
		if strings.Contains(part, "mock") {
			return true
		}
		switch part {
		case "fixture", "fixtures",
			"spec", "specs", "__tests__",
			"example", "examples",
			"fuzz", "fuzzer", "fuzzers",
			"integration", "integration_test", "int_test":
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
		// ".test." / ".spec." anywhere in the filename — not just as the final
		// suffix — covers "*.test.constants.ts", "*.test.mock.ts" and similar
		// multi-segment test-only filenames, not just "*.test.ts"/"*.spec.ts".
		strings.Contains(base, ".test.") ||
		strings.Contains(base, ".spec.") ||
		strings.HasSuffix(base, "_test.py") ||
		(strings.HasPrefix(base, "test_") && strings.Contains(base, ".py")) ||
		strings.HasSuffix(base, "test.java") ||
		strings.HasSuffix(base, "tests.java") ||
		strings.HasSuffix(base, "_test.c") ||
		strings.HasSuffix(base, "_test.cpp") ||
		strings.HasSuffix(base, "_test.cc") ||
		strings.HasSuffix(base, "_test.cxx") ||
		strings.HasSuffix(base, "_unittest.cc") ||
		strings.HasSuffix(base, "_unittest.cpp") ||
		// n8n-style credential *schema* files (e.g. AirtableApi.credentials.ts)
		// declare a credential's UI fields — they never hold a real secret
		// value, only expression placeholders or field names.
		strings.HasSuffix(base, ".credentials.ts") ||
		strings.HasSuffix(base, ".credentials.js")
}

// IsCredentialDataPath reports whether filePath is a credentials-schema
// directory or a seed/fixture-data file — contexts where a "secret-shaped"
// string is structurally never a real secret (n8n-style `credentials/`
// directories declare form fields; `*seeder*` files generate mock records for
// tests/evaluations). Narrower and additive to IsTestPath: used only by the
// hardcoded-secret/credential detectors, not folded into the general-purpose
// IsTestPath, since an eval() or SQL-injection finding in one of these files
// would still be a real issue worth flagging.
func IsCredentialDataPath(filePath string) bool {
	low := strings.ToLower(filePath)
	for _, part := range strings.FieldsFunc(low, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == "credentials" || part == "credential" {
			return true
		}
		if strings.Contains(part, "seeder") {
			return true
		}
	}
	return false
}

// IsTestOrBenchPath reports whether filePath is test or benchmark code — used
// by code-quality metrics (Complexity, Code Structure, Longest Functions,
// Biggest Types) that want production code only.
//
// Deliberately independent of IsTestPath rather than building on it: that
// function's directory check matches on a "test"-prefix (test, testdata,
// testutil, …), which is the right net for security-rule suppression but
// collides with Go's own `t.TempDir()` naming — every quality-metric unit
// test writes its fixtures under a path like ".../TestFooBar123/001/f.go",
// and a prefix match would exclude the fixture from the very test verifying
// it's included. This checks directory components for an *exact* name match
// instead (test, tests, __tests__, benchmark, benchmarks, …), which still
// catches the real "Tests/"/"Benchmarks/" folder convention (Swift Package
// Manager, Go/Java benchmark packages) without that collision, plus the same
// filename-suffix conventions IsTestPath checks (safe either way, since
// those match the file's own base name, not a path component Go's test
// harness controls).
func IsTestOrBenchPath(filePath string) bool {
	low := strings.ToLower(filePath)
	for _, part := range strings.FieldsFunc(low, func(r rune) bool { return r == '/' || r == '\\' }) {
		switch part {
		case "test", "tests", "__tests__", "testdata",
			"spec", "specs", "e2e",
			"benchmark", "benchmarks", "bench", "benches":
			return true
		}
	}
	base := low
	if idx := strings.LastIndexAny(low, "/\\"); idx >= 0 {
		base = low[idx+1:]
	}
	return strings.HasSuffix(base, "_test.go") ||
		strings.HasSuffix(base, "test.swift") ||
		strings.HasSuffix(base, "tests.swift") ||
		strings.HasSuffix(base, "spec.swift") ||
		strings.HasSuffix(base, "test.kt") ||
		strings.HasSuffix(base, "tests.kt") ||
		strings.HasSuffix(base, "spec.kt") ||
		strings.Contains(base, ".test.ts") ||
		strings.Contains(base, ".spec.ts") ||
		strings.Contains(base, ".test.tsx") ||
		strings.Contains(base, ".spec.tsx") ||
		strings.Contains(base, ".test.js") ||
		strings.Contains(base, ".spec.js") ||
		strings.HasSuffix(base, "_test.py") ||
		(strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py")) ||
		strings.HasSuffix(base, "test.java") ||
		strings.HasSuffix(base, "tests.java") ||
		strings.HasSuffix(base, "_test.c") ||
		strings.HasSuffix(base, "_test.cpp") ||
		strings.HasSuffix(base, "_test.cc") ||
		strings.HasSuffix(base, "_test.cxx") ||
		strings.HasSuffix(base, "_unittest.cc") ||
		strings.HasSuffix(base, "_unittest.cpp") ||
		strings.Contains(base, "_benchmark") ||
		strings.Contains(base, "benchmark_") ||
		strings.HasSuffix(base, "_bench.go") ||
		strings.HasSuffix(base, "_bench_test.go")
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
