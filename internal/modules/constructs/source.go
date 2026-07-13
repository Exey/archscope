// Package constructs holds ArchScope's code-construct detectors — the umbrella
// for data-structure, (and, over later milestones, complexity and
// magic-constant) detection ported from ArchSwiftScope's Constructs core. Each
// detector is a self-registering report module; this file provides the shared
// source-reading helpers they build on.
package constructs

import (
	"fmt"
	"html"
	"os"
	"strconv"
	"strings"
)

// maxSourceBytes bounds a single source read so a stray huge/minified file
// can't blow up analysis; larger files skip body-evidence gating (accept the
// name match) rather than being read.
const maxSourceBytes = 2 << 20 // 2 MiB

// fileSource is one file read once: its comment/string-stripped lines and, per
// line, the raw contents of any string literals that appeared on it.
type fileSource struct {
	stripped []string
	strings  [][]string // per-line string-literal contents (parallel to stripped)
	ok       bool
}

// sourceCache reads, comment/string-strips, and collects the string literals of
// each source file at most once per Analyze pass. Every line-level detector
// shares it so a file is never read twice. Not safe for concurrent use — one
// cache per Analyze call, used single-goroutine.
type sourceCache struct {
	files map[string]*fileSource
}

func newSourceCache() *sourceCache {
	return &sourceCache{files: map[string]*fileSource{}}
}

// get reads (or returns the cached) fileSource for filePath. A file that is
// unreadable or too large is cached as an ok=false entry.
func (c *sourceCache) get(filePath string) *fileSource {
	if s, ok := c.files[filePath]; ok {
		return s
	}
	s := &fileSource{}
	fi, err := os.Stat(filePath)
	if err == nil && fi.Size() <= maxSourceBytes {
		if data, err := os.ReadFile(filePath); err == nil {
			s.stripped, s.strings = readSource(string(data), ext(filePath))
			s.ok = true
		}
	}
	c.files[filePath] = s
	return s
}

// lines returns the file's comment/string-stripped lines, or nil when the file
// is unreadable or too large.
func (c *sourceCache) lines(filePath string) []string {
	if s := c.get(filePath); s.ok {
		return s.stripped
	}
	return nil
}

// stringLiterals returns, per stripped line, the raw contents of the string
// literals found on that line, or nil when the file is unreadable/too large.
func (c *sourceCache) stringLiterals(filePath string) [][]string {
	if s := c.get(filePath); s.ok {
		return s.strings
	}
	return nil
}

// ext returns the lowercased file extension including the dot (".swift").
func ext(path string) string {
	if i := strings.LastIndexByte(path, '.'); i >= 0 {
		return strings.ToLower(path[i:])
	}
	return ""
}

// hashComment reports whether '#' starts a line comment in the given language.
// In Python/Ruby/shell it does; in Swift/C-family it's a directive/selector
// sigil, so stripping from '#' there would wrongly blank real code.
func hashComment(fileExt string) bool {
	switch fileExt {
	case ".py", ".rb", ".sh", ".yaml", ".yml", ".toml":
		return true
	}
	return false
}

// readSource blanks comments and string-literal contents from source (so prose
// in a doc comment or a log message can't read as implementation evidence) and,
// in the same pass, collects each line's string-literal contents. It handles //
// and (language-appropriate) # line comments, /* */ block comments, and
// single/double/backtick string literals. Structure (braces, identifiers) is
// preserved; only comment/string *content* is removed from the stripped lines.
// Returns one stripped line and one string-literal list per input line.
func readSource(src, fileExt string) (stripped []string, stringLits [][]string) {
	hashes := hashComment(fileExt)
	rawLines := strings.Split(src, "\n")
	stripped = make([]string, len(rawLines))
	stringLits = make([][]string, len(rawLines))
	inBlock := false // inside a /* … */ that spans lines
	for idx, line := range rawLines {
		var b strings.Builder
		b.Grow(len(line))
		var lits []string
		i := 0
		for i < len(line) {
			c := line[i]
			if inBlock {
				if c == '*' && i+1 < len(line) && line[i+1] == '/' {
					inBlock = false
					i += 2
					continue
				}
				i++
				continue
			}
			// line comments
			if c == '/' && i+1 < len(line) && line[i+1] == '/' {
				break
			}
			if hashes && c == '#' {
				break
			}
			// block comment start
			if c == '/' && i+1 < len(line) && line[i+1] == '*' {
				inBlock = true
				i += 2
				continue
			}
			// string literals — keep delimiters, blank the content in the
			// stripped line but collect the raw content for stringLits.
			if c == '"' || c == '\'' || c == '`' {
				b.WriteByte(c)
				i++
				contentStart := i
				for i < len(line) {
					if line[i] == '\\' && c != '`' && i+1 < len(line) {
						i += 2
						continue
					}
					if line[i] == c {
						break
					}
					i++
				}
				if i <= len(line) && contentStart <= len(line) {
					end := i
					if end > len(line) {
						end = len(line)
					}
					lits = append(lits, line[contentStart:end])
				}
				if i < len(line) { // closing delimiter present
					b.WriteByte(c)
					i++
				}
				continue
			}
			b.WriteByte(c)
			i++
		}
		stripped[idx] = b.String()
		stringLits[idx] = lits
	}
	return stripped, stringLits
}

// typeDeclKeywords are the leading tokens that introduce a named type across
// the languages ArchScope parses. Used to locate a type's declaration line for
// body extraction (brace-based) and evidence gating.
var typeDeclKeywords = []string{
	"class ", "struct ", "enum ", "actor ", "interface ",
	"protocol ", "trait ", "object ", "type ", "record ",
}

// declares reports whether stripped line l declares a type named exactly name
// (identifier-boundary checked), e.g. "final class Stack {" declares "Stack"
// but "class StackView" does not.
func declares(l, name string) bool {
	for _, kw := range typeDeclKeywords {
		idx := strings.Index(l, kw+name)
		if idx < 0 {
			continue
		}
		after := idx + len(kw) + len(name)
		if after >= len(l) || !isIdentByte(l[after]) {
			return true
		}
	}
	return false
}

// typeBody returns the lowercased, brace-matched body of the type named name,
// or "" when it can't be located (e.g. indentation-based languages with no
// braces). lines must already be comment/string-stripped.
func typeBody(lines []string, name string) string {
	for i, l := range lines {
		if !declares(l, name) {
			continue
		}
		depth, started := 0, false
		var body []string
		for j := i; j < len(lines); j++ {
			for k := 0; k < len(lines[j]); k++ {
				switch lines[j][k] {
				case '{':
					depth++
					started = true
				case '}':
					depth--
				}
			}
			if started {
				body = append(body, lines[j])
			}
			if started && depth <= 0 {
				return strings.ToLower(strings.Join(body, "\n"))
			}
		}
		if started {
			return strings.ToLower(strings.Join(body, "\n"))
		}
		return "" // declared but no braces (indentation language) → can't gate
	}
	return ""
}

// bodyTokens splits a lowercased body into identifier tokens (maximal runs of
// letters/digits) so evidence terms match whole words, never substrings —
// "popover" is not "pop", ".top" alignment is not "top".
func bodyTokens(body string) map[string]bool {
	set := map[string]bool{}
	start := -1
	for i := 0; i < len(body); i++ {
		c := body[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			if start < 0 {
				start = i
			}
		} else {
			if start >= 0 {
				set[body[start:i]] = true
				start = -1
			}
		}
	}
	if start >= 0 {
		set[body[start:]] = true
	}
	return set
}

func isIdentByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// baseName returns the final path segment (handling both / and \ separators).
func baseName(path string) string {
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// vscodeHref builds a vscode:// deep link for an absolute path + line, mirroring
// the html report's own helper. Returns "" for non-absolute paths (deep links
// would be unreliable), in which case callers fall back to plain text.
func vscodeHref(absPath string, line int) string {
	if absPath == "" {
		return ""
	}
	p := strings.ReplaceAll(absPath, "\\", "/")
	if !strings.HasPrefix(p, "/") {
		return ""
	}
	h := "vscode://file" + p
	if line > 0 {
		h += ":" + strconv.Itoa(line)
	}
	return h
}

// occurrenceLink renders a symbol as a vscode deep link, or plain escaped text
// when no deep link can be built. Shared by every constructs detector's HTML.
func occurrenceLink(symbol, filePath string, line int) string {
	href := vscodeHref(filePath, line)
	if href == "" {
		return html.EscapeString(symbol)
	}
	return fmt.Sprintf(`<a class="as-vs" href="%s" title="%s:%d">%s</a>`,
		html.EscapeString(href), html.EscapeString(baseName(filePath)), line, html.EscapeString(symbol))
}
