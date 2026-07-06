package parser

import (
	"bufio"
	"os"
	"strings"

	"github.com/exey/archscope/internal/langspec"
)

// defaultBigFunctionMinLines is the threshold for flagging a "big" function
// when a spec doesn't override it.
const defaultBigFunctionMinLines = 25

// SourceLoader reads a file into lines once. It is the single I/O choke point
// reused by the parser and (later) by security rules, so a file is read at most
// once per phase and both operate on the same []string.
type SourceLoader interface {
	Load(filePath string) (lines []string, err error)
}

// FileLoader is the default disk-backed loader with a large scan buffer so very
// long lines (minified JS, generated code) do not error out.
type FileLoader struct{}

// Load reads filePath and splits it into lines (without trailing newlines).
func (FileLoader) Load(filePath string) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	sc.Buffer(buf, 10*1024*1024)

	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return lines, err
	}
	return lines, nil
}

// ParseUniversal runs the language-agnostic scan using the spec's compiled
// patterns: imports (single + block), declarations, doc comments, TODO/FIXME,
// and longest/big functions via brace depth. The returned ParsedFile may then
// be enriched by spec.ParseHook (called by Parser.Parse, not here).
func ParseUniversal(filePath string, lines []string, spec *langspec.LanguageSpec, c *langspec.Compiled) *ParsedFile {
	pf := &ParsedFile{
		FilePath:   filePath,
		LanguageID: spec.ID,
		Platform:   string(spec.Platform),
		LineCount:  len(lines),
	}

	bigMin := spec.Patterns.BigFunctionMinLines
	if bigMin <= 0 {
		bigMin = defaultBigFunctionMinLines
	}

	var (
		docLines      []string
		inImportBlock bool

		// function-size tracking via brace depth
		inFunc      bool
		curFuncName string
		funcStart   int
		braceDepth  int

		// type-size tracking via brace depth
		inType         bool
		curTypeName    string
		curTypeKind    DeclKind
		typeStart      int
		typeBraceDepth int
	)

	for idx, raw := range lines {
		lineNo := idx + 1
		trimmed := strings.TrimSpace(raw)

		// ── Imports ──
		if c.ImportBlockBeg != nil && c.ImportBlockBeg.MatchString(trimmed) {
			inImportBlock = true
			// fall through is not needed; an opening line carries no module
			continue
		}
		if inImportBlock {
			if c.ImportBlockEnd != nil && c.ImportBlockEnd.MatchString(trimmed) {
				inImportBlock = false
				continue
			}
			if c.ImportInBlock != nil {
				if m := c.ImportInBlock.FindStringSubmatch(trimmed); len(m) > 1 {
					pf.Imports = append(pf.Imports, m[1])
				}
			}
			continue
		}
		if c.ImportSingle != nil {
			if m := c.ImportSingle.FindStringSubmatch(trimmed); len(m) > 1 {
				pf.Imports = append(pf.Imports, m[1])
				continue
			}
		}

		// ── Type declarations ──
		if c.TypeDecl != nil {
			if m := c.TypeDecl.FindStringSubmatch(trimmed); len(m) >= 2 {
				name, keyword := declNameKeyword(m)
				if name != "" {
					kind := mapDeclKind(spec, keyword)
					pf.Declarations = append(pf.Declarations,
						Declaration{Name: name, Kind: kind, Line: lineNo})
					if pf.Description == "" && len(docLines) > 0 {
						pf.Description = strings.Join(docLines, " ")
					}
					docLines = nil
					if !inType {
						inType = true
						curTypeName = name
						curTypeKind = kind
						typeStart = lineNo
						typeBraceDepth = 0
					}
				}
			}
		}

		// ── Function declarations ──
		if c.FuncDecl != nil {
			if m := c.FuncDecl.FindStringSubmatch(trimmed); len(m) > 1 && m[1] != "" {
				pf.Declarations = append(pf.Declarations,
					Declaration{Name: m[1], Kind: DeclFunc, Line: lineNo})
				if !inFunc {
					inFunc = true
					curFuncName = m[1]
					funcStart = lineNo
					braceDepth = 0
				}
			}
		}

		// ── Function-length tracking (brace depth) ──
		if inFunc {
			braceDepth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
			if braceDepth <= 0 && strings.Contains(trimmed, "}") {
				length := lineNo - funcStart + 1
				if pf.LongestFunc == nil || length > pf.LongestFunc.LineCount {
					pf.LongestFunc = &FunctionInfo{
						Name: curFuncName, LineCount: length,
						FilePath: filePath, StartLine: funcStart,
					}
				}
				if length >= bigMin {
					pf.BigFunctions = append(pf.BigFunctions, FunctionInfo{
						Name: curFuncName, LineCount: length,
						FilePath: filePath, StartLine: funcStart,
					})
				}
				inFunc = false
				curFuncName = ""
			}
		}

		// ── Type-length tracking (brace depth) ──
		if inType {
			typeBraceDepth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
			if typeBraceDepth <= 0 && strings.Contains(trimmed, "}") {
				length := lineNo - typeStart + 1
				if pf.LongestType == nil || length > pf.LongestType.LineCount {
					pf.LongestType = &TypeInfo{
						Name: curTypeName, Kind: curTypeKind, LineCount: length,
						FilePath: filePath, StartLine: typeStart,
					}
				}
				inType = false
				curTypeName = ""
			}
		}

		// ── Doc comments (collected to attach to the next declaration) ──
		if c.DocComment != nil {
			if m := c.DocComment.FindStringSubmatch(trimmed); len(m) > 1 {
				docLines = append(docLines, m[1])
			} else if trimmed != "" {
				docLines = nil
			}
		}

		// ── TODO / FIXME ──
		for _, marker := range spec.Patterns.TodoMarkers {
			if strings.Contains(raw, marker) {
				pf.TodoCount++
				pf.Todos = append(pf.Todos, TodoItem{
					FilePath: filePath, Line: lineNo, Kind: "TODO",
					Text: extractTodoText(raw),
				})
				break
			}
		}
		for _, marker := range spec.Patterns.FixmeMarkers {
			if strings.Contains(raw, marker) {
				pf.FixmeCount++
				pf.Todos = append(pf.Todos, TodoItem{
					FilePath: filePath, Line: lineNo, Kind: "FIXME",
					Text: extractTodoText(raw),
				})
				break
			}
		}
	}

	return pf
}

// declNameKeyword extracts the declaration name and (optional) keyword from a
// TypeDecl match. Patterns may capture either (name) or (keyword, name) or
// (name, keyword); we accept the two common shapes:
//   - 2 groups where group1 is a keyword in DeclKindMap → (group2=name, group1=keyword)
//   - 2 groups where group1 is the name and group2 the keyword → (group1=name, group2=keyword)
//   - 1 effective group → name only, empty keyword.
func declNameKeyword(m []string) (name, keyword string) {
	switch {
	case len(m) >= 3:
		// Ambiguous; decide by which group looks like an identifier keyword.
		if looksLikeKeyword(m[1]) && !looksLikeKeyword(m[2]) {
			return m[2], m[1]
		}
		return m[1], m[2]
	case len(m) == 2:
		return m[1], ""
	default:
		return "", ""
	}
}

// looksLikeKeyword is a cheap heuristic: declaration keywords are lowercase
// words, type names usually start uppercase or contain mixed case.
func looksLikeKeyword(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			return false
		}
	}
	return true
}

// mapDeclKind converts a captured keyword to a DeclKind via the spec's map,
// defaulting to DeclType when unmapped or absent.
func mapDeclKind(spec *langspec.LanguageSpec, keyword string) DeclKind {
	if keyword != "" && spec.Patterns.DeclKindMap != nil {
		if v, ok := spec.Patterns.DeclKindMap[keyword]; ok {
			return DeclKind(v)
		}
	}
	return DeclType
}

// extractTodoText trims comment markers and whitespace from a raw line,
// returning a short readable quote of the TODO/FIXME text.
func extractTodoText(raw string) string {
	// Strip common single-line comment prefixes then whitespace.
	s := strings.TrimSpace(raw)
	for _, pfx := range []string{"//", "#", "--", "/*", "*", "<!--"} {
		if strings.HasPrefix(s, pfx) {
			s = strings.TrimSpace(s[len(pfx):])
			break
		}
	}
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}
