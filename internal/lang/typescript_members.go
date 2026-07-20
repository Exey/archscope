package lang

import (
	"regexp"

	"github.com/exey/archscope/internal/parser"
)

var (
	tsTypeDecl = regexp.MustCompile(
		`^(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+(\w+)`)
	tsFieldDecl = regexp.MustCompile(
		`^(?:public\s+|private\s+|protected\s+|readonly\s+|static\s+)*(\w+)\??\s*:\s*`)
	tsMethodName = regexp.MustCompile(
		`^(?:public\s+|private\s+|protected\s+|static\s+|async\s+|abstract\s+)*(?:get\s+|set\s+)?(\w+)\s*(?:<[^>]*>)?\s*`)
)

var tsBuiltinTypes = map[string]bool{
	"string": true, "number": true, "boolean": true, "any": true, "unknown": true, "never": true,
	"void": true, "object": true, "undefined": true, "null": true, "symbol": true, "bigint": true,
	"Array": true, "Promise": true, "Map": true, "Set": true, "Date": true, "Error": true,
	"RegExp": true, "Object": true, "Function": true, "Record": true, "Partial": true, "Pick": true,
	"Omit": true, "Readonly": true, "Number": true, "String": true, "Boolean": true,
}

var tsKeywords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "catch": true, "return": true,
	"function": true, "new": true, "typeof": true, "in": true, "of": true, "do": true, "else": true,
	"try": true, "finally": true, "throw": true, "yield": true, "await": true, "delete": true,
	"void": true, "instanceof": true,
}

// extractTypeScriptMembers is the TS/JS counterpart of extractSwiftMembers —
// same shared regex + brace-depth heuristic (members_common.go), same
// accuracy caveats (no AST for this language yet).
func extractTypeScriptMembers(lines []string) []parser.TypeMembers {
	return extractBraceMembers(lines, braceMembersConfig{
		typeDecl:   tsTypeDecl,
		fieldDecl:  tsFieldDecl,
		methodName: tsMethodName,
		keywords:   tsKeywords,
		builtins:   tsBuiltinTypes,
	})
}
