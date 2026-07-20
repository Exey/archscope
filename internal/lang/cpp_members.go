package lang

import (
	"regexp"

	"github.com/exey/archscope/internal/parser"
)

var (
	cppTypeDecl = regexp.MustCompile(`^(?:template\s*<[^>]*>\s*)?(?:class|struct)\s+(\w+)`)
	// A field line has no parens (that would make it a method signature) and
	// ends in "name;" or "name = default;" after a type prefix.
	cppFieldDecl = regexp.MustCompile(`^(?:[A-Za-z_][\w:<>,\s\*&]*[\s\*&])(\w+)\s*(?:=\s*[^;]*)?;$`)
	// Optional return-type prefix (no parens) then the method name right
	// before "(" — the empty-prefix case also matches constructors/destructors.
	cppMethodName = regexp.MustCompile(
		`^(?:virtual\s+|static\s+|inline\s+|explicit\s+|friend\s+|constexpr\s+)*(?:[\w:<>,\*&~]+[\s\*&])?(~?\w+)\s*`)
)

var cppBuiltinTypes = map[string]bool{
	"int": true, "char": true, "float": true, "double": true, "bool": true, "void": true,
	"long": true, "short": true, "unsigned": true, "signed": true, "auto": true, "wchar_t": true,
	"size_t": true, "int8_t": true, "int16_t": true, "int32_t": true, "int64_t": true,
	"uint8_t": true, "uint16_t": true, "uint32_t": true, "uint64_t": true,
}

var cppKeywords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "catch": true, "return": true,
	"sizeof": true, "new": true, "delete": true, "throw": true, "using": true, "namespace": true,
	"template": true, "class": true, "struct": true, "public": true, "private": true,
	"protected": true, "else": true, "do": true, "try": true, "typedef": true,
}

// extractCppMembers is C++'s regex/brace-depth member extractor — the same
// heuristic and accuracy caveats as extractSwiftMembers/
// extractTypeScriptMembers (see members_common.go and golang_members.go's
// doc comments). Constructors/destructors are picked up naturally since the
// return-type prefix in cppMethodName is optional.
func extractCppMembers(lines []string) []parser.TypeMembers {
	return extractBraceMembers(lines, braceMembersConfig{
		typeDecl:   cppTypeDecl,
		fieldDecl:  cppFieldDecl,
		methodName: cppMethodName,
		keywords:   cppKeywords,
		builtins:   cppBuiltinTypes,
	})
}
