package lang

import (
	"regexp"

	"github.com/exey/archscope/internal/parser"
)

var (
	javaTypeDecl = regexp.MustCompile(
		`^(?:(?:public|private|protected|abstract|final|static)\s+)*class\s+(\w+)`)
	javaFieldDecl = regexp.MustCompile(
		`^(?:(?:public|private|protected|static|final|transient|volatile)\s+)*[\w$.<>\[\],\s]+[\s\*](\w+)\s*(?:=\s*[^;]*)?;$`)
	// Return-type token group is optional so bare "ClassName(" constructors
	// still match via the trailing capture.
	javaMethodName = regexp.MustCompile(
		`^(?:(?:public|private|protected|static|final|abstract|synchronized|native)\s+)*(?:[\w$.<>\[\]]+\s+)*(\w+)\s*`)
)

var javaBuiltinTypes = map[string]bool{
	"int": true, "long": true, "short": true, "byte": true, "char": true, "float": true,
	"double": true, "boolean": true, "void": true,
	"String": true, "Object": true, "Integer": true, "Long": true, "Boolean": true, "Double": true,
	"Float": true, "Character": true, "Void": true, "List": true, "Map": true, "Set": true,
	"ArrayList": true, "HashMap": true, "HashSet": true, "Optional": true,
}

var javaKeywords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "catch": true, "return": true,
	"new": true, "instanceof": true, "synchronized": true, "try": true, "else": true, "do": true,
	"throw": true, "throws": true, "super": true, "this": true, "class": true, "interface": true,
}

// extractJavaMembers is Java's regex/brace-depth member extractor — same
// heuristic and accuracy caveats as extractSwiftMembers/
// extractTypeScriptMembers/extractCppMembers (see members_common.go).
func extractJavaMembers(lines []string) []parser.TypeMembers {
	return extractBraceMembers(lines, braceMembersConfig{
		typeDecl:   javaTypeDecl,
		fieldDecl:  javaFieldDecl,
		methodName: javaMethodName,
		keywords:   javaKeywords,
		builtins:   javaBuiltinTypes,
	})
}
