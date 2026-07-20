package lang

import (
	"regexp"

	"github.com/exey/archscope/internal/parser"
)

var (
	swiftTypeDecl = regexp.MustCompile(
		`^(?:public\s+|private\s+|internal\s+|fileprivate\s+|final\s+|open\s+)*(?:class|struct|actor)\s+(\w+)`)
	swiftFieldDecl = regexp.MustCompile(
		`^(?:public\s+|private\s+|internal\s+|fileprivate\s+|static\s+|lazy\s+|weak\s+|@\w+\s+)*(?:var|let)\s+(\w+)\b`)
	swiftMethodName = regexp.MustCompile(
		`^(?:@\w+\s+)*(?:public\s+|private\s+|internal\s+|fileprivate\s+|static\s+|final\s+|mutating\s+|override\s+)*func\s+(\w+)\s*(?:<[^>]*>)?\s*`)
)

var swiftBuiltinTypes = map[string]bool{
	"String": true, "Int": true, "Int8": true, "Int16": true, "Int32": true, "Int64": true,
	"UInt": true, "UInt8": true, "UInt16": true, "UInt32": true, "UInt64": true,
	"Double": true, "Float": true, "Bool": true, "Character": true, "Any": true, "AnyObject": true,
	"Void": true, "Self": true,
}

var swiftKeywords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "catch": true, "guard": true, "repeat": true,
}

// extractSwiftMembers is a Go-adjacent, phase-1 coupling/cohesion data
// source for Swift: unlike extractGoMembers it has no AST to lean on (Swift
// has no stdlib parser), so it reuses the same regex + brace-depth approach
// internal/parser/universal.go already uses for BigFunctions/LongestType via
// the shared extractBraceMembers helper (members_common.go). See that file's
// doc comment for the accuracy caveats.
func extractSwiftMembers(lines []string) []parser.TypeMembers {
	return extractBraceMembers(lines, braceMembersConfig{
		typeDecl:   swiftTypeDecl,
		fieldDecl:  swiftFieldDecl,
		methodName: swiftMethodName,
		keywords:   swiftKeywords,
		builtins:   swiftBuiltinTypes,
	})
}
