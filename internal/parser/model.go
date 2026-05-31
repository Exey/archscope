// Package parser defines the universal source model and the language-agnostic
// line scanner. Everything language-specific is supplied by a langspec.
package parser

import (
	"path/filepath"
	"strings"
)

// DeclKind is the normalized kind of a declaration, unioned across languages.
type DeclKind string

const (
	DeclStruct    DeclKind = "struct"
	DeclClass     DeclKind = "class"
	DeclInterface DeclKind = "interface" // protocol (Swift) / interface (TS, Go, Kotlin)
	DeclEnum      DeclKind = "enum"
	DeclActor     DeclKind = "actor"
	DeclExtension DeclKind = "extension"
	DeclFunc      DeclKind = "func"
	DeclType      DeclKind = "type"
	DeclConst     DeclKind = "const"
	DeclVar       DeclKind = "var"
	// proto / IDL
	DeclMessage DeclKind = "message"
	DeclService DeclKind = "service"
	DeclRPC     DeclKind = "rpc"
)

// Declaration is one named declaration found in a source file.
type Declaration struct {
	Name string   `json:"name"`
	Kind DeclKind `json:"kind"`
	Line int      `json:"line"`
}

// FunctionInfo records the size/location of a function.
type FunctionInfo struct {
	Name      string `json:"name"`
	LineCount int    `json:"lineCount"`
	FilePath  string `json:"filePath"`
	StartLine int    `json:"startLine"`
}

// GitMetadata holds per-file git history (filled later by the git analyzer).
type GitMetadata struct {
	LastModified    float64  `json:"lastModified"`
	ChangeFrequency int      `json:"changeFrequency"`
	TopAuthors      []string `json:"topAuthors"`
	RecentMessages  []string `json:"recentMessages"`
	FirstCommitDate float64  `json:"firstCommitDate"`
}

// ParsedFile is the universal product of parsing any source file.
type ParsedFile struct {
	FilePath     string         `json:"filePath"`
	LanguageID   string         `json:"languageId"`  // which LanguageSpec owns it
	Platform     string         `json:"platform"`    // report-tab bucket
	ModuleName   string         `json:"moduleName"`  // package / module / microservice
	ProjectType  string         `json:"projectType"` // "SwiftPM", "Go module", ...
	Imports      []string       `json:"imports"`
	Declarations []Declaration  `json:"declarations"`
	Description  string         `json:"description"` // leading doc comment
	LineCount    int            `json:"lineCount"`
	TodoCount    int            `json:"todoCount"`
	FixmeCount   int            `json:"fixmeCount"`
	LongestFunc  *FunctionInfo  `json:"longestFunction,omitempty"`
	BigFunctions []FunctionInfo `json:"bigFunctions,omitempty"`
	GitMeta      GitMetadata    `json:"gitMetadata"`
	// Extra is a free-form bag for language hooks (e.g. Swift sceneGroup) so the
	// core model stays stable while hooks add language-specific data.
	Extra map[string]any `json:"extra,omitempty"`
}

// FileName returns the base name of the file.
func (p *ParsedFile) FileName() string {
	return filepath.Base(p.FilePath)
}

// FileNameWithoutExt returns the base name without its extension.
func (p *ParsedFile) FileNameWithoutExt() string {
	name := p.FileName()
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[:i]
	}
	return name
}

// CountKind returns how many declarations of a given kind the file has.
func (p *ParsedFile) CountKind(k DeclKind) int {
	n := 0
	for _, d := range p.Declarations {
		if d.Kind == k {
			n++
		}
	}
	return n
}
