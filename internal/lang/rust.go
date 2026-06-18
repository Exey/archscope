package lang

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/parser"
)

func init() {
	langspec.Default.Register(langspec.LanguageSpec{
		ID:          "rust",
		DisplayName: "Rust",
		Platform:    langspec.PlatformRust,
		Extensions:  []string{"rs"},
		ModuleIcon:  "📦",
		ModuleLabel: "Crates & Modules",

		VersionProbes: []langspec.VersionProbe{
			{File: "rust-toolchain.toml", Pattern: `channel\s*=\s*"([^"]+)"`},
			{File: "rust-toolchain", Pattern: `^([\w.-]+)`},
		},
		ProjectTypes: []langspec.ProjectType{
			{Name: "Cargo", MarkerFiles: []string{"Cargo.toml"}},
		},
		Modules: langspec.ModuleDetection{
			MarkerFiles:   []string{"Cargo.toml"},
			ContainerDirs: []string{"src", "crates", "libs"},
		},

		Patterns: langspec.ParsePatterns{
			// use std::collections::HashMap;  |  use crate::models::User;
			// extern crate serde;
			ImportSingle: `^(?:use|extern crate)\s+([\w:]+)`,

			// struct Foo | enum Bar | trait Baz | union Qux
			TypeDecl: `^(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(struct|enum|trait|union|type)\s+(\w+)`,
			// fn name(  | pub fn name(  | async fn name(  | pub async fn name(
			FuncDecl: `^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)\s*[(<]`,

			DocComment:    `^///\s?(.*)`,
			CommentPrefix: `//`,
			TodoMarkers:   []string{"// TODO", "//TODO", "// todo!"},
			FixmeMarkers:  []string{"// FIXME", "//FIXME"},
			DeclKindMap: map[string]string{
				"struct": string(parser.DeclStruct),
				"enum":   string(parser.DeclEnum),
				"trait":  string(parser.DeclInterface),
				"union":  string(parser.DeclStruct),
				"type":   string(parser.DeclType),
			},
		},

		ParseHook:       rustParseHook,
		SecurityRuleIDs: []string{"rust.unsafe_block", "rust.transmute", "rust.hardcoded_credential"},
	})
}

// rustParseHook extracts the crate name from Cargo.toml (walking up from the
// file path) and records it as the module name when the scanner has not already
// assigned one. It also normalises `use` paths to their top-level crate name
// so the tech-stack import map can match them.
func rustParseHook(filePath string, lines []string, pfAny any) {
	pf, ok := pfAny.(*parser.ParsedFile)
	if !ok {
		return
	}

	// Derive crate name from Cargo.toml if present.
	if pf.ModuleName == "" {
		if name := rustCrateName(filepath.Dir(filePath)); name != "" {
			pf.ModuleName = name
		}
	}

	// Normalise imports: "tokio::runtime::Runtime" → "tokio",
	// "std::collections::HashMap" → "std", keeping only the first path segment.
	// The parser captures the full use path; we shorten for the tech-stack map.
	for i, imp := range pf.Imports {
		if idx := strings.Index(imp, "::"); idx >= 0 {
			pf.Imports[i] = imp[:idx]
		}
	}
}

// rustCrateName walks up from dir looking for a Cargo.toml with a [package]
// name field, returning the crate name or "".
func rustCrateName(dir string) string {
	for depth := 0; depth < 5; depth++ {
		cargo := filepath.Join(dir, "Cargo.toml")
		raw, err := os.ReadFile(cargo)
		content := string(raw)
		if err == nil && content != "" {
			for _, line := range strings.Split(content, "\n") {
				t := strings.TrimSpace(line)
				if strings.HasPrefix(t, "name") {
					parts := strings.SplitN(t, "=", 2)
					if len(parts) == 2 {
						name := strings.Trim(strings.TrimSpace(parts[1]), `"`)
						if name != "" {
							return name
						}
					}
				}
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}
