package lang

import (
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules/traffic"
	"github.com/exey/archscope/internal/parser"
)

// C support. C and C++ share the PlatformC report tab (like Swift+ObjC share
// PlatformSwiftObjC). ".c" is exclusively C's; ".h" is shared with C++ and
// ObjC (see cpp.go, objc.go) — C registers it with NO Sniff predicate, which
// makes C the default/fallback language for a header that shows no C++ or
// ObjC signal, since a plain C-style header is the most common "nothing else
// matched" case.
func init() {
	langspec.Default.Register(langspec.LanguageSpec{
		ID:          "c",
		DisplayName: "C",
		Platform:    langspec.PlatformC,
		Extensions:  []string{"c", "h"},
		ModuleIcon:  "🔩",
		ModuleLabel: "Libraries & Modules",

		VersionProbes: []langspec.VersionProbe{
			{File: "CMakeLists.txt", Pattern: `CMAKE_C_STANDARD\s+(\d+)`},
		},
		ProjectTypes: []langspec.ProjectType{
			{Name: "CMake", MarkerFiles: []string{"CMakeLists.txt"}},
			{Name: "Make", MarkerFiles: []string{"Makefile", "makefile"}},
			{Name: "Autotools", MarkerFiles: []string{"configure.ac", "configure.in"}},
			{Name: "Meson", MarkerFiles: []string{"meson.build"}},
		},
		Modules: langspec.ModuleDetection{
			MarkerFiles:   []string{"CMakeLists.txt", "Makefile", "meson.build"},
			ContainerDirs: []string{"src", "lib", "include"},
		},

		Patterns: langspec.ParsePatterns{
			// #include <foo.h> | #include "foo.h"
			ImportSingle: `^#\s*include\s+[<"]([^>"]+)[>"]`,
			// struct Foo | enum Bar | union Baz | typedef struct Foo
			TypeDecl: `^(?:typedef\s+)?(struct|enum|union)\s+(\w+)`,
			// returnType [qualifiers] name(args) [{] — the optional prefix
			// excludes '#' so preprocessor macro bodies like
			// "#define MAX(a,b) ((a)>(b)?(a):(b))" never look like a
			// function signature, and the pattern requires the line to end
			// at ')' (plus optional '{' or trailing "// comment") so a
			// ';'-terminated prototype never falsely opens a function span.
			FuncDecl:      `^(?:[^#]*[\s*])?([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{?\s*(?://.*)?$`,
			DocComment:    `^(?:///|\*)\s?(.*)`,
			CommentPrefix: `//`,
			TodoMarkers:   []string{"// TODO", "//TODO"},
			FixmeMarkers:  []string{"// FIXME", "//FIXME"},
			DeclKindMap: map[string]string{
				"struct": string(parser.DeclStruct),
				"enum":   string(parser.DeclEnum),
				"union":  string(parser.DeclStruct),
			},
		},

		ParseHook: cParseHook,
		SecurityRuleIDs: []string{
			"c.gets_call", "c.unsafe_string_copy", "c.format_string",
			"c.command_injection", "c.hardcoded_credential", "c.weak_random",
			"c.insecure_temp_file",
		},
	})
}

func cParseHook(filePath string, lines []string, pfAny any) {
	pf, ok := pfAny.(*parser.ParsedFile)
	if !ok {
		return
	}
	in, out := traffic.ExtractCTraffic(filePath, lines)
	if len(in) > 0 || len(out) > 0 {
		if pf.Extra == nil {
			pf.Extra = map[string]any{}
		}
		if len(in) > 0 {
			pf.Extra["trafficInbound"] = in
		}
		if len(out) > 0 {
			pf.Extra["trafficOutbound"] = out
		}
	}
}
