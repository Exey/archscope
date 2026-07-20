package lang

import (
	"regexp"

	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules/traffic"
	"github.com/exey/archscope/internal/parser"
)

// C++ support, sharing the PlatformC report tab with C. ".cpp"/".cc"/".cxx"/
// ".hpp"/".hh"/".hxx" are exclusively C++'s; ".h" is shared with C and ObjC
// (see c.go, objc.go) via a Sniff predicate — a header is classified as C++
// when it shows an unmistakable C++-only signal (class/namespace/template/
// std::/access specifiers/extern "C++"), otherwise it falls through to
// ObjC's Sniff and finally to C's default.
var reCppHeaderSignal = regexp.MustCompile(
	`\bclass\s+\w|\bnamespace\s+\w|\btemplate\s*<|\bstd::|` +
		`\bpublic\s*:|\bprivate\s*:|\bprotected\s*:|extern\s+"C\+\+"|\busing\s+namespace\b`,
)

func cppSniff(peekLines []string) bool {
	for _, l := range peekLines {
		if reCppHeaderSignal.MatchString(l) {
			return true
		}
	}
	return false
}

func init() {
	langspec.Default.Register(langspec.LanguageSpec{
		ID:          "cpp",
		DisplayName: "C++",
		Platform:    langspec.PlatformC,
		Extensions:  []string{"cpp", "cc", "cxx", "c++", "hpp", "hh", "hxx", "h++", "h"},
		ModuleIcon:  "🔩",
		ModuleLabel: "Libraries & Modules",
		Sniff:       cppSniff,

		VersionProbes: []langspec.VersionProbe{
			{File: "CMakeLists.txt", Pattern: `CMAKE_CXX_STANDARD\s+(\d+)`},
		},
		ProjectTypes: []langspec.ProjectType{
			{Name: "CMake", MarkerFiles: []string{"CMakeLists.txt"}},
			{Name: "Make", MarkerFiles: []string{"Makefile", "makefile"}},
			{Name: "Meson", MarkerFiles: []string{"meson.build"}},
			{Name: "Conan", MarkerFiles: []string{"conanfile.txt", "conanfile.py"}},
			{Name: "vcpkg", MarkerFiles: []string{"vcpkg.json"}},
		},
		Modules: langspec.ModuleDetection{
			MarkerFiles:   []string{"CMakeLists.txt", "Makefile", "meson.build"},
			ContainerDirs: []string{"src", "lib", "include"},
		},

		Patterns: langspec.ParsePatterns{
			// #include <vector> | #include "foo.hpp"
			ImportSingle: `^#\s*include\s+[<"]([^>"]+)[>"]`,
			// class Foo | struct Foo | enum class Foo | namespace foo |
			// template<...> class Foo (the template<...> prefix is consumed
			// by the optional leading group).
			TypeDecl: `^(?:template\s*<[^>]*>\s*)?(class|struct|namespace|union|enum)(?:\s+class)?\s+(\w+)`,
			// returnType [qualifiers] [Class::]name(args) [const] [override]
			// [noexcept] [{] — same '#'-exclusion and ';'-exclusion as C's
			// FuncDecl, plus ':'/'&' as valid separators so qualified member
			// definitions ("Foo::Bar(...)") and reference returns match.
			FuncDecl: `^(?:[^#]*[\s*&:])?([A-Za-z_~]\w*)\s*\([^;{}]*\)\s*` +
				`(?:const\s*)?(?:override\s*)?(?:noexcept\b[^;{}]*)?\{?\s*(?://.*)?$`,
			DocComment:    `^(?:///|\*)\s?(.*)`,
			CommentPrefix: `//`,
			TodoMarkers:   []string{"// TODO", "//TODO"},
			FixmeMarkers:  []string{"// FIXME", "//FIXME"},
			DeclKindMap: map[string]string{
				"class":     string(parser.DeclClass),
				"struct":    string(parser.DeclStruct),
				"enum":      string(parser.DeclEnum),
				"union":     string(parser.DeclStruct),
				"namespace": string(parser.DeclType),
			},
		},

		ParseHook: cppParseHook,
		SecurityRuleIDs: []string{
			"cpp.unsafe_string_copy", "cpp.format_string", "cpp.command_injection",
			"cpp.hardcoded_credential", "cpp.weak_random", "cpp.reinterpret_cast",
			"cpp.raw_new_delete",
		},
	})
}

func cppParseHook(filePath string, lines []string, pfAny any) {
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

	if members := extractCppMembers(lines); len(members) > 0 {
		if pf.Extra == nil {
			pf.Extra = map[string]any{}
		}
		pf.Extra["members"] = members
	}
}
