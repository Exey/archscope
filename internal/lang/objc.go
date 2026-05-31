package lang

import (
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/parser"
)

// Objective-C support. Added purely as a self-registering spec — no engine
// changes — to demonstrate the "drop a file in internal/lang" extension model
// end to end. ObjC shares the Apple platform tab with Swift (PlatformSwiftObjC)
// and inherits every universal security rule automatically.
func init() {
	langspec.Default.Register(langspec.LanguageSpec{
		ID:          "objc",
		DisplayName: "Objective-C",
		Platform:    langspec.PlatformSwiftObjC,
		Extensions:  []string{"m", "mm", "h"},
		Client:      true,
		ModuleIcon:  "📦",
		ModuleLabel: "Packages & Modules",

		ProjectTypes: []langspec.ProjectType{
			{Name: "CocoaPods", MarkerFiles: []string{"Podfile"}},
			{Name: "Xcode", MarkerFiles: []string{"*.xcodeproj", "*.xcworkspace"}},
		},
		Modules: langspec.ModuleDetection{
			MarkerFiles:   []string{"Podfile"},
			ContainerDirs: []string{"Classes", "Sources"},
		},

		Patterns: langspec.ParsePatterns{
			// #import <Foundation/Foundation.h> | #import "Header.h"
			ImportSingle: `^#import\s+[<"]([\w./]+)[>"]`,
			// @interface Foo … | @protocol Bar … (capture keyword + name)
			TypeDecl: `^@(interface|protocol)\s+(\w+)`,
			// - (void)doThing:… | + (instancetype)shared  → first selector word
			FuncDecl:      `^[-+]\s*\([^)]*\)\s*(\w+)`,
			DocComment:    `^///\s?(.*)`,
			CommentPrefix: `//`,
			TodoMarkers:   []string{"// TODO", "//TODO"},
			FixmeMarkers:  []string{"// FIXME", "//FIXME"},
			DeclKindMap: map[string]string{
				"interface": string(parser.DeclClass),
				"protocol":  string(parser.DeclInterface),
			},
		},
	})
}
