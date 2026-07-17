package lang

import (
	"regexp"

	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/parser"
)

// Objective-C support. ObjC shares the Apple platform tab with Swift
// (PlatformSwiftObjC) and inherits every universal security rule
// automatically.
//
// ".h" is also claimed by C and C++ (internal/lang/c.go, cpp.go), so ObjC
// registers it with a Sniff predicate rather than exclusive ownership: a
// header is classified as ObjC when it contains an unmistakable ObjC/Cocoa
// signal (@interface/@implementation/@protocol/#import/NS-prefixed types),
// and falls back to the C/C++ Sniff chain otherwise. See langspec.Registry's
// shared-extension resolution.
var reObjCHeaderSignal = regexp.MustCompile(
	`@(interface|implementation|protocol|property|end)\b|^\s*#import\b|\bNS[A-Z]\w*\b|\bUI[A-Z]\w*\b`,
)

func objcSniff(peekLines []string) bool {
	for _, l := range peekLines {
		if reObjCHeaderSignal.MatchString(l) {
			return true
		}
	}
	return false
}

func init() {
	langspec.Default.Register(langspec.LanguageSpec{
		ID:          "objc",
		DisplayName: "Objective-C",
		Platform:    langspec.PlatformSwiftObjC,
		Extensions:  []string{"m", "mm", "h"},
		Client:      true,
		Sniff:       objcSniff,
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
