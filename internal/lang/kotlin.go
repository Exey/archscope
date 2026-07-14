package lang

import (
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules/traffic"
	"github.com/exey/archscope/internal/parser"
)

// Kotlin support — a client/UI language (Android, KMP). Registered as a
// self-contained spec; because Client is true, the architecture module shows
// app-architecture pattern detection (MVC/MVVM/…) for Kotlin, exactly as it
// does for Swift and TypeScript.
func init() {
	langspec.Default.Register(langspec.LanguageSpec{
		ID:          "kotlin",
		DisplayName: "Kotlin",
		Platform:    langspec.PlatformKotlin,
		Extensions:  []string{"kt", "kts"},
		Client:      true,
		ModuleIcon:  "📦",
		ModuleLabel: "Packages & Modules",

		VersionProbes: []langspec.VersionProbe{
			{File: "build.gradle.kts", Pattern: `kotlin\("[^"]+"\)\s+version\s+"([\d.]+)"`},
		},
		ProjectTypes: []langspec.ProjectType{
			{Name: "Gradle", MarkerFiles: []string{"build.gradle.kts", "build.gradle", "settings.gradle.kts"}},
		},
		Modules: langspec.ModuleDetection{
			MarkerFiles:   []string{"build.gradle.kts", "build.gradle"},
			ContainerDirs: []string{"src", "modules"},
		},

		Patterns: langspec.ParsePatterns{
			ImportSingle: `^import\s+([\w.]+)`,
			TypeDecl: `^(?:public\s+|private\s+|internal\s+|open\s+|final\s+|abstract\s+|sealed\s+|data\s+)*` +
				`(class|interface|object|enum class)\s+(\w+)`,
			FuncDecl:      `^\s*(?:@\w+\s+)*(?:public\s+|private\s+|internal\s+|override\s+|suspend\s+)*fun\s+(\w+)\s*[(<]`,
			DocComment:    `^///\s?(.*)`,
			CommentPrefix: `//`,
			TodoMarkers:   []string{"// TODO", "//TODO"},
			FixmeMarkers:  []string{"// FIXME", "//FIXME"},
			DeclKindMap: map[string]string{
				"class":      string(parser.DeclClass),
				"interface":  string(parser.DeclInterface),
				"object":     string(parser.DeclClass),
				"enum class": string(parser.DeclEnum),
			},
		},

		ParseHook: kotlinParseHook,
	})
}

// kotlinParseHook runs traffic detection (Ktor/Spring routes, Retrofit calls,
// URL literals) and stores results in Extra["trafficInbound"]/["trafficOutbound"].
func kotlinParseHook(filePath string, lines []string, pfAny any) {
	pf, ok := pfAny.(*parser.ParsedFile)
	if !ok {
		return
	}
	in, out := traffic.ExtractKotlinTraffic(filePath, lines)
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
