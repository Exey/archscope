package lang

import (
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules/traffic"
	"github.com/exey/archscope/internal/parser"
)

func init() {
	langspec.Default.Register(langspec.LanguageSpec{
		ID:          "java",
		DisplayName: "Java",
		Platform:    langspec.PlatformJava,
		Extensions:  []string{"java"},
		ModuleIcon:  "☕",
		ModuleLabel: "Packages & Services",

		VersionProbes: []langspec.VersionProbe{
			{File: "pom.xml", Pattern: `<java\.version>([\d.]+)</java\.version>`},
			{File: "build.gradle", Pattern: `sourceCompatibility\s*=\s*['"]?([\d.]+)`},
		},
		ProjectTypes: []langspec.ProjectType{
			{Name: "Maven", MarkerFiles: []string{"pom.xml"}},
			{Name: "Gradle", MarkerFiles: []string{"build.gradle", "build.gradle.kts"}},
		},
		Modules: langspec.ModuleDetection{
			MarkerFiles:   []string{"pom.xml", "build.gradle", "build.gradle.kts"},
			ContainerDirs: []string{"src", "modules", "services"},
		},

		Patterns: langspec.ParsePatterns{
			// import com.example.Foo; or import static com.example.Foo.*;
			ImportSingle: `^import(?:\s+static)?\s+([\w.]+)`,
			// public class Foo / abstract class Bar / interface Baz / enum Status
			TypeDecl: `^(?:(?:public|private|protected|abstract|final|static|sealed)\s+)*` +
				`(class|interface|enum|@interface)\s+(\w+)`,
			// Method declarations: optional modifiers + return type + name + (
			FuncDecl:      `^\s*(?:(?:public|private|protected|static|final|abstract|synchronized|native|default|override)\s+)*(?:[\w$.<>\[\]]+\s+)+(\w+)\s*\(`,
			DocComment:    `^\s*\*\s?(.*)`,
			CommentPrefix: `//`,
			TodoMarkers:   []string{"// TODO", "//TODO"},
			FixmeMarkers:  []string{"// FIXME", "//FIXME"},
			DeclKindMap: map[string]string{
				"class":      string(parser.DeclClass),
				"interface":  string(parser.DeclInterface),
				"enum":       string(parser.DeclEnum),
				"@interface": string(parser.DeclInterface),
			},
		},

		ParseHook: javaParseHook,
	})
}

func javaParseHook(filePath string, lines []string, pfAny any) {
	pf, ok := pfAny.(*parser.ParsedFile)
	if !ok {
		return
	}
	in, out := traffic.ExtractJavaTraffic(filePath, lines)
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

	if members := extractJavaMembers(lines); len(members) > 0 {
		if pf.Extra == nil {
			pf.Extra = map[string]any{}
		}
		pf.Extra["members"] = members
	}
}
