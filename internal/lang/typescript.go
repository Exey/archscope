package lang

import (
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules/traffic"
	"github.com/exey/archscope/internal/parser"
)

func init() {
	langspec.Default.Register(langspec.LanguageSpec{
		ID:          "ts",
		DisplayName: "TypeScript / JavaScript",
		Platform:    langspec.PlatformTSJS,
		// One spec owns the whole TS+JS platform bucket.
		Extensions:  []string{"ts", "tsx", "js", "jsx", "mjs", "cjs"},
		Client:      true,
		ModuleIcon:  "📦",
		ModuleLabel: "Packages",

		VersionProbes: []langspec.VersionProbe{
			{File: "package.json", Pattern: `"version"\s*:\s*"([^"]+)"`},
		},
		ProjectTypes: []langspec.ProjectType{
			{Name: "Node", MarkerFiles: []string{"package.json"}},
			{Name: "Deno", MarkerFiles: []string{"deno.json", "deno.jsonc"}},
		},
		Modules: langspec.ModuleDetection{
			MarkerFiles:   []string{"package.json"},
			ContainerDirs: []string{"packages", "apps", "services", "src"},
		},

		Patterns: langspec.ParsePatterns{
			// import x from "y" | import { a } from "y"
			ImportSingle: `^import\s+.*\s+from\s+["']([^"']+)["']`,
			// class Foo | interface Bar | enum Baz | type Qux
			TypeDecl: `^(?:export\s+)?(?:default\s+)?(?:abstract\s+)?` +
				`(class|interface|enum|type)\s+(\w+)`,
			// function name( | export function name( | async function name(
			FuncDecl:      `^(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+(\w+)\s*[(<]`,
			DocComment:    `^//\s?(.*)`,
			CommentPrefix: `//`,
			TodoMarkers:   []string{"// TODO", "//TODO"},
			FixmeMarkers:  []string{"// FIXME", "//FIXME"},
			DeclKindMap: map[string]string{
				"class":     string(parser.DeclClass),
				"interface": string(parser.DeclInterface),
				"enum":      string(parser.DeclEnum),
				"type":      string(parser.DeclType),
			},
		},

		ParseHook: tsParseHook,
	})
}

// tsParseHook runs traffic detection (Express/Fastify routes, URL literals)
// and stores results in Extra["trafficInbound"]/["trafficOutbound"].
func tsParseHook(filePath string, lines []string, pfAny any) {
	pf, ok := pfAny.(*parser.ParsedFile)
	if !ok {
		return
	}
	in, out := traffic.ExtractTypeScriptTraffic(filePath, lines)
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
