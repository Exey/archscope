package lang

import (
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules/traffic"
	"github.com/exey/archscope/internal/parser"
)

func init() {
	langspec.Default.Register(langspec.LanguageSpec{
		ID:          "go",
		DisplayName: "Go",
		Platform:    langspec.PlatformGo,
		Extensions:  []string{"go"},
		ModuleIcon:  "🔧",
		ModuleLabel: "Microservices",

		VersionProbes: []langspec.VersionProbe{
			{File: "go.mod", Pattern: `^go\s+([\d.]+)`},
		},
		ProjectTypes: []langspec.ProjectType{
			{Name: "Go module", MarkerFiles: []string{"go.mod"}},
		},
		Modules: langspec.ModuleDetection{
			MarkerFiles:   []string{"go.mod"},
			ContainerDirs: []string{"cmd", "internal", "pkg", "services"},
		},

		Patterns: langspec.ParsePatterns{
			// import "fmt"
			ImportSingle: `^import\s+"([^"]+)"`,
			// import ( ... )
			ImportBlockBeg: `^import\s*\(`,
			ImportBlockEnd: `^\)`,
			// a line inside the block: optional alias then "path"
			ImportInBlock: `^(?:[\w.]+\s+)?"([^"]+)"`,
			// type Foo struct | type Bar interface
			TypeDecl: `^type\s+(\w+)\s+(struct|interface)\b`,
			// func Name( | func (r *T) Name(
			FuncDecl: `^func\s+(?:\([^)]*\)\s+)?(\w+)\s*[(\[]`,
			// Go doc comments are // immediately preceding a decl.
			DocComment:    `^//\s?(.*)`,
			CommentPrefix: `//`,
			TodoMarkers:   []string{"// TODO", "//TODO"},
			FixmeMarkers:  []string{"// FIXME", "//FIXME"},
			DeclKindMap: map[string]string{
				"struct":    string(parser.DeclStruct),
				"interface": string(parser.DeclInterface),
			},
		},

		// Optional hook: record the package name into Extra and prefer it as the
		// module name when the scanner did not assign one.
		ParseHook: goParseHook,
		// No language-only security rules yet; universal rules still apply.
		// No language-specific report modules.
	})
}

// goParseHook scans the (already-loaded) lines for the `package` clause and
// stores it in Extra["packageName"]; if the file has no module name yet, it
// uses the package name. It also runs traffic detection and stores results in
// Extra["trafficInbound"] and Extra["trafficOutbound"].
func goParseHook(filePath string, lines []string, pfAny any) {
	pf, ok := pfAny.(*parser.ParsedFile)
	if !ok {
		return
	}
	for _, raw := range lines {
		t := trimSpace(raw)
		if len(t) > 8 && t[:8] == "package " {
			name := trimSpace(t[8:])
			if name != "" {
				if pf.Extra == nil {
					pf.Extra = map[string]any{}
				}
				pf.Extra["packageName"] = name
				if pf.ModuleName == "" {
					pf.ModuleName = name
				}
			}
			break
		}
	}

	in, out := traffic.ExtractGoTraffic(filePath, lines, pf.Imports)
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

	// Coupling/cohesion metrics (CBO/LCOM/CAM) need real field/method/call
	// data; Go is the only language that can get it cheaply today (stdlib
	// go/ast, no new dependency) — see extractGoMembers' doc comment for
	// the longer-term multi-language plan.
	if members := extractGoMembers(filePath, lines); len(members) > 0 {
		if pf.Extra == nil {
			pf.Extra = map[string]any{}
		}
		pf.Extra["members"] = members
	}
}

// trimSpace is a tiny local helper to avoid importing strings in this file just
// for one call (keeps language files lean and uniform).
func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\r') {
		j--
	}
	return s[i:j]
}
