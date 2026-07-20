package lang

import (
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules/traffic"
	"github.com/exey/archscope/internal/parser"
)

func init() {
	langspec.Default.Register(langspec.LanguageSpec{
		ID:          "python",
		DisplayName: "Python",
		Platform:    langspec.PlatformPython,
		Extensions:  []string{"py"},
		ModuleIcon:  "📦",
		ModuleLabel: "Packages",

		VersionProbes: []langspec.VersionProbe{
			{File: "pyproject.toml", Pattern: `requires-python\s*=\s*"[^\d]*([\d.]+)"`},
			{File: ".python-version", Pattern: `([\d.]+)`},
		},
		ProjectTypes: []langspec.ProjectType{
			{Name: "Poetry/PEP-621", MarkerFiles: []string{"pyproject.toml"}},
			{Name: "setuptools", MarkerFiles: []string{"setup.py", "setup.cfg"}},
			{Name: "pip", MarkerFiles: []string{"requirements.txt"}},
		},
		Modules: langspec.ModuleDetection{
			MarkerFiles:   []string{"pyproject.toml", "setup.py", "requirements.txt"},
			ContainerDirs: []string{"src", "services", "apps"},
		},

		Patterns: langspec.ParsePatterns{
			// import os | from x import y  (module captured for plain import)
			ImportSingle: `^import\s+([\w.]+)`,
			// class Foo: | class Foo(Base):
			TypeDecl: `^class\s+(\w+)\s*[:\(]`,
			// def name( | async def name(
			FuncDecl:      `^\s*(?:async\s+)?def\s+(\w+)\s*\(`,
			DocComment:    `^#\s?(.*)`,
			CommentPrefix: `#`,
			TodoMarkers:   []string{"# TODO", "#TODO", "# todo"},
			FixmeMarkers:  []string{"# FIXME", "#FIXME"},
			DeclKindMap:   map[string]string{
				// class is the only keyword captured; default kind handles it
			},
			// Python type decls only capture a name; force class kind via hook.
		},

		ParseHook: pythonParseHook,
	})
}

// pythonParseHook marks declarations captured by the class regex as DeclClass
// (the universal scanner defaults unmapped type decls to DeclType). It also
// runs traffic detection and stores results in pf.Extra.
func pythonParseHook(filePath string, lines []string, pfAny any) {
	pf, ok := pfAny.(*parser.ParsedFile)
	if !ok {
		return
	}
	for i := range pf.Declarations {
		if pf.Declarations[i].Kind == parser.DeclType {
			pf.Declarations[i].Kind = parser.DeclClass
		}
	}

	in, out := traffic.ExtractPythonTraffic(filePath, lines)
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

	if members := extractPythonMembers(lines); len(members) > 0 {
		if pf.Extra == nil {
			pf.Extra = map[string]any{}
		}
		pf.Extra["members"] = members
	}
}
