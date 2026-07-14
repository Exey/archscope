package lang

import (
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/modules/traffic"
	"github.com/exey/archscope/internal/parser"
)

func init() {
	langspec.Default.Register(langspec.LanguageSpec{
		ID:          "swift",
		DisplayName: "Swift",
		Platform:    langspec.PlatformSwiftObjC,
		Extensions:  []string{"swift"},
		Client:      true,
		ModuleIcon:  "📦",
		ModuleLabel: "Packages & Modules",

		VersionProbes: []langspec.VersionProbe{
			{File: "Package.swift", Pattern: `swift-tools-version:\s*([\d.]+)`},
			{File: ".swift-version", Pattern: `([\d.]+)`},
		},
		ProjectTypes: []langspec.ProjectType{
			{Name: "SwiftPM", MarkerFiles: []string{"Package.swift"}},
			{Name: "Tuist", MarkerFiles: []string{"Project.swift", "Workspace.swift"}},
			{Name: "Xcode", MarkerFiles: []string{"*.xcodeproj", "*.xcworkspace"}},
		},
		Modules: langspec.ModuleDetection{
			MarkerFiles:   []string{"Package.swift"},
			ContainerDirs: []string{"Sources", "Modules"},
		},

		Patterns: langspec.ParsePatterns{
			ImportSingle: `^import\s+(\w+)`,
			TypeDecl: `^(?:public\s+|private\s+|internal\s+|fileprivate\s+|final\s+|open\s+)*` +
				`(class|struct|enum|protocol|actor|extension)\s+(\w+)`,
			FuncDecl: `^\s*(?:@\w+\s+)*(?:public\s+|private\s+|internal\s+|fileprivate\s+|static\s+|final\s+)*` +
				`func\s+(\w+)\s*[(<]`,
			DocComment:    `^///\s?(.*)`,
			CommentPrefix: `//`,
			TodoMarkers:   []string{"// TODO", "//TODO"},
			FixmeMarkers:  []string{"// FIXME", "//FIXME"},
			DeclKindMap: map[string]string{
				"class":     string(parser.DeclClass),
				"struct":    string(parser.DeclStruct),
				"enum":      string(parser.DeclEnum),
				"protocol":  string(parser.DeclInterface),
				"actor":     string(parser.DeclActor),
				"extension": string(parser.DeclExtension),
			},
		},

		ParseHook: swiftParseHook,
		// Swift-only security rules (registered in swift_security.go) and the
		// Swift-only OOP-vs-POP report module (internal/modules/oopvspop).
		SecurityRuleIDs: []string{
			"swift.force_unwrap", "swift.fatal_error",
			"swift.weak_crypto", "swift.insecure_transport",
		},
		ReportModuleIDs: []string{"oopvspop"},
	})
}

// swiftParseHook records the "scene group" (…/Scenes/<X>/…) into Extra, matching
// ArchSwiftScope's sceneGroup heuristic, and tallies cheap OOP-vs-POP signals
// (final classes, singletons, associatedtype, `some`, generics, overrides,
// NSObject) so the Swift-only OOP-vs-POP module can render an ArchSwiftScope-
// style metrics table without re-reading files.
func swiftParseHook(filePath string, lines []string, pfAny any) {
	pf, ok := pfAny.(*parser.ParsedFile)
	if !ok {
		return
	}
	if pf.Extra == nil {
		pf.Extra = map[string]any{}
	}
	parts := strings.Split(filepath_ToSlash(filePath), "/")
	for i, p := range parts {
		if p == "Scenes" && i+1 < len(parts) {
			pf.Extra["sceneGroup"] = parts[i+1]
			break
		}
	}

	var finalC, singletons, assoc, someUse, generics, overrides, nsobject int
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "//") {
			continue
		}
		if strings.Contains(t, "final class") || strings.Contains(t, "final actor") {
			finalC++
		}
		if strings.Contains(t, "static let shared") || strings.Contains(t, "static var shared") ||
			strings.Contains(t, "static let instance") || strings.Contains(t, "static var instance") {
			singletons++
		}
		if strings.Contains(t, "associatedtype ") {
			assoc++
		}
		if strings.Contains(t, "-> some ") || strings.Contains(t, ": some ") {
			someUse++
		}
		if reSwiftGenericFunc.MatchString(t) {
			generics++
		}
		if strings.Contains(t, "override ") {
			overrides++
		}
		if strings.Contains(t, ": NSObject") || strings.Contains(t, "NSObject,") {
			nsobject++
		}
	}
	setIfNonZero(pf.Extra, "oopFinal", finalC)
	setIfNonZero(pf.Extra, "oopSingletons", singletons)
	setIfNonZero(pf.Extra, "oopAssoc", assoc)
	setIfNonZero(pf.Extra, "oopSome", someUse)
	setIfNonZero(pf.Extra, "oopGenerics", generics)
	setIfNonZero(pf.Extra, "oopOverride", overrides)
	setIfNonZero(pf.Extra, "oopNSObject", nsobject)

	in, out := traffic.ExtractSwiftTraffic(filePath, lines)
	if len(in) > 0 {
		pf.Extra["trafficInbound"] = in
	}
	if len(out) > 0 {
		pf.Extra["trafficOutbound"] = out
	}
}

var reSwiftGenericFunc = regexp.MustCompile(`\bfunc\s+\w+\s*<`)

func setIfNonZero(m map[string]any, key string, v int) {
	if v != 0 {
		m[key] = v
	}
}

// filepath_ToSlash avoids importing path/filepath here just for ToSlash.
func filepath_ToSlash(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}
