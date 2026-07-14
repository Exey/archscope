// Package langspec defines how a single language is described to the engine.
// A language is registered by a Go file under internal/lang that builds a
// LanguageSpec value and registers it in init(). The declarative fields are
// the "config"; the optional function fields are Go logic a language may need.
//
// langspec deliberately imports nothing from the rest of the engine (no parser,
// no security) so that any package can import it without creating a cycle.
package langspec

// Platform is the report-tab bucket a language belongs to (report requirement).
type Platform string

const (
	PlatformSwiftObjC Platform = "swift_objc" // Swift + ObjC tab
	PlatformKotlin    Platform = "kotlin"     // Kotlin tab
	PlatformPython    Platform = "python"     // Python tab
	PlatformTSJS      Platform = "ts_js"      // TypeScript + JavaScript tab
	PlatformGo        Platform = "go"         // Go tab
	PlatformJava      Platform = "java"       // Java tab
	PlatformRust      Platform = "rust"       // Rust tab
)

// PlatformOrder is the canonical left-to-right tab order in the HTML report.
// (The report itself re-sorts tabs by lines of code; this is only the
// tie-break / fallback order.)
var PlatformOrder = []Platform{
	PlatformSwiftObjC, PlatformKotlin, PlatformPython, PlatformTSJS, PlatformGo, PlatformJava, PlatformRust,
}

// PlatformTitle is the human label shown on a tab.
func PlatformTitle(p Platform) string {
	switch p {
	case PlatformSwiftObjC:
		return "Swift + ObjC"
	case PlatformKotlin:
		return "Kotlin"
	case PlatformPython:
		return "Python"
	case PlatformTSJS:
		return "TS + JS"
	case PlatformGo:
		return "Go"
	case PlatformJava:
		return "Java"
	case PlatformRust:
		return "Rust"
	default:
		return string(p)
	}
}

// VersionProbe describes how to detect a language/runtime version from a repo.
type VersionProbe struct {
	// File to read relative to a project root, e.g. "go.mod", "Package.swift".
	File string
	// Pattern is a regex with one capture group yielding the version string.
	Pattern string
}

// ProjectType classifies a detected project (informational + report badge).
type ProjectType struct {
	Name        string   // "Go module", "SwiftPM", "Node", ...
	MarkerFiles []string // files whose presence implies this project type
}

// ModuleDetection tells the scanner how this language groups files into modules.
type ModuleDetection struct {
	// MarkerFiles mark a directory as a module root, e.g. ["go.mod"].
	MarkerFiles []string
	// ContainerDirs are directory names that typically hold modules, e.g. ["cmd"].
	ContainerDirs []string
	// ModuleNameFromPath, if set, derives a module name from a file path.
	// If nil, the engine falls back to the nearest marker-file directory.
	ModuleNameFromPath func(rootPath, filePath string) string
}

// ParsePatterns are the regexes the universal scanner uses for this language.
// All are raw strings compiled once at registration; empty fields are skipped.
type ParsePatterns struct {
	ImportSingle   string // single-line import -> capture group 1 = module
	ImportBlockBeg string // line that OPENS a multi-line import block
	ImportBlockEnd string // line that CLOSES it
	ImportInBlock  string // a line INSIDE an import block -> group 1 = module
	TypeDecl       string // type decl -> group1 = name, group2 = keyword (mapped via DeclKindMap)
	FuncDecl       string // function/method -> group1 = name
	DocComment     string // doc-comment line -> group1 = text
	CommentPrefix  string // line-comment prefix, e.g. "//" or "#"
	TodoMarkers    []string
	FixmeMarkers   []string
	// DeclKindMap maps a captured keyword (group2 of TypeDecl) to a normalized
	// DeclKind string (matching parser.DeclKind values like "struct","class").
	DeclKindMap map[string]string
	// BigFunctionMinLines is the threshold for BigFunctions; 0 means use default.
	BigFunctionMinLines int
	// BigTypeMinLines is the threshold for BigTypes; 0 means use default.
	BigTypeMinLines int
}

// LanguageSpec is the single source of truth for one language.
type LanguageSpec struct {
	// Identity
	ID          string
	DisplayName string
	Platform    Platform
	Extensions  []string // owned extensions WITHOUT dot: ["swift"], ["h","m","mm"]

	// Client marks UI/client-side languages (Swift, Objective-C, Kotlin,
	// TypeScript/JavaScript). The architecture module shows app-architecture
	// pattern detection (MVC, MVVM, VIPER, …) for client languages and a
	// goscope-style layered view (API/Service/Persistence/… + components) for
	// non-client/backend languages (Go, Python).
	Client bool

	// ModuleLabel / ModuleIcon name this language's unit of modularity in the
	// report — Go: "🔧" "Microservices", Swift: "📦" "Packages & Modules".
	// Empty falls back to "📦"/"Modules".
	ModuleLabel string
	ModuleIcon  string

	// Detection
	VersionProbes []VersionProbe
	ProjectTypes  []ProjectType
	Modules       ModuleDetection

	// Universal-parser tuning
	Patterns ParsePatterns

	// Optional Go hooks (nil for simple languages).
	//
	// ParseHook runs AFTER the universal parse and may enrich the result using
	// logic the regex sets cannot express. The pf argument is *parser.ParsedFile,
	// but typed as any here to keep langspec import-free; the parser asserts it.
	ParseHook func(filePath string, lines []string, pf any)

	// SecurityRuleIDs lists language-ONLY security rule IDs (universal rules are
	// attached automatically). Referenced by the security engine.
	SecurityRuleIDs []string

	// ReportModuleIDs lists language-specific report panels to render in this
	// language's tab, e.g. ["oopvspop"] for Swift.
	ReportModuleIDs []string
}
