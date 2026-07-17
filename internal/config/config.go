// Package config holds the global runtime configuration. The repository ships
// a default config (embedded in Default); a user may place an .archscope.json
// to override fields for their own needs. Load overlays the user's file on top
// of the defaults, so a partial user file only changes the keys it sets.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// DefaultConfigPath is the conventional location of the user override file.
const DefaultConfigPath = ".archscope.json"

// Output controls report output (requirement #3).
type Output struct {
	Format string `json:"format"` // "html" | "sarif" | "both"
	Dir    string `json:"dir"`    // output directory
}

// Languages toggles the built-in language set at runtime. New languages
// are still added by dropping a Go file in internal/lang; this only enables
// or disables the ones already registered.
type Languages struct {
	Enabled  []string `json:"enabled"`  // empty = all registered
	Disabled []string `json:"disabled"` // IDs to skip
}

// Security configures the security engine.
type Security struct {
	Enabled            bool     `json:"enabled"`
	MaxFindingsPerRule int      `json:"maxFindingsPerRule"`
	DisabledRules      []string `json:"disabledRules"`
	MinSeverity        string   `json:"minSeverity"` // "LOW" | "MEDIUM" | "HIGH"
}

// Fetch configures remote-repo cloning (requirement #5), used only for URLs.
type Fetch struct {
	Ref   string `json:"ref"`   // branch/tag/sha; "" = default branch
	Depth int    `json:"depth"` // 0 = full history (needed for git stats)
}

// Config is the whole runtime configuration.
type Config struct {
	ProjectName     string    `json:"projectName"`
	ExcludePaths    []string  `json:"excludePaths"`
	MaxFilesAnalyze int       `json:"maxFilesAnalyze"`
	GitCommitLimit  int       `json:"gitCommitLimit"`
	HotspotCount    int       `json:"hotspotCount"`
	FolderAsTab     bool      `json:"folderAsTab"`   // split per-folder into separate tabs (default true; --lang-platforms disables)
	GitRepoAsTab    bool      `json:"gitRepoAsTab"`  // split per-git-repository into separate tabs (overrides FolderAsTab when set)
	ScanAllFiles    bool      `json:"scanAllFiles"`  // scan git-submodule (third-party) directories too (default false; --scan-all-files enables)
	RenderModules   bool      `json:"renderModules"` // include the Modules & Microservices section; omitted by default
	Output          Output    `json:"output"`
	Languages       Languages `json:"languages"`
	Security        Security  `json:"security"`
	Fetch           Fetch     `json:"fetch"`
}

// Default returns the repo-shipped defaults.
func Default() Config {
	return Config{
		ProjectName: "",
		ExcludePaths: []string{
			".git", ".build", "node_modules", "vendor", "dist", "build",
			".idea", ".vscode", "__pycache__", ".cache", "DerivedData",
			"Pods", "target", ".venv", "venv", "env", "site-packages",
			"Carthage", ".swiftpm", "bower_components",
			// Vendored/external code and build tooling checked directly into a
			// repo (not necessarily as a git submodule — see ParseGitSubmodules
			// for that separate signal) under conventional names: a top-level
			// "third-party" (or "ThirdParty") folder of forked/vendored external
			// libraries, a "build-system"/"BuildSystem" folder of build tooling
			// (code generators, project-file generators, …), and a "scripts"/
			// "Scripts" folder of CI/debugging/automation helpers — none of it
			// product code, all of it noise in per-language metrics otherwise.
			"third-party", "ThirdParty", "build-system", "BuildSystem",
			"scripts", "Scripts", "fastlane",
			// CMake/CLion build output and generated-file directories.
			"cmake-build-debug", "cmake-build-release", "CMakeFiles",
		},
		MaxFilesAnalyze: 50000,
		GitCommitLimit:  1000,
		HotspotCount:    15,
		FolderAsTab:     true, // one platform tab per top-level folder by default; --lang-platforms opts out
		Output:          Output{Format: "html", Dir: "output"},
		Languages:       Languages{},
		Security: Security{
			Enabled:            true,
			MaxFindingsPerRule: 100,
			MinSeverity:        "LOW",
		},
		Fetch: Fetch{Ref: "", Depth: 0},
	}
}

// Load returns Default() overlaid with the user's file at path (or
// DefaultConfigPath when path is empty). A missing file is not an error — the
// defaults are returned. A malformed file logs a warning and returns defaults.
//
// The overlay is a straight JSON unmarshal onto a Default() value, so any key
// the user omits keeps its default and any key they set wins.
func Load(path string) Config {
	if path == "" {
		path = DefaultConfigPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Default()
	}
	cfg := Default()
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "archscope: failed to parse %s, using defaults: %v\n", path, err)
		return Default()
	}
	return cfg
}

// CreateDefault writes the default config to path (or DefaultConfigPath),
// giving users a starting point to edit.
func CreateDefault(path string) error {
	if path == "" {
		path = DefaultConfigPath
	}
	data, err := json.MarshalIndent(Default(), "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("Created default config at %s\n", path)
	return nil
}
