// Command archscope analyzes a codebase and writes an interactive HTML report.
//
// Usage:
//
//	archscope <path-or-url> [flags]
//
// Flags:
//
//	--open          open the report in the default browser when done
//	--output, -o    output directory (default: from config, usually "output")
//	--format        "html" | "sarif" | "both" (default: html)
//	--config        path to .archscope.json (default: .archscope.json in cwd)
//	--ref           git ref to check out when cloning a remote URL
//	--depth         clone depth; 0 = full history (default: 0)
//	--skip-modules  omit the Modules & Microservices section (and its graphs)
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/exey/archscope/internal/config"
	"github.com/exey/archscope/internal/fetch"
	_ "github.com/exey/archscope/internal/lang" // register language specs
	"github.com/exey/archscope/internal/modules"
	_ "github.com/exey/archscope/internal/modules/arch" // register report modules
	_ "github.com/exey/archscope/internal/modules/dddmodel"
	_ "github.com/exey/archscope/internal/modules/designpattern"
	_ "github.com/exey/archscope/internal/modules/oopvspop"
	_ "github.com/exey/archscope/internal/modules/speccoverage"
	_ "github.com/exey/archscope/internal/modules/traffic"
	htmlreport "github.com/exey/archscope/internal/report/html"
	mdreport "github.com/exey/archscope/internal/report/markdown"
	"github.com/exey/archscope/internal/report/sarif"
	"github.com/exey/archscope/internal/result"
)

func main() {
	// Manual arg parsing so flags work in any position:
	//   archscope ~/code --open
	//   archscope --open ~/code
	//   archscope ~/code --format both --output ./out
	var (
		target      string
		openFlag    bool
		outputDir   string
		format      string
		cfgPath     string
		ref         string
		depth       int
		folderAsTab bool
		skipModules bool
	)

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--open" || a == "-open":
			openFlag = true
		case a == "--output" || a == "-output" || a == "-o":
			if i+1 < len(args) {
				i++
				outputDir = args[i]
			}
		case strings.HasPrefix(a, "--output=") || strings.HasPrefix(a, "-o="):
			outputDir = a[strings.Index(a, "=")+1:]
		case a == "--format" || a == "-format":
			if i+1 < len(args) {
				i++
				format = args[i]
			}
		case strings.HasPrefix(a, "--format=") || strings.HasPrefix(a, "-format="):
			format = a[strings.Index(a, "=")+1:]
		case a == "--config" || a == "-config":
			if i+1 < len(args) {
				i++
				cfgPath = args[i]
			}
		case strings.HasPrefix(a, "--config=") || strings.HasPrefix(a, "-config="):
			cfgPath = a[strings.Index(a, "=")+1:]
		case a == "--ref" || a == "-ref":
			if i+1 < len(args) {
				i++
				ref = args[i]
			}
		case strings.HasPrefix(a, "--ref=") || strings.HasPrefix(a, "-ref="):
			ref = a[strings.Index(a, "=")+1:]
		case a == "--depth" || a == "-depth":
			if i+1 < len(args) {
				i++
				depth, _ = strconv.Atoi(args[i])
			}
		case strings.HasPrefix(a, "--depth=") || strings.HasPrefix(a, "-depth="):
			depth, _ = strconv.Atoi(a[strings.Index(a, "=")+1:])
		case a == "--folder-as-tab" || a == "-folder-as-tab":
			folderAsTab = true
		case a == "--skip-modules" || a == "-skip-modules":
			skipModules = true
		case a == "--help" || a == "-h":
			printUsage()
			os.Exit(0)
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(os.Stderr, "archscope: unknown flag %q\n", a)
			printUsage()
			os.Exit(1)
		default:
			if target == "" {
				target = a
			}
		}
	}

	if target == "" {
		printUsage()
		os.Exit(1)
	}

	cfg := config.Load(cfgPath)
	if outputDir == "" {
		outputDir = cfg.Output.Dir
	}
	if format == "" {
		format = cfg.Output.Format
	}
	if folderAsTab {
		cfg.FolderAsTab = true
	}
	if skipModules {
		cfg.SkipModules = true
	}

	src := fetch.FromArg(target, ref, depth)
	resolved, err := fetch.Resolve(src)
	if err != nil {
		fatalf("archscope: %v\n", err)
	}
	defer resolved.Cleanup() //nolint:errcheck

	pipelineStart := time.Now()
	res, err := result.RunWithProgress(resolved.Path, cfg, func(msg string) {
		fmt.Printf(" → [%5.1fs] %s\n", time.Since(pipelineStart).Seconds(), msg)
	})
	if err != nil {
		fatalf("archscope: analysis failed: %v\n", err)
	}
	if resolved.WasClone {
		res.IsRemote = true
		res.SourceURL = target
	}

	printCapabilityTable(res)

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fatalf("archscope: cannot create output dir: %v\n", err)
	}

	name := strings.ReplaceAll(res.ProjectName, string(filepath.Separator), "_")
	if name == "" {
		name = "report"
	}

	var reportPath string
	switch strings.ToLower(format) {
	case "sarif":
		outPath := filepath.Join(outputDir, name+".sarif")
		if err := sarif.Write(res, outPath); err != nil {
			fatalf("archscope: sarif write failed: %v\n", err)
		}
		fmt.Println("SARIF →", outPath)
	case "md", "markdown":
		mdPath := filepath.Join(outputDir, name+".md")
		if err := mdreport.Write(res, mdPath); err != nil {
			fatalf("archscope: markdown write failed: %v\n", err)
		}
		fmt.Println("MD    →", mdPath)
		reportPath = mdPath
	case "both":
		htmlPath := filepath.Join(outputDir, name+".html")
		if err := htmlreport.Write(res, htmlPath); err != nil {
			fatalf("archscope: html write failed: %v\n", err)
		}
		fmt.Println("HTML  →", htmlPath)
		sarifPath := filepath.Join(outputDir, name+".sarif")
		if err := sarif.Write(res, sarifPath); err != nil {
			fatalf("archscope: sarif write failed: %v\n", err)
		}
		fmt.Println("SARIF →", sarifPath)
		reportPath = htmlPath
	default: // "html"
		htmlPath := filepath.Join(outputDir, name+".html")
		if err := htmlreport.Write(res, htmlPath); err != nil {
			fatalf("archscope: html write failed: %v\n", err)
		}
		fmt.Println("HTML  →", htmlPath)
		reportPath = htmlPath
	}

	if openFlag && reportPath != "" {
		abs, _ := filepath.Abs(reportPath)
		openInBrowser(abs)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: archscope <path-or-url> [flags]

Flags:
  --open              open the HTML report in the browser when done
  --format <fmt>      html | sarif | md | both  (default: from config)
  --output, -o <dir>  output directory    (default: from config, usually "output")
  --config <file>     path to .archscope.json
  --ref <ref>         git ref for remote URLs (branch/tag/sha)
  --depth <n>         clone depth for remote URLs (0 = full history)
  --folder-as-tab     show each top-level folder as its own tab (e.g. "pharmen Py", "gptzakaz Go")
  --skip-modules      omit the Modules & Microservices section (file inventory, declarations, and
                      its CDN-loaded graph) per platform, plus the global Architecture Graph;
                      all platforms are unfolded by default when this is set
`)
}

func openInBrowser(path string) {
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(os.Stderr, "open: file not found: %s\n", path)
		return
	}
	fmt.Printf("open: %s\n", path)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("/usr/bin/open", path)
	case "linux":
		cmd = exec.Command("xdg-open", path)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
	}
	if cmd == nil {
		return
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: failed (%v)", err)
		if len(out) > 0 {
			fmt.Fprintf(os.Stderr, ": %s", out)
		}
		fmt.Fprintln(os.Stderr)
		return
	}
	if len(out) > 0 {
		fmt.Printf("open: %s\n", out)
	}
	fmt.Println("open: ok")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}

// printCapabilityTable prints a compact per-platform × per-module matrix to
// stdout showing which analysis cards were produced (✓) or absent (—).
func printCapabilityTable(res *result.AnalysisResult) {
	platforms := res.Scan.PlatformsOrdered()
	if len(platforms) == 0 {
		return
	}

	// Build column list in canonical order from MetaByID.
	type col struct{ id, label string }
	type entry struct {
		id    string
		order int
	}
	var entries []entry
	for id, m := range modules.MetaByID {
		entries = append(entries, entry{id, m.Order})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].order < entries[j].order })
	cols := make([]col, 0, len(entries))
	for _, e := range entries {
		cols = append(cols, col{e.id, moduleShortLabel(e.id)})
	}

	// Which module IDs rendered for each platform.
	platHas := map[string]map[string]bool{}
	for _, panel := range res.ModulePanels {
		key := string(panel.Platform)
		if platHas[key] == nil {
			platHas[key] = map[string]bool{}
		}
		platHas[key][panel.ModuleID] = true
	}

	// Column widths.
	platW := len("Platform")
	for _, pg := range platforms {
		if l := len(pg.TabLabel()); l > platW {
			platW = l
		}
	}
	colW := make([]int, len(cols))
	for i, c := range cols {
		colW[i] = len(c.label)
		if colW[i] < 2 {
			colW[i] = 2
		}
	}

	// Header.
	fmt.Printf("\n Modules per platform:\n")
	fmt.Printf(" %-*s", platW, "Platform")
	for i, c := range cols {
		fmt.Printf("  %-*s", colW[i], c.label)
		_ = i
	}
	fmt.Println()

	// Separator.
	total := platW + 1
	for _, w := range colW {
		total += w + 3
	}
	fmt.Println(" " + strings.Repeat("─", total))

	// Rows.
	for _, pg := range platforms {
		key := string(pg.Platform)
		fmt.Printf(" %-*s", platW, pg.TabLabel())
		for i, c := range cols {
			mark := "—"
			if platHas[key][c.id] {
				mark = "✓"
			}
			fmt.Printf("  %-*s", colW[i], mark)
			_ = i
		}
		fmt.Println()
	}
	fmt.Println()
}

func moduleShortLabel(id string) string {
	switch id {
	case "arch":
		return "Arch"
	case "dddmodel":
		return "DDD"
	case "oopvspop":
		return "OOP"
	case "traffic":
		return "Traffic"
	case "speccoverage":
		return "Spec"
	case "designpattern":
		return "Patterns"
	}
	return id
}
