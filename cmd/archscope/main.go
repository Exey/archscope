// Command archscope analyzes a codebase and writes an interactive HTML report.
//
// Usage:
//
//	archscope <path-or-url> [flags]
//
// Flags:
//
//	--open          open the report in the default browser when done
//	--output, -o    output directory (default: current directory)
//	--format        "html" | "sarif" | "both" (default: html)
//	--config        path to .archscope.json (default: .archscope.json in cwd)
//	--ref           git ref to check out when cloning a remote URL
//	--depth         clone depth; 0 = full history (default: 0)
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/exey/archscope/internal/config"
	"github.com/exey/archscope/internal/fetch"
	_ "github.com/exey/archscope/internal/lang" // register all language specs via init()
	htmlreport "github.com/exey/archscope/internal/report/html"
	"github.com/exey/archscope/internal/report/sarif"
	"github.com/exey/archscope/internal/result"
)

func main() {
	fs := flag.NewFlagSet("archscope", flag.ExitOnError)
	openFlag := fs.Bool("open", false, "open the report in the default browser when done")
	outputDir := fs.String("output", "", "output directory (default: from config, usually \"output\")")
	fs.StringVar(outputDir, "o", "", "output directory (shorthand)")
	format := fs.String("format", "", `output format: "html", "sarif", or "both" (default: from config)`)
	cfgPath := fs.String("config", "", "path to .archscope.json")
	ref := fs.String("ref", "", "git ref to check out when cloning a remote URL")
	depth := fs.Int("depth", 0, "clone depth (0 = full history)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: archscope <path-or-url> [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(os.Args[1:])

	args := fs.Args()
	if len(args) == 0 {
		fs.Usage()
		os.Exit(1)
	}
	target := args[0]

	cfg := config.Load(*cfgPath)

	// CLI flags override config; config provides defaults for unset flags.
	if *outputDir == "" {
		*outputDir = cfg.Output.Dir
	}
	if *format == "" {
		*format = cfg.Output.Format
	}

	// Resolve source (local or remote).
	src := fetch.FromArg(target, *ref, *depth)
	resolved, err := fetch.Resolve(src)
	if err != nil {
		fatalf("archscope: %v\n", err)
	}
	defer resolved.Cleanup() //nolint:errcheck

	// Run the analysis pipeline.
	res, err := result.RunWithProgress(resolved.Path, cfg, func(msg string) {
		fmt.Println(" →", msg)
	})
	if err != nil {
		fatalf("archscope: analysis failed: %v\n", err)
	}
	if resolved.WasClone {
		res.IsRemote = true
		res.SourceURL = target
	}

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		fatalf("archscope: cannot create output dir: %v\n", err)
	}

	name := strings.ReplaceAll(res.ProjectName, string(filepath.Separator), "_")
	if name == "" {
		name = "report"
	}

	var reportPath string
	switch strings.ToLower(*format) {
	case "sarif":
		outPath := filepath.Join(*outputDir, name+".sarif")
		if err := sarif.Write(res, outPath); err != nil {
			fatalf("archscope: sarif write failed: %v\n", err)
		}
		fmt.Println("SARIF →", outPath)
	case "both":
		htmlPath := filepath.Join(*outputDir, name+".html")
		if err := htmlreport.Write(res, htmlPath); err != nil {
			fatalf("archscope: html write failed: %v\n", err)
		}
		fmt.Println("HTML  →", htmlPath)
		sarifPath := filepath.Join(*outputDir, name+".sarif")
		if err := sarif.Write(res, sarifPath); err != nil {
			fatalf("archscope: sarif write failed: %v\n", err)
		}
		fmt.Println("SARIF →", sarifPath)
		reportPath = htmlPath
	default: // "html"
		htmlPath := filepath.Join(*outputDir, name+".html")
		if err := htmlreport.Write(res, htmlPath); err != nil {
			fatalf("archscope: html write failed: %v\n", err)
		}
		fmt.Println("HTML  →", htmlPath)
		reportPath = htmlPath
	}

	if *openFlag && reportPath != "" {
		abs, _ := filepath.Abs(reportPath)
		openInBrowser(abs)
	}
}

func openInBrowser(path string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "linux":
		cmd = exec.Command("xdg-open", path)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
	}
	if cmd != nil {
		cmd.Start() //nolint:errcheck
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}
