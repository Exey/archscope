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
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/exey/archscope/internal/config"
	"github.com/exey/archscope/internal/fetch"
	_ "github.com/exey/archscope/internal/lang" // register all language specs via init()
	htmlreport "github.com/exey/archscope/internal/report/html"
	"github.com/exey/archscope/internal/report/sarif"
	"github.com/exey/archscope/internal/result"
)

func main() {
	// Manual arg parsing so flags work in any position:
	//   archscope ~/code --open
	//   archscope --open ~/code
	//   archscope ~/code --format both --output ./out
	var (
		target    string
		openFlag  bool
		outputDir string
		format    string
		cfgPath   string
		ref       string
		depth     int
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

	src := fetch.FromArg(target, ref, depth)
	resolved, err := fetch.Resolve(src)
	if err != nil {
		fatalf("archscope: %v\n", err)
	}
	defer resolved.Cleanup() //nolint:errcheck

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
  --open            open the HTML report in the browser when done
  --format <fmt>    html | sarif | both  (default: from config)
  --output, -o <dir> output directory    (default: from config, usually "output")
  --config <file>   path to .archscope.json
  --ref <ref>       git ref for remote URLs (branch/tag/sha)
  --depth <n>       clone depth for remote URLs (0 = full history)
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
