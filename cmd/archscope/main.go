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
//	--format        "html" | "sarif" | "md" (comma-separated for multiple; default: html)
//	--config        path to .archscope.json (default: .archscope.json in cwd)
//	--ref           git ref to check out when cloning a remote URL
//	--depth         clone depth; 0 = full history (default: 0)
//	--fail-on       exit 2 when findings exist at or above threshold: low|medium|high
//	--render-modules  include the Modules & Microservices section (and its graphs); omitted by default
//	--lang-platforms  group all files of a language into one platform tab (shorthand for --group-by=language)
//	--group-by      how to group platform tabs: language | folder | gitrepo (default: auto-detected)
//	--scan-all-files  also scan git-submodule (third-party/vendored) directories, skipped by default
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/exey/archscope/internal/config"
	"github.com/exey/archscope/internal/fetch"
	_ "github.com/exey/archscope/internal/lang" // register language specs
	"github.com/exey/archscope/internal/modules"
	_ "github.com/exey/archscope/internal/modules/arch" // register report modules
	_ "github.com/exey/archscope/internal/modules/constructs"
	_ "github.com/exey/archscope/internal/modules/dddmodel"
	_ "github.com/exey/archscope/internal/modules/oopvspop"
	_ "github.com/exey/archscope/internal/modules/speccoverage"
	_ "github.com/exey/archscope/internal/modules/traffic"
	"github.com/exey/archscope/internal/report"
	_ "github.com/exey/archscope/internal/report/html"     // register html emitter
	_ "github.com/exey/archscope/internal/report/markdown" // register md emitter
	_ "github.com/exey/archscope/internal/report/sarif"    // register sarif emitter
	"github.com/exey/archscope/internal/result"
	"github.com/exey/archscope/internal/scanner"
)

// exitCodeError is returned by run when a specific exit code is required.
// Exit code 2 signals --fail-on threshold exceeded; 1 is reserved for
// operational errors (returned as plain errors from run).
type exitCodeError struct {
	code int
	msg  string
}

func (e *exitCodeError) Error() string { return e.msg }

func main() {
	// Pre-pass: walk os.Args to separate the one positional argument (target
	// path or URL) from the flag arguments. This lets flags appear in any
	// position relative to the target:
	//   archscope ~/repo --open
	//   archscope --open ~/repo
	//
	// valFlags lists flags whose next argument is their value (no '=' inline).
	valFlags := map[string]bool{
		"output": true, "o": true,
		"format":   true,
		"config":   true,
		"ref":      true,
		"depth":    true,
		"fail-on":  true,
		"group-by": true,
	}
	rawArgs := os.Args[1:]
	var target string
	var flagArgs []string
	for i := 0; i < len(rawArgs); i++ {
		a := rawArgs[i]
		if a == "--" {
			for _, rest := range rawArgs[i+1:] {
				if target == "" {
					target = rest
				} else {
					fmt.Fprintf(os.Stderr, "archscope: unexpected argument %q\n", rest)
					os.Exit(1)
				}
			}
			break
		}
		if !strings.HasPrefix(a, "-") {
			if target == "" {
				target = a
			} else {
				fmt.Fprintf(os.Stderr, "archscope: unexpected argument %q (target already set to %q)\n", a, target)
				os.Exit(1)
			}
			continue
		}
		flagArgs = append(flagArgs, a)
		// For flags that take a separate value arg (not inline with '='),
		// consume the next raw argument so it doesn't get mis-classified.
		name := strings.TrimLeft(a, "-")
		if idx := strings.IndexByte(name, '='); idx < 0 && valFlags[name] {
			if i+1 < len(rawArgs) {
				i++
				flagArgs = append(flagArgs, rawArgs[i])
			}
		}
	}

	fs := flag.NewFlagSet("archscope", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = printUsage

	var (
		openFlag      bool
		outputDir     string
		format        string
		cfgPath       string
		ref           string
		depth         int
		langPlatforms bool
		renderModules bool
		failOn        string
		groupBy       string
		scanAllFiles  bool
	)

	fs.BoolVar(&openFlag, "open", false, "open the HTML report in the browser when done")
	fs.StringVar(&outputDir, "output", "", "output directory (overrides config)")
	fs.StringVar(&outputDir, "o", "", "output directory (shorthand for --output)")
	fs.StringVar(&format, "format", "", "output format: html | sarif | md (comma-separated for multiple; overrides config)")
	fs.StringVar(&cfgPath, "config", "", "path to .archscope.json (default: .archscope.json in cwd)")
	fs.StringVar(&ref, "ref", "", "git ref for remote URLs (branch/tag/sha)")
	fs.IntVar(&depth, "depth", 0, "clone depth for remote URLs; 0 = full history")
	fs.BoolVar(&langPlatforms, "lang-platforms", false, "group all files of a language into one platform tab (shorthand for --group-by=language)")
	fs.BoolVar(&renderModules, "render-modules", false, "include the Modules & Microservices section and its CDN-loaded graphs (omitted by default)")
	fs.StringVar(&failOn, "fail-on", "", "exit 2 when findings exist at or above threshold: low | medium | high")
	fs.StringVar(&groupBy, "group-by", "", "how to group platform tabs: language | folder | gitrepo (default: auto-detected from .git count, prompts interactively when 2+ repos are found)")
	fs.BoolVar(&scanAllFiles, "scan-all-files", false, "also scan git-submodule (third-party/vendored) directories, skipped by default")

	if err := fs.Parse(flagArgs); err != nil {
		if err != flag.ErrHelp {
			printUsage()
		}
		os.Exit(1)
	}

	if target == "" {
		printUsage()
		os.Exit(1)
	}

	switch strings.ToLower(failOn) {
	case "", "low", "medium", "high":
	default:
		fmt.Fprintf(os.Stderr, "archscope: unknown --fail-on %q (want low | medium | high)\n", failOn)
		os.Exit(1)
	}

	groupBy = strings.ToLower(strings.TrimSpace(groupBy))
	switch groupBy {
	case "", "language", "folder", "gitrepo":
	default:
		fmt.Fprintf(os.Stderr, "archscope: unknown --group-by %q (want language, folder, or gitrepo)\n", groupBy)
		os.Exit(1)
	}
	if langPlatforms && groupBy == "" {
		groupBy = "language"
	}

	if err := run(target, ref, depth, cfgPath, outputDir, format, failOn, groupBy, openFlag, renderModules, scanAllFiles); err != nil {
		if ec, ok := err.(*exitCodeError); ok {
			if ec.msg != "" {
				fmt.Fprintln(os.Stderr, ec.msg)
			}
			os.Exit(ec.code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run executes the full analysis. Deferred cleanup (clone temp dir removal)
// fires on every return path because os.Exit in main would bypass it.
func run(target, ref string, depth int, cfgPath, outputDir, format, failOn, groupBy string, openFlag, renderModules, scanAllFiles bool) error {
	cfg := config.Load(cfgPath)
	if outputDir == "" {
		outputDir = cfg.Output.Dir
	}
	if format == "" {
		format = cfg.Output.Format
	}
	// Wire Fetch config defaults when CLI flags were not provided.
	if ref == "" {
		ref = cfg.Fetch.Ref
	}
	if depth == 0 && cfg.Fetch.Depth > 0 {
		depth = cfg.Fetch.Depth
	}
	if scanAllFiles {
		cfg.ScanAllFiles = true
	}
	if renderModules {
		cfg.RenderModules = true
	}

	src := fetch.FromArg(target, ref, depth)
	resolved, err := fetch.Resolve(src)
	if err != nil {
		return fmt.Errorf("archscope: %w", err)
	}
	defer resolved.Cleanup() //nolint:errcheck

	// Decide how platform tabs are grouped. An explicit --group-by (or its
	// --lang-platforms shorthand) always wins; otherwise the choice depends on
	// how many git repositories live under the target: a single repo (or
	// none) is one project, not a monorepo of independent services, so it
	// defaults to grouping by language regardless of how many languages are
	// present; 2+ repos is a real "which way do you want this sliced"
	// question, asked interactively when possible.
	if groupBy == "" {
		gitRepos := scanner.DiscoverGitRepos(resolved.Path, cfg.ExcludePaths)
		switch {
		case len(gitRepos) <= 1:
			fmt.Println("archscope: single project (0-1 git repositories) — grouping platform tabs by language (pass --group-by to override)")
			groupBy = "language"
		default:
			groupBy = promptGroupingMode(len(gitRepos))
		}
	}
	applyGroupBy(&cfg, groupBy)

	pipelineStart := time.Now()
	res, err := result.RunWithProgress(resolved.Path, cfg, func(msg string) {
		fmt.Printf(" → [%5.1fs] %s\n", time.Since(pipelineStart).Seconds(), msg)
	})
	if err != nil {
		return fmt.Errorf("archscope: analysis failed: %w", err)
	}
	if resolved.WasClone {
		res.IsRemote = true
		res.SourceURL = target
	}

	printCapabilityTable(res)

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("archscope: cannot create output dir: %w", err)
	}

	name := strings.ReplaceAll(res.ProjectName, string(filepath.Separator), "_")
	if name == "" {
		name = "report"
	}

	// Normalize format: "both" is a legacy alias for "html,sarif"; empty defaults to "html".
	fmtStr := strings.ToLower(strings.TrimSpace(format))
	switch fmtStr {
	case "both":
		fmtStr = "html,sarif"
	case "markdown":
		fmtStr = "md"
	case "":
		fmtStr = "html"
	}

	var reportPath string
	for _, id := range strings.Split(fmtStr, ",") {
		id = strings.TrimSpace(id)
		em, ok := report.Lookup(id)
		if !ok {
			return fmt.Errorf("archscope: unknown format %q (want html, sarif, md)", id)
		}
		outPath := filepath.Join(outputDir, name+em.Ext())
		if err := em.Write(res, outPath); err != nil {
			return fmt.Errorf("archscope: %s write failed: %w", strings.ToUpper(id), err)
		}
		fmt.Printf("%-6s→ %s\n", strings.ToUpper(id), outPath)
		if em.Ext() == ".html" && reportPath == "" {
			reportPath = outPath
		}
	}

	if openFlag && reportPath != "" {
		abs, _ := filepath.Abs(reportPath)
		openInBrowser(abs)
	}

	// F11: exit 2 when --fail-on threshold is met.
	if failOn != "" {
		threshold := failOnRank(strings.ToLower(failOn))
		for _, rr := range res.Security {
			if rr.Passed() {
				continue
			}
			if failOnRank(strings.ToLower(string(rr.Rule.Severity))) >= threshold {
				return &exitCodeError{
					code: 2,
					msg:  fmt.Sprintf("archscope: findings at or above %q threshold — exit 2", failOn),
				}
			}
		}
	}
	return nil
}

// applyGroupBy sets the config fields that control platform-tab grouping.
// mode is one of "language", "folder", "gitrepo" (anything else falls back
// to "folder", today's long-standing default).
func applyGroupBy(cfg *config.Config, mode string) {
	switch mode {
	case "language":
		cfg.FolderAsTab = false
		cfg.GitRepoAsTab = false
	case "gitrepo":
		cfg.FolderAsTab = false
		cfg.GitRepoAsTab = true
	default:
		cfg.FolderAsTab = true
		cfg.GitRepoAsTab = false
	}
}

// promptGroupingMode asks the user (interactively, when stdin is a terminal)
// how to group platform tabs when 2+ git repositories were found under the
// target — that ambiguity can't be resolved automatically the way a single
// repo can. Falls back to "folder" (the long-standing default) without
// blocking when stdin isn't a terminal (CI, piped input, etc.) or the read
// fails/hits EOF.
func promptGroupingMode(repoCount int) string {
	if !stdinIsTerminal() {
		fmt.Printf("archscope: found %d git repositories; not an interactive terminal, defaulting to per-folder tabs (pass --group-by to choose explicitly and skip this message)\n", repoCount)
		return "folder"
	}
	fmt.Printf("\narchscope: found %d git repositories under this path. How should platform tabs be grouped?\n", repoCount)
	fmt.Println("  1. By Languages         — one tab per language, regardless of folder or repo")
	fmt.Println("  2. By first-level folders — one tab per top-level folder (default)")
	fmt.Println("  3. By folders with .git  — one tab per detected git repository")
	fmt.Print("Choose 1-3 (default 2): ")

	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.TrimSpace(line) {
	case "1":
		return "language"
	case "3":
		return "gitrepo"
	default:
		return "folder"
	}
}

// stdinIsTerminal reports whether os.Stdin looks like an interactive
// terminal rather than a pipe, redirect, or CI's non-interactive stdin —
// used to avoid ever blocking a scripted/CI run on a prompt it can't answer.
func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// failOnRank maps a lower-case severity name to a comparable integer.
func failOnRank(s string) int {
	switch s {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: archscope <path-or-url> [flags]

Flags:
  --open              open the HTML report in the browser when done
  --format <fmt>      html | sarif | md (comma-separated for multiple; default: from config)
  --output, -o <dir>  output directory    (default: from config, usually "output")
  --config <file>     path to .archscope.json
  --ref <ref>         git ref for remote URLs (branch/tag/sha)
  --depth <n>         clone depth for remote URLs (0 = full history)
  --fail-on <lvl>     exit 2 when findings exist at or above: low | medium | high
  --lang-platforms    group all files of a language into one platform tab (shorthand for --group-by=language)
  --group-by <mode>   how to group platform tabs: language | folder | gitrepo
                      (default: auto — one git repo groups by language, 2+ prompts interactively)
  --render-modules    include the Modules & Microservices section (and its CDN-loaded graphs); omitted by default
  --scan-all-files    also scan git-submodule (third-party/vendored) directories, skipped by default
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

// printCapabilityTable prints a compact per-platform × per-module matrix to
// stdout showing which analysis cards were produced (✓) or absent (—).
func printCapabilityTable(res *result.AnalysisResult) {
	platforms := res.Scan.PlatformsOrdered()
	if len(platforms) == 0 {
		return
	}

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

	platHas := map[string]map[string]bool{}
	for _, panel := range res.ModulePanels {
		key := string(panel.Platform)
		if platHas[key] == nil {
			platHas[key] = map[string]bool{}
		}
		platHas[key][panel.ModuleID] = true
	}

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

	fmt.Printf("\n Modules per platform:\n")
	fmt.Printf(" %-*s", platW, "Platform")
	for i, c := range cols {
		fmt.Printf("  %-*s", colW[i], c.label)
	}
	fmt.Println()

	total := platW + 1
	for _, w := range colW {
		total += w + 3
	}
	fmt.Println(" " + strings.Repeat("─", total))

	for _, pg := range platforms {
		key := string(pg.Platform)
		fmt.Printf(" %-*s", platW, pg.TabLabel())
		for i, c := range cols {
			mark := "—"
			if platHas[key][c.id] {
				mark = "✓"
			}
			fmt.Printf("  %-*s", colW[i], mark)
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
