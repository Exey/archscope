// Command archscope analyzes a codebase and writes an interactive HTML report.
//
// Usage:
//
//	archscope <path-or-url> [flags]
//
// Flags:
//
//	--open          open the report in the default browser when done
//	--spec <file>   OpenAPI spec (repeatable, comma-separated) the code is analysed against, in addition to specs found in the tree
//	--inspect <file> saved celery inspect / rabbitmqctl output for the 🧵 Concurrency card (repeatable)
//	--browser <name> open the report in that browser (chrome | firefox | safari | edge | brave | opera | <app>); implies --open
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
//	--review        review mode: Evolution since <commit|branch> with GitLab MR-line buttons
//	--evolution     compare Programming Culture now vs. git history: 2w,1m,last-tag,<date>,<commit> or auto (e.g. --evolution 1m 2w)
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
	"github.com/exey/archscope/internal/evolution"
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
	reporthtml "github.com/exey/archscope/internal/report/html" // register html emitter; also provides CultureScores
	_ "github.com/exey/archscope/internal/report/markdown"      // register md emitter
	_ "github.com/exey/archscope/internal/report/sarif"         // register sarif emitter
	"github.com/exey/archscope/internal/result"
	"github.com/exey/archscope/internal/scanner"
)

// isExtraEvolutionSpec reports whether arg is a further --evolution value:
// spec-shaped (see evolution.LooksLikeSpec) and not the name of an existing
// file or directory, which is far more likely to be the scan target.
func isExtraEvolutionSpec(arg string) bool {
	if strings.HasPrefix(arg, "-") || !evolution.LooksLikeSpec(arg) {
		return false
	}
	_, err := os.Stat(arg)
	return err != nil
}

func isExistingDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// exitCodeError is returned by run when a specific exit code is required.
// Exit code 2 signals --fail-on threshold exceeded; 1 is reserved for
// operational errors (returned as plain errors from run).
type exitCodeError struct {
	code int
	msg  string
}

func (e *exitCodeError) Error() string { return e.msg }

// splitArgs separates the one positional argument (target path or URL) from
// the flag arguments, so flags may appear in any position relative to the target:
//
//	archscope ~/repo --open
//	archscope --open ~/repo
func splitArgs(rawArgs []string) (target string, flagArgs []string, err error) {
	// valFlags lists flags whose next argument is their value (no '=' inline).
	valFlags := map[string]bool{
		"output": true, "o": true,
		"format":   true,
		"config":   true,
		"ref":      true,
		"depth":    true,
		"fail-on":  true,
		"group-by": true,
		"against":  true,
		"browser":  true,
		"spec":     true,
		"inspect":  true,
	}
	for i := 0; i < len(rawArgs); i++ {
		a := rawArgs[i]
		if a == "--" {
			for _, rest := range rawArgs[i+1:] {
				if target != "" {
					return "", nil, fmt.Errorf("unexpected argument %q", rest)
				}
				target = rest
			}
			break
		}
		if !strings.HasPrefix(a, "-") {
			if target != "" {
				return "", nil, fmt.Errorf("unexpected argument %q (target already set to %q)", a, target)
			}
			target = a
			continue
		}
		// For flags that take a separate value arg (not inline with '='),
		// consume the next raw argument so it doesn't get mis-classified.
		name := strings.TrimLeft(a, "-")
		flagName, _, inline := strings.Cut(name, "=")
		switch {
		case flagName == "evolution":
			// --evolution takes several space-separated specs ("--evolution 1m 2w"
			// = two baselines + now = three points). The first value is taken
			// as-is; further args join it only while they are unmistakably specs
			// (duration/date/last-tag/auto/commit id) and not an existing path, so
			// `--evolution 1m ~/repo` and `--evolution 1m 2w ./repo` both still
			// find their target.
			val := ""
			if inline {
				val = a[strings.IndexByte(a, '=')+1:]
			} else if i+1 < len(rawArgs) && !strings.HasPrefix(rawArgs[i+1], "-") {
				i++
				val = rawArgs[i]
			}
			for i+1 < len(rawArgs) && isExtraEvolutionSpec(rawArgs[i+1]) {
				i++
				val += "," + rawArgs[i]
			}
			flagArgs = append(flagArgs, "--evolution="+val)
		case flagName == "review" && !inline:
			// Bare `--review` reviews against the local default branch ("auto");
			// a following value is the ref, unless it is a flag or the scan target.
			val := "auto"
			if i+1 < len(rawArgs) && !strings.HasPrefix(rawArgs[i+1], "-") && !isExistingDir(rawArgs[i+1]) {
				i++
				val = rawArgs[i]
			}
			flagArgs = append(flagArgs, "--review="+val)
		case !inline && valFlags[name]:
			flagArgs = append(flagArgs, a)
			if i+1 < len(rawArgs) {
				i++
				flagArgs = append(flagArgs, rawArgs[i])
			}
		default:
			flagArgs = append(flagArgs, a)
		}
	}
	return target, flagArgs, nil
}

func main() {
	target, flagArgs, err := splitArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "archscope: %v\n", err)
		os.Exit(1)
	}

	fs := flag.NewFlagSet("archscope", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = printUsage

	o := runOptions{target: target}
	var (
		browserFlag   string
		specFlag      listFlag
		inspectFlag   listFlag
		langPlatforms bool
	)

	fs.BoolVar(&o.open, "open", false, "open the HTML report in the browser when done")
	fs.Var(&specFlag, "spec", "OpenAPI/Swagger spec file(s) to analyse the code against — comma-separated or repeated; used for 📜 OpenAPI lint and 🧱 Spec Coverage in addition to specs found in the tree")
	fs.Var(&inspectFlag, "inspect", "saved output of `celery inspect registered|scheduled` or `rabbitmqctl list_queues|list_exchanges|list_bindings` (comma-separated or repeated) — shown in the 🧵 Concurrency card and compared with the tasks found in code")
	fs.StringVar(&browserFlag, "browser", "", "open the report in this browser (chrome, firefox, safari, edge, brave or an app name); implies --open")
	fs.StringVar(&o.outputDir, "output", "", "output directory (overrides config)")
	fs.StringVar(&o.outputDir, "o", "", "output directory (shorthand for --output)")
	fs.StringVar(&o.format, "format", "", "output format: html | sarif | md (comma-separated for multiple; overrides config)")
	fs.StringVar(&o.cfgPath, "config", "", "path to .archscope.json (default: .archscope.json in cwd)")
	fs.StringVar(&o.ref, "ref", "", "git ref for remote URLs (branch/tag/sha)")
	fs.IntVar(&o.depth, "depth", 0, "clone depth for remote URLs; 0 = full history")
	fs.BoolVar(&langPlatforms, "lang-platforms", false, "group all files of a language into one platform tab (shorthand for --group-by=language)")
	fs.BoolVar(&o.renderModules, "render-modules", false, "include the Modules & Microservices section and its CDN-loaded graphs (omitted by default)")
	fs.StringVar(&o.failOn, "fail-on", "", "exit 2 when findings exist at or above threshold: low | medium | high")
	fs.StringVar(&o.groupBy, "group-by", "", "how to group platform tabs: language | folder | gitrepo (default: auto-detected from .git count, prompts interactively when 2+ repos are found)")
	fs.BoolVar(&o.noGitPull, "no-git-pull", false, "review mode: don't fetch, switch to the reviewed branch or fast-forward branches — review the repository exactly as it is")
	fs.BoolVar(&o.scanAllFiles, "scan-all-files", false, "also scan git-submodule (third-party/vendored) directories, skipped by default")

	fs.StringVar(&o.evolutionSpec, "evolution", "", "compare Programming Culture now vs. git history, comma- or space-separated: 2w | 1m | 3m | last-tag | YYYY-MM-DD | <commit> | auto (= 2w,1m,last-tag)")

	fs.StringVar(&o.reviewRef, "review", "", "review mode: Evolution since a commit or branch (merge-base, like a merge request diff) with per-issue GitLab \"MR with line\" buttons; bare --review (or auto) = the local default branch (origin/HEAD, main, master, develop); \"last-commit\" = HEAD~1")

	fs.StringVar(&o.againstRef, "against", "", "review mode: compare the branch under review with this branch instead of the one you are on (e.g. --review feat/x --against main)")

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

	switch strings.ToLower(o.failOn) {
	case "", "low", "medium", "high":
	default:
		fmt.Fprintf(os.Stderr, "archscope: unknown --fail-on %q (want low | medium | high)\n", o.failOn)
		os.Exit(1)
	}

	o.groupBy = strings.ToLower(strings.TrimSpace(o.groupBy))
	switch o.groupBy {
	case "", "language", "folder", "gitrepo":
	default:
		fmt.Fprintf(os.Stderr, "archscope: unknown --group-by %q (want language, folder, or gitrepo)\n", o.groupBy)
		os.Exit(1)
	}
	if langPlatforms && o.groupBy == "" {
		o.groupBy = "language"
	}

	browserName = browserFlag
	specPaths = splitSpecs(strings.Join(specFlag, ","))
	inspectPaths = splitSpecs(strings.Join(inspectFlag, ","))
	if browserFlag != "" {
		o.open = true
	}

	if err := run(o); err != nil {
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

// preflightReview resolves the --review ref (and --against) against the repository
// before the scan starts. It returns an error — printed by main, exit status 1 —
// when the path is not inside a git repository or the ref is not a commit/branch
// there (local or on a remote), so nothing is scanned for a review that can't run.
func preflightReview(path, reviewRef, againstRef string) ([]string, error) {
	repo, _, err := evolution.Toplevel(path)
	if err != nil {
		return nil, fmt.Errorf("archscope: review mode needs a git repository, but %s is not inside one: %v", path, err)
	}
	spec := evolution.ReviewPrefix + reviewRef
	if againstRef != "" {
		spec += "@@" + againstRef
	}
	ref, err := evolution.Resolve(repo, spec, time.Now())
	if err != nil {
		return nil, fmt.Errorf("archscope: cannot review %q — %v\n  Nothing was scanned. Check the branch/commit name (`git branch -a`), `git fetch` if it only exists on the remote, or pass the MR's source branch name", reviewRef, err)
	}
	var changed []string
	for _, f := range evolution.ChangedFiles(repo, ref.SHA, ref.HeadSHA) {
		changed = append(changed, filepath.Join(repo, filepath.FromSlash(f.Path)))
	}
	return changed, nil
}

// runOptions is what the command line asks one analysis run to do.
type runOptions struct {
	target, ref, cfgPath, outputDir, format, failOn, groupBy, evolutionSpec, reviewRef, againstRef string
	depth                                                                                          int
	open, renderModules, scanAllFiles, noGitPull                                                   bool
}

// run executes the full analysis. Deferred cleanup (clone temp dir removal)
// fires on every return path because os.Exit in main would bypass it.
func run(o runOptions) error {
	cfg := config.Load(o.cfgPath)
	cfg.SpecPaths = specPaths
	cfg.InspectPaths = inspectPaths
	if o.outputDir == "" {
		o.outputDir = cfg.Output.Dir
	}
	if o.format == "" {
		o.format = cfg.Output.Format
	}
	// Wire Fetch config defaults when CLI flags were not provided.
	if o.ref == "" {
		o.ref = cfg.Fetch.Ref
	}
	if o.depth == 0 && cfg.Fetch.Depth > 0 {
		o.depth = cfg.Fetch.Depth
	}
	if o.scanAllFiles {
		cfg.ScanAllFiles = true
	}
	if o.renderModules {
		cfg.RenderModules = true
	}

	src := fetch.FromArg(o.target, o.ref, o.depth)
	resolved, err := fetch.Resolve(src)
	if err != nil {
		return fmt.Errorf("archscope: %w", err)
	}
	defer resolved.Cleanup() //nolint:errcheck // best-effort removal of the clone's temp dir

	// Review mode needs the ref to exist: check it before scanning anything, so a
	// typo'd branch or MR name fails in seconds instead of after a full analysis.
	if o.reviewRef != "" && !o.noGitPull && !resolved.WasClone {
		// Fetch, switch to the reviewed branch and bring it and its target branch up to
		// date, so the diff is the merge request's own. --no-git-pull skips all of it.
		if root, _, err := evolution.Toplevel(resolved.Path); err == nil {
			if sr := evolution.SyncForReview(root, o.reviewRef, o.againstRef, func(m string) { fmt.Println(" → " + m) }); sr.Against != "" {
				o.againstRef = sr.Against
			}
		}
	}
	if o.reviewRef != "" {
		changed, err := preflightReview(resolved.Path, o.reviewRef, o.againstRef)
		if err != nil {
			return err
		}
		cfg.ReviewChanged = changed // keep only the platforms the change touches
	}

	// Decide how platform tabs are grouped. An explicit --group-by (or its
	// --lang-platforms shorthand) always wins; otherwise the choice depends on
	// how many git repositories live under the target: a single repo (or
	// none) is one project, not a monorepo of independent services, so it
	// defaults to grouping by language regardless of how many languages are
	// present; 2+ repos is a real "which way do you want this sliced"
	// question, asked interactively when possible.
	if o.groupBy == "" {
		gitRepos := scanner.DiscoverGitRepos(resolved.Path, cfg.ExcludePaths)
		switch {
		case len(gitRepos) <= 1:
			fmt.Println("archscope: single project (0-1 git repositories) — grouping platform tabs by language (pass --group-by to override)")
			o.groupBy = "language"
		default:
			o.groupBy = promptGroupingMode(len(gitRepos))
		}
	}
	applyGroupBy(&cfg, o.groupBy)

	pipelineStart := time.Now()
	res, err := result.RunWithProgress(resolved.Path, cfg, func(msg string) {
		fmt.Printf(" → [%5.1fs] %s\n", time.Since(pipelineStart).Seconds(), msg)
	})
	if err != nil {
		return fmt.Errorf("archscope: analysis failed: %w", err)
	}
	if resolved.WasClone {
		res.IsRemote = true
		res.SourceURL = o.target
	}

	progressFn := func(msg string) {
		fmt.Printf(" → [%5.1fs] %s\n", time.Since(pipelineStart).Seconds(), msg)
	}
	specs := evolution.ParseSpecs(o.evolutionSpec)
	switch {
	case o.reviewRef != "":
		res.Evolution = result.RunReview(res, cfg, o.reviewRef, o.againstRef, specs, reporthtml.CultureScores, progressFn)
	case len(specs) > 0:
		res.Evolution = result.RunEvolution(res, cfg, specs, reporthtml.CultureScores, progressFn)
	}

	printCapabilityTable(res)

	if err := os.MkdirAll(o.outputDir, 0o755); err != nil {
		return fmt.Errorf("archscope: cannot create output dir: %w", err)
	}

	name := strings.ReplaceAll(res.ProjectName, string(filepath.Separator), "_")
	if name == "" {
		name = "report"
	}

	// Normalize format: "both" is a legacy alias for "html,sarif"; empty defaults to "html".
	fmtStr := strings.ToLower(strings.TrimSpace(o.format))
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
		outPath := filepath.Join(o.outputDir, name+em.Ext())
		if err := em.Write(res, outPath); err != nil {
			return fmt.Errorf("archscope: %s write failed: %w", strings.ToUpper(id), err)
		}
		fmt.Printf("%-6s→ %s\n", strings.ToUpper(id), outPath)
		if em.Ext() == ".html" && reportPath == "" {
			reportPath = outPath
		}
	}

	if o.open && reportPath != "" {
		abs, _ := filepath.Abs(reportPath)
		openInBrowser(abs)
	}

	// F11: exit 2 when --fail-on threshold is met.
	if o.failOn != "" {
		threshold := failOnRank(strings.ToLower(o.failOn))
		for _, rr := range res.Security {
			if rr.Passed() {
				continue
			}
			if failOnRank(strings.ToLower(string(rr.Rule.Severity))) >= threshold {
				return &exitCodeError{
					code: 2,
					msg:  fmt.Sprintf("archscope: findings at or above %q threshold — exit 2", o.failOn),
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
  --spec <file>       OpenAPI spec to analyse the code against (comma-separated or repeated); added to the specs found in the tree
  --inspect <file>    saved "celery inspect registered|scheduled" / "rabbitmqctl list_queues|list_exchanges|list_bindings" output (comma-separated or repeated)
  --browser <name>    open it in that browser instead of the default (chrome | firefox | safari | edge | brave | opera | <app>); implies --open
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
  --review [<ref>]    review mode (bare = against the local default branch: origin/HEAD, main, master, develop): Evolution since a commit/branch (merge-base, like an MR diff) plus GitLab
                      "MR with line" buttons on every introduced issue; "last-commit" = HEAD~1
  --no-git-pull       review mode: don't fetch, switch to the reviewed branch or fast-forward branches (default: do)
  --against <ref>     with --review <branch>: compare that branch with <ref> (default: the branch you are on)
  --evolution <list>  compare Programming Culture now vs. git history (adds a 📈 Evolution card + MD export).
                      Comma-separated: 2w | 14d | 1m | 3m | 1y | last-tag | YYYY-MM-DD | <commit/branch/tag>
                      or "auto" (= 2w,1m,last-tag). Several values: comma- or space-separated,
                      e.g. --evolution 1m 2w  (3 points: 1 month ago -> 2 weeks ago -> now)
`)
}

// listFlag collects a repeated string flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// inspectPaths are the --inspect dumps (absolute).
var inspectPaths []string

// specPaths are the --spec files (absolute).
var specPaths []string

// splitSpecs turns the --spec value(s) into absolute paths.
func splitSpecs(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			if abs, err := filepath.Abs(p); err == nil {
				p = abs
			}
			out = append(out, p)
		}
	}
	return out
}

// browserName is the --browser choice ("" = the system default).
var browserName string

// browserCommand builds the command that opens path in the named browser, or
// in the system default when name is empty. Friendly names (chrome, firefox,
// safari, edge, brave) map to each OS's app or binary; anything else is passed
// through as an application name.
func browserCommand(goos, name, path string) *exec.Cmd {
	key := strings.ToLower(strings.TrimSpace(name))
	apps := map[string]string{"chrome": "Google Chrome", "firefox": "Firefox", "safari": "Safari", "edge": "Microsoft Edge", "brave": "Brave Browser", "opera": "Opera", "chromium": "Chromium", "arc": "Arc"}
	switch goos {
	case "darwin":
		if key == "" {
			return exec.Command("/usr/bin/open", path)
		}
		app := apps[key]
		if app == "" {
			app = name
		}
		return exec.Command("/usr/bin/open", "-a", app, path)
	case "linux":
		bin := "xdg-open"
		if key != "" {
			bin = map[string]string{"chrome": "google-chrome", "edge": "microsoft-edge", "brave": "brave-browser"}[key]
			if bin == "" {
				bin = key
			}
		}
		return exec.Command(bin, path)
	case "windows":
		if key == "" {
			return exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
		}
		exe := map[string]string{"chrome": "chrome", "edge": "msedge"}[key]
		if exe == "" {
			exe = key
		}
		return exec.Command("cmd", "/c", "start", "", exe, path)
	}
	return nil
}

func openInBrowser(path string) {
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(os.Stderr, "open: file not found: %s\n", path)
		return
	}
	fmt.Printf("open: %s\n", path)

	cmd := browserCommand(runtime.GOOS, browserName, path)
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
