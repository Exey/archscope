// codestructure.go is a language-agnostic reading of low-level code-shape
// health, rewriting the metrics ~/xlizard's SourceMonitor-style analyzer
// computes for C-like sources (comment density, block-nesting depth,
// preprocessor-directive density, parameter count) against ArchScope's own
// universal brace-based line scanner, so they work across every brace
// language ArchScope parses (Go, Kotlin, TS/JS, Rust, Java, C#, Swift).
// Indentation-only sources (Python) have no braces to walk, so — mirroring
// Complexity's own documented limitation — they contribute no per-function
// offenders here, a graceful no-op rather than a false reading.
//
// On top of the per-function/per-file metrics, this also reads a folder-
// layout smell purely from the platform's own scanned file paths (no extra
// disk walk): folders holding an unusually large number of files, folders
// that hold only a single file each (over-fragmentation), and "container"
// folders that hold no files of their own, only subfolders — the common
// leftover-refactor clutter pattern. Everything here is a heuristic read of
// scanned source, not a verdict.
package constructs

import (
	"fmt"
	"html"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/security"
)

func init() { modules.Default.Register(CodeStructure{}) }

// Thresholds above which a function/folder is flagged. Chosen to match common
// lint-style conventions (lizard/SourceMonitor defaults), not hard limits.
const (
	csMaxParams          = 5  // more parameters than this is a smell
	csMaxNestDepth       = 4  // deeper block nesting than this is a smell
	csOvercrowdedFolder  = 30 // more files than this in one folder is a smell
	csManyEmptyFolders   = 3  // this many container-only folders is a smell
	csManySingleFileDirs = 10 // this many one-file folders is a smell
)

// MaxNestDepth exports csMaxNestDepth for cross-package scoring (Programming
// Culture's Code Quality dimension folds Code Structure's nesting signal in).
const MaxNestDepth = csMaxNestDepth

// CodeStructure is the universal low-level code-shape detector.
type CodeStructure struct{}

func (CodeStructure) ID() string                       { return "codestructure" }
func (CodeStructure) Title() string                    { return "Code Structure" }
func (CodeStructure) AppliesTo(languageID string) bool { return true } // universal

// CSFuncOffender is one function that crossed a parameter-count or
// nesting-depth threshold, or (for WorstNest) simply the deepest one found.
type CSFuncOffender struct {
	Symbol   string
	FilePath string
	Line     int
	Value    int
}

// CSFolderStat is one folder with an unusual file count.
type CSFolderStat struct {
	Path  string
	Count int
}

// CSAnyUsage is one TS/JS file's count of loose `any` / `object` type
// annotations — the escape hatches that switch off static typing.
type CSAnyUsage struct {
	FilePath  string
	FirstLine int // line of the first occurrence, for the deep link
	AnyCount  int
	ObjCount  int
}

// Total is the file's combined loose-type count.
func (u CSAnyUsage) Total() int { return u.AnyCount + u.ObjCount }

// reLooseAny / reLooseObject match `any` and `object`/`Object` in TypeScript
// *type* position — after `:` `<` `,` `|` `&` or `as` — so a variable or
// property that merely happens to be named "any" is not counted, and neither
// is `Object.keys(...)`. Applied to comment/string-stripped lines.
var (
	reLooseAny    = regexp.MustCompile(`(?::|<|,|\||&|\bas)\s*any\b`)
	reLooseObject = regexp.MustCompile(`(?::|<|,|\||&|\bas)\s*(?:object|Object)\b`)
)

// csTSExtensions are the file extensions the loose-type scan runs on.
var csTSExtensions = map[string]bool{
	".ts": true, ".tsx": true, ".mts": true, ".cts": true,
	".js": true, ".jsx": true, ".mjs": true, ".cjs": true,
}

// csMaxAnyListShown caps the loose-type file list.
const csMaxAnyListShown = 15

// CodeStructureReport is the module output.
type CodeStructureReport struct {
	HighParamFuncs []CSFuncOffender // params > csMaxParams
	DeepNestFuncs  []CSFuncOffender // nesting > csMaxNestDepth
	WorstNest      CSFuncOffender   // deepest nesting found anywhere (zero Value = none)

	CommentPercent    int // 0–100, lines that are comment-only ÷ total lines
	PreprocDirectives int // total #define/#include/#if.../Swift #if.../… lines

	LooseTypeTotal int          // total `any` + `object` type annotations (TS/JS only)
	LooseTypeFiles []CSAnyUsage // per-file loose-type counts, sorted worst-first

	BugIssues   []CSIssue // 🐛 Suspicious code: Go bug-class checks (dupSubExpr, badLock, offBy1…)
	DupIssues   []CSIssue // 👯 Duplicate code: identical branch bodies, duplicate case labels
	HookIssues  []CSIssue // ⚛️ React hooks & state (TS/JS): missing deps, effect loops, direct mutation…
	ReactIssues []CSIssue // 🧩 React components (TS/JS): size, props, JSX depth, prop drilling

	OvercrowdedFolders []CSFolderStat // folders with > csOvercrowdedFolder files
	EmptyFolders       []string       // container-only folders (no files of their own)
	SingleFileFolders  []string       // one-file folders, only set when > csManySingleFileDirs

	scanned bool
}

// HasData reports whether any file was successfully read for this platform.
func (r CodeStructureReport) HasData() bool { return r.scanned }

// ReviewIssueCount is the number of suspicious-code, duplicate-code and React
// findings — everything this card surfaces as a review item.
func (r CodeStructureReport) ReviewIssueCount() int {
	return len(r.BugIssues) + len(r.DupIssues) + len(r.HookIssues) + len(r.ReactIssues)
}

// IssuePoints weighs those findings for the Code Quality score: HIGH 5, MEDIUM
// 2, LOW 0.5 (unscored advice such as "use isEmpty" must not drown real bugs).
func (r CodeStructureReport) IssuePoints() float64 {
	var pts float64
	for _, set := range [][]CSIssue{r.BugIssues, r.DupIssues, r.HookIssues, r.ReactIssues} {
		h, m, l := issueSevCounts(set)
		pts += float64(h)*5 + float64(m)*2 + float64(l)*0.5
	}
	return pts
}

// HasFolderSmells reports whether any folder-layout issue was flagged.
func (r CodeStructureReport) HasFolderSmells() bool {
	return len(r.OvercrowdedFolders) > 0 || len(r.EmptyFolders) > 0 || len(r.SingleFileFolders) > 0
}

// reFuncSig finds a function/method declaration and the position of its
// parameter list's opening paren. Unlike the shared reFuncDecl (magic
// constants' symbol attribution), this also recognizes Go's receiver clause
// ("func (r *Foo) Bar(") so Go methods — the common case in this very
// codebase — aren't invisible to parameter/nesting counting.
var reFuncSig = regexp.MustCompile(`(^|[^\w.])(?:func(?:\s*\([^)]*\))?|fn|fun|function)\s+(\w+)\s*(\()`)

// csFuncRange is one function's brace-matched body range plus where its
// parameter list begins.
type csFuncRange struct {
	name    string
	start   int // line index of the declaration
	end     int // line index where the body closes
	parenAt int // byte offset in lines[start] of the parameter list's '('
}

// csFuncRanges finds every function declaration in lines and brace-matches its
// body, reusing the shared matchBraceEnd (pure brace counting, keyword-agnostic).
func csFuncRanges(lines []string) []csFuncRange {
	var out []csFuncRange
	for i, line := range lines {
		m := reFuncSig.FindStringSubmatchIndex(line)
		if m == nil {
			continue
		}
		end := matchBraceEnd(lines, i)
		if end < 0 {
			continue
		}
		out = append(out, csFuncRange{name: line[m[4]:m[5]], start: i, end: end, parenAt: m[6]})
	}
	return out
}

// nestDepthOf returns the deepest block nesting inside [start,end] relative to
// the function's own body (a flat function with no nested block is 0).
func nestDepthOf(lines []string, start, end int) int {
	depth, maxDepth := 0, 0
	for j := start; j <= end && j < len(lines); j++ {
		line := lines[j]
		for k := 0; k < len(line); k++ {
			switch line[k] {
			case '{':
				depth++
				if depth-1 > maxDepth {
					maxDepth = depth - 1
				}
			case '}':
				if depth > 0 {
					depth--
				}
			}
		}
	}
	return maxDepth
}

// paramCountAt extracts the parameter list starting at lines[start][parenAt]
// (its opening paren) — scanning forward across lines when the signature
// wraps — and counts its top-level comma-separated parameters.
func paramCountAt(lines []string, start, parenAt int) int {
	var sig strings.Builder
	depth := 0
	limit := start + 10 // bound how far a wrapped signature can scan
	for j := start; j < len(lines) && j <= limit; j++ {
		line := lines[j]
		from := 0
		if j == start {
			from = parenAt
		}
		done := false
		for k := from; k < len(line); k++ {
			c := line[k]
			switch c {
			case '(':
				depth++
				if depth == 1 {
					continue
				}
			case ')':
				depth--
				if depth == 0 {
					done = true
				}
			}
			if depth >= 1 {
				sig.WriteByte(c)
			}
			if done {
				break
			}
		}
		if done {
			break
		}
		sig.WriteByte(' ')
	}
	return countTopLevelCommas(sig.String())
}

// countTopLevelCommas counts comma-separated parameters in a parameter-list
// body, ignoring commas nested inside parens/brackets/braces/generics so a
// closure or generic-type parameter doesn't inflate the count.
func countTopLevelCommas(sig string) int {
	sig = strings.TrimSpace(sig)
	if sig == "" {
		return 0
	}
	depth := 0
	count := 1
	for i := 0; i < len(sig); i++ {
		switch sig[i] {
		case '(', '[', '<', '{':
			depth++
		case ')', ']', '>', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				count++
			}
		}
	}
	return count
}

// scanLooseTypes counts `any` and `object`/`Object` type annotations across a
// file's comment/string-stripped lines and records where the first one is.
func scanLooseTypes(filePath string, stripped []string) CSAnyUsage {
	u := CSAnyUsage{FilePath: filePath}
	for i, line := range stripped {
		anyN := len(reLooseAny.FindAllStringIndex(line, -1))
		objN := len(reLooseObject.FindAllStringIndex(line, -1))
		if anyN+objN == 0 {
			continue
		}
		if u.FirstLine == 0 {
			u.FirstLine = i + 1
		}
		u.AnyCount += anyN
		u.ObjCount += objN
	}
	return u
}

// Analyze reads each file's raw and comment/string-stripped lines and derives
// the parameter-count, nesting-depth, comment-density, preprocessor-density,
// and folder-layout signals.
func (CodeStructure) Analyze(files []*parser.ParsedFile) any {
	cache := newSourceCache()
	var rep CodeStructureReport
	var commentLines, totalLines int

	prod := make([]*parser.ParsedFile, 0, len(files))
	for _, f := range files {
		if !security.IsTestOrBenchPath(f.FilePath) {
			prod = append(prod, f)
		}
	}
	files = prod

	for _, f := range files {
		if isConstructDetectorFile(f.FilePath) {
			continue
		}
		stripped := cache.lines(f.FilePath)
		raw := cache.rawLines(f.FilePath)
		if stripped == nil || raw == nil {
			continue
		}
		rep.scanned = true
		totalLines += len(raw)

		for i, s := range stripped {
			if i >= len(raw) {
				break
			}
			trimmed := strings.TrimSpace(s)
			if trimmed == "" && strings.TrimSpace(raw[i]) != "" {
				commentLines++
				continue
			}
			// A directive/macro line (#define, #include, #if…, Swift's #if/
			// #available/#warning) survives stripping intact in languages
			// where '#' isn't a comment marker (readSource only blanks it to
			// "" for Python/Ruby/shell/YAML/TOML, where it IS a comment).
			if strings.HasPrefix(trimmed, "#") {
				rep.PreprocDirectives++
			}
		}

		if csTSExtensions[ext(f.FilePath)] {
			if u := scanLooseTypes(f.FilePath, stripped); u.Total() > 0 {
				rep.LooseTypeTotal += u.Total()
				rep.LooseTypeFiles = append(rep.LooseTypeFiles, u)
			}
		}

		if fe := ext(f.FilePath); csStringLang(fe) != csStrNone && csStringLang(fe) != csStrPython {
			masked := maskSource(raw, fe)
			rep.BugIssues = append(rep.BugIssues, scanBugSmells(f.FilePath, masked)...)
			rep.DupIssues = append(rep.DupIssues, scanDuplicateCode(f.FilePath, masked)...)
			h, c := scanReact(f.FilePath, masked)
			rep.HookIssues = append(rep.HookIssues, h...)
			rep.ReactIssues = append(rep.ReactIssues, c...)
		}

		for _, fr := range csFuncRanges(stripped) {
			nest := nestDepthOf(stripped, fr.start, fr.end)
			if nest > rep.WorstNest.Value {
				rep.WorstNest = CSFuncOffender{Symbol: fr.name, FilePath: f.FilePath, Line: fr.start + 1, Value: nest}
			}
			if nest > csMaxNestDepth {
				rep.DeepNestFuncs = append(rep.DeepNestFuncs,
					CSFuncOffender{Symbol: fr.name, FilePath: f.FilePath, Line: fr.start + 1, Value: nest})
			}
			if params := paramCountAt(stripped, fr.start, fr.parenAt); params > csMaxParams {
				rep.HighParamFuncs = append(rep.HighParamFuncs,
					CSFuncOffender{Symbol: fr.name, FilePath: f.FilePath, Line: fr.start + 1, Value: params})
			}
		}
	}

	if totalLines > 0 {
		rep.CommentPercent = int(float64(commentLines)/float64(totalLines)*100 + 0.5)
	}
	sort.SliceStable(rep.HighParamFuncs, func(i, j int) bool { return rep.HighParamFuncs[i].Value > rep.HighParamFuncs[j].Value })
	sort.SliceStable(rep.DeepNestFuncs, func(i, j int) bool { return rep.DeepNestFuncs[i].Value > rep.DeepNestFuncs[j].Value })
	sort.SliceStable(rep.LooseTypeFiles, func(i, j int) bool { return rep.LooseTypeFiles[i].Total() > rep.LooseTypeFiles[j].Total() })

	sortIssues(rep.BugIssues)
	sortIssues(rep.DupIssues)
	sortIssues(rep.HookIssues)
	sortIssues(rep.ReactIssues)
	analyzeFolderLayout(files, &rep)
	return rep
}

// analyzeFolderLayout groups files by their containing directory and flags
// three "trash" layout smells, derived purely from scanned file paths (no
// filesystem walk, so it works the same for a remote/cloned repo):
//
//   - overcrowded: a folder holding more than csOvercrowdedFolder files.
//   - container-only ("empty"): a folder that is the direct parent of a
//     populated folder but holds zero files of its own — the common
//     leftover-refactor wrapper folder. Git doesn't track truly empty
//     directories anyway, so this is the meaningful "empty folder" signal for
//     a scanned repo.
//   - single-file folders: when more than csManySingleFileDirs folders each
//     hold exactly one file — over-fragmentation.
func analyzeFolderLayout(files []*parser.ParsedFile, rep *CodeStructureReport) {
	counts := map[string]int{}
	parents := map[string]bool{}
	for _, f := range files {
		dir := filepath.Dir(f.FilePath)
		counts[dir]++
		if parent := filepath.Dir(dir); parent != dir {
			parents[parent] = true
		}
	}

	for dir, n := range counts {
		if n > csOvercrowdedFolder {
			rep.OvercrowdedFolders = append(rep.OvercrowdedFolders, CSFolderStat{Path: dir, Count: n})
		}
	}
	sort.SliceStable(rep.OvercrowdedFolders, func(i, j int) bool {
		return rep.OvercrowdedFolders[i].Count > rep.OvercrowdedFolders[j].Count
	})

	var singleFile []string
	for dir, n := range counts {
		if n == 1 {
			singleFile = append(singleFile, dir)
		}
	}
	if len(singleFile) > csManySingleFileDirs {
		sort.Strings(singleFile)
		rep.SingleFileFolders = singleFile
	}

	var empty []string
	for p := range parents {
		if counts[p] == 0 {
			empty = append(empty, p)
		}
	}
	if len(empty) >= csManyEmptyFolders {
		sort.Strings(empty)
		rep.EmptyFolders = empty
	}
}

// SummaryCards surfaces the comment-density and worst-nesting headline stats.
func (CodeStructure) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(CodeStructureReport)
	if !ok || !r.HasData() {
		return nil
	}
	cards := []modules.SummaryCard{
		{Num: strconv.Itoa(r.CommentPercent) + "%", Label: "comments"},
	}
	if r.WorstNest.Value > 0 {
		cards = append(cards, modules.SummaryCard{Num: strconv.Itoa(r.WorstNest.Value), Label: "max nesting"})
	}
	if r.LooseTypeTotal > 0 {
		cards = append(cards, modules.SummaryCard{Num: strconv.Itoa(r.LooseTypeTotal), Label: "any / object types"})
	}
	if n := r.ReviewIssueCount(); n > 0 {
		cards = append(cards, modules.SummaryCard{Num: strconv.Itoa(n), Label: "review issues"})
	}
	return cards
}

// RenderMarkdown renders the headline stats, offender tables, and folder
// smells as markdown.
func (CodeStructure) RenderMarkdown(res any) string {
	r, ok := res.(CodeStructureReport)
	if !ok || !r.HasData() {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**Comments:** %d%% · **Worst nesting:** %d", r.CommentPercent, r.WorstNest.Value)
	if r.PreprocDirectives > 0 {
		fmt.Fprintf(&b, " · **Preprocessor directives:** %d", r.PreprocDirectives)
	}
	if r.LooseTypeTotal > 0 {
		fmt.Fprintf(&b, " · **`any` / `object` types:** %d", r.LooseTypeTotal)
	}
	b.WriteString("\n\n")

	writeOffenders := func(title string, offenders []CSFuncOffender) {
		if len(offenders) == 0 {
			return
		}
		fmt.Fprintf(&b, "%s\n\n| Function | Value | Location |\n|----------|------:|----------|\n", title)
		for i, o := range offenders {
			if i == 20 {
				fmt.Fprintf(&b, "| | | +%d more |\n", len(offenders)-20)
				break
			}
			fmt.Fprintf(&b, "| %s | %d | %s:%d |\n", o.Symbol, o.Value, baseName(o.FilePath), o.Line)
		}
		b.WriteString("\n")
	}
	writeOffenders("High-parameter functions", r.HighParamFuncs)
	writeOffenders("Deeply nested functions", r.DeepNestFuncs)

	if len(r.LooseTypeFiles) > 0 {
		fmt.Fprintf(&b, "`any` / `object` types by file (%d total)\n\n| File | any | object | Location |\n|------|----:|-------:|----------|\n", r.LooseTypeTotal)
		for i, u := range r.LooseTypeFiles {
			if i == csMaxAnyListShown {
				fmt.Fprintf(&b, "| | | | +%d more |\n", len(r.LooseTypeFiles)-csMaxAnyListShown)
				break
			}
			fmt.Fprintf(&b, "| %s | %d | %d | %s:%d |\n", baseName(u.FilePath), u.AnyCount, u.ObjCount, baseName(u.FilePath), u.FirstLine)
		}
		b.WriteString("\n")
	}

	issuesMarkdown(&b, "🐛 Suspicious code (Go)", r.BugIssues, true)
	issuesMarkdown(&b, "👯 Duplicate code", r.DupIssues, true)
	issuesMarkdown(&b, "⚛️ React hooks & state", r.HookIssues, true)
	issuesMarkdown(&b, "🧩 React components", r.ReactIssues, true)

	if r.HasFolderSmells() {
		b.WriteString("Folder-structure smells:\n\n")
		for _, fs := range r.OvercrowdedFolders {
			fmt.Fprintf(&b, "- Overcrowded: `%s` (%d files)\n", fs.Path, fs.Count)
		}
		if len(r.EmptyFolders) > 0 {
			fmt.Fprintf(&b, "- %d container-only folder(s) with no files of their own\n", len(r.EmptyFolders))
		}
		if len(r.SingleFileFolders) > 0 {
			fmt.Fprintf(&b, "- %d folders holding a single file each\n", len(r.SingleFileFolders))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// csMaxOffendersShown caps an offender table so a pathological codebase can't
// produce an unbounded list.
const csMaxOffendersShown = 20

// RenderHTML renders the headline stats, offender tables, and folder smells.
func (CodeStructure) RenderHTML(res any) string {
	r, ok := res.(CodeStructureReport)
	if !ok || !r.HasData() {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="as-cs">`)

	writeCSHeader(&b, r)

	writeCSOffenders(&b, "params", "🔢", fmt.Sprintf("Functions with too many parameters (&gt; %d)", csMaxParams), "PARAMS", r.HighParamFuncs)
	writeCSOffenders(&b, "nest", "🪆", fmt.Sprintf("Deeply nested functions (&gt; %d levels)", csMaxNestDepth), "DEPTH", r.DeepNestFuncs)
	writeCSLooseTypes(&b, r.LooseTypeFiles, r.LooseTypeTotal)
	writeIssueSubcard(&b, "bug", "🐛", "Suspicious code (Go)", "Bug-class patterns from go-critic: identical operands, impossible conditions, off-by-one, missing return after http.Error, bad locks…", r.BugIssues, true, maxIssueExamples)
	writeIssueSubcard(&b, "dup", "👯", "Duplicate code", "Neighbouring if/else branches with the same body and repeated case labels.", r.DupIssues, true, maxIssueExamples)
	writeIssueSubcard(&b, "hooks", "⚛️", "React hooks & state", "Hook and state mistakes (ported from react-code-audit): missing dependencies, setState loops, in-place state mutation, derived state, index keys…", r.HookIssues, true, maxIssueExamples)
	writeIssueSubcard(&b, "react", "🧩", "React components", "Component size, prop count, JSX nesting depth and prop drilling.", r.ReactIssues, true, maxIssueExamples)

	if r.HasFolderSmells() {
		n := len(r.OvercrowdedFolders)
		if len(r.EmptyFolders) > 0 {
			n++
		}
		if len(r.SingleFileFolders) > 0 {
			n++
		}
		writeSubOpen(&b, "folders", "🗑️", "Folder structure smells", n, "")
		b.WriteString(`<ul class="as-cs__folders">`)
		for _, fs := range r.OvercrowdedFolders {
			fmt.Fprintf(&b, `<li>Overcrowded — <span class="mono">%s</span> (%d files)</li>`, html.EscapeString(fs.Path), fs.Count)
		}
		if n := len(r.SingleFileFolders); n > 0 {
			fmt.Fprintf(&b, `<li>%d folders hold a single file each — over-fragmented layout</li>`, n)
		}
		if n := len(r.EmptyFolders); n > 0 {
			fmt.Fprintf(&b, `<li>%d container-only folder(s) hold no files of their own, just subfolders</li>`, n)
		}
		b.WriteString(`</ul>`)
		writeSubClose(&b)
	}

	b.WriteString(`</div>`)
	return b.String()
}

// writeCSLooseTypes renders the top loose-`any`/`object`-type files as a table,
// laid out like the nesting/parameter offender tables.
func writeCSLooseTypes(b *strings.Builder, files []CSAnyUsage, total int) {
	if len(files) == 0 {
		return
	}
	writeSubOpen(b, "loose", "🕳️", fmt.Sprintf(`Loose <span class="mono">any</span> / <span class="mono">object</span> types <span class="as-count">in %d files</span>`, len(files)), total, "")
	b.WriteString(`<table class="as-table as-cs__table"><thead><tr><th>File</th><th>any</th><th>object</th><th>Location</th></tr></thead><tbody>`)
	for i, u := range files {
		if i == csMaxAnyListShown {
			fmt.Fprintf(b, `<tr><td colspan="4" class="as-cs__more">… and %d more</td></tr>`, len(files)-csMaxAnyListShown)
			break
		}
		loc := occurrenceLink(fmt.Sprintf("%s:%d", baseName(u.FilePath), u.FirstLine), u.FilePath, u.FirstLine)
		fmt.Fprintf(b, `<tr><td class="mono">%s</td><td class="mono">%d</td><td class="mono">%d</td><td class="mono">%s</td></tr>`,
			html.EscapeString(baseName(u.FilePath)), u.AnyCount, u.ObjCount, loc)
	}
	b.WriteString(`</tbody></table>`)
	writeSubClose(b)
}

// csTone colours a findings minicard by its worst severity.
func csTone(h, m, l int) string {
	switch {
	case h > 0:
		return "var(--crit)"
	case m > 0:
		return "var(--bad)"
	case l > 0:
		return "var(--warn)"
	}
	return "var(--good)"
}

// nestTarget links the worst-nesting minicard to the nesting subcard when one exists.
func nestTarget(r CodeStructureReport) string {
	if len(r.DeepNestFuncs) > 0 {
		return "nest"
	}
	return ""
}

// writeCSMini renders one header minicard: a big value, its label and an
// optional muted sub-line, with a coloured accent edge.
func writeCSMini(b *strings.Builder, val, label, sub, color, target string) {
	cls, attr := "as-cs__mini", ""
	if target != "" {
		cls, attr = "as-cs__mini as-cs__mini--link", ` data-target="`+html.EscapeString(target)+`" title="Jump to the details"`
	}
	fmt.Fprintf(b, `<div class="%s"%s style="--mini:%s"><span class="as-cs__mini-val">%s</span><span class="as-cs__mini-label">%s</span>`,
		cls, attr, color, html.EscapeString(val), html.EscapeString(label))
	if sub != "" {
		fmt.Fprintf(b, `<span class="as-cs__mini-sub">%s</span>`, html.EscapeString(sub))
	}
	b.WriteString(`</div>`)
}

// writeCSHeader renders the card's header as two rows of minicards: the code-shape
// metrics, then one summary minicard per findings subcard below (with its
// HIGH · MEDIUM · LOW split) so the whole card reads at a glance.
func writeCSHeader(b *strings.Builder, r CodeStructureReport) {
	b.WriteString(`<div class="as-cs__minis-title">Code shape</div><div class="as-cs__minis">`)
	writeCSMini(b, strconv.Itoa(r.CommentPercent)+"%", "comments", "of all lines", healthColor(r.CommentPercent), "")
	if r.WorstNest.Value > 0 {
		writeCSMini(b, strconv.Itoa(r.WorstNest.Value), "worst nesting", r.WorstNest.Symbol, healthColor(100-r.WorstNest.Value*15), nestTarget(r))
	}
	if n := len(r.DeepNestFuncs); n > 0 {
		writeCSMini(b, strconv.Itoa(n), "deeply nested", fmt.Sprintf("functions > %d levels", csMaxNestDepth), healthColor(100-n*5), "nest")
	}
	if n := len(r.HighParamFuncs); n > 0 {
		writeCSMini(b, strconv.Itoa(n), "many parameters", fmt.Sprintf("functions > %d params", csMaxParams), healthColor(100-n*5), "params")
	}
	if r.LooseTypeTotal > 0 {
		writeCSMini(b, strconv.Itoa(r.LooseTypeTotal), "any / object types", fmt.Sprintf("in %d files", len(r.LooseTypeFiles)), healthColor(100-r.LooseTypeTotal*2), "loose")
	}
	if r.PreprocDirectives > 0 {
		writeCSMini(b, strconv.Itoa(r.PreprocDirectives), "preprocessor", "directives", "var(--text-dim)", "")
	}
	b.WriteString(`</div>`)

	type sum struct {
		key, icon, label string
		issues           []CSIssue
	}
	sums := []sum{
		{"bug", "🐛", "suspicious code", r.BugIssues},
		{"dup", "👯", "duplicate code", r.DupIssues},
		{"hooks", "⚛️", "React hooks & state", r.HookIssues},
		{"react", "🧩", "React components", r.ReactIssues},
	}
	var minis strings.Builder
	for _, sm := range sums {
		if len(sm.issues) == 0 {
			continue
		}
		h, m, l := issueSevCounts(sm.issues)
		writeCSMini(&minis, strconv.Itoa(len(sm.issues)), sm.icon+" "+sm.label, fmt.Sprintf("%dH · %dM · %dL", h, m, l), csTone(h, m, l), sm.key)
	}
	if r.HasFolderSmells() {
		n := len(r.OvercrowdedFolders)
		if len(r.EmptyFolders) > 0 {
			n++
		}
		if len(r.SingleFileFolders) > 0 {
			n++
		}
		writeCSMini(&minis, strconv.Itoa(n), "🗑️ folder smells", "layout", "var(--warn)", "folders")
	}
	if minis.Len() > 0 {
		b.WriteString(`<div class="as-cs__minis-title">Findings</div><div class="as-cs__minis">`)
		b.WriteString(minis.String())
		b.WriteString(`</div>`)
	}
}

func writeCSOffenders(b *strings.Builder, key, icon, title, valLabel string, offenders []CSFuncOffender) {
	if len(offenders) == 0 {
		return
	}
	writeSubOpen(b, key, icon, title, len(offenders), "")
	fmt.Fprintf(b, `<table class="as-table as-cs__table"><thead><tr><th>Function</th><th>%s</th><th>Location</th></tr></thead><tbody>`, valLabel)
	for i, o := range offenders {
		if i == csMaxOffendersShown {
			fmt.Fprintf(b, `<tr><td colspan="3" class="as-cs__more">… and %d more</td></tr>`, len(offenders)-csMaxOffendersShown)
			break
		}
		loc := occurrenceLink(fmt.Sprintf("%s:%d", baseName(o.FilePath), o.Line), o.FilePath, o.Line)
		fmt.Fprintf(b, `<tr><td class="mono">%s</td><td class="mono">%d</td><td class="mono">%s</td></tr>`,
			html.EscapeString(o.Symbol), o.Value, loc)
	}
	b.WriteString(`</tbody></table>`)
	writeSubClose(b)
}
