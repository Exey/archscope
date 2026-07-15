package constructs

import (
	"fmt"
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
)

func init() { modules.Default.Register(Complexity{}) }

// Complexity is a heuristic Big-O "health" reading of how the codebase iterates.
// It estimates per-function time complexity from iteration nesting (nested
// for/while loops, nested higher-order closures like .map/.filter, and linear
// collection ops used inside a loop) and space complexity from collection
// allocations inside loops. Anything O(N²) or worse is surfaced as a violation
// with a source link; the score is the share of loop-bearing functions that
// stay O(N) or better. Everything is an approximation, surfaced as "health",
// not proof.
//
// Ported from ArchSwiftScope's ComplexityDetector; the Swift-only brace walk is
// generalized to every brace language ArchScope parses (Go, Kotlin, TS/JS,
// Rust, Java, C#, Swift). Indentation-only sources (Python) have no braces, so
// the walk finds no loop frames and they contribute nothing — a graceful no-op
// rather than a false reading.
type Complexity struct{}

func (Complexity) ID() string                       { return "complexity" }
func (Complexity) Title() string                    { return "Complexity" }
func (Complexity) AppliesTo(languageID string) bool { return true } // universal

// CollectionUsage counts how often the classic collections appear in source.
type CollectionUsage struct {
	Array      int
	Dictionary int
	Set        int
	Sequence   int
	Lazy       int // .lazy modifier, not its own collection
}

func (u CollectionUsage) Total() int { return u.Array + u.Dictionary + u.Set + u.Sequence }
func (u CollectionUsage) IsEmpty() bool {
	return u.Total() == 0 && u.Lazy == 0
}

// Violation is one function charged O(N²) or worse, for time or space.
type Violation struct {
	Symbol   string // enclosing function / type
	FilePath string
	Line     int // 1-based
	Order    int // 2 = O(N²), 3 = O(N³), …
	Reason   string
}

// bigO renders the complexity badge for the violation's order.
func (v Violation) bigO() string {
	switch {
	case v.Order <= 1:
		return "𝒪(n)"
	case v.Order == 2:
		return "𝒪(n²)"
	case v.Order == 3:
		return "𝒪(n³)"
	case v.Order == 4:
		return "𝒪(n⁴)"
	default:
		return "𝒪(nⁿ)"
	}
}

// ComplexityReport is the module output.
type ComplexityReport struct {
	Usage           CollectionUsage
	TimeViolations  []Violation
	SpaceViolations []Violation
	TimeHealth      int // 0–100
	SpaceHealth     int // 0–100
}

// HasData reports whether anything worth rendering was found.
func (r ComplexityReport) HasData() bool {
	return !r.Usage.IsEmpty() || len(r.TimeViolations) > 0 || len(r.SpaceViolations) > 0
}

// Analyze reads each file's stripped source and estimates per-function time and
// space complexity from iteration nesting.
func (Complexity) Analyze(files []*parser.ParsedFile) any {
	cache := newSourceCache()
	var usage CollectionUsage
	var timeCands, spaceCands []Violation
	iterationScopes := map[string]bool{} // (file\x01symbol) that contain ≥1 loop

	for _, f := range files {
		lines := cache.lines(f.FilePath)
		if lines == nil {
			continue
		}
		analyzeComplexity(lines, f.FilePath, &usage, &timeCands, &spaceCands, iterationScopes)
	}

	timeV := dedupViolations(timeCands)
	spaceV := dedupViolations(spaceCands)
	n := len(iterationScopes)
	return ComplexityReport{
		Usage:           usage,
		TimeViolations:  timeV,
		SpaceViolations: spaceV,
		TimeHealth:      cleanRatioHealth(len(timeV), n),
		SpaceHealth:     cleanRatioHealth(len(spaceV), n),
	}
}

// ── aggregation ──────────────────────────────────────────────────────────────

// dedupViolations keeps one violation per (file, symbol): the worst order, and
// among equal orders the first (structural) reason.
func dedupViolations(cands []Violation) []Violation {
	best := map[string]Violation{}
	for _, c := range cands {
		key := c.FilePath + "\x01" + c.Symbol
		if cur, ok := best[key]; ok && cur.Order >= c.Order {
			continue
		}
		best[key] = c
	}
	out := make([]Violation, 0, len(best))
	for _, v := range best {
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order > out[j].Order
		}
		if out[i].Symbol != out[j].Symbol {
			return out[i].Symbol < out[j].Symbol
		}
		return out[i].Line < out[j].Line
	})
	return out
}

// cleanRatioHealth is the share of loop-bearing functions that stay clean — a
// density, so the score means the same in a 5-file tool and a 5,000-file repo.
func cleanRatioHealth(violating, total int) int {
	if total <= 0 {
		return 100
	}
	clean := total - violating
	if clean < 0 {
		clean = 0
	}
	return int(float64(clean)/float64(total)*100 + 0.5)
}

// ── per-file structural analysis ─────────────────────────────────────────────

type cxFrame struct {
	isLoop  bool
	name    string
	hasName bool
}

// analyzeComplexity walks braces in one file's stripped lines, tracking loop
// nesting depth per enclosing symbol and emitting O(N²)+ violations.
func analyzeComplexity(lines []string, filePath string, usage *CollectionUsage,
	time, space *[]Violation, iterationScopes map[string]bool) {

	var stack []cxFrame
	pending := ""

	loopDepth := func() int {
		d := 0
		for _, f := range stack {
			if f.isLoop {
				d++
			}
		}
		return d
	}
	currentSymbol := func() string {
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].hasName {
				return stack[i].name
			}
		}
		return "(top level)"
	}

	for li, line := range lines {
		if line == "" {
			continue
		}
		countCollections(line, usage)

		depthAtStart := loopDepth()
		if depthAtStart >= 1 {
			if op := linearOp(line); op != "" {
				*time = append(*time, Violation{currentSymbol(), filePath, li + 1,
					depthAtStart + 1, op + " inside loop"})
			}
			if alloc := allocation(line); alloc != "" {
				*space = append(*space, Violation{currentSymbol(), filePath, li + 1,
					depthAtStart + 1, "allocates " + alloc + " inside loop"})
			}
		}

		segStart := 0
		for i := 0; i < len(line); i++ {
			switch line[i] {
			case '{':
				segText := line[segStart:i]
				if pending != "" {
					segText = pending + " " + segText
				}
				pending = ""
				isLoop, label, name, hasName := classifyBrace(segText)
				if isLoop {
					iterationScopes[filePath+"\x01"+currentSymbol()] = true
					newDepth := loopDepth() + 1
					if newDepth >= 2 {
						*time = append(*time, Violation{currentSymbol(), filePath, li + 1,
							newDepth, label})
					}
				}
				stack = append(stack, cxFrame{isLoop: isLoop, name: name, hasName: hasName})
				segStart = i + 1
			case '}':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				segStart = i + 1
				pending = ""
			case ';':
				segStart = i + 1
				pending = ""
			}
		}
		if segStart < len(line) {
			leftover := line[segStart:]
			if pending != "" {
				leftover = pending + " " + leftover
			}
			if len(leftover) > 500 {
				leftover = leftover[len(leftover)-500:]
			}
			pending = leftover
		}
	}
}

// ── line classification ──────────────────────────────────────────────────────
//
// Go's regexp (RE2) has no lookbehind/lookahead, so keyword boundaries use a
// leading (^|[^\w.]) group (rejecting a preceding word char or '.') and a
// trailing \b, reproducing the Swift patterns' (?<![\w.])…(?![\w]).

var (
	reLoopKw    = regexp.MustCompile(`(^|[^\w.])(for|while|repeat|loop|foreach)\b`)
	reControlKw = regexp.MustCompile(`(^|[^\w.])(if|guard|switch|else|do|catch|when)\b`)
	reHOF       = regexp.MustCompile(`\.(map|filter|forEach|compactMap|flatMap|reduce|sorted|first|firstIndex|last|contains|allSatisfy|min|max|drop|dropFirst|dropLast|prefix|suffix|partition|split|reversed)\b[^{}]*$`)
	reFunc      = regexp.MustCompile(`(^|[^\w.])(?:func|fn|fun|function)\s+(\w+)`)
	reType      = regexp.MustCompile(`(^|[^\w.])(?:class|struct|enum|actor|extension|interface|trait|object|impl)\s+(\w+)`)
	reInit      = regexp.MustCompile(`(^|[^\w.])init[?!]?\s*[(<]`)
	reSubscript = regexp.MustCompile(`(^|[^\w.])subscript\s*[(<]`)
	reComputed  = regexp.MustCompile(`(^|[^\w.])(?:var|val)\s+(\w+)\s*:\s*[^={]+$`)
)

// classifyBrace classifies the brace whose preceding segment text is seg.
func classifyBrace(seg string) (isLoop bool, label, name string, hasName bool) {
	if m := reLoopKw.FindStringSubmatch(seg); m != nil {
		return true, "nested " + m[2] + " loop", "", false
	}
	// A control-flow brace (if/guard/switch/…) is not a loop, and means any
	// higher-order call on the line was a condition, not a trailing closure —
	// so don't mistake `if a.contains(x) {` for a loop.
	if reControlKw.MatchString(seg) {
		return false, "", "", false
	}
	if m := reHOF.FindStringSubmatch(seg); m != nil {
		return true, "." + m[1] + " {} closure", "", false
	}
	if m := reFunc.FindStringSubmatch(seg); m != nil {
		return false, "", m[2], true
	}
	if reInit.MatchString(seg) {
		return false, "", "init", true
	}
	if reSubscript.MatchString(seg) {
		return false, "", "subscript", true
	}
	if m := reComputed.FindStringSubmatch(seg); m != nil {
		return false, "", m[2], true
	}
	if m := reType.FindStringSubmatch(seg); m != nil {
		return false, "", m[2], true
	}
	return false, "", "", false
}

// linearOps are unambiguously-linear collection scans that compound when run
// inside a loop. Deliberately excludes .map/.reduce/.compactMap/.min/.max:
// those inside a loop are often over a small, unrelated collection
// (legitimately O(N+M)), so counting them here over-reports.
var linearOps = []struct{ needle, label string }{
	{".sorted(", ".sorted()"},
	{".filter(", ".filter()"},
	{".contains(where", ".contains(where:)"},
	{".first(where", ".first(where:)"},
	{".firstIndex(", ".firstIndex()"},
	{".allSatisfy(", ".allSatisfy()"},
}

func linearOp(line string) string {
	for _, op := range linearOps {
		if strings.Contains(line, op.needle) {
			return op.label
		}
	}
	return ""
}

// allocs are expressions that allocate a fresh collection.
var allocs = []struct{ needle, label string }{
	{".map(", "array"}, {".map {", "array"}, {".map{", "array"},
	{".filter(", "array"}, {".filter {", "array"}, {".filter{", "array"},
	{".compactMap", "array"}, {".flatMap", "array"},
	{".sorted", "array"}, {".reversed(", "array"}, {".joined(", "string/array"},
	{".reduce(into:", "collection"},
	{"Array(", "Array"}, {"Set(", "Set"}, {"Dictionary(", "Dictionary"},
	{"= [", "collection literal"},
}

func allocation(line string) string {
	for _, a := range allocs {
		if a.needle == "= [" {
			if containsAssignmentArrayLiteral(line) {
				return a.label
			}
		} else if strings.Contains(line, a.needle) {
			return a.label
		}
	}
	return ""
}

// containsAssignmentArrayLiteral is true when line assigns an array literal
// (`x = []`, `arr = [1, 2]`) — but not a comparison that merely contains the
// same three characters (`x == []`, `x != []`, `x >= []`).
func containsAssignmentArrayLiteral(line string) bool {
	from := 0
	for {
		i := strings.Index(line[from:], "= [")
		if i < 0 {
			return false
		}
		pos := from + i
		precededByCmp := pos > 0 && strings.IndexByte("=!<>", line[pos-1]) >= 0
		if !precededByCmp {
			return true
		}
		from = pos + 1
	}
}

// ── collection usage counting ────────────────────────────────────────────────

var (
	reArrayType = regexp.MustCompile(`:\s*\[[^:\[\]]+\]|->\s*\[[^:\[\]]+\]`)
	reDictType  = regexp.MustCompile(`:\s*\[[^\[\]]*:[^\[\]]*\]|->\s*\[[^\[\]]*:[^\[\]]*\]`)
	reArrayTok  = regexp.MustCompile(`\bArray\b`)
	reDictTok   = regexp.MustCompile(`\bDictionary\b`)
	reSetTok    = regexp.MustCompile(`\bSet\b`)
	reSeqTok    = regexp.MustCompile(`\b(?:Sequence|AnySequence|IteratorProtocol)\b`)
	reLazyTok   = regexp.MustCompile(`\.lazy\b`)
)

func countCollections(line string, u *CollectionUsage) {
	u.Array += len(reArrayTok.FindAllStringIndex(line, -1)) + len(reArrayType.FindAllStringIndex(line, -1))
	u.Dictionary += len(reDictTok.FindAllStringIndex(line, -1)) + len(reDictType.FindAllStringIndex(line, -1))
	u.Set += len(reSetTok.FindAllStringIndex(line, -1))
	u.Sequence += len(reSeqTok.FindAllStringIndex(line, -1))
	u.Lazy += len(reLazyTok.FindAllStringIndex(line, -1))
}

// ── rendering ────────────────────────────────────────────────────────────────

// SummaryCards surfaces the time/space health percentages in the panel header.
func (Complexity) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(ComplexityReport)
	if !ok || !r.HasData() {
		return nil
	}
	return []modules.SummaryCard{
		{Num: strconv.Itoa(r.TimeHealth) + "%", Label: "time health"},
		{Num: strconv.Itoa(r.SpaceHealth) + "%", Label: "space health"},
	}
}

// RenderMarkdown renders the health scores and violations as markdown.
func (Complexity) RenderMarkdown(res any) string {
	r, ok := res.(ComplexityReport)
	if !ok || !r.HasData() {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**Time health:** %d/100 · **Space health:** %d/100\n\n", r.TimeHealth, r.SpaceHealth)
	writeViolTable := func(title string, vs []Violation) {
		if len(vs) == 0 {
			return
		}
		fmt.Fprintf(&b, "%s\n\n| Big-O | Symbol | Reason | Location |\n|-------|--------|--------|----------|\n", title)
		for i, v := range vs {
			if i == 20 {
				fmt.Fprintf(&b, "| | | | +%d more |\n", len(vs)-20)
				break
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s:%d |\n", v.bigO(), v.Symbol, v.Reason, baseName(v.FilePath), v.Line)
		}
		b.WriteString("\n")
	}
	writeViolTable("Time-complexity hotspots", r.TimeViolations)
	writeViolTable("Space-complexity hotspots", r.SpaceViolations)
	return b.String()
}

// RenderHTML renders the two health bars, collection-usage chips, and the
// time/space violation tables with vscode links.
func (Complexity) RenderHTML(res any) string {
	r, ok := res.(ComplexityReport)
	if !ok || !r.HasData() {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="as-cx">`)

	// Health gauges.
	b.WriteString(`<div class="as-cx__health">`)
	writeGauge(&b, "⏱️ Time O-Health", r.TimeHealth)
	writeGauge(&b, "💾 Space O-Health", r.SpaceHealth)
	b.WriteString(`</div>`)

	// Collection-usage chips.
	if !r.Usage.IsEmpty() {
		b.WriteString(`<div class="as-cx__usage">`)
		for _, c := range []struct {
			label string
			n     int
		}{
			{"Array", r.Usage.Array}, {"Dictionary", r.Usage.Dictionary},
			{"Set", r.Usage.Set}, {"Sequence", r.Usage.Sequence}, {".lazy", r.Usage.Lazy},
		} {
			if c.n > 0 {
				fmt.Fprintf(&b, `<span class="as-cx__chip">%s <b>×%d</b></span>`, html.EscapeString(c.label), c.n)
			}
		}
		b.WriteString(`</div>`)
	}

	writeViolations(&b, "Time-complexity hotspots", r.TimeViolations)
	writeViolations(&b, "Space-complexity hotspots", r.SpaceViolations)

	b.WriteString(`</div>`)
	return b.String()
}

func writeGauge(b *strings.Builder, label string, score int) {
	col := healthColor(score)
	fmt.Fprintf(b, `<div class="as-cx__gauge"><div class="as-cx__glabel"><span>%s</span><span style="color:%s;font-weight:600">%d%%</span></div>`,
		html.EscapeString(label), col, score)
	fmt.Fprintf(b, `<div class="as-cx__bar"><div class="as-cx__fill" style="width:%d%%;background:%s"></div></div></div>`, score, col)
}

// maxViolationsShown caps a violation table so a pathological file can't produce
// an unbounded list.
const maxViolationsShown = 25

func writeViolations(b *strings.Builder, title string, vs []Violation) {
	if len(vs) == 0 {
		return
	}
	fmt.Fprintf(b, `<div class="as-cx__viol-title">%s <span class="as-count">(%d)</span></div>`,
		html.EscapeString(title), len(vs))
	b.WriteString(`<table class="as-table as-cx__table"><thead><tr><th>Big-O</th><th>Symbol</th><th>Reason</th><th>Location</th></tr></thead><tbody>`)
	for i, v := range vs {
		if i == maxViolationsShown {
			fmt.Fprintf(b, `<tr><td colspan="4" class="as-cx__more">… and %d more</td></tr>`, len(vs)-maxViolationsShown)
			break
		}
		loc := occurrenceLink(fmt.Sprintf("%s:%d", baseName(v.FilePath), v.Line), v.FilePath, v.Line)
		fmt.Fprintf(b, `<tr><td><span class="as-cx__bigo as-cx__bigo--%d">%s</span></td><td class="mono">%s</td><td>%s</td><td class="mono">%s</td></tr>`,
			minInt(v.Order, 4), html.EscapeString(v.bigO()), html.EscapeString(v.Symbol), html.EscapeString(v.Reason), loc)
	}
	b.WriteString(`</tbody></table>`)
}

func healthColor(score int) string {
	switch {
	case score >= 75:
		return "var(--good)"
	case score >= 50:
		return "var(--warn)"
	default:
		return "var(--crit)"
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
