// algorithms.go is a universal detector for well-known algorithms implemented
// in a codebase — sorting, searching, graph/shortest-path, string matching,
// and classic numeric routines.
//
// Method. It adapts the central idea of the "Algorithm Identification in Source
// Code" project (~/algorithm-identification): classify a piece of code against a
// *known catalog* of algorithms for a functionality (sorting, searching,
// shortest-path, …). That project explores heavyweight classifiers — execution
// profiling (valgrind time/memory), MOSS similarity, tree/graph-kernel SVMs, and
// CodeBERT/GraphCodeBERT — none of which fit ArchScope's dependency-free, static,
// single-pass design. So the catalog-classification premise is kept while the
// signal is switched to the static, low-false-positive name convention used by
// the sibling designpattern/datastructures detectors: a function or type named
// `bubbleSort`, `dijkstra`, `binarySearch`, `kmpSearch`, … is almost always an
// implementation of that algorithm.
//
// Detection is token-based, not substring-based, to avoid classic false
// positives: an identifier is split into lowercase word tokens ("quickSort" →
// [quick, sort], "KMPSearch" → [kmp, search]) and matched against per-algorithm
// token signatures. Common-word algorithms require their functionality token
// too ({bubble, sort}, not bare "bubble") so `bubbleChart` is never mistaken for
// Bubble Sort; only distinctive proper-noun algorithms (dijkstra, kruskal, …)
// match on a single token.
package constructs

import (
	"fmt"
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
)

func init() { modules.Default.Register(Algorithms{}) }

// Algorithms is the universal algorithm detector.
type Algorithms struct{}

func (Algorithms) ID() string                       { return "algorithms" }
func (Algorithms) Title() string                    { return "Algorithms" }
func (Algorithms) AppliesTo(languageID string) bool { return true } // universal

// algoCategory groups detected algorithms by the functionality they implement,
// mirroring the reference project's sorting / searching / shortest-path split.
type algoCategory string

const (
	sorting   algoCategory = "Sorting"
	searching algoCategory = "Searching & Selection"
	graphAlg  algoCategory = "Graph · Shortest Path · Flow"
	strMatch  algoCategory = "String Matching"
	numeric   algoCategory = "Numeric & Classic"
)

// algoCategoryOrder fixes the display order.
var algoCategoryOrder = []algoCategory{sorting, searching, graphAlg, strMatch, numeric}

// algoCategoryIcon is the emoji shown before each category's as-sub heading.
var algoCategoryIcon = map[algoCategory]string{
	sorting:   "🔃",
	searching: "🔎",
	graphAlg:  "🕸️",
	strMatch:  "🔤",
	numeric:   "🔢",
}

// algoRule maps a token signature to a canonical algorithm name and category. A
// signature matches an identifier when either every token is present as a
// word token, OR the identifier's joined-lowercase form contains the tokens
// concatenated (so "aStarSearch", "astar_search" and "AStarSearch" all match
// {astar, search}). Rules are ranked most-specific-first (most tokens) in
// init() so "fibonacciSearch" resolves to Fibonacci Search, not Fibonacci.
type algoRule struct {
	tokens   []string
	joined   string // precomputed strings.Join(tokens, "")
	name     string
	category algoCategory
}

var algoRules = []algoRule{
	// ── Sorting ─────────────────────────────────────────────────────────────
	{tokens: []string{"bubble", "sort"}, name: "Bubble Sort", category: sorting},
	{tokens: []string{"isort"}, name: "Insertion Sort", category: sorting},
	{tokens: []string{"insertion", "sort"}, name: "Insertion Sort", category: sorting},
	{tokens: []string{"selection", "sort"}, name: "Selection Sort", category: sorting},
	{tokens: []string{"merge", "sort"}, name: "Merge Sort", category: sorting},
	{tokens: []string{"qsort"}, name: "Quicksort", category: sorting},
	{tokens: []string{"quick", "sort"}, name: "Quicksort", category: sorting},
	{tokens: []string{"heap", "sort"}, name: "Heapsort", category: sorting},
	{tokens: []string{"counting", "sort"}, name: "Counting Sort", category: sorting},
	{tokens: []string{"radix", "sort"}, name: "Radix Sort", category: sorting},
	{tokens: []string{"shell", "sort"}, name: "Shellsort", category: sorting},
	{tokens: []string{"bucket", "sort"}, name: "Bucket Sort", category: sorting},
	{tokens: []string{"tim", "sort"}, name: "Timsort", category: sorting},
	{tokens: []string{"comb", "sort"}, name: "Comb Sort", category: sorting},
	{tokens: []string{"cocktail", "sort"}, name: "Cocktail Shaker Sort", category: sorting},
	{tokens: []string{"gnome", "sort"}, name: "Gnome Sort", category: sorting},
	{tokens: []string{"pancake", "sort"}, name: "Pancake Sort", category: sorting},
	{tokens: []string{"pigeonhole", "sort"}, name: "Pigeonhole Sort", category: sorting},
	{tokens: []string{"intro", "sort"}, name: "Introsort", category: sorting},

	// ── Searching & selection ───────────────────────────────────────────────
	{tokens: []string{"bsearch"}, name: "Binary Search", category: searching},
	{tokens: []string{"binary", "search"}, name: "Binary Search", category: searching},
	{tokens: []string{"linear", "search"}, name: "Linear Search", category: searching},
	{tokens: []string{"sequential", "search"}, name: "Linear Search", category: searching},
	{tokens: []string{"interpolation", "search"}, name: "Interpolation Search", category: searching},
	{tokens: []string{"jump", "search"}, name: "Jump Search", category: searching},
	{tokens: []string{"exponential", "search"}, name: "Exponential Search", category: searching},
	{tokens: []string{"ternary", "search"}, name: "Ternary Search", category: searching},
	{tokens: []string{"fibonacci", "search"}, name: "Fibonacci Search", category: searching},
	{tokens: []string{"quick", "select"}, name: "Quickselect", category: searching},
	{tokens: []string{"quickselect"}, name: "Quickselect", category: searching},

	// ── Graph · shortest path · flow ────────────────────────────────────────
	{tokens: []string{"dijkstra"}, name: "Dijkstra", category: graphAlg},
	{tokens: []string{"bellman", "ford"}, name: "Bellman–Ford", category: graphAlg},
	{tokens: []string{"floyd", "warshall"}, name: "Floyd–Warshall", category: graphAlg},
	{tokens: []string{"astar", "search"}, name: "A* Search", category: graphAlg},
	{tokens: []string{"astar", "path"}, name: "A* Search", category: graphAlg},
	{tokens: []string{"astar", "pathfinding"}, name: "A* Search", category: graphAlg},
	{tokens: []string{"astar", "heuristic"}, name: "A* Search", category: graphAlg},
	{tokens: []string{"breadth", "first"}, name: "Breadth-First Search", category: graphAlg},
	{tokens: []string{"bfs"}, name: "Breadth-First Search", category: graphAlg},
	{tokens: []string{"depth", "first"}, name: "Depth-First Search", category: graphAlg},
	{tokens: []string{"dfs"}, name: "Depth-First Search", category: graphAlg},
	{tokens: []string{"kruskal"}, name: "Kruskal (MST)", category: graphAlg},
	{tokens: []string{"prims"}, name: "Prim (MST)", category: graphAlg},
	{tokens: []string{"prim", "mst"}, name: "Prim (MST)", category: graphAlg},
	{tokens: []string{"prim", "spanning"}, name: "Prim (MST)", category: graphAlg},
	{tokens: []string{"topological", "sort"}, name: "Topological Sort", category: graphAlg},
	{tokens: []string{"toposort"}, name: "Topological Sort", category: graphAlg},
	{tokens: []string{"tarjan"}, name: "Tarjan (SCC)", category: graphAlg},
	{tokens: []string{"kosaraju"}, name: "Kosaraju (SCC)", category: graphAlg},
	{tokens: []string{"ford", "fulkerson"}, name: "Ford–Fulkerson (Max Flow)", category: graphAlg},
	{tokens: []string{"edmonds", "karp"}, name: "Edmonds–Karp (Max Flow)", category: graphAlg},
	{tokens: []string{"hopcroft", "karp"}, name: "Hopcroft–Karp (Matching)", category: graphAlg},

	// ── String matching ─────────────────────────────────────────────────────
	{tokens: []string{"knuth", "morris", "pratt"}, name: "Knuth–Morris–Pratt", category: strMatch},
	{tokens: []string{"kmp", "search"}, name: "Knuth–Morris–Pratt", category: strMatch},
	{tokens: []string{"kmp"}, name: "Knuth–Morris–Pratt", category: strMatch},
	{tokens: []string{"rabin", "karp"}, name: "Rabin–Karp", category: strMatch},
	{tokens: []string{"boyer", "moore"}, name: "Boyer–Moore", category: strMatch},
	{tokens: []string{"aho", "corasick"}, name: "Aho–Corasick", category: strMatch},
	{tokens: []string{"manacher"}, name: "Manacher", category: strMatch},
	{tokens: []string{"levenshtein"}, name: "Levenshtein (Edit Distance)", category: strMatch},
	{tokens: []string{"edit", "distance"}, name: "Levenshtein (Edit Distance)", category: strMatch},
	{tokens: []string{"longest", "common", "subsequence"}, name: "Longest Common Subsequence", category: strMatch},
	{tokens: []string{"lcs"}, name: "Longest Common Subsequence", category: strMatch},

	// ── Numeric & classic ───────────────────────────────────────────────────
	{tokens: []string{"euclid", "gcd"}, name: "Euclidean GCD", category: numeric},
	{tokens: []string{"binary", "gcd"}, name: "Binary GCD (Stein)", category: numeric},
	{tokens: []string{"gcd"}, name: "Euclidean GCD", category: numeric},
	{tokens: []string{"sieve", "eratosthenes"}, name: "Sieve of Eratosthenes", category: numeric},
	{tokens: []string{"eratosthenes"}, name: "Sieve of Eratosthenes", category: numeric},
	{tokens: []string{"miller", "rabin"}, name: "Miller–Rabin Primality", category: numeric},
	{tokens: []string{"newton", "raphson"}, name: "Newton–Raphson", category: numeric},
	{tokens: []string{"fast", "fourier"}, name: "Fast Fourier Transform", category: numeric},
	{tokens: []string{"karatsuba"}, name: "Karatsuba Multiplication", category: numeric},
	{tokens: []string{"binary", "exponentiation"}, name: "Binary Exponentiation", category: numeric},
	{tokens: []string{"modular", "exponentiation"}, name: "Binary Exponentiation", category: numeric},
	{tokens: []string{"knapsack"}, name: "Knapsack (DP)", category: numeric},
	{tokens: []string{"kadane"}, name: "Kadane (Max Subarray)", category: numeric},
	{tokens: []string{"huffman"}, name: "Huffman Coding", category: numeric},
	{tokens: []string{"fibonacci"}, name: "Fibonacci", category: numeric},
	{tokens: []string{"ramer", "douglas", "peucker"}, name: "Ramer–Douglas–Peucker", category: numeric},
	{tokens: []string{"douglas", "peucker"}, name: "Ramer–Douglas–Peucker", category: numeric},
}

func init() {
	for i := range algoRules {
		algoRules[i].joined = strings.Join(algoRules[i].tokens, "")
	}
	// Most-specific first: more tokens, then longer joined form, wins.
	sort.SliceStable(algoRules, func(i, j int) bool {
		if len(algoRules[i].tokens) != len(algoRules[j].tokens) {
			return len(algoRules[i].tokens) > len(algoRules[j].tokens)
		}
		return len(algoRules[i].joined) > len(algoRules[j].joined)
	})
}

// ── Structural (name-independent) detection ─────────────────────────────────
//
// Phase 1 above (matchAlgoRule) only catches a function whose *name* gives it
// away (`bubbleSort`, `dijkstra`, …). Some algorithms are just as often
// written under an unrelated name — a backtracking search called
// `chatContextMenuItems`, a two-pointer scan called `findEdgePoints` — so
// this phase fingerprints a function's *body shape* instead: loop nesting,
// self-recursion, and the presence of specific idiom substrings/tokens.
// Ported from ArchSwiftScope's AlgorithmDetector.StructuralRule/FnFeatures.
//
// Kept to the handful of algorithms where structural detection was requested
// (Backtracking, Two-Pointer, structural Depth-First Search, structural
// Sieve of Eratosthenes) rather than porting the reference's full ~20-rule
// catalog — the fingerprinting infrastructure generalizes, but each
// additional rule is its own false-positive surface to validate.

// fnFeat is a function body's structural fingerprint.
type fnFeat struct {
	norm      string          // body with comments/strings stripped and whitespace removed
	spaced    string          // same, but whitespace preserved (needed to tell "while x" from "whileX")
	tokens    map[string]bool // whole identifier tokens appearing in the body
	loopNest  int             // max nesting depth of for/while/repeat
	selfCalls int             // recursive calls to the enclosing function
}

func (f fnFeat) hasLoop() bool { return f.loopNest >= 1 }

func (f fnFeat) any(subs []string) bool {
	for _, s := range subs {
		if strings.Contains(f.norm, s) {
			return true
		}
	}
	return false
}

// structuralRule pairs an algorithm with a body-shape predicate.
type structuralRule struct {
	name     string
	category algoCategory
	matches  func(fnFeat) bool
}

var reLoopKeyword = regexp.MustCompile(`(^|[^a-z0-9_])(for|while|repeat)($|[^a-z0-9_])`)
var reWhileLess = regexp.MustCompile(`\bwhile\s+(\w+)\s*<\s*(\w+)`)

// reForLess catches the same converging-pointer condition inside a C-style
// three-clause for header ("for i, j := 0, n-1; i < j; …", "for (int i = 0,
// j = n - 1; i < j; i++, j--)") — the non-greedy [^{]*? stops at the first
// "var < var" before the loop's opening brace, which is always the header's
// own condition clause, never something from inside the body.
var reForLess = regexp.MustCompile(`\bfor\b[^{]*?\b(\w+)\s*<\s*(\w+)\b`)

// containsBounded is a substring search with identifier-boundary checks: "l+=1"
// must not match inside "total+=1". Boundaries are enforced only on the ends
// of needle that are themselves word characters.
func containsBounded(norm, needle string) bool {
	if needle == "" {
		return false
	}
	isWord := func(b byte) bool {
		return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
	}
	needPre, needPost := isWord(needle[0]), isWord(needle[len(needle)-1])
	from := 0
	for {
		idx := strings.Index(norm[from:], needle)
		if idx < 0 {
			return false
		}
		start := from + idx
		end := start + len(needle)
		preOK := !needPre || start == 0 || !isWord(norm[start-1])
		postOK := !needPost || end == len(norm) || !isWord(norm[end])
		if preOK && postOK {
			return true
		}
		from = start + 1
	}
}

// hasIncrementBy1 reports whether spaced contains "<varName> <op> 1" (any
// amount of whitespace around the operator) — used to confirm a while-loop
// bound variable actually advances by exactly one per iteration.
func hasIncrementBy1(spaced, varName, op string) bool {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(varName) + `\s*` + regexp.QuoteMeta(op) + `\s*1\b`)
	return re.MatchString(spaced)
}

// hasStepBy1 reports whether varName is advanced by exactly one in either
// idiom family a language uses for it: compound assignment ("l += 1") or a
// postfix/prefix increment/decrement operator ("l++"/"++l", "r--"/"--r").
// The plain compound-assignment check alone missed the far more common
// "i++"/"j--" spelling used in Go/Java/C/JS/Kotlin/Swift loops.
func hasStepBy1(norm, spaced, varName string, positive bool) bool {
	op, incDec := "+=", "++"
	if !positive {
		op, incDec = "-=", "--"
	}
	return hasIncrementBy1(spaced, varName, op) ||
		containsBounded(norm, varName+incDec) ||
		containsBounded(norm, incDec+varName)
}

// selfSquareTerms returns every identifier x that appears as "x*x" in norm —
// the marking-start idiom of a sieve (start at p*p). Go's RE2 has no
// backreferences (unlike the reference's `(\w+)\*\1`), so this replicates
// that regex's own backtracking behavior by hand: since norm has whitespace
// stripped, the identifier run immediately before '*' often includes a glued-
// on keyword too ("while p * p" → "whilep*p"), so this tries every suffix
// length of that run, longest first — exactly the order `(\w+)\*\1` tries
// backtracking over \w+'s captured length — and keeps the first (longest)
// suffix that equals the same-length run right after '*'.
func selfSquareTerms(norm string) map[string]bool {
	out := map[string]bool{}
	isIdent := func(b byte) bool {
		return b == '_' || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
	}
	for i := 0; i < len(norm); i++ {
		if norm[i] != '*' {
			continue
		}
		j := i - 1
		for j >= 0 && isIdent(norm[j]) {
			j--
		}
		beforeFull := norm[j+1 : i]
		if beforeFull == "" {
			continue
		}
		rest := norm[i+1:]
		for l := len(beforeFull); l >= 1; l-- {
			if l > len(rest) {
				continue
			}
			suffix := beforeFull[len(beforeFull)-l:]
			if suffix == rest[:l] {
				out[suffix] = true
				break
			}
		}
	}
	return out
}

// structuralRules is checked in order; the first match wins per function.
// DFS is listed before Backtracking so a genuine visited-set DFS claims it
// first — Backtracking only catches the recursive try/undo shape DFS's
// stricter `visited` requirement doesn't already cover.
var structuralRules = []structuralRule{
	{
		name: "Sieve of Eratosthenes", category: numeric,
		matches: func(f fnFeat) bool {
			if !f.hasLoop() || !f.any([]string{"=false", "=true"}) {
				return false
			}
			for term := range selfSquareTerms(f.norm) {
				if containsBounded(f.norm, "by:"+term) || containsBounded(f.norm, "+="+term) {
					return true
				}
			}
			return false
		},
	},
	{
		name: "Depth-First Search", category: graphAlg,
		matches: func(f fnFeat) bool {
			return f.hasLoop() && f.tokens["visited"] &&
				(f.any([]string{"removelast(", "poplast("}) || f.selfCalls >= 1)
		},
	},
	{
		name: "Backtracking (DFS)", category: searching,
		matches: func(f fnFeat) bool {
			return f.selfCalls >= 1 && f.any([]string{"append("}) &&
				f.any([]string{"removelast(", "poplast("})
		},
	},
	{
		name: "Two-Pointer Technique", category: searching,
		matches: func(f fnFeat) bool {
			check := func(re *regexp.Regexp) bool {
				for _, m := range re.FindAllStringSubmatch(f.spaced, -1) {
					if hasStepBy1(f.norm, f.spaced, m[1], true) && hasStepBy1(f.norm, f.spaced, m[2], false) {
						return true
					}
				}
				return false
			}
			return check(reWhileLess) || check(reForLess)
		},
	},
}

// computeFnFeatures brace-matches the function body starting at lines[startLine]
// (0-indexed) and extracts its structural fingerprint. lines must already be
// comment/string-stripped. Returns ok=false for a bodiless/unmatched function.
func computeFnFeatures(lines []string, startLine int, funcName string) (fnFeat, bool) {
	depth, started := 0, false
	var loopStack []int
	maxNest := 0
	var cleaned []string
	pendingLoop := false
	for j := startLine; j < len(lines) && len(cleaned) < 1200; j++ {
		line := strings.ToLower(lines[j])
		if reLoopKeyword.MatchString(line) {
			pendingLoop = true
		}
		for k := 0; k < len(line); k++ {
			switch line[k] {
			case '{':
				depth++
				started = true
				if pendingLoop {
					loopStack = append(loopStack, depth)
					pendingLoop = false
					if len(loopStack) > maxNest {
						maxNest = len(loopStack)
					}
				}
			case '}':
				depth--
				for len(loopStack) > 0 && loopStack[len(loopStack)-1] > depth {
					loopStack = loopStack[:len(loopStack)-1]
				}
			}
		}
		cleaned = append(cleaned, line)
		if started && depth <= 0 {
			break
		}
	}
	if !started {
		return fnFeat{}, false
	}

	joined := strings.Join(cleaned, "\n")
	var normB strings.Builder
	normB.Grow(len(joined))
	for _, r := range joined {
		if !unicode.IsSpace(r) {
			normB.WriteRune(r)
		}
	}
	norm := normB.String()

	tokens := map[string]bool{}
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			tokens[string(cur)] = true
			cur = cur[:0]
		}
	}
	for _, r := range joined {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			cur = append(cur, r)
		} else {
			flush()
		}
	}
	flush()

	selfCalls := 0
	needle := strings.ToLower(funcName) + "("
	isWord := func(b byte) bool {
		return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
	}
	for from := 0; ; {
		idx := strings.Index(norm[from:], needle)
		if idx < 0 {
			break
		}
		start := from + idx
		if start == 0 || !isWord(norm[start-1]) {
			selfCalls++
		}
		from = start + 1
	}

	return fnFeat{norm: norm, spaced: joined, tokens: tokens, loopNest: maxNest, selfCalls: selfCalls}, true
}

// matchStructuralRule fingerprints the function at lines[startLine] and tests
// it against structuralRules. A body under 30 chars (norm) is too small to
// fingerprint reliably and is rejected, same as the reference.
func matchStructuralRule(lines []string, startLine int, funcName string) (name string, cat algoCategory, ok bool) {
	f, computed := computeFnFeatures(lines, startLine, funcName)
	if !computed || len(f.norm) < 30 {
		return "", "", false
	}
	for _, r := range structuralRules {
		if r.matches(f) {
			return r.name, r.category, true
		}
	}
	return "", "", false
}

// AlgoOccurrence is one detected algorithm declaration with its location, used
// to build a vscode:// deep link in the report.
type AlgoOccurrence struct {
	Symbol   string // the declaration name, e.g. "quickSort"
	FilePath string // absolute path, for the vscode:// link
	Line     int
}

// AlgoMatch is one canonical algorithm with all its occurrences.
type AlgoMatch struct {
	Name        string
	Category    algoCategory
	Count       int
	Occurrences []AlgoOccurrence
}

// AlgorithmsResult is the module output.
type AlgorithmsResult struct {
	Matches []AlgoMatch
}

// HasDetection reports whether any algorithm was found.
func (r AlgorithmsResult) HasDetection() bool { return len(r.Matches) > 0 }

// isCandidateKind reports whether a declaration kind can name an algorithm: a
// function/method (the usual case) or a type acting as an algorithm object
// (QuickSorter, DijkstraSolver, …).
func isCandidateKind(k parser.DeclKind) bool {
	switch k {
	case parser.DeclFunc, parser.DeclStruct, parser.DeclClass,
		parser.DeclInterface, parser.DeclActor, parser.DeclType:
		return true
	}
	return false
}

// Analyze scans function and type declarations and classifies them against the
// algorithm catalog: first by name convention (Phase 1), then, for functions
// a name rule didn't already claim, by body shape (Phase 2 — see
// matchStructuralRule).
func (Algorithms) Analyze(files []*parser.ParsedFile) any {
	type agg struct {
		category algoCategory
		occ      []AlgoOccurrence
	}
	found := map[string]*agg{}
	cache := newSourceCache()

	record := func(name string, cat algoCategory, symbol, path string, line int) {
		a := found[name]
		if a == nil {
			a = &agg{category: cat}
			found[name] = a
		}
		a.occ = append(a.occ, AlgoOccurrence{Symbol: symbol, FilePath: path, Line: line})
	}

	for _, f := range files {
		for _, d := range f.Declarations {
			if !isCandidateKind(d.Kind) {
				continue
			}
			if r, ok := matchAlgoRule(d.Name); ok {
				record(r.name, r.category, d.Name, f.FilePath, d.Line)
				continue
			}
			if d.Kind != parser.DeclFunc {
				continue
			}
			lines := cache.lines(f.FilePath)
			if lines == nil || d.Line <= 0 || d.Line > len(lines) {
				continue
			}
			if name, cat, ok := matchStructuralRule(lines, d.Line-1, d.Name); ok {
				record(name, cat, d.Name, f.FilePath, d.Line)
			}
		}
	}

	var matches []AlgoMatch
	for name, a := range found {
		matches = append(matches, AlgoMatch{
			Name: name, Category: a.category, Count: len(a.occ), Occurrences: a.occ,
		})
	}
	sort.SliceStable(matches, func(i, j int) bool {
		ci, cj := algoCategoryRank(matches[i].Category), algoCategoryRank(matches[j].Category)
		if ci != cj {
			return ci < cj
		}
		if matches[i].Count != matches[j].Count {
			return matches[i].Count > matches[j].Count
		}
		return matches[i].Name < matches[j].Name
	})
	return AlgorithmsResult{Matches: matches}
}

// SummaryCards surfaces the number of distinct algorithms detected.
func (Algorithms) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(AlgorithmsResult)
	if !ok || !r.HasDetection() {
		return nil
	}
	return []modules.SummaryCard{
		{Num: strconv.Itoa(len(r.Matches)), Label: plural(len(r.Matches), "algorithm", "algorithms")},
	}
}

// RenderMarkdown renders detected algorithms as a markdown table.
func (Algorithms) RenderMarkdown(res any) string {
	r, ok := res.(AlgorithmsResult)
	if !ok || !r.HasDetection() {
		return ""
	}
	var b strings.Builder
	b.WriteString("| Algorithm | Category | Count | Examples |\n")
	b.WriteString("|-----------|----------|------:|---------|\n")
	for _, m := range r.Matches {
		var ex []string
		for i, o := range m.Occurrences {
			if i == 6 {
				ex = append(ex, fmt.Sprintf("+%d more", len(m.Occurrences)-6))
				break
			}
			ex = append(ex, fmt.Sprintf("%s (%s:%d)", o.Symbol, baseName(o.FilePath), o.Line))
		}
		fmt.Fprintf(&b, "| %s | %s | %d | %s |\n", m.Name, string(m.Category), m.Count, strings.Join(ex, ", "))
	}
	b.WriteString("\n")
	return b.String()
}

// maxLinksPerAlgo caps the number of vscode links rendered per algorithm so a
// codebase with hundreds of sort helpers stays readable.
const maxLinksPerAlgo = 12

// RenderHTML renders the algorithms grouped by category, each with its count
// and vscode:// deep links to every declaration.
func (Algorithms) RenderHTML(res any) string {
	r, ok := res.(AlgorithmsResult)
	if !ok {
		return ""
	}
	if !r.HasDetection() {
		return `<p class="as-empty">No well-known algorithms detected from naming conventions.</p>`
	}
	byCat := map[algoCategory][]AlgoMatch{}
	for _, m := range r.Matches {
		byCat[m.Category] = append(byCat[m.Category], m)
	}
	var b strings.Builder
	b.WriteString(`<div class="as-dp">`)
	for _, cat := range algoCategoryOrder {
		ms := byCat[cat]
		if len(ms) == 0 {
			continue
		}
		fmt.Fprintf(&b, `<div class="as-dp__group"><h5 class="as-sub">%s %s</h5><div class="as-dp__items">`, algoCategoryIcon[cat], html.EscapeString(string(cat)))
		for _, m := range ms {
			fmt.Fprintf(&b, `<div class="as-dp__item"><span class="as-dp__name">%s</span><span class="as-dp__count">×%d</span>`,
				html.EscapeString(m.Name), m.Count)
			b.WriteString(`<span class="as-dp__ex">`)
			for i, o := range m.Occurrences {
				if i == maxLinksPerAlgo {
					fmt.Fprintf(&b, ` +%d more`, len(m.Occurrences)-maxLinksPerAlgo)
					break
				}
				if i > 0 {
					b.WriteString(` · `)
				}
				b.WriteString(occurrenceLink(o.Symbol, o.FilePath, o.Line))
			}
			b.WriteString(`</span></div>`)
		}
		b.WriteString(`</div></div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// ── helpers ──────────────────────────────────────────────────────────────────

// matchAlgoRule returns the most-specific rule matching name. Because
// algoRules is sorted by token count descending, the first hit is the most
// specific.
func matchAlgoRule(name string) (algoRule, bool) {
	tokens, joined := tokenize(name)
	set := make(map[string]bool, len(tokens))
	for _, t := range tokens {
		set[t] = true
	}
	for _, r := range algoRules {
		if r.matches(set, joined) {
			return r, true
		}
	}
	return algoRule{}, false
}

// matches reports whether the signature is satisfied: every token present as a
// word token, or the concatenated tokens present as a substring of the joined
// identifier (handling run-together spellings like "aStarSearch").
func (r algoRule) matches(set map[string]bool, joined string) bool {
	all := true
	for _, t := range r.tokens {
		if !set[t] {
			all = false
			break
		}
	}
	if all {
		return true
	}
	return strings.Contains(joined, r.joined)
}

// tokenize splits an identifier into lowercase word tokens and returns the
// joined lowercase-alphanumeric form. It handles camelCase, PascalCase,
// snake_case, acronym runs ("KMPSearch" → [kmp, search]) and letter/digit
// boundaries ("sha256" → [sha, 256]).
func tokenize(name string) (tokens []string, joined string) {
	var cur []rune
	var jb strings.Builder
	runes := []rune(name)
	isU := func(r rune) bool { return r >= 'A' && r <= 'Z' }
	isL := func(r rune) bool { return r >= 'a' && r <= 'z' }
	isD := func(r rune) bool { return r >= '0' && r <= '9' }
	flush := func() {
		if len(cur) > 0 {
			tokens = append(tokens, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for i, r := range runes {
		if !(isU(r) || isL(r) || isD(r)) {
			flush()
			continue
		}
		jb.WriteRune(toLowerRune(r))
		if len(cur) > 0 {
			prev := cur[len(cur)-1]
			switch {
			case isU(r) && (isL(prev) || isD(prev)):
				flush() // lower/digit → Upper: new word
			case isU(r) && isU(prev) && i+1 < len(runes) && isL(runes[i+1]):
				flush() // end of acronym run before a Capitalized word
			case isD(r) != isD(prev):
				flush() // letter ↔ digit boundary
			}
		}
		cur = append(cur, r)
	}
	flush()
	return tokens, jb.String()
}

func toLowerRune(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

func algoCategoryRank(c algoCategory) int {
	for i, x := range algoCategoryOrder {
		if x == c {
			return i
		}
	}
	return len(algoCategoryOrder)
}
