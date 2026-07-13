// Package algorithms is a universal detector for well-known algorithms
// implemented in a codebase — sorting, searching, graph/shortest-path, string
// matching, and classic numeric routines.
//
// Method. It adapts the central idea of the "Algorithm Identification in Source
// Code" project (~/algorithm-identification): classify a piece of code against a
// *known catalog* of algorithms for a functionality (sorting, searching,
// shortest-path, …). That project explores heavyweight classifiers — execution
// profiling (valgrind time/memory), MOSS similarity, tree/graph-kernel SVMs, and
// CodeBERT/GraphCodeBERT — none of which fit ArchScope's dependency-free, static,
// single-pass design. So the catalog-classification premise is kept while the
// signal is switched to the static, low-false-positive name convention used by
// the sibling designpattern/datastructures modules: a function or type named
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
package algorithms

import (
	"fmt"
	"html"
	"sort"
	"strconv"
	"strings"

	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
)

func init() { modules.Default.Register(Module{}) }

// Module is the universal algorithm detector.
type Module struct{}

func (Module) ID() string                       { return "algorithms" }
func (Module) Title() string                    { return "Algorithms" }
func (Module) AppliesTo(languageID string) bool { return true } // universal

// category groups detected algorithms by the functionality they implement,
// mirroring the reference project's sorting / searching / shortest-path split.
type category string

const (
	sorting   category = "Sorting"
	searching category = "Searching & Selection"
	graphAlg  category = "Graph · Shortest Path · Flow"
	strMatch  category = "String Matching"
	numeric   category = "Numeric & Classic"
)

// categoryOrder fixes the display order.
var categoryOrder = []category{sorting, searching, graphAlg, strMatch, numeric}

// categoryIcon is the emoji shown before each category's as-sub heading.
var categoryIcon = map[category]string{
	sorting:   "🔃",
	searching: "🔎",
	graphAlg:  "🕸️",
	strMatch:  "🔤",
	numeric:   "🔢",
}

// rule maps a token signature to a canonical algorithm name and category. A
// signature matches an identifier when either every token is present as a
// word token, OR the identifier's joined-lowercase form contains the tokens
// concatenated (so "aStarSearch", "astar_search" and "AStarSearch" all match
// {astar, search}). Rules are ranked most-specific-first (most tokens) in
// init() so "fibonacciSearch" resolves to Fibonacci Search, not Fibonacci.
type rule struct {
	tokens   []string
	joined   string // precomputed strings.Join(tokens, "")
	name     string
	category category
}

var rules = []rule{
	// ── Sorting ─────────────────────────────────────────────────────────────
	{tokens: []string{"bubble", "sort"}, name: "Bubble Sort", category: sorting},
	{tokens: []string{"insertion", "sort"}, name: "Insertion Sort", category: sorting},
	{tokens: []string{"selection", "sort"}, name: "Selection Sort", category: sorting},
	{tokens: []string{"merge", "sort"}, name: "Merge Sort", category: sorting},
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
}

func init() {
	for i := range rules {
		rules[i].joined = strings.Join(rules[i].tokens, "")
	}
	// Most-specific first: more tokens, then longer joined form, wins.
	sort.SliceStable(rules, func(i, j int) bool {
		if len(rules[i].tokens) != len(rules[j].tokens) {
			return len(rules[i].tokens) > len(rules[j].tokens)
		}
		return len(rules[i].joined) > len(rules[j].joined)
	})
}

// Occurrence is one detected algorithm declaration with its location, used to
// build a vscode:// deep link in the report.
type Occurrence struct {
	Symbol   string // the declaration name, e.g. "quickSort"
	FilePath string // absolute path, for the vscode:// link
	Line     int
}

// Match is one canonical algorithm with all its occurrences.
type Match struct {
	Name        string
	Category    category
	Count       int
	Occurrences []Occurrence
}

// Result is the module output.
type Result struct {
	Matches []Match
}

// HasDetection reports whether any algorithm was found.
func (r Result) HasDetection() bool { return len(r.Matches) > 0 }

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
// algorithm catalog.
func (Module) Analyze(files []*parser.ParsedFile) any {
	type agg struct {
		category category
		occ      []Occurrence
	}
	found := map[string]*agg{}

	for _, f := range files {
		for _, d := range f.Declarations {
			if !isCandidateKind(d.Kind) {
				continue
			}
			r, ok := matchRule(d.Name)
			if !ok {
				continue
			}
			a := found[r.name]
			if a == nil {
				a = &agg{category: r.category}
				found[r.name] = a
			}
			a.occ = append(a.occ, Occurrence{Symbol: d.Name, FilePath: f.FilePath, Line: d.Line})
		}
	}

	var matches []Match
	for name, a := range found {
		matches = append(matches, Match{
			Name: name, Category: a.category, Count: len(a.occ), Occurrences: a.occ,
		})
	}
	sort.SliceStable(matches, func(i, j int) bool {
		ci, cj := categoryRank(matches[i].Category), categoryRank(matches[j].Category)
		if ci != cj {
			return ci < cj
		}
		if matches[i].Count != matches[j].Count {
			return matches[i].Count > matches[j].Count
		}
		return matches[i].Name < matches[j].Name
	})
	return Result{Matches: matches}
}

// SummaryCards surfaces the number of distinct algorithms detected.
func (Module) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(Result)
	if !ok || !r.HasDetection() {
		return nil
	}
	return []modules.SummaryCard{
		{Num: strconv.Itoa(len(r.Matches)), Label: plural(len(r.Matches), "algorithm", "algorithms")},
	}
}

// RenderMarkdown renders detected algorithms as a markdown table.
func (Module) RenderMarkdown(res any) string {
	r, ok := res.(Result)
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
func (Module) RenderHTML(res any) string {
	r, ok := res.(Result)
	if !ok {
		return ""
	}
	if !r.HasDetection() {
		return `<p class="as-empty">No well-known algorithms detected from naming conventions.</p>`
	}
	byCat := map[category][]Match{}
	for _, m := range r.Matches {
		byCat[m.Category] = append(byCat[m.Category], m)
	}
	var b strings.Builder
	b.WriteString(`<div class="as-dp">`)
	for _, cat := range categoryOrder {
		ms := byCat[cat]
		if len(ms) == 0 {
			continue
		}
		fmt.Fprintf(&b, `<div class="as-dp__group"><h5 class="as-sub">%s %s</h5><div class="as-dp__items">`, categoryIcon[cat], html.EscapeString(string(cat)))
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
				b.WriteString(occurrenceLink(o))
			}
			b.WriteString(`</span></div>`)
		}
		b.WriteString(`</div></div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// ── helpers ──────────────────────────────────────────────────────────────────

// matchRule returns the most-specific rule matching name. Because rules is
// sorted by token count descending, the first hit is the most specific.
func matchRule(name string) (rule, bool) {
	tokens, joined := tokenize(name)
	set := make(map[string]bool, len(tokens))
	for _, t := range tokens {
		set[t] = true
	}
	for _, r := range rules {
		if r.matches(set, joined) {
			return r, true
		}
	}
	return rule{}, false
}

// matches reports whether the signature is satisfied: every token present as a
// word token, or the concatenated tokens present as a substring of the joined
// identifier (handling run-together spellings like "aStarSearch").
func (r rule) matches(set map[string]bool, joined string) bool {
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
		jb.WriteRune(toLower(r))
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

func toLower(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

func occurrenceLink(o Occurrence) string {
	href := vscodeHref(o.FilePath, o.Line)
	if href == "" {
		return html.EscapeString(o.Symbol)
	}
	return fmt.Sprintf(`<a class="as-vs" href="%s" title="%s:%d">%s</a>`,
		html.EscapeString(href), html.EscapeString(baseName(o.FilePath)), o.Line, html.EscapeString(o.Symbol))
}

// vscodeHref builds a vscode:// deep link for an absolute path + line, mirroring
// the html report's own helper. Returns "" for non-absolute paths (deep links
// would be unreliable), in which case callers fall back to plain text.
func vscodeHref(absPath string, line int) string {
	if absPath == "" {
		return ""
	}
	p := strings.ReplaceAll(absPath, "\\", "/")
	if !strings.HasPrefix(p, "/") {
		return ""
	}
	h := "vscode://file" + p
	if line > 0 {
		h += ":" + strconv.Itoa(line)
	}
	return h
}

func baseName(path string) string {
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
		return path[i+1:]
	}
	return path
}

func categoryRank(c category) int {
	for i, x := range categoryOrder {
		if x == c {
			return i
		}
	}
	return len(categoryOrder)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
