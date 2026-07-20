package constructs

import (
	"reflect"
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func fn(name string) parser.Declaration {
	return parser.Declaration{Name: name, Kind: parser.DeclFunc, Line: 1}
}

func detected(files []*parser.ParsedFile) map[string]int {
	res := (Algorithms{}).Analyze(files).(AlgorithmsResult)
	got := map[string]int{}
	for _, m := range res.Matches {
		got[m.Name] = m.Count
	}
	return got
}

func TestTokenize(t *testing.T) {
	cases := map[string][]string{
		"bubbleSort":    {"bubble", "sort"},
		"bubble_sort":   {"bubble", "sort"},
		"BubbleSort":    {"bubble", "sort"},
		"KMPSearch":     {"kmp", "search"},
		"aStar":         {"a", "star"},
		"binarySearch":  {"binary", "search"},
		"dijkstra":      {"dijkstra"},
		"sha256sum":     {"sha", "256", "sum"},
		"quickSortImpl": {"quick", "sort", "impl"},
	}
	for in, want := range cases {
		got, _ := tokenize(in)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("tokenize(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestDetectsAcrossFunctionalities(t *testing.T) {
	files := []*parser.ParsedFile{
		file("a.go", fn("bubbleSort")),
		file("b.go", fn("quick_sort")),
		file("c.ts", fn("binarySearch")),
		file("d.py", fn("dijkstra")),
		file("e.java", fn("bellmanFord")),
		file("f.go", fn("kmpSearch")),
		file("g.go", fn("aStarPathfinding")),
		file("h.go", fn("kadaneMaxSubarray")),
	}
	got := detected(files)
	for _, want := range []string{
		"Bubble Sort", "Quicksort", "Binary Search", "Dijkstra",
		"Bellman–Ford", "Knuth–Morris–Pratt", "A* Search", "Kadane (Max Subarray)",
	} {
		if got[want] == 0 {
			t.Errorf("missing algorithm %q (got %v)", want, got)
		}
	}
}

func TestMostSpecificWins(t *testing.T) {
	// "fibonacciSearch" is Fibonacci Search, not generic Fibonacci.
	got := detected([]*parser.ParsedFile{file("a.go", fn("fibonacciSearch"))})
	if got["Fibonacci Search"] != 1 {
		t.Errorf("expected Fibonacci Search, got %v", got)
	}
	if _, ok := got["Fibonacci"]; ok {
		t.Errorf("generic Fibonacci should not also match: %v", got)
	}
}

func TestRequiresFunctionalityToken(t *testing.T) {
	// Common-word algorithm names must not fire without their functionality
	// token: bubbleChart is not Bubble Sort, heapView is not Heapsort.
	files := []*parser.ParsedFile{file("a.go",
		fn("bubbleChart"), fn("heapView"), fn("mergeAccounts"),
		fn("selectionRange"), fn("insertionPoint"),
	)}
	if (Algorithms{}).Analyze(files).(AlgorithmsResult).HasDetection() {
		t.Errorf("expected no detections, got %+v", (Algorithms{}).Analyze(files).(AlgorithmsResult).Matches)
	}
}

func TestAvoidsProperNounFalsePositives(t *testing.T) {
	// Token matching must not turn "primary"/"primitive"/"euclidean distance"
	// into Prim / Euclidean GCD.
	files := []*parser.ParsedFile{file("a.go",
		fn("primaryKey"), fn("createPrimitive"), fn("euclideanDistance"),
		fn("starRating"), fn("aStarRating"),
	)}
	if (Algorithms{}).Analyze(files).(AlgorithmsResult).HasDetection() {
		t.Errorf("expected no detections, got %+v", (Algorithms{}).Analyze(files).(AlgorithmsResult).Matches)
	}
}

func TestSingleTokenRulesSkipJoinedFallback(t *testing.T) {
	// The joined-substring fallback exists only for genuinely multi-token
	// signatures (aStarSearch → {astar, search}). A single-token rule must
	// get recall solely from the exact-token check — falling back to a bare
	// substring search on the joined identifier would let unrelated names
	// resolve by pure boundary coincidence: "WebSearchController" joins to
	// "websearchcontroller", which contains "bsearch"; "loadFSCache" joins to
	// "loadfscache", which contains "dfs".
	files := []*parser.ParsedFile{file("a.go",
		fn("WebSearchController"), fn("loadFSCache"),
	)}
	if (Algorithms{}).Analyze(files).(AlgorithmsResult).HasDetection() {
		t.Errorf("expected no detections, got %+v", (Algorithms{}).Analyze(files).(AlgorithmsResult).Matches)
	}
}

func TestGCDExcludedForSwift(t *testing.T) {
	// Bare "gcd" means Grand Central Dispatch in Swift, not the numeric
	// algorithm — excluded there; still detected for every other language.
	swiftFile := &parser.ParsedFile{FilePath: "a.swift", LanguageID: "swift",
		Declarations: []parser.Declaration{fn("gcdQueue")}}
	if got := detected([]*parser.ParsedFile{swiftFile}); len(got) != 0 {
		t.Errorf("expected no detection for bare gcd in Swift, got %v", got)
	}

	goFile := &parser.ParsedFile{FilePath: "a.go", LanguageID: "go",
		Declarations: []parser.Declaration{fn("gcd")}}
	if got := detected([]*parser.ParsedFile{goFile}); got["Euclidean GCD"] == 0 {
		t.Errorf("expected Euclidean GCD for bare gcd in Go, got %v", got)
	}
}

func TestDetectsAbbreviatedNames(t *testing.T) {
	files := []*parser.ParsedFile{
		file("a.go", fn("qsort")),
		file("b.go", fn("bsearch")),
		file("c.go", fn("isort")),
		file("d.go", fn("lcsLength")),
	}
	got := detected(files)
	for _, want := range []string{"Quicksort", "Binary Search", "Insertion Sort", "Longest Common Subsequence"} {
		if got[want] == 0 {
			t.Errorf("missing algorithm %q (got %v)", want, got)
		}
	}
}

func TestDetectsRamerDouglasPeucker(t *testing.T) {
	got := detected([]*parser.ParsedFile{file("a.go", fn("ramerDouglasPeucker"))})
	if got["Ramer–Douglas–Peucker"] != 1 {
		t.Errorf("expected Ramer–Douglas–Peucker, got %v", got)
	}
	got = detected([]*parser.ParsedFile{file("b.go", fn("douglasPeuckerSimplify"))})
	if got["Ramer–Douglas–Peucker"] != 1 {
		t.Errorf("expected Ramer–Douglas–Peucker via douglas+peucker tokens, got %v", got)
	}
}

// ── Structural (name-independent) detection ─────────────────────────────────

func TestStructuralDetectsBacktracking(t *testing.T) {
	src := `func chatContextMenuItems(_ n: Int, path: [Int]) -> [[Int]] {
    var results: [[Int]] = []
    var path = path
    func helper(_ start: Int) {
        for i in start..<n {
            path.append(i)
            helper(i + 1)
            path.removeLast()
        }
    }
    helper(0)
    return results
}
`
	f := writeFile(t, ".swift", src,
		parser.Declaration{Name: "chatContextMenuItems", Kind: parser.DeclFunc, Line: 1},
		parser.Declaration{Name: "helper", Kind: parser.DeclFunc, Line: 4})
	got := detected([]*parser.ParsedFile{f})
	if got["Backtracking (DFS)"] != 1 {
		t.Errorf("expected Backtracking (DFS) from the unnamed recursive helper, got %v", got)
	}
}

func TestStructuralDetectsTwoPointer(t *testing.T) {
	src := `func findEdgePoints(_ arr: [Int]) -> Bool {
    var l = 0
    var r = arr.count - 1
    while l < r {
        if arr[l] == arr[r] {
            l += 1
            r -= 1
        } else {
            return false
        }
    }
    return true
}
`
	f := writeFile(t, ".swift", src,
		parser.Declaration{Name: "findEdgePoints", Kind: parser.DeclFunc, Line: 1})
	got := detected([]*parser.ParsedFile{f})
	if got["Two-Pointer Technique"] != 1 {
		t.Errorf("expected Two-Pointer Technique from unnamed converging-pointer loop, got %v", got)
	}
}

func TestStructuralDetectsTwoPointerWithIncrementOperators(t *testing.T) {
	// Same shape as TestStructuralDetectsTwoPointer, but l++/r-- instead of
	// l += 1/r -= 1 — the far more common spelling in Go/Java/C/JS/Kotlin/Swift.
	src := `func isPalindromeRange(_ arr: [Int]) -> Bool {
    var l = 0
    var r = arr.count - 1
    while l < r {
        if arr[l] != arr[r] {
            return false
        }
        l++
        r--
    }
    return true
}
`
	f := writeFile(t, ".swift", src,
		parser.Declaration{Name: "isPalindromeRange", Kind: parser.DeclFunc, Line: 1})
	got := detected([]*parser.ParsedFile{f})
	if got["Two-Pointer Technique"] != 1 {
		t.Errorf("expected Two-Pointer Technique with ++/-- operators, got %v", got)
	}
}

func TestStructuralDetectsTwoPointerInForLoop(t *testing.T) {
	// C-style three-clause for header (Java/C/JS): i++/j-- in the post-clause
	// is recognized as a step, same as inside a while-loop body.
	src := `func isPalindromeFor(int[] a) {
	for (int i = 0, j = a.length - 1; i < j; i++, j--) {
	}
}
`
	f := writeFile(t, ".java", src,
		parser.Declaration{Name: "isPalindromeFor", Kind: parser.DeclFunc, Line: 1})
	got := detected([]*parser.ParsedFile{f})
	if got["Two-Pointer Technique"] != 1 {
		t.Errorf("expected Two-Pointer Technique from a Java-style for-header with i++/j--, got %v", got)
	}
}

func TestStructuralTwoPointerMissesGoTupleStep(t *testing.T) {
	// Documents a known limitation: Go's for-loop post-clause can't use i++,
	// j-- together (Go only allows a single simple statement there), so
	// idiomatic Go writes the tuple-assignment form "i, j = i+1, j-1" instead
	// — a shape this detector doesn't parse. Recognizing it would need real
	// multi-assignment parsing, out of scope for a per-function fingerprint.
	src := `func isPalindromeFor(a []int) bool {
	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
	}
	return true
}
`
	f := writeFile(t, ".go", src,
		parser.Declaration{Name: "isPalindromeFor", Kind: parser.DeclFunc, Line: 1})
	got := detected([]*parser.ParsedFile{f})
	if _, ok := got["Two-Pointer Technique"]; ok {
		t.Errorf("Go's tuple post-clause is not currently recognized as a step; got a match unexpectedly: %v — update this test if that changed", got)
	}
}

func TestStructuralDetectsDepthFirstSearch(t *testing.T) {
	src := `func floodFill(_ grid: [[Int]], _ start: Int) -> Set<Int> {
    var visited = Set<Int>()
    var stack = [start]
    while !stack.isEmpty {
        let node = stack.removeLast()
        if visited.contains(node) { continue }
        visited.insert(node)
        stack.append(node)
    }
    return visited
}
`
	f := writeFile(t, ".swift", src,
		parser.Declaration{Name: "floodFill", Kind: parser.DeclFunc, Line: 1})
	got := detected([]*parser.ParsedFile{f})
	if got["Depth-First Search"] != 1 {
		t.Errorf("expected structural Depth-First Search from visited-set + removeLast, got %v", got)
	}
}

func TestStructuralDetectsSieveOfEratosthenes(t *testing.T) {
	src := `func primesUpTo(_ n: Int) -> [Int] {
    var isComposite = [Bool](repeating: false, count: n + 1)
    var p = 2
    while p * p <= n {
        if !isComposite[p] {
            var m = p * p
            while m <= n {
                isComposite[m] = true
                m += p
            }
        }
        p += 1
    }
    return (2...n).filter { !isComposite[$0] }
}
`
	f := writeFile(t, ".swift", src,
		parser.Declaration{Name: "primesUpTo", Kind: parser.DeclFunc, Line: 1})
	got := detected([]*parser.ParsedFile{f})
	if got["Sieve of Eratosthenes"] != 1 {
		t.Errorf("expected Sieve of Eratosthenes from the p*p marking-start idiom, got %v", got)
	}
}

func TestStructuralIgnoresTinyOrNameMatchedFunctions(t *testing.T) {
	// A name match (Phase 1) must win outright — no structural pass needed —
	// and a trivial one-liner must not spuriously fingerprint as anything.
	src := `func bubbleSort(_ a: [Int]) -> [Int] { return a }
func noop() {}
`
	f := writeFile(t, ".swift", src,
		parser.Declaration{Name: "bubbleSort", Kind: parser.DeclFunc, Line: 1},
		parser.Declaration{Name: "noop", Kind: parser.DeclFunc, Line: 2})
	got := detected([]*parser.ParsedFile{f})
	if got["Bubble Sort"] != 1 {
		t.Errorf("expected Bubble Sort by name, got %v", got)
	}
	if len(got) != 1 {
		t.Errorf("expected only the name match, got %v", got)
	}
}

func TestCountsAndVscodeLink(t *testing.T) {
	files := []*parser.ParsedFile{
		file("/abs/sort.go",
			parser.Declaration{Name: "quickSort", Kind: parser.DeclFunc, Line: 10},
			parser.Declaration{Name: "quicksortPartition", Kind: parser.DeclFunc, Line: 25}),
	}
	res := (Algorithms{}).Analyze(files)
	if got := detected([]*parser.ParsedFile{files[0]})["Quicksort"]; got != 2 {
		t.Errorf("expected Quicksort ×2, got %d", got)
	}
	out := (Algorithms{}).RenderHTML(res)
	if !strings.Contains(out, "Quicksort") || !strings.Contains(out, "×2") {
		t.Errorf("render missing name/count: %s", out)
	}
	if !strings.Contains(out, "vscode://file/abs/sort.go:10") {
		t.Errorf("render missing vscode link: %s", out)
	}
}
