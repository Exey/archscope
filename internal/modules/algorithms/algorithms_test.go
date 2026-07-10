package algorithms

import (
	"reflect"
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func file(name string, decls ...parser.Declaration) *parser.ParsedFile {
	return &parser.ParsedFile{FilePath: name, Declarations: decls}
}
func fn(name string) parser.Declaration {
	return parser.Declaration{Name: name, Kind: parser.DeclFunc, Line: 1}
}

func detected(files []*parser.ParsedFile) map[string]int {
	res := (Module{}).Analyze(files).(Result)
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
	if (Module{}).Analyze(files).(Result).HasDetection() {
		t.Errorf("expected no detections, got %+v", (Module{}).Analyze(files).(Result).Matches)
	}
}

func TestAvoidsProperNounFalsePositives(t *testing.T) {
	// Token matching must not turn "primary"/"primitive"/"euclidean distance"
	// into Prim / Euclidean GCD.
	files := []*parser.ParsedFile{file("a.go",
		fn("primaryKey"), fn("createPrimitive"), fn("euclideanDistance"),
		fn("starRating"), fn("aStarRating"),
	)}
	if (Module{}).Analyze(files).(Result).HasDetection() {
		t.Errorf("expected no detections, got %+v", (Module{}).Analyze(files).(Result).Matches)
	}
}

func TestCountsAndVscodeLink(t *testing.T) {
	files := []*parser.ParsedFile{
		file("/abs/sort.go",
			parser.Declaration{Name: "quickSort", Kind: parser.DeclFunc, Line: 10},
			parser.Declaration{Name: "quicksortPartition", Kind: parser.DeclFunc, Line: 25}),
	}
	res := (Module{}).Analyze(files)
	if got := detected([]*parser.ParsedFile{files[0]})["Quicksort"]; got != 2 {
		t.Errorf("expected Quicksort ×2, got %d", got)
	}
	out := (Module{}).RenderHTML(res)
	if !strings.Contains(out, "Quicksort") || !strings.Contains(out, "×2") {
		t.Errorf("render missing name/count: %s", out)
	}
	if !strings.Contains(out, "vscode://file/abs/sort.go:10") {
		t.Errorf("render missing vscode link: %s", out)
	}
}
