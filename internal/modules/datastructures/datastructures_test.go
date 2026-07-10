package datastructures

import (
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func file(name string, decls ...parser.Declaration) *parser.ParsedFile {
	return &parser.ParsedFile{FilePath: name, Declarations: decls}
}
func ty(name string) parser.Declaration {
	return parser.Declaration{Name: name, Kind: parser.DeclClass, Line: 1}
}

func detectedNames(files []*parser.ParsedFile) map[string]int {
	res := (Module{}).Analyze(files).(Result)
	got := map[string]int{}
	for _, m := range res.Matches {
		got[m.Name] = m.Count
	}
	return got
}

func TestDetectsCoreStructures(t *testing.T) {
	files := []*parser.ParsedFile{
		file("a.swift", ty("DoublyLinkedList")),
		file("b.kt", ty("MinHeap")),
		file("c.ts", ty("BinarySearchTree")),
		file("d.go", ty("DirectedGraph")),
		file("e.py", parser.Declaration{Name: "Trie", Kind: parser.DeclClass, Line: 3}),
		file("f.go", ty("LRUCache")),
	}
	got := detectedNames(files)
	for _, want := range []string{
		"Linked List", "Min-Heap", "Binary Search Tree", "Directed Graph", "Trie", "LRU Cache",
	} {
		if got[want] == 0 {
			t.Errorf("missing structure %q (got %v)", want, got)
		}
	}
}

func TestLongestMatchWins(t *testing.T) {
	// "BinarySearchTree" must resolve to the specific rule, not the generic "Tree".
	got := detectedNames([]*parser.ParsedFile{file("a.go", ty("BinarySearchTree"))})
	if got["Binary Search Tree"] != 1 {
		t.Errorf("expected Binary Search Tree, got %v", got)
	}
	if _, ok := got["Tree"]; ok {
		t.Errorf("generic Tree should not also match: %v", got)
	}
	// Acronym-prefixed names must match at the acronym boundary.
	got = detectedNames([]*parser.ParsedFile{file("b.go", ty("AVLTree")), file("c.go", ty("KDTree"))})
	if got["AVL Tree"] != 1 || got["k-d Tree"] != 1 {
		t.Errorf("acronym boundary match failed: %v", got)
	}
}

func TestDisambiguatesTrickyNames(t *testing.T) {
	files := []*parser.ParsedFile{
		file("a.go", ty("DirectedAcyclicGraph")), // must NOT collapse to "Directed Graph"
		file("b.go", ty("BrodalQueue")),          // a heap, not the generic Queue
		file("c.go", ty("HashTree")),             // a Merkle tree, not a Hash-* structure
		file("d.go", ty("Hypergraph")),           // lowercase-'g' suffix, exact match
		file("e.go", ty("PatriciaTrie")),
		file("f.go", ty("MinHash")), // must not collide with Min-Heap
	}
	got := detectedNames(files)
	for name, want := range map[string]int{
		"Directed Acyclic Graph": 1,
		"Brodal Queue":           1,
		"Merkle (Hash) Tree":     1,
		"Hypergraph":             1,
		"Patricia Trie":          1,
		"MinHash":                1,
	} {
		if got[name] != want {
			t.Errorf("expected %q ×%d, got %v", name, want, got)
		}
	}
	if _, ok := got["Directed Graph"]; ok {
		t.Errorf("DirectedAcyclicGraph must not also match Directed Graph: %v", got)
	}
	if _, ok := got["Queue"]; ok {
		t.Errorf("BrodalQueue must not also match generic Queue: %v", got)
	}
}

func TestIgnoresStdlibAndDomainCollections(t *testing.T) {
	// Standard-library / primitive collection names and ordinary domain
	// collections must NOT be counted as developer data structures.
	files := []*parser.ParsedFile{file("a.swift",
		ty("Set"), ty("Array"), ty("Dictionary"), ty("Map"), ty("List"),
		ty("UserList"), ty("ProductArray"), ty("TransformMatrix"), ty("Vector3"),
		ty("LinkedListNode"), // a node is part of, not the structure itself
	)}
	res := (Module{}).Analyze(files).(Result)
	if res.HasDetection() {
		t.Errorf("expected no detections, got %+v", res.Matches)
	}
}

func TestNonTypeKindsIgnored(t *testing.T) {
	// A function or variable named like a structure must not be counted.
	files := []*parser.ParsedFile{file("a.go",
		parser.Declaration{Name: "buildStack", Kind: parser.DeclFunc, Line: 1},
		parser.Declaration{Name: "globalQueue", Kind: parser.DeclVar, Line: 2},
	)}
	if (Module{}).Analyze(files).(Result).HasDetection() {
		t.Error("expected functions/vars to be ignored")
	}
}

func TestRenderHasCountAndVscodeLink(t *testing.T) {
	files := []*parser.ParsedFile{
		file("/abs/src/list.go", parser.Declaration{Name: "LinkedList", Kind: parser.DeclStruct, Line: 42}),
	}
	out := (Module{}).RenderHTML((Module{}).Analyze(files))
	if !strings.Contains(out, "Linked List") {
		t.Errorf("render missing structure name: %s", out)
	}
	if !strings.Contains(out, "×1") {
		t.Errorf("render missing count: %s", out)
	}
	if !strings.Contains(out, "vscode://file/abs/src/list.go:42") {
		t.Errorf("render missing vscode link: %s", out)
	}
}
