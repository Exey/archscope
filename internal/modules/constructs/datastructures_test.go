package constructs

import (
	"os"
	"path/filepath"
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
	res := (DataStructures{}).Analyze(files).(Result)
	got := map[string]int{}
	for _, m := range res.Matches {
		got[m.Name] = m.Count
	}
	return got
}

// writeFile writes src to a temp file with the given extension and returns a
// ParsedFile carrying its absolute path plus the given declarations.
func writeFile(t *testing.T, ext, src string, decls ...parser.Declaration) *parser.ParsedFile {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f"+ext)
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return &parser.ParsedFile{FilePath: p, Declarations: decls}
}

func TestDetectsCoreStructures(t *testing.T) {
	// All non-gated (compound) suffixes: detected from the name alone.
	files := []*parser.ParsedFile{
		file("a.swift", ty("DoublyLinkedList")),
		file("b.kt", ty("MinHeap")),
		file("c.ts", ty("BinarySearchTree")),
		file("d.go", ty("DirectedGraph")),
		file("e.py", ty("PrefixTree")), // → "Trie" (suffix "PrefixTree", not gated)
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

func TestDetectsBSTAcronymSuffix(t *testing.T) {
	got := detectedNames([]*parser.ParsedFile{file("a.go", ty("NodeBST"))})
	if got["Binary Search Tree"] != 1 {
		t.Errorf("expected Binary Search Tree from BST acronym suffix, got %v", got)
	}
}

func TestSnakeCaseSuffixMatching(t *testing.T) {
	files := []*parser.ParsedFile{
		file("a.go", ty("my_stack")),           // real Stack — gated, needs body evidence
		file("b.go", ty("my_linked_list")),     // unambiguous compound suffix — no gating
		file("c.go", ty("singly_linked_list")), // multi-word suffix, exact PascalCase name
		file("d.go", ty("event_queue")),        // compound suffix, single underscore word
	}
	got := detectedNames(files)
	if got["Linked List"] != 2 {
		t.Errorf("expected Linked List ×2 (my_linked_list, singly_linked_list), got %v", got)
	}
	if got["Event Queue"] != 1 {
		t.Errorf("expected Event Queue, got %v", got)
	}
	// my_stack has no push/pop evidence in its (empty) body — must stay rejected,
	// same as the PascalCase gating behavior.
	if _, ok := got["Stack"]; ok {
		t.Errorf("snake_case Stack without body evidence must still be rejected: %v", got)
	}
}

func TestSnakeCaseDoesNotDoubleMatchAlreadyPascalNames(t *testing.T) {
	// A name with no underscore must go through the exact-case path only,
	// unaffected by the snake_case fallback.
	got := detectedNames([]*parser.ParsedFile{file("a.go", ty("LinkedList"))})
	if got["Linked List"] != 1 {
		t.Errorf("expected Linked List ×1, got %v", got)
	}
}

func TestLongestMatchWins(t *testing.T) {
	got := detectedNames([]*parser.ParsedFile{file("a.go", ty("BinarySearchTree"))})
	if got["Binary Search Tree"] != 1 {
		t.Errorf("expected Binary Search Tree, got %v", got)
	}
	if _, ok := got["Tree"]; ok {
		t.Errorf("generic Tree should not also match: %v", got)
	}
	got = detectedNames([]*parser.ParsedFile{file("b.go", ty("AVLTree")), file("c.go", ty("KDTree"))})
	if got["AVL Tree"] != 1 || got["k-d Tree"] != 1 {
		t.Errorf("acronym boundary match failed: %v", got)
	}
}

func TestDisambiguatesTrickyNames(t *testing.T) {
	files := []*parser.ParsedFile{
		file("a.go", ty("DirectedAcyclicGraph")), // must NOT collapse to "Directed Graph"
		file("b.go", ty("BrodalHeap")),           // → "Brodal Queue", not the generic Queue
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
}

func TestIgnoresStdlibAndDomainCollections(t *testing.T) {
	files := []*parser.ParsedFile{file("a.swift",
		ty("Set"), ty("Array"), ty("Dictionary"), ty("Map"), ty("List"),
		ty("UserList"), ty("ProductArray"), ty("TransformMatrix"), ty("Vector3"),
		ty("LinkedListNode"), // a node is part of, not the structure itself
	)}
	if (DataStructures{}).Analyze(files).(Result).HasDetection() {
		t.Errorf("expected no detections, got %+v", (DataStructures{}).Analyze(files).(Result).Matches)
	}
}

func TestNonTypeKindsIgnored(t *testing.T) {
	files := []*parser.ParsedFile{file("a.go",
		parser.Declaration{Name: "buildStack", Kind: parser.DeclFunc, Line: 1},
		parser.Declaration{Name: "globalQueue", Kind: parser.DeclVar, Line: 2},
	)}
	if (DataStructures{}).Analyze(files).(Result).HasDetection() {
		t.Error("expected functions/vars to be ignored")
	}
}

// ── Evidence gating (generic single-word suffixes) ───────────────────────────

func TestGenericSuffixNeedsBodyEvidence(t *testing.T) {
	// A real Stack implementation: push/pop vocabulary in the body → accepted.
	realStack := writeFile(t, ".swift",
		"final class IntStack {\n    private var items: [Int] = []\n    func push(_ x: Int) { items.append(x) }\n    func pop() -> Int? { items.popLast() }\n}\n",
		parser.Declaration{Name: "IntStack", Kind: parser.DeclClass, Line: 1})
	if detectedNames([]*parser.ParsedFile{realStack})["Stack"] != 1 {
		t.Errorf("real Stack with push/pop body should be detected")
	}

	// A service that merely ends in "Stack" but has no stack vocabulary → rejected.
	notStack := writeFile(t, ".swift",
		"final class TelemetryStack {\n    func report(_ e: Event) { send(e) }\n    func flush() {}\n}\n",
		parser.Declaration{Name: "TelemetryStack", Kind: parser.DeclClass, Line: 1})
	if (DataStructures{}).Analyze([]*parser.ParsedFile{notStack}).(Result).HasDetection() {
		t.Errorf("look-alike Stack without body evidence must be rejected")
	}
}

func TestGraphEvidenceRecognizesCamelCaseCompounds(t *testing.T) {
	// "adjacencyList"/"adjacencyMatrix" lowercase to one token each
	// ("adjacencylist"/"adjacencymatrix"), not "adjacency" as its own word —
	// must still count as strong evidence, not just bare "adjacency".
	g := writeFile(t, ".go",
		"type CityGraph struct {\n\tadjacencyList map[int][]int\n}\n",
		parser.Declaration{Name: "CityGraph", Kind: parser.DeclStruct, Line: 1})
	if detectedNames([]*parser.ParsedFile{g})["Graph"] != 1 {
		t.Errorf("expected Graph detected from adjacencyList field")
	}
}

func TestRejectsFrameworkFalseFriendsAndViews(t *testing.T) {
	// SwiftUI layout views are rejected by name outright.
	for _, name := range []string{"HStack", "VStack", "ZStack", "NavigationStack"} {
		f := file("v.swift", parser.Declaration{Name: name, Kind: parser.DeclStruct, Line: 1})
		if (DataStructures{}).Analyze([]*parser.ParsedFile{f}).(Result).HasDetection() {
			t.Errorf("%s is a SwiftUI view, must not be a data structure", name)
		}
	}
	// A custom `…Stack` whose body is a SwiftUI view (`: some View`) is rejected
	// even though its name isn't in the hard-coded false-friend set.
	cardStack := writeFile(t, ".swift",
		"struct CardStack {\n    var body: some View { Text(\"hi\") }\n}\n",
		parser.Declaration{Name: "CardStack", Kind: parser.DeclStruct, Line: 1})
	if (DataStructures{}).Analyze([]*parser.ParsedFile{cardStack}).(Result).HasDetection() {
		t.Errorf("CardStack view (: some View) must be rejected")
	}
}

// ── Self-referential / linked structures (name-free, Swift-only) ────────────

func TestLinkedDetectsSinglyLinkedNode(t *testing.T) {
	f := writeFile(t, ".swift",
		"final class ListNode {\n    var next: ListNode?\n    var value: Int = 0\n}\n",
		parser.Declaration{Name: "ListNode", Kind: parser.DeclClass, Line: 1})
	got := detectedNames([]*parser.ParsedFile{f})
	if got["Singly Linked Node"] != 1 {
		t.Errorf("expected Singly Linked Node, got %v", got)
	}
}

func TestLinkedDetectsBinaryTreeAndDoublyLinkedShapes(t *testing.T) {
	f := writeFile(t, ".swift",
		"final class BTNode {\n    var left: BTNode?\n    var right: BTNode?\n}\n"+
			"final class DLNode {\n    var next: DLNode?\n    var prev: DLNode?\n}\n",
		parser.Declaration{Name: "BTNode", Kind: parser.DeclClass, Line: 1},
		parser.Declaration{Name: "DLNode", Kind: parser.DeclClass, Line: 4})
	got := detectedNames([]*parser.ParsedFile{f})
	if got["Binary Tree Node"] != 1 {
		t.Errorf("expected Binary Tree Node, got %v", got)
	}
	if got["Doubly Linked Node"] != 1 {
		t.Errorf("expected Doubly Linked Node, got %v", got)
	}
}

func TestLinkedDetectsTreeNodeSelfCollectionAndSelfReferentialType(t *testing.T) {
	f := writeFile(t, ".swift",
		"final class TreeNode2 {\n    var children: [TreeNode2] = []\n}\n"+
			"final class Employee {\n    var manager: Employee?\n}\n",
		parser.Declaration{Name: "TreeNode2", Kind: parser.DeclClass, Line: 1},
		parser.Declaration{Name: "Employee", Kind: parser.DeclClass, Line: 4})
	got := detectedNames([]*parser.ParsedFile{f})
	if got["Tree Node (self collection)"] != 1 {
		t.Errorf("expected Tree Node (self collection), got %v", got)
	}
	if got["Self-Referential Type"] != 1 {
		t.Errorf("expected Self-Referential Type for Employee.manager, got %v", got)
	}
}

func TestLinkedDetectsRecursiveEnum(t *testing.T) {
	f := writeFile(t, ".swift",
		"indirect enum Expr {\n    case add(Expr, Expr)\n    case lit(Int)\n}\n",
		parser.Declaration{Name: "Expr", Kind: parser.DeclEnum, Line: 1})
	got := detectedNames([]*parser.ParsedFile{f})
	if got["Recursive Enum"] != 1 {
		t.Errorf("expected Recursive Enum, got %v", got)
	}
}

func TestLinkedDetectsEmbeddingLevels(t *testing.T) {
	// Container directly embeds the self-referential ListNode (L1); Wrapper
	// embeds Container, one hop further in (L2).
	f := writeFile(t, ".swift",
		"final class ListNode {\n    var next: ListNode?\n}\n"+
			"final class Container {\n    var head: ListNode?\n}\n"+
			"final class Wrapper {\n    var box: Container?\n}\n",
		parser.Declaration{Name: "ListNode", Kind: parser.DeclClass, Line: 1},
		parser.Declaration{Name: "Container", Kind: parser.DeclClass, Line: 4},
		parser.Declaration{Name: "Wrapper", Kind: parser.DeclClass, Line: 7})
	got := detectedNames([]*parser.ParsedFile{f})
	if got["Embeds Linked Structure (direct)"] != 1 {
		t.Errorf("expected Embeds Linked Structure (direct) for Container, got %v", got)
	}
	if got["Embeds Linked Structure (nested)"] != 1 {
		t.Errorf("expected Embeds Linked Structure (nested) for Wrapper, got %v", got)
	}
}

func TestLinkedSkipsTypesAlreadyClaimedBySuffixRules(t *testing.T) {
	// A type suffix-matched as "Linked List" (LinkedList) must not also be
	// double-reported by the name-free engine, even though it's structurally
	// self-referential too.
	f := writeFile(t, ".swift",
		"final class MyLinkedList {\n    var next: MyLinkedList?\n}\n",
		parser.Declaration{Name: "MyLinkedList", Kind: parser.DeclClass, Line: 1})
	got := detectedNames([]*parser.ParsedFile{f})
	if got["Linked List"] != 1 {
		t.Errorf("expected suffix match Linked List, got %v", got)
	}
	if _, ok := got["Singly Linked Node"]; ok {
		t.Errorf("MyLinkedList should not be double-reported by the linked-structure engine: %v", got)
	}
}

func TestLinkedIgnoresComputedProperties(t *testing.T) {
	// `var parent: Node? { lookup() }` is a computed property — it creates no
	// stored self-reference edge and must not count.
	f := writeFile(t, ".swift",
		"final class LooksLinked {\n    var parent: LooksLinked? { lookup() }\n    func lookup() -> LooksLinked? { nil }\n}\n",
		parser.Declaration{Name: "LooksLinked", Kind: parser.DeclClass, Line: 1})
	got := detectedNames([]*parser.ParsedFile{f})
	for name := range got {
		if strings.Contains(name, "Linked") || strings.Contains(name, "Self-Referential") {
			t.Errorf("computed property must not count as a self-reference: %v", got)
		}
	}
}

func TestRenderHasCountIconAndVscodeLink(t *testing.T) {
	files := []*parser.ParsedFile{
		file("/abs/src/list.go", parser.Declaration{Name: "LinkedList", Kind: parser.DeclStruct, Line: 42}),
	}
	out := (DataStructures{}).RenderHTML((DataStructures{}).Analyze(files))
	if !strings.Contains(out, "Linked List") {
		t.Errorf("render missing structure name: %s", out)
	}
	if !strings.Contains(out, "×1") {
		t.Errorf("render missing count: %s", out)
	}
	if !strings.Contains(out, "📚") {
		t.Errorf("render missing category icon: %s", out)
	}
	if !strings.Contains(out, "vscode://file/abs/src/list.go:42") {
		t.Errorf("render missing vscode link: %s", out)
	}
}
