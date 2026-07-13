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
