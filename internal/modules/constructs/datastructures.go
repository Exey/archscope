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

func init() { modules.Default.Register(DataStructures{}) }

// DataStructures is the universal developer-implemented data-structure
// detector. It classifies type declarations against a known catalog by
// longest-suffix name match, then gates the handful of generic single-word
// suffixes (Stack/Queue/Tree/…) behind body-evidence so a UI-framework
// `HStack` or a domain `MessageQueue` service is never mistaken for the data
// structure.
//
// It deliberately does NOT count language standard-library collections (Swift
// Array/Set/Dictionary, Go slice/map, Kotlin List, …) or primitives: the
// detector only inspects developer-declared type declarations, so a
// `class LinkedList` is the developer's own structure while a `let items:
// [User]` usage is invisible to it by construction.
//
// Ported from ArchSwiftScope's DataStructureDetector — the catalog, category
// icons, framework false-friends, and evidence-gating vocabulary follow it,
// generalized from Swift-only to every language ArchScope parses.
type DataStructures struct{}

func (DataStructures) ID() string                       { return "datastructures" }
func (DataStructures) Title() string                    { return "Data Structures" }
func (DataStructures) AppliesTo(languageID string) bool { return true } // universal

// category groups the detected structures for display; each carries an icon.
type category struct {
	label string
	icon  string
}

var (
	linear = category{"Linear · Lists · Stacks · Queues", "📚"}
	tree   = category{"Trees · Heaps", "🌲"}
	hashed = category{"Hash-Based", "#️⃣"}
	graph  = category{"Graphs", "🕸️"}
	other  = category{"Specialized", "🧩"}
	// linkedCat groups the name-free self-referential/linked-structure engine's
	// matches (see detectLinkedStructures) — a distinct category since these
	// names describe a *shape* found in the type graph, not a well-known
	// textbook structure name like the others.
	linkedCat = category{"Self-Referential · Linked", "🔗"}
)

// categoryOrder fixes the display order.
var categoryOrder = []category{linear, tree, hashed, graph, other, linkedCat}

// rule maps a declaration-name suffix (PascalCase, matched case-sensitively at
// a word boundary) to a canonical data-structure name and category.
type rule struct {
	suffix   string
	name     string
	category category
}

var rules = []rule{
	// ── Linear: arrays / lists / stacks / queues ────────────────────────────
	{"SinglyLinkedList", "Linked List", linear},
	{"DoublyLinkedList", "Linked List", linear},
	{"CircularLinkedList", "Linked List", linear},
	{"XorLinkedList", "Linked List", linear},
	{"LinkedList", "Linked List", linear},
	{"SkipList", "Skip List", linear},
	{"UnrolledList", "Unrolled Linked List", linear},
	{"SelfOrganizingList", "Self-Organizing List", linear},
	{"AssociationList", "Association List", linear},
	{"DifferenceList", "Difference List", linear},
	{"SortedList", "Sorted List", linear},
	{"FreeList", "Free List", linear},
	{"ConcTreeList", "Conc-Tree List", linear},
	{"ConcTree", "Conc-Tree List", linear},
	{"VList", "VList", linear},
	{"DynamicArray", "Dynamic Array", linear},
	{"GrowableArray", "Dynamic Array", linear},
	{"ArrayList", "Dynamic Array", linear},
	{"SortedArray", "Sorted Array", linear},
	{"ParallelArray", "Parallel Array", linear},
	{"HashedArrayTree", "Hashed Array Tree", linear},
	{"SuffixArray", "Suffix Array", linear},
	{"DopeVector", "Dope Vector", linear},
	{"PriorityQueue", "Priority Queue", linear},
	{"DoubleEndedQueue", "Deque", linear},
	{"BlockingQueue", "Blocking Queue", linear},
	{"ConcurrentQueue", "Concurrent Queue", linear},
	{"WorkQueue", "Work Queue", linear},
	// Deliberately no "DispatchQueue" rule: it is GCD's concurrency primitive,
	// not a data structure the codebase implements.
	{"MessageQueue", "Message Queue", linear},
	{"EventQueue", "Event Queue", linear},
	{"TaskQueue", "Task Queue", linear},
	{"CircularQueue", "Circular Buffer", linear},
	{"CircularBuffer", "Circular Buffer", linear},
	{"RingBuffer", "Circular Buffer", linear},
	{"DoubleBuffer", "Double Buffer", linear},
	{"TripleBuffer", "Triple Buffer", linear},
	{"Zipper", "Zipper", linear},
	{"Deque", "Deque", linear},
	{"Stack", "Stack", linear},
	{"Queue", "Queue", linear},

	// ── Trees & heaps ───────────────────────────────────────────────────────
	{"BinarySearchTree", "Binary Search Tree", tree},
	{"BST", "Binary Search Tree", tree},
	{"BinaryTree", "Binary Tree", tree},
	{"CartesianTree", "Cartesian Tree", tree},
	{"OrderStatisticTree", "Order Statistic Tree", tree},
	{"AVLTree", "AVL Tree", tree},
	{"RedBlackTree", "Red–Black Tree", tree},
	{"SplayTree", "Splay Tree", tree},
	{"ScapegoatTree", "Scapegoat Tree", tree},
	{"AATree", "AA Tree", tree},
	{"WeightBalancedTree", "Weight-Balanced Tree", tree},
	{"BPlusTree", "B+ Tree", tree},
	{"BTree", "B-Tree", tree},
	{"Treap", "Treap", tree},
	{"SegmentTree", "Segment Tree", tree},
	{"FenwickTree", "Fenwick Tree", tree},
	{"IntervalTree", "Interval Tree", tree},
	{"RangeTree", "Range Tree", tree},
	{"FingerTree", "Finger Tree", tree},
	{"SuffixTree", "Suffix Tree", tree},
	{"RadixTree", "Radix Tree", tree},
	{"CompressedTrie", "Compressed Trie", tree},
	{"TernarySearchTrie", "Ternary Search Trie", tree},
	{"PatriciaTrie", "Patricia Trie", tree},
	{"PatriciaTree", "Patricia Trie", tree},
	{"DoubleArrayTrie", "Double-Array Trie", tree},
	{"XFastTrie", "X-Fast Trie", tree},
	{"YFastTrie", "Y-Fast Trie", tree},
	{"PrefixTree", "Trie", tree},
	{"Trie", "Trie", tree},
	{"VanEmdeBoasTree", "van Emde Boas Tree", tree},
	{"LinkCutTree", "Link-Cut Tree", tree},
	{"EulerTourTree", "Euler Tour Tree", tree},
	{"KaryTree", "K-ary Tree", tree},
	{"TernaryTree", "Ternary Tree", tree},
	{"QuadTree", "Quadtree", tree},
	{"Quadtree", "Quadtree", tree},
	{"Octree", "Octree", tree},
	{"KDTree", "k-d Tree", tree},
	{"KdTree", "k-d Tree", tree},
	{"RStarTree", "R* Tree", tree},
	{"RPlusTree", "R+ Tree", tree},
	{"RTree", "R-Tree", tree},
	{"VPTree", "VP-Tree", tree},
	{"BKTree", "BK-Tree", tree},
	{"BSPTree", "BSP Tree", tree},
	{"HilbertRTree", "Hilbert R-Tree", tree},
	{"CoverTree", "Cover Tree", tree},
	{"MetricTree", "Metric Tree", tree},
	{"MTree", "M-Tree", tree},
	{"XTree", "X-Tree", tree},
	{"UBTree", "UB-Tree", tree},
	{"TTree", "T-Tree", tree},
	{"TangoTree", "Tango Tree", tree},
	{"TopTree", "Top Tree", tree},
	{"WAVLTree", "WAVL Tree", tree},
	{"ZipTree", "Zip Tree", tree},
	{"ThreadedBinaryTree", "Threaded Binary Tree", tree},
	{"RandomizedBST", "Randomized Binary Search Tree", tree},
	{"BVH", "Bounding Volume Hierarchy", tree},
	{"MerkleTree", "Merkle Tree", tree},
	{"HashTree", "Merkle (Hash) Tree", tree},
	{"LSMTree", "Log-Structured Merge-Tree", tree},
	{"AbstractSyntaxTree", "Abstract Syntax Tree", tree},
	{"SyntaxTree", "Syntax Tree", tree},
	{"ParseTree", "Parse Tree", tree},
	{"DecisionTree", "Decision Tree", tree},
	{"ExpressionTree", "Expression Tree", tree},
	{"FibonacciHeap", "Fibonacci Heap", tree},
	{"BinomialHeap", "Binomial Heap", tree},
	{"PairingHeap", "Pairing Heap", tree},
	{"LeftistHeap", "Leftist Heap", tree},
	{"SkewHeap", "Skew Heap", tree},
	{"DAryHeap", "d-ary Heap", tree},
	{"BrodalHeap", "Brodal Queue", tree},
	{"SoftHeap", "Soft Heap", tree},
	{"BinaryHeap", "Binary Heap", tree},
	{"IndexedHeap", "Indexed Heap", tree},
	{"MinMaxHeap", "Min-Max Heap", tree},
	{"MinHeap", "Min-Heap", tree},
	{"MaxHeap", "Max-Heap", tree},
	{"Heap", "Heap", tree},
	{"Tree", "Tree", tree},

	// ── Hash-based ──────────────────────────────────────────────────────────
	{"HashArrayMappedTrie", "Hash Array Mapped Trie", hashed},
	{"HashTable", "Hash Table", hashed},
	{"LinkedHashMap", "Hash Map", hashed},
	{"HashMap", "Hash Map", hashed},
	{"HashSet", "Hash Set", hashed},
	{"HashList", "Hash List", hashed},
	{"BloomFilter", "Bloom Filter", hashed},
	{"CountingBloomFilter", "Counting Bloom Filter", hashed},
	{"CuckooFilter", "Cuckoo Filter", hashed},
	{"QuotientFilter", "Quotient Filter", hashed},
	{"XorFilter", "Xor Filter", hashed},
	{"CuckooHash", "Cuckoo Hash Table", hashed},
	{"RobinHoodHash", "Robin Hood Hash Table", hashed},
	{"HopscotchHash", "Hopscotch Hash Table", hashed},
	{"OpenAddressing", "Open-Addressed Hash Table", hashed},
	{"CountMinSketch", "Count–Min Sketch", hashed},
	{"HyperLogLog", "HyperLogLog", hashed},
	{"ConsistentHashRing", "Consistent Hashing", hashed},
	{"ConsistentHash", "Consistent Hashing", hashed},
	{"RollingHash", "Rolling Hash", hashed},
	{"MinHash", "MinHash", hashed},
	{"SimHash", "SimHash", hashed},
	{"HAMT", "Hash Array Mapped Trie", hashed},

	// ── Graphs ──────────────────────────────────────────────────────────────
	{"DirectedAcyclicGraph", "Directed Acyclic Graph", graph},
	{"DirectedGraph", "Directed Graph", graph},
	{"UndirectedGraph", "Undirected Graph", graph},
	{"SceneGraph", "Scene Graph", graph},
	{"DisjointSet", "Disjoint-Set (Union-Find)", graph},
	{"UnionFind", "Disjoint-Set (Union-Find)", graph},
	{"AdjacencyList", "Adjacency List", graph},
	{"AdjacencyMatrix", "Adjacency Matrix", graph},
	{"IncidenceMatrix", "Incidence Matrix", graph},
	{"DoublyConnectedEdgeList", "Doubly Connected Edge List (DCEL)", graph},
	{"HalfEdgeList", "Doubly Connected Edge List (DCEL)", graph},
	{"EdgeList", "Edge List", graph},
	{"ControlFlowGraph", "Control-Flow Graph", graph},
	{"DependencyGraph", "Dependency Graph", graph},
	{"CallGraph", "Call Graph", graph},
	{"FlowNetwork", "Flow Network", graph},
	{"DiGraph", "Directed Graph", graph},
	{"Multigraph", "Multigraph", graph},
	{"Hypergraph", "Hypergraph", graph},
	{"DAG", "Directed Acyclic Graph", graph},
	{"Graph", "Graph", graph},

	// ── Specialized ─────────────────────────────────────────────────────────
	{"SparseMatrix", "Sparse Matrix", other},
	{"RoutingTable", "Routing Table", other},
	{"SymbolTable", "Symbol Table", other},
	{"LookupTable", "Lookup Table", other},
	{"JumpTable", "Jump Table", other},
	{"TranspositionTable", "Transposition Table", other},
	{"PieceTable", "Piece Table", other},
	{"BitArray", "Bit Array", other},
	{"SuccinctBitVector", "Succinct Bit Vector", other},
	{"BitVector", "Bit Vector", other},
	{"BitSet", "Bit Set", other},
	{"Bitset", "Bit Set", other},
	{"BitBoard", "Bitboard", other},
	{"BitField", "Bit Field", other},
	{"WaveletTree", "Wavelet Tree", other},
	{"GapBuffer", "Gap Buffer", other},
	{"LRUCache", "LRU Cache", other},
	{"LFUCache", "LFU Cache", other},
	{"ARCache", "Adaptive Replacement Cache", other},
	{"TwoQCache", "2Q Cache", other},
	{"Multiset", "Multiset (Bag)", other},
	{"OrderedSet", "Ordered Set", other},
	{"OrderedMap", "Ordered Map", other},
	{"OrderedDictionary", "Ordered Dictionary", other},
	{"SortedSet", "Sorted Set", other},
	{"SortedDictionary", "Sorted Dictionary", other},
	{"SortedMap", "Sorted Map", other},
	{"PersistentVector", "Persistent Vector", other},
	{"ImmutableArray", "Immutable Array", other},
	{"CopyOnWriteArray", "Copy-on-Write Array", other},
	{"Rope", "Rope", other},
	{"Blockchain", "Blockchain", other},
}

func init() {
	// Longest suffix wins: sort descending by suffix length once.
	sort.SliceStable(rules, func(i, j int) bool {
		return len(rules[i].suffix) > len(rules[j].suffix)
	})
}

// frameworkFalseFriends are UI-framework layout/navigation types whose names
// end in "Stack" but are views, never stack data structures — rejected outright.
var frameworkFalseFriends = map[string]bool{
	"HStack": true, "VStack": true, "ZStack": true,
	"LazyHStack": true, "LazyVStack": true, "NavigationStack": true,
}

// evidence is the structural vocabulary proving that a type matched on a
// generic single-word suffix (Stack/Queue/…) is a real implementation rather
// than a look-alike. Strong terms are unambiguous (2 points); weak terms are
// shared structural vocabulary (1 point). A body needs ≥ 2 points.
type evidence struct {
	strong map[string]bool
	weak   map[string]bool
}

func words(ws ...string) map[string]bool {
	m := make(map[string]bool, len(ws))
	for _, w := range ws {
		m[w] = true
	}
	return m
}

// evidenceBySuffix gates each generic single-word suffix behind its structure's
// vocabulary (whole-token match against the stripped, lowercased type body).
var evidenceBySuffix = map[string]evidence{
	"Stack": {
		strong: words("lifo"),
		weak:   words("push", "pop", "peek", "top", "node", "isempty"),
	},
	"Queue": {
		strong: words("enqueue", "dequeue", "fifo"),
		weak:   words("front", "rear", "head", "tail", "peek", "poll", "offer", "node"),
	},
	"Deque": {
		strong: words("pushfront", "pushback", "popfront", "popback", "enqueuefront", "enqueueback"),
		weak:   words("front", "back", "head", "tail", "enqueue", "dequeue", "push", "pop", "node"),
	},
	"Heap": {
		strong: words("heapify", "siftup", "siftdown", "percolateup", "percolatedown",
			"bubbleup", "bubbledown", "extractmin", "extractmax"),
		weak: words("sift", "percolate", "parent", "child", "peek", "node", "root"),
	},
	"Tree": {
		strong: words("subtree", "inorder", "preorder", "postorder", "leaf", "leaves",
			"sibling", "ancestor", "descendant", "rebalance"),
		weak: words("root", "parent", "child", "children", "node", "nodes", "depth",
			"height", "degree", "traverse", "rotate", "edge"),
	},
	"Trie": {
		strong: words("endofword", "isword", "isend", "isterminal", "wordend"),
		weak:   words("prefix", "children", "root", "node", "nodes", "word"),
	},
	"Graph": {
		// "adjacencyList"/"adjacencyMatrix" lowercase to one token each
		// ("adjacencylist"/"adjacencymatrix"), not "adjacency" + "list" —
		// bodyTokens splits on non-alphanumeric runs, so camelCase compounds
		// survive as a single token. Listed alongside bare "adjacency" so
		// both spellings count as strong evidence.
		strong: words("adjacency", "adjacencylist", "adjacencymatrix", "adjacent",
			"vertex", "vertices", "addedge", "addvertex", "indegree", "outdegree", "acyclic"),
		weak: words("edge", "edges", "node", "nodes", "neighbor", "neighbors",
			"neighbour", "neighbours", "degree", "cycle", "link", "matrix"),
	},
	"Rope": {
		strong: words(),
		weak:   words("concat", "substring", "split", "weight", "rebalance", "leaf", "node"),
	},
	"Multiset": {
		strong: words("multiplicity"),
		weak:   words("occurrences", "count", "add", "remove", "contains"),
	},
}

// hasEvidence reports whether a stripped, lowercased type body scores enough
// structural vocabulary (≥ 2 points) for the given structure. UI views are
// look-alikes by construction, so a SwiftUI `: some View` body never qualifies.
func hasEvidence(ev evidence, body string) bool {
	if strings.Contains(body, ": some view") {
		return false
	}
	score := 0
	for tok := range bodyTokens(body) {
		if ev.strong[tok] {
			score += 2
		} else if ev.weak[tok] {
			score++
		}
		if score >= 2 {
			return true
		}
	}
	return false
}

// Occurrence is one detected structure declaration with its location.
type Occurrence struct {
	TypeName string
	FilePath string // absolute path, for the vscode:// link
	Line     int
}

// Match is one canonical structure with all its occurrences.
type Match struct {
	Name        string
	Category    category
	Count       int
	Occurrences []Occurrence
	// Detail is an optional one-line explanation shown as a tooltip — used by
	// the linked-structure engine, whose match names describe a graph shape
	// rather than a well-known structure name (see linkedMatchDetail).
	Detail string
}

// Result is the module output.
type Result struct {
	Matches []Match
}

// HasDetection reports whether any custom structure was found.
func (r Result) HasDetection() bool { return len(r.Matches) > 0 }

// isTypeKind reports whether a declaration kind can name a data structure.
func isTypeKind(k parser.DeclKind) bool {
	switch k {
	case parser.DeclStruct, parser.DeclClass, parser.DeclInterface,
		parser.DeclEnum, parser.DeclActor, parser.DeclType:
		return true
	}
	return false
}

// Analyze scans type declarations across files, classifies them against the
// catalog, gates generic-suffix matches behind body evidence, and runs the
// name-free linked-structure engine over any Swift files present.
func (DataStructures) Analyze(files []*parser.ParsedFile) any {
	type agg struct {
		category category
		occ      []Occurrence
	}
	found := map[string]*agg{}
	cache := newSourceCache()
	skip := map[string]bool{} // types the suffix rules already claimed

	for _, f := range files {
		for _, d := range f.Declarations {
			if !isTypeKind(d.Kind) || frameworkFalseFriends[d.Name] {
				continue
			}
			r, ok := matchRule(d.Name)
			if !ok {
				continue
			}
			// Gate generic single-word suffixes behind body evidence: accept
			// only when the type's body proves it implements the structure.
			if ev, gated := evidenceBySuffix[r.suffix]; gated {
				lines := cache.lines(f.FilePath)
				if lines == nil {
					continue // unreadable/too large → can't prove it; reject
				}
				body := typeBody(lines, d.Name)
				if body == "" || !hasEvidence(ev, body) {
					continue
				}
			}
			a := found[r.name]
			if a == nil {
				a = &agg{category: r.category}
				found[r.name] = a
			}
			a.occ = append(a.occ, Occurrence{TypeName: d.Name, FilePath: f.FilePath, Line: d.Line})
			skip[d.Name] = true
		}
	}

	var matches []Match
	for name, a := range found {
		matches = append(matches, Match{
			Name: name, Category: a.category, Count: len(a.occ), Occurrences: a.occ,
		})
	}
	matches = append(matches, detectLinkedStructures(files, cache, skip)...)

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

// ── Self-referential / linked structures (Swift-only) ──────────────────────
//
// mx-find-linked-structures, ported from ArchSwiftScope's DataStructureDetector:
// a name-free detector that scans every type's stored-property field types,
// builds a self-reference graph, and propagates two hops to find both
// self-referential types (Level 0 — a type with a field of its own type) and
// types that embed them (Level 1/2 — a type with a field of a linked type).
// Swift-only: the field-type regex is Swift-syntax-specific (`var x: Type`);
// Go/Java/Kotlin/TS would each need their own field-declaration grammar to
// generalize correctly, which is out of scope here — mirrors the Swift-only
// content-scan precedent in designpattern.go's scanSwiftFile.

var (
	reLinkedTypeDecl = regexp.MustCompile(
		`^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|internal|fileprivate|open|package|final|indirect|nonisolated|dynamic)\s+)*(?:class|struct|enum|actor)\s+(\w+)`)
	reLinkedStoredProp = regexp.MustCompile(
		`^\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:(?:public|private|internal|fileprivate|open|package|final|weak|unowned|lazy|nonisolated)(?:\([^)]*\))?\s+)*(?:var|let)\s+(\w+)\s*:\s*([^={]+)`)
	reLinkedCasePayload = regexp.MustCompile(`^\s*(?:indirect\s+)?case\s+\w+[^(]*\(([^)]*)\)`)
	reLinkedTypeName    = regexp.MustCompile(`[A-Z][A-Za-z0-9_]*`)
)

// linkedTypeScan is one type declaration's field-reference profile.
type linkedTypeScan struct {
	name              string
	filePath          string
	line              int             // 1-based declaration line
	selfFieldNames    map[string]bool // lowercased names of self-referencing stored props
	selfViaCollection bool            // self reference wrapped in [ ] / Set< / Dictionary<
	selfViaEnumCase   bool            // self reference in an enum case payload
	fieldRefs         map[string]bool // every capitalized type name referenced by fields
}

func (t linkedTypeScan) isSelfRef() bool {
	return len(t.selfFieldNames) > 0 || t.selfViaEnumCase
}

// isComputedLinkedProperty reports whether a `var`/`let` line is a computed
// property (`{ get }`, or a bare getter body) rather than a stored one —
// `var parent: Node? { lookup() }` creates no actual object-graph edge.
// didSet/willSet observers still decorate a genuinely stored property, so
// those are let through.
func isComputedLinkedProperty(line string) bool {
	idx := strings.IndexByte(line, '{')
	if idx < 0 {
		return false
	}
	after := strings.TrimSpace(line[idx+1:])
	return !(strings.HasPrefix(after, "didSet") || strings.HasPrefix(after, "willSet"))
}

func linkedTypeNamesIn(s string) map[string]bool {
	out := map[string]bool{}
	for _, m := range reLinkedTypeName.FindAllString(s, -1) {
		out[m] = true
	}
	return out
}

// scanLinkedTypes scans one file for type declarations (any nesting depth)
// and collects each type's field-level type references. lines must already
// be comment/string stripped.
func scanLinkedTypes(lines []string, filePath string) []linkedTypeScan {
	var out []linkedTypeScan
	for i, line := range lines {
		caps := reLinkedTypeDecl.FindStringSubmatch(line)
		if caps == nil || caps[1] == "" {
			continue
		}
		name := caps[1]
		if frameworkFalseFriends[name] {
			continue
		}

		selfFieldNames := map[string]bool{}
		selfViaCollection := false
		selfViaEnumCase := false
		fieldRefs := map[string]bool{}

		depth, started := 0, false
		for j := i; j < len(lines); j++ {
			var l string
			if j == i {
				if idx := strings.IndexByte(lines[j], '{'); idx >= 0 {
					l = lines[j][idx+1:]
				}
			} else {
				l = lines[j]
			}
			if (started && depth == 1 && j > i) || (j == i && l != "") {
				if !strings.Contains(l, "static ") && !strings.Contains(l, " class var") &&
					!strings.Contains(l, " class let") && !isComputedLinkedProperty(l) {
					if p := reLinkedStoredProp.FindStringSubmatch(l); p != nil {
						propName, typeExpr := p[1], p[2]
						refs := linkedTypeNamesIn(typeExpr)
						for r := range refs {
							fieldRefs[r] = true
						}
						if refs[name] {
							selfFieldNames[strings.ToLower(propName)] = true
							if strings.Contains(typeExpr, "[") || strings.Contains(typeExpr, "Set<") ||
								strings.Contains(typeExpr, "Dictionary<") || strings.Contains(typeExpr, "Array<") {
								selfViaCollection = true
							}
						}
					} else if c := reLinkedCasePayload.FindStringSubmatch(l); c != nil {
						refs := linkedTypeNamesIn(c[1])
						for r := range refs {
							fieldRefs[r] = true
						}
						if refs[name] {
							selfViaEnumCase = true
						}
					}
				}
			}
			for k := 0; k < len(lines[j]); k++ {
				switch lines[j][k] {
				case '{':
					depth++
					started = true
				case '}':
					depth--
				}
			}
			if started && depth <= 0 {
				break
			}
		}

		delete(fieldRefs, name)
		out = append(out, linkedTypeScan{
			name: name, filePath: filePath, line: i + 1,
			selfFieldNames: selfFieldNames, selfViaCollection: selfViaCollection,
			selfViaEnumCase: selfViaEnumCase, fieldRefs: fieldRefs,
		})
	}
	return out
}

// linkedMatchDetail explains what a name-free linked-structure match name
// means — unlike every other category, these names describe a *shape*
// detected from the type graph rather than a well-known textbook structure.
var linkedMatchDetail = map[string]string{
	"Recursive Enum":                   "Indirect enum case whose payload references the enum itself — a recursive type (e.g. an expression or JSON tree).",
	"Binary Tree Node":                 "Type with both `left` and `right` fields referencing its own type — a binary tree node.",
	"Doubly Linked Node":               "Type with `next` and `prev`/`previous` fields referencing its own type — a doubly linked list node.",
	"Tree Node (self collection)":      "Type holding a collection ([…] / Set / Dictionary) of its own type — an N-ary tree or graph node.",
	"Singly Linked Node":               "Type with a `next` field referencing its own type — a singly linked list node.",
	"Self-Referential Type":            "Type with a stored property referencing its own type, in a shape other than the patterns above.",
	"Embeds Linked Structure (direct)": "Not self-referential itself, but has a field whose type is one of the self-referential types above.",
	"Embeds Linked Structure (nested)": "Not self-referential itself, but has a field whose type embeds one of the self-referential types above, one hop further in.",
}

// classifyLinkedShape names the level-0 shape from its self-referencing fields.
func classifyLinkedShape(t linkedTypeScan) string {
	f := t.selfFieldNames
	switch {
	case t.selfViaEnumCase:
		return "Recursive Enum"
	case f["left"] && f["right"]:
		return "Binary Tree Node"
	case f["next"] && (f["prev"] || f["previous"]):
		return "Doubly Linked Node"
	case t.selfViaCollection:
		return "Tree Node (self collection)"
	case f["next"]:
		return "Singly Linked Node"
	default:
		return "Self-Referential Type"
	}
}

// detectLinkedStructures runs mx-find-linked-structures over every Swift file:
// level 0 = self-linking types, then a bounded 2-hop fixpoint finds every
// type that (transitively) embeds one. skip excludes types the suffix rules
// already reported (e.g. a LinkedList that's also technically self-referential).
func detectLinkedStructures(files []*parser.ParsedFile, cache *sourceCache, skip map[string]bool) []Match {
	var scans []linkedTypeScan
	for _, f := range files {
		if !strings.HasSuffix(f.FilePath, ".swift") {
			continue
		}
		lines := cache.lines(f.FilePath)
		if lines == nil {
			continue
		}
		scans = append(scans, scanLinkedTypes(lines, f.FilePath)...)
	}
	if len(scans) == 0 {
		return nil
	}

	// Level 0.
	levelOf := map[string]int{}
	for _, t := range scans {
		if t.isSelfRef() {
			levelOf[t.name] = 0
		}
	}

	// Fixpoint: field references into the linked set pull the owner in.
	// Capped at L2 for the same reason as the reference — deeper transitive
	// membership buries the interesting L0/L1 signal in noise.
	linked := map[string]bool{}
	for n := range levelOf {
		linked[n] = true
	}
	for lvl := 1; lvl <= 2; lvl++ {
		var added []string
		for _, t := range scans {
			if _, ok := levelOf[t.name]; ok {
				continue
			}
			for r := range t.fieldRefs {
				if linked[r] {
					levelOf[t.name] = lvl
					added = append(added, t.name)
					break
				}
			}
		}
		if len(added) == 0 {
			break
		}
		for _, n := range added {
			linked[n] = true
		}
	}

	// Aggregate into Matches; skip types the suffix rules already report, and
	// dedupe types scanned more than once (e.g. via partial/extension redeclaration).
	type agg struct{ occ []Occurrence }
	found := map[string]*agg{}
	reported := map[string]bool{}
	for _, t := range scans {
		level, ok := levelOf[t.name]
		if !ok || skip[t.name] || reported[t.name] {
			continue
		}
		reported[t.name] = true
		var ruleName string
		switch level {
		case 0:
			ruleName = classifyLinkedShape(t)
		case 1:
			ruleName = "Embeds Linked Structure (direct)"
		default:
			ruleName = "Embeds Linked Structure (nested)"
		}
		a := found[ruleName]
		if a == nil {
			a = &agg{}
			found[ruleName] = a
		}
		a.occ = append(a.occ, Occurrence{TypeName: t.name, FilePath: t.filePath, Line: t.line})
	}

	var matches []Match
	for name, a := range found {
		matches = append(matches, Match{
			Name: name, Category: linkedCat, Count: len(a.occ), Occurrences: a.occ,
			Detail: linkedMatchDetail[name],
		})
	}
	return matches
}

// SummaryCards surfaces the number of distinct custom data structures found.
func (DataStructures) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(Result)
	if !ok || !r.HasDetection() {
		return nil
	}
	return []modules.SummaryCard{
		{Num: strconv.Itoa(len(r.Matches)), Label: plural(len(r.Matches), "data structure", "data structures")},
	}
}

// RenderMarkdown renders detected structures as a markdown table.
func (DataStructures) RenderMarkdown(res any) string {
	r, ok := res.(Result)
	if !ok || !r.HasDetection() {
		return ""
	}
	var b strings.Builder
	b.WriteString("| Structure | Count | Examples |\n")
	b.WriteString("|-----------|------:|---------|\n")
	for _, m := range r.Matches {
		var ex []string
		for i, o := range m.Occurrences {
			if i == 6 {
				ex = append(ex, fmt.Sprintf("+%d more", len(m.Occurrences)-6))
				break
			}
			ex = append(ex, fmt.Sprintf("%s (%s:%d)", o.TypeName, baseName(o.FilePath), o.Line))
		}
		fmt.Fprintf(&b, "| %s | %d | %s |\n", m.Name, m.Count, strings.Join(ex, ", "))
	}
	b.WriteString("\n")
	return b.String()
}

// maxLinksPerStructure caps the vscode links rendered per structure.
const maxLinksPerStructure = 12

// RenderHTML renders the structures grouped by category (with its icon), each
// with a count and vscode:// deep links to every declaration.
func (DataStructures) RenderHTML(res any) string {
	r, ok := res.(Result)
	if !ok {
		return ""
	}
	if !r.HasDetection() {
		return `<p class="as-empty">No developer-implemented data structures detected from naming conventions.</p>`
	}
	byCat := map[string][]Match{}
	for _, m := range r.Matches {
		byCat[m.Category.label] = append(byCat[m.Category.label], m)
	}
	var b strings.Builder
	b.WriteString(`<div class="as-dp">`)
	for _, cat := range categoryOrder {
		ms := byCat[cat.label]
		if len(ms) == 0 {
			continue
		}
		fmt.Fprintf(&b, `<div class="as-dp__group"><h5 class="as-sub">%s %s</h5><div class="as-dp__items">`,
			cat.icon, html.EscapeString(cat.label))
		for _, m := range ms {
			nameAttr := ""
			if m.Detail != "" {
				nameAttr = fmt.Sprintf(` title="%s"`, html.EscapeString(m.Detail))
			}
			fmt.Fprintf(&b, `<div class="as-dp__item"><span class="as-dp__name"%s>%s</span><span class="as-dp__count">×%d</span>`,
				nameAttr, html.EscapeString(m.Name), m.Count)
			b.WriteString(`<span class="as-dp__ex">`)
			for i, o := range m.Occurrences {
				if i == maxLinksPerStructure {
					fmt.Fprintf(&b, ` +%d more`, len(m.Occurrences)-maxLinksPerStructure)
					break
				}
				if i > 0 {
					b.WriteString(` · `)
				}
				b.WriteString(occurrenceLink(o.TypeName, o.FilePath, o.Line))
			}
			b.WriteString(`</span></div>`)
		}
		b.WriteString(`</div></div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// ── helpers ──────────────────────────────────────────────────────────────────

// matchRule returns the longest-suffix rule matching name. Because rules is
// sorted by suffix length descending, the first hit is the most specific.
func matchRule(name string) (rule, bool) {
	for _, r := range rules {
		if strings.HasSuffix(name, r.suffix) {
			return r, true
		}
	}
	// snake_case fallback: normalize "my_stack" to "MyStack" and re-check the
	// same suffix table, rather than maintaining a second, snake_case-flavored
	// copy of every rule. Handles multi-word suffixes too — "singly_linked_list"
	// → "SinglyLinkedList" — since the whole name is normalized, not just its
	// last segment.
	if snake := snakeToPascal(name); snake != name {
		for _, r := range rules {
			if strings.HasSuffix(snake, r.suffix) {
				return r, true
			}
		}
	}
	return rule{}, false
}

// snakeToPascal converts snake_case or SCREAMING_SNAKE_CASE to PascalCase so
// the PascalCase suffix table applies regardless of naming convention:
// "my_stack" → "MyStack", "LRU_CACHE" → "LruCache". Names without an
// underscore are returned unchanged (the common case, kept cheap).
func snakeToPascal(name string) string {
	if !strings.Contains(name, "_") {
		return name
	}
	var b strings.Builder
	for _, part := range strings.Split(name, "_") {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]))
		if len(part) > 1 {
			b.WriteString(strings.ToLower(part[1:]))
		}
	}
	return b.String()
}

func categoryRank(c category) int {
	for i, x := range categoryOrder {
		if x.label == c.label {
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
