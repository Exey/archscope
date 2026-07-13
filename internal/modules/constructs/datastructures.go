package constructs

import (
	"fmt"
	"html"
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
)

// categoryOrder fixes the display order.
var categoryOrder = []category{linear, tree, hashed, graph, other}

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
		strong: words("adjacency", "adjacent", "vertex", "vertices", "addedge", "addvertex",
			"indegree", "outdegree", "acyclic"),
		weak: words("edge", "edges", "node", "nodes", "neighbor", "neighbors",
			"neighbour", "neighbours", "degree", "cycle", "link"),
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
// catalog, and gates generic-suffix matches behind body evidence.
func (DataStructures) Analyze(files []*parser.ParsedFile) any {
	type agg struct {
		category category
		occ      []Occurrence
	}
	found := map[string]*agg{}
	cache := newSourceCache()

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
			fmt.Fprintf(&b, `<div class="as-dp__item"><span class="as-dp__name">%s</span><span class="as-dp__count">×%d</span>`,
				html.EscapeString(m.Name), m.Count)
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
	return rule{}, false
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
