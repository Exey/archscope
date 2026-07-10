// Package datastructures is a universal detector for custom data structures
// that developers implement themselves — linked lists, trees, heaps, graphs,
// tries, hash tables, and the like, drawn from Wikipedia's "List of data
// structures". It works purely from declaration-name conventions: a type whose
// name ends in "LinkedList", "BinaryTree", "MinHeap", "Trie", … is almost
// always an implementation of that structure.
//
// It deliberately does NOT count language standard-library collections (Swift
// Array/Set/Dictionary, Go slice/map, Kotlin List, …) or primitive types,
// because those are never re-declared as source types — the detector only ever
// inspects developer-declared type declarations, so a `class LinkedList` is the
// developer's own structure while a `let items: [User]` array usage is invisible
// to it by construction. Generic single-word collection names (List, Array,
// Set, Map, Dictionary, Table, Node, Buffer, Vector, Matrix) are intentionally
// excluded to avoid attributing ordinary domain collections (UserList,
// ProductArray) as data structures.
package datastructures

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

// Module is the universal custom-data-structure detector.
type Module struct{}

func (Module) ID() string                       { return "datastructures" }
func (Module) Title() string                    { return "Data Structures" }
func (Module) AppliesTo(languageID string) bool { return true } // universal

// category groups the detected structures for display.
type category string

const (
	linear category = "Linear · Lists · Stacks · Queues"
	tree   category = "Trees · Heaps"
	hashed category = "Hash-Based"
	graph  category = "Graphs"
	other  category = "Specialized"
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

// rules is the full keyword catalog. A type name is attributed to the rule
// whose suffix is the LONGEST match, so "BinarySearchTree" resolves to the
// specific "Binary Search Tree" rather than the generic "Tree". Kept sorted by
// suffix length (descending) in init() to make longest-match a first-hit scan.
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
	{"DynamicArray", "Dynamic Array", linear},
	{"GrowableArray", "Dynamic Array", linear},
	{"ArrayList", "Dynamic Array", linear},
	{"SortedArray", "Sorted Array", linear},
	{"ParallelArray", "Parallel Array", linear},
	{"HashedArrayTree", "Hashed Array Tree", linear},
	{"SuffixArray", "Suffix Array", linear},
	{"DopeVector", "Dope Vector", linear},
	{"PriorityQueue", "Priority Queue", linear},
	{"CircularQueue", "Circular Buffer", linear},
	{"CircularBuffer", "Circular Buffer", linear},
	{"RingBuffer", "Circular Buffer", linear},
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
	{"TangoTree", "Tango Tree", tree},
	{"AATree", "AA Tree", tree},
	{"WeightBalancedTree", "Weight-Balanced Tree", tree},
	{"BPlusTree", "B+ Tree", tree},
	{"BTree", "B-Tree", tree},
	{"FusionTree", "Fusion Tree", tree},
	{"DancingTree", "Dancing Tree", tree},
	{"VanEmdeBoasTree", "van Emde Boas Tree", tree},
	{"Treap", "Treap", tree},
	{"Queap", "Queap", tree},
	{"SegmentTree", "Segment Tree", tree},
	{"FenwickTree", "Fenwick Tree", tree},
	{"IntervalTree", "Interval Tree", tree},
	{"RangeTree", "Range Tree", tree},
	{"FingerTree", "Finger Tree", tree},
	{"LinkCutTree", "Link/Cut Tree", tree},
	{"RoseTree", "Rose Tree", tree},
	{"ExponentialTree", "Exponential Tree", tree},
	{"KAryTree", "k-ary Tree", tree},
	{"TernaryTree", "Ternary Tree", tree},
	{"SuffixTree", "Suffix Tree", tree},
	{"RadixTree", "Radix Tree", tree},
	{"PatriciaTree", "Patricia Trie", tree},
	{"PatriciaTrie", "Patricia Trie", tree},
	{"DoubleArrayTrie", "Double-Array Trie", tree},
	{"XFastTrie", "X-Fast Trie", tree},
	{"YFastTrie", "Y-Fast Trie", tree},
	{"PrefixTree", "Trie", tree},
	{"Trie", "Trie", tree},
	{"JudyArray", "Judy Array", tree},
	{"FMIndex", "FM-Index", tree},
	{"QuadTree", "Quadtree", tree},
	{"Quadtree", "Quadtree", tree},
	{"Octree", "Octree", tree},
	{"KDTree", "k-d Tree", tree},
	{"KdTree", "k-d Tree", tree},
	{"RStarTree", "R* Tree", tree},
	{"RPlusTree", "R+ Tree", tree},
	{"RTree", "R-Tree", tree},
	{"MetricTree", "Metric Tree", tree},
	{"CoverTree", "Cover Tree", tree},
	{"VPTree", "VP-Tree", tree},
	{"BKTree", "BK-Tree", tree},
	{"MTree", "M-Tree", tree},
	{"UBTree", "UB-Tree", tree},
	{"BSPTree", "BSP Tree", tree},
	{"BoundingVolumeHierarchy", "Bounding Volume Hierarchy", tree},
	{"BoundingIntervalHierarchy", "Bounding Interval Hierarchy", tree},
	{"BVH", "Bounding Volume Hierarchy", tree},
	{"AbstractSyntaxTree", "Abstract Syntax Tree", tree},
	{"SyntaxTree", "Syntax Tree", tree},
	{"ParseTree", "Parse Tree", tree},
	{"DecisionTree", "Decision Tree", tree},
	{"ExpressionTree", "Expression Tree", tree},
	{"MerkleTree", "Merkle Tree", tree},
	{"HashTree", "Merkle (Hash) Tree", tree},
	{"LogStructuredMergeTree", "Log-Structured Merge-Tree", tree},
	{"LSMTree", "Log-Structured Merge-Tree", tree},
	{"FibonacciHeap", "Fibonacci Heap", tree},
	{"BinomialHeap", "Binomial Heap", tree},
	{"PairingHeap", "Pairing Heap", tree},
	{"LeftistHeap", "Leftist Heap", tree},
	{"SkewHeap", "Skew Heap", tree},
	{"SoftHeap", "Soft Heap", tree},
	{"WeakHeap", "Weak Heap", tree},
	{"RadixHeap", "Radix Heap", tree},
	{"TernaryHeap", "Ternary Heap", tree},
	{"MinMaxHeap", "Min-Max Heap", tree},
	{"BrodalQueue", "Brodal Queue", tree},
	{"DAryHeap", "d-ary Heap", tree},
	{"DaryHeap", "d-ary Heap", tree},
	{"BinaryHeap", "Binary Heap", tree},
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
	{"CuckooFilter", "Cuckoo Filter", hashed},
	{"QuotientFilter", "Quotient Filter", hashed},
	{"CuckooHash", "Cuckoo Hash Table", hashed},
	{"CountMinSketch", "Count–Min Sketch", hashed},
	{"RollingHash", "Rolling Hash", hashed},
	{"MinHash", "MinHash", hashed},
	{"HAMT", "Hash Array Mapped Trie", hashed},
	{"Ctrie", "Concurrent Hash Trie", hashed},

	// ── Graphs ──────────────────────────────────────────────────────────────
	{"DirectedAcyclicGraph", "Directed Acyclic Graph", graph},
	{"DirectedGraph", "Directed Graph", graph},
	{"UndirectedGraph", "Undirected Graph", graph},
	{"SceneGraph", "Scene Graph", graph},
	{"BinaryDecisionDiagram", "Binary Decision Diagram", graph},
	{"DiGraph", "Directed Graph", graph},
	{"Multigraph", "Multigraph", graph},
	{"Hypergraph", "Hypergraph", graph},
	{"AdjacencyList", "Adjacency List", graph},
	{"AdjacencyMatrix", "Adjacency Matrix", graph},
	{"IncidenceMatrix", "Incidence Matrix", graph},
	{"DisjointSet", "Disjoint-Set (Union-Find)", graph},
	{"UnionFind", "Disjoint-Set (Union-Find)", graph},
	{"DAG", "Directed Acyclic Graph", graph},
	{"Graph", "Graph", graph},

	// ── Specialized ─────────────────────────────────────────────────────────
	{"SparseMatrix", "Sparse Matrix", other},
	{"RoutingTable", "Routing Table", other},
	{"SymbolTable", "Symbol Table", other},
	{"LookupTable", "Lookup Table", other},
	{"ControlTable", "Control Table", other},
	{"PageTable", "Page Table", other},
	{"BitArray", "Bit Array", other},
	{"BitVector", "Bit Vector", other},
	{"BitSet", "Bit Set", other},
	{"Bitset", "Bit Set", other},
	{"BitField", "Bit Field", other},
	{"Bitboard", "Bitboard", other},
	{"GapBuffer", "Gap Buffer", other},
	{"PieceTable", "Piece Table", other},
	{"DoublyConnectedEdgeList", "Doubly Connected Edge List", other},
	{"WingedEdge", "Winged Edge", other},
	{"QuadEdge", "Quad-Edge", other},
	{"HalfEdge", "Half-Edge (DCEL)", other},
	{"LRUCache", "LRU Cache", other},
	{"LFUCache", "LFU Cache", other},
	{"Rope", "Rope", other},
}

func init() {
	sort.SliceStable(rules, func(i, j int) bool {
		return len(rules[i].suffix) > len(rules[j].suffix)
	})
}

// Occurrence is one detected structure declaration with its location, used to
// build a vscode:// deep link in the report.
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

// Analyze scans type declarations across files and attributes structure roles.
func (Module) Analyze(files []*parser.ParsedFile) any {
	type agg struct {
		category category
		occ      []Occurrence
	}
	found := map[string]*agg{}

	for _, f := range files {
		for _, d := range f.Declarations {
			if !isTypeKind(d.Kind) {
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
func (Module) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(Result)
	if !ok || !r.HasDetection() {
		return nil
	}
	return []modules.SummaryCard{
		{Num: strconv.Itoa(len(r.Matches)), Label: plural(len(r.Matches), "data structure", "data structures")},
	}
}

// RenderMarkdown renders detected structures as a markdown table.
func (Module) RenderMarkdown(res any) string {
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

// maxLinksPerStructure caps the number of vscode links rendered per structure
// so a codebase with hundreds of Node/Tree types stays readable.
const maxLinksPerStructure = 12

// RenderHTML renders the structures grouped by category, each with its count
// and vscode:// deep links to every declaration.
func (Module) RenderHTML(res any) string {
	r, ok := res.(Result)
	if !ok {
		return ""
	}
	if !r.HasDetection() {
		return `<p class="as-empty">No developer-implemented data structures detected from naming conventions.</p>`
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
		fmt.Fprintf(&b, `<div class="as-dp__group"><h5 class="as-sub">%s</h5><div class="as-dp__items">`, html.EscapeString(string(cat)))
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

// matchRule returns the longest-suffix rule matching name. Because rules is
// sorted by suffix length descending, the first hit is the most specific.
func matchRule(name string) (rule, bool) {
	for _, r := range rules {
		if hasStructSuffix(name, r.suffix) {
			return r, true
		}
	}
	return rule{}, false
}

// hasStructSuffix reports whether name ends in suffix as a whole PascalCase
// segment. Since every suffix begins with an uppercase letter and the match is
// case-sensitive, a suffix match already lands on a segment boundary (e.g.
// "AVLTree" → "Tree", "LRUCache" → "Cache"); the only extra guard rejects a
// zero-length prefix mismatch, which strings.HasSuffix already handles.
func hasStructSuffix(name, suffix string) bool {
	return strings.HasSuffix(name, suffix)
}

func occurrenceLink(o Occurrence) string {
	label := o.TypeName
	href := vscodeHref(o.FilePath, o.Line)
	if href == "" {
		return html.EscapeString(label)
	}
	return fmt.Sprintf(`<a class="as-vs" href="%s" title="%s:%d">%s</a>`,
		html.EscapeString(href), html.EscapeString(baseName(o.FilePath)), o.Line, html.EscapeString(label))
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
