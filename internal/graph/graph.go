// Package graph builds a module-level dependency graph from parsed files and
// ranks hotspots with PageRank, ported from goscope. Nodes are module names;
// an edge A→B is inferred when a file in module A imports something whose final
// path segment matches module B (a deliberately coarse, language-agnostic
// heuristic — exact import resolution is out of scope for a static pass).
package graph

import (
	"sort"
	"strings"

	"github.com/exey/archscope/internal/parser"
)

// DependencyGraph is a directed graph over module names.
type DependencyGraph struct {
	nodes map[string]bool
	out   map[string]map[string]bool // module -> set of modules it depends on
	in    map[string]map[string]bool // module -> set of modules depending on it
	rank  map[string]float64
}

// New returns an empty graph.
func New() *DependencyGraph {
	return &DependencyGraph{
		nodes: map[string]bool{},
		out:   map[string]map[string]bool{},
		in:    map[string]map[string]bool{},
		rank:  map[string]float64{},
	}
}

// Build populates nodes and edges from the parsed files.
func (g *DependencyGraph) Build(files []*parser.ParsedFile) {
	// Index module names (and a lowercase first/last-segment alias) for import
	// matching. The first segment is what catches Go-style cross-service imports
	// like "userservice/services" → module "userservice"; the last segment
	// catches package-style imports.
	alias := map[string]string{} // lowercased name/segment -> canonical module
	var names []string
	for _, f := range files {
		m := f.ModuleName
		if m == "" {
			m = "root"
		}
		g.nodes[m] = true
		alias[strings.ToLower(m)] = m
		alias[strings.ToLower(firstSegment(m))] = m
		alias[strings.ToLower(lastSegment(m))] = m
		names = append(names, m)
	}
	resolve := func(imp string) (string, bool) {
		low := strings.ToLower(imp)
		if to, ok := alias[firstSegment(low)]; ok {
			return to, true
		}
		if to, ok := alias[lastSegment(low)]; ok {
			return to, true
		}
		// Prefix match (import path begins with a module name).
		for _, m := range names {
			ml := strings.ToLower(m)
			if low == ml || strings.HasPrefix(low, ml+"/") {
				return m, true
			}
		}
		return "", false
	}
	for _, f := range files {
		from := f.ModuleName
		if from == "" {
			from = "root"
		}
		for _, imp := range f.Imports {
			to, ok := resolve(imp)
			if !ok || to == from {
				continue
			}
			g.addEdge(from, to)
		}
	}
}

// firstSegment returns the first path component of a slash/dot path.
func firstSegment(s string) string {
	s = strings.ReplaceAll(s, "\\", "/")
	if i := strings.IndexAny(s, "/."); i >= 0 {
		return s[:i]
	}
	return s
}

func (g *DependencyGraph) addEdge(from, to string) {
	if g.out[from] == nil {
		g.out[from] = map[string]bool{}
	}
	if g.in[to] == nil {
		g.in[to] = map[string]bool{}
	}
	g.out[from][to] = true
	g.in[to][from] = true
}

// Analyze runs PageRank (damping 0.85, 40 iterations) over the module graph.
func (g *DependencyGraph) Analyze() {
	n := len(g.nodes)
	if n == 0 {
		return
	}
	const damping = 0.85
	const iters = 40
	init := 1.0 / float64(n)
	for node := range g.nodes {
		g.rank[node] = init
	}
	for i := 0; i < iters; i++ {
		next := make(map[string]float64, n)
		dangling := 0.0
		for node := range g.nodes {
			if len(g.out[node]) == 0 {
				dangling += g.rank[node]
			}
		}
		base := (1.0-damping)/float64(n) + damping*dangling/float64(n)
		for node := range g.nodes {
			next[node] = base
		}
		for node := range g.nodes {
			outs := g.out[node]
			if len(outs) == 0 {
				continue
			}
			share := damping * g.rank[node] / float64(len(outs))
			for dst := range outs {
				next[dst] += share
			}
		}
		g.rank = next
	}
}

// HotspotEntry is one ranked module.
type HotspotEntry struct {
	Name     string  `json:"name"`
	PageRank float64 `json:"pageRank"`
	InDeg    int     `json:"inDegree"`
	OutDeg   int     `json:"outDegree"`
}

// GetTopHotspots returns the highest-PageRank modules (limit<=0 = all).
func (g *DependencyGraph) GetTopHotspots(limit int) []HotspotEntry {
	out := make([]HotspotEntry, 0, len(g.nodes))
	for node := range g.nodes {
		out = append(out, HotspotEntry{
			Name:     node,
			PageRank: g.rank[node],
			InDeg:    len(g.in[node]),
			OutDeg:   len(g.out[node]),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PageRank != out[j].PageRank {
			return out[i].PageRank > out[j].PageRank
		}
		if out[i].InDeg != out[j].InDeg {
			return out[i].InDeg > out[j].InDeg
		}
		return out[i].Name < out[j].Name
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// NodeCount / EdgeCount expose graph size for the report summary.
// Edges returns module→module dependency pairs ({from, to}: from depends on to).
func (g *DependencyGraph) Edges() [][2]string {
	var out [][2]string
	for from, tos := range g.out {
		for to := range tos {
			out = append(out, [2]string{from, to})
		}
	}
	return out
}

// InDegree returns how many modules depend on the named module.
func (g *DependencyGraph) InDegree(module string) int { return len(g.in[module]) }

func (g *DependencyGraph) NodeCount() int { return len(g.nodes) }
func (g *DependencyGraph) EdgeCount() int {
	n := 0
	for _, outs := range g.out {
		n += len(outs)
	}
	return n
}

func lastSegment(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\\", "/")
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndexByte(s, '.'); i >= 0 && i < len(s)-1 {
		s = s[i+1:]
	}
	return s
}
