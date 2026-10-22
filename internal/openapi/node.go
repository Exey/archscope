// Package openapi lints OpenAPI (Swagger 2 / OpenAPI 3.x) specifications — a Go
// port of the rules of ~/vacuum (a Spectral-style linter) that matter most when
// reviewing a merge request: operation ids, path parameters, references, security
// (the OWASP API rules), responses and schema hygiene. ArchScope has no external
// dependencies, so this package carries its own small YAML/JSON reader that keeps
// line numbers, which is what lets every finding point at a line of the spec.
package openapi

import (
	"sort"
	"strconv"
	"strings"
)

// Kind is the node type.
type Kind int

const (
	Null Kind = iota
	Scalar
	Map
	Seq
)

// Node is one YAML/JSON value with the line it starts on.
type Node struct {
	Kind   Kind
	Value  string   // scalar text (unquoted)
	Quoted bool     // scalar was quoted ("1" is a string, 1 is a number)
	Line   int      // 1-based
	Keys   []string // Map: keys in document order
	KLines []int    // Map: the line each key is written on
	Vals   []*Node  // Map: values parallel to Keys; Seq: the items
	Dups   []DupKey // Map: keys that appear more than once
}

// DupKey is a repeated mapping key.
type DupKey struct {
	Key  string
	Line int
}

// Get returns the value of key in a mapping, or nil.
func (n *Node) Get(key string) *Node {
	if n == nil || n.Kind != Map {
		return nil
	}
	for i, k := range n.Keys {
		if k == key {
			return n.Vals[i]
		}
	}
	return nil
}

// KeyLine is the line the key is written on (the node's own line when absent).
func (n *Node) KeyLine(key string) int {
	if n == nil {
		return 0
	}
	for i, k := range n.Keys {
		if k == key && i < len(n.KLines) {
			return n.KLines[i]
		}
	}
	return n.Line
}

// Path follows keys through nested mappings.
func (n *Node) Path(keys ...string) *Node {
	for _, k := range keys {
		if n = n.Get(k); n == nil {
			return nil
		}
	}
	return n
}

// Str is the scalar text of a node ("" for nil / non-scalars).
func (n *Node) Str() string {
	if n == nil || n.Kind != Scalar {
		return ""
	}
	return n.Value
}

// Bool reports a scalar true.
func (n *Node) Bool() bool { return n != nil && n.Kind == Scalar && !n.Quoted && n.Value == "true" }

// Has reports whether a mapping has the key (even with a null value).
func (n *Node) Has(key string) bool {
	if n == nil || n.Kind != Map {
		return false
	}
	for _, k := range n.Keys {
		if k == key {
			return true
		}
	}
	return false
}

// Items returns a sequence's items (nil otherwise).
func (n *Node) Items() []*Node {
	if n == nil || n.Kind != Seq {
		return nil
	}
	return n.Vals
}

// Pairs returns a mapping's (key, value) pairs in order.
func (n *Node) Pairs() ([]string, []*Node) {
	if n == nil || n.Kind != Map {
		return nil, nil
	}
	return n.Keys, n.Vals
}

// SortedKeys returns the mapping's keys sorted (for deterministic output).
func (n *Node) SortedKeys() []string {
	if n == nil || n.Kind != Map {
		return nil
	}
	k := append([]string(nil), n.Keys...)
	sort.Strings(k)
	return k
}

func (n *Node) setPair(key string, val *Node, line int) {
	for _, k := range n.Keys {
		if k == key {
			n.Dups = append(n.Dups, DupKey{Key: key, Line: line})
			break
		}
	}
	n.Keys = append(n.Keys, key)
	n.KLines = append(n.KLines, line)
	n.Vals = append(n.Vals, val)
}

func itoa(i int) string { return strconv.Itoa(i) }

func isTrimmedPrefix(s, p string) bool { return strings.HasPrefix(strings.TrimSpace(s), p) }
