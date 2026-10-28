package constructs

import (
	"strings"
	"testing"
)

// Go methods — with or without a named receiver — are attributed to themselves,
// not lumped together as "(top level)".
func TestComplexityNamesGoMethods(t *testing.T) {
	src := `package x

func (Algo) First(xs, ys, zs []int) {
	for _, a := range xs {
		for _, b := range ys {
			for _, c := range zs {
				_ = a + b + c
			}
		}
	}
}

func (a *Algo) Second(xs, ys []int) {
	for _, a := range xs {
		for _, b := range ys {
			_ = a + b
		}
	}
}
`
	var usage CollectionUsage
	var time, space []Violation
	analyzeComplexity(strings.Split(src, "\n"), "/x/a.go", &usage, &time, &space, map[string]bool{})
	got := map[string]bool{}
	for _, v := range time {
		got[v.Symbol] = true
	}
	if !got["First"] || !got["Second"] || got["(top level)"] {
		t.Errorf("symbols = %v", got)
	}
}

func TestHierarchyWalkIsNotNested(t *testing.T) {
	src := `package p

func walk(types []T) {
	for _, tm := range types {
		for _, m := range tm.Methods {
			for _, e := range m.Refs {
				use(e)
			}
		}
	}
}

func triangle(items []int) {
	for i := range items {
		for j := range items {
			use(i + j)
		}
	}
}

func grouped(files []F, byCat map[string][]int, cats []string) {
	for _, f := range files {
		for _, c := range changes(f.Items) {
			use(c)
		}
	}
	for _, cat := range cats {
		for _, m := range byCat[cat] {
			use(m)
		}
	}
}

func related(xs []int) {
	for _, x := range xs {
		for _, y := range near(xs, x) {
			use(y)
		}
	}
}

func product(a, b []int) {
	for _, x := range a {
		for _, y := range b {
			use(x + y)
		}
	}
}
`
	var time, space []Violation
	analyzeComplexity(strings.Split(src, "\n"), "x.go", &CollectionUsage{}, &time, &space, map[string]bool{})
	got := map[string]int{}
	for _, v := range time {
		if v.Order > got[v.Symbol] {
			got[v.Symbol] = v.Order
		}
	}
	if got["walk"] != 0 {
		t.Errorf("walking a hierarchy once is linear, got depth %d", got["walk"])
	}
	if got["grouped"] != 0 {
		t.Errorf("a collection derived from the outer element is part of one walk, got depth %d", got["grouped"])
	}
	if got["related"] != 2 {
		t.Errorf("a collection built from the outer collection is a product, got depth %d", got["related"])
	}
	if got["triangle"] != 2 || got["product"] != 2 {
		t.Errorf("independent nested loops must still count: %v", got)
	}
}
