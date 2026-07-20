package constructs

import (
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func TestLCOMStatsFullyCohesive(t *testing.T) {
	// Two methods sharing the same single field: 1 pair, shares a field →
	// P=0, Q=1 → LCOM=0; one connected component → LCOM4=1.
	methods := []parser.MethodMembers{
		{Name: "A", FieldRefs: []string{"x"}},
		{Name: "B", FieldRefs: []string{"x"}},
	}
	lcom, lcom4 := lcomStats(methods)
	if lcom != 0 || lcom4 != 1 {
		t.Fatalf("want LCOM=0 LCOM4=1, got LCOM=%d LCOM4=%d", lcom, lcom4)
	}
}

func TestLCOMStatsSplitClass(t *testing.T) {
	// A/B share field x; C/D share field y; no field spans both groups →
	// two connected components (the class does two unrelated things).
	methods := []parser.MethodMembers{
		{Name: "A", FieldRefs: []string{"x"}},
		{Name: "B", FieldRefs: []string{"x"}},
		{Name: "C", FieldRefs: []string{"y"}},
		{Name: "D", FieldRefs: []string{"y"}},
	}
	lcom, lcom4 := lcomStats(methods)
	// Pairs: AB(share) BC(no) BD(no) AC(no) AD(no) CD(share) → P=4, Q=2 → LCOM=2.
	if lcom != 2 {
		t.Errorf("want LCOM=2, got %d", lcom)
	}
	if lcom4 != 2 {
		t.Errorf("want LCOM4=2 (two connected components), got %d", lcom4)
	}
}

func TestCAMScoreIdenticalVocabulary(t *testing.T) {
	methods := []parser.MethodMembers{
		{Name: "A", ParamTypes: []string{"User", "Logger"}},
		{Name: "B", ParamTypes: []string{"User", "Logger"}},
	}
	if cam := camScore(methods); cam != 1 {
		t.Fatalf("want CAM=1 for identical param-type vocabulary, got %.2f", cam)
	}
}

func TestCAMScoreDisjointVocabulary(t *testing.T) {
	methods := []parser.MethodMembers{
		{Name: "A", ParamTypes: []string{"User"}},
		{Name: "B", ParamTypes: []string{"Logger"}},
	}
	// dt=2 distinct types, each used by exactly 1 of 2 methods: sum=2, n*dt=4 → CAM=0.5.
	if cam := camScore(methods); cam != 0.5 {
		t.Fatalf("want CAM=0.5 for fully disjoint param types, got %.2f", cam)
	}
}

func ccFile(moduleName string, imports []string, members []parser.TypeMembers) *parser.ParsedFile {
	f := &parser.ParsedFile{
		FilePath:   moduleName + "/f.go",
		ModuleName: moduleName,
		Imports:    imports,
		LineCount:  100,
	}
	if len(members) > 0 {
		f.Extra = map[string]any{"members": members}
	}
	return f
}

func TestCouplingCohesionAnalyze(t *testing.T) {
	files := []*parser.ParsedFile{
		ccFile("core", nil, []parser.TypeMembers{
			{
				TypeName: "Service",
				Fields:   []string{"x", "y"},
				Methods: []parser.MethodMembers{
					{Name: "A", FieldRefs: []string{"x"}},
					{Name: "B", FieldRefs: []string{"y"}},
				},
			},
		}),
		ccFile("api", []string{"core"}, nil),
	}
	res := CouplingCohesion{}.Analyze(files).(CouplingCohesionResult)
	if !res.HasData() {
		t.Fatal("want HasData() true")
	}
	if !res.HasCohesionData {
		t.Fatal("want HasCohesionData true (one file had Extra[\"members\"])")
	}
	var core *ModuleCoupling
	for i := range res.Modules {
		if res.Modules[i].Name == "core" {
			core = &res.Modules[i]
		}
	}
	if core == nil {
		t.Fatalf("want a \"core\" module entry, got %+v", res.Modules)
	}
	if core.Ca != 1 {
		t.Errorf("want core.Ca=1 (api imports it), got %d", core.Ca)
	}
	if len(res.Cohesion) != 1 || res.Cohesion[0].TypeName != "Service" {
		t.Fatalf("want one Cohesion entry for Service, got %+v", res.Cohesion)
	}
	if res.CouplingScore < 5 || res.CouplingScore > 100 {
		t.Errorf("CouplingScore out of range: %d", res.CouplingScore)
	}
	if res.CohesionScore < 5 || res.CohesionScore > 100 {
		t.Errorf("CohesionScore out of range: %d", res.CohesionScore)
	}
}

func TestCouplingCohesionAnalyzeNoGoData(t *testing.T) {
	files := []*parser.ParsedFile{
		ccFile("web", []string{"api"}, nil),
		ccFile("api", nil, nil),
	}
	res := CouplingCohesion{}.Analyze(files).(CouplingCohesionResult)
	if res.HasCohesionData {
		t.Fatal("want HasCohesionData false when no file has Extra[\"members\"]")
	}
	if len(res.Cohesion) != 0 {
		t.Fatalf("want no Cohesion entries, got %+v", res.Cohesion)
	}
}
