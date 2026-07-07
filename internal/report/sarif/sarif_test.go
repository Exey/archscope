package sarif

import (
	"encoding/json"
	"testing"

	"github.com/exey/archscope/internal/result"
	"github.com/exey/archscope/internal/security"
)

func sampleResult() *result.AnalysisResult {
	return &result.AnalysisResult{
		ProjectName: "demo",
		Security: []security.RuleResult{
			{
				Rule: security.Rule{
					ID: "universal.hardcoded_secrets", Name: "Hardcoded Secrets",
					Severity: security.SevHigh, Category: "insecure_data_storage",
					Description: "secret in source",
				},
				Findings: []security.Finding{
					{RuleID: "universal.hardcoded_secrets", File: "a/b.swift", Line: 42, Snippet: `let k = "x"`},
				},
				TotalCount: 1,
			},
			{
				Rule: security.Rule{
					ID: "swift.fatal_error", Name: "Fatal Error",
					Severity: security.SevLow, Category: "crash_factors",
				},
				Findings:   nil,
				TotalCount: 0,
			},
		},
	}
}

func TestBuildShape(t *testing.T) {
	log := Build(sampleResult())
	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "ArchScope" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("rules = %d, want 2", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 1 {
		t.Fatalf("results = %d, want 1 (only the rule with a finding)", len(run.Results))
	}
	r0 := run.Results[0]
	if r0.Level != "error" {
		t.Errorf("HIGH should map to error, got %q", r0.Level)
	}
	if r0.Locations[0].PhysicalLocation.Region.StartLine != 42 {
		t.Errorf("startLine = %d, want 42", r0.Locations[0].PhysicalLocation.Region.StartLine)
	}
	if r0.RuleIndex < 0 || r0.RuleIndex >= len(run.Tool.Driver.Rules) {
		t.Errorf("ruleIndex %d out of range", r0.RuleIndex)
	}
}

func TestBuildMarshalsToValidJSON(t *testing.T) {
	b, err := json.Marshal(Build(sampleResult()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back["$schema"] == nil {
		t.Errorf("missing $schema")
	}
}

func TestLevelMapping(t *testing.T) {
	if level(security.SevHigh) != "error" || level(security.SevMedium) != "warning" || level(security.SevLow) != "note" {
		t.Errorf("severity→level mapping incorrect")
	}
}

func TestBuildEmptyScanIsSchemaValid(t *testing.T) {
	// A clean scan must emit results:[] not results:null — null is rejected by
	// the SARIF schema and GitHub's upload endpoint.
	log := Build(&result.AnalysisResult{ProjectName: "clean"})
	b, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) == "" {
		t.Fatal("empty output")
	}
	// Confirm results is an array literal, not null.
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	runs, _ := raw["runs"].([]any)
	if len(runs) == 0 {
		t.Fatal("no runs")
	}
	run0, _ := runs[0].(map[string]any)
	results, ok := run0["results"]
	if !ok {
		t.Fatal("results key missing")
	}
	if results == nil {
		t.Fatal("results is null — must be []")
	}
}

func TestBuildCWEAndSecuritySeverity(t *testing.T) {
	res := &result.AnalysisResult{
		Security: []security.RuleResult{{
			Rule: security.Rule{
				ID: "universal.hardcoded_secrets", Name: "Hardcoded Secrets",
				Severity: security.SevHigh, CWE: "798",
			},
			Findings:   []security.Finding{{File: "src/config.go", Line: 5}},
			TotalCount: 1,
		}},
	}
	log := Build(res)
	desc := log.Runs[0].Tool.Driver.Rules[0]
	if desc.DefaultConfiguration == nil || desc.DefaultConfiguration.Level != "error" {
		t.Errorf("defaultConfiguration.level not set correctly")
	}
	props := desc.Properties
	if props == nil {
		t.Fatal("properties nil")
	}
	if props["security-severity"] != 8.0 {
		t.Errorf("security-severity = %v, want 8.0", props["security-severity"])
	}
	tags, _ := props["tags"].([]string)
	found := false
	for _, tag := range tags {
		if tag == "external/cwe/cwe-798" {
			found = true
		}
	}
	if !found {
		t.Errorf("CWE tag not found in tags: %v", tags)
	}
}

func TestBuildRelPathURIBaseID(t *testing.T) {
	res := &result.AnalysisResult{
		Security: []security.RuleResult{{
			Rule:       security.Rule{ID: "r1", Name: "R1", Severity: security.SevLow},
			Findings:   []security.Finding{{RelPath: "internal/foo/bar.go", Line: 1}},
			TotalCount: 1,
		}},
	}
	log := Build(res)
	run := log.Runs[0]
	if run.OriginalURIBaseIDs["SRCROOT"].URI != "./" {
		t.Errorf("originalUriBaseIds[SRCROOT] = %q, want ./", run.OriginalURIBaseIDs["SRCROOT"].URI)
	}
	loc := run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation
	if loc.URI != "internal/foo/bar.go" {
		t.Errorf("uri = %q, want internal/foo/bar.go", loc.URI)
	}
	if loc.URIBaseID != "SRCROOT" {
		t.Errorf("uriBaseId = %q, want SRCROOT", loc.URIBaseID)
	}
}
