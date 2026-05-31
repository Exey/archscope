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
