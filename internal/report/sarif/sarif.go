// Package sarif renders an AnalysisResult to a single SARIF 2.1.0 log. Each
// security rule becomes a reportingDescriptor under the tool driver's rules[],
// and each finding becomes a result with one physical location (file +
// startLine) and a level mapped from severity (HIGH→error, MEDIUM→warning,
// LOW→note). A multi-language repo emits ONE combined log: each result already
// carries its file path, which encodes language and platform, matching how
// SARIF viewers and code-scanning dashboards expect a single artifact.
package sarif

import (
	"encoding/json"
	"os"

	"github.com/exey/archscope/internal/report"
	"github.com/exey/archscope/internal/result"
	"github.com/exey/archscope/internal/security"
)

// Write emits a SARIF 2.1.0 log for the whole analysis to outPath.
func Write(res *result.AnalysisResult, outPath string) error {
	data, err := json.MarshalIndent(Build(res), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, append(data, '\n'), 0o644)
}

// Build constructs the SARIF document (separated from Write for testability).
func Build(res *result.AnalysisResult) sarifLog {
	ruleIndex := map[string]int{}
	var descriptors []descriptor
	var results []sarifResult

	for _, rr := range res.Security {
		idx, ok := ruleIndex[rr.Rule.ID]
		if !ok {
			idx = len(descriptors)
			ruleIndex[rr.Rule.ID] = idx
			descriptors = append(descriptors, descriptor{
				ID:               rr.Rule.ID,
				Name:             rr.Rule.Name,
				ShortDescription: message{Text: rr.Rule.Name},
				FullDescription:  fullDesc(rr.Rule.Description),
				Properties: map[string]any{
					"category": rr.Rule.Category,
					"severity": string(rr.Rule.Severity),
				},
			})
		}
		for _, f := range rr.Findings {
			results = append(results, sarifResult{
				RuleID:    rr.Rule.ID,
				RuleIndex: idx,
				Level:     level(rr.Rule.Severity),
				Message:   message{Text: messageText(rr.Rule, f)},
				Locations: []location{{
					PhysicalLocation: physical{
						ArtifactLocation: artifact{URI: uri(f)},
						Region:           region{StartLine: maxInt(f.Line, 1)},
					},
				}},
			})
		}
	}

	return sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{{
			Tool: tool{Driver: driver{
				Name:           "ArchScope",
				Version:        report.Version,
				InformationURI: "https://github.com/exey/archscope",
				Rules:          descriptors,
			}},
			Results: results,
		}},
	}
}

func level(s security.Severity) string {
	switch s {
	case security.SevHigh:
		return "error"
	case security.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

func messageText(r security.Rule, f security.Finding) string {
	if f.Snippet != "" {
		return r.Name + ": " + f.Snippet
	}
	return r.Name + " detected."
}

func uri(f security.Finding) string {
	if f.File != "" {
		return f.File
	}
	return f.FullPath
}

func fullDesc(s string) *message {
	if s == "" {
		return nil
	}
	return &message{Text: s}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ── SARIF 2.1.0 minimal object model ─────────────────────────────────────────

type sarifLog struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool    tool          `json:"tool"`
	Results []sarifResult `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string       `json:"name"`
	Version        string       `json:"version"`
	InformationURI string       `json:"informationUri,omitempty"`
	Rules          []descriptor `json:"rules"`
}

type descriptor struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription message        `json:"shortDescription"`
	FullDescription  *message       `json:"fullDescription,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type message struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string     `json:"ruleId"`
	RuleIndex int        `json:"ruleIndex"`
	Level     string     `json:"level"`
	Message   message    `json:"message"`
	Locations []location `json:"locations"`
}

type location struct {
	PhysicalLocation physical `json:"physicalLocation"`
}

type physical struct {
	ArtifactLocation artifact `json:"artifactLocation"`
	Region           region   `json:"region"`
}

type artifact struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine int `json:"startLine"`
}
