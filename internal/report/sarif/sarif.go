// Package sarif renders an AnalysisResult to a single SARIF 2.1.0 log.
// Each security rule becomes a reportingDescriptor under the tool driver's
// rules[], and each finding becomes a result with one physical location.
//
// GitLab / GitHub compatibility:
//   - results/rules are always arrays (never null) — schema-valid on clean scans
//   - rule descriptors include properties.security-severity (0–10) for GitLab to
//     derive correct severity; properties.tags includes "external/cwe/cwe-<id>"
//     so GitLab classifies findings (e.g. CWE-798 → secret detection)
//   - artifactLocations carry uriBaseId:"SRCROOT" + originalUriBaseIds so
//     click-through to source works in VS Code, GitLab, and GitHub
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
	descriptors := []descriptor{}
	results := []sarifResult{}

	for _, rr := range res.Security {
		idx, ok := ruleIndex[rr.Rule.ID]
		if !ok {
			idx = len(descriptors)
			ruleIndex[rr.Rule.ID] = idx
			props := map[string]any{
				"category":          rr.Rule.Category,
				"severity":          string(rr.Rule.Severity),
				"security-severity": securitySeverity(rr.Rule.Severity),
			}
			if rr.Rule.CWE != "" {
				props["tags"] = []string{"security", "external/cwe/cwe-" + rr.Rule.CWE}
			} else {
				props["tags"] = []string{"security"}
			}
			descriptors = append(descriptors, descriptor{
				ID:                   rr.Rule.ID,
				Name:                 rr.Rule.Name,
				ShortDescription:     message{Text: rr.Rule.Name},
				FullDescription:      fullDesc(rr.Rule.Description),
				DefaultConfiguration: &defaultConf{Level: level(rr.Rule.Severity)},
				Properties:           props,
			})
		}
		for _, f := range rr.Findings {
			u, baseID := sarifURI(f)
			results = append(results, sarifResult{
				RuleID:    rr.Rule.ID,
				RuleIndex: idx,
				Level:     level(rr.Rule.Severity),
				Message:   message{Text: messageText(rr.Rule, f)},
				Locations: []location{{
					PhysicalLocation: physical{
						ArtifactLocation: artifact{URI: u, URIBaseID: baseID},
						Region:           region{StartLine: max(f.Line, 1)},
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
			// SRCROOT lets SARIF viewers resolve relative URIs against the repo
			// root without knowing the absolute checkout path.
			OriginalURIBaseIDs: map[string]artifact{
				"SRCROOT": {URI: "./"},
			},
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

// securitySeverity maps severity to the 0.0–10.0 scale GitLab/GitHub use.
// GitLab requires security-severity ≥ 9.0 for "Critical"; HIGH → 8.0 keeps
// it firmly in "High". MEDIUM/LOW use the midpoints of their bands.
func securitySeverity(s security.Severity) float64 {
	switch s {
	case security.SevHigh:
		return 8.0
	case security.SevMedium:
		return 5.5
	default: // LOW
		return 3.0
	}
}

func messageText(r security.Rule, f security.Finding) string {
	if f.Snippet != "" {
		return r.Name + ": " + f.Snippet
	}
	return r.Name + " detected."
}

func sarifURI(f security.Finding) (uri, baseID string) {
	if f.RelPath != "" {
		return f.RelPath, "SRCROOT"
	}
	// Fallback: display path (last 3 segments) without uriBaseId.
	if f.File != "" {
		return f.File, ""
	}
	return f.FullPath, ""
}

func fullDesc(s string) *message {
	if s == "" {
		return nil
	}
	return &message{Text: s}
}

// ── SARIF 2.1.0 minimal object model ─────────────────────────────────────────

type sarifLog struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool               tool                `json:"tool"`
	Results            []sarifResult       `json:"results"`
	OriginalURIBaseIDs map[string]artifact `json:"originalUriBaseIds,omitempty"`
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
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     message        `json:"shortDescription"`
	FullDescription      *message       `json:"fullDescription,omitempty"`
	DefaultConfiguration *defaultConf   `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any `json:"properties,omitempty"`
}

type defaultConf struct {
	Level string `json:"level"`
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
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type region struct {
	StartLine int `json:"startLine"`
}
