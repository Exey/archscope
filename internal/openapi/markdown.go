package openapi

import (
	"fmt"
	"sort"
	"strings"
)

// Group is one rule's findings within a file.
type Group struct {
	Items []Finding
}

// GroupByRule buckets findings by rule: real findings before advisory ones, worst
// severity first, then the most frequent rule.
func GroupByRule(fs []Finding) []Group {
	idx := map[string]int{}
	var gs []Group
	for _, f := range fs {
		i, ok := idx[f.RuleID]
		if !ok {
			i = len(gs)
			idx[f.RuleID] = i
			gs = append(gs, Group{})
		}
		gs[i].Items = append(gs[i].Items, f)
	}
	rank := map[string]int{"HIGH": 3, "MEDIUM": 2, "LOW": 1}
	sort.SliceStable(gs, func(i, j int) bool {
		a, b := gs[i].Items[0], gs[j].Items[0]
		if a.Advisory != b.Advisory {
			return !a.Advisory
		}
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] > rank[b.Severity]
		}
		return len(gs[i].Items) > len(gs[j].Items)
	})
	return gs
}

// ChangeGroup is one kind of change within a file.
type ChangeGroup struct {
	Level string
	Rule  string
	Items []Change
}

// LevelLabel is how a change level reads in a report.
func LevelLabel(level string) string {
	switch level {
	case lvBreaking:
		return "BREAKING"
	case lvWarning:
		return "RISKY"
	}
	return "COMPATIBLE"
}

// GroupChanges buckets changes by level and rule, breaking first (Diff already sorts them).
func GroupChanges(cs []Change) []ChangeGroup {
	idx := map[string]int{}
	var gs []ChangeGroup
	for _, c := range cs {
		k := c.Level + "|" + c.Rule
		i, ok := idx[k]
		if !ok {
			i = len(gs)
			idx[k] = i
			gs = append(gs, ChangeGroup{Level: c.Level, Rule: c.Rule})
		}
		gs[i].Items = append(gs[i].Items, c)
	}
	return gs
}

// ChangeCounts tallies changes by level.
func ChangeCounts(cs []Change) (breaking, risky, compatible int) {
	for _, c := range cs {
		switch c.Level {
		case lvBreaking:
			breaking++
		case lvWarning:
			risky++
		default:
			compatible++
		}
	}
	return
}

// Counts tallies the non-advisory findings by severity.
func Counts(fs []Finding) (h, m, l int) {
	for _, f := range fs {
		if f.Advisory {
			continue
		}
		switch f.Severity {
		case "HIGH":
			h++
		case "MEDIUM":
			m++
		default:
			l++
		}
	}
	return
}

// RenderMarkdown renders the reports as a Markdown section; rel shortens a path.
func RenderMarkdown(reps []FileReport, rel func(string) string) string {
	if len(reps) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## 📜 OpenAPI\n\n")
	for _, f := range reps {
		h, m, l := Counts(f.Findings)
		fmt.Fprintf(&b, "### `%s` — OpenAPI %s · %d operations · %dH · %dM · %dL\n\n", rel(f.Path), f.Version, f.Operations, h, m, l)
		if len(f.Changes) > 0 {
			br, rk, cp := ChangeCounts(f.Changes)
			fmt.Fprintf(&b, "**Changes since the base** — %d breaking · %d risky · %d compatible\n\n| Impact | Change | Hits | Where |\n|--------|--------|-----:|-------|\n", br, rk, cp)
			base := f.Path
			if i := strings.LastIndexAny(base, `/\`); i >= 0 {
				base = base[i+1:]
			}
			for _, g := range GroupChanges(f.Changes) {
				var at []string
				for i, c := range g.Items {
					if i == 50 {
						at = append(at, fmt.Sprintf("+%d more", len(g.Items)-50))
						break
					}
					at = append(at, fmt.Sprintf("%s:%d (%s)", base, c.Line, c.Detail))
				}
				fmt.Fprintf(&b, "| %s | %s | %d | %s |\n", LevelLabel(g.Level), g.Rule, len(g.Items), strings.Join(at, "<br>"))
			}
			b.WriteString("\n")
		}
		if len(f.Findings) == 0 {
			b.WriteString("No findings.\n\n")
			continue
		}
		b.WriteString("| Severity | Issue | Hits | Where |\n|----------|-------|-----:|-------|\n")
		base := f.Path
		if i := strings.LastIndexAny(base, `/\`); i >= 0 {
			base = base[i+1:]
		}
		for _, g := range GroupByRule(f.Findings) {
			var at []string
			for i, fd := range g.Items {
				if i == 50 {
					at = append(at, fmt.Sprintf("+%d more", len(g.Items)-50))
					break
				}
				loc := fmt.Sprintf("%s:%d", base, fd.Line)
				if fd.Detail != "" {
					loc += " (" + fd.Detail + ")"
				}
				at = append(at, loc)
			}
			label := g.Items[0].Rule
			if g.Items[0].Advisory {
				label += " (advisory)"
			}
			fmt.Fprintf(&b, "| %s | %s | %d | %s |\n", g.Items[0].Severity, label, len(g.Items), strings.Join(at, "<br>"))
		}
		b.WriteString("\n")
	}
	return b.String()
}
