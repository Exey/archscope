// issues.go is the shared shape for every "this line looks wrong" finding the
// lexical review checks produce — Code Structure's Strings / Suspicious code /
// Duplicate code subcards and the Regex and Concurrency & API cards. One type,
// one grouping, one table renderer, so each check only has to say *what* it
// saw and how to fix it.
package constructs

import (
	"fmt"
	"html"
	"sort"
	"strings"

	"github.com/exey/archscope/internal/security"
)

// CSIssue is one flagged construct.
type CSIssue struct {
	RuleID   string            // stable id, e.g. "concat-in-loop"
	Rule     string            // short human label
	Message  string            // what to do instead
	Group    string            // optional sub-heading inside a card ("" = none)
	Severity security.Severity // "" = unscored advice (rendered as LOW)
	FilePath string
	Line     int
	Snippet  string // trimmed source line (also the evolution key, so it carries no line number)
	Detail   string // what this particular hit is about (an identifier, a count); shown beside its location
}

// Label is the rule name plus this hit's detail, for lists that show one issue at a time.
func (c CSIssue) Label() string {
	if c.Detail == "" {
		return c.Rule
	}
	return c.Rule + " — " + c.Detail
}

// issueGroup is every issue of one rule collapsed into a row.
type issueGroup struct {
	RuleID, Rule, Message, Group string
	Severity                     security.Severity
	Items                        []CSIssue
}

// groupIssues buckets issues by rule, worst severity first, then most hits.
func groupIssues(v []CSIssue) []issueGroup {
	idx := map[string]int{}
	var gs []issueGroup
	for _, is := range v {
		i, ok := idx[is.RuleID]
		if !ok {
			i = len(gs)
			idx[is.RuleID] = i
			gs = append(gs, issueGroup{RuleID: is.RuleID, Rule: is.Rule, Message: is.Message, Group: is.Group, Severity: is.Severity})
		}
		gs[i].Items = append(gs[i].Items, is)
	}
	sort.SliceStable(gs, func(i, j int) bool {
		if sevRank(gs[i].Severity) != sevRank(gs[j].Severity) {
			return sevRank(gs[i].Severity) > sevRank(gs[j].Severity)
		}
		return len(gs[i].Items) > len(gs[j].Items)
	})
	return gs
}

// issueSevCounts tallies scored severities.
func issueSevCounts(v []CSIssue) (high, med, low int) {
	for _, is := range v {
		switch is.Severity {
		case security.SevHigh:
			high++
		case security.SevMedium:
			med++
		default:
			low++
		}
	}
	return
}

// sortIssues orders issues by file then line, for stable output.
func sortIssues(v []CSIssue) {
	sort.SliceStable(v, func(i, j int) bool {
		if v[i].FilePath != v[j].FilePath {
			return v[i].FilePath < v[j].FilePath
		}
		return v[i].Line < v[j].Line
	})
}

// maxIssueExamples caps the example links shown per rule row in Code Structure
// subcards; the dedicated cards list every location (capped far higher).
const maxIssueExamples = 5

// maxIssueLocations caps the locations listed in one row of a dedicated card.
const maxIssueLocations = 200

// writeIssueTable renders issues grouped by rule: [Severity] Issue · Hits · Fix · Where.
func writeIssueTable(b *strings.Builder, issues []CSIssue, withSev bool, maxLoc int) {
	b.WriteString(`<table class="as-table as-cs__table"><thead><tr>`)
	if withSev {
		b.WriteString(`<th>Severity</th>`)
	}
	b.WriteString(`<th>Issue</th><th>Hits</th><th>Fix</th><th>Where</th></tr></thead><tbody>`)
	for _, g := range groupIssues(issues) {
		var links []string
		for i, is := range g.Items {
			if i == maxLoc {
				links = append(links, fmt.Sprintf(`<span class="as-cx__more">+%d more</span>`, len(g.Items)-maxLoc))
				break
			}
			link := occurrenceLink(fmt.Sprintf("%s:%d", baseName(is.FilePath), is.Line), is.FilePath, is.Line)
			if is.Detail != "" {
				link += ` <span class="as-cs__detail">` + html.EscapeString(is.Detail) + `</span>`
			}
			links = append(links, link)
		}
		b.WriteString(`<tr>`)
		if withSev {
			fmt.Fprintf(b, `<td><span class="as-sev %s">%s</span></td>`, mlSevClass(g.Severity), sevLabel(g.Severity))
		}
		fmt.Fprintf(b, `<td>%s</td><td class="mono">%d</td><td class="as-cs__fix">%s</td><td class="mono">%s</td></tr>`,
			html.EscapeString(g.Rule), len(g.Items), inlineCode(html.EscapeString(g.Message)), strings.Join(links, ", "))
	}
	b.WriteString(`</tbody></table>`)
}

// inlineCode turns `x` spans of already-escaped text into <code>.
func inlineCode(escaped string) string {
	parts := strings.Split(escaped, "`")
	if len(parts)%2 == 0 { // unbalanced backticks: leave as written
		return escaped
	}
	var b strings.Builder
	for i, p := range parts {
		if i%2 == 1 {
			b.WriteString(`<code class="mono">` + p + `</code>`)
		} else {
			b.WriteString(p)
		}
	}
	return b.String()
}

func sevLabel(s security.Severity) string {
	if s == "" {
		return "LOW"
	}
	return strings.ToUpper(string(s))
}

// writeSubOpen opens one titled subcard inside the Code Structure panel; key
// is what a header minicard's data-target points at. titleHTML must already be
// escaped. Close it with writeSubClose.
func writeSubOpen(b *strings.Builder, key, icon, titleHTML string, count int, hint string) {
	attr := ""
	if key != "" {
		attr = ` data-sub="` + html.EscapeString(key) + `"`
	}
	fmt.Fprintf(b, `<div class="as-cs__sub"%s><div class="as-cs__sub-head"><span class="ico">%s</span><span class="as-cs__sub-title">%s</span> <span class="as-count">(%d)</span></div>`,
		attr, icon, titleHTML, count)
	if hint != "" {
		fmt.Fprintf(b, `<div class="as-cs__sub-hint">%s</div>`, html.EscapeString(hint))
	}
}

func writeSubClose(b *strings.Builder) { b.WriteString(`</div>`) }

// writeIssueSubcard renders one titled subcard of issues inside the Code
// Structure panel (or a dedicated card).
func writeIssueSubcard(b *strings.Builder, key, icon, title, hint string, issues []CSIssue, withSev bool, maxLoc int) {
	if len(issues) == 0 {
		return
	}
	writeSubOpen(b, key, icon, html.EscapeString(title), len(issues), hint)
	writeIssueTable(b, issues, withSev, maxLoc)
	writeSubClose(b)
}

// issuesMarkdown renders issues grouped by rule as a markdown table.
func issuesMarkdown(b *strings.Builder, title string, issues []CSIssue, withSev bool) {
	if len(issues) == 0 {
		return
	}
	fmt.Fprintf(b, "%s (%d)\n\n", title, len(issues))
	if withSev {
		b.WriteString("| Severity | Issue | Hits | Locations |\n|----------|-------|-----:|-----------|\n")
	} else {
		b.WriteString("| Issue | Hits | Examples |\n|-------|-----:|----------|\n")
	}
	for _, g := range groupIssues(issues) {
		limit := maxIssueExamples
		if withSev {
			limit = maxIssueLocations
		}
		var ex []string
		for i, is := range g.Items {
			if i == limit {
				ex = append(ex, fmt.Sprintf("+%d more", len(g.Items)-limit))
				break
			}
			loc := fmt.Sprintf("%s:%d", baseName(is.FilePath), is.Line)
			if is.Detail != "" {
				loc += " (" + is.Detail + ")"
			}
			ex = append(ex, loc)
		}
		if withSev {
			fmt.Fprintf(b, "| %s | %s | %d | %s |\n", sevLabel(g.Severity), g.Rule, len(g.Items), strings.Join(ex, ", "))
		} else {
			fmt.Fprintf(b, "| %s | %d | %s |\n", g.Rule, len(g.Items), strings.Join(ex, ", "))
		}
	}
	b.WriteString("\n")
}

// writeIssueCard renders a dedicated card body (Regex, Concurrency & API): a
// summary line, then one severity-tagged table per Group. A clean scan renders
// a positive confirmation rather than nothing, because the Programming Culture
// tooltip always links to the card.
func writeIssueCard(b *strings.Builder, icon, noun string, issues []CSIssue) {
	b.WriteString(`<div class="as-ml">`)
	if len(issues) == 0 {
		fmt.Fprintf(b, `<div class="as-ml__summary as-ml__summary--clean">✅ No %s issues detected in the scanned files.</div></div>`, noun)
		return
	}
	h, m, l := issueSevCounts(issues)
	fmt.Fprintf(b, `<div class="as-ml__summary">%s <b>%d</b> %s issue%s <span class="as-count">(%dH / %dM / %dL)</span></div>`,
		icon, len(issues), noun, plural(len(issues), "", "s"), h, m, l)
	for _, grp := range issueGroupsByName(issues) {
		if grp.name == "" {
			writeIssueTable(b, grp.items, true, maxIssueLocations)
			continue
		}
		info := groupInfo[grp.name]
		writeIssueSubcard(b, "", info.icon, grp.name, info.hint, grp.items, true, maxIssueLocations)
	}
	b.WriteString(`</div>`)
}

type namedIssues struct {
	name  string
	items []CSIssue
}

// groupInfo gives each named group of a dedicated card its subcard icon and hint;
// groupOrder fixes their order (Strings first).
var groupInfo = map[string]struct{ icon, hint string }{
	stringsGroup: {"🔤", "String building and comparison idioms — concatenation in loops, go-critic's string checks, interpolation over `+` chains."},
	regexGroup:   {"🔎", "Regular expressions that are compiled in loops, can't compile, backtrack catastrophically or can be simplified."},
	perfGroup:    {"⚡", "go-critic's allocation and copying idioms: appendCombine, rangeAppendAll, sliceClear, indexAlloc, preferWriteByte, preferStringWriter."},
}

var groupOrder = []string{stringsGroup, regexGroup, perfGroup}

// issueGroupsByName splits issues by their Group: the known groups in groupOrder,
// then any others in first-seen order.
func issueGroupsByName(issues []CSIssue) []namedIssues {
	idx := map[string]int{}
	var out []namedIssues
	for _, is := range issues {
		i, ok := idx[is.Group]
		if !ok {
			i = len(out)
			idx[is.Group] = i
			out = append(out, namedIssues{name: is.Group})
		}
		out[i].items = append(out[i].items, is)
	}
	rank := func(name string) int {
		for i, g := range groupOrder {
			if g == name {
				return i
			}
		}
		return len(groupOrder)
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i].name) < rank(out[j].name) })
	return out
}

// issueCardMarkdown is writeIssueCard's markdown twin.
func issueCardMarkdown(b *strings.Builder, noun string, issues []CSIssue) {
	if len(issues) == 0 {
		return
	}
	h, m, l := issueSevCounts(issues)
	fmt.Fprintf(b, "**%d %s issues** (%dH / %dM / %dL)\n\n", len(issues), noun, h, m, l)
	for _, grp := range issueGroupsByName(issues) {
		title := grp.name
		if title == "" {
			title = noun
		}
		issuesMarkdown(b, title, grp.items, true)
	}
}

// sortIssuesBySeverity orders worst-first, then file and line.
func sortIssuesBySeverity(v []CSIssue) {
	sort.SliceStable(v, func(i, j int) bool {
		if sevRank(v[i].Severity) != sevRank(v[j].Severity) {
			return sevRank(v[i].Severity) > sevRank(v[j].Severity)
		}
		if v[i].FilePath != v[j].FilePath {
			return v[i].FilePath < v[j].FilePath
		}
		return v[i].Line < v[j].Line
	})
}
