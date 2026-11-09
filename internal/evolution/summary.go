package evolution

import (
	"fmt"
	"sort"
	"strings"
)

// ChangeSummary is the "what changed" strip of a review: functions and other
// declarations added, updated and deleted by the merge request.
type ChangeSummary struct {
	FuncsNew, FuncsUpdated, FuncsDeleted []string // names ("Type.Method" is not known: plain names)
	TypesNew, TypesDeleted               []string // struct / class / interface / enum / type
	ValuesNew, ValuesDeleted             []string // const / var
	FilesNew, FilesDeleted, FilesChanged int
	TestsAdded                           int // new test functions
}

// Empty reports whether nothing was counted.
func (s *ChangeSummary) Empty() bool {
	return s == nil || len(s.FuncsNew)+len(s.FuncsUpdated)+len(s.FuncsDeleted)+len(s.TypesNew)+len(s.TypesDeleted)+len(s.ValuesNew)+len(s.ValuesDeleted)+s.FilesNew+s.FilesDeleted+s.FilesChanged == 0
}

// SummaryCard is one tile of the strip.
type SummaryCard struct {
	Icon, Label string
	N           int
	Tone        string // "up" | "down" | "flat"
	Names       []string
}

// Cards lists the eight tiles in display order.
func (s *ChangeSummary) Cards() []SummaryCard {
	return []SummaryCard{
		{"➕", "new functions", len(s.FuncsNew), "up", s.FuncsNew},
		{"✏️", "updated functions", len(s.FuncsUpdated), "flat", s.FuncsUpdated},
		{"🗑️", "deleted functions", len(s.FuncsDeleted), "down", s.FuncsDeleted},
		{"🧱", "new types", len(s.TypesNew), "up", s.TypesNew},
		{"🪦", "removed types", len(s.TypesDeleted), "down", s.TypesDeleted},
		{"🔣", "new consts / vars", len(s.ValuesNew), "up", s.ValuesNew},
		{"📄", "new files", s.FilesNew, "up", nil},
		{"🧪", "new test functions", s.TestsAdded, "up", nil},
	}
}

// RenderSummaryMarkdown mirrors the HTML strip as a table.
func RenderSummaryMarkdown(s *ChangeSummary) string {
	if s.Empty() {
		return ""
	}
	var b strings.Builder
	b.WriteString("**What the change does**\n\n| | Count | Names |\n|---|---:|---|\n")
	for _, c := range s.Cards() {
		fmt.Fprintf(&b, "| %s %s | %d | %s |\n", c.Icon, c.Label, c.N, NameList(c.Names, 6))
	}
	fmt.Fprintf(&b, "\n_%d files changed · %d removed_\n\n", s.FilesChanged, s.FilesDeleted)
	return b.String()
}

// NameList joins up to max names, then "+N more".
func NameList(names []string, max int) string {
	if len(names) == 0 {
		return ""
	}
	n := append([]string(nil), names...)
	sort.Strings(n)
	if len(n) > max {
		return "`" + strings.Join(n[:max], "`, `") + fmt.Sprintf("`, +%d more", len(n)-max)
	}
	return "`" + strings.Join(n, "`, `") + "`"
}
