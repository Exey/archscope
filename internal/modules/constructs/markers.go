// markers.go is Code Structure's 🔀 Merge & diff markers subcard — a port of
// dodgy's "things that must not be in a public project": conflict markers and
// pasted unified-diff headers left in source. They compile in some languages and
// silently change behaviour in others, so they are HIGH, and they are exactly the
// kind of thing a merge-request review should catch. Universal: it reads raw lines
// of every scanned language.
package constructs

import (
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/security"
)

var (
	reConflictOpen  = regexp.MustCompile(`^<{7}(?:\s|$)`)
	reConflictClose = regexp.MustCompile(`^>{7}(?:\s|$)`)
	reConflictMid   = regexp.MustCompile(`^={7}\s*$`)
	reDiffGit       = regexp.MustCompile(`^diff --git a/\S+ b/\S+`)
	reDiffFile      = regexp.MustCompile(`^(?:\+\+\+|---) [ab]/\S+`)
	reDiffHunk      = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@`)
)

// scanMarkers returns conflict-marker and diff-header issues of one file.
func scanMarkers(filePath string, raw []string) []CSIssue {
	var out []CSIssue
	add := func(i int, id, rule, msg, detail string) {
		snip := strings.TrimSpace(raw[i])
		if len(snip) > 100 {
			snip = snip[:100] + "…"
		}
		out = append(out, CSIssue{RuleID: id, Rule: rule, Message: msg, Detail: detail, Severity: security.SevHigh, FilePath: filePath, Line: i + 1, Snippet: snip})
	}
	open := -1
	for i, l := range raw {
		switch {
		case reConflictOpen.MatchString(l):
			open = i
			add(i, "marker-conflict", "Merge conflict marker",
				"An unresolved merge conflict was committed: everything between `<<<<<<<` and `>>>>>>>` is both sides at once. Resolve it and delete the markers.",
				strings.TrimSpace(strings.TrimLeft(l, "<")))
		case reConflictClose.MatchString(l) && open < 0:
			add(i, "marker-conflict", "Merge conflict marker",
				"A stray `>>>>>>>` conflict marker is left over from a merge; resolve the conflict and delete it.", "")
		case reConflictClose.MatchString(l):
			open = -1
		case reDiffGit.MatchString(l):
			add(i, "marker-diff", "Pasted diff header",
				"A `diff --git` header is in the source — a patch was pasted instead of applied. Remove it.", "")
		case reDiffFile.MatchString(l) && i+1 < len(raw) && (reDiffHunk.MatchString(raw[i+1]) || reDiffFile.MatchString(raw[i+1])):
			add(i, "marker-diff", "Pasted diff header",
				"Unified-diff `---`/`+++` file lines are in the source — a patch was pasted instead of applied. Remove it.", "")
		}
	}
	return out
}
