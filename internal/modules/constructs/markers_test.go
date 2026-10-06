package constructs

import "testing"

func TestMergeConflictAndDiffMarkers(t *testing.T) {
	src := "package p\n\nfunc F() int {\n<<<<<<< HEAD\n\treturn 1\n=======\n\treturn 2\n>>>>>>> feature/x\n}\n"
	ids := issueIDs(goReport(t, src).MarkerIssues)
	if len(ids) != 1 || ids[0] != "marker-conflict" {
		t.Errorf("conflict markers: %v", ids)
	}
	diff := "package p\n// diff --git a/x.go b/x.go\n"
	if ids := issueIDs(goReport(t, diff).MarkerIssues); len(ids) != 0 {
		t.Errorf("an indented/commented diff mention must not match: %v", ids)
	}
	pasted := "package p\ndiff --git a/x.go b/x.go\n--- a/x.go\n+++ b/x.go\n@@ -1,2 +1,3 @@\n"
	got := issueIDs(goReport(t, pasted).MarkerIssues)
	if !hasRule(got, "marker-diff") {
		t.Errorf("pasted diff missed: %v", got)
	}
	// ===== underline in a docstring is not a conflict
	doc := "def f():\n    \"\"\"\n    Title\n    =======\n    \"\"\"\n"
	if ids := issueIDs(pyReport(t, doc).MarkerIssues); len(ids) != 0 {
		t.Errorf("rst underline flagged: %v", ids)
	}
}
