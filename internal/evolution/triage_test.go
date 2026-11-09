package evolution

import (
	"strings"
	"testing"
)

func TestRankFilesPutsRiskyBeforeBig(t *testing.T) {
	files := []ReviewFile{
		{Path: "big.go", Add: 900, Del: 10, Issues: []Item{{Kind: "Long function", Weight: 2}}},
		{Path: "small.go", Add: 8, Issues: []Item{{Kind: "HIGH security", Weight: 7}}},
		{Path: "small_test.go", Add: 50, Issues: []Item{{Kind: "HIGH security", Weight: 7}}},
		{Path: "clean.go", Add: 100},
	}
	r := RankFiles(files)
	if len(r) != 2 || r[0].Path != "small.go" {
		t.Fatalf("ranking = %+v", r)
	}
	if !strings.Contains(strings.Join(r[0].Reasons, " "), "1 HIGH") {
		t.Errorf("reasons = %v", r[0].Reasons)
	}
}

func TestUntestedChanges(t *testing.T) {
	files := []ReviewFile{
		{Path: "a/svc.go", Add: 40}, {Path: "a/svc_test.go", Add: 5},
		{Path: "b/x.go", Add: 40}, {Path: "b/tiny.go", Add: 3},
		{Path: "c/y.py", Add: 20}, {Path: "tests/test_y.py", Add: 5},
	}
	got := UntestedChanges(files, func(string) bool { return true })
	if len(got) != 1 || got[0].Path != "b/x.go" {
		t.Errorf("untested = %+v", got)
	}
}

func TestNewDependencies(t *testing.T) {
	added := map[int]string{3: "\tgithub.com/new/lib v1.2.0", 4: "\tgithub.com/old/lib v1.3.0"}
	names, line := NewDependencies("go.mod", added, "require github.com/old/lib v1.2.0\n")
	if len(names) != 1 || names[0] != "github.com/new/lib" || line != 3 {
		t.Errorf("names=%v line=%d", names, line)
	}
	if DependencyManifest("svc/requirements-dev.txt") != "requirements.txt" {
		t.Error("requirements-dev.txt is a manifest")
	}
}

func TestRiskyMigrationLines(t *testing.T) {
	added := map[int]string{
		1: "-- DROP TABLE commented;",
		2: "ALTER TABLE users DROP COLUMN age;",
		3: "ALTER TABLE users ADD COLUMN email text NOT NULL;",
		4: "ALTER TABLE users ADD COLUMN ok text NOT NULL DEFAULT '';",
		5: "CREATE INDEX idx ON users(email);",
		6: "CREATE INDEX CONCURRENTLY idx2 ON users(name);",
	}
	got := RiskyMigrationLines(added)
	lines := []int{}
	for _, g := range got {
		lines = append(lines, g.Line)
	}
	if len(lines) != 3 || lines[0] != 2 || lines[1] != 3 || lines[2] != 5 {
		t.Errorf("risky lines = %v", lines)
	}
	if !IsMigrationPath("db/migrations/001_add.sql") || IsMigrationPath("src/main.go") {
		t.Error("IsMigrationPath")
	}
}
