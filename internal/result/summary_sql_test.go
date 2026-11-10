package result

import "testing"

func TestIsSQLFunc(t *testing.T) {
	src := []string{
		"func (f F) summaryMonths() squirrel.SelectBuilder {",
		"\treturn squirrel.Select(\"a\").",
		"\t\tSuffix(`UNION ALL",
		"SELECT '', p.brand_id FROM p`)",
		"}",
		"func add(a, b int) int {",
		"\treturn a + b",
		"}",
	}
	if untestableTech("a.go", src, 1, 5) == "" {
		t.Error("query builder must be excluded")
	}
	if untestableTech("a.go", src, 6, 3) != "" {
		t.Error("plain function is testable")
	}
}
