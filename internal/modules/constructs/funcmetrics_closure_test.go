package constructs

import (
	"strings"
	"testing"
)

// A function that registers closures is charged for the closures' complexity
// but not for their returns, branches and locals.
func TestBodyStatsClosuresAreTheirOwn(t *testing.T) {
	src := "func init() {\n\tadd(func(c Ctx) string {\n\t\tif c.x {\n\t\t\treturn a(c)\n\t\t}\n\t\treturn b(c)\n\t})\n\tadd(func(c Ctx) string {\n\t\tv := 1\n\t\treturn d(c, v)\n\t})\n\tif ok {\n\t\treturn\n\t}\n}\n"
	st := bodyStats(csStrGo, ".go", strings.Split(src, "\n"), nil)
	if st.returns != 1 {
		t.Errorf("returns: want 1 (the outer one), got %d", st.returns)
	}
	if st.branches != 1 {
		t.Errorf("branches: want 1 (the outer if), got %d", st.branches)
	}
	if st.locals != 0 {
		t.Errorf("locals: want 0 (v belongs to the closure), got %d", st.locals)
	}
	if st.cc < 3 {
		t.Errorf("cyclomatic complexity still includes the closure's branch, got %d", st.cc)
	}
	// a method header is not a function literal
	m := bodyStats(csStrGo, ".go", strings.Split("func (c *T) Get() string {\n\treturn c.x\n}\n", "\n"), nil)
	if m.returns != 1 {
		t.Errorf("method returns = %d", m.returns)
	}
}
