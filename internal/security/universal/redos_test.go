package universal

import (
	"strings"
	"testing"
)

func TestReDOSSkipsLinearTimeEngines(t *testing.T) {
	src := strings.Split("x = regexp.MustCompile(`^(a+)+$`)", "\n")
	r := UniversalReDOS()
	if n := len(r.Detect("/app/x.go", src)); n != 0 {
		t.Errorf("Go regexp is RE2 (linear time): got %d findings", n)
	}
	if n := len(r.Detect("/app/x.rs", []string{`let r = Regex::new("^(a+)+$").unwrap();`})); n != 0 {
		t.Errorf("Rust regex crate is linear time: got %d findings", n)
	}
	if n := len(r.Detect("/app/x.py", []string{`r = re.compile("^(a+)+$")`})); n != 1 {
		t.Errorf("Python's backtracking engine must still fire: got %d", n)
	}
}
