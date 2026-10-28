package parser

import "testing"

func TestMarkerInComment(t *testing.T) {
	for line, want := range map[string]bool{
		`x := 1 // TODO: later`:    true,
		`// FIXME`:                 true,
		`// TODO(exey) split this`: true,
		`FixmeMarkers:  []string{"// FIXME", "//FIXME"},`:   false, // the marker quoted in a string
		`src := "// TODO: nope\n"`:                          false,
		`// TODO/FIXME backlog density folds into the read`: false, // prose naming the markers
		`// TODOS are tracked elsewhere`:                    false,
		`return "// TODO" + rest // FIXME real one`:         true,
		`# TODO: python style`:                              true,
	} {
		marker := "// TODO"
		switch {
		case len(line) > 0 && line[0] == '#':
			marker = "# TODO"
		case containsStr(line, "FIXME"):
			marker = "// FIXME"
		}
		if got := markerInComment(line, marker); got != want {
			t.Errorf("%q: got %v want %v", line, got, want)
		}
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
