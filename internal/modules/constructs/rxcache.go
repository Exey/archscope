package constructs

import (
	"regexp"
	"sync"
)

var rxCache sync.Map // pattern → *regexp.Regexp

// rx compiles a pattern built from runtime values (a name, a path) once and
// reuses it, so a rule that needs one per symbol inside a loop pays for the
// compile the first time only. Constant patterns belong in package-level vars.
func rx(pattern string) *regexp.Regexp {
	if re, ok := rxCache.Load(pattern); ok {
		return re.(*regexp.Regexp)
	}
	re := regexp.MustCompile(pattern)
	rxCache.Store(pattern, re)
	return re
}
