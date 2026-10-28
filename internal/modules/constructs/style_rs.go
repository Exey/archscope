// style_rs.go holds the Rust rules of the 🧹 Style & design subcard, ported from
// thai-lint: unwrap()/expect() that panic at runtime, clone() inside loops, and
// blocking std calls inside async functions.
package constructs

import (
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/security"
)

var (
	reRsUnwrap   = regexp.MustCompile(`\.unwrap\(\)`)
	reRsExpect   = regexp.MustCompile(`\.expect\(`)
	reRsClone    = regexp.MustCompile(`\.clone\(\)`)
	reRsLoop     = regexp.MustCompile(`^\s*(?:'\w+:\s*)?(?:for\s+.+\s+in\s+.+|while\s+.+|loop)\s*\{`)
	reRsAsyncFn  = regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?async\s+fn\b`)
	reRsBlocking = regexp.MustCompile(`\bstd::thread::sleep\b|(?:^|[^:\w])thread::sleep\(|\bstd::fs::\w+|\bstd::net::(?:Tcp|Udp)\w+|\breqwest::blocking\b|\bstd::io::stdin\b`)
	reRsFsBare   = regexp.MustCompile(`(?:^|[^:\w])fs::(?:read|write|read_to_string|File|create_dir\w*|remove_\w+|copy|metadata|read_dir)\b`)
)

func (c *styleCtx) scanRust() {
	code := c.m.code
	p := "/" + strings.ToLower(strings.ReplaceAll(c.path, "\\", "/"))
	if baseName(c.path) == "build.rs" || strings.Contains(p, "/tests/") || strings.Contains(p, "/benches/") || strings.Contains(p, "/examples/") {
		return
	}
	inTest := make([]bool, len(code))
	for i, l := range code {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "#[cfg(test)]") || strings.HasPrefix(t, "#[test]") || strings.HasPrefix(t, "#[tokio::test") {
			end := i
			for j := i + 1; j < len(code) && j <= i+4; j++ {
				if strings.Contains(code[j], "{") {
					end = matchBraceEnd(code, j)
					break
				}
			}
			for k := i; k <= end && k < len(code); k++ {
				inTest[k] = true
			}
		}
	}
	usesStdFs := false
	for _, l := range c.m.raw {
		if strings.Contains(l, "use std::fs") {
			usesStdFs = true
			break
		}
	}
	for i, l := range code {
		if inTest[i] {
			continue
		}
		if reRsUnwrap.MatchString(l) {
			c.add(i, security.SevMedium, "rs-unwrap", ".unwrap() can panic at runtime",
				"Propagate with `?`, or handle the None / Err case; unwrap turns an expected failure into a crash.", "unwrap", false)
		} else if reRsExpect.MatchString(l) {
			c.add(i, security.SevLow, "rs-expect", ".expect() can panic at runtime",
				"The message helps, but the panic still happens. Propagate with `?` (adding context) unless the invariant is truly impossible to break.", "expect", false)
		}
	}
	flaggedClone := map[int]bool{}
	for i, l := range code {
		if inTest[i] || !reRsLoop.MatchString(l) {
			continue
		}
		end := matchBraceEnd(code, i)
		for j := i + 1; j < end && j < len(code); j++ {
			if reRsClone.MatchString(code[j]) && !flaggedClone[j] {
				flaggedClone[j] = true
				c.add(j, security.SevLow, "rs-clone-loop", ".clone() inside a loop",
					"A clone per iteration allocates and copies every time. Borrow (`&x`), clone once before the loop, or use Rc/Arc if the sharing is intended.", "clone", false)
			}
		}
	}
	for i, l := range code {
		if inTest[i] || !reRsAsyncFn.MatchString(l) {
			continue
		}
		end := matchBraceEnd(code, i)
		for j := i; j <= end && j < len(code); j++ {
			if reRsBlocking.MatchString(code[j]) || (usesStdFs && reRsFsBare.MatchString(code[j])) {
				c.add(j, security.SevMedium, "rs-blocking-async", "Blocking call inside an async fn",
					"A blocking std call stalls the executor thread and every task on it. Use the async equivalent (tokio::time::sleep, tokio::fs, tokio::net) or spawn_blocking.", "blocking", false)
			}
		}
	}
}
