package lang

import (
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/security"
)

// reRule builds a security.Rule whose Detect flags every non-comment line that
// matches re. If any skip substring (matched case-insensitively) is present on
// the line, that line is ignored — a cheap, shared false-positive guard. This
// is the common constructor behind the language-specific rule files, keeping
// each rule a single declarative entry.
func reRule(id, name, category string, sev security.Severity, langs []string, re *regexp.Regexp, desc string, skip ...string) security.Rule {
	return security.Rule{
		ID:          id,
		Name:        name,
		Severity:    sev,
		Category:    category,
		Languages:   langs,
		Description: desc,
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if !re.MatchString(line) {
					continue
				}
				if len(skip) > 0 {
					low := strings.ToLower(line)
					skipped := false
					for _, s := range skip {
						if strings.Contains(low, s) {
							skipped = true
							break
						}
					}
					if skipped {
						continue
					}
				}
				out = append(out, security.NewFinding(filePath, i, lines))
			}
			return out
		},
	}
}

// insecureURLSkips are hosts that legitimately appear behind http:// (loopback,
// XML namespaces, doc placeholders) and must not trip transport rules.
var insecureURLSkips = []string{
	"localhost", "127.0.0.1", "0.0.0.0", "w3.org", "schemas.",
	"example.com", "example.org", "xmlns",
}
