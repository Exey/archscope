package result

import (
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/security"
)

// PlatformSecurity is the security findings that fall in one platform's files
// (test code excluded), grouped by rule, with the severity tally. The HTML
// "Danger Details" card and its Markdown twin both read it.
type PlatformSecurity struct {
	Rules             []security.RuleResult
	Total             int
	High, Medium, Low int
}

// PlatformSecurity filters the repo-wide findings down to one platform.
func (r *AnalysisResult) PlatformSecurity(plat langspec.Platform) PlatformSecurity {
	pmap := map[string]langspec.Platform{}
	for _, f := range r.Files {
		pmap[f.FilePath] = langspec.Platform(f.Platform)
	}
	var out PlatformSecurity
	for _, rr := range r.Security {
		var fs []security.Finding
		for _, f := range rr.Findings {
			if pmap[f.FullPath] == plat && !security.IsTestPath(f.FullPath) {
				fs = append(fs, f)
			}
		}
		if len(fs) == 0 {
			continue
		}
		out.Rules = append(out.Rules, security.RuleResult{Rule: rr.Rule, Findings: fs, TotalCount: len(fs)})
		out.Total += len(fs)
		switch rr.Rule.Severity {
		case security.SevHigh:
			out.High += len(fs)
		case security.SevMedium:
			out.Medium += len(fs)
		default:
			out.Low += len(fs)
		}
	}
	return out
}
