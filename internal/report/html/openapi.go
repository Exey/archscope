package html

import (
	"fmt"
	"strings"

	"github.com/exey/archscope/internal/openapi"
	"github.com/exey/archscope/internal/result"
)

// renderOpenAPISection is the 📜 OpenAPI card: every specification found, with
// its findings grouped by rule (vacuum's rule set, ported) and a VS Code link to
// each line. In review mode it holds just the specs the merge request changes.
func renderOpenAPISection(res *result.AnalysisResult) string {
	if len(res.OpenAPI) == 0 {
		return ""
	}
	var b strings.Builder
	total, files, breaking := 0, 0, 0
	for _, f := range res.OpenAPI {
		total += f.Real()
		breaking += f.Breaking()
		files++
	}
	extra := ""
	if breaking > 0 {
		extra = fmt.Sprintf(" · %d breaking change%s", breaking, plural(breaking, "", "s"))
	}
	fmt.Fprintf(&b, `<div class="as-section" id="as-openapi"><div class="as-section__head"><span class="ico">📜</span><h2>OpenAPI</h2><span class="as-count">%d spec file%s · %d finding%s%s</span></div>`,
		files, plural(files, "", "s"), total, plural(total, "", "s"), extra)
	for _, f := range res.OpenAPI {
		rel := relPath(res.RootPath, f.Path)
		h, m, l := openapiCounts(f.Findings)
		fmt.Fprintf(&b, `<div class="as-cs__sub"><div class="as-cs__sub-head"><span class="ico">📄</span><span class="as-cs__sub-title">%s</span> <span class="as-count">OpenAPI %s · %d operation%s · %dH · %dM · %dL</span></div>`,
			esc(rel), esc(f.Version), f.Operations, plural(f.Operations, "", "s"), h, m, l)
		b.WriteString(renderSpecChanges(f))
		if len(f.Findings) == 0 {
			b.WriteString(`<div class="as-ml__summary as-ml__summary--clean">✅ No findings.</div></div>`)
			continue
		}
		if len(f.Changes) > 0 {
			fmt.Fprintf(&b, `<div class="as-ml__summary" style="margin-top:18px">Lint findings — %d</div>`, len(f.Findings))
		}
		b.WriteString(`<table class="as-table as-cs__table"><thead><tr><th>Severity</th><th>Issue</th><th>Hits</th><th class="as-cs__th-fix">Fix</th><th class="as-cs__th-where">Where</th></tr></thead><tbody>`)
		for _, g := range groupOpenAPI(f.Findings) {
			var links []string
			for i, fd := range g.Items {
				if i == 50 {
					links = append(links, fmt.Sprintf(`<span class="as-cx__more">+%d more</span>`, len(g.Items)-50))
					break
				}
				loc := fmt.Sprintf("%s:%d", baseOf(f.Path), fd.Line)
				link := esc(loc)
				if href := vscodeHref(f.Path, fd.Line); href != "" {
					link = fmt.Sprintf(`<a class="as-vs" href="%s" title="Open in VS Code">%s</a>`, esc(href), esc(loc))
				}
				if fd.Detail != "" {
					link += ` <span class="as-cs__detail">` + esc(fd.Detail) + `</span>`
				}
				links = append(links, link)
			}
			sev, cls := g.Items[0].Severity, "sev-low"
			switch sev {
			case "HIGH":
				cls = "sev-high"
			case "MEDIUM":
				cls = "sev-medium"
			}
			label := g.Items[0].Rule
			if g.Items[0].Advisory {
				label += " (advisory)"
			}
			fmt.Fprintf(&b, `<tr><td><span class="as-sev %s">%s</span></td><td>%s</td><td class="mono">%d</td><td class="as-cs__fix">%s</td><td class="mono">%s</td></tr>`,
				cls, esc(sev), esc(label), len(g.Items), codeSpans(esc(g.Items[0].Message)), strings.Join(links, "<br>"))
		}
		b.WriteString(`</tbody></table></div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// renderSpecChanges is the review-mode "Changes since the base" table: what the
// merge request does to the API contract, breaking changes first.
func renderSpecChanges(f openapi.FileReport) string {
	if len(f.Changes) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<div class="as-ml__summary">Changes since the base — <b>%s</b></div>`, esc(openapi.ChangeSummary(f.Changes)))
	b.WriteString(`<table class="as-table as-cs__table"><thead><tr><th>Impact</th><th>Change</th><th>Hits</th><th class="as-cs__th-where">Where</th></tr></thead><tbody>`)
	for _, g := range openapi.GroupChanges(f.Changes) {
		var links []string
		for i, c := range g.Items {
			if i == 50 {
				links = append(links, fmt.Sprintf(`<span class="as-cx__more">+%d more</span>`, len(g.Items)-50))
				break
			}
			loc := fmt.Sprintf("%s:%d", baseOf(f.Path), c.Line)
			link := esc(loc)
			if href := vscodeHref(f.Path, c.Line); href != "" {
				link = fmt.Sprintf(`<a class="as-vs" href="%s" title="Open in VS Code">%s</a>`, esc(href), esc(loc))
			}
			links = append(links, link+` <span class="as-cs__detail">`+codeSpans(esc(c.Detail))+`</span>`)
		}
		cls := "sev-low"
		switch g.Level {
		case "breaking":
			cls = "sev-high"
		case "warning":
			cls = "sev-medium"
		}
		fmt.Fprintf(&b, `<tr><td><span class="as-sev %s">%s</span></td><td>%s</td><td class="mono">%d</td><td class="mono">%s</td></tr>`,
			cls, openapi.LevelLabel(g.Level), esc(g.Rule), len(g.Items), strings.Join(links, "<br>"))
	}
	b.WriteString(`</tbody></table>`)
	return b.String()
}

type openapiGroup = openapi.Group

func groupOpenAPI(fs []openapi.Finding) []openapiGroup { return openapi.GroupByRule(fs) }

func openapiCounts(fs []openapi.Finding) (h, m, l int) { return openapi.Counts(fs) }

func baseOf(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// codeSpans turns `x` spans of already-escaped text into <code>.
func codeSpans(escaped string) string {
	parts := strings.Split(escaped, "`")
	if len(parts)%2 == 0 {
		return escaped
	}
	var b strings.Builder
	for i, p := range parts {
		if i%2 == 1 {
			b.WriteString(`<code class="mono">` + p + `</code>`)
		} else {
			b.WriteString(p)
		}
	}
	return b.String()
}
