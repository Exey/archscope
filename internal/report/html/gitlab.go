package html

import (
	"fmt"
	"sort"
	"strings"

	"github.com/exey/archscope/internal/evolution"
	"github.com/exey/archscope/internal/result"
)

// renderGitLabCard is the review-mode settings block at the top of the 📈 Evolution
// card: the GitLab project path, the GitLab host on its right and the merge
// request number. They are prefilled from the git remote and refs/merge-requests,
// edited in place, and remembered in the browser; every "MR with line" button
// reads them.
func renderGitLabCard(res *result.AnalysisResult) string {
	rv := res.Review
	if rv == nil {
		return ""
	}
	mrNote := `<span class="as-gl__hint">No merge request found in refs/merge-requests — type its number, or buttons link to the file at the branch instead.</span>`
	mr := ""
	if rv.MRIID > 0 {
		mr = fmt.Sprint(rv.MRIID)
		mrNote = fmt.Sprintf(`<span class="as-gl__hint">Merge request detected from %s.</span>`, esc(rv.MRSource))
	}
	ref := rv.Branch
	if ref == "" {
		ref = rv.HeadSHA
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<div class="as-gl" id="as-gl-card" data-store="archscope-gl:%s" data-ref="%s">`, esc(res.ProjectName), esc(ref))
	b.WriteString(`<div class="as-gl__title">🦊 GitLab MR links</div>`)
	fmt.Fprintf(&b, `<p class="as-evo__meta">Reviewing <code>%s</code> against <code>%s</code> (merge-base <code>%s</code>). Every issue below gets an <strong>MR ↗ L&lt;line&gt;</strong> button: it copies <code>path/to/file#L&lt;line&gt;</code> for your comment and opens that line in the merge request. Saved in this browser.</p>`,
		esc(reviewSubject(rv)), esc(reviewAgainst(rv)), esc(shortSHA(rv.BaseSHA)))
	b.WriteString(`<div class="as-gl__row">`)
	fmt.Fprintf(&b, `<input id="as-gl-project" class="as-gl__in as-gl__in--project" type="text" placeholder="group/project" value="%s" data-orig="%s" title="GitLab project path">`, esc(rv.Project), esc(rv.Project))
	fmt.Fprintf(&b, `<input id="as-gl-host" class="as-gl__in as-gl__in--host" type="text" placeholder="https://gitlab.example.com" value="%s" data-orig="%s" title="GitLab host">`, esc(rv.Host), esc(rv.Host))
	fmt.Fprintf(&b, `<label class="as-gl__mr">MR&nbsp;!<input id="as-gl-mr" class="as-gl__in as-gl__in--num" type="text" inputmode="numeric" placeholder="IID" value="%s" data-orig="%s" title="Merge request number (IID)"></label>`, esc(mr), esc(mr))
	b.WriteString(`</div>`)
	b.WriteString(mrNote)
	b.WriteString(`</div>`)
	return b.String()
}

// reviewSubject / reviewAgainst are the two sides to name in the UI.
func reviewSubject(rv *evolution.Review) string {
	if rv.Branch != "" {
		return rv.Branch
	}
	return shortSHA(rv.HeadSHA)
}

func reviewAgainst(rv *evolution.Review) string {
	if rv.Against != "" {
		return rv.Against
	}
	return rv.Ref
}

// writeReviewChanges renders "Changes: 29 files +1860 −1072" and the file list,
// each file marked ✓ OK (green) or with the issues the change introduced there.
func writeReviewChanges(b *strings.Builder, rv *evolution.Review) {
	bad := 0
	for _, f := range rv.Files {
		if !f.OK() {
			bad++
		}
	}
	fmt.Fprintf(b, `<div class="as-rv"><div class="as-rv__head"><strong>Changes:</strong> %d %s <span class="as-evo__d as-evo__d--up">+%s</span> <span class="as-evo__d as-evo__d--down">−%s</span>`,
		len(rv.Files), plural(len(rv.Files), "file", "files"), fmtNum(rv.Adds), fmtNum(rv.Dels))
	if len(rv.Files) > 0 {
		if bad == 0 {
			b.WriteString(` <span class="as-evo__chip as-evo__chip--up">✓ all files OK</span>`)
		} else {
			fmt.Fprintf(b, ` <span class="as-evo__chip as-evo__chip--up">✓ %d OK</span> <span class="as-evo__chip as-evo__chip--down">⚠ %d with issues</span>`, len(rv.Files)-bad, bad)
		}
	}
	b.WriteString(`</div>`)
	if len(rv.Files) == 0 {
		b.WriteString(`<p class="as-empty">No changed files between the merge-base and the reviewed branch.</p></div>`)
		return
	}
	b.WriteString(`<div class="as-rv__files">`)
	// Files with issues first, then OK ones — what needs a comment is on top.
	ordered := append([]evolution.ReviewFile(nil), rv.Files...)
	sort.SliceStable(ordered, func(i, j int) bool { return len(ordered[i].Issues) > len(ordered[j].Issues) })
	for _, f := range ordered {
		stat := fmt.Sprintf(`<span class="as-evo__d as-evo__d--up">+%d</span> <span class="as-evo__d as-evo__d--down">−%d</span>`, f.Add, f.Del)
		if f.Binary {
			stat = `<span class="as-evo__tag">binary</span>`
		}
		if f.OK() {
			fmt.Fprintf(b, `<div class="as-rv__file as-rv__file--ok"><span class="as-rv__status as-rv__status--ok">✓ OK</span><span class="mono as-rv__path">%s</span>%s</div>`, esc(f.Path), stat)
			continue
		}
		fmt.Fprintf(b, `<details class="as-rv__file as-rv__file--bad" open><summary><span class="as-rv__status as-rv__status--bad">⚠ %d %s</span><span class="mono as-rv__path">%s</span>%s</summary><ul class="as-evo__items">`,
			len(f.Issues), plural(len(f.Issues), "issue", "issues"), esc(f.Path), stat)
		for _, it := range f.Issues {
			fmt.Fprintf(b, `<li>%s</li>`, itemHTML(it, "", true))
		}
		b.WriteString(`</ul></details>`)
	}
	b.WriteString(`</div></div>`)
}

func shortSHA(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}
