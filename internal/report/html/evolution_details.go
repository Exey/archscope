package html

import (
	"fmt"
	"strings"

	"github.com/exey/archscope/internal/evolution"
)

// writeDetails renders, below a comparison, WHY each dimension moved and WHERE:
// for every (platform, dimension) that got worse — the changed signals and the
// concrete offenders that were introduced, each linked to its file:line. What
// got better follows in a collapsed section.
func writeDetails(b *strings.Builder, c evolution.Comparison, review bool) {
	b.WriteString(`<div class="as-evo__details">`)
	if len(c.WorseDetails) == 0 {
		b.WriteString(`<p class="as-clean">✓ Nothing got worse.</p>`)
	} else {
		fmt.Fprintf(b, `<div class="as-evo__dtitle as-evo__dtitle--down">▼ What got worse, and where <span class="as-count">(%d)</span></div>`, len(c.WorseDetails))
		for _, d := range c.WorseDetails {
			writeDetailCard(b, d, review)
		}
	}
	if len(c.BetterDetails) > 0 {
		fmt.Fprintf(b, `<details class="as-evo__better"><summary>▲ What got better <span class="as-count">(%d)</span></summary>`, len(c.BetterDetails))
		for _, d := range c.BetterDetails {
			writeDetailCard(b, d, review)
		}
		b.WriteString(`</details>`)
	}
	b.WriteString(`</div>`)
}

func writeDetailCard(b *strings.Builder, d evolution.Detail, review bool) {
	dir := evoDir(d.Delta)
	fmt.Fprintf(b, `<div class="as-evo__dcard as-evo__dcard--%s"><div class="as-evo__dhead">`+
		`<span class="as-plat-badge as-plat-%s">%s</span><span class="as-cult-name">%s</span>`+
		`<span class="as-evo__ddim">%s %s</span>`+
		`<span class="as-evo__then">%d</span><span class="as-evo__to">→</span><strong>%d</strong>`+
		`<span class="as-evo__d as-evo__d--%s">%s %s</span></div>`,
		dir, esc(d.Lang), esc(d.Abbr), esc(d.Label),
		evolution.Dims[d.Dim].Icon, esc(evolution.Dims[d.Dim].Name),
		d.Then, d.Now, dir, evolution.Arrow(d.Delta), evolution.SignedInt(d.Delta))

	if len(d.Metrics) > 0 || d.LOCThen != d.LOCNow {
		b.WriteString(`<ul class="as-evo__dlist">`)
		for _, m := range d.Metrics {
			cls, arrow := "up", "▲"
			if m.Worse() {
				cls, arrow = "down", "▼"
			}
			fmt.Fprintf(b, `<li><span class="as-evo__d as-evo__d--%s">%s</span> %s <span class="as-evo__then">%s</span><span class="as-evo__to">→</span><strong>%s</strong></li>`,
				cls, arrow, esc(m.Name), esc(evolution.FormatMetric(m.Then, m.Unit)), esc(evolution.FormatMetric(m.Now, m.Unit)))
		}
		if d.LOCThen != d.LOCNow {
			fmt.Fprintf(b, `<li class="as-evo__info">ℹ️ Code size %s → %s LOC — length and TODO penalties are per 1000 lines, so growth alone can nudge a score</li>`,
				fmtNum(d.LOCThen), fmtNum(d.LOCNow))
		}
		b.WriteString(`</ul>`)
	}

	if len(d.Added) > 0 {
		fmt.Fprintf(b, `<div class="as-evo__dsub">Introduced since the baseline <span class="as-count">(%d)</span></div><ul class="as-evo__items">`, len(d.Added))
		for i, it := range d.Added {
			if i == evolution.MaxDetailItems {
				fmt.Fprintf(b, `<li class="as-evo__more">… and %d more</li>`, len(d.Added)-evolution.MaxDetailItems)
				break
			}
			fmt.Fprintf(b, `<li>%s</li>`, itemHTML(it, "", review))
		}
		b.WriteString(`</ul>`)
	}
	if len(d.Grew) > 0 {
		fmt.Fprintf(b, `<div class="as-evo__dsub">Grew <span class="as-count">(%d)</span></div><ul class="as-evo__items">`, len(d.Grew))
		for i, g := range d.Grew {
			if i == evolution.MaxDetailItems {
				fmt.Fprintf(b, `<li class="as-evo__more">… and %d more</li>`, len(d.Grew)-evolution.MaxDetailItems)
				break
			}
			fmt.Fprintf(b, `<li>%s</li>`, itemHTML(g.Item, fmt.Sprintf("%d → %d", g.ThenSize, g.Item.Size), review))
		}
		b.WriteString(`</ul>`)
	}
	if d.Resolved > 0 {
		fmt.Fprintf(b, `<p class="as-evo__resolved">✓ %d offender(s) resolved since the baseline</p>`, d.Resolved)
	}
	b.WriteString(`</div>`)
}

// itemHTML renders one offender: kind chip, symbol, file:line (a VS Code link when
// the file exists in the working tree) and its note. override replaces the note.
func itemHTML(it evolution.Item, override string, review bool) string {
	loc := it.Rel
	if it.Line > 0 {
		loc = fmt.Sprintf("%s:%d", it.Rel, it.Line)
	}
	locHTML := esc(loc)
	if href := vscodeHref(it.Path, it.Line); href != "" {
		locHTML = fmt.Sprintf(`<a class="as-vs" href="%s" title="Open in VS Code">%s</a>`, esc(href), esc(loc))
	}
	note := it.Note
	if override != "" {
		note = override
	}
	out := fmt.Sprintf(`<span class="as-evo__kind as-evo__kind--w%d">%s</span> <span class="mono">%s</span> — <span class="mono">%s</span>`,
		minInt(it.Weight, 7), esc(it.Kind), esc(it.Name), locHTML)
	if note != "" {
		out += fmt.Sprintf(` <em class="as-evo__note">%s</em>`, esc(note))
	}
	if review && it.RepoPath != "" && it.Line > 0 {
		out += fmt.Sprintf(` <button type="button" class="as-evo__mr" data-path="%s" data-line="%d" data-old="%d" data-hash="%s" `+
			`title="Copies %s#L%d and opens this line in the merge request">MR ↗ L%d</button>`,
			esc(it.RepoPath), it.Line, it.OldPos, evolution.FileHash(it.RepoPath), esc(it.RepoPath), it.Line, it.Line)
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// writeTimelinePane renders the multi-point view: the points, the net verdict
// oldest → now, one table and one multi-dot track per platform, then every leg
// as its own step with what got worse in it.
func writeTimelinePane(b *strings.Builder, tl evolution.Timeline) {
	b.WriteString(`<p class="as-evo__meta"><strong>` + fmt.Sprint(len(tl.Points)) + ` points:</strong> `)
	for i, p := range tl.Points {
		if i > 0 {
			b.WriteString(` <span class="as-evo__to">→</span> `)
		}
		if p.Now {
			b.WriteString(`<strong>now</strong> (working tree)`)
		} else {
			fmt.Fprintf(b, `<strong>%s</strong> <code>%s</code> %s`, esc(p.Ref.Title), esc(p.Ref.Short()), esc(p.Ref.Date.Format("2006-01-02")))
		}
	}
	b.WriteString(`</p>`)
	writeBanner(b, tl.Span)

	b.WriteString(`<div class="as-cult-scroll"><table class="as-cult-table as-evo__table"><thead><tr><th>Platform</th>`)
	for _, d := range evolution.Dims {
		fmt.Fprintf(b, `<th>%s %s</th>`, d.Icon, esc(d.Name))
	}
	b.WriteString(`</tr></thead><tbody>`)
	for _, r := range tl.VisibleRows() {
		fmt.Fprintf(b, `<tr><td class="as-cult-plat"><span class="as-plat-badge as-plat-%s">%s</span><span class="as-cult-name">%s</span></td>`,
			esc(r.Lang), esc(r.Abbr), esc(r.Label))
		for i := range evolution.Dims {
			vals, ok := r.Series(i)
			b.WriteString(`<td>`)
			first, last := -1, -1
			for pi := range vals {
				if pi > 0 {
					b.WriteString(`<span class="as-evo__to">→</span>`)
				}
				switch {
				case !ok[pi]:
					b.WriteString(`<span class="as-evo__then">–</span>`)
				case pi == len(vals)-1:
					fmt.Fprintf(b, `<strong>%d</strong>`, vals[pi])
				default:
					fmt.Fprintf(b, `<span class="as-evo__then">%d</span>`, vals[pi])
				}
				if ok[pi] {
					if first < 0 {
						first = vals[pi]
					}
					last = vals[pi]
				}
			}
			if first >= 0 {
				dl := last - first
				fmt.Fprintf(b, ` <span class="as-evo__d as-evo__d--%s">%s %s</span>`, evoDir(dl), evolution.Arrow(dl), evolution.SignedInt(dl))
			}
			b.WriteString(`</td>`)
		}
		b.WriteString(`</tr>`)
	}
	b.WriteString(`</tbody></table></div>`)

	b.WriteString(`<div class="as-evo__bells">`)
	for _, r := range tl.VisibleRows() {
		complete := true
		for _, s := range r.Scores {
			if s == nil {
				complete = false
			}
		}
		if !complete {
			continue // a platform missing from a point has no continuous path to draw
		}
		fmt.Fprintf(b, `<div class="as-evo__bell"><div class="as-evo__bellhead"><span class="as-plat-badge as-plat-%s">%s</span><span class="as-cult-name">%s</span></div>`,
			esc(r.Lang), esc(r.Abbr), esc(r.Label))
		for i, d := range evolution.Dims {
			vals, _ := r.Series(i)
			writeTrack(b, d, vals)
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div>`)

	b.WriteString(`<div class="as-evo__dtitle">Step by step</div>`)
	for i, st := range tl.Steps {
		open := ""
		if len(st.WorseDetails) > 0 {
			open = " open"
		}
		fmt.Fprintf(b, `<details class="as-evo__step"%s><summary><strong>Step %d</strong> · %s <span class="as-evo__to">→</span> %s `+
			`<span class="as-evo__chip as-evo__chip--up">▲ %d</span><span class="as-evo__chip as-evo__chip--down">▼ %d</span><span class="as-evo__chip as-evo__chip--flat">= %d</span></summary>`,
			open, i+1, esc(tl.Points[i].Title()), esc(tl.Points[i+1].Title()), st.Better, st.Worse, st.Same)
		writeDetails(b, st, false)
		b.WriteString(`</details>`)
	}
}
