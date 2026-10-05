package html

import (
	"fmt"
	"strings"

	"github.com/exey/archscope/internal/evolution"
	"github.com/exey/archscope/internal/result"
)

// levelColor is the ladder color for a level name ("" → neutral).
func levelColor(name string) string {
	for _, d := range devLevels {
		if d.name == name {
			return d.color
		}
	}
	return "#8a8f98"
}

// evoHint is shown inside 🔰 Programming Culture when no --evolution data exists,
// so the feature is discoverable from the report itself.
const evoHint = `<div class="as-evo as-evo--hint"><span class="as-evo__title">📈 Evolution</span>` +
	`<span class="as-evo__hintxt">What got better, what got worse since 2 weeks / 1 month / the last tag / any commit — ` +
	`regenerate with <code>--evolution 2w,1m,last-tag</code> (or <code>--evolution a1b2c3d</code>).</span></div>`

// evoPane is one switchable view inside the card: the timeline or one
// baseline-vs-now comparison.
type evoPane struct {
	label, title, file, md string
	body                   func(b *strings.Builder)
}

// renderEvolution builds the 📈 Evolution subcard (range tabs, then-vs-now table,
// dumbbell charts, what-got-worse details, Export MD), or the discoverability
// hint when none was asked for. With two or more baselines a ⏱ Timeline tab
// leads: oldest → … → now, i.e. `--evolution 1m 2w` shows three points.
func renderEvolution(res *result.AnalysisResult) string {
	if len(res.Evolution) == 0 {
		return evoHint
	}
	var panes []evoPane
	if tl, ok := evolution.NewTimeline(res.Evolution); ok {
		panes = append(panes, evoPane{
			label: "⏱ Timeline", title: tl.Heading(), file: "evolution-timeline.md",
			md:   "# Programming Culture evolution — " + tl.Heading() + "\n\n" + evolution.RenderTimelineMarkdown(tl),
			body: func(b *strings.Builder) { writeTimelinePane(b, tl) },
		})
	}
	for _, c := range res.Evolution {
		c := c
		panes = append(panes, evoPane{
			label: c.Ref.Label, title: c.Ref.Title + " · " + c.Ref.Short(),
			file: "evolution-" + slug(c.Ref.Label) + ".md",
			md:   "# Programming Culture evolution — " + c.Ref.Title + "\n\n" + evolution.RenderMarkdown(c),
			body: func(b *strings.Builder) { writeComparisonBody(b, c) },
		})
	}

	var b strings.Builder
	b.WriteString(`<div class="as-evo" id="as-evo"><div class="as-evo__bar"><span class="as-evo__title">📈 Evolution</span><div class="as-evo__tabs">`)
	for i, p := range panes {
		on := ""
		if i == 0 {
			on = " as-evo__tab--on"
		}
		fmt.Fprintf(&b, `<button type="button" class="as-evo__tab%s" data-evo="%d" title="%s">%s</button>`, on, i, esc(p.title), esc(p.label))
	}
	b.WriteString(`</div><button type="button" class="as-toggle as-evo__export" title="Download the view shown as a Markdown file">⬇ Export MD</button></div>`)
	for i, p := range panes {
		show := ""
		if i != 0 {
			show = ` style="display:none"`
		}
		fmt.Fprintf(&b, `<div class="as-evo__pane" data-evo-pane="%d" data-evo-file="%s"%s>`, i, esc(p.file), show)
		p.body(&b)
		fmt.Fprintf(&b, `<textarea class="as-evo__md" hidden readonly>%s</textarea></div>`, esc(p.md))
	}
	b.WriteString(`</div>`)
	return b.String()
}

// writeBanner is the verdict strip: net result, better/worse/unchanged chips and
// the single best / worst move.
func writeBanner(b *strings.Builder, c evolution.Comparison) {
	vcls := "flat"
	if c.Better > c.Worse {
		vcls = "up"
	} else if c.Worse > c.Better {
		vcls = "down"
	}
	fmt.Fprintf(b, `<div class="as-evo__banner as-evo__banner--%s"><span class="as-evo__verdict">%s</span>`+
		`<span class="as-evo__chip as-evo__chip--up">▲ %d better</span>`+
		`<span class="as-evo__chip as-evo__chip--down">▼ %d worse</span>`+
		`<span class="as-evo__chip as-evo__chip--flat">= %d unchanged</span>`,
		vcls, esc(c.Verdict()), c.Better, c.Worse, c.Same)
	if m := c.BestMove; m != nil {
		fmt.Fprintf(b, `<span class="as-evo__move as-evo__d--up">best: %s %s %s</span>`, esc(m.Platform), esc(m.Dim), evolution.SignedInt(m.Delta))
	}
	if m := c.WorstMove; m != nil {
		fmt.Fprintf(b, `<span class="as-evo__move as-evo__d--down">worst: %s %s %s</span>`, esc(m.Platform), esc(m.Dim), evolution.SignedInt(m.Delta))
	}
	b.WriteString(`</div>`)
}

// writeComparisonBody renders one baseline-vs-now comparison: meta line, banner,
// numbers, dumbbells, and below them what got worse (and better) with its causes.
func writeComparisonBody(b *strings.Builder, c evolution.Comparison) {
	fmt.Fprintf(b, `<p class="as-evo__meta">Baseline: <strong>%s</strong> · <code>%s</code> %s`,
		esc(c.Ref.Title), esc(c.Ref.Short()), esc(c.Ref.Date.Format("2006-01-02")))
	if c.Ref.Subject != "" {
		fmt.Fprintf(b, ` “%s”`, esc(c.Ref.Subject))
	}
	if c.To != "" {
		fmt.Fprintf(b, ` → <strong>%s</strong></p>`, esc(strings.NewReplacer("`", "", "**", "").Replace(c.To)))
	} else {
		b.WriteString(` → <strong>now</strong> (working tree)</p>`)
	}
	writeBanner(b, c)

	// Step 2 — exact numbers.
	b.WriteString(`<div class="as-cult-scroll"><table class="as-cult-table as-evo__table"><thead><tr><th>Platform</th><th>Code Level</th>`)
	for _, d := range evolution.Dims {
		fmt.Fprintf(b, `<th>%s %s</th>`, d.Icon, esc(d.Name))
	}
	b.WriteString(`<th>LOC</th></tr></thead><tbody>`)
	for _, r := range c.Rows {
		b.WriteString(`<tr>`)
		fmt.Fprintf(b, `<td class="as-cult-plat"><span class="as-plat-badge as-plat-%s">%s</span><span class="as-cult-name">%s</span></td>`,
			esc(r.Lang), esc(r.Abbr), esc(r.Label))
		fmt.Fprintf(b, `<td>%s</td>`, evoLevelCell(r))
		for i, d := range evolution.Dims {
			b.WriteString(`<td>`)
			switch {
			case r.Both():
				dl := r.Delta(i)
				fmt.Fprintf(b, `<span class="as-evo__then">%d</span><span class="as-evo__to">→</span><strong>%d</strong> <span class="as-evo__d as-evo__d--%s">%s %s</span>`,
					d.Get(*r.Then), d.Get(*r.Now), evoDir(dl), evolution.Arrow(dl), evolution.SignedInt(dl))
			case r.Now != nil:
				fmt.Fprintf(b, `<span class="as-evo__tag">new</span> <strong>%d</strong>`, d.Get(*r.Now))
			default:
				fmt.Fprintf(b, `<span class="as-evo__tag">gone</span> <span class="as-evo__then">%d</span>`, d.Get(*r.Then))
			}
			b.WriteString(`</td>`)
		}
		switch {
		case r.Both():
			fmt.Fprintf(b, `<td class="mono">%s → %s</td>`, fmtNum(r.Then.LOC), fmtNum(r.Now.LOC))
		case r.Now != nil:
			fmt.Fprintf(b, `<td class="mono">%s</td>`, fmtNum(r.Now.LOC))
		default:
			fmt.Fprintf(b, `<td class="mono">was %s</td>`, fmtNum(r.Then.LOC))
		}
		b.WriteString(`</tr>`)
	}
	b.WriteString(`</tbody></table></div>`)

	// Step 3 — the picture: one dumbbell per dimension, then → now on a 0–100 track.
	b.WriteString(`<div class="as-evo__bells">`)
	for _, r := range c.Rows {
		if !r.Both() {
			continue
		}
		fmt.Fprintf(b, `<div class="as-evo__bell"><div class="as-evo__bellhead"><span class="as-plat-badge as-plat-%s">%s</span><span class="as-cult-name">%s</span></div>`,
			esc(r.Lang), esc(r.Abbr), esc(r.Label))
		for _, d := range evolution.Dims {
			writeTrack(b, d, []int{d.Get(*r.Then), d.Get(*r.Now)})
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div>`)

	// Step 4 — below it all: what got worse, and where it was added.
	writeDetails(b, c)
}

// writeTrack draws one dimension as a path across 0–100: a dot per point joined
// by bars colored by the direction of each leg, hollow for the past and solid for
// the last point. Two values make the classic dumbbell; three a timeline.
func writeTrack(b *strings.Builder, d evolution.Dim, vals []int) {
	pc := func(v int) int { return clampInt(v, 0, 100) }
	n := len(vals)
	total := vals[n-1] - vals[0]
	var links, dots, path []string
	for i := 0; i < n; i++ {
		path = append(path, fmt.Sprint(vals[i]))
		if i+1 < n {
			lo, hi := vals[i], vals[i+1]
			if lo > hi {
				lo, hi = hi, lo
			}
			links = append(links, fmt.Sprintf(`<span class="as-evo__link as-evo__link--%s" style="left:%d%%;width:%d%%"></span>`,
				evoDir(vals[i+1]-vals[i]), pc(lo), pc(hi)-pc(lo)))
		}
		if i == n-1 {
			dots = append(dots, fmt.Sprintf(`<span class="as-evo__dot as-evo__dot--now as-evo__dot--%s" style="left:%d%%"></span>`, evoDir(total), pc(vals[i])))
		} else {
			dots = append(dots, fmt.Sprintf(`<span class="as-evo__dot as-evo__dot--then" style="left:%d%%"></span>`, pc(vals[i])))
		}
	}
	fmt.Fprintf(b, `<div class="as-evo__row"><span class="as-evo__rowlbl">%s %s</span><div class="as-evo__track" title="%s">%s%s</div>`+
		`<span class="as-evo__rowval">%s <span class="as-evo__d as-evo__d--%s">%s</span></span></div>`,
		d.Icon, esc(d.Name), esc(strings.Join(path, " → ")), strings.Join(links, ""), strings.Join(dots, ""),
		strings.Join(path, " → "), evoDir(total), evolution.SignedInt(total))
}

func evoLevelCell(r evolution.Row) string {
	chip := func(name string) string {
		c := levelColor(name)
		return fmt.Sprintf(`<span class="as-cult-lvl" style="background:%s22;color:%s;border-color:%s55">%s</span>`, c, c, c, esc(name))
	}
	switch {
	case r.Both() && r.Then.Level != r.Now.Level:
		return chip(r.Then.Level) + ` <span class="as-evo__to">→</span> ` + chip(r.Now.Level) +
			fmt.Sprintf(` <span class="as-evo__d as-evo__d--%s">%s</span>`, evoDir(r.LevelShift()), evolution.Arrow(r.LevelShift()))
	case r.Both():
		return chip(r.Now.Level)
	case r.Now != nil:
		return chip(r.Now.Level) + ` <span class="as-evo__tag">new</span>`
	default:
		return chip(r.Then.Level) + ` <span class="as-evo__tag">gone</span>`
	}
}

func evoDir(d int) string {
	switch {
	case d > 0:
		return "up"
	case d < 0:
		return "down"
	}
	return "flat"
}

// slug lowercases s and turns runs of non-alphanumerics into single hyphens.
func slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}
