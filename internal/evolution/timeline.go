package evolution

import (
	"fmt"
	"sort"
	"strings"
)

// Point is one position on the timeline: a historical commit, or "now".
type Point struct {
	Ref    Ref
	Now    bool
	Scores []Score
}

// Title is the point's column heading.
func (p Point) Title() string {
	if p.Now {
		return "now"
	}
	return p.Ref.Title
}

// TLRow is one platform across every point (nil where it had no reading).
type TLRow struct {
	Key, Label, Abbr, Lang string
	IsDevOps               bool
	Scores                 []*Score // aligned with Timeline.Points
}

// Series returns dimension dim's value at each point (ok=false where absent).
func (r TLRow) Series(dim int) (vals []int, ok []bool) {
	for _, s := range r.Scores {
		if s == nil {
			vals, ok = append(vals, 0), append(ok, false)
			continue
		}
		vals, ok = append(vals, Dims[dim].Get(*s)), append(ok, true)
	}
	return
}

// Timeline lines several baselines up in date order, ending at "now": with
// `--evolution 1m 2w` that is 1 month ago → 2 weeks ago → now.
type Timeline struct {
	Points []Point
	Rows   []TLRow
	// Steps[i] compares Points[i] with Points[i+1] — what changed in that leg.
	Steps []Comparison
	// Span compares the oldest point with now.
	Span Comparison
}

// NewTimeline builds a Timeline from the per-baseline comparisons. It needs at
// least two baselines (two points plus "now" make a trend); ok is false otherwise.
func NewTimeline(cs []Comparison) (Timeline, bool) {
	if len(cs) < 2 {
		return Timeline{}, false
	}
	sorted := append([]Comparison(nil), cs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Ref.Date.Before(sorted[j].Ref.Date) })

	var tl Timeline
	for _, c := range sorted {
		tl.Points = append(tl.Points, Point{Ref: c.Ref, Scores: c.ThenScores()})
	}
	tl.Points = append(tl.Points, Point{Now: true, Scores: sorted[0].NowScores()})
	tl.Span = sorted[0]

	index := map[string]int{}
	for pi, p := range tl.Points {
		for i := range p.Scores {
			sc := &p.Scores[i]
			ri, seen := index[sc.Key]
			if !seen {
				ri = len(tl.Rows)
				index[sc.Key] = ri
				tl.Rows = append(tl.Rows, TLRow{Key: sc.Key, Label: sc.Label, Abbr: sc.Abbr, Lang: sc.Lang,
					IsDevOps: sc.IsDevOps, Scores: make([]*Score, len(tl.Points))})
			}
			tl.Rows[ri].Scores[pi] = sc
		}
	}
	// Show platforms in "now" order first (that is the order of the main table).
	sort.SliceStable(tl.Rows, func(i, j int) bool {
		return tl.Rows[i].Scores[len(tl.Points)-1] != nil && tl.Rows[j].Scores[len(tl.Points)-1] == nil
	})

	for i := 0; i+1 < len(tl.Points); i++ {
		from, to := tl.Points[i], tl.Points[i+1]
		step := Compare(from.Ref, to.Scores, from.Scores)
		if !to.Now {
			step.To = fmt.Sprintf("%s (`%s`)", to.Ref.Title, to.Ref.Short())
		}
		tl.Steps = append(tl.Steps, step)
	}
	return tl, true
}

// Heading is "1 month ago → 2 weeks ago → now".
func (t Timeline) Heading() string {
	var parts []string
	for _, p := range t.Points {
		parts = append(parts, p.Title())
	}
	return strings.Join(parts, " → ")
}

// RenderTimelineMarkdown renders the timeline: one table of each platform's
// values across all points, then every leg with its own what-got-worse detail.
func RenderTimelineMarkdown(t Timeline) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**%d points:** ", len(t.Points))
	for i, p := range t.Points {
		if i > 0 {
			b.WriteString(" → ")
		}
		if p.Now {
			b.WriteString("**now** (working tree)")
		} else {
			fmt.Fprintf(&b, "%s (`%s` %s)", p.Ref.Title, p.Ref.Short(), p.Ref.Date.Format("2006-01-02"))
		}
	}
	fmt.Fprintf(&b, "\n\n**%s** (oldest → now) · ▲ %d better · ▼ %d worse · = %d unchanged\n\n",
		t.Span.Verdict(), t.Span.Better, t.Span.Worse, t.Span.Same)

	b.WriteString("| Platform |")
	for _, d := range Dims {
		fmt.Fprintf(&b, " %s %s |", d.Icon, d.Name)
	}
	b.WriteString("\n|---|")
	for range Dims {
		b.WriteString("---:|")
	}
	b.WriteString("\n")
	for _, r := range t.Rows {
		fmt.Fprintf(&b, "| %s |", r.Label)
		for i := range Dims {
			vals, ok := r.Series(i)
			var cells []string
			first, last := -1, -1
			for pi := range vals {
				if !ok[pi] {
					cells = append(cells, "–")
					continue
				}
				cells = append(cells, fmt.Sprint(vals[pi]))
				if first < 0 {
					first = vals[pi]
				}
				last = vals[pi]
			}
			cell := strings.Join(cells, " → ")
			if first >= 0 {
				cell += fmt.Sprintf(" (%s %s)", Arrow(last-first), SignedInt(last-first))
			}
			fmt.Fprintf(&b, " %s |", cell)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")

	for i, st := range t.Steps {
		to := t.Points[i+1].Title()
		fmt.Fprintf(&b, "#### Step %d: %s → %s\n\n%s\n", i+1, t.Points[i].Title(), to, RenderMarkdown(st))
	}
	return b.String()
}

// LooksLikeSpec reports whether s is unambiguously an evolution spec (a
// duration, a date, "last-tag", "auto" or a hex commit id) rather than a path —
// the CLI uses it to let `--evolution 1m 2w` take several space-separated values.
func LooksLikeSpec(s string) bool {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return false
	case strings.EqualFold(s, "auto"), strings.EqualFold(s, "last-tag"):
		return true
	case durationRe.MatchString(s), dateRe.MatchString(s):
		return true
	case len(s) >= 7 && hexRe.MatchString(s):
		return true
	}
	return false
}
