// Package evolution compares a codebase's Programming Culture scores now
// against the same codebase at an earlier point in git history — "how did the
// code look two weeks ago, and what got better or worse since?".
//
// The package is deliberately free of the report/result layers: it knows how to
// resolve a baseline (a duration like 2w, the last tag, a date, a commit),
// extract that commit's tree into a temp dir, and diff two lists of per-platform
// Scores. Scoring itself (which lives with the HTML report's culture model) and
// the orchestration that runs the analysis pipeline on the extracted tree are
// supplied by the caller — see internal/result/evolution.go.
package evolution

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Score is one platform's (or DevOps') Programming Culture reading.
type Score struct {
	Key      string // platform tab key — the join key between "then" and "now"
	Label    string
	Abbr     string
	Lang     string // CSS color-class language
	IsDevOps bool
	LOC      int

	Design, Quality, Security, Perf, Overall int

	Level     string // Code Level name, e.g. "Middle"
	LevelRank int    // position on the ladder; higher = more senior

	// Metrics are the raw signals behind each dimension and Items the individual
	// offenders (findings, long functions, hotspots…) — together they explain
	// WHY a dimension moved. Both are optional; Compare skips what is absent.
	Metrics []Metric
	Items   []Item
}

// Metric is one raw signal feeding a dimension, e.g. "Long functions" = 4.
type Metric struct {
	Dim          int    // index into Dims (1..4)
	Name         string // stable join key between "then" and "now"
	Value        int
	Unit         string // "", "%" or " lines"
	HigherBetter bool
}

// Item is one concrete offender behind a dimension (a HIGH finding, an O(N²)
// function, a 400-line function…). Key must be unique within a Score and stable
// across commits (path relative to the scan root + name, never a line number),
// so "added since baseline" is simply the keys that were not there before.
type Item struct {
	Dim    int
	Kind   string // "HIGH security", "O(N²)", "Long function", …
	Name   string // rule / symbol
	Note   string // short extra context (snippet, reason, "212 lines")
	Rel    string // path relative to the scan root
	Path   string // absolute path in the working tree — "" on the baseline side
	Line   int
	Size   int // lines / depth / parameter count, for "grew" detection; 0 = not sized
	Weight int // severity weight for ordering (HIGH 7, MEDIUM 2, …)
	Key    string
}

// Ref is a resolved baseline commit.
type Ref struct {
	Spec    string // what the user asked for: "2w", "last-tag", "a1b2c3d", …
	Label   string // short tab label: "2 weeks", "since v1.2.0"
	Title   string // longer description: "2 weeks ago", "last tag v1.2.0"
	SHA     string
	Subject string
	Date    time.Time
}

// Short is the 7-char commit id.
func (r Ref) Short() string {
	if len(r.SHA) > 7 {
		return r.SHA[:7]
	}
	return r.SHA
}

// Dim names one scored dimension and reads it from a Score.
type Dim struct {
	Name string
	Icon string
	Get  func(Score) int
}

// Dims are the four culture dimensions plus the overall score, in display order.
var Dims = []Dim{
	{"Overall", "🔰", func(s Score) int { return s.Overall }},
	{"Design", "🏛️", func(s Score) int { return s.Design }},
	{"Code Quality", "🧹", func(s Score) int { return s.Quality }},
	{"Security", "🛡️", func(s Score) int { return s.Security }},
	{"Performance", "⚡", func(s Score) int { return s.Perf }},
}

// Row compares one platform. Then or Now is nil when the platform did not
// reach the culture LOC threshold (or did not exist) on that side.
type Row struct {
	Key      string
	Label    string
	Abbr     string
	Lang     string
	IsDevOps bool
	Then     *Score
	Now      *Score
}

// Both reports whether the platform has a reading on both sides.
func (r Row) Both() bool { return r.Then != nil && r.Now != nil }

// Delta is now − then for dimension i of Dims (0 when either side is absent).
func (r Row) Delta(i int) int {
	if !r.Both() {
		return 0
	}
	return Dims[i].Get(*r.Now) - Dims[i].Get(*r.Then)
}

// LevelShift is the change in ladder rungs (positive = promoted).
func (r Row) LevelShift() int {
	if !r.Both() {
		return 0
	}
	return r.Now.LevelRank - r.Then.LevelRank
}

// Mover is one notable dimension change, for the "biggest moves" summary.
type Mover struct {
	Platform string
	Dim      string
	Delta    int
}

// Comparison is the full then-vs-now result for one baseline.
type Comparison struct {
	Ref  Ref
	To   string // what Ref is compared against; "" = the working tree ("now")
	Rows []Row

	// Counts over the four dimensions (not Overall) of every platform that has a
	// reading on both sides.
	Better, Worse, Same int

	BestMove, WorstMove *Mover // nil when nothing improved / declined

	// One Detail per (platform, dimension) that moved: why, and where.
	WorseDetails, BetterDetails []Detail
}

// MetricChange is one raw signal that differs between then and now.
type MetricChange struct {
	Name         string
	Unit         string
	Then, Now    int
	HigherBetter bool
}

// Worse reports whether the change is in the bad direction.
func (m MetricChange) Worse() bool { return (m.Now < m.Then) == m.HigherBetter }

// Grown is an offender present on both sides that got bigger (a function that
// went from 210 to 340 lines, nesting that went one level deeper).
type Grown struct {
	Item     Item
	ThenSize int
}

// Detail explains one dimension's move on one platform.
type Detail struct {
	Key, Label, Abbr, Lang string
	Dim                    int // index into Dims
	Then, Now, Delta       int
	LOCThen, LOCNow        int
	Metrics                []MetricChange // changed signals, bad ones first
	Added                  []Item         // offenders that did not exist at the baseline
	Grew                   []Grown
	Resolved               int // offenders that existed at the baseline and are gone
}

// Explained reports whether the detail has anything beyond the bare numbers.
func (d Detail) Explained() bool {
	return len(d.Metrics) > 0 || len(d.Added) > 0 || len(d.Grew) > 0 || d.Resolved > 0
}

// Compare diffs now against then, joining on Score.Key. Rows follow the order of
// now; platforms that only existed then are appended.
func Compare(ref Ref, now, then []Score) Comparison {
	c := Comparison{Ref: ref}
	thenBy := make(map[string]*Score, len(then))
	for i := range then {
		thenBy[then[i].Key] = &then[i]
	}
	seen := map[string]bool{}
	for i := range now {
		n := &now[i]
		seen[n.Key] = true
		c.Rows = append(c.Rows, Row{
			Key: n.Key, Label: n.Label, Abbr: n.Abbr, Lang: n.Lang, IsDevOps: n.IsDevOps,
			Then: thenBy[n.Key], Now: n,
		})
	}
	for i := range then {
		t := &then[i]
		if !seen[t.Key] {
			c.Rows = append(c.Rows, Row{
				Key: t.Key, Label: t.Label, Abbr: t.Abbr, Lang: t.Lang, IsDevOps: t.IsDevOps, Then: t,
			})
		}
	}
	for _, r := range c.Rows {
		if !r.Both() {
			continue
		}
		for i := 1; i < len(Dims); i++ { // skip Overall: it is derived from the four
			d := r.Delta(i)
			if d != 0 {
				det := buildDetail(r, i)
				if d < 0 {
					c.WorseDetails = append(c.WorseDetails, det)
				} else {
					c.BetterDetails = append(c.BetterDetails, det)
				}
			}
			switch {
			case d > 0:
				c.Better++
				if c.BestMove == nil || d > c.BestMove.Delta {
					c.BestMove = &Mover{r.Label, Dims[i].Name, d}
				}
			case d < 0:
				c.Worse++
				if c.WorstMove == nil || d < c.WorstMove.Delta {
					c.WorstMove = &Mover{r.Label, Dims[i].Name, d}
				}
			default:
				c.Same++
			}
		}
	}
	sort.SliceStable(c.WorseDetails, func(i, j int) bool { return c.WorseDetails[i].Delta < c.WorseDetails[j].Delta })
	sort.SliceStable(c.BetterDetails, func(i, j int) bool { return c.BetterDetails[i].Delta > c.BetterDetails[j].Delta })
	return c
}

// buildDetail diffs the metrics and offender items of one dimension of a row.
func buildDetail(r Row, dim int) Detail {
	d := Detail{
		Key: r.Key, Label: r.Label, Abbr: r.Abbr, Lang: r.Lang, Dim: dim,
		Then: Dims[dim].Get(*r.Then), Now: Dims[dim].Get(*r.Now),
		LOCThen: r.Then.LOC, LOCNow: r.Now.LOC,
	}
	d.Delta = d.Now - d.Then

	thenM := map[string]Metric{}
	for _, m := range r.Then.Metrics {
		if m.Dim == dim {
			thenM[m.Name] = m
		}
	}
	for _, m := range r.Now.Metrics {
		if t, ok := thenM[m.Name]; m.Dim == dim && ok && t.Value != m.Value {
			d.Metrics = append(d.Metrics, MetricChange{Name: m.Name, Unit: m.Unit, Then: t.Value, Now: m.Value, HigherBetter: m.HigherBetter})
		}
	}
	// Bad changes first, then by size of the move.
	sort.SliceStable(d.Metrics, func(i, j int) bool {
		wi, wj := d.Metrics[i].Worse(), d.Metrics[j].Worse()
		if wi != wj {
			return wi
		}
		return absInt(d.Metrics[i].Now-d.Metrics[i].Then) > absInt(d.Metrics[j].Now-d.Metrics[j].Then)
	})

	thenI := map[string]Item{}
	for _, it := range r.Then.Items {
		if it.Dim == dim {
			thenI[it.Key] = it
		}
	}
	nowKeys := map[string]bool{}
	for _, it := range r.Now.Items {
		if it.Dim != dim {
			continue
		}
		nowKeys[it.Key] = true
		t, existed := thenI[it.Key]
		switch {
		case !existed:
			d.Added = append(d.Added, it)
		case it.Size > 0 && t.Size > 0 && it.Size-t.Size >= maxInt(3, t.Size/10):
			d.Grew = append(d.Grew, Grown{Item: it, ThenSize: t.Size})
		}
	}
	for k := range thenI {
		if !nowKeys[k] {
			d.Resolved++
		}
	}
	sort.SliceStable(d.Added, func(i, j int) bool {
		a, b := d.Added[i], d.Added[j]
		if a.Weight != b.Weight {
			return a.Weight > b.Weight
		}
		if a.Size != b.Size {
			return a.Size > b.Size
		}
		return a.Rel < b.Rel
	})
	sort.SliceStable(d.Grew, func(i, j int) bool {
		return d.Grew[i].Item.Size-d.Grew[i].ThenSize > d.Grew[j].Item.Size-d.Grew[j].ThenSize
	})
	return d
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ThenScores / NowScores recover the two score lists a Comparison was built from.
func (c Comparison) ThenScores() []Score {
	var out []Score
	for _, r := range c.Rows {
		if r.Then != nil {
			out = append(out, *r.Then)
		}
	}
	return out
}

func (c Comparison) NowScores() []Score {
	var out []Score
	for _, r := range c.Rows {
		if r.Now != nil {
			out = append(out, *r.Now)
		}
	}
	return out
}

// Verdict is a one-phrase read of the whole comparison.
func (c Comparison) Verdict() string {
	switch {
	case c.Better == 0 && c.Worse == 0:
		return "No change in any dimension"
	case c.Better > c.Worse:
		return "Net improvement"
	case c.Worse > c.Better:
		return "Net decline"
	default:
		return "Mixed — improvements offset by declines"
	}
}

// Arrow is the glyph for a delta.
func Arrow(d int) string {
	switch {
	case d > 0:
		return "▲"
	case d < 0:
		return "▼"
	}
	return "="
}

// SignedInt formats a delta with an explicit sign (+8, −3, 0).
func SignedInt(d int) string {
	switch {
	case d > 0:
		return fmt.Sprintf("+%d", d)
	case d < 0:
		return fmt.Sprintf("−%d", -d)
	}
	return "0"
}

// toLabel is the right-hand side of a comparison: the working tree unless the
// comparison is a step between two historical points.
func (c Comparison) toLabel() string {
	if c.To != "" {
		return c.To
	}
	return "**now** (working tree)"
}

// RenderMarkdown renders one comparison as a Markdown section body (no
// top-level heading) — used by `--format md` and by the HTML "Export MD" button.
func RenderMarkdown(c Comparison) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**Baseline:** %s — `%s` %s", c.Ref.Title, c.Ref.Short(), c.Ref.Date.Format("2006-01-02"))
	if c.Ref.Subject != "" {
		fmt.Fprintf(&b, " “%s”", c.Ref.Subject)
	}
	fmt.Fprintf(&b, " → %s\n\n", c.toLabel())
	fmt.Fprintf(&b, "**%s** · ▲ %d better · ▼ %d worse · = %d unchanged", c.Verdict(), c.Better, c.Worse, c.Same)
	if c.BestMove != nil {
		fmt.Fprintf(&b, " · best: %s %s %s", c.BestMove.Platform, c.BestMove.Dim, SignedInt(c.BestMove.Delta))
	}
	if c.WorstMove != nil {
		fmt.Fprintf(&b, " · worst: %s %s %s", c.WorstMove.Platform, c.WorstMove.Dim, SignedInt(c.WorstMove.Delta))
	}
	b.WriteString("\n\n")

	b.WriteString("| Platform | Level |")
	for _, d := range Dims {
		fmt.Fprintf(&b, " %s %s |", d.Icon, d.Name)
	}
	b.WriteString(" LOC |\n|---|---|")
	for range Dims {
		b.WriteString("---:|")
	}
	b.WriteString("---:|\n")
	for _, r := range c.Rows {
		fmt.Fprintf(&b, "| %s | %s |", r.Label, levelCellMD(r))
		for i, d := range Dims {
			switch {
			case r.Both():
				dl := r.Delta(i)
				fmt.Fprintf(&b, " %d → %d (%s %s) |", d.Get(*r.Then), d.Get(*r.Now), Arrow(dl), SignedInt(dl))
			case r.Now != nil:
				fmt.Fprintf(&b, " new: %d |", d.Get(*r.Now))
			default:
				fmt.Fprintf(&b, " gone (was %d) |", d.Get(*r.Then))
			}
		}
		switch {
		case r.Both():
			fmt.Fprintf(&b, " %d → %d |\n", r.Then.LOC, r.Now.LOC)
		case r.Now != nil:
			fmt.Fprintf(&b, " %d |\n", r.Now.LOC)
		default:
			fmt.Fprintf(&b, " was %d |\n", r.Then.LOC)
		}
	}
	b.WriteString("\n")

	if len(c.WorseDetails) == 0 {
		b.WriteString("✓ Nothing got worse.\n\n")
	} else {
		b.WriteString("#### ▼ What got worse, and where\n\n")
		for _, d := range c.WorseDetails {
			writeDetailMD(&b, d)
		}
	}
	if len(c.BetterDetails) > 0 {
		b.WriteString("#### ▲ What got better\n\n")
		for _, d := range c.BetterDetails {
			writeDetailMD(&b, d)
		}
	}
	b.WriteString("_Scores are the same Programming Culture heuristic evaluated on both trees; a platform is only scored once it has enough code. A conversation starter, not a verdict._\n")
	return b.String()
}

// MaxDetailItems caps how many introduced offenders a Detail lists per kind of
// list before collapsing the rest into "+N more".
const MaxDetailItems = 10

// FormatMetric renders a metric value with its unit.
func FormatMetric(v int, unit string) string { return fmt.Sprintf("%d%s", v, unit) }

func writeDetailMD(b *strings.Builder, d Detail) {
	fmt.Fprintf(b, "**%s · %s %s: %d → %d (%s)**\n\n", d.Label, Dims[d.Dim].Icon, Dims[d.Dim].Name, d.Then, d.Now, SignedInt(d.Delta))
	for _, m := range d.Metrics {
		arrow := "▲"
		if m.Worse() {
			arrow = "▼"
		}
		fmt.Fprintf(b, "- %s %s: %s → %s\n", arrow, m.Name, FormatMetric(m.Then, m.Unit), FormatMetric(m.Now, m.Unit))
	}
	if d.LOCThen != d.LOCNow {
		fmt.Fprintf(b, "- ℹ️ Code size: %d → %d LOC (density-based penalties are per 1000 lines)\n", d.LOCThen, d.LOCNow)
	}
	if len(d.Added) > 0 {
		fmt.Fprintf(b, "- **Introduced (%d):**\n", len(d.Added))
		for i, it := range d.Added {
			if i == MaxDetailItems {
				fmt.Fprintf(b, "  - … and %d more\n", len(d.Added)-MaxDetailItems)
				break
			}
			fmt.Fprintf(b, "  - %s\n", itemMD(it))
		}
	}
	if len(d.Grew) > 0 {
		fmt.Fprintf(b, "- **Grew (%d):**\n", len(d.Grew))
		for i, g := range d.Grew {
			if i == MaxDetailItems {
				fmt.Fprintf(b, "  - … and %d more\n", len(d.Grew)-MaxDetailItems)
				break
			}
			fmt.Fprintf(b, "  - %s — %d → %d\n", itemMD(g.Item), g.ThenSize, g.Item.Size)
		}
	}
	if d.Resolved > 0 {
		fmt.Fprintf(b, "- ✓ %d offender(s) resolved\n", d.Resolved)
	}
	if !d.Explained() && d.LOCThen == d.LOCNow {
		b.WriteString("- No tracked signal changed — a rounding-level shift from re-weighting.\n")
	}
	b.WriteString("\n")
}

func itemMD(it Item) string {
	loc := it.Rel
	if it.Line > 0 {
		loc = fmt.Sprintf("%s:%d", it.Rel, it.Line)
	}
	s := fmt.Sprintf("%s `%s` — `%s`", it.Kind, strings.ReplaceAll(it.Name, "`", "'"), loc)
	if it.Note != "" {
		s += " · " + it.Note
	}
	return s
}

func levelCellMD(r Row) string {
	switch {
	case r.Both() && r.Then.Level != r.Now.Level:
		return fmt.Sprintf("%s → %s %s", r.Then.Level, r.Now.Level, Arrow(r.LevelShift()))
	case r.Both():
		return r.Now.Level
	case r.Now != nil:
		return r.Now.Level + " (new)"
	default:
		return r.Then.Level + " (gone)"
	}
}
