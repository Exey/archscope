package result

import (
	"fmt"
	"time"

	"github.com/exey/archscope/internal/config"
	"github.com/exey/archscope/internal/evolution"
)

// ScoreFunc turns a finished analysis into per-platform Programming Culture
// scores. The culture model lives in the HTML report package (which imports
// this one), so the caller injects it rather than result importing it back.
type ScoreFunc func(*AnalysisResult) []evolution.Score

// RunEvolution compares res (the working tree) against each requested baseline
// in git history: it resolves every spec to a commit, extracts that commit's
// tree to a temp dir, runs the same pipeline with the same config on it, scores
// both sides with score, and diffs them. Specs that cannot be resolved (no tag,
// repo too young, unknown ref) are reported through progress and skipped — one
// bad spec never loses the others. Specs that resolve to a commit already
// compared (e.g. 2w and 1m in a young repo) are skipped as duplicates.
func RunEvolution(res *AnalysisResult, cfg config.Config, specs []string, score ScoreFunc, progress func(string)) []evolution.Comparison {
	say := func(format string, a ...any) {
		if progress != nil {
			progress(fmt.Sprintf(format, a...))
		}
	}
	if len(specs) == 0 {
		return nil
	}
	repo, sub, err := evolution.Toplevel(res.RootPath)
	if err != nil {
		say("Evolution skipped: %v", err)
		return nil
	}

	now := score(res)
	seen := map[string]string{} // commit → first spec that resolved to it
	var out []evolution.Comparison
	for _, spec := range specs {
		ref, err := evolution.Resolve(repo, spec, time.Now())
		if err != nil {
			say("Evolution %q skipped: %v", spec, err)
			continue
		}
		if prev, dup := seen[ref.SHA]; dup {
			say("Evolution %q skipped: same commit (%s) as %q", spec, ref.Short(), prev)
			continue
		}
		seen[ref.SHA] = spec

		say("Evolution: scoring %s (%s %s)…", ref.Title, ref.Short(), ref.Date.Format("2006-01-02"))
		dir, cleanup, err := evolution.Extract(repo, ref.SHA, sub)
		if err != nil {
			say("Evolution %q skipped: %v", spec, err)
			continue
		}
		past, err := RunWithProgress(dir, cfg, nil)
		cleanup()
		if err != nil {
			say("Evolution %q skipped: analysis of %s failed: %v", spec, ref.Short(), err)
			continue
		}
		out = append(out, evolution.Compare(ref, now, score(past)))
	}
	return out
}
