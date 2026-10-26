package result

import (
	"fmt"
	"github.com/exey/archscope/internal/openapi"
	"os"
	"path/filepath"
	"strings"
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
	cfg.NoSpecScan = true // baselines are scored on code only
	repo, sub, err := evolution.Toplevel(res.RootPath)
	if err != nil {
		say("Evolution skipped: %v", err)
		return nil
	}

	nowScores := score(res)
	subjectScores := map[string][]evolution.Score{} // reviewed tip → scores of ITS tree
	seen := map[string]string{}                     // commit → first spec that resolved to it
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
		now := nowScores
		if ref.HeadSHA != "" {
			// Review of a branch that is not checked out: "now" is that branch's own tree.
			sc, ok := subjectScores[ref.HeadSHA]
			if !ok {
				say("Evolution: scoring the reviewed branch %s (%s)…", ref.Target, shortSHA(ref.HeadSHA))
				sdir, scleanup, err := evolution.Extract(repo, ref.HeadSHA, sub)
				if err != nil {
					say("Evolution %q skipped: %v", spec, err)
					continue
				}
				sres, err := RunWithProgress(sdir, cfg, nil)
				scleanup()
				if err != nil {
					say("Evolution %q skipped: analysis of %s failed: %v", spec, ref.Target, err)
					continue
				}
				sc = score(sres)
				// The temp tree is gone; point offenders at the same file in the working tree.
				for i := range sc {
					for j := range sc[i].Items {
						it := &sc[i].Items[j]
						it.Path = filepath.Join(repo, filepath.FromSlash(sub), filepath.FromSlash(it.Rel))
					}
				}
				subjectScores[ref.HeadSHA] = sc
			}
			now = sc
		}
		cmp := evolution.Compare(ref, now, score(past))
		if ref.HeadSHA != "" {
			cmp.To = fmt.Sprintf("branch %s (`%s`)", ref.Target, shortSHA(ref.HeadSHA))
		}
		out = append(out, cmp)
	}
	return out
}

// RunReview is review mode (--review <commit|branch>): an Evolution whose
// baseline is the merge-base of HEAD and ref — what a merge request diffs
// against — plus the facts needed to link every introduced offender to its
// line in the MR (GitLab host/project, the MR IID found from
// refs/merge-requests, and per-line diff anchors). extra are additional
// --evolution specs. ref "" or "auto" picks the local default branch (see
// evolution.DefaultBranch). The review comparison always comes first.
func RunReview(res *AnalysisResult, cfg config.Config, ref, against string, extra []string, score ScoreFunc, progress func(string)) []evolution.Comparison {
	// Score the baselines on the same platforms the review analysed.
	cfg.OnlyPlatforms, cfg.ReviewChanged, cfg.NoSpecScan = res.ReviewPlatforms, nil, true
	spec := evolution.ReviewPrefix + ref
	if against != "" {
		spec += "@@" + against
	}
	var lastSkip string
	wrapped := func(m string) {
		if strings.Contains(m, "skipped") {
			lastSkip = m
		}
		if progress != nil {
			progress(m)
		}
	}
	comps := RunEvolution(res, cfg, append([]string{spec}, extra...), score, wrapped)
	idx := -1
	for i, c := range comps {
		if c.Ref.Spec == spec {
			idx = i
		}
	}
	if idx < 0 {
		res.ReviewNote = strings.TrimSpace(lastSkip)
		if res.ReviewNote == "" {
			res.ReviewNote = "review of " + ref + " could not run"
		}
		return comps // RunEvolution already logged why
	}
	repo, sub, err := evolution.Toplevel(res.RootPath)
	if err != nil {
		return comps
	}
	base := comps[idx].Ref
	target := base.Target
	if target == "" {
		target = ref
	}
	info := evolution.ReviewInfo(repo, target, base)
	evolution.EnrichReview(repo, sub, info.BaseSHA, info.HeadSHA, &comps[idx])
	info.AttachFiles(repo, comps[idx])
	attachSpecFindings(res, repo, &info)
	attachQuality(res, repo, &info)
	res.Review = &info
	if progress != nil {
		progress(info.String())
	}
	comps[0], comps[idx] = comps[idx], comps[0]
	return comps
}

func shortSHA(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

// attachSpecFindings adds, to each changed OpenAPI file of the merge request, the
// findings the change *introduced*: the spec is linted at the reviewed side and at
// the merge-base, and only findings the base didn't already have are kept — so a
// reviewer sees what this MR broke, not the spec's history. Advisory findings
// stay out of the review list.
func attachSpecFindings(res *AnalysisResult, repo string, rv *evolution.Review) {
	for i := range rv.Files {
		f := &rv.Files[i]
		ext := strings.ToLower(filepath.Ext(f.Path))
		if f.Binary || (ext != ".yaml" && ext != ".yml" && ext != ".json") {
			continue
		}
		var now string
		if rv.Subject != "" && rv.HeadSHA != "" {
			now, _ = evolution.FileAt(repo, rv.HeadSHA, f.Path)
		} else if b, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(f.Path))); err == nil {
			now = string(b)
		}
		newFindings, ok := openapi.Lint(now)
		if !ok {
			continue
		}
		oldCount := map[string]int{}
		var changes []openapi.Change
		if old, err := evolution.FileAt(repo, rv.BaseSHA, f.Path); err == nil {
			oldFindings, _ := openapi.Lint(old)
			for _, of := range oldFindings {
				oldCount[of.RuleID+"|"+of.Detail]++
			}
			changes, _ = openapi.Diff(old, now)
		}
		head := rv.HeadSHA
		if rv.Subject == "" {
			head = ""
		}
		oldPos := evolution.NewToOld(repo, rv.BaseSHA, head, f.Path)
		abs := filepath.Join(repo, filepath.FromSlash(f.Path))
		rel := f.Path
		if r, err := filepath.Rel(res.RootPath, abs); err == nil && !strings.HasPrefix(r, "..") {
			rel = filepath.ToSlash(r)
		}
		for _, c := range changes {
			if c.Level == "info" {
				continue
			}
			name, weight := "API change: "+c.Rule, 2
			if c.Level == "breaking" {
				name, weight = "Breaking API change: "+c.Rule, 7
			}
			line, pos := c.Line, -1
			if line <= 0 {
				line = 1
			}
			if p, ok := oldPos[line]; ok {
				pos = p
			}
			f.Issues = append(f.Issues, evolution.Item{
				Dim: 2, Kind: "OpenAPI", Name: name, Note: c.Detail, Rel: rel, Path: abs, Line: line,
				Weight: weight, RepoPath: f.Path, OldPos: pos, Key: "oasdiff|" + c.Level + "|" + c.Rule + "|" + c.Detail,
			})
		}
		for j := range res.OpenAPI {
			if filepath.Clean(res.OpenAPI[j].Path) == filepath.Clean(abs) {
				res.OpenAPI[j].Changes = changes
			}
		}
		for _, nf := range newFindings {
			k := nf.RuleID + "|" + nf.Detail
			if nf.Advisory {
				continue
			}
			if oldCount[k] > 0 {
				oldCount[k]--
				continue
			}
			weight := 1
			switch nf.Severity {
			case "HIGH":
				weight = 7
			case "MEDIUM":
				weight = 2
			}
			pos := -1
			if p, ok := oldPos[nf.Line]; ok {
				pos = p
			}
			f.Issues = append(f.Issues, evolution.Item{
				Dim: 2, Kind: "OpenAPI", Name: nf.Rule, Note: nf.Detail, Rel: rel, Path: abs, Line: nf.Line,
				Weight: weight, RepoPath: f.Path, OldPos: pos, Key: "oas|" + k,
			})
		}
	}
}
