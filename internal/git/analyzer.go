// Package git is the language-agnostic git-history analyzer, ported from
// goscope and extended with the branching-model classifier. Everything here
// shells out to the `git` binary on PATH; every entry point degrades to a zero
// value when git is missing or the directory is not a repository, so the rest
// of the pipeline never has to special-case "no history".
package git

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AuthorStats aggregates one author's footprint across the analyzed repos.
type AuthorStats struct {
	FilesModified      int            `json:"filesModified"`
	TotalCommits       int            `json:"totalCommits"`
	FirstCommit        float64        `json:"firstCommit"`
	LastCommit         float64        `json:"lastCommit"`
	MicroserviceCounts map[string]int `json:"microserviceCounts"`
	TotalLOCAdded      int            `json:"totalLOCAdded"`
}

// FileChurnStat is one file's change frequency.
type FileChurnStat struct {
	RelPath     string   `json:"relPath"`
	ChangeCount int      `json:"changeCount"`
	TopAuthors  []string `json:"topAuthors"`
}

// TagStats summarizes release tagging.
type TagStats struct {
	TotalTags    int      `json:"totalTags"`
	SemverTags   int      `json:"semverTags"`
	LatestSemver string   `json:"latestSemver"`
	SemverList   []string `json:"semverList"`
}

// CommitStats summarizes commit-message hygiene (conventional commits).
type CommitStats struct {
	Total      int            `json:"total"`
	Typed      int            `json:"typed"`
	TypeCounts map[string]int `json:"typeCounts"`
	Samples    []string       `json:"samples"`
}

// BranchInfo is one (stale) branch.
type BranchInfo struct {
	Name         string  `json:"name"`
	LastActivity float64 `json:"lastActivity"`
	DaysInactive int     `json:"daysInactive"`
}

// BranchingModelKind is the inferred branching strategy.
type BranchingModelKind string

const (
	ModelGitflow    BranchingModelKind = "Gitflow"
	ModelTrunkBased BranchingModelKind = "Trunk-Based Development"
	ModelGitHubFlow BranchingModelKind = "GitHub Flow"
	ModelGitLabFlow BranchingModelKind = "GitLab Flow"
	ModelOneFlow    BranchingModelKind = "OneFlow"
	ModelUnknown    BranchingModelKind = "Unknown"
)

// Icon returns an emoji badge for the model.
func (m BranchingModelKind) Icon() string {
	switch m {
	case ModelGitflow:
		return "🌿"
	case ModelTrunkBased:
		return "🪵"
	case ModelGitHubFlow:
		return "🐙"
	case ModelGitLabFlow:
		return "🦊"
	case ModelOneFlow:
		return "1️⃣"
	default:
		return "❓"
	}
}

// Detail returns a one-line description of the model.
func (m BranchingModelKind) Detail() string {
	switch m {
	case ModelGitflow:
		return "Long-lived integration branch · release & hotfix tracks"
	case ModelTrunkBased:
		return "Single trunk · micro-commits · continuous integration"
	case ModelGitHubFlow:
		return "Short-lived feature branches merged directly to main"
	case ModelGitLabFlow:
		return "GitHub Flow + cascading environment branches"
	case ModelOneFlow:
		return "One permanent branch · releases tagged on main"
	default:
		return "Insufficient history to determine strategy"
	}
}

// ModelScore is one model's weighted score in the classifier.
type ModelScore struct {
	Model BranchingModelKind `json:"model"`
	Score float64            `json:"score"`
}

// BranchingModel is the classifier's verdict plus its evidence.
type BranchingModel struct {
	Model               BranchingModelKind `json:"model"`
	Confidence          float64            `json:"confidence"` // winner score / total score
	IntegrationBranch   string             `json:"integrationBranch"`
	EnvironmentBranches []string           `json:"environmentBranches"`
	ReleasePrefixCount  int                `json:"releasePrefixCount"`
	HotfixPrefixCount   int                `json:"hotfixPrefixCount"`
	MergeCommitRatio    float64            `json:"mergeCommitRatio"`
	MergesPerDay        float64            `json:"mergesPerDay"`
	HasDualMerges       bool               `json:"hasDualMerges"`
	HasCascadingMerges  bool               `json:"hasCascadingMerges"`
	Signals             []string           `json:"signals"`
	ModelScores         []ModelScore       `json:"modelScores"`
}

// BranchStats is the branch-topology summary (design §9.3) plus the model.
type BranchStats struct {
	TotalBranches      int            `json:"totalBranches"`
	StaleBranches      []BranchInfo   `json:"staleBranches"`
	StaleThresholdDays int            `json:"staleThresholdDays"`
	AvgLifetimeDays    float64        `json:"avgLifetimeDays"`
	AvgTTMDays         float64        `json:"avgTTMDays"`
	AvgIntegDelayHours float64        `json:"avgIntegDelayHours"`
	MaxDepth           int            `json:"maxDepth"`
	RollbackCount      int            `json:"rollbackCount"`
	TotalMainCommits   int            `json:"totalMainCommits"`
	PeakCommitDay      string         `json:"peakCommitDay"`
	PrimaryBranch      string         `json:"primaryBranch"`
	Model              BranchingModel `json:"branchingModel"`
}

// Analyzer is bound to one repository.
type Analyzer struct {
	RepoPath    string
	CommitLimit int
}

// NewAnalyzer constructs an analyzer for repoPath.
func NewAnalyzer(repoPath string, commitLimit int) *Analyzer {
	if commitLimit <= 0 {
		commitLimit = 1000
	}
	return &Analyzer{RepoPath: repoPath, CommitLimit: commitLimit}
}

// Available reports whether git is on PATH and repoPath is inside a work tree.
func Available(repoPath string) bool {
	if _, err := exec.LookPath("git"); err != nil {
		return false
	}
	out, ok := runGit(repoPath, "rev-parse", "--is-inside-work-tree")
	return ok && strings.TrimSpace(out) == "true"
}

// runGit runs `git -C repo args...` and returns trimmed stdout and success.
func runGit(repo string, args ...string) (string, bool) {
	full := append([]string{"-C", repo}, args...)
	cmd := exec.Command("git", full...)
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return strings.TrimRight(string(out), "\n"), true
}

// ── Authors / churn ──────────────────────────────────────────────────────────

// commitLogRe is unused placeholder kept for clarity of the log format below.

// GetAuthorStatsMultiRepo aggregates author footprints across repos.
func GetAuthorStatsMultiRepo(gitRepos []string, commitLimit int) map[string]*AuthorStats {
	out := map[string]*AuthorStats{}
	for _, repo := range gitRepos {
		mergeAuthorStats(out, repo, commitLimit)
	}
	return out
}

// mergeAuthorStats folds one repo's author stats into acc.
func mergeAuthorStats(acc map[string]*AuthorStats, repo string, commitLimit int) {
	raw, ok := runGit(repo, "log", "-n", strconv.Itoa(commitLimit), "--no-merges",
		"--numstat", "--pretty=format:__C__\t%an\t%at")
	if !ok {
		return
	}
	var author string
	var ts float64
	seenFile := map[string]map[string]bool{} // author -> file set
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "__C__\t") {
			f := strings.Split(line, "\t")
			if len(f) >= 3 {
				author = f[1]
				ts = parseFloat(f[2])
				st := acc[author]
				if st == nil {
					st = &AuthorStats{MicroserviceCounts: map[string]int{}}
					acc[author] = st
					seenFile[author] = map[string]bool{}
				}
				st.TotalCommits++
				if st.FirstCommit == 0 || ts < st.FirstCommit {
					st.FirstCommit = ts
				}
				if ts > st.LastCommit {
					st.LastCommit = ts
				}
			}
			continue
		}
		if author == "" || strings.TrimSpace(line) == "" {
			continue
		}
		// numstat line: added \t deleted \t path
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			continue
		}
		added := parseInt(parts[0]) // "-" for binary -> 0
		path := parts[2]
		st := acc[author]
		st.TotalLOCAdded += added
		if seenFile[author] == nil {
			seenFile[author] = map[string]bool{}
		}
		if !seenFile[author][path] {
			seenFile[author][path] = true
			st.FilesModified++
		}
		st.MicroserviceCounts[topSegment(path)]++
	}
}

// GetChurnStats returns the topN most-frequently-changed files across repos.
func GetChurnStats(gitRepos []string, commitLimit, topN int) []FileChurnStat {
	type churn struct {
		count   int
		authors map[string]int
	}
	files := map[string]*churn{}
	for _, repo := range gitRepos {
		raw, ok := runGit(repo, "log", "-n", strconv.Itoa(commitLimit), "--no-merges",
			"--name-only", "--pretty=format:__A__\t%an")
		if !ok {
			continue
		}
		author := ""
		for _, line := range strings.Split(raw, "\n") {
			if strings.HasPrefix(line, "__A__\t") {
				author = strings.TrimPrefix(line, "__A__\t")
				continue
			}
			path := strings.TrimSpace(line)
			if path == "" {
				continue
			}
			c := files[path]
			if c == nil {
				c = &churn{authors: map[string]int{}}
				files[path] = c
			}
			c.count++
			c.authors[author]++
		}
	}
	out := make([]FileChurnStat, 0, len(files))
	for path, c := range files {
		out = append(out, FileChurnStat{
			RelPath: path, ChangeCount: c.count, TopAuthors: topKeys(c.authors, 3),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ChangeCount != out[j].ChangeCount {
			return out[i].ChangeCount > out[j].ChangeCount
		}
		return out[i].RelPath < out[j].RelPath
	})
	if topN > 0 && len(out) > topN {
		out = out[:topN]
	}
	return out
}

// ── Tags ───────────────────────────────────────────────────────────────────

var semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

// GetTagStats summarizes tags across repos (uses the first repo that has tags).
func GetTagStats(gitRepos []string) TagStats {
	var stats TagStats
	seen := map[string]bool{}
	for _, repo := range gitRepos {
		raw, ok := runGit(repo, "tag")
		if !ok || strings.TrimSpace(raw) == "" {
			continue
		}
		for _, t := range strings.Split(raw, "\n") {
			t = strings.TrimSpace(t)
			if t == "" || seen[t] {
				continue
			}
			seen[t] = true
			stats.TotalTags++
			if semverRe.MatchString(t) {
				stats.SemverTags++
				stats.SemverList = append(stats.SemverList, t)
			}
		}
	}
	sort.Slice(stats.SemverList, func(i, j int) bool {
		return semverLess(stats.SemverList[i], stats.SemverList[j])
	})
	if n := len(stats.SemverList); n > 0 {
		stats.LatestSemver = stats.SemverList[n-1]
	}
	return stats
}

// ── Commit messages ──────────────────────────────────────────────────────────

var conventionalRe = regexp.MustCompile(`^(\w+)(\([^)]*\))?!?:\s`)

// GetCommitMessageStats classifies commit subjects as conventional or not.
func GetCommitMessageStats(gitRepos []string, commitLimit int) CommitStats {
	stats := CommitStats{TypeCounts: map[string]int{}}
	for _, repo := range gitRepos {
		raw, ok := runGit(repo, "log", "-n", strconv.Itoa(commitLimit), "--no-merges",
			"--pretty=format:%s")
		if !ok {
			continue
		}
		for _, s := range strings.Split(raw, "\n") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			stats.Total++
			if m := conventionalRe.FindStringSubmatch(s); m != nil {
				stats.Typed++
				stats.TypeCounts[strings.ToLower(m[1])]++
			}
			if len(stats.Samples) < 8 {
				stats.Samples = append(stats.Samples, s)
			}
		}
	}
	return stats
}

// ── Branches + branching model ───────────────────────────────────────────────

var integrationCandidates = map[string]bool{
	"develop": true, "dev": true, "devel": true, "development": true,
	"integration": true, "next": true,
}

var envKeywords = []string{"staging", "stage", "production", "prod", "preprod", "preview", "qa"}

// GetBranchStats computes branch topology and the branching model for the first
// repo in gitRepos (branch topology is per-repo; the primary repo is canonical).
func GetBranchStats(gitRepos []string, staleDays int) BranchStats {
	stats := BranchStats{StaleThresholdDays: staleDays}
	if len(gitRepos) == 0 {
		return stats
	}
	repo := gitRepos[0]
	if !Available(repo) {
		return stats
	}
	primary := primaryBranch(repo)
	stats.PrimaryBranch = primary
	now := float64(time.Now().Unix())

	// All branch refs (local + remote), normalized (strip origin/, drop HEAD).
	refs := branchRefs(repo)
	names := map[string]float64{} // name -> last-activity unix
	for _, r := range refs {
		names[r.name] = r.last
	}
	stats.TotalBranches = len(names)

	// Stale branches + lifetime / TTM / integration-delay over non-primary branches.
	var lifetimes, ttms, integDelays []float64
	mergeInfo := mergeCommitIndex(repo, primary) // tipSHA -> merge unix
	for name, last := range names {
		if name == primary || name == "main" || name == "master" || name == "HEAD" {
			continue
		}
		daysInactive := int((now - last) / 86400.0)
		if staleDays > 0 && daysInactive >= staleDays {
			stats.StaleBranches = append(stats.StaleBranches, BranchInfo{
				Name: name, LastActivity: last, DaysInactive: daysInactive,
			})
		}
		// development span (lifetime) = lastCommit - firstCommit on branch since divergence
		first := firstCommitSince(repo, primary, name)
		if first > 0 && last >= first {
			lifetimes = append(lifetimes, (last-first)/86400.0)
		}
		// ahead-count contributes to MaxDepth
		if ahead := aheadCount(repo, primary, name); ahead > stats.MaxDepth {
			stats.MaxDepth = ahead
		}
		// if this branch tip was merged into primary, derive TTM + integ-delay
		if tip, ok := runGit(repo, "rev-parse", name); ok {
			if mt, merged := mergeInfo[strings.TrimSpace(tip)]; merged {
				if first > 0 {
					ttms = append(ttms, (mt-first)/86400.0)
				}
				if mt >= last {
					integDelays = append(integDelays, (mt-last)/3600.0)
				}
			}
		}
	}
	sort.Slice(stats.StaleBranches, func(i, j int) bool {
		return stats.StaleBranches[i].DaysInactive > stats.StaleBranches[j].DaysInactive
	})
	stats.AvgLifetimeDays = avg(lifetimes)
	stats.AvgTTMDays = avg(ttms)
	stats.AvgIntegDelayHours = avg(integDelays)

	// Total commits on primary, rollbacks, peak day.
	if c, ok := runGit(repo, "rev-list", "--count", primary); ok {
		stats.TotalMainCommits = parseInt(strings.TrimSpace(c))
	}
	if c, ok := runGit(repo, "rev-list", "--count", "--grep=^Revert", primary); ok {
		stats.RollbackCount = parseInt(strings.TrimSpace(c))
	}
	stats.PeakCommitDay = peakCommitDay(repo, primary, stats.TotalMainCommits)

	stats.Model = detectBranchingModel(repo, primary, names, stats.TotalMainCommits, stats.AvgLifetimeDays, now)
	return stats
}

// detectBranchingModel is the weighted classifier ported from the upstream
// Swift analyzer: it reads branch names, merge topology, integration tempo and
// branch lifetime and scores the five common strategies.
func detectBranchingModel(repo, primary string, names map[string]float64, totalMainCommits int, avgLifetimeDays, now float64) BranchingModel {
	var bm BranchingModel
	bm.Model = ModelUnknown
	if totalMainCommits <= 5 {
		return bm
	}
	protected := map[string]bool{primary: true, "main": true, "master": true, "HEAD": true}

	for name := range names {
		switch {
		case integrationCandidates[name] && bm.IntegrationBranch == "":
			bm.IntegrationBranch = name
		case strings.HasPrefix(name, "release/"), strings.HasPrefix(name, "rel/"), strings.HasPrefix(name, "releases/"):
			bm.ReleasePrefixCount++
		case strings.HasPrefix(name, "hotfix/"), strings.HasPrefix(name, "hotfix-"), strings.HasPrefix(name, "hf/"):
			bm.HotfixPrefixCount++
		}
		if !protected[name] && !integrationCandidates[name] && matchesEnv(name) {
			bm.EnvironmentBranches = append(bm.EnvironmentBranches, name)
		}
	}
	sort.Strings(bm.EnvironmentBranches)

	if mc, ok := runGit(repo, "rev-list", "--count", "--merges", primary); ok && totalMainCommits > 0 {
		bm.MergeCommitRatio = float64(parseInt(strings.TrimSpace(mc))) / float64(totalMainCommits)
	}
	if first, ok := runGit(repo, "log", primary, "--pretty=format:%at", "--reverse"); ok {
		if lines := strings.SplitN(first, "\n", 2); len(lines) > 0 {
			if ft := parseFloat(strings.TrimSpace(lines[0])); ft > 0 {
				ageDays := (now - ft) / 86400.0
				if ageDays < 1 {
					ageDays = 1
				}
				bm.MergesPerDay = bm.MergeCommitRatio * float64(totalMainCommits) / ageDays
			}
		}
	}
	if bm.IntegrationBranch != "" {
		mainMerges := mergeSubjects(repo, primary, 50)
		integMerges := mergeSubjects(repo, bm.IntegrationBranch, 50)
		bm.HasDualMerges = intersectionCount(mainMerges, integMerges) >= 2
	}
	for i, env := range bm.EnvironmentBranches {
		if i >= 3 {
			break
		}
		if s, ok := runGit(repo, "log", env, "--merges", "-3", "--pretty=format:%s"); ok && strings.TrimSpace(s) != "" {
			bm.HasCascadingMerges = true
			break
		}
	}

	s := map[BranchingModelKind]float64{
		ModelGitflow: 0, ModelTrunkBased: 0, ModelGitHubFlow: 0, ModelGitLabFlow: 0, ModelOneFlow: 0,
	}
	add := func(k BranchingModelKind, v float64) { s[k] += v }

	if bm.IntegrationBranch != "" {
		add(ModelGitflow, 40)
		add(ModelTrunkBased, -20)
		add(ModelGitHubFlow, -10)
		bm.Signals = append(bm.Signals, "Integration branch '"+bm.IntegrationBranch+"' detected")
	}
	if bm.ReleasePrefixCount > 0 {
		add(ModelGitflow, 25)
		bm.Signals = append(bm.Signals, plural(bm.ReleasePrefixCount, "release/* branch", "release/* branches"))
	}
	if bm.HotfixPrefixCount > 0 {
		add(ModelGitflow, 18)
		add(ModelOneFlow, 5)
		bm.Signals = append(bm.Signals, plural(bm.HotfixPrefixCount, "hotfix/* branch", "hotfix/* branches"))
	}
	if bm.HasDualMerges {
		add(ModelGitflow, 35)
		bm.Signals = append(bm.Signals, "Dual-merge pattern across '"+primary+"' and '"+bm.IntegrationBranch+"'")
	}
	switch {
	case bm.MergeCommitRatio > 0.7:
		add(ModelGitflow, 15)
		bm.Signals = append(bm.Signals, "High merge-commit ratio ("+pct(bm.MergeCommitRatio)+") on "+primary)
	case bm.MergeCommitRatio > 0 && bm.MergeCommitRatio < 0.2:
		add(ModelTrunkBased, 20)
		add(ModelOneFlow, 5)
		bm.Signals = append(bm.Signals, "Linear history ("+pct(bm.MergeCommitRatio)+" merges — squash/rebase)")
	case bm.MergeCommitRatio >= 0.3 && bm.MergeCommitRatio <= 0.7:
		add(ModelGitLabFlow, 8)
		add(ModelGitHubFlow, 5)
	}
	if avgLifetimeDays > 0 {
		switch {
		case avgLifetimeDays < 1.0:
			add(ModelTrunkBased, 25)
			add(ModelGitHubFlow, 8)
			bm.Signals = append(bm.Signals, "Very short avg branch lifetime → micro-commit cadence")
		case avgLifetimeDays < 3.0:
			add(ModelGitHubFlow, 20)
			add(ModelTrunkBased, 8)
			add(ModelGitLabFlow, 8)
			bm.Signals = append(bm.Signals, "Short avg branch lifetime")
		default:
			add(ModelGitflow, 15)
			bm.Signals = append(bm.Signals, "Long avg branch lifetime → batch integration releases")
		}
	}
	if bm.MergesPerDay > 0 {
		switch {
		case bm.MergesPerDay > 3.0:
			add(ModelTrunkBased, 30)
			bm.Signals = append(bm.Signals, "High merge frequency into "+primary)
		case bm.MergesPerDay > 1.0:
			add(ModelGitHubFlow, 20)
			add(ModelTrunkBased, 8)
			add(ModelGitLabFlow, 8)
		case bm.MergesPerDay < 0.5:
			add(ModelGitflow, 10)
			add(ModelOneFlow, 5)
		}
	}
	if bm.HasCascadingMerges {
		add(ModelGitLabFlow, 50)
		bm.Signals = append(bm.Signals, "Cascading merges into environment branches: "+strings.Join(bm.EnvironmentBranches, ", "))
	} else if len(bm.EnvironmentBranches) > 0 {
		add(ModelGitLabFlow, 20)
		add(ModelGitHubFlow, -10)
		bm.Signals = append(bm.Signals, "Environment branches found: "+strings.Join(bm.EnvironmentBranches, ", "))
	}
	if bm.IntegrationBranch == "" && bm.ReleasePrefixCount == 0 && !bm.HasCascadingMerges {
		add(ModelOneFlow, 8)
	}
	if bm.IntegrationBranch == "" && bm.ReleasePrefixCount == 0 && bm.HotfixPrefixCount == 0 && !bm.HasCascadingMerges {
		add(ModelGitHubFlow, 15)
		if len(bm.Signals) == 0 {
			bm.Signals = append(bm.Signals, "Simple feature-branch workflow — no integration/release/hotfix branches")
		}
	}

	total := 0.0
	for k := range s {
		if s[k] < 0 {
			s[k] = 0
		}
		total += s[k]
	}
	scores := make([]ModelScore, 0, len(s))
	for k, v := range s {
		scores = append(scores, ModelScore{Model: k, Score: v})
	}
	sort.Slice(scores, func(i, j int) bool { return scores[i].Score > scores[j].Score })
	bm.ModelScores = scores
	if len(scores) > 0 && scores[0].Score > 0 && total > 0 {
		bm.Model = scores[0].Model
		bm.Confidence = scores[0].Score / total
	}
	return bm
}

// ── Blame (per-finding author attribution) ────────────────────────────────────

var blameAuthorRe = regexp.MustCompile(`^author (.+)$`)

// BlameLinesSubset returns author names for the requested 1-based line numbers
// of filePath (relative to the repo). It blames the whole file once and selects
// the wanted lines; on any error it returns an empty map (callers tolerate it).
func (a *Analyzer) BlameLinesSubset(filePath string, want map[int]bool) map[int]string {
	out := map[int]string{}
	if len(want) == 0 || !Available(a.RepoPath) {
		return out
	}
	rel := filePath
	if abs, err := filepath.Abs(filePath); err == nil {
		if r, err := filepath.Rel(a.RepoPath, abs); err == nil {
			rel = r
		}
	}
	raw, ok := runGit(a.RepoPath, "blame", "--line-porcelain", "--", rel)
	if !ok {
		return out
	}
	line := 0
	author := ""
	for _, l := range strings.Split(raw, "\n") {
		if m := blameAuthorRe.FindStringSubmatch(l); m != nil {
			author = m[1]
			continue
		}
		if strings.HasPrefix(l, "\t") { // the actual source line; advances counter
			line++
			if want[line] && author != "" {
				out[line] = author
			}
		}
	}
	return out
}

// ── small git helpers ──────────────────────────────────────────────────────

type branchRef struct {
	name string
	last float64
}

// branchRefs lists local + remote branch refs with last-commit unix time,
// normalized: origin/ prefix stripped and HEAD pointers dropped.
func branchRefs(repo string) []branchRef {
	raw, ok := runGit(repo, "for-each-ref",
		"--format=%(refname:short)%09%(committerdate:unix)",
		"refs/heads/", "refs/remotes/")
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var out []branchRef
	for _, l := range strings.Split(raw, "\n") {
		f := strings.Split(l, "\t")
		if len(f) < 2 {
			continue
		}
		name := strings.TrimSpace(f[0])
		if name == "" || strings.HasSuffix(name, "/HEAD") {
			continue
		}
		name = strings.TrimPrefix(name, "origin/")
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, branchRef{name: name, last: parseFloat(strings.TrimSpace(f[1]))})
	}
	return out
}

func primaryBranch(repo string) string {
	if b, ok := runGit(repo, "symbolic-ref", "--short", "HEAD"); ok {
		if t := strings.TrimSpace(b); t != "" {
			return t
		}
	}
	if b, ok := runGit(repo, "rev-parse", "--abbrev-ref", "origin/HEAD"); ok {
		t := strings.TrimSpace(strings.TrimPrefix(b, "origin/"))
		if t != "" && t != "HEAD" {
			return t
		}
	}
	for _, cand := range []string{"main", "master"} {
		if _, ok := runGit(repo, "rev-parse", "--verify", cand); ok {
			return cand
		}
	}
	return "HEAD"
}

func firstCommitSince(repo, primary, branch string) float64 {
	out, ok := runGit(repo, "log", "--reverse", "--pretty=format:%at", primary+".."+branch)
	if !ok {
		return 0
	}
	if lines := strings.SplitN(strings.TrimSpace(out), "\n", 2); len(lines) > 0 && lines[0] != "" {
		return parseFloat(lines[0])
	}
	return 0
}

func aheadCount(repo, primary, branch string) int {
	if c, ok := runGit(repo, "rev-list", "--count", primary+".."+branch); ok {
		return parseInt(strings.TrimSpace(c))
	}
	return 0
}

// mergeCommitIndex maps each merged-in parent SHA to the merge commit time, so
// a branch tip can be matched to when it landed on primary.
func mergeCommitIndex(repo, primary string) map[string]float64 {
	out := map[string]float64{}
	raw, ok := runGit(repo, "log", primary, "--merges", "-200", "--pretty=format:%ct\t%P")
	if !ok {
		return out
	}
	for _, l := range strings.Split(raw, "\n") {
		f := strings.SplitN(l, "\t", 2)
		if len(f) < 2 {
			continue
		}
		mt := parseFloat(f[0])
		for _, p := range strings.Fields(f[1]) {
			out[p] = mt
		}
	}
	return out
}

func mergeSubjects(repo, branch string, n int) map[string]bool {
	out := map[string]bool{}
	if raw, ok := runGit(repo, "log", branch, "--merges", "-"+strconv.Itoa(n), "--pretty=format:%s"); ok {
		for _, s := range strings.Split(raw, "\n") {
			if s = strings.TrimSpace(s); s != "" {
				out[s] = true
			}
		}
	}
	return out
}

func peakCommitDay(repo, primary string, total int) string {
	if total == 0 {
		return ""
	}
	raw, ok := runGit(repo, "log", primary, "--pretty=format:%ad", "--date=format:%a")
	if !ok {
		return ""
	}
	counts := map[string]int{}
	for _, d := range strings.Split(raw, "\n") {
		if d = strings.TrimSpace(d); d != "" {
			counts[d]++
		}
	}
	best, bestN := "", -1
	for d, n := range counts {
		if n > bestN {
			best, bestN = d, n
		}
	}
	return best
}

// ── pure helpers ─────────────────────────────────────────────────────────────

func matchesEnv(name string) bool {
	for _, k := range envKeywords {
		if name == k || strings.HasPrefix(name, k+"/") || strings.HasPrefix(name, k+"-") {
			return true
		}
	}
	return false
}

func intersectionCount(a, b map[string]bool) int {
	n := 0
	for k := range a {
		if b[k] {
			n++
		}
	}
	return n
}

func topSegment(path string) string {
	p := filepath.ToSlash(path)
	if i := strings.IndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	return "."
}

func topKeys(m map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	var s []kv
	for k, v := range m {
		s = append(s, kv{k, v})
	}
	sort.Slice(s, func(i, j int) bool {
		if s[i].v != s[j].v {
			return s[i].v > s[j].v
		}
		return s[i].k < s[j].k
	})
	out := make([]string, 0, n)
	for i := 0; i < len(s) && i < n; i++ {
		out = append(out, s[i].k)
	}
	return out
}

func avg(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs))
}

func parseInt(s string) int {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return 0
	}
	n, _ := strconv.Atoi(s)
	return n
}

func parseFloat(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

func semverLess(a, b string) bool {
	pa, pb := semverRe.FindStringSubmatch(a), semverRe.FindStringSubmatch(b)
	if pa == nil || pb == nil {
		return a < b
	}
	for i := 1; i <= 3; i++ {
		x, y := parseInt(pa[i]), parseInt(pb[i])
		if x != y {
			return x < y
		}
	}
	return false
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func pct(f float64) string { return strconv.Itoa(int(f*100+0.5)) + "%" }
