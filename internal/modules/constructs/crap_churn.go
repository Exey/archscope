package constructs

import (
	"math"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// crap_churn.go is crapkit's churn weighting: how much recent change a file has
// seen. Every commit in the window (12 months back from HEAD's date, never from the
// wall clock) gets a logistic weight by its position between the oldest and the
// newest commit of the window — 0.5 for the newest, near nothing for the oldest —
// and a file's churn is the sum over the commits that touched it. Five edits last
// month so outrank fifty from two years ago. A window whose commits share one
// timestamp has no range to weight against, so each commit counts once.

const crapChurnMonths = 12

// churnTable is one repository's per-file churn.
type churnTable struct {
	weight  map[string]float64 // repo-relative slash path → weight
	commits map[string]int     // …and the number of commits behind it
	window  int                // commits in the window
	months  int
}

// twr is the time-weighted recency of a commit at ts.
func twr(ts, oldest, newest int64) float64 {
	if newest == oldest {
		return 1.0
	}
	t := float64(ts-oldest) / float64(newest-oldest)
	return 1.0 / (1.0 + math.Exp(-12.0*t+12.0))
}

// gitChurn reads the window's log of the repository at root. nil when git cannot.
func gitChurn(root string, months int) *churnTable {
	head, err := exec.Command("git", "-C", root, "log", "-1", "--format=%ct").Output()
	if err != nil {
		return nil
	}
	ct, err := strconv.ParseInt(strings.TrimSpace(string(head)), 10, 64)
	if err != nil {
		return nil
	}
	cutoff := time.Unix(ct, 0).AddDate(0, -months, 0).Unix()
	out, err := exec.Command("git", "-c", "core.quotePath=false", "-C", root, "log", "--since="+strconv.FormatInt(cutoff, 10),
		"--no-renames", "--name-only", "--format=\x01%at").Output()
	if err != nil {
		return nil
	}
	type commit struct {
		at    int64
		files []string
	}
	var commits []commit
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "\x01"):
			at, _ := strconv.ParseInt(line[1:], 10, 64)
			commits = append(commits, commit{at: at})
		case line != "" && len(commits) > 0:
			c := &commits[len(commits)-1]
			c.files = append(c.files, line)
		}
	}
	if len(commits) == 0 {
		return &churnTable{weight: map[string]float64{}, commits: map[string]int{}, months: months}
	}
	oldest, newest := commits[0].at, commits[0].at
	for _, c := range commits {
		if c.at < oldest {
			oldest = c.at
		}
		if c.at > newest {
			newest = c.at
		}
	}
	t := &churnTable{weight: map[string]float64{}, commits: map[string]int{}, window: len(commits), months: months}
	parts := map[string][]float64{}
	for _, c := range commits {
		w := twr(c.at, oldest, newest)
		for _, f := range c.files {
			parts[f] = append(parts[f], w)
			t.commits[f]++
		}
	}
	for f, ws := range parts {
		sort.Float64s(ws) // a fixed order, so the sum does not depend on how git lists commits
		sum := 0.0
		for _, w := range ws {
			sum += w
		}
		t.weight[f] = math.Round(sum*10000) / 10000
	}
	return t
}

// repoRootOf returns the git top level of dir ("" outside a repository), cached.
func repoRootOf(cache map[string]string, dir string) string {
	if r, ok := cache[dir]; ok {
		return r
	}
	root := ""
	if out, err := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel").Output(); err == nil {
		root = strings.TrimSpace(string(out))
		if r, err := filepath.EvalSymlinks(root); err == nil {
			root = r
		}
	}
	cache[dir] = root
	return root
}
