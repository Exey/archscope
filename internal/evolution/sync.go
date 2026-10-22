package evolution

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// SyncResult tells the CLI what SyncForReview did to the repository.
type SyncResult struct {
	Against  string // --against to use from now on ("" = unchanged)
	Switched string // branch that was checked out for the review ("" = none)
	From     string // the branch the user was on before
}

// SyncForReview prepares the repository for a review: it fetches the remote,
// checks out (creating a tracking branch if only origin has it) and fast-forwards
// the branch under review when it isn't the checked-out one, and brings the
// target branch the merge request goes into (dev, main, …) up to date, so the
// merge-base — and therefore the diff — is the merge request's own. It never
// discards work: with uncommitted changes to tracked files it does not switch,
// every update is fast-forward only, and failures are reported through log and
// then ignored (the review still runs on what is local).
//
// When it switches away from the branch you were on and no --against was given,
// that branch becomes the base (as it was before the switch), returned in Against.
func SyncForReview(repo, reviewRef, against string, log func(string)) SyncResult {
	say := func(m string) {
		if log != nil {
			log(m)
		}
	}
	var res SyncResult
	if out, err := gitTimeout(repo, 90*time.Second, "remote"); err != nil || strings.TrimSpace(out) == "" {
		say("git: no remote — reviewing local branches as they are")
		return res
	}
	if _, err := gitTimeout(repo, 90*time.Second, "fetch", "--prune", "origin"); err != nil {
		say("git: fetch failed (" + shortErr(err) + ") — continuing with what is local")
	} else {
		say("git: fetched origin")
	}

	spec := ReviewPrefix + reviewRef
	if against != "" {
		spec += "@@" + against
	}
	ref, err := Resolve(repo, spec, time.Now())
	if err != nil {
		return res // the caller reports an unknown ref
	}
	current, _ := git(repo, "rev-parse", "--abbrev-ref", "HEAD")

	// 1) the branch under review
	if ref.HeadSHA != "" && ref.Target != "" {
		name := localBranchName(repo, ref.Target)
		switch {
		case current == "HEAD":
			say("git: detached HEAD — not switching to " + name)
		case dirtyTracked(repo):
			say("git: uncommitted changes — not switching to " + name + "; reviewing it from its commit")
		default:
			if err := checkoutBranch(repo, name); err != nil {
				say("git: could not check out " + name + " (" + shortErr(err) + ")")
			} else {
				res.Switched, res.From = name, current
				say("git: switched to " + name + " (was " + current + ")")
				if _, err := gitTimeout(repo, 90*time.Second, "pull", "--ff-only"); err != nil {
					say("git: could not fast-forward " + name + " (" + shortErr(err) + ")")
				} else {
					say("git: " + name + " is up to date")
				}
				if against == "" && current != "" && current != name {
					res.Against = current // keep the base the review had before the switch
				}
			}
		}
	} else if name := strings.TrimPrefix(reviewRef, "origin/"); current != "" && name == current && !dirtyTracked(repo) {
		// reviewing the branch you are already on: just bring it up to date
		if _, err := gitTimeout(repo, 90*time.Second, "pull", "--ff-only"); err == nil {
			say("git: " + current + " is up to date")
		}
	}

	// 1b) no --against: infer the branch the merge request goes into
	if against == "" && res.Against == "" {
		isBranchReview := ref.HeadSHA != "" || strings.TrimPrefix(reviewRef, "origin/") == current
		if head := ref.HeadSHA; isBranchReview {
			if head == "" {
				head, _ = git(repo, "rev-parse", "HEAD")
			}
			if guess := GuessTargetBranch(repo, head); guess != "" && guess != strings.TrimPrefix(reviewRef, "origin/") && guess != localBranchName(repo, reviewRef) {
				res.Against = guess
				say("git: merge request target looks like " + guess + " (closest base branch)")
			}
		}
	}

	// 2) the branch the merge request goes into
	target := ref.Against
	if ref.HeadSHA == "" && target == "" {
		target = ref.Target // reviewing the checked-out branch against a target such as dev
	}
	if res.Against != "" {
		target = res.Against
	}
	if target != "" && target != "HEAD" && !strings.HasPrefix(target, "HEAD~") {
		updateBranch(repo, localBranchName(repo, target), say)
	}
	return res
}

// updateBranch fast-forwards a local branch to its remote counterpart without
// switching to it (or pulls, when it is the checked-out branch).
func updateBranch(repo, name string, say func(string)) {
	if name == "" {
		return
	}
	if _, err := git(repo, "rev-parse", "--verify", "--quiet", "refs/heads/"+name); err != nil {
		return // no local branch: the remote-tracking one is used as is
	}
	if _, err := git(repo, "rev-parse", "--verify", "--quiet", "refs/remotes/origin/"+name); err != nil {
		return
	}
	current, _ := git(repo, "rev-parse", "--abbrev-ref", "HEAD")
	var err error
	if current == name {
		if dirtyTracked(repo) {
			return
		}
		_, err = gitTimeout(repo, 90*time.Second, "pull", "--ff-only")
	} else {
		_, err = gitTimeout(repo, 90*time.Second, "fetch", "origin", name+":"+name)
	}
	if err != nil {
		say("git: could not fast-forward " + name + " (" + shortErr(err) + ")")
		return
	}
	say("git: " + name + " is up to date")
}

// localBranchName maps "origin/feat/x" / "refs/remotes/origin/feat/x" / "feat/x" to "feat/x".
func localBranchName(repo, ref string) string {
	ref = strings.TrimPrefix(ref, "refs/remotes/")
	ref = strings.TrimPrefix(ref, "refs/heads/")
	if remotes, err := git(repo, "remote"); err == nil {
		for _, r := range strings.Fields(remotes) {
			if strings.HasPrefix(ref, r+"/") {
				return strings.TrimPrefix(ref, r+"/")
			}
		}
	}
	return ref
}

// checkoutBranch checks out a local branch, or creates one tracking origin/<name>.
func checkoutBranch(repo, name string) error {
	if _, err := git(repo, "rev-parse", "--verify", "--quiet", "refs/heads/"+name); err == nil {
		_, err := git(repo, "checkout", name)
		return err
	}
	_, err := git(repo, "checkout", "--track", "origin/"+name)
	return err
}

// dirtyTracked reports uncommitted changes to tracked files.
func dirtyTracked(repo string) bool {
	out, err := git(repo, "status", "--porcelain", "--untracked-files=no")
	return err != nil || out != ""
}

// gitTimeout is git() with a deadline and prompts disabled, for network commands.
func gitTimeout(repo string, d time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repo}, args...)...)
	cmd.Env = append(cmd.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(out)), &gitErr{msg: strings.TrimSpace(string(out)), err: err}
	}
	return strings.TrimSpace(string(out)), nil
}

type gitErr struct {
	msg string
	err error
}

func (e *gitErr) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return e.err.Error()
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 140 {
		s = s[:140] + "…"
	}
	return s
}

// GuessTargetBranch infers which branch a merge request from head goes into: of the
// usual integration branches (dev, develop, main, master, trunk, staging, release/*),
// the one with the smallest symmetric distance to head (commits only in it plus commits only in head) — the one head was cut from and is closest to. Remote-tracking
// refs are preferred (they are fresh after a fetch). "" when none qualifies.
func GuessTargetBranch(repo, head string) string {
	out, err := git(repo, "for-each-ref", "--format=%(refname)", "refs/remotes/origin", "refs/heads")
	if err != nil {
		return ""
	}
	priority := map[string]int{"dev": 0, "develop": 1, "development": 2, "main": 3, "master": 4, "trunk": 5, "staging": 6}
	type cand struct {
		name, ref string
		dist, pri int
	}
	var best *cand
	seen := map[string]bool{}
	for _, ref := range strings.Split(out, "\n") {
		name := strings.TrimPrefix(strings.TrimPrefix(ref, "refs/remotes/origin/"), "refs/heads/")
		if name == "" || name == "HEAD" || seen[name] {
			continue
		}
		pri, known := priority[name]
		if !known && !strings.HasPrefix(name, "release/") {
			continue
		}
		if !known {
			pri = 10
		}
		// prefer the remote-tracking ref for the distance, fall back to the local one
		rev := "refs/remotes/origin/" + name
		if _, err := git(repo, "rev-parse", "--verify", "--quiet", rev); err != nil {
			rev = "refs/heads/" + name
		}
		tip, err := git(repo, "rev-parse", rev)
		if err != nil || tip == head {
			continue
		}
		if _, err := git(repo, "merge-base", tip, head); err != nil {
			continue // unrelated history
		}
		// symmetric distance: commits only in the candidate + commits only in head
		cnt, err := git(repo, "rev-list", "--left-right", "--count", tip+"..."+head)
		if err != nil {
			continue
		}
		var behind, ahead int
		if f := strings.Fields(cnt); len(f) == 2 {
			fmtSscan(f[0], &behind)
			fmtSscan(f[1], &ahead)
		}
		if ahead == 0 {
			continue // head is contained in it: already merged
		}
		dist := behind + ahead
		seen[name] = true
		if c := (cand{name, rev, dist, pri}); best == nil || c.dist < best.dist || c.dist == best.dist && c.pri < best.pri {
			best = &c
		}
	}
	if best == nil {
		return ""
	}
	return best.name
}

func fmtSscan(s string, v *int) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	*v = n
}
