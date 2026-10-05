package evolution

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AutoSpecs is what `--evolution auto` expands to. last-tag is skipped quietly
// (see Resolve's ErrNoTag) in repositories that have no tags.
var AutoSpecs = []string{"2w", "1m", "last-tag"}

// ParseSpecs splits a comma-separated --evolution value into specs, expanding
// "auto" and dropping blanks/duplicates.
func ParseSpecs(v string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[strings.ToLower(s)] {
			return
		}
		seen[strings.ToLower(s)] = true
		out = append(out, s)
	}
	for _, s := range strings.Split(v, ",") {
		if strings.EqualFold(strings.TrimSpace(s), "auto") {
			for _, a := range AutoSpecs {
				add(a)
			}
			continue
		}
		add(s)
	}
	return out
}

// ReviewPrefix marks a spec as a review baseline: the merge-base of HEAD and the
// given commit/branch (see the --review flag).
const ReviewPrefix = "review:"

// ErrNoTag is returned by Resolve for "last-tag" when the repo has no usable tag.
var ErrNoTag = fmt.Errorf("no tag found")

var (
	durationRe = regexp.MustCompile(`(?i)^(\d+)\s*(d|day|days|w|wk|week|weeks|m|mo|month|months|y|yr|year|years)$`)
	dateRe     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	hexRe      = regexp.MustCompile(`^[0-9a-fA-F]{6,40}$`)
)

// git runs a git command in repo and returns trimmed stdout.
func git(repo string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// Toplevel returns the git repository containing path and path's location
// inside it ("" when path is the repo root).
func Toplevel(path string) (repo, sub string, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	top, err := git(abs, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", "", fmt.Errorf("%s is not inside a git repository", path)
	}
	// Resolve symlinks on both sides (macOS /var → /private/var) so Rel works.
	if r, e := filepath.EvalSymlinks(top); e == nil {
		top = r
	}
	if r, e := filepath.EvalSymlinks(abs); e == nil {
		abs = r
	}
	rel, err := filepath.Rel(top, abs)
	if err != nil || rel == "." {
		return top, "", nil
	}
	return top, filepath.ToSlash(rel), nil
}

// Resolve turns a spec into a concrete baseline commit in repo.
//
// Specs: a duration back from now (2w, 14d, 1m, 3m, 1y), "last-tag" (the most
// recent tag — the previous one when HEAD is itself tagged), a YYYY-MM-DD date
// (the repo as of the end of that day), or any commit-ish (sha, branch, tag).
func Resolve(repo, spec string, now time.Time) (Ref, error) {
	spec = strings.TrimSpace(spec)
	ref := Ref{Spec: spec}
	var sha string

	switch {
	case strings.HasPrefix(spec, ReviewPrefix):
		if err := resolveReview(repo, strings.TrimPrefix(spec, ReviewPrefix), &ref); err != nil {
			return ref, err
		}
		sha = ref.SHA
		ref.SHA = ""

	case strings.EqualFold(spec, "last-tag"):
		tag, err := lastTag(repo)
		if err != nil {
			return ref, err
		}
		ref.Label, ref.Title = "since "+tag, "last tag "+tag
		out, err := git(repo, "rev-list", "-n1", tag)
		if err != nil {
			return ref, err
		}
		sha = out

	case durationRe.MatchString(spec):
		m := durationRe.FindStringSubmatch(spec)
		n, _ := strconv.Atoi(m[1])
		cutoff, label := durationBack(now, n, strings.ToLower(m[2]))
		ref.Label, ref.Title = label, label+" ago"
		out, err := git(repo, "rev-list", "-1", "--before="+cutoff.Format(time.RFC3339), "HEAD")
		if err != nil {
			return ref, err
		}
		if out == "" {
			return ref, fmt.Errorf("history starts after %s — no commit that old", cutoff.Format("2006-01-02"))
		}
		sha = out

	case dateRe.MatchString(spec):
		ref.Label, ref.Title = "since "+spec, "as of "+spec
		out, err := git(repo, "rev-list", "-1", "--before="+spec+"T23:59:59", "HEAD")
		if err != nil {
			return ref, err
		}
		if out == "" {
			return ref, fmt.Errorf("history starts after %s", spec)
		}
		sha = out

	default:
		out := resolveCommit(repo, spec)
		if out == "" {
			return ref, fmt.Errorf("%q is not a duration, date, tag or commit in this repository", spec)
		}
		sha = out
		name := spec
		if hexRe.MatchString(spec) { // a sha reads better abbreviated; a branch/tag name as typed
			name = out[:7]
		}
		ref.Label, ref.Title = "since "+name, "commit "+name
	}

	info, err := git(repo, "show", "-s", "--format=%H%x1f%cI%x1f%s", sha)
	if err != nil {
		return ref, err
	}
	parts := strings.SplitN(info, "\x1f", 3)
	if len(parts) < 3 {
		return ref, fmt.Errorf("unexpected git output for %s", sha)
	}
	ref.SHA = parts[0]
	ref.Date, _ = time.Parse(time.RFC3339, parts[1])
	ref.Subject = parts[2]
	return ref, nil
}

// resolveCommit turns a commit-ish into a sha, also finding a branch that only
// exists on a remote (feat/x → origin/feat/x) — typical for a branch someone
// else pushed and you have not checked out. "" when nothing matches.
func resolveCommit(repo, name string) string {
	try := func(n string) string {
		out, err := git(repo, "rev-parse", "--verify", "--quiet", n+"^{commit}")
		if err != nil {
			return ""
		}
		return out
	}
	if sha := try(name); sha != "" {
		return sha
	}
	if remotes, err := git(repo, "remote"); err == nil {
		// origin first, then any other remote.
		list := strings.Fields(remotes)
		sort.SliceStable(list, func(i, j int) bool { return list[i] == "origin" && list[j] != "origin" })
		for _, r := range list {
			if sha := try("refs/remotes/" + r + "/" + name); sha != "" {
				return sha
			}
		}
	}
	return ""
}

// resolvedName is the name to show/use for a commit-ish after resolveCommit:
// the name as typed when it resolves directly, else its remote-tracking form.
func resolvedName(repo, name string) string {
	if _, err := git(repo, "rev-parse", "--verify", "--quiet", name+"^{commit}"); err == nil {
		return name
	}
	if remotes, err := git(repo, "remote"); err == nil {
		list := strings.Fields(remotes)
		sort.SliceStable(list, func(i, j int) bool { return list[i] == "origin" && list[j] != "origin" })
		for _, r := range list {
			if _, err := git(repo, "rev-parse", "--verify", "--quiet", "refs/remotes/"+r+"/"+name+"^{commit}"); err == nil {
				return r + "/" + name
			}
		}
	}
	return name
}

// isDefaultBranchName reports whether name (with or without a remote prefix) is
// the repository's default/target branch by name: such a ref is a merge TARGET,
// never the thing being reviewed.
func isDefaultBranchName(repo, name string) bool {
	bare := name
	if i := strings.IndexByte(bare, '/'); i > 0 && (strings.HasPrefix(bare, "origin/") || strings.HasPrefix(bare, "upstream/")) {
		bare = bare[i+1:]
	}
	switch bare {
	case "main", "master", "develop", "dev", "trunk":
		return true
	}
	d := DefaultBranch(repo)
	return d != "" && (name == d || strings.TrimPrefix(d, "origin/") == bare)
}

// resolveReview fills ref for a review spec "<ref>[@@<against>]":
//
//   - ref is a merge TARGET (a default branch such as main/develop, an ancestor of
//     HEAD, or empty/auto): review HEAD (the working tree) against the merge-base,
//     exactly what an MR from the current branch diffs.
//   - otherwise ref is the BRANCH UNDER REVIEW (say feat/x, even if only on
//     origin and not checked out): review its tip against the merge-base of ref
//     and the current branch (or @@against), i.e. "what feat/x adds".
//
// ref.SHA receives the base commit; ref.HeadSHA the reviewed tip ("" = working tree).
func resolveReview(repo, spec string, ref *Ref) error {
	target, against, _ := strings.Cut(spec, "@@")
	auto := target == "" || strings.EqualFold(target, "auto")
	if auto {
		if target = DefaultBranch(repo); target == "" {
			return fmt.Errorf("could not find a main/master/develop branch to review against — name one: --review <branch>")
		}
	}
	if strings.EqualFold(target, "last-commit") {
		target = "HEAD~1"
	}
	tip := resolveCommit(repo, target)
	if tip == "" {
		return fmt.Errorf("%q is not a commit or branch in this repository (also looked for it on the remotes)", target)
	}
	target = resolvedName(repo, target)
	head, _ := git(repo, "rev-parse", "HEAD")
	isAnc := func(a, b string) bool {
		return exec.Command("git", "-C", repo, "merge-base", "--is-ancestor", a, b).Run() == nil
	}
	ref.Target = target

	switch {
	case auto && tip == head:
		// Checked out on the default branch itself: nothing to merge — review the last commit.
		prev := resolveCommit(repo, "HEAD~1")
		if prev == "" {
			return fmt.Errorf("on %s with no earlier commit — nothing to review", target)
		}
		ref.Target = "HEAD~1"
		ref.Label, ref.Title = "review: last commit", "last commit (you are on "+DefaultBranch(repo)+")"
		ref.SHA = prev

	case against == "" && (auto || isDefaultBranchName(repo, target) || isAnc(tip, head) && tip != head):
		// ref is the target: where the current branch left it.
		ref.SHA = tip
		if mb, err := git(repo, "merge-base", "HEAD", tip); err == nil && mb != "" {
			ref.SHA = mb
		}
		ref.Label, ref.Title = "review: "+target, "merge-base with "+target

	default:
		// ref is the branch under review. Compare it with --against, else with the
		// default branch, else with where you are now.
		baseName := against
		if baseName == "" {
			if tip == head {
				baseName = DefaultBranch(repo) // reviewing the current branch itself
			} else {
				baseName = "HEAD"
			}
		}
		if baseName == "" {
			return fmt.Errorf("%s is the checked-out branch and no default branch was found — pass --against <branch>", target)
		}
		baseSHA := resolveCommit(repo, baseName)
		if baseSHA == "" {
			return fmt.Errorf("--against %q is not a commit or branch in this repository", baseName)
		}
		baseName = resolvedName(repo, baseName)
		ref.SHA = baseSHA
		if mb, err := git(repo, "merge-base", tip, baseSHA); err == nil && mb != "" {
			ref.SHA = mb
		}
		ref.Against = baseName
		if baseName == "HEAD" {
			if b, err := git(repo, "rev-parse", "--abbrev-ref", "HEAD"); err == nil && b != "HEAD" {
				ref.Against = b
			}
		}
		if tip != head {
			ref.HeadSHA = tip
		}
		ref.Label, ref.Title = "review: "+target, target+" vs "+ref.Against
	}
	return nil
}

// DefaultBranch finds the branch a merge request would target, locally: the
// remote's default (origin/HEAD) when known, else the first of main, master,
// develop (local, then origin/). "" when none exists.
func DefaultBranch(repo string) string {
	if out, err := git(repo, "symbolic-ref", "--short", "refs/remotes/origin/HEAD"); err == nil && out != "" {
		if _, err := git(repo, "rev-parse", "--verify", "--quiet", out+"^{commit}"); err == nil {
			return out
		}
	}
	for _, name := range []string{"main", "master", "develop", "origin/main", "origin/master", "origin/develop"} {
		if _, err := git(repo, "rev-parse", "--verify", "--quiet", "refs/heads/"+name+"^{commit}"); err == nil {
			return name
		}
		if strings.HasPrefix(name, "origin/") {
			if _, err := git(repo, "rev-parse", "--verify", "--quiet", "refs/remotes/"+name+"^{commit}"); err == nil {
				return name
			}
		}
	}
	return ""
}

// lastTag returns the most recent tag reachable from HEAD, stepping back one
// when HEAD sits exactly on it (a comparison against itself shows nothing).
func lastTag(repo string) (string, error) {
	tag, err := git(repo, "describe", "--tags", "--abbrev=0", "HEAD")
	if err != nil || tag == "" {
		return "", ErrNoTag
	}
	tagSHA, _ := git(repo, "rev-list", "-n1", tag)
	headSHA, _ := git(repo, "rev-parse", "HEAD")
	if tagSHA != "" && tagSHA == headSHA {
		prev, err := git(repo, "describe", "--tags", "--abbrev=0", tag+"^")
		if err != nil || prev == "" {
			return "", ErrNoTag
		}
		return prev, nil
	}
	return tag, nil
}

// durationBack returns the cutoff time and a human label for "n units ago".
func durationBack(now time.Time, n int, unit string) (time.Time, string) {
	plural := func(word string) string {
		if n == 1 {
			return fmt.Sprintf("%d %s", n, word)
		}
		return fmt.Sprintf("%d %ss", n, word)
	}
	switch unit[0] {
	case 'd':
		return now.AddDate(0, 0, -n), plural("day")
	case 'w':
		return now.AddDate(0, 0, -7*n), plural("week")
	case 'y':
		return now.AddDate(-n, 0, 0), plural("year")
	default: // m, mo, month(s)
		return now.AddDate(0, -n, 0), plural("month")
	}
}

// Extract writes the tree of sha (limited to sub, "" = whole repo) into a fresh
// temp directory via `git archive` — no worktree metadata is added to the repo
// and the checkout has no .git, so the analysis pipeline sees a plain tree.
// It returns the directory to scan (tmp/<sub>) and a cleanup func.
func Extract(repo, sha, sub string) (dir string, cleanup func(), err error) {
	tmp, err := os.MkdirTemp("", "archscope-evo-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(tmp) }

	args := []string{"-C", repo, "archive", "--format=tar", sha}
	if sub != "" {
		args = append(args, "--", sub)
	}
	cmd := exec.Command("git", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cleanup()
		return "", nil, err
	}
	if err := cmd.Start(); err != nil {
		cleanup()
		return "", nil, err
	}
	extractErr := untar(stdout, tmp)
	if _, derr := io.Copy(io.Discard, stdout); derr != nil && extractErr == nil {
		extractErr = derr
	}
	if werr := cmd.Wait(); werr != nil {
		cleanup()
		return "", nil, fmt.Errorf("git archive %s: %w: %s", sha, werr, strings.TrimSpace(stderr.String()))
	}
	if extractErr != nil {
		cleanup()
		return "", nil, extractErr
	}
	dir = tmp
	if sub != "" {
		dir = filepath.Join(tmp, filepath.FromSlash(sub))
	}
	return dir, cleanup, nil
}

// untar extracts regular files and directories from a tar stream into dst,
// refusing any path that would escape it. Symlinks and special files are skipped
// — the analysis only reads source text.
func untar(r io.Reader, dst string) error {
	tr := tar.NewReader(r)
	root := filepath.Clean(dst) + string(os.PathSeparator)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dst, filepath.FromSlash(h.Name))
		if !strings.HasPrefix(target+string(os.PathSeparator), root) {
			continue // zip-slip guard
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
	}
}
