package evolution

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Review describes the merge request a --review run is about: where the project
// lives on GitLab, which MR (if one could be found) and what the diff is against.
type Review struct {
	Subject  string // the branch/commit under review ("" = the checked-out working tree)
	Against  string // what it is compared with: the target branch, or the branch you are on
	Files    []ReviewFile
	Adds     int    // total added lines across Files
	Dels     int    // total removed lines
	Ref      string // what the user passed to --review
	BaseSHA  string // merge-base the comparison starts from
	HeadSHA  string
	Branch   string // current branch ("" when detached)
	MRIID    int    // 0 = no merge request found
	Host     string // https://gitlab.example.com ("" = unknown)
	Project  string // group/subgroup/project
	MRSource string // "local refs" | "ls-remote" | ""
}

var mrRefRe = regexp.MustCompile(`refs/(?:remotes/[^/]+/)?merge-requests/(\d+)/head$`)

// mrHeads returns MR IID → head commit, from merge-request refs already in the
// repository (fetched with +refs/merge-requests/*:refs/remotes/origin/merge-requests/*),
// falling back to asking the remote — what `git ls-remote origin | grep
// merge-requests` shows. source says which one answered.
func mrHeads(repo string) (heads map[int]string, source string) {
	heads = map[int]string{}
	if out, err := git(repo, "for-each-ref", "--format=%(objectname) %(refname)"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			sha, ref, ok := strings.Cut(strings.TrimSpace(line), " ")
			if m := mrRefRe.FindStringSubmatch(ref); ok && m != nil {
				n, _ := strconv.Atoi(m[1])
				heads[n] = sha
			}
		}
	}
	if len(heads) > 0 {
		return heads, "local refs"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "-C", repo, "ls-remote", "origin", "refs/merge-requests/*/head").Output()
	if err != nil {
		return heads, ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			if m := mrRefRe.FindStringSubmatch(f[1]); m != nil {
				n, _ := strconv.Atoi(m[1])
				heads[n] = f[0]
			}
		}
	}
	if len(heads) > 0 {
		return heads, "ls-remote"
	}
	return heads, ""
}

// DetectMR finds the merge request IID for the commits between base and head.
// An MR whose head is exactly head wins; otherwise the newest MR head that is
// contained in head and not already in base (the MR's commits are part of this
// range). 0 when none matches.
func DetectMR(repo, base, head string) (iid int, source string) {
	heads, source := mrHeads(repo)
	if len(heads) == 0 {
		return 0, ""
	}
	for n, sha := range heads {
		if sha == head {
			return n, source
		}
	}
	isAncestor := func(a, b string) bool {
		return exec.Command("git", "-C", repo, "merge-base", "--is-ancestor", a, b).Run() == nil
	}
	type cand struct {
		iid  int
		when int64
	}
	var cands []cand
	for n, sha := range heads {
		if !isAncestor(sha, head) || isAncestor(sha, base) {
			continue
		}
		ts, _ := git(repo, "show", "-s", "--format=%ct", sha)
		w, _ := strconv.ParseInt(ts, 10, 64)
		cands = append(cands, cand{n, w})
	}
	if len(cands) == 0 {
		return 0, ""
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].when != cands[j].when {
			return cands[i].when > cands[j].when
		}
		return cands[i].iid > cands[j].iid
	})
	return cands[0].iid, source
}

var (
	scpRemoteRe = regexp.MustCompile(`^(?:[^@/]+@)?([^:/]+):(?:\d+/)?(.+?)(?:\.git)?/?$`)
	urlRemoteRe = regexp.MustCompile(`^(?:https?|ssh|git)://(?:[^@/]+@)?([^:/]+)(?::\d+)?/(.+?)(?:\.git)?/?$`)
)

// ParseRemote splits a git remote URL (https, ssh:// or scp-style) into the web
// host (https://host) and the project path (group/project).
func ParseRemote(url string) (host, project string) {
	url = strings.TrimSpace(url)
	if m := urlRemoteRe.FindStringSubmatch(url); m != nil {
		return "https://" + m[1], m[2]
	}
	if m := scpRemoteRe.FindStringSubmatch(url); m != nil && !strings.Contains(url, "://") {
		return "https://" + m[1], m[2]
	}
	return "", ""
}

// RemoteHostProject reads origin's (or the first remote's) URL.
func RemoteHostProject(repo string) (host, project string) {
	url, err := git(repo, "remote", "get-url", "origin")
	if err != nil || url == "" {
		names, _ := git(repo, "remote")
		first, _, _ := strings.Cut(names, "\n")
		if first == "" {
			return "", ""
		}
		if url, err = git(repo, "remote", "get-url", first); err != nil {
			return "", ""
		}
	}
	return ParseRemote(url)
}

// FileHash is GitLab's diff anchor for a file: the SHA-1 of its path.
func FileHash(p string) string {
	sum := sha1.Sum([]byte(p))
	return hex.EncodeToString(sum[:])
}

var hunkRe = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// NewToOld maps each added/changed line (new numbering) of repoPath in
// base..HEAD to GitLab's "old line" position for that row of the MR diff — the
// old-side counter at that point — so `#<filehash>_<old>_<new>` anchors work.
// Lines outside the diff are absent.
func NewToOld(repo, base, head, repoPath string) map[int]int {
	if head == "" {
		head = "HEAD"
	}
	out, err := git(repo, "diff", "-U0", "--no-color", base, head, "--", repoPath)
	if err != nil {
		return nil
	}
	m := map[int]int{}
	newFile := false // "--- /dev/null": every line is added and GitLab's old position is 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "--- ") {
			newFile = line == "--- /dev/null"
			continue
		}
		h := hunkRe.FindStringSubmatch(line)
		if h == nil {
			continue
		}
		oldStart, _ := strconv.Atoi(h[1])
		oldLen := 1
		if h[2] != "" {
			oldLen, _ = strconv.Atoi(h[2])
		}
		newStart, _ := strconv.Atoi(h[3])
		newLen := 1
		if h[4] != "" {
			newLen, _ = strconv.Atoi(h[4])
		}
		oldPos := oldStart + oldLen // after the removed lines
		switch {
		case newFile:
			oldPos = 0 // a new file has no old side: GitLab anchors are <hash>_0_<line>
		case oldLen == 0:
			oldPos = oldStart + 1 // pure insertion: git reports the line BEFORE it
		}
		for i := 0; i < newLen; i++ {
			m[newStart+i] = oldPos
		}
	}
	return m
}

// EnrichReview fills RepoPath and OldPos on the offenders of c's details so the
// report can offer an "MR with line" button for each. sub is the scan root's
// path inside the repository.
func EnrichReview(repo, sub, base, head string, c *Comparison) {
	cache := map[string]map[int]int{}
	fill := func(it *Item) {
		if it.Rel == "" {
			return
		}
		it.RepoPath = path.Join(sub, it.Rel)
		mp, ok := cache[it.RepoPath]
		if !ok {
			mp = NewToOld(repo, base, head, it.RepoPath)
			cache[it.RepoPath] = mp
		}
		if old, ok := mp[it.Line]; ok {
			it.OldPos = old
		} else {
			it.OldPos = -1 // not part of the diff: link to the file only
		}
	}
	for i := range c.Introduced {
		fill(&c.Introduced[i])
	}
	for i := range c.Grown {
		fill(&c.Grown[i].Item)
	}
	for _, list := range [][]Detail{c.WorseDetails, c.BetterDetails} {
		for di := range list {
			for i := range list[di].Added {
				fill(&list[di].Added[i])
			}
			for i := range list[di].Grew {
				fill(&list[di].Grew[i].Item)
			}
		}
	}
}

// ReviewFile is one changed file of the reviewed branch with its verdict.
type ReviewFile struct {
	Path     string
	Add, Del int
	Binary   bool
	Issues   []Item // offenders this change introduced or grew in the file
}

// OK reports whether the change introduced no tracked issue in the file.
func (f ReviewFile) OK() bool { return len(f.Issues) == 0 }

// ChangedFiles lists the files changed between base and head (head "" = the
// working tree) with their added/removed line counts, like `git diff --numstat`.
func ChangedFiles(repo, base, head string) []ReviewFile {
	args := []string{"diff", "--numstat", "--no-renames", base}
	if head != "" {
		args = append(args, head)
	}
	out, err := git(repo, args...)
	if err != nil || out == "" {
		return nil
	}
	var files []ReviewFile
	for _, line := range strings.Split(out, "\n") {
		f := strings.SplitN(line, "\t", 3)
		if len(f) != 3 {
			continue
		}
		rf := ReviewFile{Path: f[2]}
		if f[0] == "-" || f[1] == "-" {
			rf.Binary = true
		} else {
			rf.Add, _ = strconv.Atoi(f[0])
			rf.Del, _ = strconv.Atoi(f[1])
		}
		files = append(files, rf)
	}
	sort.SliceStable(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files
}

// AttachFiles lists the changed files of the review and marks each OK or with
// the issues c says it introduced there. Call after EnrichReview.
func (r *Review) AttachFiles(repo string, c Comparison) {
	r.Files = ChangedFiles(repo, r.BaseSHA, r.diffHead())
	byFile := map[string][]Item{}
	for _, it := range c.Introduced {
		byFile[it.RepoPath] = append(byFile[it.RepoPath], it)
	}
	for _, g := range c.Grown {
		byFile[g.Item.RepoPath] = append(byFile[g.Item.RepoPath], g.Item)
	}
	for i := range r.Files {
		r.Files[i].Issues = byFile[r.Files[i].Path]
		r.Adds += r.Files[i].Add
		r.Dels += r.Files[i].Del
	}
}

// diffHead is the right-hand side for git diff: the reviewed tip, or "" for the working tree.
func (r Review) diffHead() string {
	if r.Subject == "" {
		return ""
	}
	return r.HeadSHA
}

// ReviewInfo gathers the repo-level facts for a review run.
func ReviewInfo(repo, ref string, base Ref) Review {
	r := Review{Ref: ref, BaseSHA: base.SHA, Against: base.Against}
	if base.HeadSHA != "" {
		r.HeadSHA = base.HeadSHA
		r.Subject = base.Target
		r.Branch = base.Target
	} else {
		r.HeadSHA, _ = git(repo, "rev-parse", "HEAD")
		if b, err := git(repo, "rev-parse", "--abbrev-ref", "HEAD"); err == nil && b != "HEAD" {
			r.Branch = b
		}
		r.Against = base.Target
	}
	r.Host, r.Project = RemoteHostProject(repo)
	r.MRIID, r.MRSource = DetectMR(repo, base.SHA, r.HeadSHA)
	return r
}

// String is a one-line summary for progress output.
func (r Review) String() string {
	mr := "no merge request found"
	if r.MRIID > 0 {
		mr = fmt.Sprintf("MR !%d (%s)", r.MRIID, r.MRSource)
	}
	return fmt.Sprintf("review vs %s — %s", r.Ref, mr)
}
