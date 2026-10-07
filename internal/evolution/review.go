package evolution

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
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
	Provider string // "gitlab" | "github": which host's links the report builds
}

// mrRefRe matches GitLab's refs/merge-requests/N/head and GitHub's
// refs/pull/N/head (also the common fetch mappings refs/remotes/origin/pull/N,
// refs/remotes/origin/pr/N), local or remote-tracking.
var mrRefRe = regexp.MustCompile(`refs/(?:remotes/[^/]+/)?(?:merge-requests|pull|pr)/(\d+)(?:/head)?$`)

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
	out, err := exec.CommandContext(ctx, "git", "-C", repo, "ls-remote", "origin", "refs/merge-requests/*/head", "refs/pull/*/head").Output()
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

// FileHash256 is GitHub's diff anchor for a file ("diff-" + this): the SHA-256 of its path.
func FileHash256(p string) string {
	sum := sha256.Sum256([]byte(p))
	return hex.EncodeToString(sum[:])
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
	r.Provider = DetectProvider(repo, r.Host)
	return r
}

// DetectProvider says whether the remote is GitHub or GitLab. A github.com /
// github.* host is GitHub, gitlab.* is GitLab; for a self-hosted host with
// neither in its name the pull-request refs the repository already holds decide
// (refs/pull or refs/pr → GitHub), and GitLab is the default.
func DetectProvider(repo, host string) string {
	h := strings.ToLower(host)
	switch {
	case strings.Contains(h, "github"):
		return "github"
	case strings.Contains(h, "gitlab"):
		return "gitlab"
	}
	if out, err := git(repo, "for-each-ref", "--format=%(refname)"); err == nil {
		for _, ref := range strings.Split(out, "\n") {
			if strings.Contains(ref, "/pull/") || strings.Contains(ref, "/pr/") {
				return "github"
			}
			if strings.Contains(ref, "/merge-requests/") {
				return "gitlab"
			}
		}
	}
	return "gitlab"
}

// String is a one-line summary for progress output.
func (r Review) String() string {
	mr := "no merge request found"
	if r.Provider == "github" {
		mr = "no pull request found"
		if r.MRIID > 0 {
			mr = fmt.Sprintf("PR #%d (%s)", r.MRIID, r.MRSource)
		}
	} else if r.MRIID > 0 {
		mr = fmt.Sprintf("MR !%d (%s)", r.MRIID, r.MRSource)
	}
	return fmt.Sprintf("review vs %s — %s", r.Ref, mr)
}

// RenderReviewMarkdown is the "Changes" block of a review as Markdown, mirroring
// the HTML card: totals, then every file — those with issues first, each issue
// listed under it — and the clean ones marked ✓ OK.
func RenderReviewMarkdown(rv *Review) string {
	if rv == nil {
		return ""
	}
	bad := 0
	for _, f := range rv.Files {
		if !f.OK() {
			bad++
		}
	}
	var b strings.Builder
	noun := "files"
	if len(rv.Files) == 1 {
		noun = "file"
	}
	fmt.Fprintf(&b, "**Changes:** %d %s · +%s · −%s", len(rv.Files), noun, commaInt(rv.Adds), commaInt(rv.Dels))
	if len(rv.Files) > 0 {
		if bad == 0 {
			b.WriteString(" · ✓ all files OK")
		} else {
			fmt.Fprintf(&b, " · ✓ %d OK · ⚠ %d with issues", len(rv.Files)-bad, bad)
		}
	}
	b.WriteString("\n\n")
	if len(rv.Files) == 0 {
		b.WriteString("_No changed files between the merge-base and the reviewed branch._\n\n")
		return b.String()
	}
	files := append([]ReviewFile(nil), rv.Files...)
	sort.SliceStable(files, func(i, j int) bool { return len(files[i].Issues) > len(files[j].Issues) })
	for _, f := range files {
		stat := fmt.Sprintf("+%d −%d", f.Add, f.Del)
		if f.Binary {
			stat = "binary"
		}
		if f.OK() {
			fmt.Fprintf(&b, "- ✓ OK `%s` (%s)\n", f.Path, stat)
			continue
		}
		n := len(f.Issues)
		word := "issues"
		if n == 1 {
			word = "issue"
		}
		fmt.Fprintf(&b, "- ⚠ %d %s `%s` (%s)\n", n, word, f.Path, stat)
		shown := map[int]bool{} // one snippet per starting line, however many issues point at it
		for _, it := range f.Issues {
			fmt.Fprintf(&b, "  - %s\n", itemMD(it))
			if shown[it.Line] {
				continue
			}
			shown[it.Line] = true
			if snip := codeSnippet(rv, it); snip != "" {
				for _, l := range strings.Split(strings.TrimRight(snip, "\n"), "\n") {
					b.WriteString("    " + l + "\n")
				}
			}
		}
	}
	b.WriteString("\n")
	return b.String()
}

// commaInt formats 2556 as "2,556".
func commaInt(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

const (
	snippetMaxFunc = 50 // longest function body quoted
	snippetBefore  = 3  // context lines above a statement-level issue
	snippetAfter   = 3  // …and below
)

var funcHeadRe = regexp.MustCompile(`^\s*(?:(?:export|public|private|protected|internal|static|async|suspend|override|open|final|pub)\s+)*(?:func|def|fn|fun|function|class|struct|interface|impl)\b|^\s*(?:public|private|protected|static|final|abstract|synchronized)\b.*\)\s*(?:throws[^{]*)?\{\s*$|^\s*(?:const|let|var)\s+\w+\s*(?::[^=]+)?=\s*(?:async\s*)?\(.*\)\s*(?::[^=]+)?=>`)

// codeSnippet quotes the code around an issue, as a fenced block with line
// numbers and a → marker on the flagged line: the whole function (up to
// snippetMaxFunc lines) when the issue is on a declaration, otherwise the line
// with a few lines of context on either side. The text comes from the reviewed
// commit when the branch under review isn't checked out, else from disk.
func codeSnippet(rv *Review, it Item) string {
	if it.Line <= 0 || (it.RepoPath == "" && it.Path == "") {
		return ""
	}
	lines := sourceLines(rv, it)
	if it.Line > len(lines) {
		return ""
	}
	start, end := it.Line-1, it.Line-1
	isDecl := funcHeadRe.MatchString(lines[start])
	if isDecl {
		end = blockEnd(lines, start, it.Path)
		if end-start+1 > snippetMaxFunc {
			end = start + snippetMaxFunc - 1
		}
	} else {
		start = max(0, start-snippetBefore)
		end = min(len(lines)-1, end+snippetAfter)
	}
	var b strings.Builder
	b.WriteString("```" + fenceLang(it.RepoPath) + "\n")
	w := len(strconv.Itoa(end + 1))
	for i := start; i <= end; i++ {
		mark := " "
		if i == it.Line-1 {
			mark = "→"
		}
		fmt.Fprintf(&b, "%s %*d │ %s\n", mark, w, i+1, strings.TrimRight(lines[i], " \t\r"))
	}
	if cut := blockEnd(lines, it.Line-1, it.Path); isDecl && cut > end {
		b.WriteString("  … (function continues)\n")
	}
	b.WriteString("```\n")
	return b.String()
}

// sourceLines reads the issue's file at the reviewed side.
func sourceLines(rv *Review, it Item) []string {
	var data string
	if rv != nil && rv.Subject != "" && rv.HeadSHA != "" && it.RepoPath != "" && it.Path != "" && strings.HasSuffix(filepath.ToSlash(it.Path), it.RepoPath) {
		repo := strings.TrimSuffix(filepath.ToSlash(it.Path), it.RepoPath)
		if out, err := git(filepath.FromSlash(strings.TrimSuffix(repo, "/")), "show", rv.HeadSHA+":"+it.RepoPath); err == nil {
			data = out
		}
	}
	if data == "" {
		raw, err := os.ReadFile(it.Path)
		if err != nil {
			return nil
		}
		data = string(raw)
	}
	return strings.Split(data, "\n")
}

// blockEnd is the last line of the block starting at lines[start]: brace-matched,
// or indentation-delimited for Python.
func blockEnd(lines []string, start int, path string) int {
	if strings.HasSuffix(path, ".py") || strings.HasSuffix(path, ".pyi") {
		base := len(lines[start]) - len(strings.TrimLeft(lines[start], " \t"))
		last := start
		for j := start + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == "" {
				continue
			}
			if len(lines[j])-len(strings.TrimLeft(lines[j], " \t")) <= base {
				break
			}
			last = j
		}
		return last
	}
	depth, started := 0, false
	for j := start; j < len(lines) && j < start+400; j++ {
		for _, c := range lines[j] {
			switch c {
			case '{':
				depth++
				started = true
			case '}':
				depth--
			}
		}
		if started && depth <= 0 {
			return j
		}
		if !started && j > start+25 { // a multi-line parameter list can push the body brace down
			break // no body brace nearby: treat as a one-liner
		}
	}
	return start
}

func fenceLang(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return "go"
	case ".py", ".pyi":
		return "python"
	case ".ts", ".tsx":
		return "ts"
	case ".js", ".jsx", ".mjs", ".cjs":
		return "js"
	case ".java":
		return "java"
	case ".kt", ".kts":
		return "kotlin"
	case ".swift":
		return "swift"
	case ".rs":
		return "rust"
	case ".c", ".h":
		return "c"
	case ".cpp", ".cc", ".hpp":
		return "cpp"
	case ".cs":
		return "csharp"
	}
	return ""
}
