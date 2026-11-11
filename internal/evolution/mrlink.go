package evolution

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// MRLink is a merge / pull request named by its web address, so `--review` takes
// the link a colleague pasted instead of a copied branch name.
type MRLink struct {
	Host     string // https://gitlab.example.com
	Project  string // group/subgroup/project
	IID      int
	Provider string // "gitlab" | "github"
}

// gitlabMRRe: https://host/group/sub/proj/-/merge_requests/13 (and /diffs, ?tab=…), or the
// older form without the "/-/".
var gitlabMRRe = regexp.MustCompile(`^(https?://[^/]+)/(.+?)/(?:-/)?merge_requests/(\d+)(?:[/?#].*)?$`)

// githubPRRe: https://github.com/owner/repo/pull/7 (and /files, /commits).
var githubPRRe = regexp.MustCompile(`^(https?://[^/]+)/([^/]+/[^/]+)/pull/(\d+)(?:[/?#].*)?$`)

// ParseMRLink recognises a GitLab merge-request or GitHub pull-request address.
func ParseMRLink(s string) (MRLink, bool) {
	s = strings.TrimSpace(s)
	if m := gitlabMRRe.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[3])
		return MRLink{Host: m[1], Project: m[2], IID: n, Provider: "gitlab"}, true
	}
	if m := githubPRRe.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[3])
		return MRLink{Host: m[1], Project: m[2], IID: n, Provider: "github"}, true
	}
	return MRLink{}, false
}

// mrRef is the ref the host publishes for a request's head.
func (l MRLink) mrRef() (remote, local string) {
	if l.Provider == "github" {
		return fmt.Sprintf("refs/pull/%d/head", l.IID), fmt.Sprintf("refs/remotes/origin/pull/%d", l.IID)
	}
	return fmt.Sprintf("refs/merge-requests/%d/head", l.IID), fmt.Sprintf("refs/remotes/origin/merge-requests/%d", l.IID)
}

// MRInfo is what a link resolves to in the local repository.
type MRInfo struct {
	Ref    string // what to review: the source branch, or the fetched request ref
	Target string // the branch it goes into ("" = infer)
	Title  string
	Source string // the source branch ("" = unknown)
}

// apiClient is replaced in tests.
var apiClient = &http.Client{Timeout: 8 * time.Second}

// apiMR asks the host for the request's branches and title. Public projects answer
// anonymously; a private one needs GITLAB_TOKEN (GITLAB_PRIVATE_TOKEN, GL_TOKEN) or
// GITHUB_TOKEN (GH_TOKEN). Any failure just means "unknown" — the refs still work.
func apiMR(l MRLink) (source, target, title string) {
	var u string
	req := func() (*http.Request, error) {
		switch l.Provider {
		case "github":
			base := "https://api.github.com"
			if !strings.Contains(l.Host, "github.com") {
				base = l.Host + "/api/v3"
			}
			u = fmt.Sprintf("%s/repos/%s/pulls/%d", base, l.Project, l.IID)
		default:
			u = fmt.Sprintf("%s/api/v4/projects/%s/merge_requests/%d", l.Host, url.PathEscape(l.Project), l.IID)
		}
		r, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return nil, err
		}
		if l.Provider == "github" {
			if t := firstEnv("GITHUB_TOKEN", "GH_TOKEN"); t != "" {
				r.Header.Set("Authorization", "Bearer "+t)
			}
		} else if t := firstEnv("GITLAB_TOKEN", "GITLAB_PRIVATE_TOKEN", "GL_TOKEN"); t != "" {
			r.Header.Set("PRIVATE-TOKEN", t)
		}
		return r, nil
	}
	r, err := req()
	if err != nil {
		return
	}
	resp, err := apiClient.Do(r)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var body struct {
		Title        string `json:"title"`
		SourceBranch string `json:"source_branch"` // GitLab
		TargetBranch string `json:"target_branch"`
		Head         struct {
			Ref string `json:"ref"`
		} `json:"head"` // GitHub
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	}
	if json.NewDecoder(resp.Body).Decode(&body) != nil {
		return
	}
	if l.Provider == "github" {
		return body.Head.Ref, body.Base.Ref, body.Title
	}
	return body.SourceBranch, body.TargetBranch, body.Title
}

func firstEnv(names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return ""
}

// sameProject compares a link with origin's address, ignoring case and a trailing .git.
func sameProject(l MRLink, host, project string) bool {
	norm := func(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")) }
	return norm(l.Host) == norm(host) && norm(l.Project) == norm(project)
}

// ResolveMRLink makes the request reviewable in repo: it fetches origin (so the
// target branch is current) and the request's own head ref, and asks the host for
// the source and target branch. Progress goes to say.
func ResolveMRLink(repo string, l MRLink, say func(string)) (MRInfo, error) {
	if say == nil {
		say = func(string) {}
	}
	if host, project := RemoteHostProject(repo); host != "" && !sameProject(l, host, project) {
		return MRInfo{}, fmt.Errorf("the link is for %s/%s, but this repository's origin is %s/%s — point archscope at a clone of that project", l.Host, l.Project, host, project)
	}
	if _, err := gitTimeout(repo, 90*time.Second, "fetch", "--prune", "origin"); err != nil {
		say("git: fetch failed (" + shortErr(err) + ") — continuing with what is local")
	} else {
		say("git: fetched origin")
	}
	remoteRef, localRef := l.mrRef()
	if _, err := gitTimeout(repo, 90*time.Second, "fetch", "origin", "+"+remoteRef+":"+localRef); err != nil {
		return MRInfo{}, fmt.Errorf("could not fetch %s from origin (%s) — is the link for this repository, and does the request still exist?", remoteRef, shortErr(err))
	}
	head, err := git(repo, "rev-parse", localRef+"^{commit}")
	if err != nil || head == "" {
		return MRInfo{}, fmt.Errorf("%s fetched but does not resolve to a commit", localRef)
	}
	info := MRInfo{Ref: strings.TrimPrefix(localRef, "refs/remotes/")}
	source, target, title := apiMR(l)
	info.Title, info.Source, info.Target = title, source, target
	// Prefer the branch's own name when the remote branch is exactly the request's head.
	if source != "" {
		if tip, err := git(repo, "rev-parse", "--verify", "--quiet", "refs/remotes/origin/"+source+"^{commit}"); err == nil && tip == head {
			info.Ref = "origin/" + source
		}
	}
	word := "MR !"
	if l.Provider == "github" {
		word = "PR #"
	}
	desc := fmt.Sprintf("%s%d", word, l.IID)
	if title != "" {
		desc += " “" + title + "”"
	}
	switch {
	case source != "" && target != "":
		desc += fmt.Sprintf(": %s → %s", source, target)
	case target == "":
		desc += " (target branch unknown — inferred from history)"
	}
	say("link: " + desc)
	return info, nil
}
