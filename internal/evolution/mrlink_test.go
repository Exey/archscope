package evolution

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseMRLink(t *testing.T) {
	cases := map[string]MRLink{
		"https://gitlab.pharm-sklad.ru/dev/partners/-/merge_requests/13":              {"https://gitlab.pharm-sklad.ru", "dev/partners", 13, "gitlab"},
		"https://gitlab.example.com/g/sub/proj/-/merge_requests/7/diffs?tab=1#note_3": {"https://gitlab.example.com", "g/sub/proj", 7, "gitlab"},
		"https://gitlab.example.com/g/proj/merge_requests/9":                          {"https://gitlab.example.com", "g/proj", 9, "gitlab"},
		"https://github.com/Exey/archscope/pull/42/files":                             {"https://github.com", "Exey/archscope", 42, "github"},
	}
	for in, want := range cases {
		got, ok := ParseMRLink(in)
		if !ok || got != want {
			t.Errorf("ParseMRLink(%q) = %+v %v, want %+v", in, got, ok, want)
		}
	}
	for _, in := range []string{"main", "PHARMZAKAZ-1180", "origin/feat/x", "https://example.com/some/page", "auto", ""} {
		if _, ok := ParseMRLink(in); ok {
			t.Errorf("%q is not a request link", in)
		}
	}
}

// origin publishes refs/merge-requests/13/head the way GitLab does; the clone has never seen it.
func TestResolveMRLinkFetchesRequestHead(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	base := t.TempDir()
	if r, err := filepath.EvalSymlinks(base); err == nil {
		base = r
	}
	run := func(dir string, args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	work := filepath.Join(base, "work")
	os.MkdirAll(work, 0o755)
	run(work, "init", "-q", "-b", "dev")
	os.WriteFile(filepath.Join(work, "a.txt"), []byte("1\n"), 0o644)
	run(work, "add", "-A")
	run(work, "commit", "-q", "-m", "base")
	run(work, "checkout", "-q", "-b", "feat/x")
	os.WriteFile(filepath.Join(work, "b.txt"), []byte("2\n"), 0o644)
	run(work, "add", "-A")
	run(work, "commit", "-q", "-m", "feature")
	head := run(work, "rev-parse", "HEAD")
	origin := filepath.Join(base, "origin.git")
	run(base, "clone", "-q", "--bare", work, origin)
	run(origin, "update-ref", "refs/merge-requests/13/head", head)
	clone := filepath.Join(base, "clone")
	run(base, "clone", "-q", origin, clone)
	run(clone, "checkout", "-q", "-B", "dev", "origin/dev") // you are on the target, not on the request

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/merge_requests/13") {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"title":"Add b","source_branch":"feat/x","target_branch":"dev"}`))
	}))
	defer srv.Close()
	link := MRLink{Host: srv.URL, Project: "g/p", IID: 13, Provider: "gitlab"}

	info, err := ResolveMRLink(clone, link, nil)
	if err != nil {
		t.Fatal(err)
	}
	if info.Ref != "origin/feat/x" || info.Target != "dev" || info.Title != "Add b" {
		t.Errorf("info = %+v", info)
	}
	if got := run(clone, "rev-parse", "refs/remotes/origin/merge-requests/13"); got != head {
		t.Errorf("request head not fetched: %s", got)
	}
	// and the whole review resolves against the target the host named
	ref, err := Resolve(clone, ReviewPrefix+info.Ref+"@@"+info.Target, time.Now())
	if err != nil || ref.Against == "" || ref.HeadSHA != head {
		t.Errorf("Resolve = %+v %v", ref, err)
	}

	// without the host's answer the request ref itself is reviewed and the target is inferred
	apiClient = &http.Client{}
	dead := MRLink{Host: "http://127.0.0.1:1", Project: "g/p", IID: 13, Provider: "gitlab"}
	info, err = ResolveMRLink(clone, dead, nil)
	if err != nil || info.Ref != "origin/merge-requests/13" || info.Target != "" {
		t.Errorf("no API: %+v %v", info, err)
	}
	if _, err := ResolveMRLink(clone, MRLink{Host: srv.URL, Project: "g/p", IID: 99, Provider: "gitlab"}, nil); err == nil {
		t.Error("a request origin does not publish must fail")
	}
}
