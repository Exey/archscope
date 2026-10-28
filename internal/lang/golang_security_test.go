package lang_test

import (
	"strings"
	"testing"
)

func goDetect(t *testing.T, id, src string) int {
	t.Helper()
	return len(javaRule(t, id).Detect("/app/x.go", strings.Split(src, "\n")))
}

func TestGoCommandInjection(t *testing.T) {
	for src, want := range map[string]int{
		`cmd := exec.Command("sh", "-c", "ls "+dir)`:                      1,
		`cmd := exec.Command("bash", "-c", fmt.Sprintf("rm -rf %s", p))`:  1,
		`cmd := exec.Command(fmt.Sprintf("/opt/%s/run", v))`:              1,
		`cmd := exec.CommandContext(ctx, "sh", "-c", "echo "+msg)`:        1,
		`cmd := exec.Command("git", "-C", repo, "show", rev+":"+path)`:    0, // fixed program, one built argument: no shell
		`cmd := exec.Command(bin, "--name="+name)`:                        0,
		`cmd := exec.CommandContext(ctx, "git", "log", "--since="+since)`: 0,
		`cmd := exec.Command("git", "status")`:                            0,
	} {
		if got := goDetect(t, "go.command_injection", src); got != want {
			t.Errorf("%s: got %d want %d", src, got, want)
		}
	}
}

func TestGoHTTPNoTLSIgnoresStrings(t *testing.T) {
	if goDetect(t, "go.http_server_no_tls", `log.Fatal(http.ListenAndServe(":80", mux))`) != 1 {
		t.Error("a real cleartext server should fire")
	}
	if goDetect(t, "go.http_server_no_tls", `if sfx, ok := substringAfter(ln, "http.ListenAndServe(", "http.ListenAndServeTLS("); ok {`) != 0 {
		t.Error("a detector that merely names the call is not a server")
	}
}

func TestGoTOCTOUNeedsTheSamePath(t *testing.T) {
	race := "func f(p string) {\n\tif _, err := os.Stat(p); os.IsNotExist(err) {\n\t\tos.Create(p)\n\t}\n}\n"
	if goDetect(t, "go.toctou", race) != 1 {
		t.Error("stat then create of the same path is the race")
	}
	readOnly := "func f(a, b string) bool {\n\t_, err := os.Stat(a)\n\treturn err == nil\n}\n\nfunc g(b string) {\n\tos.Create(b)\n}\n"
	if goDetect(t, "go.toctou", readOnly) != 0 {
		t.Error("a Stat that is only read, and an unrelated Create, are not a race")
	}
	idem := "func f(d string) {\n\tif _, err := os.Stat(d); err != nil {\n\t\tos.MkdirAll(d, 0o755)\n\t}\n}\n"
	if goDetect(t, "go.toctou", idem) != 0 {
		t.Error("MkdirAll is idempotent")
	}
}
