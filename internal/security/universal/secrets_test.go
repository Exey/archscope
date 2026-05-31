package universal

import "testing"

// fire reports how many findings the hardcoded-secrets detector returns for a
// single line of the given pseudo-file.
func fire(path, line string) int {
	return len(detectHardcodedSecrets(path, []string{line}))
}

func TestSecretsTruePositives(t *testing.T) {
	cases := []struct {
		name, path, line string
	}{
		{"password", "a.py", `password = "hunter2hunter2"`},
		{"api key mixed", "a.swift", `let apiKey = "AIzaSyD-1234567890abcdef"`},
		{"ts secret", "a.ts", `const secret = "abcdef0123456789";`},
		{"hex digest", "a.go", `key := "0123456789abcdef0123456789abcdef"`},
		{"jwt", "a.js", `const t = "eyJhbGciOi.eyJzdWIiOi.SflKxwRJSM";`},
	}
	for _, c := range cases {
		if n := fire(c.path, c.line); n == 0 {
			t.Errorf("%s: expected a finding, got none (line: %s)", c.name, c.line)
		}
	}
}

func TestSecretsFalsePositiveGuards(t *testing.T) {
	cases := []struct {
		name, path, line string
	}{
		{"snake_case wire key", "a.swift", `case accessToken = "access_token"`},
		{"placeholder", "a.go", `token = "placeholder"`},
		{"example value", "a.py", `api_key = "your_api_key_here"`},
		{"word boundary linkToken", "a.ts", `const linkToken = computeLink();`},
		{"enum case json key", "a.swift", `case userName = "user_name"`},
		{"comment line", "a.go", `// password = "realvalue123"`},
	}
	for _, c := range cases {
		if n := fire(c.path, c.line); n != 0 {
			t.Errorf("%s: expected no finding, got %d (line: %s)", c.name, n, c.line)
		}
	}
}

func TestSecretsSkipsTestPaths(t *testing.T) {
	if n := fire("Tests/AuthTests.swift", `let apiKey = "AIzaSyD-1234567890abcdef"`); n != 0 {
		t.Errorf("expected secrets in test paths to be skipped, got %d", n)
	}
}

func TestPrivateKeyDetected(t *testing.T) {
	r := PrivateKeyInSource()
	got := r.Detect("config.go", []string{`pem := "-----BEGIN RSA PRIVATE KEY-----"`})
	if len(got) == 0 {
		t.Errorf("expected a private-key finding")
	}
}
