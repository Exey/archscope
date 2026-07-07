// Package universal holds security rules that apply to every language. These
// are the cross-language primitives the design calls for (requirement #2): a
// single implementation reused regardless of source language. Importing this
// package registers its rules into security.Default via init().
package universal

import (
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/security"
)

// keywordAssignment matches `password|secret|apiKey|token|… = "…8+ chars…"`.
//
// The leading/trailing \b word boundaries are deliberate: without them a field
// like `linkToken` or `refreshTokenStore` would trigger on the bare keyword
// "token". This was the dominant false-positive class observed in real repos.
// Both `=` and `:` separators are accepted (covers Go/Swift/TS `=` and
// YAML/JSON/Python-dict `:`).
var keywordAssignment = regexp.MustCompile(
	`(?i)\b(password|passwd|secret|api[_-]?key|auth[_-]?key|access[_-]?token|token|` +
		`private[_-]?key|client[_-]?secret|app[_-]?secret)\b\s*[:=]\s*["']([^"']{8,})["']`,
)

// hexBlob matches 32+ consecutive hex characters assigned to a string — an
// MD5/SHA-1/SHA-256 digest or raw key material that no human types by hand.
var hexBlob = regexp.MustCompile(`[:=]\s*["']([0-9a-fA-F]{32,})["']`)

// jwtLiteral matches a three-segment JWS/JWT (`eyJ…header.payload.signature`).
var jwtLiteral = regexp.MustCompile(
	`["'](eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,})["']`,
)

// knownPrefixSecret matches well-known service-specific secret formats where
// the prefix alone is a reliable indicator regardless of variable name context.
// Each alternative is anchored to its documented format so false positives are
// structurally impossible (AKIA is always 20 chars; ghp_ tokens are always 36).
var knownPrefixSecret = regexp.MustCompile(
	`["'](` +
		`AKIA[0-9A-Z]{16}` + // AWS access key ID
		`|ASIA[0-9A-Z]{16}` + // AWS STS temporary key
		`|ghp_[A-Za-z0-9]{36}` + // GitHub personal access token
		`|gho_[A-Za-z0-9]{36}` + // GitHub OAuth token
		`|ghs_[A-Za-z0-9]{36}` + // GitHub server-to-server token
		`|github_pat_[A-Za-z0-9_]{59}` + // GitHub fine-grained PAT
		`|sk_live_[0-9a-zA-Z]{24,}` + // Stripe live secret key
		`|sk_test_[0-9a-zA-Z]{24,}` + // Stripe test secret key
		`|xoxb-[0-9]{11}-[0-9A-Za-z-]{24,}` + // Slack bot token
		`|xoxp-[0-9]+-[0-9]+-[0-9A-Za-z-]+` + // Slack user token
		`|AIza[0-9A-Za-z\-_]{35}` + // Google API key
		`)["']`,
)

// jsonKeyValue matches an all-lowercase snake_case literal *containing an
// underscore* — these are almost always JSON key names being mapped
// (`case accessToken = "access_token"`, `"token": "refresh_token"`), not real
// credentials. Requiring the underscore is deliberate: a bare lowercase value
// like "hunter2" or "abcdef0123456789" is far more likely an actual secret
// than a wire key, so it must NOT be skipped.
var jsonKeyValue = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)+$`)

// secretSkipWords are values that look like placeholders, not real secrets.
var secretSkipWords = []string{
	"example", "test", "dummy", "fake", "sample", "placeholder",
	"your_", "xxx", "todo", "changeme", "insert", "enter", "redacted",
	"null", "none", "undefined",
}

// privateKeyHeader matches PEM private-key headers committed into source.
var privateKeyHeader = regexp.MustCompile(
	`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`,
)

func init() {
	security.Default.RegisterRule(HardcodedSecrets())       // CWE-798 set inside
	security.Default.RegisterRule(PrivateKeyInSource())     // CWE-321 set inside
	security.Default.RegisterRule(SQLStringInterpolation()) // CWE-89 set inside
}

// HardcodedSecrets is the canonical universal rule: a credential assigned to a
// literal in source. Languages is empty, so it runs against every language.
//
// Three orthogonal detectors fire it: a keyword=literal assignment, a raw hex
// blob (digest / key material), or a JWT literal. A battery of false-positive
// guards (placeholder words, JSON key-name mapping, enum `case` lines, test
// paths) keeps the signal clean — this mirrors the corner-case hardening done
// in the upstream Swift analyzer, generalized to all languages.
func HardcodedSecrets() security.Rule {
	return security.Rule{
		ID:       "universal.hardcoded_secrets",
		CWE:      "798",
		Name:     "Hardcoded Secrets",
		Severity: security.SevHigh,
		Category: "insecure_data_storage",
		Description: "Credentials assigned to a literal in source — API keys, passwords, tokens, " +
			"or raw key material (hex digests, JWTs) — are committed to history permanently. Load " +
			"secrets from environment variables or a secret manager at runtime, and rotate any value " +
			"found here: consider it compromised.",
		Detect: detectHardcodedSecrets,
	}
}

func detectHardcodedSecrets(filePath string, lines []string) []security.Finding {
	if isLikelyTestPath(filePath) {
		return nil
	}
	var out []security.Finding
	for i, line := range lines {
		if security.IsComment(line) {
			continue
		}
		// Enum `case Name = "json_key"` lines map identifiers to wire keys; the
		// value is a JSON field name, not a secret.
		if strings.HasPrefix(strings.TrimSpace(line), "case ") {
			continue
		}

		// 1) keyword = "literal"
		if m := keywordAssignment.FindStringSubmatch(line); m != nil {
			val := m[2]
			low := strings.ToLower(val)
			isJSONKey := jsonKeyValue.MatchString(low) && len(val) <= 40
			if !isJSONKey && !containsAny(low, secretSkipWords) {
				out = append(out, security.NewFinding(filePath, i, lines))
				continue
			}
		}
		// 2) raw hex digest / key material
		if hexBlob.MatchString(line) && !containsAny(strings.ToLower(line), secretSkipWords) {
			out = append(out, security.NewFinding(filePath, i, lines))
			continue
		}
		// 3) JWT literal
		if jwtLiteral.MatchString(line) {
			out = append(out, security.NewFinding(filePath, i, lines))
			continue
		}
		// 4) known-prefix secrets (AWS, GitHub, Stripe, Slack, Google) — no
		// keyword context needed; the prefix format alone is definitive.
		if knownPrefixSecret.MatchString(line) {
			out = append(out, security.NewFinding(filePath, i, lines))
		}
	}
	return out
}

// PrivateKeyInSource flags a PEM private key embedded in a source/config file.
func PrivateKeyInSource() security.Rule {
	return security.Rule{
		ID:       "universal.private_key_in_source",
		CWE:      "321",
		Name:     "Private Key Committed to Source",
		Severity: security.SevHigh,
		Category: "cryptography",
		Description: "A PEM-encoded private key is embedded in the repository. Private keys must " +
			"never be committed; rotate the key immediately and load it at runtime from a secret " +
			"store or mounted secret.",
		Detect: func(filePath string, lines []string) []security.Finding {
			if security.IsTestPath(filePath) {
				return nil
			}
			var out []security.Finding
			for i, line := range lines {
				if privateKeyHeader.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// sqlInterp matches a SQL string built with interpolation. The verb list is
// intentionally restricted to DML/DDL commands — bare WHERE/FROM appear in log
// lines and error messages constantly and produced most of the noise upstream.
var sqlInterp = regexp.MustCompile(
	`(?i)\b(SELECT\s|INSERT\s+INTO|UPDATE\s|DELETE\s+FROM|DROP\s+TABLE|CREATE\s+TABLE|ALTER\s+TABLE)`,
)

// interpolationMarker matches the interpolation syntaxes of the supported
// languages: Swift `\(`, JS/TS template `${`, Python f-string `{` after f", and
// classic `%`/`+` concatenation is left out (too noisy).
var interpolationMarker = regexp.MustCompile(`\\\(|\$\{|f["'][^"']*\{`)

// SQLStringInterpolation flags a SQL query assembled via string interpolation,
// the classic injection vector. Universal: the interpolation syntaxes covered
// span Swift, JS/TS and Python.
func SQLStringInterpolation() security.Rule {
	return security.Rule{
		ID:       "universal.sql_string_interpolation",
		CWE:      "89",
		Name:     "Unsafe String Interpolation in SQL Queries",
		Severity: security.SevHigh,
		Category: "io_validation",
		Description: "Building SQL with string interpolation lets attacker-controlled input break " +
			"out of the query and execute arbitrary SQL. Use parameterized queries with bound " +
			"placeholders so values are never treated as executable SQL.",
		Detect: func(filePath string, lines []string) []security.Finding {
			if isLikelyTestPath(filePath) {
				return nil
			}
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if interpolationMarker.MatchString(line) && sqlInterp.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// isLikelyTestPath delegates to the canonical security.IsTestPath which covers
// all language test conventions (Go _test.go, Swift *Test.swift, JS *.spec.ts,
// Python test_*.py, plus test/mock/fixture/e2e directory components).
func isLikelyTestPath(filePath string) bool {
	return security.IsTestPath(filePath)
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
