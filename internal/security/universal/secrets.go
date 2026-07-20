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
	"null", "none", "undefined", "{{", "managed",
}

// reDottedPathValue matches a value shaped like a dotted reference/config path
// (`instanceRoles.resource.apiKey`) rather than a literal secret — real
// secrets are opaque random strings, not chains of identifier segments joined
// by dots.
var reDottedPathValue = regexp.MustCompile(`^\$?[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$`)

// reEnumMemberLine matches a bare enum-member assignment — just
// `Name = "value",` with nothing else on the line, comma required. This is
// the TS/JS shape of the `case Name = "value"` mapping Swift/Kotlin use; the
// trailing comma is what distinguishes it from an ordinary top-level
// `keyword = "literal"` assignment (which never ends in a comma).
var reEnumMemberLine = regexp.MustCompile(`^[A-Za-z_]\w*\s*=\s*['"][^'"]*['"],$`)

// reStringConcat matches a quoted literal immediately followed by string
// concatenation (`'foo=' + x`) — the literal is a fragment of a larger
// runtime-built string, not a complete secret in itself.
var reStringConcat = regexp.MustCompile(`["']\s*\+`)

// reMaskedValue matches a run of masking characters (•, *, #, x) — a UI
// redaction placeholder like '••••••••••••3f9a', not a real secret.
var reMaskedValue = regexp.MustCompile(`[•*#x]{4,}`)

// reCamelPhrase matches a value built entirely from letters and shaped like
// concatenated English words (camelCase transitions) — e.g.
// "accessTokenRefreshed" returned by a dummy/mock auth stub describing what
// it did, not a real secret. Genuine secrets are virtually always
// random-looking (mixed alphanumeric, base64, hex) for entropy; a pure-letter
// multi-word phrase is a template/placeholder tell.
var reCamelPhrase = regexp.MustCompile(`^[a-z]+(?:[A-Z][a-z]+)+$`)

// isLowDiversity reports whether s uses too few distinct characters to be
// real key material — a genuine hash/key drawn from 16 hex symbols uses many
// of them; a placeholder like "000...0" or "fff...f" uses one or two.
func isLowDiversity(s string) bool {
	seen := make(map[rune]bool, len(s))
	for _, c := range s {
		seen[c] = true
	}
	return len(seen) < 4
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
		trimmed := strings.TrimSpace(line)
		// Enum `case Name = "json_key"` (Swift/Kotlin) and bare `Name =
		// "value",` (TS/JS) lines map identifiers to wire keys or other enum
		// values; the literal is a name, not a secret.
		if strings.HasPrefix(trimmed, "case ") || reEnumMemberLine.MatchString(trimmed) {
			continue
		}
		// A literal immediately followed by string concatenation (`'prefix=' +
		// realValue`) is a fragment being built at runtime, not the complete
		// secret — the actual value lives in whatever it's concatenated with.
		if reStringConcat.MatchString(line) {
			continue
		}

		// 1) keyword = "literal"
		if m := keywordAssignment.FindStringSubmatch(line); m != nil {
			val := m[2]
			low := strings.ToLower(val)
			isJSONKey := jsonKeyValue.MatchString(low) && len(val) <= 40
			isPlaceholder := reDottedPathValue.MatchString(val) || reMaskedValue.MatchString(val) ||
				strings.Contains(val, " ") || containsAny(low, secretSkipWords) || reCamelPhrase.MatchString(val)
			if !isJSONKey && !isPlaceholder {
				out = append(out, security.NewFinding(filePath, i, lines))
				continue
			}
		}
		// 2) raw hex digest / key material — a genuine digest/key drawn from 16
		// hex symbols uses many of them; a placeholder like "000...0" uses one,
		// so low character diversity rules it out.
		if m := hexBlob.FindStringSubmatch(line); m != nil &&
			!containsAny(strings.ToLower(line), secretSkipWords) && !isLowDiversity(m[1]) {
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

// isLikelyTestPath delegates to the canonical security.IsTestPath (all
// language test conventions, plus test/mock/fixture/e2e directory components)
// and security.IsCredentialDataPath (credential-schema/seed-data files).
func isLikelyTestPath(filePath string) bool {
	return security.IsTestPath(filePath) || security.IsCredentialDataPath(filePath)
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
