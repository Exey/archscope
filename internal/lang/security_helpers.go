package lang

import (
	"math"
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/security"
	_ "github.com/exey/archscope/internal/security/universal" // register CWE-798/321/89 universal rules
)

// reRule builds a security.Rule whose Detect flags every non-comment line that
// matches re. If any skip substring (matched case-insensitively) is present on
// the line, that line is ignored — a cheap, shared false-positive guard. This
// is the common constructor behind the language-specific rule files, keeping
// each rule a single declarative entry.
func reRule(id, name, category string, sev security.Severity, langs []string, re *regexp.Regexp, desc string, skip ...string) security.Rule {
	return security.Rule{
		ID:          id,
		Name:        name,
		Severity:    sev,
		Category:    category,
		Languages:   langs,
		Description: desc,
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				stripped := security.StripStringsAndComments(line)
				if !re.MatchString(stripped) {
					continue
				}
				if len(skip) > 0 {
					low := strings.ToLower(stripped)
					skipped := false
					for _, s := range skip {
						if strings.Contains(low, s) {
							skipped = true
							break
						}
					}
					if skipped {
						continue
					}
				}
				out = append(out, security.NewFinding(filePath, i, lines))
			}
			return out
		},
	}
}

// twoReRule builds a Rule that fires when must AND also both match the same
// non-comment line. This is the standard "sink + source" two-pattern check used
// for injection/traversal/SSRF rules where caller and argument appear inline.
func twoReRule(id, name, category string, sev security.Severity, langs []string, must, also *regexp.Regexp, desc string) security.Rule {
	return security.Rule{
		ID:          id,
		Name:        name,
		Severity:    sev,
		Category:    category,
		Languages:   langs,
		Description: desc,
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				stripped := security.StripStringsAndComments(line)
				if must.MatchString(stripped) && also.MatchString(stripped) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// reSensitiveData matches variable/key names that suggest security-sensitive
// values — reused across logging, storage, and SSRF rules.
var reSensitiveData = regexp.MustCompile(
	`(?i)\b(password|passwd|passphrase|psk|secret|secretkey|api[_-]?key|apikey|token|credential|private[_-]?key|privkey|auth|nonce|salt)\b`,
)

// insecureURLSkips are hosts that legitimately appear behind http:// (loopback,
// XML namespaces, doc placeholders) and must not trip transport rules.
var insecureURLSkips = []string{
	"localhost", "127.0.0.1", "0.0.0.0", "w3.org", "schemas.",
	"example.com", "example.org", "xmlns",
}

// reCredAssign matches a credential-naming identifier assigned to a string
// literal of ≥ 6 chars. Group 1 = keyword (password, api_key, …);
// group 2 = the literal value — used by credentialRule for entropy gating.
var reCredAssign = regexp.MustCompile(
	`(?i)\b(password|passwd|secret|api[_-]?key|api_token|access[_-]?token|` +
		`private[_-]?key|client[_-]?secret|db[_-]?pass(?:word)?|access[_-]?key|` +
		`auth[_-]?token)\b\s*(?::=|=|:)\s*["']([^"']{6,})["']`,
)

// credAssignSkips suppresses env-var lookups and config-reference patterns
// that appear in the assignment line but indicate the value is not a literal
// secret. Low-entropy placeholders ("changeme", "example" …) are caught by
// credentialEntropy instead and do not need explicit entries here.
var credAssignSkips = []string{
	"getenv", "environ", "process.env", "config.", "os.env",
	"viper.", "settings.", "${", "{{", "managed",
}

// reDottedPathValue matches a value shaped like a dotted reference/config path
// (`instanceRoles.resource.apiKey`, `$credentials.apiKey`) rather than a
// literal secret — real secrets are opaque random strings, not chains of
// identifier segments joined by dots.
var reDottedPathValue = regexp.MustCompile(`^\$?[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$`)

// reEnumMemberLine matches a bare enum-member assignment — just
// `Name = "value",` with nothing else on the line, comma required — the
// TS/JS shape of the `case Name = "value"` mapping Swift/Kotlin use. The
// trailing comma distinguishes it from an ordinary `keyword = "literal"`
// assignment, which never ends in a comma.
var reEnumMemberLine = regexp.MustCompile(`^[A-Za-z_]\w*\s*=\s*['"][^'"]*['"],$`)

// reStringConcat matches a quoted literal immediately followed by string
// concatenation (`'foo=' + x`) — the literal is a fragment of a larger
// runtime-built string, not a complete secret in itself.
var reStringConcat = regexp.MustCompile(`["']\s*\+`)

// reMaskedValue matches a run of masking characters (•, *, #, x) — a UI
// redaction placeholder like '••••••••••••3f9a', not a real secret.
var reMaskedValue = regexp.MustCompile(`[•*#x]{4,}`)

// credentialEntropy computes the Shannon entropy (bits per symbol) of s.
// Real secrets produced by a CSPRNG typically score ≥ 3.5; human-readable
// words, JSON/YAML keys, and short placeholders score < 3.2.
func credentialEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int, len(s))
	for _, c := range s {
		freq[c]++
	}
	n := float64(len(s))
	var h float64
	for _, cnt := range freq {
		p := float64(cnt) / n
		h -= p * math.Log2(p)
	}
	return h
}

// isCredentialTestPath delegates to the canonical security.IsTestPath (all
// language test conventions, plus test/mock/fixture/e2e directory components)
// and security.IsCredentialDataPath (credential-schema/seed-data files).
func isCredentialTestPath(filePath string) bool {
	return security.IsTestPath(filePath) || security.IsCredentialDataPath(filePath)
}

// credentialRule returns a CWE-798 rule for the given language set with
// four-layer false-positive suppression:
//  1. Test/fixture/mock path skipping (whole file).
//  2. Serialisation-key pattern: lines starting with "case " (Swift CodingKeys,
//     Kotlin sealed classes) are skipped because the literal is a wire-key, not a value.
//  3. Entropy gate: literals scoring < 3.2 bits/char (dictionary words, short
//     placeholders, JSON keys like "access_token") are discarded.
//  4. credAssignSkips allowlist: env-var and config-reference patterns.
func credentialRule(id string, langs []string, desc string) security.Rule {
	return security.Rule{
		ID:          id,
		Name:        "Hardcoded Credential",
		Severity:    security.SevHigh,
		Category:    "insecure_data_storage",
		CWE:         "798",
		Languages:   langs,
		Description: desc,
		Detect: func(filePath string, lines []string) []security.Finding {
			if isCredentialTestPath(filePath) {
				return nil
			}
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "case ") || reEnumMemberLine.MatchString(trimmed) {
					continue
				}
				if reStringConcat.MatchString(line) {
					continue
				}
				m := reCredAssign.FindStringSubmatch(line)
				if m == nil {
					continue
				}
				if reDottedPathValue.MatchString(m[2]) || reMaskedValue.MatchString(m[2]) || strings.Contains(m[2], " ") {
					continue
				}
				if credentialEntropy(m[2]) < 3.2 {
					continue
				}
				low := strings.ToLower(line)
				skipped := false
				for _, s := range credAssignSkips {
					if strings.Contains(low, s) {
						skipped = true
						break
					}
				}
				if !skipped {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}
