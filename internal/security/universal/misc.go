package universal

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/security"
)

func init() {
	security.Default.RegisterRule(UniversalReDOS())
	security.Default.RegisterRule(DotEnvCredentials())
}

// reAnyRegexCompile matches regex compilation calls across Go, Python, JS/TS,
// Kotlin/Java and Swift — used to gate the ReDoS line check.
var reAnyRegexCompile = regexp.MustCompile(
	`\bregexp\.(MustCompile|Compile)\s*\(` + // Go
		`|\bre\.(compile|match|search|fullmatch)\s*\(` + // Python
		`|\bnew\s+RegExp\s*\(` + // JS/TS
		`|\bRegex\s*\(` + // Kotlin/Swift
		`|\bPattern\.compile\s*\(` + // Java/Kotlin
		`|\.toRegex\s*\(`, // Kotlin extension
)

// reReDOSPattern matches nested quantifiers that cause catastrophic backtracking:
//   - (X+)+ / (X*)+ / (X+)* — the inner group contains a quantifier
//   - (X|Y+)+ / (X+|Y)+ — alternation inside a repeated group with a quantifier
var reReDOSPattern = regexp.MustCompile(
	`\([^()\n]{1,60}[+*][^()\n]{0,20}\)[+*]` +
		`|\([^()\n]{0,30}\|[^()\n]{0,30}[+*][^()\n]{0,10}\)[+*]`,
)

// UniversalReDOS detects catastrophic-backtracking (ReDoS) regex patterns
// passed to compile/match functions across all supported languages. Uses a
// two-stage check: the stripped line must contain a regex compilation call
// (to exclude comments and string-definition contexts), then the original
// line is checked for dangerous nested quantifiers inside the string literal.
func UniversalReDOS() security.Rule {
	return security.Rule{
		ID:       "universal.redos",
		CWE:      "1333",
		Name:     "Regular Expression DoS (ReDoS)",
		Severity: security.SevMedium,
		Category: "crash_factors",
		Description: "A regex compilation or match call contains a pattern with nested quantifiers " +
			"(e.g. (a+)+, (\\w+\\d+)+) that cause catastrophic backtracking. An attacker who " +
			"controls input matched against this regex can force exponential backtracking and " +
			"hang the process. Rewrite with possessive quantifiers, atomic groups, or an RE2-safe " +
			"equivalent pattern.",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				stripped := security.StripStringsAndComments(line)
				if !reAnyRegexCompile.MatchString(stripped) {
					continue
				}
				// Check dangerous pattern on the ORIGINAL line to look inside string literals.
				if reReDOSPattern.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// reEnvCredential matches credential assignments in .env files:
// KEY=value where KEY suggests sensitive material.
var reEnvCredential = regexp.MustCompile(
	`(?i)^[ \t]*(PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|TOKEN|PRIVATE_KEY|DB_PASS(?:WORD)?|` +
		`ACCESS_KEY|AUTH_TOKEN|CLIENT_SECRET|APP_SECRET|ENCRYPTION_KEY|HMAC_KEY|` +
		`JWT_SECRET|SIGNING_KEY|MASTER_KEY|PSK)\s*=\s*(.+)`,
)

// envSkipValues are clearly non-secret .env values (env-var references, placeholders).
var envSkipValues = []string{
	"${", "$(", "%{", "changeme", "your_", "xxx", "placeholder",
	"example", "test", "dummy", "todo", "insert", "redacted",
	"<", ">", "null", "none", "undefined",
}

// dotEnvNames are the filenames we scan for committed credentials.
var dotEnvNames = map[string]bool{
	".env": true, ".env.local": true, ".env.production": true,
	".env.staging": true, ".env.development": true,
}

// DotEnvCredentials is a ProjectDetect rule that walks the repository looking
// for committed .env files that contain credential assignments. Committing
// .env files to source control is a common cause of secret leakage.
func DotEnvCredentials() security.Rule {
	return security.Rule{
		ID:          "universal.dotenv_credentials",
		CWE:         "798",
		Name:        "Credentials in .env File",
		Severity:    security.SevHigh,
		Category:    "insecure_data_storage",
		ProjectOnly: true,
		Description: "A .env file committed to the repository contains a credential assignment " +
			"(PASSWORD=, SECRET=, API_KEY=, etc.). Committing .env files exposes secrets to " +
			"anyone with repository access. Add .env to .gitignore and load secrets from a " +
			"secret manager or CI/CD environment variables instead.",
		ProjectDetect: func(repoPath string) []security.Finding {
			var out []security.Finding
			_ = filepath.WalkDir(repoPath, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				// Skip vendor, node_modules, .git
				rel := filepath.ToSlash(strings.TrimPrefix(filepath.ToSlash(path), filepath.ToSlash(repoPath)+"/"))
				for _, skip := range []string{"vendor/", "node_modules/", ".git/"} {
					if strings.HasPrefix(rel, skip) {
						return nil
					}
				}
				if !dotEnvNames[filepath.Base(path)] {
					return nil
				}
				data, readErr := os.ReadFile(path)
				if readErr != nil {
					return nil
				}
				lines := strings.Split(string(data), "\n")
				for i, line := range lines {
					m := reEnvCredential.FindStringSubmatch(line)
					if m == nil {
						continue
					}
					val := strings.TrimSpace(m[2])
					if val == "" || containsAny(strings.ToLower(val), envSkipValues) {
						continue
					}
					out = append(out, security.Finding{
						File:     rel,
						FullPath: path,
						Line:     i + 1,
						Snippet:  security.Snippet(line),
					})
				}
				return nil
			})
			return out
		},
	}
}
