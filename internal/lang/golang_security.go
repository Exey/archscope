package lang

import (
	"regexp"

	"github.com/exey/archscope/internal/security"
)

// Go-only security rules: weak crypto imports/use, disabled TLS verification,
// command-injection-prone exec, SQL via fmt.Sprintf, and plaintext HTTP servers.
// Gated by Languages:["go"].
var goLangs = []string{"go"}

var (
	reGoWeakCrypto      = regexp.MustCompile(`"crypto/(md5|sha1|des|rc4)"|\b(md5|sha1)\.New\s*\(|\bdes\.NewCipher\s*\(`)
	reGoInsecureTLS     = regexp.MustCompile(`InsecureSkipVerify\s*:\s*true`)
	reGoCmdInjection    = regexp.MustCompile(`exec\.Command(Context)?\s*\(.*(fmt\.Sprintf|"\s*\+|\+\s*")`)
	reGoHTTPNoTLS       = regexp.MustCompile(`\bhttp\.ListenAndServe\s*\(`)
	reGoMathRand        = regexp.MustCompile(`"math/rand(/v[0-9]+)?"`)
	reGoTLSNoMinVersion = regexp.MustCompile(`tls\.Config\s*\{`)
	reGoTLSHasMinVer    = regexp.MustCompile(`MinVersion\s*:`)
	reGoCookieNoHTTP    = regexp.MustCompile(`http\.Cookie\s*\{`)
	reGoCookieHTTPOnly  = regexp.MustCompile(`HttpOnly\s*:\s*true`)
	// security-header rules — file-level helpers
	reGoGinRouter   = regexp.MustCompile(`\bgin\.(Default|New)\s*\(`)
	reGoGinSecMW    = regexp.MustCompile(`(?i)(ginhelmet|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security)`)
	reGoHTTPHdrSet  = regexp.MustCompile(`\.Header\(\)\.(Set|Add)\s*\(`)
	reGoHTTPSecHdr  = regexp.MustCompile(`Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security`)
	// two-part SQL rule helpers — used in goSQLFmtRule below
	reGoSQLFmt = regexp.MustCompile(`\bfmt\.(Sprintf|Printf|Fprintf)\s*\(`)
	reGoSQLKW  = regexp.MustCompile(`(?i)\b(SELECT\s|INSERT\s+INTO\s|UPDATE\s|DELETE\s+FROM\s|DROP\s+TABLE\s|ALTER\s+TABLE\s)`)
	// new coverage
	reGoFileSink    = regexp.MustCompile(`\b(os\.(Open|ReadFile|Remove|Stat|Create|OpenFile)|ioutil\.ReadFile|filepath\.Join)\s*\(`)
	reGoUserInput   = regexp.MustCompile(`r\.(URL\.Query|FormValue|PathValue|PostFormValue)\s*\(|c\.(Param|Query|PostForm|GetQuery)\s*\(`)
	reGoLogSink     = regexp.MustCompile(`\b(log\.(Print|Printf|Println|Fatal|Fatalf|Fatalln|Panic|Panicf)|fmt\.(Print|Printf|Println))\s*\(`)
	reGoGobDecoder  = regexp.MustCompile(`\bgob\.NewDecoder\s*\(`)
	reGoHTTPCallSink = regexp.MustCompile(`\bhttp\.(Get|Post|Head|NewRequest)\s*\(`)
	reGoCookieNoSec = regexp.MustCompile(`Secure\s*:\s*true`)
)

func init() {
	security.Default.RegisterRule(reRule(
		"go.weak_crypto", "Weak Cryptography", "cryptography", security.SevHigh, goLangs,
		reGoWeakCrypto,
		"crypto/md5, crypto/sha1, crypto/des and crypto/rc4 are broken or obsolete for security "+
			"use. Use crypto/sha256+ for hashing and crypto/aes with GCM for symmetric encryption.",
	).WithCWE("327"))
	security.Default.RegisterRule(reRule(
		"go.insecure_tls", "Disabled TLS Verification", "network_security", security.SevHigh, goLangs,
		reGoInsecureTLS,
		"InsecureSkipVerify: true disables certificate validation, defeating TLS and enabling "+
			"man-in-the-middle attacks. Verify certificates; pin or supply a proper RootCAs pool if needed.",
	).WithCWE("295"))
	security.Default.RegisterRule(reRule(
		"go.command_injection", "Command Injection Risk", "io_validation", security.SevMedium, goLangs,
		reGoCmdInjection,
		"Building an exec.Command argument by formatting or concatenating strings can let input "+
			"alter the command. Pass fixed args as separate parameters and never interpolate user input.",
	).WithCWE("78"))
	security.Default.RegisterRule(reRule(
		"go.http_server_no_tls", "HTTP Server Without TLS", "network_security", security.SevMedium, goLangs,
		reGoHTTPNoTLS,
		"http.ListenAndServe serves cleartext HTTP. Production servers should use "+
			"https.ListenAndServeTLS or terminate TLS at a reverse proxy — cleartext HTTP exposes "+
			"session tokens and payloads to interception.",
	).WithCWE("319"))
	security.Default.RegisterRule(goSQLFmtRule())
	security.Default.RegisterRule(reRule(
		"go.insecure_rand", "Insecure Random (math/rand)", "cryptography", security.SevMedium, goLangs,
		reGoMathRand,
		"math/rand is a pseudo-random number generator and must not be used for security-sensitive "+
			"operations (tokens, nonces, key material). Use crypto/rand instead.",
	).WithCWE("338"))
	security.Default.RegisterRule(goTLSNoMinVersionRule())
	security.Default.RegisterRule(goCookieNoHTTPOnlyRule())
	security.Default.RegisterRule(goGinMissingSecHeadersRule())
	security.Default.RegisterRule(goHTTPMissingSecHeadersRule())
	security.Default.RegisterRule(twoReRule(
		"go.path_traversal", "Path Traversal", "io_validation", security.SevHigh, goLangs,
		reGoFileSink, reGoUserInput,
		"A file-system call uses a path derived from a request parameter without sanitization. "+
			"An attacker can supply \"../\" sequences to escape the intended directory. "+
			"Use filepath.Clean and verify the result is inside the allowed root. (CWE-22)",
	).WithCWE("22"))
	security.Default.RegisterRule(twoReRule(
		"go.sensitive_logging", "Sensitive Data in Logs", "insecure_data_storage", security.SevMedium, goLangs,
		reGoLogSink, reSensitiveData,
		"A log call references a password, token or credential. Logs are often stored in "+
			"plain text and forwarded to external aggregators. Redact or omit sensitive values "+
			"before logging. (CWE-532)",
	).WithCWE("532"))
	security.Default.RegisterRule(reRule(
		"go.gob_deserialization", "Unsafe gob Deserialization", "io_validation", security.SevMedium, goLangs,
		reGoGobDecoder,
		"gob.NewDecoder decodes arbitrary Go values; deserializing attacker-controlled bytes "+
			"can instantiate unexpected types or trigger panics. Validate the source of the "+
			"data and prefer a schema-safe format (JSON, protobuf) for untrusted input. (CWE-502)",
	).WithCWE("502"))
	security.Default.RegisterRule(twoReRule(
		"go.ssrf", "Server-Side Request Forgery", "io_validation", security.SevHigh, goLangs,
		reGoHTTPCallSink, reGoUserInput,
		"A user-controlled value is passed directly to an HTTP client call (http.Get, http.Post, "+
			"http.NewRequest). An attacker can redirect the request to internal services. "+
			"Validate and allowlist target URLs before issuing outbound requests. (CWE-918)",
	).WithCWE("918"))
	security.Default.RegisterRule(goCookieNoSecureRule())
}

// goCookieNoSecureRule flags http.Cookie literals without Secure: true.
func goCookieNoSecureRule() security.Rule {
	return security.Rule{
		ID:        "go.cookie_no_secure",
		Name:      "Cookie Missing Secure Flag",
		Severity:  security.SevMedium,
		Category:  "authentication",
		CWE:       "614",
		Languages: goLangs,
		Description: "An http.Cookie literal was found without Secure: true. Without the Secure " +
			"flag the cookie is transmitted over cleartext HTTP, exposing session tokens to " +
			"network interception. Set Secure: true on all session and authentication cookies.",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reGoCookieNoHTTP.MatchString(line) && !reGoCookieNoSec.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// goGinMissingSecHeadersRule flags files that create a Gin router but have no
// Content-Security-Policy / X-Frame-Options / security-header middleware anywhere
// in the same file. Fires at the gin.New/Default call site.
func goGinMissingSecHeadersRule() security.Rule {
	return security.Rule{
		ID:        "go.gin_missing_security_headers",
		Name:      "Gin Router Without Security Headers",
		Severity:  security.SevMedium,
		Category:  "platform_config",
		CWE:       "16",
		Languages: goLangs,
		Description: "A Gin router is initialized without any Content-Security-Policy, " +
			"X-Frame-Options, X-Content-Type-Options or helmet-style middleware visible " +
			"in the same file. Security headers protect against clickjacking and XSS. " +
			"Add ginhelmet or set headers explicitly in a middleware. (CWE-16)",
		Detect: func(filePath string, lines []string) []security.Finding {
			ginLine := -1
			hasSecHeaders := false
			for i, line := range lines {
				if reGoGinRouter.MatchString(line) && ginLine == -1 {
					ginLine = i
				}
				if reGoGinSecMW.MatchString(line) {
					hasSecHeaders = true
				}
			}
			if ginLine >= 0 && !hasSecHeaders {
				return []security.Finding{security.NewFinding(filePath, ginLine, lines)}
			}
			return nil
		},
	}
}

// goHTTPMissingSecHeadersRule fires when a file manually sets HTTP response
// headers (e.g. Content-Type) but never sets any security headers — a clear
// indicator that headers are configured by hand and the security ones were omitted.
func goHTTPMissingSecHeadersRule() security.Rule {
	return security.Rule{
		ID:        "go.http_missing_security_headers",
		Name:      "HTTP Handler Without Security Headers",
		Severity:  security.SevLow,
		Category:  "platform_config",
		CWE:       "16",
		Languages: goLangs,
		Description: "This file writes HTTP response headers (Header().Set/Add) but never " +
			"sets Content-Security-Policy, X-Frame-Options or other security headers. " +
			"Ensure security headers are applied in middleware or per-handler before the " +
			"response body is written. (CWE-16)",
		Detect: func(filePath string, lines []string) []security.Finding {
			hdrLine := -1
			hasSecHeaders := false
			for i, line := range lines {
				if reGoHTTPHdrSet.MatchString(line) && hdrLine == -1 {
					hdrLine = i
				}
				if reGoHTTPSecHdr.MatchString(line) {
					hasSecHeaders = true
				}
			}
			if hdrLine >= 0 && !hasSecHeaders {
				return []security.Finding{security.NewFinding(filePath, hdrLine, lines)}
			}
			return nil
		},
	}
}

// goTLSNoMinVersionRule flags tls.Config literals that don't set MinVersion on
// the same line. Multi-line structs won't trigger a false negative because the
// rule is a prompt to audit the config, not a definitive finding.
func goTLSNoMinVersionRule() security.Rule {
	return security.Rule{
		ID:        "go.tls_no_minversion",
		Name:      "TLS Config Missing MinVersion",
		Severity:  security.SevMedium,
		Category:  "network_security",
		CWE:       "327",
		Languages: goLangs,
		Description: "A tls.Config literal was found without an explicit MinVersion. " +
			"Without it the Go default applies (TLS 1.2 as of Go 1.22), but setting " +
			"MinVersion: tls.VersionTLS13 explicitly prevents accidental downgrades. " +
			"(CWE-327)",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reGoTLSNoMinVersion.MatchString(line) && !reGoTLSHasMinVer.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// goCookieNoHTTPOnlyRule flags http.Cookie literals missing HttpOnly: true on
// the same line. Session cookies without HttpOnly are readable by JS (XSS pivot).
func goCookieNoHTTPOnlyRule() security.Rule {
	return security.Rule{
		ID:        "go.cookie_no_httponly",
		Name:      "Cookie Missing HttpOnly Flag",
		Severity:  security.SevMedium,
		Category:  "authentication",
		CWE:       "1004",
		Languages: goLangs,
		Description: "An http.Cookie literal was found without HttpOnly: true. " +
			"Without this flag the cookie is accessible to JavaScript, enabling " +
			"session theft via XSS. Set HttpOnly: true on all session cookies. " +
			"(CWE-1004)",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reGoCookieNoHTTP.MatchString(line) && !reGoCookieHTTPOnly.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// goSQLFmtRule detects Go SQL queries assembled with fmt.Sprintf, which enables
// SQL injection. A single regex cannot express "both patterns on one line" in
// Go's RE2 dialect, so Detect performs two match checks per line.
func goSQLFmtRule() security.Rule {
	return security.Rule{
		ID:        "go.sql_fmt_sprintf",
		Name:      "SQL Query via fmt.Sprintf",
		Severity:  security.SevHigh,
		Category:  "io_validation",
		CWE:       "89",
		Languages: goLangs,
		Description: "Building a SQL query with fmt.Sprintf lets attacker-controlled input break " +
			"out of the query and execute arbitrary SQL (CWE-89). Use database/sql parameterized " +
			"queries — db.Query(\"SELECT...\", args...) — so values are bound safely.",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reGoSQLFmt.MatchString(line) && reGoSQLKW.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}
