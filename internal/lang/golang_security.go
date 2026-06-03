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
	// reGoMathRand matches actual rand.* function calls (not just the import)
	// so the rule can be gated on sensitive context via twoReRule.
	reGoMathRand = regexp.MustCompile(`\brand\.(Int|Intn|Int31|Int31n|Int63|Int63n|Float32|Float64|Uint32|Perm|Shuffle|Read)\s*\(`)
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
	// CWE-352: SameSite guard — matches the Strict or Lax assignment on the same line as Cookie{
	reGoSameSiteGuard  = regexp.MustCompile(`SameSite\s*:\s*http\.SameSite(Strict|Lax)Mode`)
	// CWE-434: multipart upload sink and type-validation guard
	reGoFileUploadSink = regexp.MustCompile(`\br\.FormFile\s*\(|\br\.MultipartReader\s*\(|\bmultipart\.NewReader\s*\(`)
	reGoFileTypeCheck  = regexp.MustCompile(`(?i)(http\.DetectContentType|mime\.TypeByExtension|Content-Type|allowedExt|validExt|allowedType|checkType)`)
	// CWE-601: open redirect sink
	reGoHTTPRedirect = regexp.MustCompile(`\bhttp\.Redirect\s*\(`)
	// CWE-732: file-system calls with overly permissive modes
	reGoFilePermSink  = regexp.MustCompile(`\bos\.(OpenFile|Chmod|MkdirAll|Mkdir)\s*\(`)
	reGoWidePerms     = regexp.MustCompile(`\b(0o?777|0o?666|0o?776|0o?757)\b`)
	// CWE-916: fast general-purpose hash in password context
	reGoFastHashSink  = regexp.MustCompile(`\b(sha256|sha512)\.(New|Sum256|Sum512)\s*\(|\bcrypto\.(sha256|sha512)`)
	// CWE-347: JWT parse without signing-method validation
	reGoJWTParse      = regexp.MustCompile(`\bjwt\.(Parse|ParseWithClaims)\s*\(`)
	reGoJWTMethodChk  = regexp.MustCompile(`token\.Method|SigningMethod`)
	// CWE-22 variant: zip-slip via archive/zip without path guard
	reGoZipSink       = regexp.MustCompile(`\bzip\.(NewReader|OpenReader)\s*\(`)
	reGoZipGuard      = regexp.MustCompile(`(?i)(filepath\.Clean|filepath\.Abs|strings\.HasPrefix|path\.Clean)`)
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
		"go.command_injection", "Command Injection Risk", "injection", security.SevHigh, goLangs,
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
	security.Default.RegisterRule(twoReRule(
		"go.insecure_rand", "Insecure Random in Security Context", "cryptography", security.SevMedium, goLangs,
		reGoMathRand, reSensitiveData,
		"math/rand is a pseudo-random generator and must not be used for security-sensitive values "+
			"(tokens, nonces, key material). Use crypto/rand instead.",
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
		"go.sensitive_logging", "Sensitive Data in Logs", "data_exposure", security.SevMedium, goLangs,
		reGoLogSink, reSensitiveData,
		"A log call references a password, token or credential. Logs are often stored in "+
			"plain text and forwarded to external aggregators. Redact or omit sensitive values "+
			"before logging. (CWE-532)",
	).WithCWE("532"))
	security.Default.RegisterRule(reRule(
		"go.gob_deserialization", "Unsafe gob Deserialization", "unsafe_exec", security.SevMedium, goLangs,
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
	security.Default.RegisterRule(goCookieNoSameSiteRule())
	security.Default.RegisterRule(goUnrestrictedFileUploadRule())
	security.Default.RegisterRule(twoReRule(
		"go.insecure_file_permissions", "Broad File Permissions", "io_validation", security.SevMedium, goLangs,
		reGoFilePermSink, reGoWidePerms,
		"A file-system call (os.OpenFile, os.Chmod, os.Mkdir) uses a mode that grants "+
			"world-write or world-read access (0o777, 0o666, 0o776). Use the minimum necessary "+
			"permissions — 0o600 for private files, 0o644 for public-read, 0o755 for directories. (CWE-732)",
	).WithCWE("732"))
	security.Default.RegisterRule(twoReRule(
		"go.fast_hash_for_password", "Fast Hash Used for Password", "cryptography", security.SevHigh, goLangs,
		reGoFastHashSink, reSensitiveData,
		"sha256/sha512 is used on a line that references a password or credential. "+
			"Fast general-purpose hashes can be brute-forced at billions of attempts per second. "+
			"Use bcrypt, scrypt or argon2 (golang.org/x/crypto) for storing passwords. (CWE-916)",
	).WithCWE("916"))
	security.Default.RegisterRule(goJWTNoMethodCheckRule())
	security.Default.RegisterRule(credentialRule("go.hardcoded_credentials", goLangs,
		"A credential-naming variable (password, secret, api_key…) is assigned a string literal. "+
			"Hardcoded secrets are committed to history permanently. Load credentials from "+
			"environment variables or a secret manager at runtime. (CWE-798)"))
	security.Default.RegisterRule(goZipSlipRule())
	security.Default.RegisterRule(twoReRule(
		"go.open_redirect", "Open Redirect", "session_mgmt", security.SevMedium, goLangs,
		reGoHTTPRedirect, reGoUserInput,
		"http.Redirect is called with a URL derived from a request parameter. An attacker can "+
			"supply an off-site URL to redirect victims to a phishing page. Validate the target "+
			"against an explicit allowlist or ensure it is a relative path. (CWE-601)",
	).WithCWE("601"))
}

// goCookieNoSecureRule flags http.Cookie literals without Secure: true.
func goCookieNoSecureRule() security.Rule {
	return security.Rule{
		ID:        "go.cookie_no_secure",
		Name:      "Cookie Missing Secure Flag",
		Severity:  security.SevMedium,
		Category:  "session_mgmt",
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
		Category:  "session_mgmt",
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

// goZipSlipRule fires when a file opens a zip archive (zip.NewReader /
// zip.OpenReader) but has no filepath.Clean, filepath.Abs, or strings.HasPrefix
// guard anywhere in the same file.
func goZipSlipRule() security.Rule {
	return security.Rule{
		ID:        "go.zip_slip",
		Name:      "Zip-Slip / Archive Path Traversal",
		Severity:  security.SevHigh,
		Category:  "unsafe_exec",
		CWE:       "22",
		Languages: goLangs,
		Description: "archive/zip is used without a canonical-path guard in the same file. A " +
			"malicious archive can contain entries whose names include \"../\" to overwrite " +
			"files outside the target directory. For each entry call filepath.Clean and " +
			"verify the result starts with the intended destination before writing. (CWE-22)",
		Detect: func(filePath string, lines []string) []security.Finding {
			zipLine := -1
			hasGuard := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reGoZipSink.MatchString(line) && zipLine == -1 {
					zipLine = i
				}
				if reGoZipGuard.MatchString(line) {
					hasGuard = true
				}
			}
			if zipLine >= 0 && !hasGuard {
				return []security.Finding{security.NewFinding(filePath, zipLine, lines)}
			}
			return nil
		},
	}
}

// goJWTNoMethodCheckRule fires when a file calls jwt.Parse/ParseWithClaims but
// never validates token.Method or references a SigningMethod type. Without the
// check an attacker can craft a token signed with "none" or swap RS256 for HS256
// using the server's public key as the HMAC secret.
func goJWTNoMethodCheckRule() security.Rule {
	return security.Rule{
		ID:        "go.jwt_no_method_check",
		Name:      "JWT Parsed Without Signing-Method Validation",
		Severity:  security.SevHigh,
		Category:  "authentication",
		CWE:       "347",
		Languages: goLangs,
		Description: "jwt.Parse / jwt.ParseWithClaims is called but the key function does not " +
			"validate token.Method. Without the check an attacker can forge tokens by setting " +
			"alg to 'none' or by exploiting RS/HS algorithm confusion. Add a guard: " +
			"if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok { return nil, err }. (CWE-347)",
		Detect: func(filePath string, lines []string) []security.Finding {
			parseLine := -1
			hasMethodCheck := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reGoJWTParse.MatchString(line) && parseLine == -1 {
					parseLine = i
				}
				if reGoJWTMethodChk.MatchString(line) {
					hasMethodCheck = true
				}
			}
			if parseLine >= 0 && !hasMethodCheck {
				return []security.Finding{security.NewFinding(filePath, parseLine, lines)}
			}
			return nil
		},
	}
}

// goCookieNoSameSiteRule flags http.Cookie literals that don't set SameSite to
// Strict or Lax on the same line. Cookies without SameSite are sent on
// cross-site requests, enabling CSRF. Multi-line struct literals may evade this
// check — treat findings as an audit prompt, not a definitive verdict.
func goCookieNoSameSiteRule() security.Rule {
	return security.Rule{
		ID:        "go.cookie_no_samesite",
		Name:      "Cookie Missing SameSite Attribute",
		Severity:  security.SevMedium,
		Category:  "session_mgmt",
		CWE:       "352",
		Languages: goLangs,
		Description: "An http.Cookie literal was found without SameSite set to " +
			"http.SameSiteStrictMode or SameSiteLaxMode. Without SameSite the cookie is sent " +
			"on cross-site requests, making it susceptible to CSRF attacks. Set " +
			"SameSite: http.SameSiteStrictMode on all session and authentication cookies. (CWE-352)",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reGoCookieNoHTTP.MatchString(line) && !reGoSameSiteGuard.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// goUnrestrictedFileUploadRule fires when a file handles multipart uploads but
// has no content-type or extension validation anywhere in the same file. It is
// a file-level check: one finding at the first upload call site.
func goUnrestrictedFileUploadRule() security.Rule {
	return security.Rule{
		ID:        "go.unrestricted_file_upload",
		Name:      "Unrestricted File Upload",
		Severity:  security.SevHigh,
		Category:  "io_validation",
		CWE:       "434",
		Languages: goLangs,
		Description: "A multipart file-upload handler (r.FormFile, multipart.NewReader) is present " +
			"without any content-type or extension validation in the same file. Without validation " +
			"an attacker can upload executable files. Use http.DetectContentType and restrict " +
			"allowed extensions before saving the file. (CWE-434)",
		Detect: func(filePath string, lines []string) []security.Finding {
			uploadLine := -1
			hasTypeCheck := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reGoFileUploadSink.MatchString(line) && uploadLine == -1 {
					uploadLine = i
				}
				if reGoFileTypeCheck.MatchString(line) {
					hasTypeCheck = true
				}
			}
			if uploadLine >= 0 && !hasTypeCheck {
				return []security.Finding{security.NewFinding(filePath, uploadLine, lines)}
			}
			return nil
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
		Category:  "injection",
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
