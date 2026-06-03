package lang

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/security"
)

// Kotlin-only security rules sourced from ~/semgrep-rules/kotlin/lang/security/
// and Android-specific checks. Gated by Languages:["kotlin"].
var kotlinLangs = []string{"kotlin"}

var (
	reKtWeakCrypto     = regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-1|SHA1)["']|Cipher\.getInstance\s*\(\s*["'][^"']*DES[^"']*["']`)
	reKtECBCipher      = regexp.MustCompile(`Cipher\.getInstance\s*\(\s*["'][^"']*ECB[^"']*["']`)
	reKtCmdInjection   = regexp.MustCompile(`Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(`)
	reKtCmdFmt         = regexp.MustCompile(`\bfmt\.|\.format\s*\(|string\.format\s*\(|\$\{|\+\s*["']|["']\s*\+`)
	reKtCookieSet      = regexp.MustCompile(`\bCookie\s*\(|\.addCookie\s*\(|response\.setCookie\s*\(`)
	reKtCookieHTTPOnly = regexp.MustCompile(`isHttpOnly\s*=\s*true|\.isHttpOnly\s*\(true\)|httpOnly\s*=\s*true`)
	// SQL injection helpers
	reKtSQLSink   = regexp.MustCompile(`\b(rawQuery|execSQL|compileStatement)\s*\(`)
	reKtSQLConcat  = regexp.MustCompile(`\+\s*["'\w]|["'\w]\s*\+|\$\{|\bString\.format\s*\(`)
	// new coverage
	reKtFileSink       = regexp.MustCompile(`\bFile\s*\(|\bPaths\.get\s*\(|\bFileInputStream\s*\(`)
	reKtWebInput       = regexp.MustCompile(`\.getParameter\s*\(|request\.getQueryString\b|request\.getHeader\s*\(`)
	reKtTrustAll       = regexp.MustCompile(`\bX509TrustManager\b|checkServerTrusted\s*\(`)
	reKtWeakRandSink   = regexp.MustCompile(`\b(?:new\s+)?(?:java\.util\.)?Random\s*\(\s*\)`)
	reKtObjInputStream  = regexp.MustCompile(`\bObjectInputStream\s*\(|\.readObject\s*\(\s*\)`)
	reKtLogSink        = regexp.MustCompile(`\b(Log\.(d|e|i|v|w|wtf)|println|System\.out\.print(?:ln)?)\s*\(`)
	reKtDocBuilderFac  = regexp.MustCompile(`DocumentBuilderFactory\.newInstance\s*\(`)
	reKtXXESafe        = regexp.MustCompile(`setFeature|FEATURE_SECURE_PROCESSING|setExpandEntityReferences`)
	reKtCookieSink     = regexp.MustCompile(`\bCookie\s*\(|\.addCookie\s*\(`)
	reKtCookieSecure   = regexp.MustCompile(`\.setSecure\s*\(\s*true\s*\)|isSecure\s*=\s*true|secure\s*=\s*true`)
	reKtHTTPSink       = regexp.MustCompile(`\bURL\s*\(|\bOkHttpClient\b|\bHttpURLConnection\b|\.newCall\s*\(`)
	// CWE-352: SameSite guard for Spring ResponseCookie and generic cookie APIs
	reKtSameSite       = regexp.MustCompile(`(?i)\.sameSite\s*\(|sameSite\s*=|SameSite\s*:`)
	// CWE-434: Spring MultipartFile upload sink and type-validation guard
	reKtMultipartFile  = regexp.MustCompile(`\bMultipartFile\b|\.getOriginalFilename\s*\(|\.transferTo\s*\(`)
	reKtFileTypeCheck  = regexp.MustCompile(`(?i)(contentType|mimeType|allowedType|validateFile|allowedExt|getOriginalFilename|fileExtension)`)
	// CWE-601: open redirect sink
	reKtSendRedirect   = regexp.MustCompile(`\.sendRedirect\s*\(`)
	// Android manifest helpers
	reManifestComponent = regexp.MustCompile(`<(activity|service|receiver|provider)\b`)
	reManifestExported  = regexp.MustCompile(`android:exported\s*=\s*"true"`)
	reManifestIntentFlt = regexp.MustCompile(`<intent-filter\b`)
	reManifestExpFalse  = regexp.MustCompile(`android:exported\s*=\s*"false"`)
	reManifestCompClose = regexp.MustCompile(`/>|</(?:activity|service|receiver|provider)>`)
)

func init() {
	security.Default.RegisterRule(reRule(
		"kotlin.weak_crypto", "Weak Cryptography", "cryptography", security.SevHigh, kotlinLangs,
		reKtWeakCrypto,
		"MD5 and SHA-1 are cryptographically broken; DES is obsolete. Use SHA-256+ for hashing "+
			"and AES-GCM for symmetric encryption.",
	).WithCWE("327"))
	security.Default.RegisterRule(reRule(
		"kotlin.ecb_cipher", "ECB Cipher Mode", "cryptography", security.SevHigh, kotlinLangs,
		reKtECBCipher,
		"ECB mode produces identical ciphertext for identical plaintext blocks, leaking data "+
			"patterns and providing no integrity protection. Use AES/GCM/NoPadding instead.",
	).WithCWE("327"))
	security.Default.RegisterRule(kotlinCmdInjectionRule())
	security.Default.RegisterRule(kotlinCookieNoHTTPOnlyRule())
	security.Default.RegisterRule(kotlinSQLInjectionRule())
	security.Default.RegisterRule(kotlinAndroidExportedRule())
	security.Default.RegisterRule(twoReRule(
		"kotlin.path_traversal", "Path Traversal", "io_validation", security.SevHigh, kotlinLangs,
		reKtFileSink, reKtWebInput,
		"A File / FileInputStream / Paths.get call uses a value from request parameters "+
			"without sanitization. An attacker can supply \"../\" sequences to escape the intended "+
			"directory. Resolve and canonicalize paths and verify they start with the allowed root. (CWE-22)",
	).WithCWE("22"))
	security.Default.RegisterRule(reRule(
		"kotlin.trust_all_certs", "Custom TrustManager Accepts All Certificates", "network_security", security.SevHigh, kotlinLangs,
		reKtTrustAll,
		"X509TrustManager or checkServerTrusted was found. A custom TrustManager that does "+
			"not perform certificate chain validation defeats TLS and enables man-in-the-middle "+
			"attacks. Use the default system TrustManager unless you implement full validation. (CWE-295)",
	).WithCWE("295"))
	security.Default.RegisterRule(kotlinWeakRandomRule())
	security.Default.RegisterRule(reRule(
		"kotlin.java_deserialization", "Unsafe Java Deserialization", "io_validation", security.SevHigh, kotlinLangs,
		reKtObjInputStream,
		"ObjectInputStream or readObject() deserializes arbitrary Java objects; an attacker "+
			"who controls the byte stream can exploit gadget chains to achieve remote code "+
			"execution. Avoid Java serialization for untrusted data; use JSON, protobuf or "+
			"another safe format instead. (CWE-502)",
	).WithCWE("502"))
	security.Default.RegisterRule(twoReRule(
		"kotlin.sensitive_logging", "Sensitive Data in Logs", "insecure_data_storage", security.SevMedium, kotlinLangs,
		reKtLogSink, reSensitiveData,
		"A Log.d/e/i/v or println call references a password, token or credential. Android "+
			"logs are accessible via ADB and may be captured by analytics SDKs. Redact or omit "+
			"sensitive values before logging. (CWE-532)",
	).WithCWE("532"))
	security.Default.RegisterRule(kotlinXXERule())
	security.Default.RegisterRule(kotlinCookieNoSecureRule())
	security.Default.RegisterRule(twoReRule(
		"kotlin.ssrf", "Server-Side Request Forgery", "io_validation", security.SevHigh, kotlinLangs,
		reKtHTTPSink, reKtWebInput,
		"A user-controlled request parameter is passed directly to URL / OkHttpClient / "+
			"HttpURLConnection. An attacker can redirect the request to internal services. "+
			"Validate and allowlist target URLs before making outbound requests. (CWE-918)",
	).WithCWE("918"))
	security.Default.RegisterRule(kotlinCookieNoSameSiteRule())
	security.Default.RegisterRule(kotlinUnrestrictedFileUploadRule())
	security.Default.RegisterRule(twoReRule(
		"kotlin.open_redirect", "Open Redirect", "io_validation", security.SevMedium, kotlinLangs,
		reKtSendRedirect, reKtWebInput,
		"response.sendRedirect() is called with a URL derived from a request parameter. An "+
			"attacker can supply an off-site URL to redirect victims to a phishing page. "+
			"Validate the target against an explicit allowlist or ensure it is a relative path. (CWE-601)",
	).WithCWE("601"))
}

// kotlinCookieNoSameSiteRule flags Cookie creation without a SameSite attribute
// on the same line. Multi-line builder chains may produce false positives.
func kotlinCookieNoSameSiteRule() security.Rule {
	return security.Rule{
		ID:        "kotlin.cookie_no_samesite",
		Name:      "Cookie Missing SameSite Attribute",
		Severity:  security.SevMedium,
		Category:  "authentication",
		CWE:       "352",
		Languages: kotlinLangs,
		Description: "A Cookie is created without a SameSite attribute. Without SameSite the " +
			"cookie is included in cross-site requests, enabling CSRF attacks. Use Spring's " +
			"ResponseCookie.from(...).sameSite(\"Strict\").build() or set SameSite on the " +
			"Set-Cookie header explicitly. (CWE-352)",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reKtCookieSet.MatchString(line) && !reKtSameSite.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// kotlinUnrestrictedFileUploadRule fires when a file handles Spring MultipartFile
// uploads but has no content-type or extension validation in the same file.
func kotlinUnrestrictedFileUploadRule() security.Rule {
	return security.Rule{
		ID:        "kotlin.unrestricted_file_upload",
		Name:      "Unrestricted File Upload",
		Severity:  security.SevHigh,
		Category:  "io_validation",
		CWE:       "434",
		Languages: kotlinLangs,
		Description: "A MultipartFile upload handler is present without any content-type or " +
			"extension validation in the same file. Without validation an attacker can upload " +
			"executable files. Check file.contentType against an allowlist and validate the " +
			"extension from getOriginalFilename() before storing the file. (CWE-434)",
		Detect: func(filePath string, lines []string) []security.Finding {
			uploadLine := -1
			hasTypeCheck := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reKtMultipartFile.MatchString(line) && uploadLine == -1 {
					uploadLine = i
				}
				if reKtFileTypeCheck.MatchString(line) {
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

// kotlinWeakRandomRule flags java.util.Random (not SecureRandom) in a context
// that suggests security-sensitive use (token, key, nonce, etc.).
func kotlinWeakRandomRule() security.Rule {
	return security.Rule{
		ID:        "kotlin.weak_random",
		Name:      "Weak Random Number Generator",
		Severity:  security.SevMedium,
		Category:  "cryptography",
		CWE:       "338",
		Languages: kotlinLangs,
		Description: "java.util.Random is not cryptographically secure and must not be used " +
			"to generate tokens, session IDs, keys or nonces. Use java.security.SecureRandom " +
			"or Kotlin's kotlin.random.Random with a SecureRandom source instead.",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if strings.Contains(strings.ToLower(line), "securerandom") {
					continue
				}
				if reKtWeakRandSink.MatchString(line) && reSensitiveData.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// kotlinXXERule flags DocumentBuilderFactory.newInstance() without a
// FEATURE_SECURE_PROCESSING or setExpandEntityReferences guard in the same file.
func kotlinXXERule() security.Rule {
	return security.Rule{
		ID:        "kotlin.xxe",
		Name:      "XML External Entity (XXE)",
		Severity:  security.SevHigh,
		Category:  "io_validation",
		CWE:       "611",
		Languages: kotlinLangs,
		Description: "DocumentBuilderFactory.newInstance() is used without disabling external " +
			"entity processing (FEATURE_SECURE_PROCESSING or setExpandEntityReferences(false)). " +
			"An attacker can supply XML that reads local files or triggers SSRF via XXE. " +
			"Call factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true) before parsing.",
		Detect: func(filePath string, lines []string) []security.Finding {
			dbfLine := -1
			hasGuard := false
			for i, line := range lines {
				if reKtDocBuilderFac.MatchString(line) && dbfLine == -1 {
					dbfLine = i
				}
				if reKtXXESafe.MatchString(line) {
					hasGuard = true
				}
			}
			if dbfLine >= 0 && !hasGuard {
				return []security.Finding{security.NewFinding(filePath, dbfLine, lines)}
			}
			return nil
		},
	}
}

// kotlinCookieNoSecureRule flags Cookie creation without the Secure flag.
func kotlinCookieNoSecureRule() security.Rule {
	return security.Rule{
		ID:        "kotlin.cookie_no_secure",
		Name:      "Cookie Missing Secure Flag",
		Severity:  security.SevMedium,
		Category:  "authentication",
		CWE:       "614",
		Languages: kotlinLangs,
		Description: "A Cookie is created or added to a response without the Secure flag. " +
			"Without Secure the cookie is transmitted over cleartext HTTP, exposing session " +
			"tokens to interception. Call cookie.setSecure(true) or set secure = true.",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reKtCookieSink.MatchString(line) && !reKtCookieSecure.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// kotlinCmdInjectionRule flags Runtime.exec() calls that appear alongside
// string formatting or concatenation — the classic command-injection pattern.
func kotlinCmdInjectionRule() security.Rule {
	return security.Rule{
		ID:        "kotlin.command_injection",
		Name:      "Command Injection Risk",
		Severity:  security.SevHigh,
		Category:  "io_validation",
		CWE:       "78",
		Languages: kotlinLangs,
		Description: "Runtime.getRuntime().exec() called with a formatted or concatenated string " +
			"can let attacker-controlled input inject additional shell commands. Pass a fixed " +
			"argument array and never interpolate user input into the command string. (CWE-78)",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reKtCmdInjection.MatchString(line) && reKtCmdFmt.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// kotlinCookieNoHTTPOnlyRule flags Cookie creation without HttpOnly, which
// leaves session cookies readable by JavaScript (XSS pivot).
func kotlinCookieNoHTTPOnlyRule() security.Rule {
	return security.Rule{
		ID:        "kotlin.cookie_no_httponly",
		Name:      "Cookie Missing HttpOnly Flag",
		Severity:  security.SevMedium,
		Category:  "authentication",
		CWE:       "1004",
		Languages: kotlinLangs,
		Description: "A Cookie was created or added to a response without setting the HttpOnly " +
			"flag. Without HttpOnly the cookie is accessible to JavaScript, enabling session " +
			"theft via XSS. Set isHttpOnly = true on all session cookies. (CWE-1004)",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reKtCookieSet.MatchString(line) && !reKtCookieHTTPOnly.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// kotlinSQLInjectionRule flags Android SQLite API calls (rawQuery, execSQL)
// where the query is built with string concatenation or interpolation.
func kotlinSQLInjectionRule() security.Rule {
	return security.Rule{
		ID:        "kotlin.sql_injection",
		Name:      "SQL Query via String Concatenation",
		Severity:  security.SevHigh,
		Category:  "io_validation",
		CWE:       "89",
		Languages: kotlinLangs,
		Description: "A SQLite API call (rawQuery, execSQL, compileStatement) is assembled " +
			"with string concatenation or interpolation. This enables SQL injection if any " +
			"part of the query originates from user input. Use parameterized queries with " +
			"? placeholders and a selectionArgs array instead. (CWE-89)",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reKtSQLSink.MatchString(line) && reKtSQLConcat.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// kotlinAndroidExportedRule scans AndroidManifest.xml files for components that
// are explicitly exported (android:exported="true") or implicitly exported via
// an <intent-filter> without android:exported="false". Exported components are
// accessible to any app on the device and must be protected by permissions.
func kotlinAndroidExportedRule() security.Rule {
	return security.Rule{
		ID:          "kotlin.android_exported_component",
		Name:        "Exported Android Component",
		Severity:    security.SevMedium,
		Category:    "authentication",
		CWE:         "926",
		Languages:   kotlinLangs,
		ProjectOnly: true,
		Description: "An Android component (activity, service, receiver, provider) is exported " +
			"(explicitly or via <intent-filter>) without a protecting permission. Exported " +
			"components can be invoked by any app on the device. Add " +
			"android:permission=\"...\" or set android:exported=\"false\" if external access " +
			"is not required. (CWE-926)",
		ProjectDetect: func(repoPath string) []security.Finding {
			var out []security.Finding
			_ = filepath.WalkDir(repoPath, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() || filepath.Base(path) != "AndroidManifest.xml" {
					return nil
				}
				data, readErr := os.ReadFile(path)
				if readErr != nil {
					return nil
				}
				lines := strings.Split(string(data), "\n")
				relPath := strings.TrimPrefix(filepath.ToSlash(path), filepath.ToSlash(repoPath)+"/")

				// State machine: track the current component block.
				type state struct {
					active       bool
					startLine    int
					hasIntentFlt bool
					hasExpTrue   bool
					hasExpFalse  bool
				}
				var cur state
				for i, line := range lines {
					if reManifestComponent.MatchString(line) {
						cur = state{active: true, startLine: i}
					}
					if cur.active {
						if reManifestIntentFlt.MatchString(line) {
							cur.hasIntentFlt = true
						}
						if reManifestExported.MatchString(line) {
							cur.hasExpTrue = true
						}
						if reManifestExpFalse.MatchString(line) {
							cur.hasExpFalse = true
						}
						if reManifestCompClose.MatchString(line) {
							exposed := cur.hasExpTrue || (cur.hasIntentFlt && !cur.hasExpFalse)
							if exposed {
								snip := strings.TrimSpace(lines[cur.startLine])
								out = append(out, security.Finding{
									File:     relPath,
									FullPath: path,
									Line:     cur.startLine + 1,
									Snippet:  snip,
								})
							}
							cur = state{}
						}
					}
				}
				return nil
			})
			return out
		},
	}
}
