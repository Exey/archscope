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
	// CWE-916: fast hash in password context (MessageDigest with SHA-256+)
	reKtFastHashSink   = regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*["'](SHA-256|SHA-512|SHA-384|SHA3)["']`)
	// CWE-347: jjwt parser without signing-key verification
	reKtJWTParser      = regexp.MustCompile(`\bJwts\.(parser|parserBuilder)\s*\(`)
	reKtJWTSigningKey  = regexp.MustCompile(`\.setSigningKey\s*\(|\.verifyWith\s*\(`)
	// CWE-749: addJavascriptInterface exposes Java objects to WebView JS
	reKtAddJSInterface = regexp.MustCompile(`\.addJavascriptInterface\s*\(`)
	// CWE-16: JavaScript enabled in WebView
	reKtJSEnabled      = regexp.MustCompile(`\.setJavaScriptEnabled\s*\(\s*true\s*\)`)
	// CWE-732: Android world-readable/writable file modes (deprecated constants)
	reKtWorldMode      = regexp.MustCompile(`MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE`)
	// CWE-22 variant: zip-slip via ZipInputStream without path validation
	reKtZipSink        = regexp.MustCompile(`\bZipInputStream\s*\(|\bZipEntry\b|\.getNextEntry\s*\(`)
	reKtZipGuard       = regexp.MustCompile(`(?i)(canonicalPath|getCanonicalPath|startsWith|validatePath|allowedPath|normalize)`)
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
		"kotlin.java_deserialization", "Unsafe Java Deserialization", "unsafe_exec", security.SevHigh, kotlinLangs,
		reKtObjInputStream,
		"ObjectInputStream or readObject() deserializes arbitrary Java objects; an attacker "+
			"who controls the byte stream can exploit gadget chains to achieve remote code "+
			"execution. Avoid Java serialization for untrusted data; use JSON, protobuf or "+
			"another safe format instead. (CWE-502)",
	).WithCWE("502"))
	security.Default.RegisterRule(twoReRule(
		"kotlin.sensitive_logging", "Sensitive Data in Logs", "data_exposure", security.SevMedium, kotlinLangs,
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
	security.Default.RegisterRule(credentialRule("kotlin.hardcoded_credentials", kotlinLangs,
		"A credential-naming variable is assigned a string literal. Hardcoded secrets are "+
			"committed to history permanently. Load credentials from environment variables, "+
			"BuildConfig fields fed by CI secrets, or a secret manager at runtime. (CWE-798)"))
	security.Default.RegisterRule(twoReRule(
		"kotlin.fast_hash_for_password", "Fast Hash Used for Password", "cryptography", security.SevHigh, kotlinLangs,
		reKtFastHashSink, reSensitiveData,
		"MessageDigest SHA-256/SHA-512 is used in a context that suggests password hashing. "+
			"Fast hashes can be brute-forced at billions of attempts per second. Use BCrypt, "+
			"SCrypt or Argon2 (Spring Security's PasswordEncoder, Tink, or Bouncy Castle) "+
			"for credential storage. (CWE-916)",
	).WithCWE("916"))
	security.Default.RegisterRule(kotlinJWTNoSigningKeyRule())
	security.Default.RegisterRule(kotlinCookieNoSameSiteRule())
	security.Default.RegisterRule(kotlinUnrestrictedFileUploadRule())
	security.Default.RegisterRule(reRule(
		"kotlin.add_javascript_interface", "WebView addJavascriptInterface", "io_validation", security.SevHigh, kotlinLangs,
		reKtAddJSInterface,
		"addJavascriptInterface() exposes an annotated Java object to WebView JavaScript. "+
			"On pre-API-17 devices any JS method can invoke it; on API 17+ only @JavascriptInterface "+
			"methods are exposed, but XSS in the WebView still gives full access. "+
			"Remove the bridge or restrict it to trusted, local content only. (CWE-749)",
	).WithCWE("749"))
	security.Default.RegisterRule(reRule(
		"kotlin.javascript_enabled", "JavaScript Enabled in WebView", "platform_config", security.SevMedium, kotlinLangs,
		reKtJSEnabled,
		"setJavaScriptEnabled(true) enables JavaScript in a WebView. If the WebView loads "+
			"remote or user-supplied URLs, XSS in the loaded page can access device APIs "+
			"exposed via addJavascriptInterface. Disable JavaScript unless strictly required "+
			"and ensure the WebView only loads trusted origins. (CWE-16)",
	).WithCWE("16"))
	security.Default.RegisterRule(reRule(
		"kotlin.world_readable_file", "World-Readable / World-Writable File Mode", "data_exposure", security.SevHigh, kotlinLangs,
		reKtWorldMode,
		"MODE_WORLD_READABLE and MODE_WORLD_WRITEABLE are deprecated since API 17. They "+
			"allow any installed app to read or overwrite the file, exposing sensitive data. "+
			"Use internal storage without a world mode, or ContentProvider for controlled sharing. (CWE-732)",
	).WithCWE("732"))
	security.Default.RegisterRule(kotlinZipSlipRule())
	security.Default.RegisterRule(kotlinManifestCleartextRule())
	security.Default.RegisterRule(kotlinManifestAllowBackupRule())
	security.Default.RegisterRule(twoReRule(
		"kotlin.open_redirect", "Open Redirect", "session_mgmt", security.SevMedium, kotlinLangs,
		reKtSendRedirect, reKtWebInput,
		"response.sendRedirect() is called with a URL derived from a request parameter. An "+
			"attacker can supply an off-site URL to redirect victims to a phishing page. "+
			"Validate the target against an explicit allowlist or ensure it is a relative path. (CWE-601)",
	).WithCWE("601"))
}

// kotlinJWTNoSigningKeyRule fires when a file calls Jwts.parser() /
// Jwts.parserBuilder() but never calls setSigningKey / verifyWith, meaning
// tokens are parsed without signature verification.
func kotlinJWTNoSigningKeyRule() security.Rule {
	return security.Rule{
		ID:        "kotlin.jwt_no_signing_key",
		Name:      "JWT Parsed Without Signature Verification",
		Severity:  security.SevHigh,
		Category:  "authentication",
		CWE:       "347",
		Languages: kotlinLangs,
		Description: "Jwts.parser() / Jwts.parserBuilder() is called without setSigningKey() " +
			"or verifyWith() anywhere in the file. Without a signing key the library accepts " +
			"any token regardless of its signature, allowing forgery. Call " +
			".setSigningKey(secretKey) (or .verifyWith(key) on the new API) before parsing. (CWE-347)",
		Detect: func(filePath string, lines []string) []security.Finding {
			parserLine := -1
			hasSigningKey := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reKtJWTParser.MatchString(line) && parserLine == -1 {
					parserLine = i
				}
				if reKtJWTSigningKey.MatchString(line) {
					hasSigningKey = true
				}
			}
			if parserLine >= 0 && !hasSigningKey {
				return []security.Finding{security.NewFinding(filePath, parserLine, lines)}
			}
			return nil
		},
	}
}

// kotlinZipSlipRule fires when a file processes ZIP entries (ZipInputStream /
// getNextEntry) but has no canonical-path guard anywhere in the same file.
func kotlinZipSlipRule() security.Rule {
	return security.Rule{
		ID:        "kotlin.zip_slip",
		Name:      "Zip-Slip / Archive Path Traversal",
		Severity:  security.SevHigh,
		Category:  "unsafe_exec",
		CWE:       "22",
		Languages: kotlinLangs,
		Description: "ZipInputStream / getNextEntry() is used without a canonical-path check " +
			"anywhere in the same file. A malicious archive can contain entries with \"../\" " +
			"in their names to overwrite files outside the target directory. Call " +
			"File(destDir, entry.name).canonicalPath and verify it starts with " +
			"destDir.canonicalPath before extracting each entry. (CWE-22)",
		Detect: func(filePath string, lines []string) []security.Finding {
			zipLine := -1
			hasGuard := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reKtZipSink.MatchString(line) && zipLine == -1 {
					zipLine = i
				}
				if reKtZipGuard.MatchString(line) {
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

// kotlinManifestCleartextRule scans AndroidManifest.xml for
// android:usesCleartextTraffic="true" at the <application> level.
func kotlinManifestCleartextRule() security.Rule {
	reCleartext := regexp.MustCompile(`android:usesCleartextTraffic\s*=\s*"true"`)
	return security.Rule{
		ID:          "kotlin.manifest_cleartext_traffic",
		Name:        "Cleartext Traffic Permitted in Manifest",
		Severity:    security.SevHigh,
		Category:    "network_security",
		CWE:         "319",
		Languages:   kotlinLangs,
		ProjectOnly: true,
		Description: "android:usesCleartextTraffic=\"true\" in AndroidManifest.xml allows the " +
			"app to send unencrypted HTTP traffic. This exposes data to interception. Remove " +
			"the attribute (defaults to false on API 28+) or use a Network Security Config to " +
			"restrict cleartext to specific domains during development only. (CWE-319)",
		ProjectDetect: func(repoPath string) []security.Finding {
			return manifestLineRule(repoPath, reCleartext)
		},
	}
}

// kotlinManifestAllowBackupRule scans AndroidManifest.xml for
// android:allowBackup="true", which lets adb backup extract app data without root.
func kotlinManifestAllowBackupRule() security.Rule {
	reAllowBackup := regexp.MustCompile(`android:allowBackup\s*=\s*"true"`)
	return security.Rule{
		ID:          "kotlin.manifest_allow_backup",
		Name:        "Android Backup Enabled",
		Severity:    security.SevMedium,
		Category:    "insecure_data_storage",
		CWE:         "530",
		Languages:   kotlinLangs,
		ProjectOnly: true,
		Description: "android:allowBackup=\"true\" lets any user with USB debugging enabled " +
			"extract the app's data directory via `adb backup` without root access. Set " +
			"android:allowBackup=\"false\" or use android:fullBackupContent to restrict " +
			"which files are included in backups. (CWE-530)",
		ProjectDetect: func(repoPath string) []security.Finding {
			return manifestLineRule(repoPath, reAllowBackup)
		},
	}
}

// manifestLineRule is a shared helper that walks all AndroidManifest.xml files
// under repoPath and flags every non-comment line matching re.
func manifestLineRule(repoPath string, re *regexp.Regexp) []security.Finding {
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
		for i, line := range lines {
			if re.MatchString(line) {
				out = append(out, security.Finding{
					File:     relPath,
					FullPath: path,
					Line:     i + 1,
					Snippet:  strings.TrimSpace(line),
				})
			}
		}
		return nil
	})
	return out
}

// kotlinCookieNoSameSiteRule flags Cookie creation without a SameSite attribute
// on the same line. Multi-line builder chains may produce false positives.
func kotlinCookieNoSameSiteRule() security.Rule {
	return security.Rule{
		ID:        "kotlin.cookie_no_samesite",
		Name:      "Cookie Missing SameSite Attribute",
		Severity:  security.SevMedium,
		Category:  "session_mgmt",
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
		Category:  "unsafe_exec",
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
		Category:  "session_mgmt",
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
		Category:  "injection",
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
		Category:  "session_mgmt",
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
		Category:  "injection",
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
