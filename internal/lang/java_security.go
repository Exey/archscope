package lang

import (
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/security"
)

// Java-only security rules covering OWASP Top-10 and common Spring/Java pitfalls.
// Gated by Languages:["java"].
var javaLangs = []string{"java"}

var (
	// ── SQL injection ─────────────────────────────────────────────────────────
	reJavaSQLSink   = regexp.MustCompile(`\b(executeQuery|executeUpdate|execute|executeLargeUpdate|addBatch)\s*\(`)
	reJavaSQLConcat = regexp.MustCompile(`\+\s*\w|"\s*\+|String\.format\s*\(|\.formatted\s*\(|String\.valueOf`)

	// ── Command injection ──────────────────────────────────────────────────────
	reJavaCmdSink   = regexp.MustCompile(`\bRuntime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(|\bnew\s+ProcessBuilder\s*\(`)
	reJavaCmdConcat = regexp.MustCompile(`\+\s*\w|"\s*\+|String\.format\s*\(`)

	// ── Insecure deserialization ───────────────────────────────────────────────
	reJavaDeser = regexp.MustCompile(`\bnew\s+ObjectInputStream\s*\(`)

	// ── XXE ───────────────────────────────────────────────────────────────────
	reJavaXXESink  = regexp.MustCompile(`(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)\.newInstance\s*\(`)
	reJavaXXEGuard = regexp.MustCompile(`(?i)(setFeature|setExpandEntityReferences|FEATURE_SECURE_PROCESSING|disallow-doctype|defusedxml)`)

	// ── Weak cryptography ──────────────────────────────────────────────────────
	// Matched on the RAW line (before StripStringsAndComments) — see javaWeakCryptoRule.
	reJavaWeakCrypto = regexp.MustCompile(
		`MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-?1|MD2)["']|` +
			`Cipher\.getInstance\s*\(\s*["'](DES|DESede|RC4|RC2|Blowfish)[/"']`)

	// ── Trust-all TLS ─────────────────────────────────────────────────────────
	reJavaTrustAllCert = regexp.MustCompile(
		`checkServerTrusted[^{]*\{\s*\}|` +
			`(?i)(TrustAllCerts|NullTrustManager|AllTrusting|ALLOW_ALL_HOSTNAME)`)
	reJavaTrustAllHost = regexp.MustCompile(
		`\.setHostnameVerifier\s*\(.*->\s*true|` +
			`setDefaultHostnameVerifier\s*\(.*->\s*true|ALLOW_ALL_HOSTNAME_VERIFIER`)

	// ── Spring Security CSRF disabled ─────────────────────────────────────────
	reJavaCsrfDisable = regexp.MustCompile(
		`\.csrf\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)|` +
			`csrf\s*->\s*csrf\s*\.\s*disable\s*\(\s*\)`)

	// ── JWT without signing-key validation ────────────────────────────────────
	reJavaJWTSink  = regexp.MustCompile(`\bJwts\.(parser|parserBuilder)\s*\(`)
	reJavaJWTGuard = regexp.MustCompile(`\b(setSigningKey|verifyWith|signWith|signingKey|secretKeyFor)\s*\(`)

	// ── User-input sources ────────────────────────────────────────────────────
	reJavaUserInput = regexp.MustCompile(
		`request\.(getParameter|getHeader|getQueryString|getAttribute|getCookies|getBody)\s*\(|` +
			`@(RequestParam|PathVariable|RequestBody|RequestHeader|QueryParam|PathParam)\b`)

	// ── Path traversal ────────────────────────────────────────────────────────
	reJavaFileSink = regexp.MustCompile(`\bnew\s+File\s*\(|\bPaths\.get\s*\(|\bFileInputStream\s*\(`)

	// ── XSS (reflected output) ────────────────────────────────────────────────
	reJavaXSSSink  = regexp.MustCompile(`\b(getWriter|getOutputStream)\s*\(\s*\)\s*\.(print|println|write)\s*\(|\bout\.(print|println)\s*\(`)
	reJavaXSSInput = regexp.MustCompile(`request\.getParameter\s*\(|request\.getHeader\s*\(`)

	// ── Open redirect ─────────────────────────────────────────────────────────
	reJavaRedirectSink = regexp.MustCompile(`\bresponse\.sendRedirect\s*\(|setHeader\s*\(\s*["']Location["']`)

	// ── Sensitive data in logs ────────────────────────────────────────────────
	reJavaLogSink = regexp.MustCompile(
		`\b(log|logger|LOG|LOGGER)\.(trace|debug|info|warn|warning|error|fatal)\s*\(|` +
			`\bSystem\.out\.(print|println|printf)\s*\(`)

	// ── Insecure random ───────────────────────────────────────────────────────
	reJavaWeakRandom = regexp.MustCompile(`\bnew\s+Random\s*\(\s*\)|\bMath\.random\s*\(`)

	// ── Unrestricted file upload ──────────────────────────────────────────────
	reJavaFileUpload    = regexp.MustCompile(`\bMultipartFile\b|\b(getPart|getParts)\s*\(|\bMultipartHttpServletRequest\b`)
	reJavaFileTypeCheck = regexp.MustCompile(
		`(?i)(getContentType|FilenameUtils\.getExtension|getMimeType|` +
			`allowedExt|validExt|checkType|content.?type|allowed.?type|` +
			`allowedExtensions|ALLOWED_EXTENSIONS|isValidFile|validateFile)`)

	// ── Verbose error (stack trace exposure) ─────────────────────────────────
	reJavaPrintStack = regexp.MustCompile(`\.printStackTrace\s*\(\s*\)`)

	// ── Hardcoded cryptographic key material ──────────────────────────────────
	reJavaSecretKeySpec = regexp.MustCompile(`\bnew\s+SecretKeySpec\s*\(\s*(?:new\s+byte\s*\[|"[^"]{6,}")`)

	// ── Zip-Slip ──────────────────────────────────────────────────────────────
	reJavaZipSink  = regexp.MustCompile(`\bnew\s+ZipInputStream\s*\(|\bnew\s+ZipFile\s*\(|\bentry\.getName\s*\(\s*\)`)
	reJavaZipGuard = regexp.MustCompile(`(?i)(canonical|normalize\s*\(\s*\)|startsWith|toRealPath|getCanonicalPath)`)

	// ── SQL import gate (avoids firing SQL rules in non-DB files) ─────────────
	reJavaDBImport = regexp.MustCompile(
		`import\s+(?:java\.sql\.|javax\.sql\.|jakarta\.persistence\.|` +
			`javax\.persistence\.|org\.springframework\.jdbc|org\.hibernate|` +
			`com\.baomidou|org\.jooq|io\.r2dbc)`)

	// ── Log injection ─────────────────────────────────────────────────────────
	// (reJavaUserInput + reJavaLogSink, already defined above)
)

func init() {
	// ── Injection ─────────────────────────────────────────────────────────────
	security.Default.RegisterRule(javaSQLConcatRule())
	security.Default.RegisterRule(twoReRule(
		"java.command_injection", "Command Injection Risk", "injection", security.SevHigh, javaLangs,
		reJavaCmdSink, reJavaCmdConcat,
		"Runtime.exec() or ProcessBuilder is called with a string assembled via concatenation "+
			"or String.format. If any argument is user-controlled an attacker can inject "+
			"arbitrary commands. Pass arguments as a fixed list and never interpolate input. (CWE-78)",
	).WithCWE("78").WithSkipTests())

	// ── Unsafe deserialization / exec ─────────────────────────────────────────
	security.Default.RegisterRule(reRule(
		"java.insecure_deserialization", "Insecure Deserialization", "unsafe_exec", security.SevHigh, javaLangs,
		reJavaDeser,
		"ObjectInputStream.readObject() deserializes arbitrary Java objects from a byte stream. "+
			"Deserializing attacker-controlled data can execute constructors and methods, leading to "+
			"remote code execution. Use JSON/Protobuf for untrusted data or implement a "+
			"validating ObjectInputStream that allowlists acceptable classes. (CWE-502)",
	).WithCWE("502").WithSkipTests())
	security.Default.RegisterRule(javaXXERule())
	security.Default.RegisterRule(javaZipSlipRule())

	// ── Cryptography ──────────────────────────────────────────────────────────
	security.Default.RegisterRule(javaWeakCryptoRule())
	security.Default.RegisterRule(twoReRule(
		"java.insecure_random", "Insecure Random in Security Context", "cryptography", security.SevMedium, javaLangs,
		reJavaWeakRandom, reSensitiveData,
		"new Random() and Math.random() produce predictable values unsuitable for security use "+
			"(tokens, nonces, keys). Use SecureRandom from java.security instead. (CWE-338)",
	).WithCWE("338").WithSkipTests())
	security.Default.RegisterRule(reRule(
		"java.hardcoded_key", "Hardcoded Cryptographic Key", "cryptography", security.SevHigh, javaLangs,
		reJavaSecretKeySpec,
		"SecretKeySpec is constructed directly from a string literal or hardcoded byte array. "+
			"Hardcoded keys are committed to history permanently and cannot be rotated. "+
			"Generate keys with SecureRandom and load them from a secrets manager at runtime. (CWE-321)",
	).WithCWE("321").WithSkipTests())
	security.Default.RegisterRule(twoReRule(
		"java.fast_hash_for_password", "Fast Hash Used for Password", "cryptography", security.SevHigh, javaLangs,
		reJavaWeakCrypto, reSensitiveData,
		"A fast general-purpose hash (MD5, SHA-1) is used in a context suggesting password "+
			"hashing. These algorithms can be brute-forced at billions of attempts per second. "+
			"Use BCryptPasswordEncoder, PBKDF2PasswordEncoder or Argon2PasswordEncoder. (CWE-916)",
	).WithCWE("916"))

	// ── Network security ──────────────────────────────────────────────────────
	security.Default.RegisterRule(reRule(
		"java.trust_all_certs", "TLS Certificate Verification Disabled", "network_security", security.SevHigh, javaLangs,
		reJavaTrustAllCert,
		"An empty checkServerTrusted() implementation or a trust-all TrustManager disables TLS "+
			"certificate validation, making all HTTPS connections vulnerable to man-in-the-middle "+
			"attacks. Use the default TrustManager or a properly configured SSLContext. (CWE-295)",
	).WithCWE("295").WithSkipTests())
	security.Default.RegisterRule(reRule(
		"java.trust_all_hosts", "Hostname Verification Disabled", "network_security", security.SevHigh, javaLangs,
		reJavaTrustAllHost,
		"setHostnameVerifier with a lambda returning true or ALLOW_ALL_HOSTNAME_VERIFIER disables "+
			"hostname verification, allowing an attacker to present any certificate for any host. "+
			"Remove the custom verifier and rely on the default HTTPS hostname verification. (CWE-295)",
	).WithCWE("295").WithSkipTests())

	// ── Authentication & session management ───────────────────────────────────
	security.Default.RegisterRule(reRule(
		"java.spring_csrf_disabled", "Spring Security CSRF Protection Disabled", "session_mgmt", security.SevHigh, javaLangs,
		reJavaCsrfDisable,
		".csrf().disable() or csrf -> csrf.disable() turns off CSRF protection for all "+
			"state-changing endpoints. Without it, an attacker's page can silently submit "+
			"authenticated requests on behalf of a logged-in user. Remove the disable() call "+
			"and ensure your frontend sends the CSRF token. (CWE-352)",
	).WithCWE("352"))
	security.Default.RegisterRule(javaJWTNoVerifyRule())

	// ── Input/output validation ────────────────────────────────────────────────
	security.Default.RegisterRule(twoReRule(
		"java.path_traversal", "Path Traversal", "io_validation", security.SevHigh, javaLangs,
		reJavaFileSink, reJavaUserInput,
		"A file-system call (new File, Paths.get, FileInputStream) uses a value derived from "+
			"user input. An attacker can inject \"../\" sequences to escape the intended directory. "+
			"Call file.getCanonicalPath() and verify it starts with the allowed root. (CWE-22)",
	).WithCWE("22"))
	security.Default.RegisterRule(twoReRule(
		"java.xss", "Reflected XSS", "io_validation", security.SevHigh, javaLangs,
		reJavaXSSSink, reJavaXSSInput,
		"A servlet/Spring response writer (getWriter().print) outputs a value derived directly "+
			"from request.getParameter(). An attacker can inject HTML/JS into the page. "+
			"Use HtmlUtils.htmlEscape() or OWASP Java Encoder before writing user input. (CWE-79)",
	).WithCWE("79"))
	security.Default.RegisterRule(twoReRule(
		"java.ssrf", "Server-Side Request Forgery", "io_validation", security.SevHigh, javaLangs,
		regexp.MustCompile(`\bnew\s+URL\s*\(|\bHttpURLConnection\b|\bRestTemplate\b`),
		reJavaUserInput,
		"A URL or HTTP client is used on the same line as user-supplied input. An attacker can "+
			"redirect the server-side request to internal services or cloud metadata endpoints. "+
			"Validate and allowlist target URLs before issuing outbound requests. (CWE-918)",
	).WithCWE("918"))
	security.Default.RegisterRule(twoReRule(
		"java.open_redirect", "Open Redirect", "session_mgmt", security.SevMedium, javaLangs,
		reJavaRedirectSink, reJavaUserInput,
		"response.sendRedirect() is called with a URL derived from user input. An attacker can "+
			"supply an off-site URL to redirect victims to a phishing page. Validate the target "+
			"against an explicit allowlist or ensure it is a safe relative path. (CWE-601)",
	).WithCWE("601"))
	security.Default.RegisterRule(javaFileUploadRule())

	// ── Data exposure ─────────────────────────────────────────────────────────
	security.Default.RegisterRule(twoReRule(
		"java.sensitive_logging", "Sensitive Data in Logs", "data_exposure", security.SevMedium, javaLangs,
		reJavaLogSink, reSensitiveData,
		"A log call references a password, token or credential. Log files are often stored in "+
			"plain text and forwarded to external aggregators. Redact or omit sensitive values "+
			"before logging. (CWE-532)",
	).WithCWE("532"))
	security.Default.RegisterRule(twoReRule(
		"java.log_injection", "Log Injection", "data_exposure", security.SevMedium, javaLangs,
		reJavaLogSink, reJavaUserInput,
		"A log statement writes a value derived directly from user-supplied request data. "+
			"An attacker can inject CRLF sequences to forge log entries or corrupt structured "+
			"logging. Sanitize user input (strip \\r, \\n) before logging. (CWE-117)",
	).WithCWE("117"))
	security.Default.RegisterRule(reRule(
		"java.verbose_error", "Stack Trace Exposed to Client", "data_exposure", security.SevMedium, javaLangs,
		reJavaPrintStack,
		"e.printStackTrace() writes the full stack trace to standard error, which is often "+
			"forwarded to HTTP responses in development configurations. Stack traces reveal "+
			"internal paths, class names and library versions. Use a structured logger and "+
			"return only generic error messages to clients. (CWE-209)",
	).WithCWE("209").WithSkipTests())

	// ── Hardcoded credentials ─────────────────────────────────────────────────
	security.Default.RegisterRule(credentialRule("java.hardcoded_credentials", javaLangs,
		"A credential-naming variable (password, secret, apiKey…) is assigned a string literal. "+
			"Hardcoded secrets are committed to history permanently. Load credentials from "+
			"environment variables or a secrets manager (e.g. System.getenv, AWS Secrets Manager). (CWE-798)"))
}

// javaSQLConcatRule fires when a SQL execution method and string concatenation appear on
// the same line in a file that imports a database or ORM package.
func javaSQLConcatRule() security.Rule {
	return security.Rule{
		ID:        "java.sql_concat",
		Name:      "SQL Injection via Concatenation",
		Severity:  security.SevHigh,
		Category:  "injection",
		CWE:       "89",
		Languages: javaLangs,
		Description: "A SQL execution method (executeQuery, executeUpdate, execute) is called with a " +
			"query assembled via string concatenation or String.format. Use parameterized " +
			"PreparedStatement (\"SELECT … WHERE id = ?\") so user input is never treated as SQL. (CWE-89)",
		Detect: func(filePath string, lines []string) []security.Finding {
			hasDB := false
			for _, l := range lines {
				if reJavaDBImport.MatchString(l) {
					hasDB = true
					break
				}
			}
			if !hasDB {
				return nil
			}
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				stripped := security.StripStringsAndComments(line)
				if reJavaSQLSink.MatchString(stripped) && reJavaSQLConcat.MatchString(stripped) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// javaWeakCryptoRule matches on raw (unstripped) lines because the algorithm
// name lives inside a string literal that StripStringsAndComments would erase.
func javaWeakCryptoRule() security.Rule {
	return security.Rule{
		ID:        "java.weak_crypto",
		Name:      "Weak Cryptography",
		Severity:  security.SevHigh,
		Category:  "cryptography",
		CWE:       "327",
		Languages: javaLangs,
		Description: "MD5, SHA-1 and MD2 are cryptographically broken for security use. " +
			"DES, DESede, RC4, RC2 and Blowfish have known weaknesses and are deprecated. " +
			"Use SHA-256 or stronger for hashing and AES-GCM for symmetric encryption. (CWE-327)",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reJavaWeakCrypto.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// javaXXERule fires when DocumentBuilderFactory/SAXParserFactory/XMLInputFactory
// is instantiated but no secure-processing feature or entity guard is set in the
// same file.
func javaXXERule() security.Rule {
	return security.Rule{
		ID:        "java.xxe",
		Name:      "XML External Entity (XXE)",
		Severity:  security.SevHigh,
		Category:  "unsafe_exec",
		CWE:       "611",
		Languages: javaLangs,
		Description: "An XML parser factory (DocumentBuilderFactory, SAXParserFactory, XMLInputFactory) " +
			"is instantiated without disabling external entity expansion in the same file. " +
			"An attacker can use XXE to read local files or trigger SSRF. Call " +
			"factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true) and " +
			"factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true). (CWE-611)",
		Detect: func(filePath string, lines []string) []security.Finding {
			sinkLine := -1
			hasGuard := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reJavaXXESink.MatchString(line) && sinkLine == -1 {
					sinkLine = i
				}
				if reJavaXXEGuard.MatchString(line) {
					hasGuard = true
				}
			}
			if sinkLine >= 0 && !hasGuard {
				return []security.Finding{security.NewFinding(filePath, sinkLine, lines)}
			}
			return nil
		},
	}
}

// javaZipSlipRule fires when a ZipInputStream is used without a canonical path
// guard anywhere in the same file.
func javaZipSlipRule() security.Rule {
	return security.Rule{
		ID:        "java.zip_slip",
		Name:      "Zip-Slip / Archive Path Traversal",
		Severity:  security.SevHigh,
		Category:  "unsafe_exec",
		CWE:       "22",
		Languages: javaLangs,
		Description: "A ZipInputStream or ZipFile is used without a canonical-path guard in the same file. " +
			"A malicious archive can contain entries with \"../\" in their names to overwrite " +
			"files outside the target directory. For each ZipEntry call " +
			"Paths.get(destDir).resolve(entry.getName()).normalize() and verify it starts with " +
			"the destination root before writing. (CWE-22)",
		Detect: func(filePath string, lines []string) []security.Finding {
			zipLine := -1
			hasGuard := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reJavaZipSink.MatchString(line) && zipLine == -1 {
					zipLine = i
				}
				if reJavaZipGuard.MatchString(line) {
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

// javaJWTNoVerifyRule fires when a file calls Jwts.parser()/parserBuilder() but
// never sets a signing key — meaning tokens are accepted without signature verification.
func javaJWTNoVerifyRule() security.Rule {
	return security.Rule{
		ID:        "java.jwt_no_verify",
		Name:      "JWT Parsed Without Signature Verification",
		Severity:  security.SevHigh,
		Category:  "authentication",
		CWE:       "347",
		Languages: javaLangs,
		Description: "Jwts.parser() or Jwts.parserBuilder() is called without setSigningKey() or " +
			"verifyWith() anywhere in the file. Without a signing key the library accepts tokens " +
			"with any or no signature, allowing attackers to forge tokens. Set a strong signing " +
			"key and validate the algorithm explicitly. (CWE-347)",
		Detect: func(filePath string, lines []string) []security.Finding {
			parseLine := -1
			hasGuard := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reJavaJWTSink.MatchString(line) && parseLine == -1 {
					parseLine = i
				}
				if reJavaJWTGuard.MatchString(line) {
					hasGuard = true
				}
			}
			if parseLine >= 0 && !hasGuard {
				return []security.Finding{security.NewFinding(filePath, parseLine, lines)}
			}
			return nil
		},
	}
}

// javaFileUploadRule fires when a file handles multipart uploads (MultipartFile,
// getPart) but has no content-type or extension validation anywhere in the file.
func javaFileUploadRule() security.Rule {
	return security.Rule{
		ID:        "java.unrestricted_file_upload",
		Name:      "Unrestricted File Upload",
		Severity:  security.SevHigh,
		Category:  "io_validation",
		CWE:       "434",
		Languages: javaLangs,
		Description: "A multipart file-upload handler (MultipartFile, getPart) is present without " +
			"any content-type, MIME-type, or filename-extension validation in the same file. " +
			"Without validation an attacker can upload executable files (.jsp, .class). " +
			"Call getContentType() or getOriginalFilename() and restrict accepted types. (CWE-434)",
		Detect: func(filePath string, lines []string) []security.Finding {
			uploadLine := -1
			hasTypeCheck := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reJavaFileUpload.MatchString(line) && uploadLine == -1 {
					uploadLine = i
				}
				if reJavaFileTypeCheck.MatchString(line) {
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

// javaIsTestPath extends the universal IsTestPath with Java-specific conventions.
func javaIsTestPath(filePath string) bool {
	if security.IsTestPath(filePath) {
		return true
	}
	low := strings.ToLower(filePath)
	base := low
	if idx := strings.LastIndexAny(low, "/\\"); idx >= 0 {
		base = low[idx+1:]
	}
	return strings.HasSuffix(base, "it.java") // integration tests: UserServiceIT.java
}
