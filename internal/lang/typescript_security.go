package lang

import (
	"regexp"

	"github.com/exey/archscope/internal/security"
)

// TS/JS-only security rules: dynamic code execution, DOM-based XSS sinks,
// cleartext transport, prototype pollution, and insecure cookie handling.
// Gated to the typescript language spec (which owns ts/tsx/js/jsx/mjs/cjs).
var tsLangs = []string{"ts"}

var (
	reJSEval             = regexp.MustCompile(`\beval\s*\(|new\s+Function\s*\(`)
	reJSDangerHTML       = regexp.MustCompile(`dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\(`)
	reJSTransport        = regexp.MustCompile(`http://`)
	reJSProtoPollute     = regexp.MustCompile(`\.__proto__\s*=|\["__proto__"\]\s*=|Object\.assign\s*\(\s*\w+\s*,\s*req\b`)
	reJSInsecureCookie   = regexp.MustCompile(`document\.cookie\s*=`)
	reJSCORSWildcard     = regexp.MustCompile(`(?i)(Access-Control-Allow-Origin['":\s,]+['"]\*['"]|origin\s*:\s*['"]\*['"]|cors\s*\(\s*\{\s*origin\s*:\s*['"]\*['"])`)
	reJSNoSQLSink         = regexp.MustCompile(`\b(findOne|findMany|updateOne|updateMany|deleteOne|deleteMany|aggregate)\s*\(`)
	reJSNoSQLSource       = regexp.MustCompile(`\breq\.(body|params|query)\b`)
	reJSStorageSink       = regexp.MustCompile(`\b(localStorage|sessionStorage)\s*\.\s*setItem\s*\(`)
	reJSStorageSensKey    = regexp.MustCompile(`(?i)\b(password|passwd|token|secret|api[_-]?key|credential|auth|private[_-]?key)\b`)
	// new coverage
	reJSChildProcSink     = regexp.MustCompile(`\b(exec|execSync|spawn|spawnSync)\s*\(`)
	reJSChildProcConcat   = regexp.MustCompile(`\$\{|\+\s*["'\w]|["'\w]\s*\+|\breq\.(body|params|query)\b`)
	reJSSQLSink           = regexp.MustCompile(`\b(db\.|pool\.|connection\.|client\.)?query\s*\(|\b\.execute\s*\(|\b\.raw\s*\(`)
	reJSSQLConcat         = regexp.MustCompile(`\+\s*["'\w]|["'\w]\s*\+|\$\{|\breq\.(body|params|query)\b`)
	reJSRejectUnauth      = regexp.MustCompile(`rejectUnauthorized\s*:\s*false`)
	reJSMathRandom        = regexp.MustCompile(`\bMath\.random\s*\(\s*\)`)
	reJSConsoleSink       = regexp.MustCompile(`\b(console\.(log|error|debug|warn|info))\s*\(`)
	reJSResCookieSink     = regexp.MustCompile(`\bres\.cookie\s*\(|response\.cookie\s*\(`)
	reJSCookieSecure      = regexp.MustCompile(`secure\s*:\s*true`)
	reJSFetchSink         = regexp.MustCompile(`\b(fetch|axios\.(get|post|put|delete|request)|http\.(get|post|request))\s*\(`)
	// CWE-352: res.cookie without sameSite on the same line
	reJSSameSite      = regexp.MustCompile(`(?i)sameSite\s*:`)
	// CWE-434: multer initialisation and fileFilter guard
	reJSMulterInit    = regexp.MustCompile(`\bmulter\s*\(\s*\{`)
	reJSFileFilter    = regexp.MustCompile(`\bfileFilter\b`)
	// CWE-601: open redirect sink
	reJSRedirectSink  = regexp.MustCompile(`\b(?:res|response)\.redirect\s*\(`)
	// CWE-327: weak crypto via Node's crypto module
	reJSWeakCrypto    = regexp.MustCompile(`\bcrypto\.createHash\s*\(\s*["'](md5|sha1)["']`)
	// CWE-22: fs sink for path traversal
	reJSFSSink        = regexp.MustCompile(`\bfs\.(readFile|writeFile|createReadStream|createWriteStream|open|appendFile|unlink|stat|access|copyFile)\s*\(`)
	// CWE-1336: server-side template injection sinks
	reJSTemplateSink  = regexp.MustCompile(`\bejs\.render(?:File)?\s*\(|\bpug\.render(?:File)?\s*\(|\bnunjucks\.renderString\s*\(|\bHandlebars\.compile\s*\(`)
	// CWE-347: JWT algorithm:none and missing algorithms allowlist
	reJSJWTNone       = regexp.MustCompile(`(?i)algorithm\s*[:=]\s*["']none["']`)
	reJSJWTVerify     = regexp.MustCompile(`\bjwt\.verify\s*\(`)
	reJSJWTAlgorithms = regexp.MustCompile(`\balgorithms\s*:`)
	// CWE-916: fast hash (sha256/sha512) used in password context
	reJSFastHashSink = regexp.MustCompile(`\bcrypto\.createHash\s*\(\s*["'](sha256|sha512|sha384|sha3)["']`)
	// CWE-913: setTimeout/setInterval with a string literal (eval-equivalent)
	reJSSetTimeoutStr = regexp.MustCompile(`\b(?:setTimeout|setInterval)\s*\(\s*["'` + "`" + `]`)
	// CWE-770: express.json()/bodyParser.json() called with no options (no limit)
	reJSBodyParserNoLimit = regexp.MustCompile(`\b(?:express\.json|express\.urlencoded|bodyParser\.json|bodyParser\.urlencoded)\s*\(\s*\)`)
	// CWE-400 / CWE-1299: express() initialisation helpers
	reJSExpressInit = regexp.MustCompile(`\bexpress\s*\(\s*\)`)
	reJSRateLimit   = regexp.MustCompile(`(?i)(express-rate-limit|rateLimit|rate.limit|slowDown|throttle)`)
	reJSHelmet      = regexp.MustCompile(`\bhelmet\s*\(|require\s*\(\s*["']helmet["']\s*\)|from\s+["']helmet["']`)
	// multer size-limit guard
	reJSMullerLimits = regexp.MustCompile(`\blimits\s*:|\bfileSize\s*:`)
	// explicit security header fallback for helmet check
	reJSSecHeader = regexp.MustCompile(`Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security`)
)

func init() {
	security.Default.RegisterRule(reRule(
		"javascript.eval", "Dynamic Code Execution", "unsafe_exec", security.SevHigh, tsLangs,
		reJSEval,
		"eval() and new Function() execute strings as code; with any untrusted input this is an "+
			"injection vector. Parse data with JSON.parse and model behavior with explicit functions.",
	).WithCWE("94"))
	security.Default.RegisterRule(reRule(
		"javascript.dom_xss", "DOM XSS Sink", "io_validation", security.SevMedium, tsLangs,
		reJSDangerHTML,
		"Assigning unsanitized strings to innerHTML / dangerouslySetInnerHTML / document.write "+
			"injects markup and enables cross-site scripting. Render text nodes or sanitize with a "+
			"vetted library (e.g. DOMPurify).",
	).WithCWE("79"))
	security.Default.RegisterRule(reRule(
		"javascript.insecure_transport", "Insecure Transport", "network_security", security.SevMedium, tsLangs,
		reJSTransport,
		"Cleartext http:// endpoints expose requests to interception and tampering. Use https:// "+
			"for all remote calls.",
		insecureURLSkips...,
	).WithCWE("319"))
	security.Default.RegisterRule(reRule(
		"javascript.prototype_pollution", "Prototype Pollution", "io_validation", security.SevHigh, tsLangs,
		reJSProtoPollute,
		"Assigning to __proto__ or merging untrusted input into an object with Object.assign can "+
			"modify the prototype of every object in the process, enabling denial-of-service or "+
			"property-injection attacks. Validate and sanitize input before merging; use Object.create(null) "+
			"for dictionaries.",
	).WithCWE("1321"))
	security.Default.RegisterRule(reRule(
		"javascript.insecure_cookie", "Cookie Without Secure Flags", "session_mgmt", security.SevMedium, tsLangs,
		reJSInsecureCookie,
		"Cookies set via document.cookie are accessible to JavaScript and sent over cleartext "+
			"connections unless the Secure and HttpOnly flags are added. Prefer server-side "+
			"Set-Cookie headers with Secure; HttpOnly; SameSite=Strict for session tokens.",
	).WithCWE("1004"))
	security.Default.RegisterRule(reRule(
		"javascript.cors_wildcard", "CORS Wildcard Origin", "network_security", security.SevMedium, tsLangs,
		reJSCORSWildcard,
		"Setting Access-Control-Allow-Origin: * or cors({ origin: '*' }) allows any domain to "+
			"make credentialed cross-origin requests. Restrict the allowed origin to an explicit "+
			"allowlist instead of using a wildcard.",
	).WithCWE("942"))
	security.Default.RegisterRule(jsNoSQLInjectionRule())
	security.Default.RegisterRule(jsInsecureStorageRule())
	security.Default.RegisterRule(twoReRule(
		"javascript.node_command_injection", "Node.js Command Injection", "injection", security.SevHigh, tsLangs,
		reJSChildProcSink, reJSChildProcConcat,
		"child_process.exec / spawn is called with a string assembled from user input or "+
			"template literals. An attacker can break out of the command and execute arbitrary "+
			"shell commands. Pass arguments as an array and never pass user input through a "+
			"shell interpreter. (CWE-78)",
	).WithCWE("78").WithSkipTests())
	security.Default.RegisterRule(twoReRule(
		"javascript.sql_concat", "SQL Injection via Concatenation", "injection", security.SevHigh, tsLangs,
		reJSSQLSink, reJSSQLConcat,
		"A database query method (.query, .execute, .raw) is called with a string assembled "+
			"via concatenation, template literals, or direct request data. Use parameterized "+
			"queries or an ORM query builder to prevent SQL injection. (CWE-89)",
	).WithCWE("89"))
	security.Default.RegisterRule(reRule(
		"javascript.reject_unauthorized_false", "TLS Certificate Validation Disabled", "network_security", security.SevHigh, tsLangs,
		reJSRejectUnauth,
		"rejectUnauthorized: false disables TLS certificate validation in Node.js, making "+
			"the connection trivially vulnerable to man-in-the-middle attacks. Remove this "+
			"option or set it to true. (CWE-295)",
	).WithCWE("295").WithSkipTests())
	security.Default.RegisterRule(twoReRule(
		"javascript.math_random_security", "Math.random in Security Context", "cryptography", security.SevMedium, tsLangs,
		reJSMathRandom, reSensitiveData,
		"Math.random() is not cryptographically secure and must not be used to generate "+
			"tokens, keys, nonces or any security-sensitive values. Use "+
			"crypto.randomBytes() or crypto.getRandomValues() instead. (CWE-338)",
	).WithCWE("338"))
	security.Default.RegisterRule(twoReRule(
		"javascript.sensitive_logging", "Sensitive Data in Logs", "data_exposure", security.SevMedium, tsLangs,
		reJSConsoleSink, reSensitiveData,
		"A console.log/error/debug call references a password, token or credential. Browser "+
			"and server logs are often captured and forwarded to external systems. Redact or "+
			"omit sensitive values before logging. (CWE-532)",
	).WithCWE("532"))
	security.Default.RegisterRule(jsResCookieNoSecureRule())
	security.Default.RegisterRule(jsResCookieNoSameSiteRule())
	security.Default.RegisterRule(jsUnrestrictedFileUploadRule())
	security.Default.RegisterRule(reRule(
		"javascript.weak_crypto", "Weak Cryptography (Node.js)", "cryptography", security.SevHigh, tsLangs,
		reJSWeakCrypto,
		"crypto.createHash('md5') and crypto.createHash('sha1') produce digests that are "+
			"cryptographically broken. Use 'sha256' or stronger for integrity, and a password "+
			"KDF (bcrypt, scrypt, argon2) for credential storage. (CWE-327)",
	).WithCWE("327"))
	security.Default.RegisterRule(twoReRule(
		"javascript.path_traversal", "Path Traversal", "io_validation", security.SevHigh, tsLangs,
		reJSFSSink, reJSNoSQLSource,
		"A Node.js fs call uses a path derived from req.body/params/query without sanitization. "+
			"An attacker can supply \"../\" sequences to read or overwrite arbitrary files. "+
			"Use path.resolve and verify the result starts with the allowed base directory. (CWE-22)",
	).WithCWE("22"))
	security.Default.RegisterRule(twoReRule(
		"javascript.ssti", "Server-Side Template Injection", "injection", security.SevHigh, tsLangs,
		reJSTemplateSink, reJSNoSQLSource,
		"A template engine (EJS, Pug, Nunjucks, Handlebars) is invoked with content derived "+
			"from req.body/params/query. An attacker can inject template directives to execute "+
			"arbitrary code server-side. Never pass raw user input to template rendering functions; "+
			"use safe data-binding instead. (CWE-1336)",
	).WithCWE("1336"))
	security.Default.RegisterRule(reRule(
		"javascript.jwt_alg_none", "JWT Algorithm None", "authentication", security.SevHigh, tsLangs,
		reJSJWTNone,
		"algorithm: 'none' disables JWT signature verification entirely, allowing an attacker "+
			"to forge tokens by stripping the signature. Always specify a strong signing algorithm "+
			"(RS256, ES256, HS256) and reject tokens with algorithm 'none'. (CWE-347)",
	).WithCWE("347"))
	security.Default.RegisterRule(jsJWTNoAlgorithmsRule())
	security.Default.RegisterRule(credentialRule("javascript.hardcoded_credentials", tsLangs,
		"A credential-naming variable is assigned a string literal. Hardcoded secrets are "+
			"committed to history permanently. Load credentials from process.env or a secret "+
			"manager at runtime. (CWE-798)"))
	security.Default.RegisterRule(twoReRule(
		"javascript.fast_hash_for_password", "Fast Hash Used for Password", "cryptography", security.SevHigh, tsLangs,
		reJSFastHashSink, reSensitiveData,
		"crypto.createHash('sha256'/'sha512') is used in a context that suggests password "+
			"hashing. Fast hashes can be brute-forced at billions of attempts per second. "+
			"Use bcrypt, scrypt or argon2 (e.g. bcryptjs, argon2 npm packages) for "+
			"credential storage. (CWE-916)",
	).WithCWE("916"))
	security.Default.RegisterRule(twoReRule(
		"javascript.open_redirect", "Open Redirect", "session_mgmt", security.SevMedium, tsLangs,
		reJSRedirectSink, reJSNoSQLSource,
		"res.redirect() is called with a URL derived from req.body/params/query. An attacker can "+
			"supply an off-site URL to redirect victims to a phishing page. Validate the target "+
			"against an explicit allowlist or ensure it is a safe relative path. (CWE-601)",
	).WithCWE("601"))
	security.Default.RegisterRule(twoReRule(
		"javascript.log_injection", "Log Injection", "data_exposure", security.SevMedium, tsLangs,
		reJSConsoleSink, reJSNoSQLSource,
		"A console.log/error/debug/warn call writes a value derived from req.body/params/query. "+
			"An attacker can inject CRLF sequences (\\r\\n) to forge log entries in server-side "+
			"logging pipelines. Sanitize or encode user input before logging. (CWE-117)",
	).WithCWE("117"))
	security.Default.RegisterRule(twoReRule(
		"javascript.ssrf", "Server-Side Request Forgery", "io_validation", security.SevHigh, tsLangs,
		reJSFetchSink, reJSNoSQLSource,
		"A user-controlled value (req.body/params/query) is passed directly to fetch, axios "+
			"or http.get. An attacker can redirect the request to internal services or cloud "+
			"metadata endpoints. Validate and allowlist target URLs. (CWE-918)",
	).WithCWE("918"))
	security.Default.RegisterRule(jsEvalSetTimeoutRule())
	security.Default.RegisterRule(jsBodyParserNoLimitRule())
	security.Default.RegisterRule(jsMullerNoFileSizeRule())
	security.Default.RegisterRule(jsNoRateLimitRule())
	security.Default.RegisterRule(jsNoHelmetRule())
}

// jsEvalSetTimeoutRule fires when setTimeout or setInterval is called with a
// string literal as the first argument — a direct eval() equivalent that executes
// the string as JavaScript at runtime.
func jsEvalSetTimeoutRule() security.Rule {
	return security.Rule{
		ID:        "javascript.eval_settimeout",
		Name:      "eval-Equivalent in setTimeout / setInterval",
		Severity:  security.SevHigh,
		Category:  "unsafe_exec",
		CWE:       "913",
		Languages: tsLangs,
		Description: "setTimeout(\"code\") and setInterval(\"code\") evaluate the string argument " +
			"as JavaScript, identical to eval(). If any part of the string is user-controlled " +
			"this is remote code execution. Pass a function reference instead: " +
			"setTimeout(() => doWork(), delay). (CWE-913)",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reJSSetTimeoutStr.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// jsBodyParserNoLimitRule fires when express.json() / bodyParser.json() is
// called with no arguments — accepting requests of unlimited size, which enables
// memory-exhaustion DoS attacks via large JSON payloads.
func jsBodyParserNoLimitRule() security.Rule {
	return security.Rule{
		ID:        "javascript.body_no_size_limit",
		Name:      "Request Body Parser Without Size Limit",
		Severity:  security.SevMedium,
		Category:  "crash_factors",
		CWE:       "770",
		Languages: tsLangs,
		Description: "express.json() / express.urlencoded() / bodyParser.json() is called with no " +
			"options. Without a limit: option an attacker can send arbitrarily large request " +
			"bodies and exhaust server memory. Pass { limit: '1mb' } (or your chosen cap). (CWE-770)",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reJSBodyParserNoLimit.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// jsMullerNoFileSizeRule fires when multer is initialised without a limits.fileSize
// cap — allowing unlimited file uploads that can exhaust disk space or memory.
func jsMullerNoFileSizeRule() security.Rule {
	return security.Rule{
		ID:        "javascript.multer_no_filesize_limit",
		Name:      "File Upload Without fileSize Limit",
		Severity:  security.SevMedium,
		Category:  "crash_factors",
		CWE:       "770",
		Languages: tsLangs,
		Description: "multer() is initialised without a limits.fileSize constraint. Without it " +
			"clients can upload files of any size, exhausting server disk or memory. Pass " +
			"{ limits: { fileSize: 5 * 1024 * 1024 } } (or your chosen cap). (CWE-770)",
		Detect: func(filePath string, lines []string) []security.Finding {
			multerLine := -1
			hasLimit := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reJSMulterInit.MatchString(line) && multerLine == -1 {
					multerLine = i
				}
				if reJSMullerLimits.MatchString(line) {
					hasLimit = true
				}
			}
			if multerLine >= 0 && !hasLimit {
				return []security.Finding{security.NewFinding(filePath, multerLine, lines)}
			}
			return nil
		},
	}
}

// jsNoRateLimitRule fires when a file initialises an Express application but
// imports no rate-limiting middleware — leaving all endpoints open to brute-force
// and resource-exhaustion attacks.
func jsNoRateLimitRule() security.Rule {
	return security.Rule{
		ID:        "javascript.no_rate_limit",
		Name:      "Express App Without Rate Limiting",
		Severity:  security.SevMedium,
		Category:  "crash_factors",
		CWE:       "400",
		Languages: tsLangs,
		Description: "An Express application is initialised (express()) without any rate-limiting " +
			"middleware in the file (express-rate-limit, rateLimit, slowDown, throttle). " +
			"Without rate limiting authentication endpoints and public APIs are vulnerable to " +
			"brute-force and denial-of-service attacks. Apply rateLimit() as global or " +
			"per-route middleware. (CWE-400)",
		Detect: func(filePath string, lines []string) []security.Finding {
			if security.IsTestPath(filePath) {
				return nil
			}
			appLine := -1
			hasRateLimit := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reJSExpressInit.MatchString(line) && appLine == -1 {
					appLine = i
				}
				if reJSRateLimit.MatchString(line) {
					hasRateLimit = true
				}
			}
			if appLine >= 0 && !hasRateLimit {
				return []security.Finding{security.NewFinding(filePath, appLine, lines)}
			}
			return nil
		},
	}
}

// jsNoHelmetRule fires when a file initialises an Express application but does
// not import or call helmet() — leaving the app without the standard set of
// security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, …).
func jsNoHelmetRule() security.Rule {
	return security.Rule{
		ID:        "javascript.no_helmet",
		Name:      "Express App Without Security Headers (helmet)",
		Severity:  security.SevMedium,
		Category:  "network_security",
		CWE:       "1299",
		Languages: tsLangs,
		Description: "An Express application is created (express()) without helmet() or explicit " +
			"Content-Security-Policy / X-Frame-Options headers in the same file. helmet() sets " +
			"14 security-relevant HTTP response headers in one call. Import helmet and add " +
			"app.use(helmet()) early in the middleware chain. (CWE-1299)",
		Detect: func(filePath string, lines []string) []security.Finding {
			if security.IsTestPath(filePath) {
				return nil
			}
			appLine := -1
			hasHelmet := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reJSExpressInit.MatchString(line) && appLine == -1 {
					appLine = i
				}
				if reJSHelmet.MatchString(line) || reJSSecHeader.MatchString(line) {
					hasHelmet = true
				}
			}
			if appLine >= 0 && !hasHelmet {
				return []security.Finding{security.NewFinding(filePath, appLine, lines)}
			}
			return nil
		},
	}
}

// jsJWTNoAlgorithmsRule fires when a file calls jwt.verify() but never specifies
// an algorithms allowlist. Without it the library accepts any algorithm the
// attacker claims in the header, enabling alg-confusion attacks.
func jsJWTNoAlgorithmsRule() security.Rule {
	return security.Rule{
		ID:        "javascript.jwt_no_algorithms",
		Name:      "JWT verify Without algorithms Allowlist",
		Severity:  security.SevHigh,
		Category:  "authentication",
		CWE:       "347",
		Languages: tsLangs,
		Description: "jwt.verify() is called without an algorithms option anywhere in the file. " +
			"Without an explicit allowlist the library accepts whichever algorithm the token " +
			"header claims, enabling RS/HS confusion and algorithm-substitution attacks. " +
			"Pass { algorithms: ['HS256'] } (or your chosen algorithm) to jwt.verify(). (CWE-347)",
		Detect: func(filePath string, lines []string) []security.Finding {
			verifyLine := -1
			hasAlgorithms := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reJSJWTVerify.MatchString(line) && verifyLine == -1 {
					verifyLine = i
				}
				if reJSJWTAlgorithms.MatchString(line) {
					hasAlgorithms = true
				}
			}
			if verifyLine >= 0 && !hasAlgorithms {
				return []security.Finding{security.NewFinding(filePath, verifyLine, lines)}
			}
			return nil
		},
	}
}

// jsResCookieNoSameSiteRule flags res.cookie() calls without sameSite: on the
// same line. Multi-line option objects will produce a false positive at the
// opening call — treat findings as an audit prompt.
func jsResCookieNoSameSiteRule() security.Rule {
	return security.Rule{
		ID:        "javascript.cookie_no_samesite",
		Name:      "Cookie Missing SameSite Attribute",
		Severity:  security.SevMedium,
		Category:  "session_mgmt",
		CWE:       "352",
		Languages: tsLangs,
		Description: "res.cookie() is called without a sameSite option. Without SameSite the " +
			"cookie is included in cross-site requests, enabling CSRF attacks. Pass " +
			"{ sameSite: 'Strict', secure: true, httpOnly: true } to all session cookies. (CWE-352)",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reJSResCookieSink.MatchString(line) && !reJSSameSite.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// jsUnrestrictedFileUploadRule fires when a file initialises multer without a
// fileFilter anywhere in the same file.
func jsUnrestrictedFileUploadRule() security.Rule {
	return security.Rule{
		ID:        "javascript.unrestricted_file_upload",
		Name:      "Unrestricted File Upload",
		Severity:  security.SevHigh,
		Category:  "io_validation",
		CWE:       "434",
		Languages: tsLangs,
		Description: "multer() is initialised without a fileFilter function in the same file. " +
			"Without fileFilter any file type is accepted, allowing upload of executable files. " +
			"Add a fileFilter that validates file.mimetype against an explicit allowlist. (CWE-434)",
		Detect: func(filePath string, lines []string) []security.Finding {
			multerLine := -1
			hasFilter := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reJSMulterInit.MatchString(line) && multerLine == -1 {
					multerLine = i
				}
				if reJSFileFilter.MatchString(line) {
					hasFilter = true
				}
			}
			if multerLine >= 0 && !hasFilter {
				return []security.Finding{security.NewFinding(filePath, multerLine, lines)}
			}
			return nil
		},
	}
}

// jsResCookieNoSecureRule flags Express res.cookie() calls without secure: true.
func jsResCookieNoSecureRule() security.Rule {
	return security.Rule{
		ID:        "javascript.cookie_no_secure",
		Name:      "Cookie Missing Secure Flag",
		Severity:  security.SevMedium,
		Category:  "session_mgmt",
		CWE:       "614",
		Languages: tsLangs,
		Description: "res.cookie() is called without secure: true. Without the Secure flag the " +
			"cookie is transmitted over cleartext HTTP, exposing session tokens to interception. " +
			"Set { secure: true, httpOnly: true, sameSite: 'Strict' } on all auth cookies.",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reJSResCookieSink.MatchString(line) && !reJSCookieSecure.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// jsNoSQLInjectionRule detects MongoDB query calls that directly use request
// parameters (req.body, req.params, req.query) on the same line — the classic
// NoSQL injection vector.
func jsNoSQLInjectionRule() security.Rule {
	return security.Rule{
		ID:        "javascript.nosql_injection",
		Name:      "NoSQL Injection Risk",
		Severity:  security.SevHigh,
		Category:  "injection",
		CWE:       "943",
		Languages: tsLangs,
		Description: "A MongoDB query method (findOne, updateOne, deleteOne, etc.) is called " +
			"with a value derived directly from the request (req.body/params/query). " +
			"Unsanitized operator injection ($where, $gt, $regex) can bypass authentication " +
			"or exfiltrate data. Validate and sanitize request input before using it in " +
			"query filters. (CWE-943)",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reJSNoSQLSink.MatchString(line) && reJSNoSQLSource.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// jsInsecureStorageRule flags sensitive data (passwords, tokens, API keys) being
// stored in localStorage or sessionStorage, which is unencrypted and readable by
// any script on the same origin — a common XSS post-exploitation target.
func jsInsecureStorageRule() security.Rule {
	return security.Rule{
		ID:        "javascript.insecure_storage",
		Name:      "Sensitive Data in Web Storage",
		Severity:  security.SevHigh,
		Category:  "data_exposure",
		CWE:       "922",
		Languages: tsLangs,
		Description: "localStorage.setItem / sessionStorage.setItem is called with a key that " +
			"suggests sensitive data (password, token, API key, credential). Web Storage is " +
			"unencrypted and accessible to any JavaScript on the same origin — an XSS " +
			"vulnerability immediately exposes the stored value. Store secrets in HttpOnly " +
			"cookies or a secure in-memory store. (CWE-922)",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reJSStorageSink.MatchString(line) && reJSStorageSensKey.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}
