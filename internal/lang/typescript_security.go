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
)

func init() {
	security.Default.RegisterRule(reRule(
		"javascript.eval", "Dynamic Code Execution", "io_validation", security.SevHigh, tsLangs,
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
		"javascript.insecure_cookie", "Cookie Without Secure Flags", "authentication", security.SevMedium, tsLangs,
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
		"javascript.node_command_injection", "Node.js Command Injection", "io_validation", security.SevHigh, tsLangs,
		reJSChildProcSink, reJSChildProcConcat,
		"child_process.exec / spawn is called with a string assembled from user input or "+
			"template literals. An attacker can break out of the command and execute arbitrary "+
			"shell commands. Pass arguments as an array and never pass user input through a "+
			"shell interpreter. (CWE-78)",
	).WithCWE("78"))
	security.Default.RegisterRule(twoReRule(
		"javascript.sql_concat", "SQL Injection via Concatenation", "io_validation", security.SevHigh, tsLangs,
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
	).WithCWE("295"))
	security.Default.RegisterRule(twoReRule(
		"javascript.math_random_security", "Math.random in Security Context", "cryptography", security.SevMedium, tsLangs,
		reJSMathRandom, reSensitiveData,
		"Math.random() is not cryptographically secure and must not be used to generate "+
			"tokens, keys, nonces or any security-sensitive values. Use "+
			"crypto.randomBytes() or crypto.getRandomValues() instead. (CWE-338)",
	).WithCWE("338"))
	security.Default.RegisterRule(twoReRule(
		"javascript.sensitive_logging", "Sensitive Data in Logs", "insecure_data_storage", security.SevMedium, tsLangs,
		reJSConsoleSink, reSensitiveData,
		"A console.log/error/debug call references a password, token or credential. Browser "+
			"and server logs are often captured and forwarded to external systems. Redact or "+
			"omit sensitive values before logging. (CWE-532)",
	).WithCWE("532"))
	security.Default.RegisterRule(jsResCookieNoSecureRule())
	security.Default.RegisterRule(jsResCookieNoSameSiteRule())
	security.Default.RegisterRule(jsUnrestrictedFileUploadRule())
	security.Default.RegisterRule(twoReRule(
		"javascript.open_redirect", "Open Redirect", "io_validation", security.SevMedium, tsLangs,
		reJSRedirectSink, reJSNoSQLSource,
		"res.redirect() is called with a URL derived from req.body/params/query. An attacker can "+
			"supply an off-site URL to redirect victims to a phishing page. Validate the target "+
			"against an explicit allowlist or ensure it is a safe relative path. (CWE-601)",
	).WithCWE("601"))
	security.Default.RegisterRule(twoReRule(
		"javascript.ssrf", "Server-Side Request Forgery", "io_validation", security.SevHigh, tsLangs,
		reJSFetchSink, reJSNoSQLSource,
		"A user-controlled value (req.body/params/query) is passed directly to fetch, axios "+
			"or http.get. An attacker can redirect the request to internal services or cloud "+
			"metadata endpoints. Validate and allowlist target URLs. (CWE-918)",
	).WithCWE("918"))
}

// jsResCookieNoSameSiteRule flags res.cookie() calls without sameSite: on the
// same line. Multi-line option objects will produce a false positive at the
// opening call — treat findings as an audit prompt.
func jsResCookieNoSameSiteRule() security.Rule {
	return security.Rule{
		ID:        "javascript.cookie_no_samesite",
		Name:      "Cookie Missing SameSite Attribute",
		Severity:  security.SevMedium,
		Category:  "authentication",
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
		Category:  "authentication",
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
		Category:  "io_validation",
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
		Category:  "insecure_data_storage",
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
