package lang

import (
	"regexp"

	"github.com/exey/archscope/internal/security"
)

// Python-only security rules: code-execution sinks, unsafe deserialization,
// shell injection, weak hashing, os.system, and debug-mode flags.
// Gated by Languages:["python"].
var pythonLangs = []string{"python"}

var (
	rePyEval              = regexp.MustCompile(`\b(eval|exec)\s*\(`)
	rePyPickle            = regexp.MustCompile(`\b(cPickle|pickle)\s*\.\s*loads?\s*\(`)
	rePyYAML              = regexp.MustCompile(`\byaml\s*\.\s*load\s*\(`)
	rePyShell             = regexp.MustCompile(`shell\s*=\s*True`)
	rePyWeakHash          = regexp.MustCompile(`\bhashlib\s*\.\s*(md5|sha1)\s*\(`)
	rePyOsSystem          = regexp.MustCompile(`\bos\.system\s*\(`)
	rePyDebugMode         = regexp.MustCompile(`\bDEBUG\s*=\s*True|\bapp\.run\s*\([^)]*\bdebug\s*=\s*True`)
	rePyUnverifiedSSL     = regexp.MustCompile(`ssl\._create_unverified_context|verify\s*=\s*False`)
	// Django middleware — file-level helpers
	rePyIsSettings        = regexp.MustCompile(`(?i)\bsettings\b`)
	rePyMiddlewareBlock   = regexp.MustCompile(`^MIDDLEWARE(?:_CLASSES)?\s*=`)
	rePyDjangoSecurityMW  = regexp.MustCompile(`SecurityMiddleware|XFrameOptionsMiddleware`)
	// new coverage
	rePyFileSink     = regexp.MustCompile(`\b(open\s*\(|os\.path\.(join|abspath)\s*\(|pathlib\.Path\s*\()`)
	rePyWebInput     = regexp.MustCompile(`request\.(GET|POST|args|form|json|data|params)\b|request\.get\s*\(`)
	rePySQLSink      = regexp.MustCompile(`\b(cursor|conn|connection|db)\s*\.\s*(execute|executemany|executescript)\s*\(`)
	rePySQLConcat    = regexp.MustCompile(`\+\s*["'\w]|["'\w]\s*\+|%\s*\w|\.format\s*\(`)
	rePyWeakRandom   = regexp.MustCompile(`\brandom\.(randint|random|choice|randrange|sample|shuffle)\s*\(`)
	rePyLogSink      = regexp.MustCompile(`\b(logging\.(info|debug|warning|error|critical|exception)|print)\s*\(`)
	rePyXXE          = regexp.MustCompile(`\b(xml\.etree\.ElementTree\.(parse|fromstring)|minidom\.parse|lxml\.etree\.(parse|fromstring))\s*\(`)
	rePyHTTPSink     = regexp.MustCompile(`\brequests\.(get|post|put|delete|head|patch)\s*\(|\burllib(\.(request))?\.urlopen\s*\(`)
	// CWE-352: set_cookie without samesite= on the same line
	rePySetCookie    = regexp.MustCompile(`\.set_cookie\s*\(`)
	rePySameSiteParam = regexp.MustCompile(`(?i)samesite\s*=`)
	// CWE-434: file upload sinks and type-validation guard
	rePyFileUploadSink = regexp.MustCompile(`request\.files\b|request\.FILES\b`)
	rePyFileTypeCheck  = regexp.MustCompile(`(?i)(secure_filename|\.content_type\b|\.mimetype\b|allowed_extensions|ALLOWED_EXTENSIONS|validate.*file|file.*valid|file.*type|check.*ext|imghdr|filetype|validate_upload|validate_file|allowed_mime)`)
	// CWE-601: open redirect sink (Flask redirect / Django HttpResponseRedirect)
	rePyRedirectSink = regexp.MustCompile(`\bredirect\s*\(|HttpResponseRedirect\s*\(`)
	// CWE-1336: server-side template injection sinks
	rePySSTISink     = regexp.MustCompile(`\brender_template_string\s*\(|\bTemplate\s*\(\s*f["']|\benv\.from_string\s*\(|\bJinja2\s*\(\s*f["']`)
	// CWE-732: broad file permissions
	rePyChmod        = regexp.MustCompile(`\bos\.chmod\s*\(`)
	rePyWidePerms    = regexp.MustCompile(`\b(0o?777|0o?666|0o?776|0o?757)\b`)
	// CWE-916: fast hash applied to password-named value (not a KDF)
	rePyFastHashSink = regexp.MustCompile(`\bhashlib\.(sha256|sha512|sha3_256|sha3_512|blake2b|blake2s)\s*\(`)
	// CWE-22 variant: zip/tar extraction without path validation (zip-slip)
	rePyExtractAll   = regexp.MustCompile(`\.extractall\s*\(`)
	// CWE-943: MongoDB $where operator with user input (server-side JS execution)
	rePyMongoWhere   = regexp.MustCompile(`["']\$where["']`)
	// CWE-362: TOCTOU race condition helpers
	rePyTOCTOUCheck = regexp.MustCompile(`\bos\.path\.(exists|isfile|isdir)\s*\(`)
	rePyTOCTOUUse   = regexp.MustCompile(`\bos\.(makedirs|mkdir)\s*\(`)
	rePyTOCTOUGuard = regexp.MustCompile(`exist_ok\s*=\s*True|tempfile\.|os\.O_EXCL\b`)
	// CWE-347: PyJWT algorithm:none and missing algorithms parameter
	rePyJWTNoneAlg   = regexp.MustCompile(`(?i)algorithm\s*=\s*["']none["']|algorithms\s*=\s*\[\s*["']none["']`)
	rePyJWTDecode    = regexp.MustCompile(`\bjwt\.decode\s*\(`)
	rePyJWTAlgorithms = regexp.MustCompile(`\balgorithms\s*=`)
)

func init() {
	security.Default.RegisterRule(reRule(
		"python.eval_exec", "Dynamic Code Execution", "unsafe_exec", security.SevHigh, pythonLangs,
		rePyEval,
		"eval()/exec() run arbitrary code; with any user-influenced input this is remote code "+
			"execution. Use ast.literal_eval for data, or an explicit dispatch table for behavior.",
		"literal_eval",
	).WithCWE("94"))
	security.Default.RegisterRule(reRule(
		"python.insecure_deserialization", "Insecure Deserialization", "unsafe_deprecated", security.SevMedium, pythonLangs,
		rePyPickle,
		"pickle.load/loads executes constructors from the byte stream and can run attacker code. "+
			"Use JSON or another safe format for untrusted data.",
	).WithCWE("502"))
	security.Default.RegisterRule(reRule(
		"python.unsafe_yaml", "Unsafe YAML Load", "unsafe_deprecated", security.SevMedium, pythonLangs,
		rePyYAML,
		"yaml.load with the default loader can instantiate arbitrary Python objects. Use "+
			"yaml.safe_load (or Loader=SafeLoader) for untrusted input.",
		"safe", "safeloader",
	).WithCWE("502"))
	security.Default.RegisterRule(reRule(
		"python.shell_injection", "Shell Injection Risk", "injection", security.SevHigh, pythonLangs,
		rePyShell,
		"subprocess(..., shell=True) interpolates the command into a shell; concatenated input "+
			"enables command injection. Pass an argument list and keep shell=False.",
	).WithCWE("78").WithSkipTests())
	security.Default.RegisterRule(reRule(
		"python.weak_crypto", "Weak Cryptography", "cryptography", security.SevHigh, pythonLangs,
		rePyWeakHash,
		"MD5 and SHA-1 are broken for security use. Use hashlib.sha256 (or stronger) and a "+
			"password KDF (bcrypt/scrypt/argon2) for credentials.",
	).WithCWE("328"))
	security.Default.RegisterRule(reRule(
		"python.os_system", "Shell Command via os.system", "injection", security.SevHigh, pythonLangs,
		rePyOsSystem,
		"os.system() passes the command string to the shell, enabling injection if any part is "+
			"derived from user input. Use subprocess.run with a list of arguments and "+
			"shell=False instead.",
	).WithCWE("78").WithSkipTests())
	security.Default.RegisterRule(reRule(
		"python.debug_mode", "Debug Mode Enabled", "platform_config", security.SevMedium, pythonLangs,
		rePyDebugMode,
		"DEBUG=True (Django) or app.run(debug=True) (Flask) enables the interactive debugger, "+
			"detailed tracebacks and automatic reloading in production — all of which expose "+
			"internal state and enable remote code execution. Disable debug mode before deploying.",
	).WithCWE("489"))
	security.Default.RegisterRule(reRule(
		"python.unverified_ssl", "SSL Certificate Verification Disabled", "network_security", security.SevHigh, pythonLangs,
		rePyUnverifiedSSL,
		"ssl._create_unverified_context() or verify=False disables TLS certificate validation, "+
			"making the connection vulnerable to man-in-the-middle attacks. Use "+
			"ssl.create_default_context() and keep verify=True (the default).",
		"#", "comment",
	).WithCWE("295").WithSkipTests())
	security.Default.RegisterRule(pythonDjangoSecurityMWRule())
	security.Default.RegisterRule(twoReRule(
		"python.path_traversal", "Path Traversal", "io_validation", security.SevHigh, pythonLangs,
		rePyFileSink, rePyWebInput,
		"A file-system call (open, os.path.join) uses a value derived from request data. "+
			"An attacker can inject \"../\" to escape the intended directory. Use "+
			"os.path.realpath and verify the result starts with the allowed root. (CWE-22)",
	).WithCWE("22"))
	security.Default.RegisterRule(twoReRule(
		"python.sql_concat", "SQL Injection via Concatenation", "injection", security.SevHigh, pythonLangs,
		rePySQLSink, rePySQLConcat,
		"cursor.execute / connection.execute is called with a query assembled via string "+
			"concatenation or % / .format() formatting. Use parameterized queries with ? or %s "+
			"placeholders so user input is never treated as SQL. (CWE-89)",
	).WithCWE("89"))
	security.Default.RegisterRule(twoReRule(
		"python.weak_random", "Weak Random for Security Context", "cryptography", security.SevMedium, pythonLangs,
		rePyWeakRandom, reSensitiveData,
		"random.randint / random.choice / random.random is used in a context that suggests "+
			"security-sensitive output (token, key, nonce). The random module is not "+
			"cryptographically secure. Use secrets.token_bytes() or secrets.token_hex() "+
			"for cryptographic material. (CWE-338)",
	).WithCWE("338"))
	security.Default.RegisterRule(twoReRule(
		"python.sensitive_logging", "Sensitive Data in Logs", "data_exposure", security.SevMedium, pythonLangs,
		rePyLogSink, reSensitiveData,
		"A logging call (logging.*, print) references a password, token or credential. "+
			"Log files are often stored in plain text and forwarded to external aggregators. "+
			"Redact or omit sensitive values before logging. (CWE-532)",
	).WithCWE("532"))
	security.Default.RegisterRule(reRule(
		"python.xxe", "XML External Entity (XXE)", "unsafe_exec", security.SevHigh, pythonLangs,
		rePyXXE,
		"xml.etree.ElementTree, minidom and lxml parse XML without disabling external entity "+
			"expansion by default. An attacker can use XXE to read local files or trigger "+
			"SSRF. Use defusedxml for all untrusted XML input. (CWE-611)",
	).WithCWE("611"))
	security.Default.RegisterRule(twoReRule(
		"python.ssrf", "Server-Side Request Forgery", "io_validation", security.SevHigh, pythonLangs,
		rePyHTTPSink, rePyWebInput,
		"A user-controlled value from the request is passed directly to requests.get / "+
			"urlopen. An attacker can redirect the request to internal services or cloud "+
			"metadata endpoints. Validate and allowlist target URLs. (CWE-918)",
	).WithCWE("918"))
	security.Default.RegisterRule(credentialRule("python.hardcoded_credentials", pythonLangs,
		"A credential-naming variable is assigned a string literal. Hardcoded secrets are "+
			"committed to history permanently. Load credentials from environment variables "+
			"or a secret manager (e.g. os.environ, python-dotenv). (CWE-798)"))
	security.Default.RegisterRule(reRule(
		"python.jwt_alg_none", "JWT Algorithm None", "authentication", security.SevHigh, pythonLangs,
		rePyJWTNoneAlg,
		"algorithm='none' disables JWT signature verification, allowing an attacker to forge "+
			"tokens. Always specify a strong algorithm (HS256, RS256, ES256) and never accept 'none'. (CWE-347)",
	).WithCWE("347"))
	security.Default.RegisterRule(pythonJWTNoAlgorithmsRule())
	security.Default.RegisterRule(pythonCookieNoSameSiteRule())
	security.Default.RegisterRule(pythonUnrestrictedFileUploadRule())
	security.Default.RegisterRule(twoReRule(
		"python.ssti", "Server-Side Template Injection", "injection", security.SevHigh, pythonLangs,
		rePySSTISink, rePyWebInput,
		"render_template_string() or Jinja2 Template() is called with content derived from "+
			"request data. An attacker can inject template expressions ({{ config }}, "+
			"{{ ''.__class__.__mro__ }}) to read secrets or achieve RCE. Never pass "+
			"user-controlled strings to template rendering; use safe data-binding instead. (CWE-1336)",
	).WithCWE("1336"))
	security.Default.RegisterRule(twoReRule(
		"python.insecure_file_permissions", "Broad File Permissions", "io_validation", security.SevMedium, pythonLangs,
		rePyChmod, rePyWidePerms,
		"os.chmod() is called with a mode that grants world-write or world-read access "+
			"(0o777, 0o666, 0o776, 0o757). Overly permissive modes expose files to tampering "+
			"or information disclosure. Use the minimum necessary permissions (e.g. 0o600 "+
			"for private files, 0o644 for public-read). (CWE-732)",
	).WithCWE("732"))
	security.Default.RegisterRule(twoReRule(
		"python.fast_hash_for_password", "Fast Hash Used for Password", "cryptography", security.SevHigh, pythonLangs,
		rePyFastHashSink, reSensitiveData,
		"hashlib.sha256/sha512/blake2 is used in a context that suggests password hashing. "+
			"Fast general-purpose hashes are not suitable for storing passwords — they can be "+
			"brute-forced at billions of attempts per second. Use bcrypt, scrypt or argon2 "+
			"(passlib, argon2-cffi) for credential storage. (CWE-916)",
	).WithCWE("916"))
	security.Default.RegisterRule(reRule(
		"python.zip_slip", "Zip-Slip / Archive Path Traversal", "unsafe_exec", security.SevHigh, pythonLangs,
		rePyExtractAll,
		"tarfile.extractall() / ZipFile.extractall() extracts every archive entry to the "+
			"destination without checking for directory-traversal sequences (\"../\") in entry "+
			"names. A malicious archive can overwrite arbitrary files on the server. Iterate "+
			"entries manually and reject any whose resolved path escapes the target directory. (CWE-22)",
	).WithCWE("22"))
	security.Default.RegisterRule(twoReRule(
		"python.nosql_injection", "NoSQL Injection via $where", "injection", security.SevHigh, pythonLangs,
		rePyMongoWhere, rePyWebInput,
		"A MongoDB $where operator is used on a line that also references request data. "+
			"$where executes a JavaScript expression server-side; attacker-controlled input "+
			"can read arbitrary documents or cause denial of service. Avoid $where entirely; "+
			"use standard query operators with parameterized values. (CWE-943)",
	).WithCWE("943"))
	security.Default.RegisterRule(twoReRule(
		"python.log_injection", "Log Injection", "data_exposure", security.SevMedium, pythonLangs,
		rePyLogSink, rePyWebInput,
		"A logging call writes a value derived directly from request data "+
			"(request.GET, request.POST, request.args). An attacker can inject CRLF "+
			"sequences (\\r\\n) to forge log entries or split log lines. Sanitize or encode "+
			"user input before logging. (CWE-117)",
	).WithCWE("117"))
	security.Default.RegisterRule(pythonTOCTOURule())
	security.Default.RegisterRule(twoReRule(
		"python.open_redirect", "Open Redirect", "session_mgmt", security.SevMedium, pythonLangs,
		rePyRedirectSink, rePyWebInput,
		"redirect() / HttpResponseRedirect() is called with a URL derived from request data. "+
			"An attacker can supply an off-site URL to redirect victims to a phishing page. "+
			"Validate the target against an explicit allowlist or ensure it is a safe relative path. (CWE-601)",
	).WithCWE("601"))
}

// pythonJWTNoAlgorithmsRule fires when a file calls jwt.decode() but never
// passes an algorithms= argument. Without it PyJWT accepts any algorithm the
// token header claims, enabling RS/HS confusion attacks.
func pythonJWTNoAlgorithmsRule() security.Rule {
	return security.Rule{
		ID:        "python.jwt_no_algorithms",
		Name:      "JWT decode Without algorithms Allowlist",
		Severity:  security.SevHigh,
		Category:  "authentication",
		CWE:       "347",
		Languages: pythonLangs,
		Description: "jwt.decode() is called without an algorithms= parameter anywhere in the " +
			"file. Without an explicit allowlist PyJWT accepts whichever algorithm the token " +
			"header claims, enabling algorithm-confusion attacks. Pass " +
			"algorithms=['HS256'] (or your chosen algorithm) to jwt.decode(). (CWE-347)",
		Detect: func(filePath string, lines []string) []security.Finding {
			decodeLine := -1
			hasAlgorithms := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if rePyJWTDecode.MatchString(line) && decodeLine == -1 {
					decodeLine = i
				}
				if rePyJWTAlgorithms.MatchString(line) {
					hasAlgorithms = true
				}
			}
			if decodeLine >= 0 && !hasAlgorithms {
				return []security.Finding{security.NewFinding(filePath, decodeLine, lines)}
			}
			return nil
		},
	}
}

// pythonCookieNoSameSiteRule flags set_cookie() calls without samesite= on the
// same line. Multi-line calls that set samesite= on a continuation line will
// produce a false positive — treat findings as an audit prompt.
func pythonCookieNoSameSiteRule() security.Rule {
	return security.Rule{
		ID:        "python.cookie_no_samesite",
		Name:      "Cookie Missing SameSite Attribute",
		Severity:  security.SevMedium,
		Category:  "session_mgmt",
		CWE:       "352",
		Languages: pythonLangs,
		Description: "response.set_cookie() is called without a samesite= parameter. Without " +
			"SameSite the cookie is included in cross-site requests, enabling CSRF attacks. " +
			"Pass samesite='Strict' (or 'Lax') to all session and authentication cookies. (CWE-352)",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if rePySetCookie.MatchString(line) && !rePySameSiteParam.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// pythonUnrestrictedFileUploadRule fires when a file handles uploads via
// request.files / request.FILES but has no content-type or extension validation
// anywhere in the same file.
func pythonUnrestrictedFileUploadRule() security.Rule {
	return security.Rule{
		ID:        "python.unrestricted_file_upload",
		Name:      "Unrestricted File Upload",
		Severity:  security.SevHigh,
		Category:  "io_validation",
		CWE:       "434",
		Languages: pythonLangs,
		Description: "request.files / request.FILES is accessed without any content-type, " +
			"MIME-type, or extension validation in the same file. Without validation an attacker " +
			"can upload executable files. Use werkzeug's secure_filename, check file.content_type " +
			"or file.mimetype, and restrict accepted extensions. (CWE-434)",
		Detect: func(filePath string, lines []string) []security.Finding {
			uploadLine := -1
			hasTypeCheck := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if rePyFileUploadSink.MatchString(line) && uploadLine == -1 {
					uploadLine = i
				}
				if rePyFileTypeCheck.MatchString(line) {
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

// pythonDjangoSecurityMWRule checks Django settings files for a MIDDLEWARE
// definition that is missing SecurityMiddleware or XFrameOptionsMiddleware.
// It only fires on files whose path contains "settings".
func pythonDjangoSecurityMWRule() security.Rule {
	return security.Rule{
		ID:        "python.django_no_security_middleware",
		CWE:       "16",
		Name:      "Django Missing Security Middleware",
		Severity:  security.SevMedium,
		Category:  "platform_config",
		Languages: pythonLangs,
		Description: "The Django MIDDLEWARE list does not include SecurityMiddleware or " +
			"XFrameOptionsMiddleware. SecurityMiddleware enables HSTS and other security " +
			"headers; XFrameOptionsMiddleware prevents clickjacking. Add both to MIDDLEWARE " +
			"in the correct order (SecurityMiddleware first). (CWE-16)",
		Detect: func(filePath string, lines []string) []security.Finding {
			if !rePyIsSettings.MatchString(filePath) {
				return nil
			}
			mwLine := -1
			hasSecMW := false
			for i, line := range lines {
				if rePyMiddlewareBlock.MatchString(line) && mwLine == -1 {
					mwLine = i
				}
				if rePyDjangoSecurityMW.MatchString(line) {
					hasSecMW = true
				}
			}
			if mwLine >= 0 && !hasSecMW {
				return []security.Finding{security.NewFinding(filePath, mwLine, lines)}
			}
			return nil
		},
	}
}

// pythonTOCTOURule fires when a file checks file/directory existence with
// os.path.exists/isdir/isfile and then calls os.makedirs/mkdir without
// exist_ok=True or a tempfile guard — the classic TOCTOU window.
func pythonTOCTOURule() security.Rule {
	return security.Rule{
		ID:        "python.toctou",
		Name:      "TOCTOU Race Condition",
		Severity:  security.SevMedium,
		Category:  "io_validation",
		CWE:       "362",
		Languages: pythonLangs,
		Description: "A file-system existence check (os.path.exists/isfile/isdir) is followed by " +
			"os.makedirs/mkdir in the same file without exist_ok=True or a tempfile guard. " +
			"Between the check and the create another process can create or delete the path, " +
			"leading to errors or exploitable race conditions. Use os.makedirs(path, exist_ok=True) " +
			"or handle FileExistsError atomically. (CWE-362)",
		Detect: func(filePath string, lines []string) []security.Finding {
			checkLine := -1
			hasMkdir := false
			hasGuard := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if rePyTOCTOUCheck.MatchString(line) && checkLine == -1 {
					checkLine = i
				}
				if rePyTOCTOUUse.MatchString(line) {
					hasMkdir = true
				}
				if rePyTOCTOUGuard.MatchString(line) {
					hasGuard = true
				}
			}
			if checkLine >= 0 && hasMkdir && !hasGuard {
				return []security.Finding{security.NewFinding(filePath, checkLine, lines)}
			}
			return nil
		},
	}
}
