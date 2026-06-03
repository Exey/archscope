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
)

func init() {
	security.Default.RegisterRule(reRule(
		"python.eval_exec", "Dynamic Code Execution", "io_validation", security.SevHigh, pythonLangs,
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
		"python.shell_injection", "Shell Injection Risk", "io_validation", security.SevHigh, pythonLangs,
		rePyShell,
		"subprocess(..., shell=True) interpolates the command into a shell; concatenated input "+
			"enables command injection. Pass an argument list and keep shell=False.",
	).WithCWE("78"))
	security.Default.RegisterRule(reRule(
		"python.weak_crypto", "Weak Cryptography", "cryptography", security.SevHigh, pythonLangs,
		rePyWeakHash,
		"MD5 and SHA-1 are broken for security use. Use hashlib.sha256 (or stronger) and a "+
			"password KDF (bcrypt/scrypt/argon2) for credentials.",
	).WithCWE("328"))
	security.Default.RegisterRule(reRule(
		"python.os_system", "Shell Command via os.system", "io_validation", security.SevHigh, pythonLangs,
		rePyOsSystem,
		"os.system() passes the command string to the shell, enabling injection if any part is "+
			"derived from user input. Use subprocess.run with a list of arguments and "+
			"shell=False instead.",
	).WithCWE("78"))
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
	).WithCWE("295"))
	security.Default.RegisterRule(pythonDjangoSecurityMWRule())
	security.Default.RegisterRule(twoReRule(
		"python.path_traversal", "Path Traversal", "io_validation", security.SevHigh, pythonLangs,
		rePyFileSink, rePyWebInput,
		"A file-system call (open, os.path.join) uses a value derived from request data. "+
			"An attacker can inject \"../\" to escape the intended directory. Use "+
			"os.path.realpath and verify the result starts with the allowed root. (CWE-22)",
	).WithCWE("22"))
	security.Default.RegisterRule(twoReRule(
		"python.sql_concat", "SQL Injection via Concatenation", "io_validation", security.SevHigh, pythonLangs,
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
		"python.sensitive_logging", "Sensitive Data in Logs", "insecure_data_storage", security.SevMedium, pythonLangs,
		rePyLogSink, reSensitiveData,
		"A logging call (logging.*, print) references a password, token or credential. "+
			"Log files are often stored in plain text and forwarded to external aggregators. "+
			"Redact or omit sensitive values before logging. (CWE-532)",
	).WithCWE("532"))
	security.Default.RegisterRule(reRule(
		"python.xxe", "XML External Entity (XXE)", "io_validation", security.SevHigh, pythonLangs,
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
