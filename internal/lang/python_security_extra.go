package lang

import (
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/security"
)

// Extra Python security rules, ported from bandit's checks that the first rule
// set lacked (assert, 0.0.0.0, hardcoded /tmp, tempfile.mktemp, jinja2
// autoescape, paramiko AutoAddPolicy, requests without timeout, telnet/ftp,
// ssl.wrap_socket, marshal/shelve, SQL built with f-strings, CORS wildcards) and
// the framework-specific ones for Django and Celery. The Django rules are gated
// on the file actually mentioning Django, so a stray `mark_safe` elsewhere is
// not misread. They need string literals (paths, hosts, serializer names), so
// they read the raw line instead of reRule's string-stripped one.

var (
	rePyAssert        = regexp.MustCompile(`^\s*assert\s+\S`)
	rePyBindAll       = regexp.MustCompile(`["']0\.0\.0\.0["']`)
	rePyHardTmp       = regexp.MustCompile(`["'](?:/tmp|/var/tmp|/dev/shm)(?:/[^"']*)?["']`)
	rePyMktemp        = regexp.MustCompile(`\btempfile\.mktemp\s*\(`)
	rePyJinjaNoEsc    = regexp.MustCompile(`\bautoescape\s*=\s*False`)
	rePyParamikoAuto  = regexp.MustCompile(`set_missing_host_key_policy\s*\(\s*(?:paramiko\.)?AutoAddPolicy`)
	rePyRequestsCall  = regexp.MustCompile(`\brequests\.(?:get|post|put|delete|patch|head|request)\s*\(`)
	rePyTelnetFTP     = regexp.MustCompile(`\b(?:telnetlib\.Telnet|ftplib\.FTP)\s*\(`)
	rePySSLWrap       = regexp.MustCompile(`\bssl\.wrap_socket\s*\(`)
	rePyMarshalShelve = regexp.MustCompile(`\bmarshal\.loads?\s*\(|\bshelve\.open\s*\(`)
	rePyHashNew       = regexp.MustCompile(`\bhashlib\.new\s*\(\s*["'](?:md5|sha1|md4)["']`)
	rePySQLFString    = regexp.MustCompile(`(?i)\b(?:execute|executemany|text|raw)\s*\(\s*[rR]?f["'][^"']*\b(?:select|insert\s+into|update|delete\s+from|drop\s+table)\b[^"']*\{`)
	rePyCORSWide      = regexp.MustCompile(`\bCORS_(?:ORIGIN_)?ALLOW_ALL(?:_ORIGINS)?\s*=\s*True|\b(?:origins|CORS_ALLOWED_ORIGINS)\s*=\s*\[?\s*["']\*["']`)

	// Django
	reDjangoHint      = regexp.MustCompile(`\b(?:django|rest_framework)\b`)
	rePyMarkSafe      = regexp.MustCompile(`\bmark_safe\s*\(`)
	rePyDjangoRaw     = regexp.MustCompile(`(?:\.(?:raw|extra)|\bRawSQL)\s*\(\s*(?:[rR]?f["']|[rR]?["'](?:[^"'\\]|\\.)*["']\s*(?:%|\+|\.format\s*\()|[A-Za-z_][\w.]*\s*(?:%|\+))`)
	rePyCSRFExempt    = regexp.MustCompile(`^\s*@csrf_exempt\b`)
	rePyAllowedHosts  = regexp.MustCompile(`\bALLOWED_HOSTS\s*=\s*\[[^\]]*["']\*["']`)
	rePyInsecureCooky = regexp.MustCompile(`\b(?:SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|CSRF_COOKIE_HTTPONLY)\s*=\s*False`)
	reDjangoSecureOff = regexp.MustCompile(`\bSECURE_SSL_REDIRECT\s*=\s*False|\bSECURE_HSTS_SECONDS\s*=\s*0\b`)

	// Celery
	rePyCeleryPickle = regexp.MustCompile(`(?i)\b(?:task_serializer|result_serializer|CELERY_TASK_SERIALIZER|CELERY_RESULT_SERIALIZER)\s*=\s*["']pickle["']|\b(?:accept_content|CELERY_ACCEPT_CONTENT)\s*=\s*\[[^\]]*["']pickle["']`)
)

// pyRawRule is reRule over the raw (string-preserving) line; comment lines are skipped.
func pyRawRule(id, name, category string, sev security.Severity, re *regexp.Regexp, cwe, desc string, gate *regexp.Regexp) security.Rule {
	r := security.Rule{
		ID: id, Name: name, Severity: sev, Category: category, Languages: pythonLangs, Description: desc, CWE: cwe,
		Detect: func(filePath string, lines []string) []security.Finding {
			if gate != nil && !fileMatches(lines, gate) {
				return nil
			}
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) || !re.MatchString(line) {
					continue
				}
				out = append(out, security.NewFinding(filePath, i, lines))
			}
			return out
		},
	}
	return r
}

func fileMatches(lines []string, re *regexp.Regexp) bool {
	for _, l := range lines {
		if re.MatchString(l) {
			return true
		}
	}
	return false
}

func init() {
	security.Default.RegisterRule(pyRawRule("python.assert_used", "Assert Used for Control Flow", "platform_config", security.SevLow, rePyAssert, "703",
		"`assert` statements are removed when Python runs with -O, so any check or validation written as an assert silently disappears in optimised deployments. Raise an explicit exception for runtime checks; keep assert for tests and invariants.", nil).WithSkipTests())
	security.Default.RegisterRule(pyRawRule("python.bind_all_interfaces", "Binds to All Network Interfaces", "network_security", security.SevMedium, rePyBindAll, "605",
		"Binding to 0.0.0.0 exposes the service on every network interface, including ones you did not mean to publish on. Bind to 127.0.0.1 (or a specific interface) unless the service is meant to be reachable, and put it behind a proxy or firewall.", nil).WithSkipTests())
	security.Default.RegisterRule(pyRawRule("python.hardcoded_tmp", "Hardcoded Temporary Directory", "io_validation", security.SevMedium, rePyHardTmp, "377",
		"A fixed path under /tmp is predictable and shared, so another local user can pre-create or symlink it. Use tempfile.mkstemp / TemporaryDirectory, which create unpredictable, private paths.", nil).WithSkipTests())
	security.Default.RegisterRule(pyRawRule("python.tempfile_mktemp", "Insecure tempfile.mktemp", "io_validation", security.SevMedium, rePyMktemp, "377",
		"tempfile.mktemp only returns a name; between that and the file's creation an attacker can create it first (a race). Use tempfile.mkstemp or NamedTemporaryFile, which create the file atomically.", nil))
	security.Default.RegisterRule(pyRawRule("python.jinja2_autoescape_off", "Jinja2 Autoescape Disabled", "injection", security.SevHigh, rePyJinjaNoEsc, "79",
		"autoescape=False renders template variables without HTML escaping, so any user-controlled value becomes stored/reflected XSS. Keep autoescape on (select_autoescape) and mark individual trusted values with |safe.", nil))
	security.Default.RegisterRule(pyRawRule("python.paramiko_autoadd", "SSH Host Keys Auto-Accepted", "network_security", security.SevHigh, rePyParamikoAuto, "295",
		"AutoAddPolicy silently trusts any SSH host key, defeating protection against man-in-the-middle attacks. Load known hosts and use RejectPolicy (or pin the expected key).", nil).WithSkipTests())
	security.Default.RegisterRule(pyRawRule("python.telnet_ftp", "Cleartext Telnet / FTP", "network_security", security.SevMedium, rePyTelnetFTP, "319",
		"Telnet and FTP send credentials and data unencrypted. Use SSH/SFTP (paramiko, asyncssh) or FTPS.", nil))
	security.Default.RegisterRule(pyRawRule("python.ssl_wrap_socket", "Deprecated ssl.wrap_socket", "cryptography", security.SevMedium, rePySSLWrap, "327",
		"ssl.wrap_socket is deprecated (removed in Python 3.12) and defaults to weak, unverified settings. Use ssl.create_default_context().wrap_socket(...).", nil))
	security.Default.RegisterRule(pyRawRule("python.marshal_shelve", "Unsafe marshal / shelve", "unsafe_deprecated", security.SevMedium, rePyMarshalShelve, "502",
		"marshal.loads can execute crafted bytecode structures and shelve is pickle underneath. Never load either from an untrusted source; use JSON.", nil))
	security.Default.RegisterRule(pyRawRule("python.weak_hash_new", "Weak Hash via hashlib.new", "cryptography", security.SevHigh, rePyHashNew, "328",
		"hashlib.new('md5'/'sha1') uses a broken hash. Use sha256 or stronger, and a password KDF (bcrypt/scrypt/argon2) for credentials.", nil))
	security.Default.RegisterRule(pyRawRule("python.sql_fstring", "SQL Built with an f-string", "injection", security.SevHigh, rePySQLFString, "89",
		"A query is assembled with an f-string and passed to execute()/text()/raw(): interpolated values are not escaped, so any user-controlled value is SQL injection. Use bound parameters (`execute(sql, params)` / `text(...).bindparams(...)`).", nil).WithSkipTests())
	security.Default.RegisterRule(pyRawRule("python.cors_wildcard", "CORS Allows Any Origin", "network_security", security.SevMedium, rePyCORSWide, "942",
		"Allowing every origin lets any website call the API from a victim's browser. List the specific origins that need access; never combine a wildcard with credentials.", nil))
	security.Default.RegisterRule(twoLineRequestsTimeoutRule())

	// Django — gated on the file mentioning Django (settings-only tokens need no gate).
	security.Default.RegisterRule(pyRawRule("python.django_mark_safe", "Django mark_safe", "injection", security.SevMedium, rePyMarkSafe, "79",
		"mark_safe tells Django not to escape the string; if any part of it is user-controlled the page is open to XSS. Build markup with format_html (which escapes its arguments) instead.", reDjangoHint).WithSkipTests())
	security.Default.RegisterRule(pyRawRule("python.django_raw_sql", "Django Raw SQL with Formatting", "injection", security.SevHigh, rePyDjangoRaw, "89",
		"QuerySet.raw()/extra()/RawSQL is called with a query built by % / format / f-string / concatenation, bypassing the ORM's parameter binding. Pass values through the params argument instead.", reDjangoHint).WithSkipTests())
	security.Default.RegisterRule(pyRawRule("python.django_csrf_exempt", "Django CSRF Protection Disabled", "authentication", security.SevMedium, rePyCSRFExempt, "352",
		"@csrf_exempt turns off CSRF validation for the view; a malicious site can then submit forms as the logged-in user. Only exempt endpoints that authenticate by token and not by cookie.", reDjangoHint).WithSkipTests())
	security.Default.RegisterRule(pyRawRule("python.django_allowed_hosts_wildcard", "Django ALLOWED_HOSTS Wildcard", "platform_config", security.SevMedium, rePyAllowedHosts, "346",
		"ALLOWED_HOSTS = ['*'] disables host-header validation, enabling cache poisoning and password-reset poisoning. List the real hostnames.", nil).WithSkipTests())
	security.Default.RegisterRule(pyRawRule("python.django_insecure_cookies", "Django Cookies Not Secured", "platform_config", security.SevMedium, rePyInsecureCooky, "614",
		"Session/CSRF cookies are configured without Secure/HttpOnly, so they travel over plain HTTP or are readable by scripts. Enable them in production settings.", nil).WithSkipTests())
	security.Default.RegisterRule(pyRawRule("python.django_no_https", "Django HTTPS Redirect / HSTS Off", "platform_config", security.SevLow, reDjangoSecureOff, "319",
		"SECURE_SSL_REDIRECT = False or SECURE_HSTS_SECONDS = 0 leaves the site reachable over HTTP without HSTS. Enable both in production settings.", nil).WithSkipTests())

	// Celery
	security.Default.RegisterRule(pyRawRule("python.celery_pickle", "Celery Accepts pickle", "unsafe_deprecated", security.SevHigh, rePyCeleryPickle, "502",
		"Celery configured to serialize tasks/results with pickle (or to accept it) lets anyone who can write to the broker run arbitrary code on the workers. Use json and set accept_content=['json'].", nil).WithSkipTests())
}

// twoLineRequestsTimeoutRule flags requests.<verb>(...) calls without a timeout.
// The call may wrap, so up to 6 lines are joined to find its closing paren.
func twoLineRequestsTimeoutRule() security.Rule {
	return security.Rule{
		ID: "python.requests_no_timeout", Name: "HTTP Request Without Timeout", Severity: security.SevMedium, Category: "network_security",
		Languages: pythonLangs, CWE: "400",
		Description: "requests calls have no default timeout, so a stalled server hangs the caller forever (and a worker with it). Always pass timeout=(connect, read).",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) || !rePyRequestsCall.MatchString(line) {
					continue
				}
				call := line
				depth := 0
				for _, c := range line {
					if c == '(' {
						depth++
					} else if c == ')' {
						depth--
					}
				}
				for j := i + 1; depth > 0 && j < len(lines) && j < i+6; j++ {
					call += " " + lines[j]
					for _, c := range lines[j] {
						if c == '(' {
							depth++
						} else if c == ')' {
							depth--
						}
					}
				}
				if depth > 0 || strings.Contains(call, "timeout") || strings.Contains(call, "**") {
					continue
				}
				out = append(out, security.NewFinding(filePath, i, lines))
			}
			return out
		},
	}.WithSkipTests()
}
