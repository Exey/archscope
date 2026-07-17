package lang

import (
	"regexp"

	"github.com/exey/archscope/internal/security"
)

var cLangs = []string{"c"}

var (
	reCGets          = regexp.MustCompile(`\bgets\s*\(`)
	reCUnsafeStrCopy = regexp.MustCompile(`\b(strcpy|strcat|sprintf|vsprintf)\s*\(`)
	reCFormatString  = regexp.MustCompile(`\b(printf|fprintf|sprintf|snprintf|syslog)\s*\(\s*(?:\w+\s*,\s*)?[A-Za-z_]\w*\s*\)`)
	reCCommandInject = regexp.MustCompile(`\b(system|popen)\s*\(\s*[^")]*\)`)
	reCWeakRandom    = regexp.MustCompile(`(?i)\b(token|session|key|password|salt|nonce|otp|secret|auth)\w*\s*=\s*.*\brand\s*\(`)
	reCInsecureTmp   = regexp.MustCompile(`\b(tmpnam|mktemp|tempnam)\s*\(`)
)

func init() {
	security.Default.RegisterRule(reRule(
		"c.gets_call", "Use of gets()", "memory_corruption", security.SevHigh, cLangs,
		reCGets,
		"gets() reads a line into a buffer with no length limit and cannot be used "+
			"safely — it was removed from the C11 standard library for this reason. "+
			"Use fgets(buf, sizeof(buf), stdin) instead.",
	).WithCWE("242"))

	security.Default.RegisterRule(reRule(
		"c.unsafe_string_copy", "Unbounded String Copy", "memory_corruption", security.SevHigh, cLangs,
		reCUnsafeStrCopy,
		"strcpy/strcat/sprintf/vsprintf write to a fixed-size buffer without a length "+
			"bound, so an oversized input overflows it. Use the bounded variants "+
			"(strncpy/strlcpy, strncat/strlcat, snprintf) and always account for the "+
			"NUL terminator.",
	).WithCWE("120"))

	security.Default.RegisterRule(reRule(
		"c.format_string", "Uncontrolled Format String", "memory_corruption", security.SevHigh, cLangs,
		reCFormatString,
		"A printf-family function is called with a variable as the format string "+
			"instead of a string literal. If that variable can contain attacker-controlled "+
			"data, format specifiers like %n let it read or write arbitrary memory. Always "+
			"pass a literal format string: printf(\"%s\", value) not printf(value).",
	).WithCWE("134"))

	security.Default.RegisterRule(reRule(
		"c.command_injection", "OS Command Injection", "io_validation", security.SevHigh, cLangs,
		reCCommandInject,
		"system()/popen() run their argument through a shell. Building that argument "+
			"from anything other than a fixed string literal lets an attacker inject "+
			"additional shell commands. Prefer exec-family calls with an argument array, "+
			"which bypasses the shell entirely.",
	).WithCWE("78"))

	security.Default.RegisterRule(credentialRule(
		"c.hardcoded_credential", cLangs,
		"A credential-like identifier (password, api_key, secret, …) is assigned a "+
			"string literal. Hardcoded secrets are exposed in source control and compiled "+
			"binaries. Read credentials from environment variables or a secrets manager "+
			"at runtime.",
	))

	security.Default.RegisterRule(reRule(
		"c.weak_random", "Weak Randomness for Security-Sensitive Value", "cryptography", security.SevMedium, cLangs,
		reCWeakRandom,
		"rand() is a non-cryptographic PRNG (often a simple LCG) that is predictable "+
			"from a handful of outputs, unsuitable for tokens, session IDs, keys, or nonces. "+
			"Use a CSPRNG: arc4random(), getrandom(), or /dev/urandom.",
	).WithCWE("338"))

	security.Default.RegisterRule(reRule(
		"c.insecure_temp_file", "Insecure Temporary File Creation", "unsafe_deprecated", security.SevMedium, cLangs,
		reCInsecureTmp,
		"tmpnam()/mktemp()/tempnam() generate a predictable filename and hand it back "+
			"without creating the file, leaving a race window where another process can "+
			"create or symlink that path first (CWE-377). Use mkstemp() (or "+
			"mkostemp()/O_TMPFILE), which atomically creates and opens the file.",
	).WithCWE("377"))
}
