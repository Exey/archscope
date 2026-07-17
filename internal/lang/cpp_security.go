package lang

import (
	"regexp"

	"github.com/exey/archscope/internal/security"
)

var cppLangs = []string{"cpp"}

var (
	reCppUnsafeStrCopy = regexp.MustCompile(`\b(strcpy|strcat|sprintf|vsprintf)\s*\(`)
	reCppFormatString  = regexp.MustCompile(`\b(printf|fprintf|sprintf|snprintf|syslog)\s*\(\s*(?:\w+\s*,\s*)?[A-Za-z_]\w*\s*\)`)
	reCppCommandInject = regexp.MustCompile(`\b(system|popen)\s*\(\s*[^")]*\)`)
	reCppWeakRandom    = regexp.MustCompile(`(?i)\b(token|session|key|password|salt|nonce|otp|secret|auth)\w*\s*=\s*.*\brand\s*\(`)
	reCppReinterpret   = regexp.MustCompile(`\breinterpret_cast\s*<`)
	reCppRawNew        = regexp.MustCompile(`\bnew\s+[A-Za-z_]\w*`)
)

func init() {
	security.Default.RegisterRule(reRule(
		"cpp.unsafe_string_copy", "Unbounded String Copy", "memory_corruption", security.SevHigh, cppLangs,
		reCppUnsafeStrCopy,
		"strcpy/strcat/sprintf/vsprintf write to a fixed-size buffer without a length "+
			"bound, so an oversized input overflows it. Prefer std::string/std::snprintf, "+
			"or the bounded C variants (strncpy/strlcpy, strncat/strlcat) when interop with "+
			"a C buffer is unavoidable.",
	).WithCWE("120"))

	security.Default.RegisterRule(reRule(
		"cpp.format_string", "Uncontrolled Format String", "memory_corruption", security.SevHigh, cppLangs,
		reCppFormatString,
		"A printf-family function is called with a variable as the format string "+
			"instead of a string literal. If that variable can contain attacker-controlled "+
			"data, format specifiers like %n let it read or write arbitrary memory. Pass a "+
			"literal format string, or use std::format/iostreams instead.",
	).WithCWE("134"))

	security.Default.RegisterRule(reRule(
		"cpp.command_injection", "OS Command Injection", "io_validation", security.SevHigh, cppLangs,
		reCppCommandInject,
		"system()/popen() run their argument through a shell. Building that argument "+
			"from anything other than a fixed string literal lets an attacker inject "+
			"additional shell commands. Prefer a process-spawning API that takes an "+
			"argument array and bypasses the shell (posix_spawn, CreateProcess, boost::process).",
	).WithCWE("78"))

	security.Default.RegisterRule(credentialRule(
		"cpp.hardcoded_credential", cppLangs,
		"A credential-like identifier (password, api_key, secret, …) is assigned a "+
			"string literal. Hardcoded secrets are exposed in source control and compiled "+
			"binaries. Read credentials from environment variables or a secrets manager "+
			"at runtime.",
	))

	security.Default.RegisterRule(reRule(
		"cpp.weak_random", "Weak Randomness for Security-Sensitive Value", "cryptography", security.SevMedium, cppLangs,
		reCppWeakRandom,
		"rand()/std::rand() is a non-cryptographic PRNG that is predictable from a "+
			"handful of outputs, unsuitable for tokens, session IDs, keys, or nonces. Use "+
			"<random>'s std::random_device (or a platform CSPRNG) for security-sensitive values.",
	).WithCWE("338"))

	security.Default.RegisterRule(reRule(
		"cpp.reinterpret_cast", "Unsafe Type Reinterpretation (reinterpret_cast)", "memory_corruption", security.SevMedium, cppLangs,
		reCppReinterpret,
		"reinterpret_cast reinterprets an object's bit pattern as an unrelated type with "+
			"no safety checks, which is undefined behaviour unless the source and target "+
			"types satisfy strict aliasing / layout-compatibility rules. Prefer static_cast "+
			"for related types, or std::bit_cast (C++20) for safe bit-level reinterpretation.",
	).WithCWE("119"))

	security.Default.RegisterRule(reRule(
		"cpp.raw_new_delete", "Manual Memory Management (raw new)", "unsafe_deprecated", security.SevLow, cppLangs,
		reCppRawNew,
		"A raw `new` expression hands ownership to the caller with no RAII guarantee — "+
			"an exception, early return, or forgotten `delete` on this path leaks or "+
			"double-frees the object. Prefer std::make_unique/std::make_shared so a smart "+
			"pointer owns the lifetime from allocation onward.",
		"unique_ptr", "shared_ptr", "make_unique", "make_shared", "placement new", "operator new",
	).WithCWE("401"))
}
