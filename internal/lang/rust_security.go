package lang

import (
	"regexp"

	"github.com/exey/archscope/internal/security"
)

var rustLangs = []string{"rust"}

var (
	reRustUnsafe      = regexp.MustCompile(`\bunsafe\s*\{`)
	reRustTransmute   = regexp.MustCompile(`\bstd::mem::transmute\b|mem::transmute\s*[<(]`)
	reRustUnwrap      = regexp.MustCompile(`\.unwrap\s*\(\s*\)`)
	reRustExpect      = regexp.MustCompile(`\.expect\s*\(`)
	reRustFromUtf8    = regexp.MustCompile(`from_utf8_unchecked\s*\(`)
	reRustSQLFmt      = regexp.MustCompile(`format!\s*\(`)
	reRustSQLKW       = regexp.MustCompile(`(?i)\b(SELECT\s|INSERT\s+INTO\s|UPDATE\s|DELETE\s+FROM\s|DROP\s+TABLE\s)`)
	reRustHTTPNoTLS   = regexp.MustCompile(`\.bind\s*\(\s*"[^"]*:\d+"\s*\)|HttpServer::new`)
	reRustCmdInject   = regexp.MustCompile(`Command::new\s*\(`)
	reRustCmdFmt      = regexp.MustCompile(`format!\s*\(|\.arg\s*\(\s*&?\w`)
	reRustSetenvSink  = regexp.MustCompile(`std::env::set_var\s*\(`)
	reRustPanicMacro  = regexp.MustCompile(`\bpanic!\s*\(`)
	reRustAllowUnused = regexp.MustCompile(`#\[allow\s*\(\s*(?:dead_code|unused)`)
	reRustTLSConfig   = regexp.MustCompile(`TlsConnector::builder\s*\(|ClientConfig::new\s*\(`)
	reRustTLSVerify   = regexp.MustCompile(`danger_accept_invalid_certs\s*\(\s*true\s*\)|danger_accept_invalid_hostnames\s*\(\s*true\s*\)`)
)

func init() {
	security.Default.RegisterRule(reRule(
		"rust.unsafe_block", "Unsafe Block", "memory_safety", security.SevMedium, rustLangs,
		reRustUnsafe,
		"An `unsafe {}` block opts out of Rust's memory-safety guarantees. "+
			"Audit every pointer dereference, raw transmutation, and FFI call inside it. "+
			"Keep `unsafe` scopes as small as possible and document the invariants that make them sound.",
	).WithCWE("119"))

	security.Default.RegisterRule(reRule(
		"rust.transmute", "Unsafe Memory Reinterpretation (transmute)", "memory_safety", security.SevHigh, rustLangs,
		reRustTransmute,
		"std::mem::transmute reinterprets raw bytes between types without any safety checks. "+
			"It can silently produce invalid values, violate aliasing rules, and cause undefined behaviour. "+
			"Use safe alternatives (From/Into conversions, bytemuck, zerocopy) wherever possible.",
	).WithCWE("119"))

	security.Default.RegisterRule(reRule(
		"rust.unwrap_panic", "Panic on Error (.unwrap / .expect)", "error_handling", security.SevLow, rustLangs,
		reRustUnwrap,
		".unwrap() panics on None or Err, crashing the thread (and the process if it is the main thread). "+
			"In production code prefer .ok_or(...)?, if let, or match to handle the failure path explicitly.",
	).WithCWE("248"))

	security.Default.RegisterRule(reRule(
		"rust.from_utf8_unchecked", "Unchecked UTF-8 Conversion", "memory_safety", security.SevHigh, rustLangs,
		reRustFromUtf8,
		"from_utf8_unchecked() skips the UTF-8 validity check and is undefined behaviour when the "+
			"byte slice is not valid UTF-8. Use std::str::from_utf8() and handle the Err case.",
	).WithCWE("119"))

	security.Default.RegisterRule(twoReRule(
		"rust.sql_injection", "Potential SQL Injection", "injection", security.SevHigh, rustLangs,
		reRustSQLFmt, reRustSQLKW,
		"A format!() macro assembles a SQL fragment containing a keyword like SELECT or INSERT. "+
			"User-controlled values interpolated here can enable SQL injection. "+
			"Use parameterised queries via sqlx, diesel, or sea-orm instead of string formatting.",
	).WithCWE("89"))

	security.Default.RegisterRule(reRule(
		"rust.insecure_tls", "Insecure TLS Configuration", "cryptography", security.SevHigh, rustLangs,
		reRustTLSVerify,
		"danger_accept_invalid_certs(true) or danger_accept_invalid_hostnames(true) disables TLS "+
			"certificate validation, making the connection trivially vulnerable to MITM attacks. "+
			"Never set these in production; remove the builder call entirely to use safe defaults.",
	).WithCWE("295"))

	security.Default.RegisterRule(reRule(
		"rust.hardcoded_credential", "Hardcoded Credential", "insecure_data_storage", security.SevHigh, rustLangs,
		reCredAssign,
		"A credential-like identifier (password, api_key, secret, …) is assigned a string literal. "+
			"Hardcoded secrets are exposed in source control and binary artefacts. "+
			"Read credentials from environment variables or a secrets manager at runtime.",
	).WithCWE("798"))

	security.Default.RegisterRule(reRule(
		"rust.env_set_var", "Dynamic Environment Variable Mutation (set_var)", "injection", security.SevMedium, rustLangs,
		reRustSetenvSink,
		"std::env::set_var is not thread-safe: calling it concurrently with getenv in any thread "+
			"(including C library code) is undefined behaviour on most platforms. "+
			"Set environment variables before spawning threads, or use a purpose-built config layer.",
	).WithCWE("362"))

	security.Default.RegisterRule(reRule(
		"rust.panic_macro", "Explicit panic!()", "error_handling", security.SevLow, rustLangs,
		reRustPanicMacro,
		"panic!() terminates the current thread and, in most Rust binaries, the whole process. "+
			"Replace with a Result-propagating error path (?, thiserror, anyhow) so callers can recover.",
	).WithCWE("248"))

	security.Default.RegisterRule(reRule(
		"rust.allow_dead_code", "Suppressed Lint: dead_code / unused", "code_quality", security.SevLow, rustLangs,
		reRustAllowUnused,
		"#[allow(dead_code)] or #[allow(unused)] silences warnings that often indicate unreachable "+
			"or untested logic. Review whether the item is genuinely needed or can be removed.",
	).WithCWE("561"))

	_ = reRustExpect         // reserved for future expect-in-lib rule
	_ = reRustHTTPNoTLS      // reserved for plaintext HTTP server rule
	_ = reRustCmdInject      // reserved for command injection rule
	_ = reRustCmdFmt         // reserved for command injection rule
	_ = reRustTLSConfig      // reserved for TLS builder rule
}
