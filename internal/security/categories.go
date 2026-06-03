package security

// Categories are the 14 weighted security-risk categories carried over from
// ArchSwiftScope and generalized to be language-neutral. Weights sum to 1000.
// Order is by ID (1..14).
var Categories = []Category{
	{ID: 1, Key: "insecure_data_storage", Title: "Insecure Data Storage", Icon: "🗄️", Weight: 130,
		Blurb: "Hardcoded secrets, unprotected local storage, sensitive logging."},
	{ID: 2, Key: "crash_factors", Title: "Crash & Stability", Icon: "💥", Weight: 120,
		Blurb: "Force unwraps, unchecked errors, deadlocks, fatal aborts."},
	{ID: 3, Key: "cryptography", Title: "Cryptography Issues", Icon: "🔐", Weight: 110,
		Blurb: "Weak algorithms, insecure randomness, broken modes, key handling."},
	{ID: 4, Key: "authentication", Title: "Authentication & Authorization", Icon: "🪪", Weight: 100,
		Blurb: "Credential misuse, broken cert validation, session handling."},
	{ID: 5, Key: "network_security", Title: "Network Security", Icon: "🌐", Weight: 90,
		Blurb: "Plaintext transport, disabled TLS verification, missing pinning."},
	{ID: 6, Key: "memory_corruption", Title: "Memory Corruption", Icon: "🧠", Weight: 80,
		Blurb: "Unsafe pointers, use-after-free, buffer/integer overflows."},
	{ID: 7, Key: "io_validation", Title: "Input/Output Validation", Icon: "⌨️", Weight: 80,
		Blurb: "Injection, path traversal, command injection."},
	{ID: 8, Key: "unsafe_deprecated", Title: "Unsafe & Deprecated Constructs", Icon: "🧨", Weight: 60,
		Blurb: "Dangerous legacy APIs, deprecated calls, unsafe functions."},
	{ID: 9, Key: "injection", Title: "Injection Attacks", Icon: "💉", Weight: 50,
		Blurb: "SQL, NoSQL, command-line, and template-injection sinks."},
	{ID: 10, Key: "data_exposure", Title: "Sensitive Data Exposure", Icon: "📋", Weight: 50,
		Blurb: "Credentials and PII in logs, unencrypted storage, insecure caches."},
	{ID: 11, Key: "binary_protections", Title: "Binary Protections", Icon: "🛡️", Weight: 40,
		Blurb: "Missing obfuscation, debugger/tamper detection, integrity checks."},
	{ID: 12, Key: "platform_config", Title: "Platform Configuration Weaknesses", Icon: "⚙️", Weight: 40,
		Blurb: "Manifest/plist/settings misconfigurations (debug, backup, ATS)."},
	{ID: 13, Key: "session_mgmt", Title: "Session & Access Control", Icon: "🔐", Weight: 30,
		Blurb: "Cookie flags, CSRF, open redirect, session token mishandling."},
	{ID: 14, Key: "unsafe_exec", Title: "Unsafe Deserialization & Exec", Icon: "🔩", Weight: 20,
		Blurb: "Deserializing untrusted data, eval/exec, XXE, zip-slip."},
}

// categoryByKey indexes Categories for fast lookup.
var categoryByKey = func() map[string]Category {
	m := make(map[string]Category, len(Categories))
	for _, c := range Categories {
		m[c.Key] = c
	}
	return m
}()

// CategoryByKey returns the category with the given key and whether it exists.
func CategoryByKey(key string) (Category, bool) {
	c, ok := categoryByKey[key]
	return c, ok
}
