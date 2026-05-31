package security

// Categories are the 14 weighted security-risk categories carried over from
// ArchSwiftScope and generalized to be language-neutral. Weights sum to 1000.
// Order is by ID (1..14).
var Categories = []Category{
	{ID: 1, Key: "insecure_data_storage", Title: "Insecure Data Storage", Icon: "🗄️", Weight: 130,
		Blurb: "Hardcoded secrets, unprotected local storage, sensitive logging."},
	{ID: 2, Key: "crash_factors", Title: "Crash Factors", Icon: "💥", Weight: 120,
		Blurb: "Force unwraps, unchecked errors, deadlocks, fatal aborts."},
	{ID: 3, Key: "cryptography", Title: "Cryptography Issues", Icon: "🔐", Weight: 110,
		Blurb: "Weak algorithms, insecure randomness, broken modes, key handling."},
	{ID: 4, Key: "authentication", Title: "Authentication & Authorization", Icon: "🪪", Weight: 100,
		Blurb: "Credential misuse, broken cert validation, session handling."},
	{ID: 5, Key: "network_security", Title: "Network Security", Icon: "🌐", Weight: 90,
		Blurb: "Plaintext transport, disabled TLS verification, missing pinning."},
	{ID: 6, Key: "memory_corruption", Title: "Memory Corruption & Exploit Factors", Icon: "🧠", Weight: 80,
		Blurb: "Unsafe pointers, use-after-free, buffer/integer overflows."},
	{ID: 7, Key: "io_validation", Title: "Input/Output Validation", Icon: "⌨️", Weight: 80,
		Blurb: "Injection, path traversal, command injection."},
	{ID: 8, Key: "unsafe_deprecated", Title: "Unsafe & Deprecated Constructs", Icon: "🧨", Weight: 60,
		Blurb: "Dangerous legacy APIs, deprecated calls, unsafe functions."},
	{ID: 9, Key: "supply_chain", Title: "Third-Party & Supply-Chain Risks", Icon: "📦", Weight: 50,
		Blurb: "Vulnerable or unaudited dependencies, dependency confusion."},
	{ID: 10, Key: "privacy", Title: "Privacy Violations", Icon: "🔍", Weight: 50,
		Blurb: "Excessive permissions, consent gaps, identifier misuse."},
	{ID: 11, Key: "binary_protections", Title: "Binary Protections", Icon: "🛡️", Weight: 40,
		Blurb: "Missing obfuscation, debugger/tamper detection, integrity checks."},
	{ID: 12, Key: "platform_config", Title: "Platform Configuration Weaknesses", Icon: "⚙️", Weight: 40,
		Blurb: "Manifest/plist/settings misconfigurations (debug, backup, ATS)."},
	{ID: 13, Key: "logic_state", Title: "Logic & State-based Exploit Factors", Icon: "🔀", Weight: 30,
		Blurb: "Race conditions, insecure IPC, state bugs, bypasses."},
	{ID: 14, Key: "low_level_binary", Title: "Low-level Binary Vulnerabilities", Icon: "🔩", Weight: 20,
		Blurb: "C/C++/ObjC memory-corruption primitives and runtime hazards."},
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
