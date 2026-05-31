package lang

import (
	"regexp"

	"github.com/exey/archscope/internal/security"
)

// Swift-only security rules. These complement the universal rules (hardcoded
// secrets, private keys, SQL interpolation) with idioms specific to Swift —
// force operations and fatal errors (crash factors), weak crypto, and insecure
// transport. They are gated by Languages:["swift"] so they never fire on other
// platforms. Registering them here, beside the language spec, is the whole
// "drop a file to extend a language" story.
var swiftLangs = []string{"swift"}

var (
	reSwiftForce      = regexp.MustCompile(`(\btry!|\bas!|[A-Za-z0-9_)\]]!([\s.,)?\]]|$))`)
	reSwiftFatal      = regexp.MustCompile(`\b(fatalError|preconditionFailure|assertionFailure)\s*\(`)
	reSwiftWeakCrypto = regexp.MustCompile(`(CC_MD5|CC_SHA1|Insecure\.MD5|Insecure\.SHA1|kCCAlgorithmDES|kCCAlgorithm3DES|\bMD5\()`)
	reSwiftTransport  = regexp.MustCompile(`(NSAllowsArbitraryLoads|allowsArbitraryLoads|NSExceptionAllowsInsecureHTTPLoads|http://)`)
)

func init() {
	security.Default.RegisterRule(reRule(
		"swift.force_unwrap", "Force Operation", "crash_factors", security.SevMedium, swiftLangs,
		reSwiftForce,
		"Force unwrap (!), force try (try!) or force cast (as!) crash the process on a nil or "+
			"type mismatch. Prefer optional binding (if let / guard let), try? or as? so failures "+
			"are handled instead of trapping at runtime.",
	))
	security.Default.RegisterRule(reRule(
		"swift.fatal_error", "Fatal Error", "crash_factors", security.SevLow, swiftLangs,
		reSwiftFatal,
		"fatalError / preconditionFailure / assertionFailure terminate the process. In shipping "+
			"code paths these turn recoverable conditions into hard crashes; reserve them for truly "+
			"unreachable states.",
	))
	security.Default.RegisterRule(reRule(
		"swift.weak_crypto", "Weak Cryptography", "cryptography", security.SevHigh, swiftLangs,
		reSwiftWeakCrypto,
		"MD5, SHA-1 and DES/3DES are cryptographically broken and unsuitable for security use. "+
			"Use SHA-256+ (CryptoKit's SHA256) for hashing and AES-GCM for symmetric encryption.",
	))
	security.Default.RegisterRule(reRule(
		"swift.insecure_transport", "Insecure Transport", "network_security", security.SevHigh, swiftLangs,
		reSwiftTransport,
		"Disabling App Transport Security (NSAllowsArbitraryLoads) or using cleartext http:// "+
			"exposes traffic to interception. Require TLS and remove arbitrary-load exceptions.",
		insecureURLSkips...,
	))
}
