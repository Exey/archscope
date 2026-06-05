package lang

import (
	"regexp"

	"github.com/exey/archscope/internal/security"
)

// Swift-only security rules — original checks plus the full catalog ported from
// ArchSwiftScope's SecurityAnalyzer. Gated by Languages:["swift"].
var swiftLangs = []string{"swift"}

var (
	reSwiftForce          = regexp.MustCompile(`(\btry!|\bas!|[A-Za-z0-9_)\]]!([\s.,)?\]]|$))`)
	reSwiftFatal          = regexp.MustCompile(`\b(fatalError|preconditionFailure|assertionFailure)\s*\(`)
	reSwiftWeakCrypto     = regexp.MustCompile(`(CC_MD5|CC_SHA1|Insecure\.MD5|Insecure\.SHA1|kCCAlgorithmDES|kCCAlgorithm3DES|\bMD5\()`)
	reSwiftTransport      = regexp.MustCompile(`(NSAllowsArbitraryLoads|allowsArbitraryLoads|NSExceptionAllowsInsecureHTTPLoads|http://)`)
	reSwiftUserDefaults   = regexp.MustCompile(`UserDefaults\b`)
	reSwiftSensitiveKey   = regexp.MustCompile(`(?i)\b(password|passwd|passphrase|psk|secret|secretkey|api[_-]?key|apikey|token|credential|private[_-]?key|privkey|auth)\b`)
	reSwiftInsecureRandom = regexp.MustCompile(`\b(arc4random|arc4random_buf|arc4random_uniform|rand\s*\(|Int\.random|Bool\.random|Float\.random|Double\.random|SystemRandomNumberGenerator)\b`)
	reSwiftSQLiteExec     = regexp.MustCompile(`\b(sqlite3_exec|sqlite3_prepare|\.execute\s*\(|db\.run\s*\()`)
	reSwiftInterpolation  = regexp.MustCompile(`\\\(`)
	reSwiftWebViewJS      = regexp.MustCompile(`javaScriptCanOpenWindowsAutomatically\s*=\s*true`)

	// ArchSwiftScope rules
	reSwiftNSKeyedUn     = regexp.MustCompile(`NSKeyedUnarchiver\.unarchiveObject|NSKeyedUnarchiver\.unarchiveTopLevelObject|requiringSecureCoding:\s*false`)
	reSwiftShell         = regexp.MustCompile(`\bpopen\s*\(|"/bin/(sh|bash)"|"/usr/bin/env"|\b(Process|NSTask)\s*\(\s*\)`)
	reSwiftKeychainAlw   = regexp.MustCompile(`kSecAttrAccessibleAlways\b`)
	reSwiftEvalJS        = regexp.MustCompile(`\.evaluateJavaScript\s*\(`)
	reSwiftWebViewUnsafe = regexp.MustCompile(`allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs|isFraudulentWebsiteWarningEnabled\s*=\s*false`)
	reSwiftCertBypass    = regexp.MustCompile(`allowsAnyHTTPSCertificate|validatesDomainName\s*=\s*false`)
	reSwiftHardcodedIV   = regexp.MustCompile(`(?i)\b(iv|nonce|initialVector|initializationVector)\s*[=:]\s*[\["]`)
	reSwiftCBCMode       = regexp.MustCompile(`kCCModeCBC|\.cbc\b`)
	reSwiftCBCSafe       = regexp.MustCompile(`kCCModeGCM|\.gcm|AES\.GCM|ChaChaPoly|CCHmac\b|HMAC\b`)
	reSwiftPrintLog      = regexp.MustCompile(`(?i)\b(print|debugPrint|NSLog)\s*\(`)
	reSwiftUIWebView     = regexp.MustCompile(`\bUIWebView\b`)
	reSwiftDebugFW       = regexp.MustCompile(`\bimport\s+(FLEX|Reveal|Chisel|InjectionIII|Dotzu|DBDebugToolkit|GodEye|Hyperion)\b`)
	reSwiftUnsafePtr     = regexp.MustCompile(`\b(UnsafePointer|UnsafeMutablePointer|UnsafeRawPointer|UnsafeMutableRawPointer|withUnsafeBytes|withUnsafeMutableBytes|withUnsafePointer|withUnsafeMutablePointer)\b`)
	reSwiftECBMode       = regexp.MustCompile(`kCCOptionECBMode`)
	// CWE-22: FileManager/Data file-read sinks (path traversal via interpolation)
	reSwiftFileSink      = regexp.MustCompile(`\bFileManager\.default\b|\bData\s*\(\s*contentsOf\s*:|\bNSData\s*\(\s*contentsOfFile\s*:|\bcontentsOfFile\s*:|\bURL\s*\(\s*fileURLWithPath\s*:`)
	// CWE-918: URLSession with a string-interpolated URL — attacker can redirect to internal hosts
	reSwiftURLSessionSink = regexp.MustCompile(`URLSession\b|\.dataTask\s*\(|\.downloadTask\s*\(|\.uploadTask\s*\(`)
	reSwiftURLInterp      = regexp.MustCompile(`URL\s*\(\s*string\s*:.*\\\(|URLComponents\b.*\\\(`)
	// CWE-916: fast hash in password context (CryptoKit SHA256/SHA512)
	reSwiftFastHashSink  = regexp.MustCompile(`\bSHA256\.(hash|init)|SHA512\.(hash|init)|\bSHA384\.(hash|init)|Insecure\.SHA256|Insecure\.SHA512`)
)

func init() {
	// CWE-476: force-unwrap on nil crashes the process — the Swift equivalent of null deref.
	security.Default.RegisterRule(reRule(
		"swift.force_unwrap", "Force Operation", "crash_factors", security.SevMedium, swiftLangs,
		reSwiftForce,
		"Force unwrap (!), force try (try!) or force cast (as!) crash the process on a nil or "+
			"type mismatch. Prefer optional binding (if let / guard let), try? or as? so failures "+
			"are handled instead of trapping at runtime.",
	).WithCWE("476"))
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
	).WithCWE("327"))
	security.Default.RegisterRule(reRule(
		"swift.insecure_transport", "Insecure Transport", "network_security", security.SevHigh, swiftLangs,
		reSwiftTransport,
		"Disabling App Transport Security (NSAllowsArbitraryLoads) or using cleartext http:// "+
			"exposes traffic to interception. Require TLS and remove arbitrary-load exceptions.",
		insecureURLSkips...,
	).WithCWE("319").WithSkipTests())
	security.Default.RegisterRule(swiftSensitiveUserDefaultsRule())
	security.Default.RegisterRule(twoReRule(
		"swift.insecure_random", "Insecure Random in Security Context", "cryptography", security.SevMedium, swiftLangs,
		reSwiftInsecureRandom, reSwiftSensitiveKey,
		"arc4random, rand() or Swift's Int/Bool/Float/Double.random() is used in a context that "+
			"suggests a security-sensitive value (token, key, nonce). For cryptographic material "+
			"use SecRandomCopyBytes or CryptoKit's randomness APIs instead.",
	).WithCWE("338"))
	security.Default.RegisterRule(reRule(
		"swift.webview_js_window", "WebView Allows JS Window Open", "platform_config", security.SevLow, swiftLangs,
		reSwiftWebViewJS,
		"Setting javaScriptCanOpenWindowsAutomatically = true allows JavaScript inside a WKWebView "+
			"to open new windows automatically, violating the principle of least privilege. "+
			"Disable this unless explicitly required.",
	).WithCWE("272"))
	security.Default.RegisterRule(swiftSQLiteInjectionRule())

	// ArchSwiftScope rules
	security.Default.RegisterRule(reRule(
		"swift.nskeyedunarchiver", "Insecure Deserialization (NSKeyedUnarchiver)", "unsafe_exec", security.SevHigh, swiftLangs,
		reSwiftNSKeyedUn,
		"NSKeyedUnarchiver.unarchiveObject or requiringSecureCoding: false deserializes objects "+
			"without type restrictions. Attacker-controlled archives can instantiate arbitrary "+
			"Objective-C objects and achieve code execution. Use NSKeyedUnarchiver with "+
			"requiringSecureCoding: true and a concrete expected class.",
	).WithCWE("502"))
	security.Default.RegisterRule(reRule(
		"swift.shell_injection", "Shell Command Execution", "injection", security.SevHigh, swiftLangs,
		reSwiftShell,
		"Execution of /bin/sh, /bin/bash or popen() with string interpolation risks command "+
			"injection if any argument originates from user input. Use Process with a fixed "+
			"arguments array and never pass user input through a shell interpreter.",
	).WithCWE("78"))
	security.Default.RegisterRule(reRule(
		"swift.keychain_always_accessible", "Keychain Item Always Accessible", "authentication", security.SevHigh, swiftLangs,
		reSwiftKeychainAlw,
		"kSecAttrAccessibleAlways (and AlwaysThisDeviceOnly) makes the Keychain item readable "+
			"even when the device is locked, defeating the Keychain's primary protection. Use "+
			"kSecAttrAccessibleAfterFirstUnlock or kSecAttrAccessibleWhenUnlocked instead.",
	).WithCWE("522"))
	security.Default.RegisterRule(swiftWebViewInjectionRule())
	security.Default.RegisterRule(reRule(
		"swift.webview_unsafe_config", "Unsafe WebView Configuration", "io_validation", security.SevHigh, swiftLangs,
		reSwiftWebViewUnsafe,
		"allowFileAccessFromFileURLs, allowUniversalAccessFromFileURLs or disabling the fraudulent "+
			"website warning weakens WKWebView isolation and enables cross-origin attacks or "+
			"phishing. Remove these settings unless strictly required.",
	).WithCWE("346"))
	security.Default.RegisterRule(reRule(
		"swift.cert_bypass", "Certificate Validation Bypass", "network_security", security.SevHigh, swiftLangs,
		reSwiftCertBypass,
		"allowsAnyHTTPSCertificate or validatesDomainName = false disables TLS certificate "+
			"validation, making connections trivially MITMable. Use the system trust store and "+
			"implement certificate pinning if stronger guarantees are needed.",
	).WithCWE("295").WithSkipTests())
	security.Default.RegisterRule(reRule(
		"swift.hardcoded_iv", "Hardcoded Initialization Vector", "cryptography", security.SevHigh, swiftLangs,
		reSwiftHardcodedIV,
		"A hardcoded IV or nonce makes every encryption of the same plaintext produce the same "+
			"ciphertext, breaking semantic security. Generate a fresh random IV for each "+
			"encryption operation using SecRandomCopyBytes.",
	).WithCWE("329"))
	security.Default.RegisterRule(swiftCBCNoMACRule())
	security.Default.RegisterRule(swiftSensitiveLoggingRule())
	security.Default.RegisterRule(reRule(
		"swift.uiwebview", "Deprecated UIWebView", "unsafe_deprecated", security.SevMedium, swiftLangs,
		reSwiftUIWebView,
		"UIWebView is deprecated since iOS 12 and removed in iOS 18. It lacks the security "+
			"and privacy mitigations of WKWebView. Replace all UIWebView instances with "+
			"WKWebView.",
	).WithCWE("477"))
	security.Default.RegisterRule(reRule(
		"swift.debug_framework", "Debug Framework in Production", "binary_protections", security.SevHigh, swiftLangs,
		reSwiftDebugFW,
		"FLEX, Reveal, Chisel, InjectionIII or similar diagnostic frameworks expose the app's "+
			"internal state and allow runtime manipulation. Remove all debug framework imports "+
			"before building for production or the App Store.",
	).WithCWE("489"))
	security.Default.RegisterRule(reRule(
		"swift.unsafe_pointer", "Unsafe Pointer Usage", "memory_corruption", security.SevMedium, swiftLangs,
		reSwiftUnsafePtr,
		"UnsafePointer, UnsafeMutablePointer and the withUnsafe* family bypass Swift's memory "+
			"safety guarantees. Incorrect use causes use-after-free, buffer overread or undefined "+
			"behaviour. Prefer safe Swift APIs; document and minimize every unsafe block.",
	).WithCWE("119"))
	security.Default.RegisterRule(reRule(
		"swift.ecb_mode", "ECB Cipher Mode", "cryptography", security.SevHigh, swiftLangs,
		reSwiftECBMode,
		"kCCOptionECBMode encrypts each block independently, leaking patterns in the plaintext "+
			"(the 'ECB penguin'). Use AES-GCM (CryptoKit) or CBC with a random IV and HMAC "+
			"authentication instead.",
	).WithCWE("327"))
	security.Default.RegisterRule(twoReRule(
		"swift.path_traversal", "Path Traversal", "io_validation", security.SevHigh, swiftLangs,
		reSwiftFileSink, reSwiftInterpolation,
		"A file-system operation (FileManager, Data(contentsOf:), URL(fileURLWithPath:)) uses "+
			"a path built with Swift string interpolation (\\(...)). If the interpolated value "+
			"originates from user input an attacker can supply \"../\" sequences to escape the "+
			"allowed directory. Validate and canonicalize paths before use. (CWE-22)",
	).WithCWE("22"))
	security.Default.RegisterRule(swiftSSRFRule())
	security.Default.RegisterRule(credentialRule("swift.hardcoded_credentials", swiftLangs,
		"A credential-naming variable is assigned a string literal. Hardcoded secrets are "+
			"committed to history permanently. Load credentials from a secure keychain, "+
			"configuration file, or environment at runtime. (CWE-798)"))
	security.Default.RegisterRule(twoReRule(
		"swift.fast_hash_for_password", "Fast Hash Used for Password", "cryptography", security.SevHigh, swiftLangs,
		reSwiftFastHashSink, reSwiftSensitiveKey,
		"CryptoKit SHA256/SHA512 is used in a context that suggests password hashing. Fast "+
			"hashes can be brute-forced at billions of attempts per second. Use a password KDF "+
			"(CommonCrypto PBKDF2, CryptoKit HKDF, or a third-party argon2/bcrypt wrapper) "+
			"for credential storage. (CWE-916)",
	).WithCWE("916"))
}

// swiftSSRFRule fires when a file creates a URL from string interpolation and
// also contains a URLSession network call. The interpolated URL may incorporate
// user-controlled input, allowing an attacker to redirect the request to
// internal services or cloud metadata endpoints.
func swiftSSRFRule() security.Rule {
	return security.Rule{
		ID:        "swift.ssrf",
		Name:      "Server-Side Request Forgery",
		Severity:  security.SevHigh,
		Category:  "io_validation",
		CWE:       "918",
		Languages: swiftLangs,
		Description: "A URL is constructed with Swift string interpolation (\\(...)) and a " +
			"URLSession network call is present in the same file. If the interpolated value " +
			"originates from user input an attacker can redirect the request to internal " +
			"services or cloud metadata endpoints. Validate and allowlist target hosts before " +
			"issuing outbound requests. (CWE-918)",
		Detect: func(filePath string, lines []string) []security.Finding {
			urlLine := -1
			hasSession := false
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reSwiftURLInterp.MatchString(line) && urlLine == -1 {
					urlLine = i
				}
				if reSwiftURLSessionSink.MatchString(line) {
					hasSession = true
				}
			}
			if urlLine >= 0 && hasSession {
				return []security.Finding{security.NewFinding(filePath, urlLine, lines)}
			}
			return nil
		},
	}
}

// swiftWebViewInjectionRule flags evaluateJavaScript calls that use string
// interpolation, potentially injecting attacker-controlled code into the WebView.
func swiftWebViewInjectionRule() security.Rule {
	return security.Rule{
		ID:        "swift.webview_injection",
		Name:      "WebView JavaScript Injection",
		Severity:  security.SevHigh,
		Category:  "io_validation",
		CWE:       "79",
		Languages: swiftLangs,
		Description: "evaluateJavaScript is called with a string that contains Swift " +
			"interpolation (\\(...)). If any interpolated value originates from user input " +
			"this is a client-side script injection vulnerability. Pass only static strings " +
			"to evaluateJavaScript or use the postMessage / native bridge APIs. (CWE-79)",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reSwiftEvalJS.MatchString(line) && reSwiftInterpolation.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// swiftCBCNoMACRule flags files that use CBC mode without any authenticated
// encryption (GCM, ChaChaPoly, HMAC). CBC without a MAC is vulnerable to
// padding-oracle attacks and bit-flipping.
func swiftCBCNoMACRule() security.Rule {
	return security.Rule{
		ID:        "swift.cbc_no_mac",
		Name:      "CBC Mode Without Authentication (MAC)",
		Severity:  security.SevHigh,
		Category:  "cryptography",
		CWE:       "327",
		Languages: swiftLangs,
		Description: "CBC mode is used without any authenticated encryption (AES-GCM, ChaChaPoly) " +
			"or a MAC (HMAC/CCHmac). Without authentication the ciphertext can be silently " +
			"tampered with, enabling padding-oracle and bit-flipping attacks. Use AES-GCM " +
			"(CryptoKit AES.GCM) which provides both confidentiality and integrity. (CWE-327)",
		Detect: func(filePath string, lines []string) []security.Finding {
			cbcLine := -1
			hasMac := false
			for i, line := range lines {
				if reSwiftCBCMode.MatchString(line) && cbcLine == -1 {
					cbcLine = i
				}
				if reSwiftCBCSafe.MatchString(line) {
					hasMac = true
				}
			}
			if cbcLine >= 0 && !hasMac {
				return []security.Finding{security.NewFinding(filePath, cbcLine, lines)}
			}
			return nil
		},
	}
}

// swiftSensitiveLoggingRule flags print/NSLog calls on lines that also contain
// sensitive keywords — a common accidental data-leakage pattern in debug code
// left behind in production builds.
func swiftSensitiveLoggingRule() security.Rule {
	return security.Rule{
		ID:        "swift.sensitive_logging",
		Name:      "Sensitive Data in Debug Logs",
		Severity:  security.SevMedium,
		Category:  "data_exposure",
		CWE:       "532",
		Languages: swiftLangs,
		Description: "print() / debugPrint() / NSLog() is called on a line that references " +
			"a password, token, or credential. Debug logs are stored on-device and may be " +
			"accessible via iTunes backups or crash reporters. Remove sensitive data from " +
			"log output before shipping. (CWE-532)",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reSwiftPrintLog.MatchString(line) && reSwiftSensitiveKey.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// swiftSQLiteInjectionRule flags SQLite API calls that use string interpolation.
func swiftSQLiteInjectionRule() security.Rule {
	return security.Rule{
		ID:        "swift.sqlite_injection",
		Name:      "SQLite String Interpolation",
		Severity:  security.SevHigh,
		Category:  "injection",
		CWE:       "89",
		Languages: swiftLangs,
		Description: "A SQLite query is assembled using Swift string interpolation (\\(...)). " +
			"If any interpolated value originates from user input this enables SQL injection. " +
			"Use parameterized queries with bound ? placeholders instead. (CWE-89)",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				if reSwiftSQLiteExec.MatchString(line) && reSwiftInterpolation.MatchString(line) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}

// swiftSensitiveUserDefaultsRule flags lines that store sensitive values in UserDefaults.
func swiftSensitiveUserDefaultsRule() security.Rule {
	return security.Rule{
		ID:        "swift.sensitive_userdefaults",
		Name:      "Sensitive Data in UserDefaults",
		Severity:  security.SevHigh,
		Category:  "data_exposure",
		CWE:       "311",
		Languages: swiftLangs,
		Description: "Storing passwords, tokens or API keys in UserDefaults writes them to an " +
			"unencrypted plist file on disk, readable by any process with the same container " +
			"entitlements (and by iTunes backups if not excluded). Use the iOS/macOS Keychain " +
			"for any value that must remain secret.",
		Detect: func(filePath string, lines []string) []security.Finding {
			var out []security.Finding
			for i, line := range lines {
				if security.IsComment(line) {
					continue
				}
				stripped := security.StripStringsAndComments(line)
				if reSwiftUserDefaults.MatchString(stripped) && reSwiftSensitiveKey.MatchString(stripped) {
					out = append(out, security.NewFinding(filePath, i, lines))
				}
			}
			return out
		},
	}
}
