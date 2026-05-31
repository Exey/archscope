package lang

import (
	"regexp"

	"github.com/exey/archscope/internal/security"
)

// Go-only security rules: weak crypto imports/use, disabled TLS verification
// and command-injection-prone exec. Gated by Languages:["go"].
var goLangs = []string{"go"}

var (
	reGoWeakCrypto   = regexp.MustCompile(`"crypto/(md5|sha1|des|rc4)"|\b(md5|sha1)\.New\s*\(|\bdes\.NewCipher\s*\(`)
	reGoInsecureTLS  = regexp.MustCompile(`InsecureSkipVerify\s*:\s*true`)
	reGoCmdInjection = regexp.MustCompile(`exec\.Command(Context)?\s*\(.*(fmt\.Sprintf|"\s*\+|\+\s*")`)
)

func init() {
	security.Default.RegisterRule(reRule(
		"go.weak_crypto", "Weak Cryptography", "cryptography", security.SevHigh, goLangs,
		reGoWeakCrypto,
		"crypto/md5, crypto/sha1, crypto/des and crypto/rc4 are broken or obsolete for security "+
			"use. Use crypto/sha256+ for hashing and crypto/aes with GCM for symmetric encryption.",
	))
	security.Default.RegisterRule(reRule(
		"go.insecure_tls", "Disabled TLS Verification", "network_security", security.SevHigh, goLangs,
		reGoInsecureTLS,
		"InsecureSkipVerify: true disables certificate validation, defeating TLS and enabling "+
			"man-in-the-middle attacks. Verify certificates; pin or supply a proper RootCAs pool if needed.",
	))
	security.Default.RegisterRule(reRule(
		"go.command_injection", "Command Injection Risk", "io_validation", security.SevMedium, goLangs,
		reGoCmdInjection,
		"Building an exec.Command argument by formatting or concatenating strings can let input "+
			"alter the command. Pass fixed args as separate parameters and never interpolate user input.",
	))
}
