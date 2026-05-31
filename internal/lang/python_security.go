package lang

import (
	"regexp"

	"github.com/exey/archscope/internal/security"
)

// Python-only security rules: code-execution sinks, unsafe deserialization,
// shell injection and weak hashing. Gated by Languages:["python"].
var pythonLangs = []string{"python"}

var (
	rePyEval     = regexp.MustCompile(`\b(eval|exec)\s*\(`)
	rePyPickle   = regexp.MustCompile(`\b(cPickle|pickle)\s*\.\s*loads?\s*\(`)
	rePyYAML     = regexp.MustCompile(`\byaml\s*\.\s*load\s*\(`)
	rePyShell    = regexp.MustCompile(`shell\s*=\s*True`)
	rePyWeakHash = regexp.MustCompile(`\bhashlib\s*\.\s*(md5|sha1)\s*\(`)
)

func init() {
	security.Default.RegisterRule(reRule(
		"python.eval_exec", "Dynamic Code Execution", "io_validation", security.SevHigh, pythonLangs,
		rePyEval,
		"eval()/exec() run arbitrary code; with any user-influenced input this is remote code "+
			"execution. Use ast.literal_eval for data, or an explicit dispatch table for behavior.",
		"literal_eval",
	))
	security.Default.RegisterRule(reRule(
		"python.insecure_deserialization", "Insecure Deserialization", "unsafe_deprecated", security.SevMedium, pythonLangs,
		rePyPickle,
		"pickle.load/loads executes constructors from the byte stream and can run attacker code. "+
			"Use JSON or another safe format for untrusted data.",
	))
	security.Default.RegisterRule(reRule(
		"python.unsafe_yaml", "Unsafe YAML Load", "unsafe_deprecated", security.SevMedium, pythonLangs,
		rePyYAML,
		"yaml.load with the default loader can instantiate arbitrary Python objects. Use "+
			"yaml.safe_load (or Loader=SafeLoader) for untrusted input.",
		"safe", "safeloader",
	))
	security.Default.RegisterRule(reRule(
		"python.shell_injection", "Shell Injection Risk", "io_validation", security.SevHigh, pythonLangs,
		rePyShell,
		"subprocess(..., shell=True) interpolates the command into a shell; concatenated input "+
			"enables command injection. Pass an argument list and keep shell=False.",
	))
	security.Default.RegisterRule(reRule(
		"python.weak_crypto", "Weak Cryptography", "cryptography", security.SevHigh, pythonLangs,
		rePyWeakHash,
		"MD5 and SHA-1 are broken for security use. Use hashlib.sha256 (or stronger) and a "+
			"password KDF (bcrypt/scrypt/argon2) for credentials.",
	))
}
