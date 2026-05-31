package lang

import (
	"regexp"

	"github.com/exey/archscope/internal/security"
)

// TS/JS-only security rules: dynamic code execution, DOM-based XSS sinks and
// cleartext transport. Gated to the typescript language spec (which owns
// ts/tsx/js/jsx/mjs/cjs), so it covers the whole JS/TS family.
var tsLangs = []string{"ts"}

var (
	reJSEval       = regexp.MustCompile(`\beval\s*\(|new\s+Function\s*\(`)
	reJSDangerHTML = regexp.MustCompile(`dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\(`)
	reJSTransport  = regexp.MustCompile(`http://`)
)

func init() {
	security.Default.RegisterRule(reRule(
		"javascript.eval", "Dynamic Code Execution", "io_validation", security.SevHigh, tsLangs,
		reJSEval,
		"eval() and new Function() execute strings as code; with any untrusted input this is an "+
			"injection vector. Parse data with JSON.parse and model behavior with explicit functions.",
	))
	security.Default.RegisterRule(reRule(
		"javascript.dom_xss", "DOM XSS Sink", "io_validation", security.SevMedium, tsLangs,
		reJSDangerHTML,
		"Assigning unsanitized strings to innerHTML / dangerouslySetInnerHTML / document.write "+
			"injects markup and enables cross-site scripting. Render text nodes or sanitize with a "+
			"vetted library (e.g. DOMPurify).",
	))
	security.Default.RegisterRule(reRule(
		"javascript.insecure_transport", "Insecure Transport", "network_security", security.SevMedium, tsLangs,
		reJSTransport,
		"Cleartext http:// endpoints expose requests to interception and tampering. Use https:// "+
			"for all remote calls.",
		insecureURLSkips...,
	))
}
