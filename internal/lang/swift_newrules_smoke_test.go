package lang_test

import (
	"strings"
	"testing"
	_ "github.com/exey/archscope/internal/lang"
	"github.com/exey/archscope/internal/security"
)

func findRule(id string) *security.Rule {
	for _, r := range security.Default.Rules() {
		if r.ID == id {
			rc := r; return &rc
		}
	}
	return nil
}

func fireCheck(t *testing.T, id, src string) {
	t.Helper()
	r := findRule(id)
	if r == nil { t.Errorf("%s: rule not registered", id); return }
	findings := r.Detect("test.swift", strings.Split(src, "\n"))
	if len(findings) == 0 { t.Errorf("%s: expected finding, got none", id) }
}

func noFireCheck(t *testing.T, id, src string) {
	t.Helper()
	r := findRule(id)
	if r == nil { t.Errorf("%s: rule not registered", id); return }
	findings := r.Detect("test.swift", strings.Split(src, "\n"))
	if len(findings) > 0 { t.Errorf("%s: unexpected finding on clean code", id) }
}

func TestNewSwiftRulesFire(t *testing.T) {
	fireCheck(t, "swift.pasteboard_sensitive",
		"UIPasteboard.general.string = password\n")
	fireCheck(t, "swift.biometric_passcode_fallback",
		"context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: \"x\") { _, _ in }\n")
	fireCheck(t, "swift.appstorage_sensitive",
		"@AppStorage(\"token\") var authToken: String = \"\"\n")
	fireCheck(t, "swift.realm_no_encryption",
		"let realm = try! Realm()\n")
	fireCheck(t, "swift.notification_sensitive_content",
		"let c = UNMutableNotificationContent()\nc.body = \"OTP is 123\"\n")
	fireCheck(t, "swift.device_token_logged",
		"print(\"push deviceToken = \\(deviceToken)\")\n")
	fireCheck(t, "swift.method_swizzling",
		"method_exchangeImplementations(original, swizzled)\n")
	fireCheck(t, "swift.tls_minimum_version",
		"config.tlsMinimumSupportedProtocolVersion = .TLSv10\n")
}

func TestNewSwiftRulesNoFalsePositives(t *testing.T) {
	noFireCheck(t, "swift.realm_no_encryption",
		"let config = Realm.Configuration(encryptionKey: key)\nlet realm = try! Realm(configuration: config)\n")
	noFireCheck(t, "swift.biometric_passcode_fallback",
		"context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: \"x\") { _, _ in }\n")
	noFireCheck(t, "swift.tls_minimum_version",
		"config.tlsMinimumSupportedProtocolVersion = .TLSv12\n")
}
