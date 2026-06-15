package lang_test

import (
	"testing"

	_ "github.com/exey/archscope/internal/lang" // triggers all init() registrations
	"github.com/exey/archscope/internal/security"
)

// javaRule finds a registered rule by ID. Fails the test if not found.
func javaRule(t *testing.T, id string) security.Rule {
	t.Helper()
	for _, r := range security.Default.Rules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %q not registered", id)
	return security.Rule{}
}

// javaDetect runs a rule's Detect on lines and returns the finding count.
func javaDetect(t *testing.T, id string, lines []string) int {
	t.Helper()
	r := javaRule(t, id)
	if r.Detect == nil {
		t.Fatalf("rule %q has no Detect function", id)
	}
	return len(r.Detect("/app/Foo.java", lines))
}

// ── SQL injection ─────────────────────────────────────────────────────────────

func TestJavaSecurity_SQLConcat_Fires(t *testing.T) {
	lines := []string{
		`import java.sql.Connection;`,
		`stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");`,
	}
	if n := javaDetect(t, "java.sql_concat", lines); n == 0 {
		t.Error("want finding for SQL concatenation, got 0")
	}
}

func TestJavaSecurity_SQLConcat_SafePrepared(t *testing.T) {
	lines := []string{
		`import java.sql.PreparedStatement;`,
		`ps.executeQuery();`, // no concatenation
	}
	if n := javaDetect(t, "java.sql_concat", lines); n != 0 {
		t.Errorf("want 0 findings for prepared statement, got %d", n)
	}
}

func TestJavaSecurity_SQLConcat_NoDBImport(t *testing.T) {
	lines := []string{
		`// no db import`,
		`stmt.executeQuery("SELECT * FROM " + table);`,
	}
	if n := javaDetect(t, "java.sql_concat", lines); n != 0 {
		t.Errorf("want 0 (no DB import gate), got %d", n)
	}
}

// ── Command injection ─────────────────────────────────────────────────────────

func TestJavaSecurity_CommandInjection_Fires(t *testing.T) {
	lines := []string{`Runtime.getRuntime().exec("ls " + dir);`}
	if n := javaDetect(t, "java.command_injection", lines); n == 0 {
		t.Error("want finding for Runtime.exec with concat")
	}
}

func TestJavaSecurity_CommandInjection_FixedArgs(t *testing.T) {
	lines := []string{`Runtime.getRuntime().exec(new String[]{"ls", "-la"});`}
	if n := javaDetect(t, "java.command_injection", lines); n != 0 {
		t.Errorf("want 0 findings for fixed args, got %d", n)
	}
}

// ── Insecure deserialization ──────────────────────────────────────────────────

func TestJavaSecurity_Deserialization_Fires(t *testing.T) {
	lines := []string{`ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());`}
	if n := javaDetect(t, "java.insecure_deserialization", lines); n == 0 {
		t.Error("want finding for ObjectInputStream")
	}
}

// ── XXE ───────────────────────────────────────────────────────────────────────

func TestJavaSecurity_XXE_Fires(t *testing.T) {
	lines := []string{
		`DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();`,
		`DocumentBuilder db = dbf.newDocumentBuilder();`,
	}
	if n := javaDetect(t, "java.xxe", lines); n == 0 {
		t.Error("want XXE finding when no secure feature set")
	}
}

func TestJavaSecurity_XXE_SecureProcessing(t *testing.T) {
	lines := []string{
		`DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();`,
		`dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);`,
	}
	if n := javaDetect(t, "java.xxe", lines); n != 0 {
		t.Errorf("want 0 findings when FEATURE_SECURE_PROCESSING set, got %d", n)
	}
}

// ── Weak cryptography ─────────────────────────────────────────────────────────

func TestJavaSecurity_WeakCrypto_MD5(t *testing.T) {
	lines := []string{`MessageDigest md = MessageDigest.getInstance("MD5");`}
	if n := javaDetect(t, "java.weak_crypto", lines); n == 0 {
		t.Error("want finding for MD5")
	}
}

func TestJavaSecurity_WeakCrypto_DES(t *testing.T) {
	lines := []string{`Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");`}
	if n := javaDetect(t, "java.weak_crypto", lines); n == 0 {
		t.Error("want finding for DES")
	}
}

func TestJavaSecurity_WeakCrypto_AES_Clean(t *testing.T) {
	lines := []string{`Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");`}
	if n := javaDetect(t, "java.weak_crypto", lines); n != 0 {
		t.Errorf("want 0 findings for AES-GCM, got %d", n)
	}
}

// ── Trust-all TLS ─────────────────────────────────────────────────────────────

func TestJavaSecurity_TrustAllCerts_Fires(t *testing.T) {
	lines := []string{`public void checkServerTrusted(X509Certificate[] chain, String authType) {}`}
	if n := javaDetect(t, "java.trust_all_certs", lines); n == 0 {
		t.Error("want finding for empty checkServerTrusted")
	}
}

func TestJavaSecurity_TrustAllHosts_Fires(t *testing.T) {
	lines := []string{`conn.setHostnameVerifier((hostname, session) -> true);`}
	if n := javaDetect(t, "java.trust_all_hosts", lines); n == 0 {
		t.Error("want finding for hostname verifier returning true")
	}
}

// ── Spring CSRF disabled ──────────────────────────────────────────────────────

func TestJavaSecurity_SpringCSRF_Fires(t *testing.T) {
	lines := []string{`http.csrf().disable();`}
	if n := javaDetect(t, "java.spring_csrf_disabled", lines); n == 0 {
		t.Error("want finding for csrf().disable()")
	}
}

func TestJavaSecurity_SpringCSRF_NewStyleFires(t *testing.T) {
	lines := []string{`http.csrf(csrf -> csrf.disable());`}
	if n := javaDetect(t, "java.spring_csrf_disabled", lines); n == 0 {
		t.Error("want finding for csrf -> csrf.disable()")
	}
}

// ── JWT without verification ──────────────────────────────────────────────────

func TestJavaSecurity_JWTNoVerify_Fires(t *testing.T) {
	lines := []string{`Claims claims = Jwts.parser().parseClaimsJws(token).getBody();`}
	if n := javaDetect(t, "java.jwt_no_verify", lines); n == 0 {
		t.Error("want finding for Jwts.parser() without signing key")
	}
}

func TestJavaSecurity_JWTNoVerify_WithKey(t *testing.T) {
	lines := []string{
		`Claims claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();`,
	}
	if n := javaDetect(t, "java.jwt_no_verify", lines); n != 0 {
		t.Errorf("want 0 findings when setSigningKey present, got %d", n)
	}
}

// ── Path traversal ────────────────────────────────────────────────────────────

func TestJavaSecurity_PathTraversal_Fires(t *testing.T) {
	lines := []string{`File f = new File(request.getParameter("path"));`}
	if n := javaDetect(t, "java.path_traversal", lines); n == 0 {
		t.Error("want finding for new File(request.getParameter(...))")
	}
}

// ── XSS ──────────────────────────────────────────────────────────────────────

func TestJavaSecurity_XSS_Fires(t *testing.T) {
	lines := []string{`response.getWriter().println(request.getParameter("name"));`}
	if n := javaDetect(t, "java.xss", lines); n == 0 {
		t.Error("want finding for getWriter().println(request.getParameter())")
	}
}

// ── Stack trace exposure ──────────────────────────────────────────────────────

func TestJavaSecurity_VerboseError_Fires(t *testing.T) {
	lines := []string{`} catch (Exception e) { e.printStackTrace(); }`}
	if n := javaDetect(t, "java.verbose_error", lines); n == 0 {
		t.Error("want finding for e.printStackTrace()")
	}
}

// ── Zip-Slip ──────────────────────────────────────────────────────────────────

func TestJavaSecurity_ZipSlip_Fires(t *testing.T) {
	lines := []string{
		`ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile));`,
		`ZipEntry entry = zis.getNextEntry();`,
		`File outFile = new File(destDir, entry.getName());`,
	}
	if n := javaDetect(t, "java.zip_slip", lines); n == 0 {
		t.Error("want finding for ZipInputStream without canonical path guard")
	}
}

func TestJavaSecurity_ZipSlip_WithGuard(t *testing.T) {
	lines := []string{
		`ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile));`,
		`Path resolved = Paths.get(destDir).resolve(entry.getName()).normalize();`,
		`if (!resolved.startsWith(destDir)) throw new IOException("Zip slip");`,
	}
	if n := javaDetect(t, "java.zip_slip", lines); n != 0 {
		t.Errorf("want 0 findings when path guard present, got %d", n)
	}
}

// ── File upload ───────────────────────────────────────────────────────────────

func TestJavaSecurity_FileUpload_Fires(t *testing.T) {
	lines := []string{
		`@PostMapping("/upload")`,
		`public String upload(@RequestParam MultipartFile file) {`,
		`    file.transferTo(new File("/uploads/" + file.getOriginalFilename()));`,
		`}`,
	}
	if n := javaDetect(t, "java.unrestricted_file_upload", lines); n == 0 {
		t.Error("want finding for MultipartFile without content type check")
	}
}

func TestJavaSecurity_FileUpload_WithTypeCheck(t *testing.T) {
	lines := []string{
		`public String upload(@RequestParam MultipartFile file) {`,
		`    String contentType = file.getContentType();`,
		`    if (!allowedTypes.contains(contentType)) throw new IllegalArgumentException();`,
		`    file.transferTo(dest);`,
		`}`,
	}
	if n := javaDetect(t, "java.unrestricted_file_upload", lines); n != 0 {
		t.Errorf("want 0 findings when content type checked, got %d", n)
	}
}
