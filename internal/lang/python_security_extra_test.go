package lang_test

import (
	"strings"
	"testing"
)

func pyDetect(t *testing.T, id string, src string) int {
	t.Helper()
	r := javaRule(t, id)
	return len(r.Detect("/app/mod.py", strings.Split(src, "\n")))
}

func TestPythonExtraSecurityRulesFireAndStaySilent(t *testing.T) {
	cases := []struct {
		id        string
		bad, good string
	}{
		{"python.assert_used", "assert user.is_admin\n", "# assert nothing\nvalue = 1\n"},
		{"python.bind_all_interfaces", "app.run(host='0.0.0.0')\n", "app.run(host='127.0.0.1')\n"},
		{"python.hardcoded_tmp", "path = '/tmp/report.csv'\n", "path = os.path.join(tmpdir, 'report.csv')\n"},
		{"python.tempfile_mktemp", "name = tempfile.mktemp()\n", "fd, name = tempfile.mkstemp()\n"},
		{"python.jinja2_autoescape_off", "env = Environment(loader=l, autoescape=False)\n", "env = Environment(loader=l, autoescape=True)\n"},
		{"python.paramiko_autoadd", "ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n", "ssh.set_missing_host_key_policy(paramiko.RejectPolicy())\n"},
		{"python.telnet_ftp", "tn = telnetlib.Telnet(host)\n", "sftp = paramiko.SFTPClient.from_transport(t)\n"},
		{"python.ssl_wrap_socket", "s = ssl.wrap_socket(sock)\n", "s = ctx.wrap_socket(sock)\n"},
		{"python.marshal_shelve", "obj = marshal.loads(data)\n", "obj = json.loads(data)\n"},
		{"python.weak_hash_new", "h = hashlib.new('md5')\n", "h = hashlib.new('sha256')\n"},
		{"python.sql_fstring", "cur.execute(f\"SELECT * FROM t WHERE id = {uid}\")\n", "cur.execute(\"SELECT * FROM t WHERE id = %s\", (uid,))\n"},
		{"python.cors_wildcard", "CORS_ALLOW_ALL_ORIGINS = True\n", "CORS_ALLOWED_ORIGINS = ['https://a.example']\n"},
		{"python.requests_no_timeout", "r = requests.get(url)\n", "r = requests.get(url, timeout=5)\n"},
		{"python.django_mark_safe", "from django.utils.safestring import mark_safe\nx = mark_safe(html)\n", "x = mark_safe(html)\n"},
		{"python.django_raw_sql", "import django\nqs = Model.objects.raw(\"select * from t where a = %s\" % a)\n", "import django\nqs = Model.objects.raw('select * from t where a = %s', [a])\n"},
		{"python.django_csrf_exempt", "from django.views.decorators.csrf import csrf_exempt\n@csrf_exempt\ndef v(r):\n    pass\n", "def v(r):\n    pass\n"},
		{"python.django_allowed_hosts_wildcard", "ALLOWED_HOSTS = ['*']\n", "ALLOWED_HOSTS = ['example.com']\n"},
		{"python.django_insecure_cookies", "SESSION_COOKIE_SECURE = False\n", "SESSION_COOKIE_SECURE = True\n"},
		{"python.celery_pickle", "CELERY_TASK_SERIALIZER = 'pickle'\n", "CELERY_TASK_SERIALIZER = 'json'\n"},
	}
	for _, c := range cases {
		if n := pyDetect(t, c.id, c.bad); n == 0 {
			t.Errorf("%s: want a finding for %q", c.id, c.bad)
		}
		if n := pyDetect(t, c.id, c.good); n != 0 {
			t.Errorf("%s: false positive on %q (%d)", c.id, c.good, n)
		}
	}
	// a wrapped requests call with its timeout on a later line is fine
	wrapped := "r = requests.post(\n    url,\n    json=body,\n    timeout=(3, 10),\n)\n"
	if n := pyDetect(t, "python.requests_no_timeout", wrapped); n != 0 {
		t.Errorf("wrapped call with timeout flagged (%d)", n)
	}
}
