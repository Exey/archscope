package constructs

import (
	"os"
	"strings"
	"testing"
)

func TestTopologyPython(t *testing.T) {
	src := strings.Split(`import redis
from celery import shared_task
from django.db import transaction

CELERY_BROKER_URL = "redis://:s3cret@cache:6379/0"
r = redis.Redis(host="cache")
sent = Sentinel([("s1", 26379)])

@shared_task(bind=True, max_retries=3, queue="mail")
def send_mail(self, uid):
    with transaction.atomic():
        User.objects.select_for_update().get(pk=uid)
        transaction.on_commit(lambda: notify.delay(uid))
    r.setex(f"mail:{uid}:sent", 60, 1)
    r.get("session:{sid}")
    r.hset("user:1:profile", "a", 1)

@app.task
def cleanup(): pass

q = Queue("emails", Exchange("mail"), routing_key="mail")
send_mail.apply_async(args=[1], queue="mail", countdown=5)
`, "\n")
	var tp Topology
	scanTopology(&tp, "/x/tasks.py", ".py", src, map[string]bool{})
	tp.sort()
	has := func(es []TopoEntry, kind, sub string) bool {
		for _, e := range es {
			if strings.HasPrefix(e.Kind, kind) && strings.Contains(e.Name+" "+e.Detail, sub) {
				return true
			}
		}
		return false
	}
	for _, c := range []struct {
		es        []TopoEntry
		kind, sub string
	}{
		{tp.Celery, "shared_task", "send_mail"}, {tp.Celery, "task", "cleanup"},
		{tp.Transactions, "atomic", ""}, {tp.Transactions, "row lock", ""}, {tp.Transactions, "on_commit", ""},
		{tp.Redis, "sentinel", ""}, {tp.Redis, "client", ""},
		{tp.MQ, "queue", "emails"}, {tp.MQ, "exchange", "mail"}, {tp.MQ, "enqueue", "queue=mail"}, {tp.MQ, "broker", "***"},
		{tp.KeySpace, "string", "mail:*:sent"}, {tp.KeySpace, "hash", "user:1:profile"},
	} {
		if !has(c.es, c.kind, c.sub) {
			t.Errorf("missing %s %q in %+v", c.kind, c.sub, c.es)
		}
	}
	for _, e := range tp.Redis {
		if strings.Contains(e.Name, "s3cret") {
			t.Error("password leaked")
		}
	}
	for _, e := range tp.KeySpace {
		if e.Name == "mail:*:sent" && !strings.Contains(e.Detail, "TTL") {
			t.Errorf("setex key should show TTL: %+v", e)
		}
	}
}

func TestInspectDumps(t *testing.T) {
	dir := t.TempDir()
	w := func(n, body string) string {
		p := dir + "/" + n
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	reg := w("reg.txt", "-> celery@w1: OK\n    * app.tasks.send_mail\n    * app.tasks.legacy\n-> celery@w2: OK\n    * app.tasks.send_mail\n")
	sched := w("sched.txt", "-> celery@w1: OK\n    * {'eta': '2026-10-27T10:00:00+00:00', 'priority': 6, 'request': {'id': 'x', 'name': 'app.tasks.send_mail'}}\n")
	queues := w("q.txt", "Timeout: 60.0 seconds ...\nListing queues for vhost / ...\nname\tmessages\tconsumers\nmail\t12\t2\ncelery\t0\t1\n")
	exch := w("e.txt", "Listing exchanges for vhost / ...\nname\ttype\n\tdirect\nmail\ttopic\n")
	bind := w("b.txt", "Listing bindings for vhost /...\nsource_name\tsource_kind\tdestination_name\tdestination_kind\trouting_key\targuments\nmail\texchange\tmail\tqueue\tmail.#\t[]\n")
	SetInspectDumps([]string{reg, sched, queues, exch, bind})
	defer SetInspectDumps(nil)
	l := loadLive()
	if len(l.Registered) != 2 || !strings.Contains(l.Registered[1].Detail+l.Registered[0].Detail, "2 worker(s)") {
		t.Errorf("registered: %+v", l.Registered)
	}
	if len(l.Scheduled) != 1 || l.Scheduled[0].Name != "app.tasks.send_mail" || !strings.Contains(l.Scheduled[0].Detail, "2026-10-27") {
		t.Errorf("scheduled: %+v", l.Scheduled)
	}
	if len(l.Queues) != 2 || !strings.Contains(l.Queues[1].Detail, "messages=12") || !strings.Contains(l.Queues[1].Detail, "consumers=2") {
		t.Errorf("queues: %+v", l.Queues)
	}
	if len(l.Exchanges) != 2 || len(l.Bindings) != 1 || l.Bindings[0].Name != "mail → mail" || !strings.Contains(l.Bindings[0].Detail, "mail.#") {
		t.Errorf("exchanges %+v bindings %+v", l.Exchanges, l.Bindings)
	}
	drift := l.reconcile([]TopoEntry{{Kind: "shared_task", Name: "send_mail"}, {Kind: "task", Name: "only_in_code"}})
	var got []string
	for _, d := range drift {
		got = append(got, d.Kind+":"+d.Name)
	}
	want := map[string]bool{"registered, not in code:app.tasks.legacy": true, "in code, not registered:only_in_code": true}
	if len(got) != 2 || !want[got[0]] || !want[got[1]] {
		t.Errorf("drift: %v", got)
	}
}

func TestInspectJSON(t *testing.T) {
	var l Live
	tasks := map[string]map[string]bool{}
	parseCeleryJSON(&l, "x", `{"celery@w1": {"ok": ["app.a", "app.b"]}}`, tasks)
	if len(tasks) != 2 {
		t.Errorf("tasks %v", tasks)
	}
	parseCeleryJSON(&l, "x", `[{"celery@w1": [{"eta": "2026-01-01", "priority": 3, "request": {"name": "app.a"}}]}]`, tasks)
	if len(l.Scheduled) != 1 || l.Scheduled[0].Name != "app.a" {
		t.Errorf("scheduled %+v", l.Scheduled)
	}
}
