// concurrency_topology.go inventories the moving parts a concurrent backend
// hangs together with — Celery tasks by type, atomic database transactions,
// Redis topology (clients, sentinels, clusters, pub/sub, locks, streams) and
// message-queue topology (brokers, queues, exchanges, producers, consumers).
// Lexical, per language; shown in the 🧵 Concurrency card beside its issues.
package constructs

import (
	"fmt"
	"html"
	"regexp"
	"sort"
	"strings"

	"github.com/exey/archscope/internal/parser"
)

// Topology groups what was found.
type Topology struct {
	Celery       []TopoEntry // task definitions, by type
	Transactions []TopoEntry // atomic blocks, row locks, on-commit hooks
	Redis        []TopoEntry
	MQ           []TopoEntry
	KeySpace     []TopoEntry // Redis key patterns, by data type, with the commands and TTL they see
	Live         *Live       // from --inspect dumps (celery inspect, rabbitmqctl)
	Drift        []TopoEntry // tasks that differ between the code and the live workers

	keys map[string]*keyAgg
}

// keyAgg collects every use of one Redis key pattern.
type keyAgg struct {
	typ      string
	cmds     map[string]bool
	ttl      bool
	n        int
	filePath string
	line     int
}

// TopoEntry is one finding: what it is, what it names, its settings, and where.
type TopoEntry struct {
	Kind     string // "task", "shared_task", "periodic", "sentinel", "queue", …
	Name     string // task / queue / host / key
	Detail   string // settings worth knowing: retries, queue, acks_late, savepoint=False …
	FilePath string
	Line     int
}

// Empty reports whether the topology holds no entry at all.
func (t Topology) Empty() bool {
	return t.Total() == 0
}

// Total counts every entry of the topology, entries from live dumps included.
func (t Topology) Total() int {
	n := len(t.Celery) + len(t.Transactions) + len(t.Redis) + len(t.MQ) + len(t.KeySpace) + len(t.Drift)
	if t.Live != nil {
		n += len(t.Live.Registered) + len(t.Live.Scheduled) + len(t.Live.Queues) + len(t.Live.Exchanges) + len(t.Live.Bindings)
	}
	return n
}

func (t *Topology) add(cat *[]TopoEntry, e TopoEntry, seen map[string]bool) {
	k := fmt.Sprintf("%p|%s|%s|%s|%d", cat, e.Kind, e.Name, e.FilePath, e.Line)
	if seen[k] {
		return
	}
	seen[k] = true
	*cat = append(*cat, e)
}

// finishKeys turns the collected key usage into KeySpace entries.
func (t *Topology) finishKeys() {
	for pat, a := range t.keys {
		var cmds []string
		for c := range a.cmds {
			cmds = append(cmds, strings.ToUpper(c))
		}
		sort.Strings(cmds)
		d := strings.Join(cmds, ", ")
		if a.ttl {
			d += " · TTL"
		} else if a.typ != "stream" && a.typ != "pub/sub" {
			d += " · no TTL seen"
		}
		if a.n > 1 {
			d += fmt.Sprintf(" · ×%d", a.n)
		}
		t.KeySpace = append(t.KeySpace, TopoEntry{Kind: a.typ, Name: pat, Detail: d, FilePath: a.filePath, Line: a.line})
	}
	t.keys = nil
}

func (t *Topology) sort() {
	t.finishKeys()
	for _, s := range []*[]TopoEntry{&t.Celery, &t.Transactions, &t.Redis, &t.KeySpace, &t.MQ} {
		sort.SliceStable(*s, func(i, j int) bool {
			a, b := (*s)[i], (*s)[j]
			if a.Kind != b.Kind {
				return a.Kind < b.Kind
			}
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			return a.FilePath < b.FilePath
		})
	}
}

// topoRule is one line-level pattern: the category it feeds, the kind it
// reports, the regex, and which group (0 = none) names the thing.
type topoRule struct {
	langs string // file extensions it applies to, e.g. ".py .go"
	cat   string // celery | tx | redis | mq
	kind  string
	re    *regexp.Regexp
	name  int
}

func r(s string) *regexp.Regexp { return regexp.MustCompile(s) }

const q = `['"` + "`" + `]`

var topoRules = []topoRule{
	// ── transactions (Python / Django / SQLAlchemy) ──
	{".py", "tx", "atomic", r(`\b(?:transaction\.)?atomic\s*\(([^)]*)\)`), 1},
	{".py", "tx", "atomic", r(`^\s*@(?:transaction\.)?atomic\s*$`), 0},
	{".py", "tx", "atomic", r(`\bwith\s+(?:transaction\.)?atomic\b`), 0},
	{".py", "tx", "row lock", r(`\.select_for_update\s*\(([^)]*)\)`), 1},
	{".py", "tx", "on_commit", r(`\b(?:transaction\.)?on_commit\s*\(`), 0},
	{".py", "tx", "savepoint", r(`\btransaction\.savepoint\s*\(|\.begin_nested\s*\(`), 0},
	{".py", "tx", "atomic requests", r(`ATOMIC_REQUESTS\s*[:=]\s*True`), 0},
	{".py", "tx", "non-atomic view", r(`@(?:transaction\.)?non_atomic_requests`), 0},
	{".py", "tx", "session.begin", r(`\b(?:session|Session\(\w*\))\.begin\s*\(`), 0},
	// ── Redis ──
	{".py .go .ts .js .java .kt", "redis", "sentinel", r(`\b(?:Sentinel|NewSentinelClient|NewFailoverClient|JedisSentinelPool|RedisSentinelConfiguration)\s*\(`), 0},
	{".py .go .ts .js .java .kt", "redis", "cluster", r(`\b(?:RedisCluster|NewClusterClient|Redis\.Cluster|JedisCluster|RedisClusterConfiguration)\b`), 0},
	{".py .go .ts .js .java .kt", "redis", "client", r(`\b(?:redis\.(?:Strict)?Redis|aioredis\.Redis|redis\.asyncio\.Redis|NewClient|NewUniversalClient|new\s+Redis|new\s+Jedis|JedisPool|createClient|LettuceConnectionFactory|RedisTemplate)\s*(?:\(|<|\b)`), 0},
	{".py", "redis", "client", r(`\b(?:Redis|StrictRedis)\.from_url\s*\(|\bredis\.from_url\s*\(`), 0},
	{".py .go .ts .js .java .kt", "redis", "pub/sub", r(`\.(?:pubsub|Subscribe|PSubscribe|subscribe|psubscribe)\s*\(\s*` + q + `?([\w.:*-]*)`), 1},
	{".py .go .ts .js .java .kt", "redis", "lock", r(`\b(?:\.lock|Lock|NewMutex|redsync)\s*\(\s*` + q + `([\w.:{}-]+)` + q), 1},
	{".py .go .ts .js .java .kt", "redis", "stream", r(`\.(?:xadd|xread|xreadgroup|XAdd|XRead|XReadGroup|xGroupCreate)\s*\(\s*` + q + `?([\w.:-]*)`), 1},
	// ── message queues ──
	{".py", "mq", "queue", r(`\bQueue\s*\(\s*` + q + `([\w.@:-]+)` + q), 1},
	{".py", "mq", "exchange", r(`\bExchange\s*\(\s*` + q + `([\w.@:-]+)` + q), 1},
	{".py .go .ts .js .java .kt", "mq", "queue", r(`(?:queue_declare|QueueDeclare|assertQueue)\s*\(\s*(?:queue\s*=\s*)?` + q + `([\w.@:-]+)` + q), 1},
	{".py .go .ts .js .java .kt", "mq", "exchange", r(`(?:exchange_declare|ExchangeDeclare|assertExchange)\s*\(\s*(?:exchange\s*=\s*)?` + q + `([\w.@:-]+)` + q), 1},
	{".py .go .ts .js .java .kt", "mq", "binding", r(`(?:queue_bind|QueueBind|bindQueue)\s*\(`), 0},
	{".py .go .ts .js", "mq", "producer", r(`\b(?:basic_publish|KafkaProducer|NewSyncProducer|NewAsyncProducer|kafka\.NewWriter|\.producer\s*\(|aio_pika\.[\w.]*publish)\b`), 0},
	{".py .go .ts .js", "mq", "consumer", r(`\b(?:basic_consume|KafkaConsumer|NewConsumerGroup|kafka\.NewReader|\.consumer\s*\(|channel\.consume)\b`), 0},
	{".py .go .ts .js", "mq", "queue", r(`\bnew\s+(?:Queue|Worker)\s*\(\s*` + q + `([\w.:-]+)` + q), 1},
	{".java .kt", "mq", "consumer", r(`@(?:Kafka|Rabbit|Jms|Sqs)Listener\s*\(\s*(?:(?:topics|queues|destination|value)\s*=\s*)?\{?\s*` + q + `([\w.@:-]+)` + q), 1},
	{".py .go .ts .js .java .kt", "mq", "broker", r(`\b(?:nats\.Connect|amqp\.Dial|NewConnection|aio_pika\.connect\w*|amqplib\.connect|new\s+Kafka)\s*\(`), 0},
	{".py", "mq", "task routes", r(`\b(?:task_routes|CELERY_TASK_ROUTES|task_queues|CELERY_TASK_QUEUES)\b\s*[:=]`), 0},
}

// redisCmds maps a Redis command to the data type it works on.
var redisCmds = map[string]string{
	"get": "string", "set": "string", "setex": "string", "setnx": "string", "getset": "string", "incr": "string", "incrby": "string",
	"decr": "string", "decrby": "string", "mget": "string", "append": "string", "getdel": "string",
	"hget": "hash", "hset": "hash", "hgetall": "hash", "hmset": "hash", "hmget": "hash", "hdel": "hash", "hincrby": "hash", "hexists": "hash",
	"lpush": "list", "rpush": "list", "lpop": "list", "rpop": "list", "lrange": "list", "llen": "list", "brpop": "list", "blpop": "list", "ltrim": "list",
	"sadd": "set", "srem": "set", "smembers": "set", "sismember": "set", "scard": "set", "spop": "set",
	"zadd": "zset", "zrange": "zset", "zrem": "zset", "zrangebyscore": "zset", "zincrby": "zset", "zscore": "zset", "zcard": "zset",
	"xadd": "stream", "xread": "stream", "xreadgroup": "stream", "xack": "stream",
	"publish": "pub/sub",
	"expire":  "ttl", "pexpire": "ttl", "ttl": "ttl", "exists": "any", "del": "any", "delete": "any", "unlink": "any",
}

var (
	// a Redis command whose first argument is a literal (or f-string / template) key
	reRedisKey = regexp.MustCompile(`(?i)\.(` + "get|set|setex|setnx|getset|incrby|incr|decrby|decr|mget|append|getdel|hget|hset|hgetall|hmset|hmget|hdel|hincrby|hexists|lpush|rpush|lpop|rpop|lrange|llen|brpop|blpop|ltrim|sadd|srem|smembers|sismember|scard|spop|zadd|zrange|zrem|zrangebyscore|zincrby|zscore|zcard|xadd|xread|xack|publish|expire|pexpire|ttl|exists|delete|del|unlink" + `)\(\s*(?:ctx\s*,\s*)?[fFbB]?` + q + `([^'"` + "`" + `]{2,80})` + q)
	reKeyHole  = regexp.MustCompile(`\{[^}]*\}|%[sdvq]|\$\{[^}]*\}|<[^>]*>`)
	reTTLArg   = regexp.MustCompile(`(?i)(?:ex|px|exat|expire|ttl)\s*=|EX|time\.\w+|Duration|setex`)
)

var (
	reTopoURL   = regexp.MustCompile(`\b(rediss?|redis\+sentinel|amqps?|pyamqp|kafka|nats|sqs|mqtts?)://([^\s'"` + "`" + `)>,]+)`)
	reURLSecret = regexp.MustCompile(`://([^:/@\s]*):[^@/\s]+@`)
	reBrokerKey = regexp.MustCompile(`(?i)(?:broker_url|broker_transport|CELERY_BROKER_URL|CELERY_RESULT_BACKEND|result_backend)`)

	reCeleryDeco = regexp.MustCompile(`^\s*@(?:[\w.]+\.)?(task|shared_task|periodic_task|celery\.task)\b\s*(\()?`)
	reCeleryCls  = regexp.MustCompile(`^\s*class\s+(\w+)\s*\(\s*(?:[\w.]*\.)?Task\s*\)`)
	reTopoPyDef  = regexp.MustCompile(`^\s*(?:async\s+)?def\s+(\w+)\s*\(`)
	reCrontab    = regexp.MustCompile(`\b(crontab|schedule)\s*\(([^)]*)\)`)
	reKwArg      = regexp.MustCompile(`\b(queue|name|bind|max_retries|autoretry_for|acks_late|rate_limit|time_limit|soft_time_limit|retry_backoff|retry_jitter|ignore_result|default_retry_delay|priority|serializer)\s*=\s*([^,)]+)`)
	reApplyAsync = regexp.MustCompile(`\.apply_async\s*\(([^)]*)\)`)
)

func hasExt(exts, e string) bool {
	for _, x := range strings.Fields(exts) {
		if x == e {
			return true
		}
	}
	return false
}

func maskSecret(s string) string { return reURLSecret.ReplaceAllString(s, "://$1:***@") }

func isCommentLine(t, e string) bool {
	if e == ".py" {
		return strings.HasPrefix(t, "#")
	}
	return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*")
}

// scanTopology reads one file's raw lines into t.
func scanTopology(t *Topology, filePath, e string, lines []string, seen map[string]bool) {
	if t.keys == nil {
		t.keys = map[string]*keyAgg{}
	}
	cat := func(c string) *[]TopoEntry {
		switch c {
		case "tx":
			return &t.Transactions
		case "redis":
			return &t.Redis
		case "mq":
			return &t.MQ
		}
		return &t.Celery
	}
	code := maskSource(lines, e).code
	// inCode: the match starts on code, not inside a string or comment (a detector's
	// own `Contains(line, "transaction.atomic(")` is not a transaction).
	inCode := func(i, lead, at int) bool {
		return lead+at < len(code[i]) && code[i][lead+at] != ' '
	}
	for i, raw := range lines {
		tr := strings.TrimSpace(raw)
		if tr == "" || isCommentLine(tr, e) {
			continue
		}
		lead := len(raw) - len(strings.TrimLeft(raw, " \t"))
		searching := parser.SearchesText(tr)
		for _, rule := range topoRules {
			if !hasExt(rule.langs, e) {
				continue
			}
			loc := rule.re.FindStringSubmatchIndex(tr)
			if loc == nil || !inCode(i, lead, loc[0]) {
				continue
			}
			g := rule.re.FindStringSubmatch(tr)
			name := ""
			if rule.name > 0 && rule.name < len(g) {
				name = strings.TrimSpace(g[rule.name])
			}
			detail := ""
			if rule.cat == "tx" && name != "" {
				detail = name
				name = ""
			}
			t.add(cat(rule.cat), TopoEntry{Kind: rule.kind, Name: name, Detail: detail, FilePath: filePath, Line: i + 1}, seen)
		}
		if m := reRedisKey.FindStringSubmatch(tr); m != nil && !searching && (strings.Contains(m[2], ":") || strings.Contains(strings.ToLower(tr), "redis") || strings.Contains(strings.ToLower(tr), "cache")) {
			cmd := strings.ToLower(m[1])
			typ := redisCmds[cmd]
			pat := strings.TrimSpace(reKeyHole.ReplaceAllString(m[2], "*"))
			if typ != "" && pat != "" && !strings.ContainsAny(pat, " ()=") {
				a := t.keys[pat]
				if a == nil {
					a = &keyAgg{typ: typ, cmds: map[string]bool{}, filePath: filePath, line: i + 1}
					t.keys[pat] = a
				}
				if a.typ == "any" || a.typ == "ttl" {
					a.typ = typ
				}
				a.cmds[cmd] = true
				a.n++
				if cmd == "setex" || cmd == "expire" || cmd == "pexpire" || reTTLArg.MatchString(tr) {
					a.ttl = true
				}
			}
		}
		for _, m := range reTopoURL.FindAllStringSubmatch(tr, -1) {
			if searching {
				break
			}
			target := maskSecret(m[0])
			switch m[1] {
			case "redis", "rediss", "redis+sentinel":
				kind := "url"
				if reBrokerKey.MatchString(tr) {
					t.add(&t.MQ, TopoEntry{Kind: "broker", Name: target, Detail: "Celery/Kombu broker or result backend (Redis)", FilePath: filePath, Line: i + 1}, seen)
				}
				if m[1] == "redis+sentinel" {
					kind = "sentinel url"
				}
				t.add(&t.Redis, TopoEntry{Kind: kind, Name: target, FilePath: filePath, Line: i + 1}, seen)
			default:
				t.add(&t.MQ, TopoEntry{Kind: "broker", Name: target, FilePath: filePath, Line: i + 1}, seen)
			}
		}
		if e == ".py" {
			if m := reApplyAsync.FindStringSubmatch(tr); m != nil {
				if kw := kwSummary(m[1], "queue", "countdown", "eta", "priority"); kw != "" {
					t.add(&t.MQ, TopoEntry{Kind: "enqueue", Name: strings.TrimSpace(strings.SplitN(tr, ".apply_async", 2)[0]), Detail: kw, FilePath: filePath, Line: i + 1}, seen)
				}
			}
			if m := reCrontab.FindStringSubmatch(tr); m != nil && (strings.Contains(strings.ToLower(tr), "schedule") || m[1] == "crontab") {
				t.add(&t.Celery, TopoEntry{Kind: "schedule", Name: m[1] + "(" + strings.TrimSpace(m[2]) + ")", FilePath: filePath, Line: i + 1}, seen)
			}
			if m := reCeleryCls.FindStringSubmatch(tr); m != nil {
				t.add(&t.Celery, TopoEntry{Kind: "class-based", Name: m[1], FilePath: filePath, Line: i + 1}, seen)
			}
			if m := reCeleryDeco.FindStringSubmatch(tr); m != nil {
				kind := m[1]
				if kind == "celery.task" {
					kind = "task"
				}
				opts, end := tr, i
				if m[2] != "" { // decorator arguments may span lines
					for depth := strings.Count(tr, "(") - strings.Count(tr, ")"); depth > 0 && end+1 < len(lines) && end < i+8; {
						end++
						opts += " " + strings.TrimSpace(lines[end])
						depth += strings.Count(lines[end], "(") - strings.Count(lines[end], ")")
					}
				}
				name := ""
				for j := end + 1; j < len(lines) && j < end+6; j++ {
					if d := reTopoPyDef.FindStringSubmatch(lines[j]); d != nil {
						name = d[1]
						break
					}
				}
				kind = celeryKind(kind, opts)
				t.add(&t.Celery, TopoEntry{Kind: kind, Name: name, Detail: kwSummary(opts, "queue", "name", "bind", "max_retries", "autoretry_for", "retry_backoff", "acks_late", "rate_limit", "time_limit", "soft_time_limit", "ignore_result", "priority"), FilePath: filePath, Line: i + 1}, seen)
			}
		}
	}
}

// celeryKind refines a decorator into the task's type.
func celeryKind(deco, opts string) string {
	switch {
	case deco == "periodic_task":
		return "periodic"
	case strings.Contains(opts, "autoretry_for") || strings.Contains(opts, "max_retries"):
		return deco + " · retrying"
	case strings.Contains(opts, "bind=True"):
		return deco + " · bound"
	}
	return deco
}

// kwSummary picks the named keyword arguments out of an argument list.
func kwSummary(args string, keys ...string) string {
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	var out []string
	for _, m := range reKwArg.FindAllStringSubmatch(args, -1) {
		if want[m[1]] {
			out = append(out, m[1]+"="+strings.TrimSpace(strings.Trim(strings.TrimSpace(m[2]), `"'`)))
		}
	}
	return strings.Join(out, " · ")
}

// ── rendering ──

type topoSection struct {
	icon, title, hint string
	entries           []TopoEntry
	nameHeader        string
}

func live(t Topology) *Live {
	if t.Live == nil {
		return &Live{}
	}
	return t.Live
}

func (t Topology) sections() []topoSection {
	return []topoSection{
		{"🥬", "Celery tasks", "Task definitions by type (task · shared_task · periodic · retrying · bound · class-based), with their queue, retry and timing settings, and beat schedules.", t.Celery, "Task"},
		{"🔐", "Atomic transactions", "Transaction boundaries: atomic blocks and decorators, row locks (select_for_update), savepoints, on_commit hooks and ATOMIC_REQUESTS.", t.Transactions, "Settings"},
		{"🟥", "Redis topology", "Where the code talks to Redis: clients, sentinels and clusters, connection URLs (passwords masked), pub/sub channels, locks and streams.", t.Redis, "Target"},
		{"🗝️", "Redis key space", "Key patterns the code reads and writes (variable parts shown as *), grouped by data type, with the commands used and whether a TTL is ever set — keys without one live forever.", t.KeySpace, "Key pattern"},
		{"🩺", "Code vs live workers", "Celery tasks that differ between the scanned source and the workers `celery inspect registered` reported.", t.Drift, "Task"},
		{"📋", "Registered on workers", "Tasks the live workers report (celery inspect registered), with the workers that have them.", live(t).Registered, "Task"},
		{"⏳", "Scheduled tasks", "Tasks waiting for their ETA on the workers (celery inspect scheduled).", live(t).Scheduled, "Task"},
		{"🐇", "RabbitMQ queues", "Live queues with message and consumer counts (rabbitmqctl list_queues).", live(t).Queues, "Queue"},
		{"🔀", "RabbitMQ exchanges", "Live exchanges and their types (rabbitmqctl list_exchanges).", live(t).Exchanges, "Exchange"},
		{"🔗", "RabbitMQ bindings", "Which exchange routes to which queue or exchange, and with what routing key (rabbitmqctl list_bindings).", live(t).Bindings, "Binding"},
		{"📨", "MQ topology", "Brokers, queues, exchanges, bindings, producers and consumers, and Celery enqueue calls with their queue.", t.MQ, "Target"},
	}
}

func writeTopology(b *strings.Builder, t Topology) {
	for _, s := range t.sections() {
		if len(s.entries) == 0 {
			continue
		}
		writeSubOpen(b, "", s.icon, html.EscapeString(s.title), len(s.entries), s.hint)
		fmt.Fprintf(b, `<table class="as-table as-cs__table"><thead><tr><th>Type</th><th>%s</th><th>Details</th><th>Where</th></tr></thead><tbody>`, s.nameHeader)
		for i, e := range s.entries {
			if i == maxIssueLocations {
				fmt.Fprintf(b, `<tr><td colspan="4" class="as-cs__more">… and %d more</td></tr>`, len(s.entries)-maxIssueLocations)
				break
			}
			fmt.Fprintf(b, `<tr><td>%s</td><td class="mono">%s</td><td>%s</td><td class="mono">%s</td></tr>`,
				html.EscapeString(e.Kind), html.EscapeString(e.Name), html.EscapeString(e.Detail),
				topoWhere(e, true))
		}
		b.WriteString(`</tbody></table>`)
		writeSubClose(b)
	}
}

func topologyMarkdown(b *strings.Builder, t Topology) {
	for _, s := range t.sections() {
		if len(s.entries) == 0 {
			continue
		}
		mdSubOpen(b, s.icon, s.title, len(s.entries), s.hint)
		fmt.Fprintf(b, "| Type | %s | Details | Where |\n|------|------|---------|-------|\n", s.nameHeader)
		for i, e := range s.entries {
			if i == maxIssueLocations {
				fmt.Fprintf(b, "| | | | … and %d more |\n", len(s.entries)-maxIssueLocations)
				break
			}
			fmt.Fprintf(b, "| %s | %s | %s | %s |\n", mdTableCell(e.Kind), mdTableCell(e.Name), mdTableCell(e.Detail), topoWhere(e, false))
		}
		b.WriteString("\n")
	}
}

// topoWhere is an entry's location: a link (HTML) or file:line (Markdown); "—"
// for entries that don't come from one source line (aggregated live data).
func topoWhere(e TopoEntry, link bool) string {
	switch {
	case e.FilePath == "":
		return "—"
	case e.Line == 0:
		return html.EscapeString(baseName(e.FilePath))
	case link:
		return occurrenceLink(fmt.Sprintf("%s:%d", baseName(e.FilePath), e.Line), e.FilePath, e.Line)
	}
	return fmt.Sprintf("%s:%d", baseName(e.FilePath), e.Line)
}
