// concurrency_dumps.go reads saved output of live inspection commands into the
// 🧵 Concurrency card's topology: `celery inspect registered`, `celery inspect
// scheduled` (plain or --json) and `rabbitmqctl list_queues | list_exchanges |
// list_bindings`. The code says what *should* exist; the dumps say what does —
// and the card flags tasks that differ between the two.
package constructs

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var (
	dumpMu    sync.Mutex
	dumpPaths []string
	dumpCache *Live
)

// SetInspectDumps registers the --inspect files (absolute paths).
func SetInspectDumps(paths []string) {
	dumpMu.Lock()
	dumpPaths, dumpCache = append([]string(nil), paths...), nil
	dumpMu.Unlock()
}

// Live is what the dumps show.
type Live struct {
	Registered []TopoEntry // celery inspect registered: one per task, workers in Detail
	Scheduled  []TopoEntry // celery inspect scheduled: ETA'd tasks
	Queues     []TopoEntry
	Exchanges  []TopoEntry
	Bindings   []TopoEntry
}

// Empty reports whether the dumps held no registered tasks, schedule, queues, exchanges or bindings; a nil Live is empty.
func (l *Live) Empty() bool {
	return l == nil || len(l.Registered)+len(l.Scheduled)+len(l.Queues)+len(l.Exchanges)+len(l.Bindings) == 0
}

// loadLive parses every --inspect file once.
func loadLive() *Live {
	dumpMu.Lock()
	defer dumpMu.Unlock()
	if dumpCache != nil {
		return dumpCache
	}
	l := &Live{}
	tasks := map[string]map[string]bool{}
	for _, p := range dumpPaths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		parseDump(l, p, string(b), tasks)
	}
	for name, ws := range tasks {
		var w []string
		for n := range ws {
			w = append(w, n)
		}
		sort.Strings(w)
		l.Registered = append(l.Registered, TopoEntry{Kind: "registered", Name: name, Detail: fmt.Sprintf("%d worker(s): %s", len(w), strings.Join(w, ", "))})
	}
	for _, s := range []*[]TopoEntry{&l.Registered, &l.Scheduled, &l.Queues, &l.Exchanges, &l.Bindings} {
		sort.SliceStable(*s, func(i, j int) bool { return (*s)[i].Name < (*s)[j].Name })
	}
	dumpCache = l
	return l
}

var (
	reCeleryNode  = regexp.MustCompile(`^->\s*(\S+?):\s*(?:OK|\{|$)`)
	reCeleryItem  = regexp.MustCompile(`^\s*\*\s*(\S+)(.*)$`)
	reSchedETA    = regexp.MustCompile(`['"]eta['"]:\s*u?['"]([^'"]+)['"]`)
	reSchedName   = regexp.MustCompile(`['"]name['"]:\s*u?['"]([\w.\-]+)['"]`)
	reSchedPrio   = regexp.MustCompile(`['"]priority['"]:\s*(\d+)`)
	reTaskNameOK  = regexp.MustCompile(`^[\w.\-]+$`)
	reRabbitStamp = regexp.MustCompile(`(?i)^(timeout:|listing (queues|exchanges|bindings)|\.\.\.)`)
)

func parseDump(l *Live, path, src string, tasks map[string]map[string]bool) {
	trim := strings.TrimSpace(src)
	if strings.HasPrefix(trim, "{") || strings.HasPrefix(trim, "[") {
		parseCeleryJSON(l, path, trim, tasks)
		return
	}
	lines := strings.Split(src, "\n")
	// RabbitMQ: a header or "Listing …" line decides which table follows.
	mode := ""
	var cols []string
	node := ""
	for i, raw := range lines {
		t := strings.TrimRight(raw, "\r ")
		if t == "" {
			continue
		}
		low := strings.ToLower(strings.TrimSpace(t))
		if m := reCeleryNode.FindStringSubmatch(strings.TrimSpace(t)); m != nil {
			node, mode = m[1], "celery"
			continue
		}
		if mode == "celery" {
			if m := reCeleryItem.FindStringSubmatch(t); m != nil {
				rest := strings.TrimSpace(m[2])
				if strings.Contains(t, "eta") && reSchedName.MatchString(t) {
					eta := first(reSchedETA, t)
					d := "eta " + eta
					if p := first(reSchedPrio, t); p != "" {
						d += " · priority " + p
					}
					l.Scheduled = append(l.Scheduled, TopoEntry{Kind: "scheduled", Name: first(reSchedName, t), Detail: d + " · " + node, FilePath: path, Line: i + 1})
				} else if reTaskNameOK.MatchString(m[1]) {
					addTask(tasks, m[1], node)
					_ = rest
				}
				continue
			}
		}
		switch {
		case strings.HasPrefix(low, "listing queues"):
			mode, cols = "queues", nil
			continue
		case strings.HasPrefix(low, "listing exchanges"):
			mode, cols = "exchanges", nil
			continue
		case strings.HasPrefix(low, "listing bindings"):
			mode, cols = "bindings", nil
			continue
		case reRabbitStamp.MatchString(low):
			continue
		}
		f := splitCols(t)
		if len(f) == 0 {
			continue
		}
		// header rows name their columns
		switch {
		case f[0] == "name" && (len(f) == 1 || f[1] == "messages" || f[1] == "type" || f[1] == "consumers" || strings.Contains(low, "messages") || strings.Contains(low, "type")):
			if strings.Contains(low, "type") && !strings.Contains(low, "messages") {
				mode = "exchanges"
			} else if mode == "" || mode == "celery" {
				mode = "queues"
			}
			cols = f
			continue
		case f[0] == "source_name":
			mode, cols = "bindings", f
			continue
		}
		switch mode {
		case "queues":
			e := TopoEntry{Kind: "queue", Name: f[0], FilePath: path, Line: i + 1}
			var d []string
			for j := 1; j < len(f); j++ {
				label := "col" + strconv.Itoa(j)
				if j < len(cols) {
					label = cols[j]
				} else if j == 1 {
					label = "messages"
				} else if j == 2 {
					label = "consumers"
				}
				d = append(d, label+"="+f[j])
			}
			e.Detail = strings.Join(d, " · ")
			l.Queues = append(l.Queues, e)
		case "exchanges":
			typ := ""
			if len(f) > 1 {
				typ = f[1]
			}
			if f[0] == "" {
				f[0] = "(default)"
			}
			l.Exchanges = append(l.Exchanges, TopoEntry{Kind: typ, Name: f[0], FilePath: path, Line: i + 1})
		case "bindings":
			if len(f) >= 5 {
				src, dst, rk := f[0], f[2], f[4]
				if src == "" {
					src = "(default)"
				}
				l.Bindings = append(l.Bindings, TopoEntry{Kind: f[3], Name: src + " → " + dst, Detail: "routing key: " + rk, FilePath: path, Line: i + 1})
			}
		}
	}
}

func first(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

func addTask(tasks map[string]map[string]bool, name, node string) {
	if tasks[name] == nil {
		tasks[name] = map[string]bool{}
	}
	tasks[name][node] = true
}

// splitCols splits a rabbitmqctl row: tab-separated, falling back to runs of spaces.
func splitCols(t string) []string {
	if strings.Contains(t, "\t") {
		out := strings.Split(t, "\t")
		for i := range out {
			out[i] = strings.TrimSpace(out[i])
		}
		return out
	}
	return strings.Fields(t)
}

// parseCeleryJSON reads `celery inspect registered|scheduled --json`:
// {"worker": ["task", …]} or {"worker": [{"eta": …, "request": {"name": …}}]},
// possibly wrapped in a list.
func parseCeleryJSON(l *Live, path, src string, tasks map[string]map[string]bool) {
	var any interface{}
	if err := json.Unmarshal([]byte(src), &any); err != nil {
		return
	}
	var walk func(node string, v interface{})
	walk = func(node string, v interface{}) {
		switch x := v.(type) {
		case []interface{}:
			for _, it := range x {
				walk(node, it)
			}
		case map[string]interface{}:
			if eta, ok := x["eta"].(string); ok {
				name := ""
				if rq, ok := x["request"].(map[string]interface{}); ok {
					name, _ = rq["name"].(string)
				}
				d := "eta " + eta
				if p, ok := x["priority"].(float64); ok {
					d += fmt.Sprintf(" · priority %d", int(p))
				}
				l.Scheduled = append(l.Scheduled, TopoEntry{Kind: "scheduled", Name: name, Detail: d + " · " + node, FilePath: path})
				return
			}
			for k, val := range x {
				if k == "ok" || k == "error" {
					walk(node, val)
				} else {
					walk(k, val)
				}
			}
		case string:
			if reTaskNameOK.MatchString(x) && strings.Contains(x, ".") || strings.HasPrefix(x, "celery.") {
				addTask(tasks, x, node)
			} else if reTaskNameOK.MatchString(x) {
				addTask(tasks, x, node)
			}
		}
	}
	walk("worker", any)
}

// ── comparing with the code ──

// reconcile marks registered tasks the code doesn't define, and code tasks no
// worker has registered, so drift between the two is visible.
func (l *Live) reconcile(code []TopoEntry) (extra []TopoEntry) {
	if l.Empty() || len(l.Registered) == 0 {
		return nil
	}
	inCode := map[string]bool{}
	for _, c := range code {
		if c.Name != "" && !strings.HasPrefix(c.Kind, "schedule") {
			inCode[c.Name] = true
		}
	}
	reg := map[string]bool{}
	for i := range l.Registered {
		name := l.Registered[i].Name
		last := name[strings.LastIndex(name, ".")+1:]
		reg[last] = true
		if strings.HasPrefix(name, "celery.") {
			continue
		}
		if len(inCode) > 0 && !inCode[last] {
			extra = append(extra, TopoEntry{Kind: "registered, not in code", Name: name, Detail: "a worker runs it, but no task of that name is defined in the scanned source"})
		}
	}
	for c := range inCode {
		if !reg[c] {
			extra = append(extra, TopoEntry{Kind: "in code, not registered", Name: c, Detail: "defined in the source, but no inspected worker has it registered — not deployed, or imported lazily"})
		}
	}
	return extra
}
