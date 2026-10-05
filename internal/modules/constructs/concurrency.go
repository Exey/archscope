// concurrency.go is the 🧵 Concurrency & API Misuse card: Go-only checks
// ported from go-critic that catch concurrency and standard-library misuse —
// sync.Map load-then-delete races (syncMapLoadAndDelete), exposed embedded
// mutexes (exposedSyncMutex), sync.OnceFunc used wrongly (badSyncOnceFunc),
// nil request bodies (httpNoBody), hand-rolled time conversions
// (timeExprSimplify) and wg.Add(-1). It feeds ⚡ Performance in Programming
// Culture. Lexical, over the length-preserving masked source (srcmask.go).
package constructs

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/security"
)

func init() { modules.Default.Register(Concurrency{}) }

// Concurrency is the concurrency / API-misuse detector.
type Concurrency struct{}

func (Concurrency) ID() string                       { return "concurrency" }
func (Concurrency) Title() string                    { return "Concurrency & API Misuse" }
func (Concurrency) AppliesTo(languageID string) bool { return languageID == "go" }

// ConcurrencyReport is the module output.
type ConcurrencyReport struct {
	Issues            []CSIssue
	High, Medium, Low int
}

func (r ConcurrencyReport) HasData() bool { return len(r.Issues) > 0 }
func (r ConcurrencyReport) Total() int    { return len(r.Issues) }

var (
	reSyncMapLoad  = regexp.MustCompile(`^\s*(?:\w+|_)\s*,\s*\w+\s*:?=\s*(` + goOperand + `)\.Load\(\s*(.+?)\s*\)\s*$`)
	reSyncMapDel   = regexp.MustCompile(`\b(` + goOperand + `)\.Delete\(\s*(.+?)\s*\)\s*$`)
	reEmbeddedMu   = regexp.MustCompile(`^\s*\*?sync\.(?:RW)?Mutex\s*$`)
	reGoTypeStruct = regexp.MustCompile(`^\s*type\s+([A-Za-z_]\w*)\s+struct\s*\{`)
	reOnceFunc     = regexp.MustCompile(`\bsync\.Once(?:Func|Value|Values)\s*\(`)
	reNewRequest   = regexp.MustCompile(`\b(?:http\.NewRequest|http\.NewRequestWithContext|httptest\.NewRequest)\s*\(`)
	reUnixMilli    = regexp.MustCompile(`\.UnixNano\(\)\s*/\s*(?:1_?000_?000|1e6|int64\(time\.Millisecond\))(?:[^\d_]|$)`)
	reUnixMicro    = regexp.MustCompile(`\.UnixNano\(\)\s*/\s*(?:1_?000|1e3|int64\(time\.Microsecond\))(?:[^\d_]|$)`)
	reUnixTimes    = regexp.MustCompile(`\.Unix\(\)\s*\*\s*(?:1_?000)(?:[^\d_]|$)`)
	reWgAddNeg     = regexp.MustCompile(`\b\w*(?:[wW][gG]|[wW]ait\w*)\.Add\(\s*-1\s*\)`)
)

// Analyze scans every non-test Go file.
func (Concurrency) Analyze(files []*parser.ParsedFile) any {
	cache := newSourceCache()
	var rep ConcurrencyReport
	for _, f := range files {
		if ext(f.FilePath) != ".go" || security.IsTestOrBenchPath(f.FilePath) || isConstructDetectorFile(f.FilePath) {
			continue
		}
		if raw := cache.rawLines(f.FilePath); raw != nil {
			rep.Issues = append(rep.Issues, scanConcurrency(f.FilePath, maskSource(raw, ".go"))...)
		}
	}
	sortIssuesBySeverity(rep.Issues)
	rep.High, rep.Medium, rep.Low = issueSevCounts(rep.Issues)
	return rep
}

func scanConcurrency(filePath string, m maskedFile) []CSIssue {
	var out []CSIssue
	add := func(li int, sev security.Severity, id, rule, msg string) {
		snip := strings.TrimSpace(m.raw[li])
		if len(snip) > 100 {
			snip = snip[:100] + "…"
		}
		out = append(out, CSIssue{RuleID: id, Rule: rule, Message: msg, Severity: sev, FilePath: filePath, Line: li + 1, Snippet: snip})
	}
	f := m.flat()

	for i, line := range m.code {
		if strings.TrimSpace(line) == "" {
			continue
		}
		// syncMapLoadAndDelete: v, ok := m.Load(k) … m.Delete(k).
		if g := reSyncMapLoad.FindStringSubmatch(line); g != nil {
			for j, seen := nextSig(m.code, i), 0; j >= 0 && seen < 4; j, seen = nextSig(m.code, j), seen+1 {
				if d := reSyncMapDel.FindStringSubmatch(m.code[j]); d != nil && d[1] == g[1] && squash(d[2]) == squash(g[2]) {
					add(j, security.SevMedium, "sync-map-load-delete", "sync.Map Load then Delete",
						"Another goroutine can change the entry between Load and Delete; use "+g[1]+".LoadAndDelete(key) to do both atomically.")
					break
				}
			}
		}
		// exposedSyncMutex: exported struct embedding a bare mutex.
		if g := reGoTypeStruct.FindStringSubmatch(line); g != nil && g[1][0] >= 'A' && g[1][0] <= 'Z' {
			if end := matchBraceEnd(m.code, i); end > i {
				for j := i + 1; j < end; j++ {
					if reEmbeddedMu.MatchString(m.code[j]) {
						add(j, security.SevLow, "exposed-mutex", "Embedded sync.Mutex in an exported type",
							"Embedding promotes Lock/Unlock into "+g[1]+"'s public API, letting any caller take its lock. Use an unexported field: `mu sync.Mutex`.")
					}
				}
			}
		}
		if reWgAddNeg.MatchString(line) {
			add(i, security.SevLow, "wg-add-negative", "WaitGroup.Add(-1)", "Use wg.Done(); it says what it means and can't be mistyped.")
		}
		if reUnixMilli.MatchString(line) {
			add(i, security.SevLow, "time-expr", "Manual time conversion", "Use t.UnixMilli() (Go 1.17+) instead of dividing UnixNano().")
		} else if reUnixMicro.MatchString(line) {
			add(i, security.SevLow, "time-expr", "Manual time conversion", "Use t.UnixMicro() (Go 1.17+) instead of dividing UnixNano().")
		} else if reUnixTimes.MatchString(line) {
			add(i, security.SevLow, "time-expr", "Manual time conversion", "`t.Unix() * 1000` drops the sub-second part; use t.UnixMilli() (Go 1.17+).")
		}
	}

	// badSyncOnceFunc: result unused or immediately invoked.
	for _, loc := range reOnceFunc.FindAllStringIndex(f.code, -1) {
		cl := f.matchClose(loc[1] - 1)
		if cl < 0 {
			continue
		}
		li := f.line(loc[0])
		next := f.skipSpace(cl + 1)
		switch {
		case next < len(f.code) && f.code[next] == '(':
			add(li, security.SevMedium, "once-func-misuse", "sync.OnceFunc called immediately",
				"`sync.OnceFunc(f)()` builds a new once-wrapper and calls it straight away, so it runs every time; assign the wrapper to a variable and call that.")
		case strings.HasPrefix(strings.TrimSpace(m.code[li]), "sync.Once") && strings.TrimSpace(m.code[f.line(cl)][cl-f.starts[f.line(cl)]+1:]) == "":
			add(li, security.SevMedium, "once-func-misuse", "sync.OnceFunc result discarded",
				"The function returned by sync.OnceFunc is the only thing that runs once; discarding it makes the call pointless.")
		}
	}

	// httpNoBody: nil as the body argument.
	for _, loc := range reNewRequest.FindAllStringIndex(f.code, -1) {
		cl := f.matchClose(loc[1] - 1)
		if cl < 0 {
			continue
		}
		args := splitTopLevel(f.code[loc[1]:cl], f.code[loc[1]:cl], ',')
		want := 3
		if strings.Contains(f.code[loc[0]:loc[1]], "WithContext") {
			want = 4
		}
		if len(args) == want && strings.TrimSpace(args[want-1]) == "nil" {
			add(f.line(loc[0]), security.SevLow, "http-no-body", "nil request body",
				"Pass http.NoBody instead of nil: it states the empty body explicitly and keeps ContentLength and re-use of the request correct.")
		}
	}
	return out
}

func (Concurrency) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(ConcurrencyReport)
	if !ok || !r.HasData() {
		return nil
	}
	return []modules.SummaryCard{{Num: strconv.Itoa(r.Total()), Label: "concurrency / API issues"}}
}

func (Concurrency) RenderMarkdown(res any) string {
	r, ok := res.(ConcurrencyReport)
	if !ok || !r.HasData() {
		return ""
	}
	var b strings.Builder
	issueCardMarkdown(&b, "concurrency / API", r.Issues)
	return b.String()
}

func (Concurrency) RenderHTML(res any) string {
	r, ok := res.(ConcurrencyReport)
	if !ok {
		return ""
	}
	var b strings.Builder
	writeIssueCard(&b, "🧵", "concurrency / API", r.Issues)
	return b.String()
}
