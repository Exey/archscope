// memoryleaks.go is a language-agnostic reading of resource-lifecycle health:
// unclosed file/socket/DB handles, unstopped timers, unjoined threads, un-freed
// C allocations, leaked JS listeners/intervals/observers, and Swift closures
// that likely retain-cycle self — rewriting the regex-fallback layer of
// ~/ultimate_bug_scanner's per-language resource_lifecycle checks against
// ArchScope's own stripped-source line scanner (the same sourceCache
// Complexity and Code Structure use).
//
// Like those two, this is a whole-file heuristic, not real scope/AST tracking:
// each rule pairs an "acquire" call with a "release" call and flags every
// acquire site when the file's acquire count exceeds its release count (times
// an optional per-rule noise ratio/margin, mirroring UBS's own threshold-gated
// variants for especially noisy pairs like JS event listeners). A handful of
// rules (Rust's mem::forget, Swift's retain-cycle closures) have no pairing at
// all and simply flag every occurrence of a known-risky shape. Approximation,
// not proof — the same posture as every other constructs module.
//
// All rules run against sourceCache's *stripped* lines (cache.lines, not
// cache.rawLines): comments and string-literal contents are already blanked
// before any regex sees a line, so "// call open() to read config" or a log
// message like "open(\"x\") failed" cannot masquerade as a real acquire call.
// See source.go's readSource for the stripping itself.
package constructs

import (
	"fmt"
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/security"
)

func init() { modules.Default.Register(MemoryLeaks{}) }

// MemoryLeaks is the resource-lifecycle / leak detector.
type MemoryLeaks struct{}

func (MemoryLeaks) ID() string    { return "memoryleaks" }
func (MemoryLeaks) Title() string { return "Memory Leaks" }
func (MemoryLeaks) AppliesTo(languageID string) bool {
	return len(mlRulesByLang[languageID]) > 0 || languageID == "swift"
}

// MLFinding is one flagged acquire site.
type MLFinding struct {
	RuleID   string
	Label    string
	Advice   string
	Severity security.Severity
	FilePath string
	Line     int
}

// MemoryLeaksReport is the module output.
type MemoryLeaksReport struct {
	Findings []MLFinding
	High     int
	Medium   int
	Low      int
}

func (r MemoryLeaksReport) HasData() bool { return len(r.Findings) > 0 }
func (r MemoryLeaksReport) Total() int    { return len(r.Findings) }

// mlRule is one acquire/release resource-lifecycle check, in the style of
// ultimate_bug_scanner's per-language regex-fallback table: an "acquire" call
// (open a file, spawn a thread, start a timer, allocate memory, …) is expected
// to be matched somewhere in the same file by a "release" call.
type mlRule struct {
	id       string
	label    string
	advice   string
	severity security.Severity
	langs    []string

	acquire *regexp.Regexp
	release *regexp.Regexp // nil = every acquire match is itself a finding, no pairing

	ratio  float64 // release count is scaled by this before comparing; 0 → 1
	margin int     // acquire count must exceed (release*ratio)+margin to fire

	// skipContext: if any of these substrings appears on any of the
	// skipWindow lines ending at (and including) an acquire match, that
	// occurrence is treated as already satisfied without needing a release
	// match — e.g. Java's try-with-resources ("try (" on the same line, or up
	// to skipWindow-1 lines earlier for a multi-line declaration like
	// `try (\n    Connection c = DriverManager.getConnection(url)\n) {`), or
	// Python's with-statement guarding a call split across lines ("with" a
	// line or two before a bare `open(`). skipWindow ≤ 0 means "same line
	// only" (equivalent to the original single-line check).
	skipContext []string
	skipWindow  int
}

var mlRules = []mlRule{
	// ── Go ──
	{id: "go.context_cancel", label: "context.With* cancel func never called",
		severity: security.SevHigh, langs: []string{"go"},
		acquire: regexp.MustCompile(`\bcontext\.With(?:Cancel|Timeout|Deadline)\s*\(`),
		release: regexp.MustCompile(`\bcancel\w*\s*\(\s*\)`),
		advice: "A context.With{Cancel,Timeout,Deadline} whose cancel func is never called leaks the " +
			"context's internal goroutine/timer for the life of the parent context. Always `defer cancel()` " +
			"right after acquiring it."},
	{id: "go.ticker_stop", label: "time.Ticker never stopped",
		severity: security.SevMedium, langs: []string{"go"},
		acquire: regexp.MustCompile(`\btime\.NewTicker\s*\(`),
		release: regexp.MustCompile(`\.Stop\s*\(`),
		advice: "An unstopped time.Ticker keeps firing and holding its underlying timer resource for the " +
			"life of the process. Call ticker.Stop() (typically via defer) once it's no longer needed."},
	{id: "go.timer_stop", label: "time.Timer never stopped",
		severity: security.SevMedium, langs: []string{"go"},
		acquire: regexp.MustCompile(`\btime\.NewTimer\s*\(`),
		release: regexp.MustCompile(`\.Stop\s*\(`),
		advice: "An unstopped time.Timer isn't itself a hard leak, but the pattern usually means the drain/" +
			"cleanup path was forgotten too. Call timer.Stop() once the timer is no longer needed."},
	{id: "go.file_handle", label: "os file handle never closed",
		severity: security.SevMedium, langs: []string{"go"},
		acquire: regexp.MustCompile(`\bos\.(?:Open|OpenFile|Create)\s*\(`),
		release: regexp.MustCompile(`\.Close\s*\(`),
		advice: "An os.Open/OpenFile/Create result without a matching Close() leaks a file descriptor. " +
			"Add `defer f.Close()` right after the error check."},
	{id: "go.sql_handle", label: "sql.DB never closed",
		severity: security.SevMedium, langs: []string{"go"},
		acquire: regexp.MustCompile(`\bsql\.Open\s*\(`),
		release: regexp.MustCompile(`\.Close\s*\(`),
		advice: "An sql.Open() handle without Close() leaks its connection pool. Close it (typically via " +
			"defer) once the DB handle is no longer needed."},
	{id: "go.http_body", label: "HTTP response body never closed",
		severity: security.SevMedium, langs: []string{"go"},
		acquire: regexp.MustCompile(`\.Do\s*\(\s*\w+\s*\)|\bhttp\.(?:Get|Post|Head)\s*\(`),
		release: regexp.MustCompile(`\.Body\.Close\s*\(`),
		advice: "An HTTP response whose Body is never closed leaks the underlying connection, eventually " +
			"exhausting the client's connection pool. Add `defer resp.Body.Close()` right after the error check."},
	{id: "go.sql_rows", label: "sql.Rows never closed",
		severity: security.SevMedium, langs: []string{"go"},
		acquire: regexp.MustCompile(`\.Query\s*\(|\.QueryContext\s*\(`),
		release: regexp.MustCompile(`\.Close\s*\(`),
		advice: "A *sql.Rows result that's never closed keeps its underlying connection checked out of " +
			"the pool until the next garbage collection, eventually exhausting it under load. Add " +
			"`defer rows.Close()` right after the error check. (This doesn't apply to QueryRow, which " +
			"closes itself once Scan is called.)"},

	// ── Python ──
	{id: "py.file_handle", label: "file handle never closed",
		severity: security.SevMedium, langs: []string{"python"},
		acquire: regexp.MustCompile(`\bopen\s*\(`),
		release: regexp.MustCompile(`\.close\s*\(|\bwith\s+[\w.]*open\s*\(`),
		// Covers `with (\n    open(...) as f,\n):` / `with \\\n    open(...) as f:`
		// where "with" and "open(" land on different lines, so the release
		// regex above (same-line only) can't see them together.
		skipContext: []string{"with"}, skipWindow: 3,
		advice: "A file opened without a `with` block or a matching .close() leaks a file descriptor. " +
			"Prefer `with open(...) as f:` so it's always released."},
	{id: "py.socket_handle", label: "socket never closed",
		severity: security.SevMedium, langs: []string{"python"},
		acquire: regexp.MustCompile(`\bsocket\.socket\s*\(`),
		release: regexp.MustCompile(`\.close\s*\(`),
		advice: "A socket without a matching .close() leaks the underlying file descriptor. Use " +
			"`with socket.socket(...) as s:` or close it explicitly in a finally block."},
	{id: "py.threading_thread", label: "threading.Thread never joined",
		severity: security.SevMedium, langs: []string{"python"},
		acquire: regexp.MustCompile(`\bthreading\.Thread\s*\(`),
		release: regexp.MustCompile(`\.join\s*\(`),
		advice: "A Thread that's never joined can outlive the caller's awareness of it — exceptions inside " +
			"it are silently swallowed and the caller has no point at which it's guaranteed to have " +
			"finished. Call .join() (or mark it as an intentionally-detached daemon thread)."},
	{id: "py.popen_handle", label: "subprocess.Popen never waited on",
		severity: security.SevMedium, langs: []string{"python"},
		acquire: regexp.MustCompile(`\bsubprocess\.Popen\s*\(`),
		release: regexp.MustCompile(`\.(?:wait|communicate|terminate|kill)\s*\(`),
		advice: "A Popen process that's never waited on or terminated can leak a zombie process and its " +
			"pipes. Call .communicate()/.wait() or use it as a context manager."},
	{id: "py.asyncio_task", label: "asyncio task never awaited/cancelled",
		severity: security.SevMedium, langs: []string{"python"},
		acquire: regexp.MustCompile(`\basyncio\.create_task\s*\(`),
		release: regexp.MustCompile(`\.cancel\s*\(|await\s+asyncio\.(?:gather|wait)\s*\(`),
		advice: "A task created with asyncio.create_task() that's never awaited or cancelled can be " +
			"silently garbage-collected mid-flight, dropping its exception. Keep a reference and await or " +
			"cancel it."},

	// ── Java ──
	{id: "java.executor_leak", label: "ExecutorService never shut down",
		severity: security.SevHigh, langs: []string{"java"},
		acquire: regexp.MustCompile(`\bExecutors\.\w+\s*\(|\bnew\s+ThreadPoolExecutor\s*\(`),
		release: regexp.MustCompile(`\.shutdown(?:Now)?\s*\(`),
		advice: "An ExecutorService that's never shut down leaks its worker threads for the life of the " +
			"JVM. Call shutdown()/shutdownNow() (typically in a finally block) once it's no longer needed."},
	{id: "java.stream_leak", label: "file stream never closed",
		severity: security.SevMedium, langs: []string{"java"},
		acquire: regexp.MustCompile(`\bnew\s+File(?:Input|Output)Stream\s*\(`),
		release: regexp.MustCompile(`\.close\s*\(`),
		advice: "A FileInputStream/FileOutputStream without a matching close() leaks a file descriptor. " +
			"Use try-with-resources."},
	{id: "java.jdbc_connection", label: "JDBC Connection never closed",
		severity: security.SevHigh, langs: []string{"java"},
		acquire:     regexp.MustCompile(`\bDriverManager\.getConnection\s*\(`),
		release:     regexp.MustCompile(`\.close\s*\(`),
		skipContext: []string{"try (", "try("}, skipWindow: 3, // multi-line try-with-resources declarations
		advice: "A JDBC Connection outside try-with-resources leaks a pooled connection if an exception " +
			"is thrown before close(). Acquire it inside `try (Connection c = ...) { ... }`."},
	{id: "java.statement_leak", label: "Statement never closed",
		severity: security.SevMedium, langs: []string{"java"},
		acquire:     regexp.MustCompile(`\.(?:createStatement|prepareStatement|prepareCall)\s*\(`),
		release:     regexp.MustCompile(`\.close\s*\(`),
		skipContext: []string{"try (", "try("}, skipWindow: 3,
		advice: "A Statement/PreparedStatement outside try-with-resources keeps its server-side cursor " +
			"(and, for prepared statements, the driver's compiled-plan handle) open until garbage " +
			"collection. Acquire it inside a try-with-resources block."},
	{id: "java.resultset_leak", label: "ResultSet never closed",
		severity: security.SevMedium, langs: []string{"java"},
		// executeQuery() is the actual call that returns a ResultSet — keying
		// off it (rather than "ResultSet x =") avoids false positives on
		// declarations like "ResultSet rs = null;" that aren't a real acquire.
		acquire:     regexp.MustCompile(`\.executeQuery\s*\(`),
		release:     regexp.MustCompile(`\.close\s*\(`),
		skipContext: []string{"try (", "try("}, skipWindow: 3,
		advice: "A ResultSet outside try-with-resources keeps its underlying database cursor open until " +
			"garbage collection. Acquire it inside a try-with-resources block."},

	// ── TypeScript / JavaScript ──
	{id: "ts.listener_leak", label: "addEventListener without a matching removeEventListener",
		severity: security.SevMedium, langs: []string{"ts"},
		acquire: regexp.MustCompile(`\.addEventListener\s*\(`),
		release: regexp.MustCompile(`\.removeEventListener\s*\(`),
		ratio:   5,
		advice: "This file registers substantially more event listeners than it removes. Listeners on " +
			"long-lived targets (window, document) keep their closures — and everything captured in them — " +
			"alive. Remove them on teardown/unmount."},
	{id: "ts.interval_leak", label: "setInterval without a matching clearInterval",
		severity: security.SevMedium, langs: []string{"ts"},
		acquire: regexp.MustCompile(`\bsetInterval\s*\(`),
		release: regexp.MustCompile(`\bclearInterval\s*\(`),
		advice: "An interval that's never cleared keeps firing — and keeps its closure alive — for the " +
			"life of the page/process. Call clearInterval() on teardown."},
	{id: "ts.timeout_leak", label: "many setTimeout calls with no clearTimeout anywhere",
		severity: security.SevLow, langs: []string{"ts"},
		acquire: regexp.MustCompile(`\bsetTimeout\s*\(`),
		release: regexp.MustCompile(`\bclearTimeout\s*\(`),
		margin:  20,
		advice: "Most one-shot setTimeout calls are fine, but at this volume with zero clearTimeout in the " +
			"file it's worth checking none of them capture long-lived state that should be released earlier."},
	{id: "ts.blob_url_leak", label: "createObjectURL without a matching revokeObjectURL",
		severity: security.SevMedium, langs: []string{"ts"},
		acquire: regexp.MustCompile(`URL\.createObjectURL\s*\(`),
		release: regexp.MustCompile(`URL\.revokeObjectURL\s*\(`),
		advice: "A Blob/File object URL that's never revoked keeps the underlying blob pinned in memory " +
			"for the life of the page. Call URL.revokeObjectURL() once the download/preview/media element " +
			"no longer needs it."},
	{id: "ts.observer_leak", label: "MutationObserver never disconnected",
		severity: security.SevMedium, langs: []string{"ts"},
		acquire: regexp.MustCompile(`new\s+MutationObserver\s*\(`),
		release: regexp.MustCompile(`\.disconnect\s*\(`),
		advice: "A MutationObserver that's never disconnected keeps observing — and keeps its callback " +
			"closure alive — after the component/feature it belongs to is gone. Call .disconnect() on " +
			"teardown."},
	{id: "ts.raf_leak", label: "requestAnimationFrame without a matching cancelAnimationFrame",
		severity: security.SevLow, langs: []string{"ts"},
		acquire: regexp.MustCompile(`\brequestAnimationFrame\s*\(`),
		release: regexp.MustCompile(`\bcancelAnimationFrame\s*\(`),
		margin:  5, // a self-rescheduling animation loop calls rAF far more often than it's ever cancelled
		advice: "An animation frame callback that's never cancelled keeps its closure alive and keeps " +
			"running after the component/page that scheduled it is gone. Store the returned id and call " +
			"cancelAnimationFrame() on teardown."},

	// ── Rust ──
	{id: "rust.thread_join", label: "thread::spawn handle never joined",
		severity: security.SevHigh, langs: []string{"rust"},
		acquire: regexp.MustCompile(`std::thread::spawn\s*\(|thread::spawn\s*\(`),
		release: regexp.MustCompile(`\.join\s*\(`),
		advice: "A spawned thread whose JoinHandle is dropped without .join() detaches it silently — any " +
			"panic or resource it holds is never observed or reclaimed at a known point. Join it, or " +
			"document the detach as deliberate."},
	{id: "rust.tokio_task_leak", label: "tokio::spawn task never awaited/aborted",
		severity: security.SevMedium, langs: []string{"rust"},
		acquire: regexp.MustCompile(`tokio::spawn\s*\(`),
		release: regexp.MustCompile(`\.await\b|\.abort\s*\(`),
		advice: "A tokio task whose JoinHandle is dropped keeps running detached — if it never completes " +
			"it leaks for the life of the runtime. Await or abort the handle."},
	{id: "rust.mem_forget", label: "std::mem::forget leaks its argument by design",
		severity: security.SevMedium, langs: []string{"rust"},
		acquire: regexp.MustCompile(`std::mem::forget\s*\(|mem::forget\s*\(`),
		advice: "mem::forget() deliberately skips the value's Drop, leaking anything it owns (allocations, " +
			"file handles, …). Confirm this is intentional (e.g. handing ownership to FFI) — it's easy to " +
			"reach for by mistake."},

	// ── Swift / Objective-C ──
	{id: "swift.timer_invalidate", label: "Timer never invalidated",
		severity: security.SevMedium, langs: []string{"swift"},
		acquire: regexp.MustCompile(`Timer\.scheduledTimer\s*\(`),
		release: regexp.MustCompile(`\.invalidate\s*\(`),
		advice: "A Timer that's never invalidated keeps firing — and keeps its target/closure alive — even " +
			"after the owning view/controller is gone. Call .invalidate() in deinit or on teardown."},
	{id: "swift.notification_observer", label: "NotificationCenter observer never removed",
		severity: security.SevHigh, langs: []string{"swift"},
		acquire: regexp.MustCompile(`NotificationCenter\.default\.addObserver\s*\(`),
		release: regexp.MustCompile(`NotificationCenter\.default\.removeObserver\s*\(|\.removeObserver\s*\(`),
		advice: "An observer that's never removed keeps firing into (or keeps retained) a deallocated " +
			"context. Remove it in deinit, or prefer the block-based API's returned token with a matching " +
			"removeObserver."},
	{id: "objc.notification_observer", label: "NotificationCenter observer never removed",
		severity: security.SevHigh, langs: []string{"objc"},
		acquire: regexp.MustCompile(`addObserver\s*:`),
		release: regexp.MustCompile(`removeObserver\s*:`),
		advice: "An observer that's never removed keeps firing into (or retains) a deallocated object. " +
			"Remove it in dealloc."},

	// ── C / C++ ──
	{id: "c.malloc_free", label: "heap allocation never freed",
		severity: security.SevHigh, langs: []string{"c", "cpp"},
		acquire: regexp.MustCompile(`\b(?:malloc|calloc|realloc)\s*\(`),
		release: regexp.MustCompile(`\bfree\s*\(`),
		advice: "A malloc/calloc/realloc result without a matching free() leaks heap memory for the life " +
			"of the process. Every successful allocation needs exactly one free() on every code path, " +
			"including error paths."},
	{id: "c.fopen_fclose", label: "FILE* never closed",
		severity: security.SevMedium, langs: []string{"c", "cpp"},
		acquire: regexp.MustCompile(`\bfopen\s*\(`),
		release: regexp.MustCompile(`\bfclose\s*\(`),
		advice: "An fopen() result without a matching fclose() leaks a file descriptor. Close it on every " +
			"code path, including early returns on error."},
	{id: "cpp.thread_join", label: "std::thread never joined or detached",
		severity: security.SevHigh, langs: []string{"cpp"},
		acquire: regexp.MustCompile(`std::thread\s+\w+\s*[({=]`),
		release: regexp.MustCompile(`\.join\s*\(|\.detach\s*\(`),
		advice: "A std::thread that's never joined or detached calls std::terminate() when it's " +
			"destroyed. Always join() or explicitly detach() it before it goes out of scope."},
}

// mlRulesByLang indexes mlRules by language ID for fast per-file lookup.
var mlRulesByLang = func() map[string][]mlRule {
	m := map[string][]mlRule{}
	for _, r := range mlRules {
		for _, lang := range r.langs {
			m[lang] = append(m[lang], r)
		}
	}
	return m
}()

// reSwiftClosureDangerSite lists APIs whose closures commonly outlive the
// object that created them — ported from UBS's Swift retain-cycle trigger-site
// list (URLSession/DispatchQueue/Timer/NotificationCenter/UIView.animate/
// Combine's .sink/.onReceive).
var reSwiftClosureDangerSite = regexp.MustCompile(
	`URLSession\.|DispatchQueue\.(?:global|main)|Timer\.scheduledTimer|` +
		`NotificationCenter\.default\.addObserver|UIView\.animate|\.sink\s*\(|\.onReceive\s*\(`)
var reSwiftWeakSelf = regexp.MustCompile(`\[\s*weak\s+self\s*\]|\[\s*unowned\s+self\s*\]`)

// maxSwiftClosureScanLines bounds how far swiftClosureBody scans looking for
// the matching close-brace, so a closure that (due to a parse quirk, or a
// stray unbalanced brace the stripper couldn't fully account for) never
// balances can't turn one danger-site match into an unbounded scan.
const maxSwiftClosureScanLines = 300

// swiftClosureBody returns the lines from start through the first balanced
// close-brace found (start's own line may open it, or an opening "{" may
// appear a line or more later, e.g. a multi-line call before the trailing
// closure). Brace counting runs over already comment/string-stripped lines
// (see cache.lines), so stray '{'/'}' inside a string literal can't throw the
// depth count off. Returns nil if no opening brace is found within the scan
// window at all.
func swiftClosureBody(lines []string, start int) []string {
	depth := 0
	foundOpen := false
	end := start
	limit := min(start+maxSwiftClosureScanLines, len(lines))
	for i := start; i < limit; i++ {
		for _, ch := range lines[i] {
			switch ch {
			case '{':
				depth++
				foundOpen = true
			case '}':
				if foundOpen {
					depth--
				}
			}
		}
		end = i
		if foundOpen && depth <= 0 {
			break
		}
	}
	if !foundOpen {
		return nil
	}
	return lines[start : end+1]
}

// detectSwiftRetainCycles flags a closure-danger call site (see above) that
// references self within the closure body without a [weak self]/[unowned
// self] capture list. The body is found via brace-matching (swiftClosureBody)
// rather than a fixed line window, so a long closure doesn't escape detection
// just because its capture list — or its first "self" reference — falls
// beyond a few lines.
func detectSwiftRetainCycles(filePath string, lines []string) []MLFinding {
	var out []MLFinding
	for i, l := range lines {
		if !reSwiftClosureDangerSite.MatchString(l) {
			continue
		}
		body := swiftClosureBody(lines, i)
		if body == nil {
			// No balanced closing brace found in the scan window (or the
			// call has no trailing closure at all, e.g. it takes a named
			// function reference) — fall back to a short fixed window so the
			// common case still gets checked rather than silently skipped.
			body = lines[i:min(i+4, len(lines))]
		}
		window := strings.Join(body, "\n")
		if reSwiftWeakSelf.MatchString(window) || !strings.Contains(window, "self") {
			continue
		}
		out = append(out, MLFinding{
			RuleID:   "swift.retain_cycle_self",
			Label:    "closure captures self strongly at a long-lived call site",
			Severity: security.SevMedium,
			FilePath: filePath,
			Line:     i + 1,
			Advice: "URLSession/DispatchQueue/Timer/NotificationCenter/UIView.animate/.sink/.onReceive " +
				"closures often outlive the view/controller that created them. If this closure references " +
				"self, capture it as [weak self] (or [unowned self] when self is guaranteed to outlive the " +
				"closure) and unwrap with guard.",
		})
	}
	return out
}

// detect runs one rule against a file's stripped lines.
func (r mlRule) detect(filePath string, lines []string) []MLFinding {
	window := r.skipWindow
	if window <= 0 {
		window = 1
	}
	var acquireLines []int
	releaseCount := 0
	for i, l := range lines {
		if r.acquire.MatchString(l) {
			start := max(i-window+1, 0)
			if !containsAnyInRange(lines, start, i, r.skipContext) {
				acquireLines = append(acquireLines, i+1)
			}
		}
		if r.release != nil && r.release.MatchString(l) {
			releaseCount++
		}
	}
	if len(acquireLines) == 0 {
		return nil
	}
	if r.release != nil {
		ratio := r.ratio
		if ratio <= 0 {
			ratio = 1
		}
		allowed := int(float64(releaseCount)*ratio) + r.margin
		if len(acquireLines) <= allowed {
			return nil
		}
	}
	out := make([]MLFinding, 0, len(acquireLines))
	for _, ln := range acquireLines {
		out = append(out, MLFinding{
			RuleID: r.id, Label: r.label, Advice: r.advice, Severity: r.severity,
			FilePath: filePath, Line: ln,
		})
	}
	return out
}

func containsAny(line string, needles []string) bool {
	if len(needles) == 0 {
		return false
	}
	low := strings.ToLower(line)
	for _, n := range needles {
		if strings.Contains(low, n) {
			return true
		}
	}
	return false
}

// containsAnyInRange reports whether any needle appears on lines[start:end+1]
// (inclusive of both ends). Used to look a few lines back from an acquire
// match for context that spans a multi-line statement (a try-with-resources
// or with-statement declaration split across lines).
func containsAnyInRange(lines []string, start, end int, needles []string) bool {
	if len(needles) == 0 {
		return false
	}
	for i := start; i <= end && i < len(lines); i++ {
		if containsAny(lines[i], needles) {
			return true
		}
	}
	return false
}

// Analyze reads each file's stripped source and runs every rule registered
// for its language, plus Swift's retain-cycle proximity check.
func (MemoryLeaks) Analyze(files []*parser.ParsedFile) any {
	cache := newSourceCache()
	var findings []MLFinding
	for _, f := range files {
		if security.IsTestOrBenchPath(f.FilePath) {
			continue
		}
		rules := mlRulesByLang[f.LanguageID]
		if len(rules) == 0 && f.LanguageID != "swift" {
			continue
		}
		lines := cache.lines(f.FilePath)
		if lines == nil {
			continue
		}
		for _, r := range rules {
			findings = append(findings, r.detect(f.FilePath, lines)...)
		}
		if f.LanguageID == "swift" {
			findings = append(findings, detectSwiftRetainCycles(f.FilePath, lines)...)
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return sevRank(findings[i].Severity) > sevRank(findings[j].Severity)
		}
		if findings[i].FilePath != findings[j].FilePath {
			return findings[i].FilePath < findings[j].FilePath
		}
		return findings[i].Line < findings[j].Line
	})

	var r MemoryLeaksReport
	for _, f := range findings {
		switch f.Severity {
		case security.SevHigh:
			r.High++
		case security.SevMedium:
			r.Medium++
		case security.SevLow:
			r.Low++
		}
	}
	r.Findings = findings
	return r
}

func sevRank(s security.Severity) int {
	switch s {
	case security.SevHigh:
		return 3
	case security.SevMedium:
		return 2
	default:
		return 1
	}
}

func mlSevClass(s security.Severity) string {
	switch s {
	case security.SevHigh:
		return "sev-high"
	case security.SevMedium:
		return "sev-medium"
	default:
		return "sev-low"
	}
}

func (MemoryLeaks) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(MemoryLeaksReport)
	if !ok || !r.HasData() {
		return nil
	}
	return []modules.SummaryCard{
		{Num: strconv.Itoa(r.Total()), Label: "leak signals"},
	}
}

// mlLocation is one file:line occurrence within an mlGroup.
type mlLocation struct {
	FilePath string
	Line     int
}

// mlGroup is every MLFinding for one rule collapsed into a single row: the
// reason (Label/Advice/Severity, identical across every occurrence of the
// same rule) written once, with every occurrence's location kept in
// Locations — so "NotificationCenter observer never removed" shows up as one
// row with N locations instead of N near-identical rows repeating the same
// advice.
type mlGroup struct {
	RuleID    string
	Label     string
	Advice    string
	Severity  security.Severity
	Locations []mlLocation
}

// groupMLFindings collapses findings by RuleID, preserving each group's first
// occurrence order and sorting groups worst-first: HIGH before MEDIUM before
// LOW, and within a severity, the rule with the most occurrences first.
func groupMLFindings(findings []MLFinding) []mlGroup {
	idx := map[string]int{}
	var groups []mlGroup
	for _, f := range findings {
		if i, ok := idx[f.RuleID]; ok {
			groups[i].Locations = append(groups[i].Locations, mlLocation{f.FilePath, f.Line})
			continue
		}
		idx[f.RuleID] = len(groups)
		groups = append(groups, mlGroup{
			RuleID: f.RuleID, Label: f.Label, Advice: f.Advice, Severity: f.Severity,
			Locations: []mlLocation{{f.FilePath, f.Line}},
		})
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Severity != groups[j].Severity {
			return sevRank(groups[i].Severity) > sevRank(groups[j].Severity)
		}
		return len(groups[i].Locations) > len(groups[j].Locations)
	})
	return groups
}

// maxMLLocationsShown caps how many file:line locations one grouped row
// renders before collapsing the rest into "+N more" — the same reason
// firing across hundreds of files shouldn't blow out a single table row.
const maxMLLocationsShown = 200

// mlCap splits items into the first max entries and an overflow count, so
// RenderHTML and RenderMarkdown apply the exact same cap (both for table rows
// and, within a row, for locations) via one shared shape.
func mlCap[T any](items []T, max int) (shown []T, extra int) {
	if len(items) <= max {
		return items, 0
	}
	return items[:max], len(items) - max
}

// mlLocationLinks renders a group's locations as vscode:// deep links,
// comma-separated, capped at maxMLLocationsShown.
func mlLocationLinks(locs []mlLocation) string {
	shown, extra := mlCap(locs, maxMLLocationsShown)
	links := make([]string, 0, len(shown))
	for _, l := range shown {
		links = append(links, occurrenceLink(fmt.Sprintf("%s:%d", baseName(l.FilePath), l.Line), l.FilePath, l.Line))
	}
	out := strings.Join(links, ", ")
	if extra > 0 {
		out += fmt.Sprintf(` <span class="as-cx__more">+%d more</span>`, extra)
	}
	return out
}

// mlLocationsMD renders a group's locations as plain "name:line" text for the
// Markdown report, same cap as mlLocationLinks.
func mlLocationsMD(locs []mlLocation) string {
	shown, extra := mlCap(locs, maxMLLocationsShown)
	parts := make([]string, 0, len(shown))
	for _, l := range shown {
		parts = append(parts, fmt.Sprintf("%s:%d", baseName(l.FilePath), l.Line))
	}
	out := strings.Join(parts, ", ")
	if extra > 0 {
		out += fmt.Sprintf(" +%d more", extra)
	}
	return out
}

// RenderMarkdown renders one row per rule, with every occurrence's location.
func (MemoryLeaks) RenderMarkdown(res any) string {
	r, ok := res.(MemoryLeaksReport)
	if !ok || !r.HasData() {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**%d potential leaks** (%dH / %dM / %dL)\n\n", r.Total(), r.High, r.Medium, r.Low)
	b.WriteString("| Severity | Issue | Locations |\n|----------|-------|-----------|\n")
	groups, extra := mlCap(groupMLFindings(r.Findings), maxViolationsShown)
	for _, g := range groups {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", g.Severity, g.Label, mlLocationsMD(g.Locations))
	}
	if extra > 0 {
		fmt.Fprintf(&b, "| | | +%d more |\n", extra)
	}
	b.WriteString("\n")
	return b.String()
}

// RenderHTML renders the summary line and one row per rule, with every
// occurrence's location listed (and linked) in that row's Location column.
func (MemoryLeaks) RenderHTML(res any) string {
	r, ok := res.(MemoryLeaksReport)
	if !ok {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="as-ml">`)
	if !r.HasData() {
		// Render a "clean" subcard rather than nothing at all: the ⚡
		// Performance tooltip's "💧 N Memory Leaks" line always links to this
		// panel's anchor (see cultureRow.memLeaks / perfTip), and a 0-finding
		// platform still ran every rule — that's worth a positive confirmation,
		// not a dead link.
		b.WriteString(`<div class="as-ml__summary as-ml__summary--clean">✅ No potential memory leaks detected in the scanned files.</div></div>`)
		return b.String()
	}
	fmt.Fprintf(&b, `<div class="as-ml__summary">💧 <b>%d</b> potential leak%s <span class="as-count">(%dH / %dM / %dL)</span></div>`,
		r.Total(), plural(r.Total(), "", "s"), r.High, r.Medium, r.Low)
	b.WriteString(`<table class="as-table as-ml__table"><thead><tr><th>Severity</th><th>Issue</th><th>Location</th></tr></thead><tbody>`)
	groups, extra := mlCap(groupMLFindings(r.Findings), maxViolationsShown)
	for _, g := range groups {
		fmt.Fprintf(&b, `<tr><td><span class="as-sev %s">%s</span></td><td><div class="as-ml__label">%s</div><div class="as-ml__advice">%s</div></td><td class="mono">%s</td></tr>`,
			mlSevClass(g.Severity), strings.ToUpper(string(g.Severity)), html.EscapeString(g.Label), html.EscapeString(g.Advice), mlLocationLinks(g.Locations))
	}
	if extra > 0 {
		fmt.Fprintf(&b, `<tr><td colspan="3" class="as-cx__more">… and %d more</td></tr>`, extra)
	}
	b.WriteString(`</tbody></table></div>`)
	return b.String()
}
