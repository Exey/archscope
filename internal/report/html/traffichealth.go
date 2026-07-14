// traffichealth.go computes a "🩺 Traffic Health" summary shown at the top of
// the 🛜 Traffic panel, above the Inbound/Outbound tables: a handful of
// heuristic sub-scores read from the same traffic.Entry data the tables
// already show (URI, Protocol, Port, DataFmt) plus, when available, Spec
// Coverage's readiness score. Each sub-score is independently gated — some
// don't apply to client/UI platforms (Documentation, Dependency Health,
// Observability describe a service's own API surface, which a client
// consumes rather than owns), and RESTfulness only applies when REST is
// actually the platform's dominant inbound protocol (a gRPC/GraphQL/WebSocket
// backend has nothing to gain from "does this URI look RESTful"). Whichever
// sub-scores apply are weighted and averaged; skipped ones simply don't
// contribute rather than dragging the overall score down.
//
// There is deliberately no TLS/HTTPS security check here: the overall Traffic
// Health score is itself folded into 🔰 Programming Culture's 🛡️ Security
// dimension (see culture.go), so a separate Security sub-score in here would
// double-count the same signal within one dimension.
package html

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/modules/speccoverage"
	"github.com/exey/archscope/internal/modules/traffic"
)

// trafficHealthCat is one applicable sub-score.
type trafficHealthCat struct {
	label  string
	icon   string
	score  int // 0–100
	weight int // base weight, renormalized across whichever cats apply
	detail string
}

// trafficHealth is the overall weighted read plus its contributing cats.
type trafficHealth struct {
	overall int
	cats    []trafficHealthCat
}

// computeTrafficHealth reads tr (and, when present, spec) into a
// trafficHealth. ok is false when there's nothing to read (no traffic data).
func computeTrafficHealth(tr traffic.Result, spec *speccoverage.Result, isClientPlatform bool) (trafficHealth, bool) {
	if !tr.HasData() {
		return trafficHealth{}, false
	}
	var cats []trafficHealthCat

	if trafficRESTDominant(tr.Inbound) {
		if score, detail, ok := trafficRESTfulnessScore(tr.Inbound); ok {
			cats = append(cats, trafficHealthCat{"RESTfulness", "🎯", score, 15, detail})
		}
	}

	if score, detail, ok := trafficVersioningScore(tr.Inbound); ok {
		cats = append(cats, trafficHealthCat{"Versioning", "🏷️", score, 10, detail})
	}

	if !isClientPlatform && spec != nil && spec.HasData() {
		cats = append(cats, trafficHealthCat{"Documentation", "📖", spec.SpecReady, 10,
			fmt.Sprintf("%d%% of inbound routes have a matching spec entry", spec.SpecReady)})
	}

	if score, detail, ok := trafficModernityScore(tr.Inbound, tr.Outbound); ok {
		cats = append(cats, trafficHealthCat{"Protocol Modernity", "🧬", score, 15, detail})
	}

	if !isClientPlatform {
		if score, detail, ok := trafficDependencyHealthScore(tr.Outbound); ok {
			cats = append(cats, trafficHealthCat{"Dependency Health", "🕸️", score, 15, detail})
		}
	}

	if !isClientPlatform {
		if score, detail, ok := trafficObservabilityScore(tr.Inbound); ok {
			cats = append(cats, trafficHealthCat{"Observability", "🩺", score, 10, detail})
		}
	}

	if len(cats) == 0 {
		return trafficHealth{}, false
	}
	weightSum, scoreSum := 0, 0
	for _, c := range cats {
		weightSum += c.weight
		scoreSum += c.score * c.weight
	}
	overall := 0
	if weightSum > 0 {
		overall = (scoreSum + weightSum/2) / weightSum
	}
	return trafficHealth{overall: overall, cats: cats}, true
}

// ── Security & Encryption ───────────────────────────────────────────────────

// ── API Design & RESTfulness ─────────────────────────────────────────────────

// trafficRESTDominant reports whether REST makes up at least half of inbound
// entries — the gate for even bothering with RESTfulness conventions.
func trafficRESTDominant(inbound []traffic.Entry) bool {
	if len(inbound) == 0 {
		return false
	}
	rest := 0
	for _, e := range inbound {
		if strings.HasPrefix(e.Protocol, "REST") {
			rest++
		}
	}
	return rest*2 >= len(inbound)
}

var commonVerbPrefixes = []string{
	"get", "list", "create", "update", "delete", "remove", "fetch", "add",
	"edit", "save", "find", "search", "set", "do", "make", "put", "post",
}

var reVersionSeg = regexp.MustCompile(`^v[0-9]+(?:\.[0-9]+)?$`)

// trafficPathSegments splits a URI/path into its non-empty segments,
// stripping any scheme/host prefix and query string.
func trafficPathSegments(uri string) []string {
	u := uri
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
		if j := strings.IndexByte(u, '/'); j >= 0 {
			u = u[j:]
		} else {
			u = ""
		}
	}
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u = u[:i]
	}
	var segs []string
	for _, s := range strings.Split(u, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	return segs
}

func trafficIsPathVar(seg string) bool {
	return strings.HasPrefix(seg, "{") || strings.HasPrefix(seg, ":") || strings.HasPrefix(seg, "<")
}

func trafficHasVerbSegment(segs []string) bool {
	for _, s := range segs {
		if trafficIsPathVar(s) {
			continue
		}
		low := strings.ToLower(s)
		for _, verb := range commonVerbPrefixes {
			if strings.HasPrefix(low, verb) {
				return true
			}
		}
	}
	return false
}

func trafficHasVersionSegment(segs []string) bool {
	for _, s := range segs {
		if reVersionSeg.MatchString(strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// trafficRESTfulnessScore reads path-naming conventions (nouns not verbs,
// versioning) and average path depth across REST inbound entries.
func trafficRESTfulnessScore(inbound []traffic.Entry) (score int, detail string, ok bool) {
	var rest []traffic.Entry
	for _, e := range inbound {
		if strings.HasPrefix(e.Protocol, "REST") {
			rest = append(rest, e)
		}
	}
	if len(rest) == 0 {
		return 0, "", false
	}
	nounOK, versioned, totalDepth := 0, 0, 0
	for _, e := range rest {
		segs := trafficPathSegments(e.URI)
		if !trafficHasVerbSegment(segs) {
			nounOK++
		}
		if trafficHasVersionSegment(segs) {
			versioned++
		}
		totalDepth += len(segs)
	}
	n := len(rest)
	nounPct := nounOK * 100 / n
	verPct := versioned * 100 / n
	avgDepth := float64(totalDepth) / float64(n)
	depthPenalty := 0
	if avgDepth > 4 {
		depthPenalty = int((avgDepth-4)*10 + 0.5)
	}
	score = clampInt((nounPct+verPct)/2-depthPenalty, 0, 100)
	detail = fmt.Sprintf("%d%% noun-style paths, %d%% versioned, avg depth %.1f segments", nounPct, verPct, avgDepth)
	return score, detail, true
}

// ── Versioning & Deprecation ─────────────────────────────────────────────────

// trafficVersioningScore reads path versioning across every inbound entry
// (any protocol — versioning isn't REST-specific) minus a deprecation-comment
// penalty found near each route's declaration.
func trafficVersioningScore(inbound []traffic.Entry) (score int, detail string, ok bool) {
	if len(inbound) == 0 {
		return 0, "", false
	}
	versioned := 0
	for _, e := range inbound {
		if trafficHasVersionSegment(trafficPathSegments(e.URI)) {
			versioned++
		}
	}
	verPct := versioned * 100 / len(inbound)
	deprecated := trafficCountDeprecated(inbound)
	depPct := deprecated * 100 / len(inbound)
	score = clampInt(verPct-depPct, 0, 100)
	detail = fmt.Sprintf("%d%% versioned in path, %d marked deprecated", verPct, deprecated)
	return score, detail, true
}

// trafficCountDeprecated checks each entry's declaration line itself — so a
// trailing same-line marker like `router.GET("/x") // Deprecated: use v2` is
// caught — plus the couple of lines immediately before it (a leading doc
// comment), for a "deprecated" marker (// Deprecated, @Deprecated, …).
func trafficCountDeprecated(entries []traffic.Entry) int {
	cache := map[string][]string{}
	readLines := func(path string) []string {
		if lines, cached := cache[path]; cached {
			return lines
		}
		var lines []string
		if data, err := os.ReadFile(path); err == nil {
			lines = strings.Split(string(data), "\n")
		}
		cache[path] = lines
		return lines
	}
	n := 0
	for _, e := range entries {
		if e.Line <= 0 || e.FilePath == "" {
			continue
		}
		lines := readLines(e.FilePath)
		if lines == nil {
			continue
		}
		declIdx := e.Line - 1 // 0-indexed position of the declaration line
		start := max(declIdx-3, 0)
		for i := start; i <= declIdx && i < len(lines); i++ {
			if strings.Contains(strings.ToLower(lines[i]), "deprecat") {
				n++
				break
			}
		}
	}
	return n
}

// ── Protocol & Data Format Modernity ─────────────────────────────────────────

// trafficModernityScore is the share of REST/gRPC/GraphQL among "API-shaped"
// entries; broker/queue protocols (Kafka, NATS, AMQP, Redis) are infrastructure
// choices, not a modernity signal, and are excluded from the denominator.
func trafficModernityScore(inbound, outbound []traffic.Entry) (score int, detail string, ok bool) {
	modern, legacy := 0, 0
	classify := func(e traffic.Entry) {
		switch {
		case strings.HasPrefix(e.Protocol, "REST"), e.Protocol == "gRPC", e.Protocol == "GraphQL":
			modern++
		case e.Protocol == "Redis", e.Protocol == "Kafka", e.Protocol == "NATS", e.Protocol == "AMQP":
			// infra/broker choice — neutral, not counted
		default:
			legacy++
		}
	}
	for _, e := range inbound {
		classify(e)
	}
	for _, e := range outbound {
		classify(e)
	}
	total := modern + legacy
	if total == 0 {
		return 0, "", false
	}
	score = modern * 100 / total
	detail = fmt.Sprintf("%d%% REST/gRPC/GraphQL, %d legacy/other", score, legacy)
	return score, detail, true
}

// ── Outbound Dependency Health ───────────────────────────────────────────────

var internalHostNeedles = []string{
	"localhost", "127.0.0.1", "0.0.0.0", "::1",
	".internal", ".local", "svc.cluster.local",
}

func trafficIsExternalHost(uri string) bool {
	low := strings.ToLower(uri)
	for _, n := range internalHostNeedles {
		if strings.Contains(low, n) {
			return false
		}
	}
	return true
}

// trafficDependencyHealthScore penalises a high outbound fan-out (coupling)
// and a high share of external (vs internal/service-mesh) destinations.
func trafficDependencyHealthScore(outbound []traffic.Entry) (score int, detail string, ok bool) {
	if len(outbound) == 0 {
		return 0, "", false
	}
	distinct := map[string]bool{}
	external := 0
	for _, e := range outbound {
		distinct[e.URI] = true
		if trafficIsExternalHost(e.URI) {
			external++
		}
	}
	fanOut := len(distinct)
	extPct := external * 100 / len(outbound)
	penalty := 0
	if fanOut > 15 {
		penalty += (fanOut - 15) * 2
	}
	if extPct > 60 {
		penalty += (extPct - 60) / 2
	}
	score = clampInt(100-penalty, 0, 100)
	detail = fmt.Sprintf("%d distinct outbound target(s), %d%% external", fanOut, extPct)
	return score, detail, true
}

// ── Health & Monitoring Endpoints ────────────────────────────────────────────

var observabilityNeedles = []string{"health", "ready", "metrics", "healthz", "livez", "readyz"}

// trafficObservabilityScore grades gradually by how many distinct
// health/monitoring markers are found, rather than a plain present/absent
// binary: 0→20, 1→50, 2→75, 3+→100.
func trafficObservabilityScore(inbound []traffic.Entry) (score int, detail string, ok bool) {
	if len(inbound) == 0 {
		return 0, "", false
	}
	found := map[string]bool{}
	for _, e := range inbound {
		low := strings.ToLower(e.URI)
		for _, n := range observabilityNeedles {
			if strings.Contains(low, n) {
				found[n] = true
			}
		}
	}
	switch {
	case len(found) >= 3:
		score = 100
	case len(found) == 2:
		score = 75
	case len(found) == 1:
		score = 50
	default:
		score = 20
	}
	if len(found) == 0 {
		return score, "no /health, /ready, or /metrics endpoint detected", true
	}
	return score, fmt.Sprintf("%d health/monitoring marker(s) detected", len(found)), true
}

// ── rendering ────────────────────────────────────────────────────────────────

// renderTrafficHealthBlock renders the overall score plus every applicable
// sub-score as a labelled bar, or "" when there's nothing to read.
func renderTrafficHealthBlock(th trafficHealth, ok bool) string {
	if !ok {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="as-th">`)
	fmt.Fprintf(&b, `<div class="as-th__head"><span class="as-th__score" style="color:%s">%d%%</span><span class="as-th__label">🩺 Traffic Health</span></div>`,
		gradeColor(th.overall), th.overall)
	b.WriteString(`<div class="as-th__grid">`)
	for _, c := range th.cats {
		fmt.Fprintf(&b,
			`<div class="as-th__cat" title="%s"><div class="as-th__cat-head"><span>%s %s</span><span class="as-th__cat-val" style="color:%s">%d%%</span></div>`+
				`<div class="as-th__bar"><div class="as-th__fill" style="width:%d%%;background:%s"></div></div></div>`,
			esc(c.detail), c.icon, esc(c.label), gradeColor(c.score), c.score, c.score, gradeColor(c.score))
	}
	b.WriteString(`</div>`)

	var notes []string
	for _, c := range th.cats {
		if how, ok := trafficHealthHowTo[c.label]; ok {
			notes = append(notes, fmt.Sprintf(`<div class="as-th__note"><b>%s %s</b> — %s</div>`, c.icon, esc(c.label), esc(how)))
		}
	}
	if len(notes) > 0 {
		b.WriteString(`<div class="as-th__notes">`)
		for _, n := range notes {
			b.WriteString(n)
		}
		b.WriteString(`</div>`)
	}

	b.WriteString(`</div>`)
	return b.String()
}

// trafficHealthHowTo is a short "how is this calculated" note shown below the
// bars for every sub-score, so the read behind each one is never left to
// guesswork.
var trafficHealthHowTo = map[string]string{
	"RESTfulness":        "noun-vs-verb path segments + versioned paths (/v1/…) + average path depth, across REST routes only.",
	"Versioning":         "share of routes with a version segment in the path, minus routes with a \"deprecated\" marker on or just above the route declaration.",
	"Documentation":      "reuses 🧱 Spec Coverage's readiness score — the % of routes with a matching OpenAPI/gRPC/GraphQL spec entry.",
	"Protocol Modernity": "share of REST/gRPC/GraphQL among API-shaped routes; broker protocols (Kafka/NATS/AMQP/Redis) are excluded — they're an infra choice, not a modernity signal.",
	"Dependency Health":  "penalises a high outbound fan-out (>15 distinct targets) and a high share of external (vs internal/service-mesh) destinations.",
	"Observability":      "how many of /health, /ready, /metrics (and common variants) are found among inbound routes — graded 0→20, 1→50, 2→75, 3+→100.",
}
