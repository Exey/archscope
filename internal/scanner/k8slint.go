package scanner

// k8slint.go implements a dependency-free, best-effort linter over a
// `kubectl get <resources> --all-namespaces -o yaml` cluster dump (a single
// `kind: List` document) or plain Kubernetes manifest files (single or
// `---`-separated documents). It hand-rolls just enough of the YAML
// block-style grammar to walk kubectl's own marshalling conventions —
// flow-style collections beyond `{}`/`[]`, anchors/aliases, and tab
// indentation are out of scope, matching the "report card, not a
// replacement for the real tools" spirit of devopslint.go. Checks are
// inspired by kube-linter's default rule set (resource limits, security
// context, probes, image pinning, host access).

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	k8sLintMaxFileSize  = 128 * 1024 * 1024 // cluster dumps can be tens of MB
	k8sLintMaxDepth     = 5
	k8sLintSniffBytes   = 65536
	k8sLintMaxWorkloads = 400 // hard cap to keep the report renderable
)

// K8sContainer is one container's resource + image summary within a workload.
type K8sContainer struct {
	Name       string
	Image      string
	CPURequest string // display strings ("", "" when unset)
	CPULimit   string
	MemRequest string
	MemLimit   string
	StorageReq string // ephemeral-storage
	StorageLim string
}

// K8sWorkload is one deduplicated pod-owning resource: a bare Pod (no
// controller owner) or the pod template of a Deployment/StatefulSet/
// DaemonSet/Job/CronJob — linted once on behalf of all its replicas.
type K8sWorkload struct {
	Kind       string
	Name       string
	Namespace  string
	Replicas   int // -1 = not applicable/unknown (DaemonSet, Job, CronJob)
	Containers []K8sContainer
	Checks     []DevOpsCheck // Category = container name ("Pod" for pod-level checks)
	Score      int           // 0-100 pass rate (pass=1, warn=0.5, fail=0)
}

// K8sLint is the full result of scanning one or more cluster dumps.
type K8sLint struct {
	Workloads []K8sWorkload
	Files     []string
	Truncated bool // true when more workloads were found than we render
}

// Empty reports whether no lintable workload was found.
func (l *K8sLint) Empty() bool { return l == nil || len(l.Workloads) == 0 }

// ScanK8sLint walks rootPath (up to k8sLintMaxDepth levels) for YAML files
// that look like Kubernetes manifests or `kubectl -o yaml` cluster dumps,
// then lints every Pod/Deployment/StatefulSet/DaemonSet/Job/CronJob found.
func ScanK8sLint(rootPath string) *K8sLint {
	var files []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name()
			low := strings.ToLower(name)
			full := filepath.Join(dir, name)
			if e.IsDir() {
				if depth < k8sLintMaxDepth && !strings.HasPrefix(name, ".") &&
					low != "node_modules" && low != "vendor" && low != "templates" {
					walk(full, depth+1)
				}
				continue
			}
			if !strings.HasSuffix(low, ".yaml") && !strings.HasSuffix(low, ".yml") {
				continue
			}
			if looksLikeK8sManifest(full) {
				files = append(files, full)
			}
		}
	}
	walk(rootPath, 0)
	sort.Strings(files)
	if len(files) == 0 {
		return nil
	}

	var workloads []K8sWorkload
	for _, f := range files {
		lines, ok := readLarge(f, k8sLintMaxFileSize)
		if !ok {
			continue
		}
		workloads = append(workloads, scanDocuments(lines)...)
	}
	if len(workloads) == 0 {
		return nil
	}
	sort.Slice(workloads, func(i, j int) bool {
		if workloads[i].Score != workloads[j].Score {
			return workloads[i].Score < workloads[j].Score // worst first
		}
		if workloads[i].Namespace != workloads[j].Namespace {
			return workloads[i].Namespace < workloads[j].Namespace
		}
		return workloads[i].Name < workloads[j].Name
	})
	truncated := false
	if len(workloads) > k8sLintMaxWorkloads {
		workloads = workloads[:k8sLintMaxWorkloads]
		truncated = true
	}
	return &K8sLint{Workloads: workloads, Files: relPaths(rootPath, files), Truncated: truncated}
}

// readLarge reads path fully, rejecting files above maxSize, and returns it
// split into lines with trailing "\r" trimmed (tolerating CRLF dumps).
func readLarge(path string, maxSize int64) ([]string, bool) {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 || fi.Size() > maxSize {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	lines := strings.Split(string(data), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, "\r")
	}
	return lines, true
}

// looksLikeK8sManifest sniffs the first chunk of a file for a Kubernetes
// object/list marker, and rejects Helm templates (which use `{{ }}` even for
// literal `kind:` lines' surrounding structure) since those aren't valid
// rendered YAML and would otherwise silently produce garbage results.
//
// `kubectl get ... -o yaml` marshals top-level keys alphabetically
// (apiVersion, items, kind, metadata), so on a large dump `kind: List`
// itself can sit megabytes into the file, well past any reasonably small
// sniff window — but `items:` at column 0 always immediately follows
// `apiVersion:`, right at the top, so it alone is a reliable, cheap signal.
func looksLikeK8sManifest(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 || fi.Size() > k8sLintMaxFileSize {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, k8sLintSniffBytes)
	n, _ := f.Read(buf)
	sniff := string(buf[:n])
	if strings.Contains(sniff, "{{") {
		return false
	}
	if strings.Contains(sniff, "\nitems:\n") || strings.HasPrefix(sniff, "items:\n") {
		return true
	}
	return k8sKindSniffRe.MatchString(sniff)
}

var k8sKindSniffRe = regexp.MustCompile(`(?m)^\s{0,2}kind:\s*(Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|List)\s*$`)

var k8sTargetKinds = map[string]bool{
	"Pod": true, "Deployment": true, "StatefulSet": true,
	"DaemonSet": true, "Job": true, "CronJob": true,
}

// ── YAML-lite parser ─────────────────────────────────────────────────────
//
// Values are represented as map[string]any (mapping), []any (sequence), or
// string (scalar; block scalars and multi-line quoted scalars are consumed
// structurally but collapsed to "" since their content is never inspected).

func lineIndent(s string) int {
	n := 0
	for n < len(s) && s[n] == ' ' {
		n++
	}
	return n
}

func isBlankOrComment(s string) bool {
	t := strings.TrimSpace(s)
	return t == "" || strings.HasPrefix(t, "#")
}

// peekContent returns the index and indent of the next non-blank,
// non-comment line at or after i.
func peekContent(lines []string, i int) (idx, indent int, ok bool) {
	n := len(lines)
	for i < n {
		if !isBlankOrComment(lines[i]) {
			return i, lineIndent(lines[i]), true
		}
		i++
	}
	return i, 0, false
}

var blockScalarRe = regexp.MustCompile(`^[|>][+-]?\d*$`)

func hasUnterminatedQuote(s string) (quote byte, unterminated bool) {
	if s == "" {
		return 0, false
	}
	q := s[0]
	if q != '"' && q != '\'' {
		return 0, false
	}
	for i := 1; i < len(s); i++ {
		if q == '"' && s[i] == '\\' {
			i++
			continue
		}
		if s[i] == q {
			return q, false
		}
	}
	return q, true
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			inner := s[1 : len(s)-1]
			if s[0] == '"' {
				inner = strings.ReplaceAll(inner, `\"`, `"`)
				inner = strings.ReplaceAll(inner, `\\`, `\`)
			}
			return inner
		}
	}
	return s
}

// splitKeyValue splits already-de-indented mapping content "key: value" (or
// "key:" with a nested/empty value) into key and inline value.
func splitKeyValue(content string) (key, val string, hasInline bool) {
	if idx := strings.Index(content, ": "); idx >= 0 {
		return strings.TrimSpace(content[:idx]), strings.TrimSpace(content[idx+2:]), true
	}
	if strings.HasSuffix(content, ":") {
		return strings.TrimSpace(content[:len(content)-1]), "", false
	}
	return strings.TrimSpace(content), "", false
}

// skipBlockScalarBody consumes a block-scalar's (|, >) body: every following
// line indented more than `indent`, blank lines included, stopping at the
// first line at or below `indent`. Returns the index of the first
// unconsumed line.
func skipBlockScalarBody(lines []string, i, indent int) int {
	n := len(lines)
	for i < n {
		if strings.TrimSpace(lines[i]) == "" {
			i++
			continue
		}
		if lineIndent(lines[i]) <= indent {
			break
		}
		i++
	}
	return i
}

// skipQuotedScalarBody consumes the continuation lines of a double/single
// quoted scalar that wraps past the line it started on, stopping just after
// the line containing the matching unescaped closing quote.
func skipQuotedScalarBody(lines []string, i int, quote byte) int {
	n := len(lines)
	for i < n {
		line := lines[i]
		i++
		closed := false
		for j := 0; j < len(line); j++ {
			if quote == '"' && line[j] == '\\' {
				j++
				continue
			}
			if line[j] == quote {
				closed = true
				break
			}
		}
		if closed {
			break
		}
	}
	return i
}

// skipPlainScalarContinuation consumes lines folded onto a just-parsed plain
// (unquoted) scalar — YAML allows a plain scalar to wrap across physical
// lines as long as the continuation is indented more than its enclosing
// mapping/sequence and isn't itself a new "- " item; kubectl emits long
// unquoted shell one-liners (e.g. container command args) exactly this way.
// A blank line ends a plain scalar.
func skipPlainScalarContinuation(lines []string, i, indent int) int {
	n := len(lines)
	for i < n {
		if strings.TrimSpace(lines[i]) == "" {
			break
		}
		if lineIndent(lines[i]) <= indent {
			break
		}
		i++
	}
	return i
}

// parseScalarOrBlock interprets an inline value that follows "key: ". Block
// scalars (|, >) and quoted scalars that wrap onto following lines are
// structurally skipped rather than folded/unescaped — callers only ever
// need correct skipping, never their literal content.
func parseScalarOrBlock(val string, lines []string, i, keyIndent int) (any, int) {
	if blockScalarRe.MatchString(val) {
		return "", skipBlockScalarBody(lines, i, keyIndent)
	}
	if q, unterminated := hasUnterminatedQuote(val); unterminated {
		return "", skipQuotedScalarBody(lines, i, q)
	}
	switch val {
	case "{}":
		return map[string]any{}, i
	case "[]":
		return []any{}, i
	}
	return unquote(val), skipPlainScalarContinuation(lines, i, keyIndent)
}

// parseNestedValue resolves a key's nested value (the key itself had no
// inline value) starting the search at line i. YAML permits a block
// sequence to be indented the SAME as its parent key — kubectl's own
// marshalling convention (`items:` immediately followed by `- apiVersion:`
// at that same column, and it recurses at every level: `volumes:` /
// `- name: ...`) — so a same-indent "- " line still counts as this key's
// value; anything else at or below keyIndent means the value is empty.
func parseNestedValue(lines []string, i, keyIndent int) (any, int) {
	ci, cind, ok := peekContent(lines, i)
	if !ok {
		return nil, i
	}
	if cind > keyIndent {
		return parseValueBlock(lines, ci, cind)
	}
	if cind == keyIndent {
		if child := lines[ci][cind:]; child == "-" || strings.HasPrefix(child, "- ") {
			return parseSequence(lines, ci, cind)
		}
	}
	return nil, i
}

// parseMapping parses consecutive "key: value" / "key:" lines that share
// exactly `indent` leading spaces, starting at lines[i].
func parseMapping(lines []string, i, indent int) (map[string]any, int) {
	n := len(lines)
	m := map[string]any{}
	for {
		for i < n && isBlankOrComment(lines[i]) {
			i++
		}
		if i >= n || lineIndent(lines[i]) != indent {
			break
		}
		rest := lines[i][indent:]
		if rest == "-" || strings.HasPrefix(rest, "- ") {
			break
		}
		key, val, hasInline := splitKeyValue(rest)
		i++
		if hasInline {
			v, newI := parseScalarOrBlock(val, lines, i, indent)
			m[key] = v
			i = newI
			continue
		}
		child, newI := parseNestedValue(lines, i, indent)
		m[key] = child
		i = newI
	}
	return m, i
}

// parseValueBlock dispatches to parseSequence or parseMapping based on the
// shape of the line at (i, indent).
func parseValueBlock(lines []string, i, indent int) (any, int) {
	rest := lines[i][indent:]
	if rest == "-" || strings.HasPrefix(rest, "- ") {
		return parseSequence(lines, i, indent)
	}
	return parseMapping(lines, i, indent)
}

// parseSequence parses "- ..." items sharing exactly `indent` leading spaces.
func parseSequence(lines []string, i, indent int) ([]any, int) {
	n := len(lines)
	var out []any
	for {
		for i < n && isBlankOrComment(lines[i]) {
			i++
		}
		if i >= n || lineIndent(lines[i]) != indent {
			break
		}
		rest := lines[i][indent:]
		if !(rest == "-" || strings.HasPrefix(rest, "- ")) {
			break
		}
		itemContent := strings.TrimSpace(strings.TrimPrefix(rest, "-"))
		itemIndent := indent + 2
		i++
		if itemContent == "" {
			child, newI := parseNestedValue(lines, i, indent)
			out = append(out, child)
			i = newI
			continue
		}
		if blockScalarRe.MatchString(itemContent) {
			out = append(out, "")
			i = skipBlockScalarBody(lines, i, indent)
			continue
		}
		if q, unterminated := hasUnterminatedQuote(itemContent); unterminated {
			out = append(out, "")
			i = skipQuotedScalarBody(lines, i, q)
			continue
		}
		looksLikeKV := strings.Contains(itemContent, ": ") || strings.HasSuffix(itemContent, ":")
		if !looksLikeKV {
			out = append(out, unquote(itemContent))
			i = skipPlainScalarContinuation(lines, i, indent)
			continue
		}
		key, val, hasInline := splitKeyValue(itemContent)
		item := map[string]any{}
		if hasInline {
			v, newI := parseScalarOrBlock(val, lines, i, itemIndent)
			item[key] = v
			i = newI
		} else {
			child, newI := parseNestedValue(lines, i, itemIndent)
			item[key] = child
			i = newI
		}
		rest2, newI := parseMapping(lines, i, itemIndent)
		for k, v := range rest2 {
			item[k] = v
		}
		i = newI
		out = append(out, item)
	}
	return out, i
}

// ── document/list scanning ────────────────────────────────────────────────

var topKindRe = regexp.MustCompile(`^kind:\s*(\S+)\s*$`)
var itemKindRe = regexp.MustCompile(`^  kind:\s*(Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob)\s*$`)

// scanDocuments splits raw file lines on top-level "---" separators and
// scans each resulting document.
func scanDocuments(lines []string) []K8sWorkload {
	var out []K8sWorkload
	start := 0
	for i, l := range lines {
		if strings.TrimSpace(l) == "---" && lineIndent(l) == 0 {
			out = append(out, scanDocument(lines[start:i])...)
			start = i + 1
		}
	}
	out = append(out, scanDocument(lines[start:])...)
	return out
}

// scanDocument scans one YAML document: either a `kind: List` wrapper (cheap
// boundary scan over items, deep-parsing only matching ones) or a single
// plain manifest object.
func scanDocument(lines []string) []K8sWorkload {
	itemsIdx := -1
	for idx, l := range lines {
		if l == "items:" {
			itemsIdx = idx
			break
		}
	}
	if itemsIdx >= 0 {
		return scanItemsList(lines, itemsIdx+1)
	}

	kind := ""
	for _, l := range lines {
		if m := topKindRe.FindStringSubmatch(l); m != nil {
			kind = m[1]
			break
		}
	}
	if !k8sTargetKinds[kind] {
		return nil
	}
	item, _ := parseMapping(lines, 0, 0)
	return workloadsFromItem(kind, item)
}

// scanItemsList cheaply locates each top-level "- " item's line range (no
// parsing) and only runs the full recursive-descent parser on items whose
// `kind:` line (found via a plain string scan within that range) matches one
// of our target kinds — the vast majority of a cluster dump (Secrets,
// ConfigMaps, Events, RBAC, CRDs, ...) is never touched.
func scanItemsList(lines []string, start int) []K8sWorkload {
	n := len(lines)
	var bounds []int
	endOfList := n
	for i := start; i < n; i++ {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		if lineIndent(lines[i]) != 0 {
			continue
		}
		if strings.HasPrefix(lines[i], "- ") {
			bounds = append(bounds, i)
			continue
		}
		endOfList = i
		break
	}
	var out []K8sWorkload
	for bi, s := range bounds {
		e := endOfList
		if bi+1 < len(bounds) {
			e = bounds[bi+1]
		}
		kind := ""
		for j := s; j < e; j++ {
			if m := itemKindRe.FindStringSubmatch(lines[j]); m != nil {
				kind = m[1]
				break
			}
		}
		if kind == "" {
			continue
		}
		items, _ := parseSequence(lines[s:e], 0, 0)
		if len(items) != 1 {
			continue
		}
		item, ok := items[0].(map[string]any)
		if !ok {
			continue
		}
		out = append(out, workloadsFromItem(kind, item)...)
	}
	return out
}

// ── field accessors ───────────────────────────────────────────────────────

func mapField(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok {
		return nil
	}
	mm, _ := v.(map[string]any)
	return mm
}

func listField(m map[string]any, key string) []any {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok {
		return nil
	}
	l, _ := v.([]any)
	return l
}

func strField(m map[string]any, key string) (string, bool) {
	if m == nil {
		return "", false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func boolField(m map[string]any, key string) (bool, bool) {
	s, ok := strField(m, key)
	if !ok {
		return false, false
	}
	return s == "true", true
}

func getMapPath(m map[string]any, path ...string) map[string]any {
	cur := m
	for _, p := range path {
		cur = mapField(cur, p)
	}
	return cur
}

// ── workload extraction ───────────────────────────────────────────────────

func podOwnerKind(item map[string]any) string {
	meta := mapField(item, "metadata")
	for _, o := range listField(meta, "ownerReferences") {
		om, _ := o.(map[string]any)
		if k, ok := strField(om, "kind"); ok && k != "" {
			return k
		}
	}
	return ""
}

func workloadsFromItem(kind string, item map[string]any) []K8sWorkload {
	meta := mapField(item, "metadata")
	name, _ := strField(meta, "name")
	if name == "" {
		return nil
	}
	ns, _ := strField(meta, "namespace")
	if ns == "" {
		ns = "default"
	}

	if kind == "Pod" {
		switch podOwnerKind(item) {
		case "ReplicaSet", "StatefulSet", "DaemonSet", "Job":
			return nil // already represented by its controller
		}
		spec := mapField(item, "spec")
		if spec == nil {
			return nil
		}
		return []K8sWorkload{lintWorkload(kind, name, ns, spec, 1)}
	}
	if kind == "Job" && podOwnerKind(item) == "CronJob" {
		return nil // represented by the CronJob's job template
	}

	spec := mapField(item, "spec")
	var podSpec map[string]any
	replicas := -1
	switch kind {
	case "Deployment", "StatefulSet":
		podSpec = getMapPath(spec, "template", "spec")
		if r, ok := strField(spec, "replicas"); ok {
			if rn, err := strconv.Atoi(r); err == nil {
				replicas = rn
			}
		}
	case "DaemonSet", "Job":
		podSpec = getMapPath(spec, "template", "spec")
	case "CronJob":
		podSpec = getMapPath(spec, "jobTemplate", "spec", "template", "spec")
	}
	if podSpec == nil {
		return nil
	}
	return []K8sWorkload{lintWorkload(kind, name, ns, podSpec, replicas)}
}

// ── lint checks (inspired by kube-linter's default rule set) ─────────────

func strictStatus(good bool) string {
	if good {
		return "pass"
	}
	return "fail"
}

func imageTagCheck(image string) (status, value string) {
	if image == "" {
		return "na", "no image"
	}
	if strings.Contains(image, "@sha256:") {
		return "pass", "pinned @sha256"
	}
	last := image
	if idx := strings.LastIndex(image, "/"); idx >= 0 {
		last = image[idx+1:]
	}
	if idx := strings.Index(last, ":"); idx >= 0 {
		tag := last[idx+1:]
		if tag == "" || tag == "latest" {
			return "fail", "tag: " + tag
		}
		return "pass", "tag: " + tag
	}
	return "fail", "no tag (implicit latest)"
}

func lintContainer(c map[string]any) (K8sContainer, []DevOpsCheck) {
	name, _ := strField(c, "name")
	image, _ := strField(c, "image")
	kc := K8sContainer{Name: name, Image: image}

	var checks []DevOpsCheck
	add := func(metric, status, value string) {
		checks = append(checks, DevOpsCheck{Category: name, Metric: metric, Status: status, Value: value})
	}

	res := mapField(c, "resources")
	reqs := mapField(res, "requests")
	lims := mapField(res, "limits")
	kc.CPURequest, _ = strField(reqs, "cpu")
	kc.MemRequest, _ = strField(reqs, "memory")
	kc.CPULimit, _ = strField(lims, "cpu")
	kc.MemLimit, _ = strField(lims, "memory")
	kc.StorageReq, _ = strField(reqs, "ephemeral-storage")
	kc.StorageLim, _ = strField(lims, "ephemeral-storage")

	add("CPU/memory requests set", boolStatus(kc.CPURequest != "" && kc.MemRequest != ""), ratio2(kc.CPURequest != "", kc.MemRequest != ""))
	add("CPU/memory limits set", strictStatus(kc.CPULimit != "" && kc.MemLimit != ""), ratio2(kc.CPULimit != "", kc.MemLimit != ""))

	sc := mapField(c, "securityContext")
	priv, _ := boolField(sc, "privileged")
	add("Privileged container", strictStatus(!priv), boolYesNo(priv))

	allowEsc, hasAllowEsc := boolField(sc, "allowPrivilegeEscalation")
	add("allowPrivilegeEscalation: false", strictStatus(hasAllowEsc && !allowEsc), boolYesNo(!hasAllowEsc || allowEsc))

	runAsNonRoot, hasNonRoot := boolField(sc, "runAsNonRoot")
	add("runAsNonRoot enforced", strictStatus(hasNonRoot && runAsNonRoot), boolYesNo(hasNonRoot && runAsNonRoot))

	roFS, hasRoFS := boolField(sc, "readOnlyRootFilesystem")
	add("readOnlyRootFilesystem", boolStatus(hasRoFS && roFS), boolYesNo(hasRoFS && roFS))

	caps := mapField(sc, "capabilities")
	badCap := false
	for _, v := range listField(caps, "add") {
		s, _ := v.(string)
		for _, d := range dangerousCaps {
			if strings.EqualFold(s, d) {
				badCap = true
			}
		}
	}
	add("Dangerous capabilities added", strictStatus(!badCap), boolYesNo(badCap))

	add("seccompProfile set", boolStatus(mapField(sc, "seccompProfile") != nil), boolYesNo(mapField(sc, "seccompProfile") != nil))

	_, hasLiveness := c["livenessProbe"]
	add("Liveness probe configured", boolStatus(hasLiveness), boolYesNo(hasLiveness))
	_, hasReadiness := c["readinessProbe"]
	add("Readiness probe configured", boolStatus(hasReadiness), boolYesNo(hasReadiness))

	tagStatus, tagVal := imageTagCheck(image)
	add("Pinned image tag (no :latest)", tagStatus, tagVal)

	return kc, checks
}

func lintWorkload(kind, name, ns string, podSpec map[string]any, replicas int) K8sWorkload {
	w := K8sWorkload{Kind: kind, Name: name, Namespace: ns, Replicas: replicas}
	add := func(metric, status, value string) {
		w.Checks = append(w.Checks, DevOpsCheck{Category: "Pod", Metric: metric, Status: status, Value: value})
	}

	hostNetwork, _ := boolField(podSpec, "hostNetwork")
	hostPID, _ := boolField(podSpec, "hostPID")
	hostIPC, _ := boolField(podSpec, "hostIPC")
	add("hostNetwork/hostPID/hostIPC", strictStatus(!(hostNetwork || hostPID || hostIPC)), boolYesNo(hostNetwork || hostPID || hostIPC))

	sa, hasSA := strField(podSpec, "serviceAccountName")
	add("Dedicated service account", boolStatus(hasSA && sa != "" && sa != "default"), fallback(sa, "default"))

	hostPathCount := 0
	for _, v := range listField(podSpec, "volumes") {
		vm, _ := v.(map[string]any)
		if mapField(vm, "hostPath") != nil {
			hostPathCount++
		}
	}
	add("hostPath volumes mounted", strictStatus(hostPathCount == 0), strconv.Itoa(hostPathCount))

	for _, cv := range listField(podSpec, "containers") {
		cm, _ := cv.(map[string]any)
		if cm == nil {
			continue
		}
		kc, checks := lintContainer(cm)
		w.Containers = append(w.Containers, kc)
		w.Checks = append(w.Checks, checks...)
	}

	var pts, cnt float64
	for _, c := range w.Checks {
		switch c.Status {
		case "pass":
			pts++
			cnt++
		case "warn":
			pts += 0.5
			cnt++
		case "fail":
			cnt++
		}
	}
	if cnt > 0 {
		w.Score = int(pts/cnt*100 + 0.5)
	} else {
		w.Score = 100
	}
	return w
}

func boolYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func ratio2(a, b bool) string {
	n := 0
	if a {
		n++
	}
	if b {
		n++
	}
	return ratio(n, 2)
}

func fallback(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
