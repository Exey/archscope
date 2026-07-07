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

// K8sOperatorResource is one CRD kind from a recognized operator (Prometheus
// Operator, Vault Secrets Operator, ...) found in the dump, with a total
// count and — for the few kinds we know how to read a status from — a
// best-effort health summary.
type K8sOperatorResource struct {
	Kind                 string
	Count                int
	AvailableReplicas    int // summed status.availableReplicas (Prometheus only)
	HasAvailableReplicas bool
}

// K8sIngressRule is one Ingress path rule: the host it matches (empty =
// catch-all), the path, and the backend it routes to ("service:port").
type K8sIngressRule struct {
	Host    string
	Path    string
	Backend string
}

// K8sIngressDetail is one Ingress's routing/TLS/timeout detail — the
// per-resource drill-down shown alongside the Networking & Exposure
// aggregate counts, since "2 Ingresses, 1/2 TLS" hides exactly the host,
// backend, and timeout info developers actually need.
type K8sIngressDetail struct {
	Name         string
	Namespace    string
	IngressClass string // "" if unset
	Rules        []K8sIngressRule
	TLS          bool
	TLSSecrets   []string
	Timeouts     []K8sIngressTimeout // best-effort from common proxy-timeout annotations; empty if none found
}

// K8sIngressTimeout is one proxy-timeout annotation found on an Ingress,
// split into its label (the short annotation name) and value so the
// renderer can color them separately.
type K8sIngressTimeout struct {
	Label string
	Value string
}

// K8sServicePort is one Service port mapping.
type K8sServicePort struct {
	Name       string
	Port       string
	TargetPort string
	Protocol   string
}

// K8sServiceDetail is one Service's type/ports.
type K8sServiceDetail struct {
	Name      string
	Namespace string
	Type      string // ClusterIP/NodePort/LoadBalancer/ExternalName; defaults to ClusterIP
	Ports     []K8sServicePort
}

// K8sClusterStats aggregates the non-workload resources found alongside the
// linted workloads (Services, Ingresses, RBAC, ...) into the counts and
// ratios shown by the informational sub-cards rendered after the workload
// grid. Unlike K8sWorkload these are cluster-wide tallies, not per-object
// pass/warn/fail checks — except IngressDetails/ServiceDetails, which carry
// enough per-object routing detail for their own drill-down cards.
type K8sClusterStats struct {
	Services          int
	ServicesPrivPorts int // Service ports < 1024, summed across all Services
	Ingresses         int
	IngressesTLS      int // Ingresses with spec.tls set
	NetworkPolicies   int

	IngressDetails []K8sIngressDetail
	ServiceDetails []K8sServiceDetail

	ConfigMaps           int // excludes system-generated ones (kube-root-ca.crt, kube-system namespace)
	PVCs                 int
	PVCsWithStorageClass int
	StorageClasses       int

	ServiceAccounts      int // excludes the implicit "default" account
	Roles                int
	RolesWildcard        int // Role rules using a "*" verb or resource
	RoleBindings         int
	ClusterRoles         int
	ClusterRolesWildcard int // ClusterRoles with true wildcard (verbs:* AND resources:* or apiGroups:*)
	ClusterRoleBindings  int
	ClusterAdminBindings int // ClusterRoleBindings to cluster-admin with a custom (non-platform) SA

	HPAs int
	PDBs int

	Operators []K8sOperatorResource
}

// Empty reports whether no cluster-wide stat resource was found at all.
func (s K8sClusterStats) Empty() bool {
	return s.Services == 0 && s.Ingresses == 0 && s.NetworkPolicies == 0 &&
		s.ConfigMaps == 0 && s.PVCs == 0 && s.StorageClasses == 0 &&
		s.ServiceAccounts == 0 && s.Roles == 0 && s.RoleBindings == 0 &&
		s.ClusterRoles == 0 && s.ClusterRoleBindings == 0 &&
		s.HPAs == 0 && s.PDBs == 0 && len(s.Operators) == 0
}

// K8sLint is the full result of scanning one or more cluster dumps.
type K8sLint struct {
	Workloads       []K8sWorkload
	Stats           K8sClusterStats
	Files           []string
	Truncated       bool                        // true when more workloads were found than we render
	NamespaceTiers  map[string]K8sNamespaceTier // namespace name → risk tier
	ClusterFindings []K8sClusterFinding         // cross-cutting findings from resource-graph analysis
}

// Empty reports whether no lintable workload was found.
func (l *K8sLint) Empty() bool { return l == nil || len(l.Workloads) == 0 }

// ── namespace classification + cross-cutting findings ─────────────────────

// K8sNamespaceTier is the risk classification of a namespace derived from the
// objects it contains. The highest-risk tier wins when multiple signals apply.
type K8sNamespaceTier string

const (
	K8sTierSystem         K8sNamespaceTier = "system"
	K8sTierInternetFacing K8sNamespaceTier = "internet-facing"
	K8sTierProduction     K8sNamespaceTier = "production"
	K8sTierStateful       K8sNamespaceTier = "stateful"
)

// K8sClusterFinding is a cross-cutting finding produced by resource-graph
// checks that run after all manifest objects have been parsed. Unlike the
// per-container DevOpsChecks, these span multiple resource kinds.
type K8sClusterFinding struct {
	RuleID    string
	Namespace string
	Kind      string
	Name      string
	Tier      K8sNamespaceTier
	Severity  string // "critical" | "high" | "medium" | "low"
	Title     string
	Detail    string
	CWE       string
	File      string // absolute path of the source YAML manifest (for VSCode links)
	Line      int    // 1-based line number within File where this resource is defined
}

// k8sGraph is the in-memory resource index built in a first pass over all
// parsed manifest items. The cross-cutting checks (C1/C3) consume it.
type k8sGraph struct {
	nsTier          map[string]K8sNamespaceTier
	nsNPCount       map[string]int
	nsDefaultDeny   map[string]bool
	nsHasLB         map[string]bool
	nsHasIngress    map[string]bool
	nsHasStateful   map[string]bool
	nsHasDatastore  map[string]bool
	nsWorkloadNames map[string][]string
	hpaTargets      map[string]bool // "ns/name"
	pdbNamespaces   map[string]bool
	// findings collected during build (before cross-checks)
	lbFindings      []K8sClusterFinding
	ingressFindings []K8sClusterFinding
	rbacFindings    []K8sClusterFinding
	secretFindings  []K8sClusterFinding
	hardenFindings  []K8sClusterFinding
}

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

	// Pass 1: collect all items, deduplicating across files.
	var allItems []k8sRawItem
	var workloadFiles []string
	seen := make(map[string]bool)
	for _, f := range files {
		lines, ok := readLarge(f, k8sLintMaxFileSize)
		if !ok {
			continue
		}
		fileHasWorkload := false
		for _, raw := range scanDocuments(lines) {
			meta := mapField(raw.Item, "metadata")
			name, _ := strField(meta, "name")
			ns, _ := strField(meta, "namespace")
			// A cluster dump split across multiple `kubectl get` invocations
			// commonly re-exports the same object more than once; keep only
			// the first occurrence so it isn't double-counted.
			key := raw.Kind + "/" + ns + "/" + name
			if seen[key] {
				continue
			}
			seen[key] = true
			raw.File = f // absolute path for VSCode deep links
			allItems = append(allItems, raw)
			if k8sTargetKinds[raw.Kind] {
				fileHasWorkload = true
			}
		}
		if fileHasWorkload {
			workloadFiles = append(workloadFiles, f)
		}
	}

	// Pass 2: route items to workloads or cluster stats.
	var workloads []K8sWorkload
	var stats K8sClusterStats
	for _, raw := range allItems {
		if k8sTargetKinds[raw.Kind] {
			workloads = append(workloads, workloadsFromItem(raw.Kind, raw.Item)...)
		} else {
			statsFromItem(raw.Kind, raw.Item, &stats)
		}
	}
	if len(workloads) == 0 {
		return nil
	}

	// Pass 3: build resource graph and run cross-cutting checks.
	graph := buildK8sGraph(allItems)
	clusterFindings := runCrossChecks(graph)

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
	return &K8sLint{
		Workloads:       workloads,
		Stats:           stats,
		Files:           relPaths(rootPath, workloadFiles),
		Truncated:       truncated,
		NamespaceTiers:  graph.nsTier,
		ClusterFindings: clusterFindings,
	}
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

var k8sKindSniffRe = regexp.MustCompile(`(?m)^\s{0,2}kind:\s*(Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|Service|Ingress|NetworkPolicy|ConfigMap|PersistentVolumeClaim|StorageClass|ServiceAccount|Role|RoleBinding|ClusterRole|ClusterRoleBinding|HorizontalPodAutoscaler|PodDisruptionBudget|Prometheus|Alertmanager|PrometheusRule|ServiceMonitor|PodMonitor|ScrapeConfig|VaultStaticSecret|VaultPKISecret|VaultConnection|VaultAuth|HTTPBackendGroup|GRPCBackendGroup|IngressGroupSetting|List)\s*$`)

var k8sTargetKinds = map[string]bool{
	"Pod": true, "Deployment": true, "StatefulSet": true,
	"DaemonSet": true, "Job": true, "CronJob": true,
}

// k8sOperatorKinds are CRD kinds from recognized operators (Prometheus
// Operator, Vault Secrets Operator, gateway/ALB-style backend CRDs) that get
// grouped into the "Operators" stats card, one row per kind.
var k8sOperatorKinds = map[string]bool{
	"Prometheus": true, "Alertmanager": true, "PrometheusRule": true,
	"ServiceMonitor": true, "PodMonitor": true, "ScrapeConfig": true,
	"VaultStaticSecret": true, "VaultPKISecret": true, "VaultConnection": true, "VaultAuth": true,
	"HTTPBackendGroup": true, "GRPCBackendGroup": true, "IngressGroupSetting": true,
}

// k8sStatsKinds are the non-workload kinds counted into K8sClusterStats —
// networking/exposure, config/storage, RBAC, autoscaling/budgets, plus the
// operator CRDs in k8sOperatorKinds.
var k8sStatsKinds = func() map[string]bool {
	m := map[string]bool{
		"Service": true, "Ingress": true, "NetworkPolicy": true,
		"ConfigMap": true, "PersistentVolumeClaim": true, "StorageClass": true,
		"ServiceAccount": true, "Role": true, "RoleBinding": true,
		"ClusterRole": true, "ClusterRoleBinding": true,
		"HorizontalPodAutoscaler": true, "PodDisruptionBudget": true,
	}
	for k := range k8sOperatorKinds {
		m[k] = true
	}
	return m
}()

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
var itemKindRe = regexp.MustCompile(`^  kind:\s*(\S+)\s*$`)

// k8sRawItem is one parsed manifest object paired with its `kind:`, before
// it's routed to either workload linting or cluster-stats aggregation.
type k8sRawItem struct {
	Kind      string
	Item      map[string]any
	File      string // absolute path of the source YAML file (for VSCode links)
	StartLine int    // 1-based line number of this item within File
}

// scanDocuments splits raw file lines on top-level "---" separators and
// scans each resulting document.
func scanDocuments(lines []string) []k8sRawItem {
	var out []k8sRawItem
	start := 0
	for i, l := range lines {
		if strings.TrimSpace(l) == "---" && lineIndent(l) == 0 {
			out = append(out, scanDocument(lines[start:i], start)...)
			start = i + 1
		}
	}
	out = append(out, scanDocument(lines[start:], start)...)
	return out
}

// scanDocument scans one YAML document: either a `kind: List` wrapper (cheap
// boundary scan over items, deep-parsing only matching ones) or a single
// plain manifest object.
func scanDocument(lines []string, offset int) []k8sRawItem {
	itemsIdx := -1
	for idx, l := range lines {
		if l == "items:" {
			itemsIdx = idx
			break
		}
	}
	if itemsIdx >= 0 {
		return scanItemsList(lines, itemsIdx+1, offset)
	}

	kind := ""
	for _, l := range lines {
		if m := topKindRe.FindStringSubmatch(l); m != nil {
			kind = m[1]
			break
		}
	}
	if !k8sTargetKinds[kind] && !k8sStatsKinds[kind] {
		return nil
	}
	item, _ := parseMapping(lines, 0, 0)
	return []k8sRawItem{{Kind: kind, Item: item, StartLine: offset + 1}}
}

// scanItemsList cheaply locates each top-level "- " item's line range (no
// parsing) and only runs the full recursive-descent parser on items whose
// `kind:` line (found via a plain string scan within that range) matches one
// of our target or stats kinds — the vast majority of a cluster dump
// (Secrets, Events, Nodes, Leases, ...) is never touched.
func scanItemsList(lines []string, start, offset int) []k8sRawItem {
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
	var out []k8sRawItem
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
		if kind == "" || !(k8sTargetKinds[kind] || k8sStatsKinds[kind]) {
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
		out = append(out, k8sRawItem{Kind: kind, Item: item, StartLine: offset + s + 1})
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

// ── cluster stats extraction (Networking/Config/RBAC/Autoscaling/Operators) ─

// k8sSystemNamespaces are excluded from the "custom ConfigMaps"/"custom
// ServiceAccounts" counts, since they're always present and never
// user-authored.
var k8sSystemNamespaces = map[string]bool{
	"kube-system": true, "kube-public": true, "kube-node-lease": true,
}

// k8sTierSystemPrefixes are namespace name prefixes/exact names that indicate
// platform/operator namespaces — their DaemonSet privilege findings and missing
// NetworkPolicies are expected and suppressed.
var k8sTierSystemPrefixes = []string{
	"kube-", "cattle-", "calico-", "cilium", "istio-", "linkerd",
	"monitoring", "logging", "cert-manager", "ingress-", "external-",
	"flux-", "argocd", "velero", "crossplane",
}

// k8sDatastoreImages are container image substrings that indicate a datastore
// workload — used to escalate severity when such a workload is publicly exposed.
var k8sDatastoreImages = []string{
	"mongo", "postgresql", "postgres", "mysql", "mariadb",
	"redis", "kafka", "rabbitmq", "elasticsearch", "opensearch",
	"cassandra", "influxdb", "minio", "qdrant", "weaviate",
	"chromadb", "etcd",
}

// k8sDatastorePorts are TCP ports commonly used by datastores — an unrestricted
// LoadBalancer exposing any of these is escalated to "critical".
var k8sDatastorePorts = map[string]bool{
	"27017": true, "5432": true, "3306": true, "6379": true,
	"5672": true, "15672": true, "9200": true, "9300": true,
	"6333": true, "6334": true, "9092": true, "2379": true,
	"2380": true, "9000": true,
}

// k8sPlatformSANames are well-known system/operator ServiceAccount names whose
// cluster-admin binding is expected and should not trigger an alert.
var k8sPlatformSANames = map[string]bool{
	"default": true, "cluster-admin": true,
	"kube-controller-manager": true, "kube-scheduler": true,
	"node-problem-detector": true, "cluster-autoscaler": true,
	"cert-manager": true, "external-secrets": true,
	"vault": true, "prometheus": true, "prometheus-operator": true,
	"prometheus-kube-prometheus-prometheus": true,
	"coredns":                               true, "metrics-server": true,
	"ingress-nginx": true, "aws-node": true, "kube-proxy": true,
	"flannel": true, "calico-node": true, "weave-net": true,
	"cilium": true, "cilium-operator": true,
	"argo-workflows": true, "argocd-application-controller": true,
	"argocd-server": true, "velero": true,
	"flux-system": true, "helm-operator": true,
	"crossplane": true, "crossplane-rbac-manager": true,
}

// k8sEnvSecretKeyRe matches env var names that commonly hold credentials.
// Matched against the variable name only — values are NEVER emitted in output.
var k8sEnvSecretKeyRe = regexp.MustCompile(
	`(?i)(password|passwd|secret|api[_-]?key|apitoken|auth[_-]?token|` +
		`access[_-]?token|private[_-]?key|client[_-]?secret|` +
		`signing[_-]?key|encryption[_-]?key|database[_-]?url|db[_-]?url|` +
		`dsn|jwt[_-]?secret|hmac[_-]?key|bearer[_-]?token)`,
)

// k8sHardeningEntry is one catalog rule for a well-known container image.
type k8sHardeningEntry struct {
	matchImage    string    // substring to match in container image (case-insensitive)
	requireAnyEnv []string  // flag if NONE of these env vars are set
	forbidEnvPair [2]string // {name, value}: flag if env[name] == value
	severity      string
	cwe           string
	title         string
	detail        string
}

// k8sHardeningCatalog defines per-image hardening rules checked during graph
// analysis. Secret values from forbidEnvPair comparisons are NEVER emitted.
var k8sHardeningCatalog = []k8sHardeningEntry{
	{
		matchImage:    "qdrant/qdrant",
		requireAnyEnv: []string{"QDRANT__SERVICE__API_KEY", "QDRANT__SERVICE__READ_ONLY_API_KEY"},
		severity:      "high", cwe: "306",
		title:  "Qdrant started without API key",
		detail: "Set QDRANT__SERVICE__API_KEY (or READ_ONLY_API_KEY) to restrict access to the vector database.",
	},
	{
		matchImage: "rabbitmq", forbidEnvPair: [2]string{"RABBITMQ_DEFAULT_USER", "guest"},
		severity: "critical", cwe: "798",
		title:  "RabbitMQ using default guest credentials",
		detail: "Change RABBITMQ_DEFAULT_USER and RABBITMQ_DEFAULT_PASS from the default 'guest/guest'.",
	},
	{
		matchImage:    "mongo",
		requireAnyEnv: []string{"MONGO_INITDB_ROOT_PASSWORD", "MONGODB_ROOT_PASSWORD", "MONGO_INITDB_ROOT_PASSWORD_FILE"},
		severity:      "critical", cwe: "306",
		title:  "MongoDB started without root password",
		detail: "Set MONGO_INITDB_ROOT_PASSWORD — without it the database is accessible to anyone with network access.",
	},
	{
		matchImage:    "postgres",
		requireAnyEnv: []string{"POSTGRES_PASSWORD", "POSTGRES_PASSWORD_FILE", "PGPASSWORD"},
		severity:      "high", cwe: "306",
		title:  "PostgreSQL started without a password",
		detail: "Set POSTGRES_PASSWORD (or POSTGRES_PASSWORD_FILE) to require authentication.",
	},
	{
		matchImage:    "mysql",
		requireAnyEnv: []string{"MYSQL_ROOT_PASSWORD", "MYSQL_ROOT_PASSWORD_FILE", "MYSQL_ALLOW_EMPTY_PASSWORD", "MYSQL_RANDOM_ROOT_PASSWORD"},
		severity:      "high", cwe: "306",
		title:  "MySQL started without root password",
		detail: "Set MYSQL_ROOT_PASSWORD (or MYSQL_ROOT_PASSWORD_FILE) to require authentication.",
	},
	{
		matchImage: "mysql", forbidEnvPair: [2]string{"MYSQL_ALLOW_EMPTY_PASSWORD", "true"},
		severity: "critical", cwe: "306",
		title:  "MySQL MYSQL_ALLOW_EMPTY_PASSWORD=true",
		detail: "MYSQL_ALLOW_EMPTY_PASSWORD=true disables password authentication entirely.",
	},
	{
		matchImage:    "redis",
		requireAnyEnv: []string{"REDIS_PASSWORD", "REQUIREPASS"},
		severity:      "medium", cwe: "306",
		title:  "Redis started without a password",
		detail: "Set REQUIREPASS or pass --requirepass in command args to enable authentication.",
	},
	{
		matchImage:    "minio/minio",
		requireAnyEnv: []string{"MINIO_ROOT_PASSWORD", "MINIO_SECRET_KEY"},
		severity:      "high", cwe: "306",
		title:  "MinIO started without root password",
		detail: "Set MINIO_ROOT_PASSWORD and MINIO_ROOT_USER to enable authentication.",
	},
	{
		matchImage: "minio/minio", forbidEnvPair: [2]string{"MINIO_ROOT_USER", "minioadmin"},
		severity: "high", cwe: "798",
		title:  "MinIO using default minioadmin credentials",
		detail: "Change MINIO_ROOT_USER and MINIO_ROOT_PASSWORD from the default 'minioadmin/minioadmin'.",
	},
}

// rulesHaveTrueWildcard reports whether a ClusterRole has a "true" wildcard:
// verbs contains "*" AND (resources or apiGroups contains "*"). A scoped
// wildcard (verbs:["*"] on a specific CRD apiGroup) is benign/informational
// and should not be counted as a security finding.
func rulesHaveTrueWildcard(item map[string]any) bool {
	for _, r := range listField(item, "rules") {
		rm, _ := r.(map[string]any)
		verbsStar := false
		for _, v := range listField(rm, "verbs") {
			if s, _ := v.(string); s == "*" {
				verbsStar = true
				break
			}
		}
		if !verbsStar {
			continue
		}
		for _, v := range listField(rm, "resources") {
			if s, _ := v.(string); s == "*" {
				return true
			}
		}
		for _, v := range listField(rm, "apiGroups") {
			if s, _ := v.(string); s == "*" {
				return true
			}
		}
	}
	return false
}

// rulesHaveWildcard reports whether any Role rule uses a "*" verb or resource.
// Used for namespace-scoped Roles where any wildcard is flagged (they have
// narrower scope than ClusterRoles so the threshold is lower).
func rulesHaveWildcard(item map[string]any) bool {
	for _, r := range listField(item, "rules") {
		rm, _ := r.(map[string]any)
		for _, v := range listField(rm, "verbs") {
			if s, _ := v.(string); s == "*" {
				return true
			}
		}
		for _, v := range listField(rm, "resources") {
			if s, _ := v.(string); s == "*" {
				return true
			}
		}
	}
	return false
}

// addOperatorResource tallies one operator CRD instance into stats.Operators,
// grouping by kind, and best-effort-reads a health signal for kinds we know
// how to interpret (currently just Prometheus's status.availableReplicas).
func addOperatorResource(stats *K8sClusterStats, kind string, item map[string]any) {
	var i int
	for i = range stats.Operators {
		if stats.Operators[i].Kind == kind {
			break
		}
	}
	if i == len(stats.Operators) {
		stats.Operators = append(stats.Operators, K8sOperatorResource{Kind: kind})
	}
	stats.Operators[i].Count++

	if kind == "Prometheus" {
		if s, ok := strField(mapField(item, "status"), "availableReplicas"); ok {
			if n, err := strconv.Atoi(s); err == nil {
				stats.Operators[i].AvailableReplicas += n
				stats.Operators[i].HasAvailableReplicas = true
			}
		}
	}
}

// k8sTimeoutAnnotations are the common ingress-controller annotation keys
// that set a proxy timeout — there's no standard Ingress spec field for
// this, so it's best-effort-read from whichever of these is present.
var k8sTimeoutAnnotations = []string{
	"nginx.ingress.kubernetes.io/proxy-read-timeout",
	"nginx.ingress.kubernetes.io/proxy-send-timeout",
	"nginx.ingress.kubernetes.io/proxy-connect-timeout",
	"haproxy.org/timeout-server",
	"haproxy.org/timeout-client",
	"traefik.ingress.kubernetes.io/router.timeout",
}

// ingressTimeouts best-effort-reads proxy timeouts from whichever known
// ingress-controller annotations are present, e.g. {"proxy-read-timeout", "60s"}.
func ingressTimeouts(item map[string]any) []K8sIngressTimeout {
	ann := mapField(mapField(item, "metadata"), "annotations")
	if ann == nil {
		return nil
	}
	var out []K8sIngressTimeout
	for _, key := range k8sTimeoutAnnotations {
		v, ok := strField(ann, key)
		if !ok || v == "" {
			continue
		}
		label := key[strings.LastIndex(key, "/")+1:]
		if _, err := strconv.Atoi(v); err == nil {
			v += "s"
		}
		out = append(out, K8sIngressTimeout{Label: label, Value: v})
	}
	return out
}

// ingressBackend renders a path/defaultBackend's target as "service:port",
// supporting both the networking.k8s.io/v1 (backend.service.name/port) and
// legacy extensions/v1beta1 (backend.serviceName/servicePort) shapes.
func ingressBackend(bm map[string]any) string {
	if svc := mapField(bm, "service"); svc != nil {
		name, _ := strField(svc, "name")
		port := mapField(svc, "port")
		num, _ := strField(port, "number")
		pname, _ := strField(port, "name")
		p := num
		if p == "" {
			p = pname
		}
		if name != "" && p != "" {
			return name + ":" + p
		}
		return name
	}
	name, _ := strField(bm, "serviceName")
	port, _ := strField(bm, "servicePort")
	if name != "" && port != "" {
		return name + ":" + port
	}
	return name
}

// ingressRules flattens an Ingress spec's host/path rules (falling back to
// spec.defaultBackend when there are no rules) into a flat display list.
func ingressRules(spec map[string]any) []K8sIngressRule {
	var out []K8sIngressRule
	for _, r := range listField(spec, "rules") {
		rm, _ := r.(map[string]any)
		host, _ := strField(rm, "host")
		paths := listField(mapField(rm, "http"), "paths")
		if len(paths) == 0 {
			out = append(out, K8sIngressRule{Host: host})
			continue
		}
		for _, p := range paths {
			pm, _ := p.(map[string]any)
			path, _ := strField(pm, "path")
			out = append(out, K8sIngressRule{Host: host, Path: path, Backend: ingressBackend(mapField(pm, "backend"))})
		}
	}
	if len(out) == 0 {
		if db := mapField(spec, "defaultBackend"); db != nil {
			out = append(out, K8sIngressRule{Backend: ingressBackend(db)})
		}
	}
	return out
}

// ingressTLSSecrets collects the distinct TLS secretNames referenced by an
// Ingress's spec.tls entries.
func ingressTLSSecrets(spec map[string]any) []string {
	var out []string
	for _, t := range listField(spec, "tls") {
		tm, _ := t.(map[string]any)
		if s, ok := strField(tm, "secretName"); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// statsFromItem folds one non-workload manifest object into the running
// K8sClusterStats totals shown by the informational sub-cards after the
// workload grid.
func statsFromItem(kind string, item map[string]any, stats *K8sClusterStats) {
	meta := mapField(item, "metadata")
	name, _ := strField(meta, "name")
	ns, _ := strField(meta, "namespace")
	spec := mapField(item, "spec")

	switch kind {
	case "Service":
		stats.Services++
		svcType, _ := strField(spec, "type")
		if svcType == "" {
			svcType = "ClusterIP"
		}
		var ports []K8sServicePort
		for _, p := range listField(spec, "ports") {
			pm, _ := p.(map[string]any)
			port, _ := strField(pm, "port")
			if n, err := strconv.Atoi(port); err == nil && n > 0 && n < 1024 {
				stats.ServicesPrivPorts++
			}
			pname, _ := strField(pm, "name")
			targetPort, _ := strField(pm, "targetPort")
			proto, _ := strField(pm, "protocol")
			if proto == "" {
				proto = "TCP"
			}
			ports = append(ports, K8sServicePort{Name: pname, Port: port, TargetPort: targetPort, Protocol: proto})
		}
		stats.ServiceDetails = append(stats.ServiceDetails, K8sServiceDetail{Name: name, Namespace: ns, Type: svcType, Ports: ports})
	case "Ingress":
		stats.Ingresses++
		hasTLS := len(listField(spec, "tls")) > 0
		if hasTLS {
			stats.IngressesTLS++
		}
		class, _ := strField(spec, "ingressClassName")
		stats.IngressDetails = append(stats.IngressDetails, K8sIngressDetail{
			Name: name, Namespace: ns, IngressClass: class,
			Rules: ingressRules(spec), TLS: hasTLS, TLSSecrets: ingressTLSSecrets(spec),
			Timeouts: ingressTimeouts(item),
		})
	case "NetworkPolicy":
		stats.NetworkPolicies++
	case "ConfigMap":
		if name != "kube-root-ca.crt" && !k8sSystemNamespaces[ns] {
			stats.ConfigMaps++
		}
	case "PersistentVolumeClaim":
		stats.PVCs++
		if sc, ok := strField(spec, "storageClassName"); ok && sc != "" {
			stats.PVCsWithStorageClass++
		}
	case "StorageClass":
		stats.StorageClasses++
	case "ServiceAccount":
		if name != "" && name != "default" {
			stats.ServiceAccounts++
		}
	case "Role":
		stats.Roles++
		if rulesHaveWildcard(item) {
			stats.RolesWildcard++
		}
	case "ClusterRole":
		stats.ClusterRoles++
		if rulesHaveTrueWildcard(item) {
			stats.ClusterRolesWildcard++
		}
	case "RoleBinding":
		stats.RoleBindings++
	case "ClusterRoleBinding":
		stats.ClusterRoleBindings++
		roleRef := mapField(item, "roleRef")
		if roleName, _ := strField(roleRef, "name"); roleName == "cluster-admin" {
			for _, subj := range listField(item, "subjects") {
				sm, _ := subj.(map[string]any)
				subjKind, _ := strField(sm, "kind")
				subjName, _ := strField(sm, "name")
				if subjKind == "ServiceAccount" && !k8sPlatformSANames[subjName] {
					stats.ClusterAdminBindings++
				}
			}
		}
	case "HorizontalPodAutoscaler":
		stats.HPAs++
	case "PodDisruptionBudget":
		stats.PDBs++
	default:
		if k8sOperatorKinds[kind] {
			addOperatorResource(stats, kind, item)
		}
	}
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

// ── resource graph + cross-cutting checks ────────────────────────────────

// buildK8sGraph does a single pass over all parsed items to build the
// correlation index needed by the cross-cutting checks (C1/C2/C3).
func buildK8sGraph(items []k8sRawItem) *k8sGraph {
	g := &k8sGraph{
		nsTier:          make(map[string]K8sNamespaceTier),
		nsNPCount:       make(map[string]int),
		nsDefaultDeny:   make(map[string]bool),
		nsHasLB:         make(map[string]bool),
		nsHasIngress:    make(map[string]bool),
		nsHasStateful:   make(map[string]bool),
		nsHasDatastore:  make(map[string]bool),
		nsWorkloadNames: make(map[string][]string),
		hpaTargets:      make(map[string]bool),
		pdbNamespaces:   make(map[string]bool),
	}
	allNS := make(map[string]bool)

	for _, raw := range items {
		meta := mapField(raw.Item, "metadata")
		name, _ := strField(meta, "name")
		ns, _ := strField(meta, "namespace")
		if ns == "" {
			ns = "default"
		}
		allNS[ns] = true
		spec := mapField(raw.Item, "spec")

		switch raw.Kind {
		case "NetworkPolicy":
			g.nsNPCount[ns]++
			podSel := mapField(spec, "podSelector")
			if podSel != nil {
				hasLabels := len(mapField(podSel, "matchLabels")) > 0
				hasExprs := len(listField(podSel, "matchExpressions")) > 0
				if !hasLabels && !hasExprs {
					g.nsDefaultDeny[ns] = true
				}
			}

		case "Service":
			svcType, _ := strField(spec, "type")
			if svcType == "LoadBalancer" || svcType == "NodePort" {
				g.nsHasLB[ns] = true
			}
			if svcType == "LoadBalancer" {
				srcRanges := listField(spec, "loadBalancerSourceRanges")
				ann := mapField(meta, "annotations")
				isInternal := false
				for k := range ann {
					if strings.Contains(strings.ToLower(k), "internal") {
						isInternal = true
					}
				}
				if !isInternal && len(srcRanges) == 0 {
					var ports []string
					for _, p := range listField(spec, "ports") {
						pm, _ := p.(map[string]any)
						port, _ := strField(pm, "port")
						if port != "" {
							ports = append(ports, port)
						}
					}
					sev := "high"
					detail := "Service '" + name + "' in namespace '" + ns + "' is a LoadBalancer with no loadBalancerSourceRanges — anyone on the internet can reach this endpoint."
					if k8sPortsAreDatastore(ports) {
						sev = "critical"
						detail += " The exposed ports match known datastore services — a data breach is possible."
					}
					g.lbFindings = append(g.lbFindings, K8sClusterFinding{
						RuleID:    "k8s.unrestricted_lb",
						Namespace: ns, Kind: "Service", Name: name,
						Severity: sev, CWE: "749", File: raw.File, Line: raw.StartLine,
						Title:  "LoadBalancer without source IP restriction",
						Detail: detail,
					})
				}
			}

		case "Ingress":
			g.nsHasIngress[ns] = true
			if len(listField(spec, "tls")) == 0 {
				g.ingressFindings = append(g.ingressFindings, K8sClusterFinding{
					RuleID:    "k8s.ingress_no_tls",
					Namespace: ns, Kind: "Ingress", Name: name,
					Severity: "medium", CWE: "319", File: raw.File, Line: raw.StartLine,
					Title:  "Ingress without TLS termination",
					Detail: "Ingress '" + name + "' in namespace '" + ns + "' has no spec.tls entry — traffic between client and cluster is unencrypted.",
				})
			}

		case "StatefulSet":
			g.nsHasStateful[ns] = true

		case "HorizontalPodAutoscaler":
			target := mapField(spec, "scaleTargetRef")
			if tname, _ := strField(target, "name"); tname != "" {
				g.hpaTargets[ns+"/"+tname] = true
			}

		case "PodDisruptionBudget":
			g.pdbNamespaces[ns] = true

		case "ClusterRoleBinding":
			roleRef := mapField(raw.Item, "roleRef")
			roleName, _ := strField(roleRef, "name")
			if roleName == "cluster-admin" {
				for _, subj := range listField(raw.Item, "subjects") {
					sm, _ := subj.(map[string]any)
					subjKind, _ := strField(sm, "kind")
					subjName, _ := strField(sm, "name")
					subjNS, _ := strField(sm, "namespace")
					if subjKind == "ServiceAccount" && !k8sPlatformSANames[subjName] {
						g.rbacFindings = append(g.rbacFindings, K8sClusterFinding{
							RuleID:    "k8s.cluster_admin_custom_sa",
							Namespace: subjNS, Kind: "ClusterRoleBinding", Name: name,
							Severity: "critical", CWE: "269", File: raw.File, Line: raw.StartLine,
							Title:  "Custom ServiceAccount bound to cluster-admin",
							Detail: "ClusterRoleBinding '" + name + "' grants cluster-admin to ServiceAccount '" + subjName + "' — full read/write access to all cluster resources.",
						})
					}
				}
			}

		case "ConfigMap":
			if name == "kube-root-ca.crt" || k8sSystemNamespaces[ns] {
				break
			}
			data := mapField(raw.Item, "data")
			for k, v := range data {
				val, _ := v.(string)
				// Only flag non-empty literal values (not templated references like $(VAR) or ${VAR})
				if k8sEnvSecretKeyRe.MatchString(k) && val != "" &&
					!strings.ContainsAny(val, "$(") && !strings.Contains(val, "${") {
					g.secretFindings = append(g.secretFindings, K8sClusterFinding{
						RuleID:    "k8s.secret_in_configmap",
						Namespace: ns, Kind: "ConfigMap", Name: name,
						Severity: "high", CWE: "312", File: raw.File, Line: raw.StartLine,
						Title:  "Sensitive key in ConfigMap: " + k,
						Detail: "ConfigMap '" + name + "' key '" + k + "' matches a credential pattern. ConfigMaps are unencrypted — use a Secret with encryption-at-rest or an external secret manager.",
					})
				}
			}
		}

		// Workload-level graph data: datastore images, env secrets, app hardening.
		if k8sTargetKinds[raw.Kind] {
			g.nsWorkloadNames[ns] = append(g.nsWorkloadNames[ns], name)
			podSpec := k8sGetPodSpec(raw.Kind, raw.Item)
			for _, cv := range listField(podSpec, "containers") {
				cm, _ := cv.(map[string]any)
				image, _ := strField(cm, "image")
				if isDatastoreImage(image) {
					g.nsHasDatastore[ns] = true
				}
				for _, f := range checkAppHardening(ns, name, cm) {
					f.File = raw.File
					f.Line = raw.StartLine
					g.hardenFindings = append(g.hardenFindings, f)
				}
				for _, f := range checkEnvSecrets(ns, raw.Kind, name, cm) {
					f.File = raw.File
					f.Line = raw.StartLine
					g.secretFindings = append(g.secretFindings, f)
				}
			}
		}
	}

	// Escalate LB findings for datastore namespaces (image-based signal may
	// arrive after the Service was scanned, so apply after the full pass).
	for i := range g.lbFindings {
		f := &g.lbFindings[i]
		if f.Severity != "critical" && g.nsHasDatastore[f.Namespace] {
			f.Severity = "critical"
			f.Detail += " This namespace hosts datastore workloads — a data breach is possible."
		}
	}

	// Classify namespace tiers.
	for ns := range allNS {
		g.nsTier[ns] = classifyNSTier(ns, g)
	}

	// Stamp tier onto all pre-collected findings.
	for i := range g.lbFindings {
		g.lbFindings[i].Tier = g.nsTier[g.lbFindings[i].Namespace]
	}
	for i := range g.ingressFindings {
		g.ingressFindings[i].Tier = g.nsTier[g.ingressFindings[i].Namespace]
	}
	for i := range g.rbacFindings {
		if g.rbacFindings[i].Namespace != "" {
			g.rbacFindings[i].Tier = g.nsTier[g.rbacFindings[i].Namespace]
		}
	}
	for i := range g.secretFindings {
		g.secretFindings[i].Tier = g.nsTier[g.secretFindings[i].Namespace]
	}
	for i := range g.hardenFindings {
		g.hardenFindings[i].Tier = g.nsTier[g.hardenFindings[i].Namespace]
	}

	return g
}

// classifyNSTier assigns a risk tier to a namespace based on the graph signals
// collected during buildK8sGraph.
func classifyNSTier(ns string, g *k8sGraph) K8sNamespaceTier {
	if k8sSystemNamespaces[ns] {
		return K8sTierSystem
	}
	for _, pfx := range k8sTierSystemPrefixes {
		if strings.HasPrefix(ns, pfx) || ns == strings.TrimSuffix(pfx, "-") {
			return K8sTierSystem
		}
	}
	if g.nsHasStateful[ns] || g.nsHasDatastore[ns] {
		return K8sTierStateful
	}
	if g.nsHasLB[ns] || g.nsHasIngress[ns] {
		return K8sTierInternetFacing
	}
	lns := strings.ToLower(ns)
	if strings.HasPrefix(lns, "prod") || strings.HasSuffix(lns, "-prod") ||
		strings.HasSuffix(lns, "-production") || strings.Contains(lns, "-prod-") {
		return K8sTierProduction
	}
	return K8sTierProduction // default non-system to production (conservative)
}

// runCrossChecks uses the completed graph to produce the final list of
// ClusterFindings, adding NetworkPolicy gap findings and merging the rest.
func runCrossChecks(g *k8sGraph) []K8sClusterFinding {
	var findings []K8sClusterFinding

	// C3: NetworkPolicy gap — namespace has workloads but no default-deny NP.
	for ns, workloadNames := range g.nsWorkloadNames {
		if g.nsTier[ns] == K8sTierSystem {
			continue
		}
		if len(workloadNames) == 0 || g.nsDefaultDeny[ns] {
			continue
		}
		sev := "medium"
		if g.nsTier[ns] == K8sTierInternetFacing || g.nsTier[ns] == K8sTierStateful {
			sev = "high"
		}
		findings = append(findings, K8sClusterFinding{
			RuleID:    "k8s.np_gap",
			Namespace: ns, Kind: "Namespace",
			Tier:     g.nsTier[ns],
			Severity: sev, CWE: "284",
			Title:  "Namespace lacks a default-deny NetworkPolicy",
			Detail: "Namespace '" + ns + "' has " + strconv.Itoa(len(workloadNames)) + " workload(s) but no NetworkPolicy with an empty podSelector — all pod-to-pod traffic is implicitly allowed.",
		})
	}

	findings = append(findings, g.rbacFindings...)
	findings = append(findings, g.lbFindings...)
	findings = append(findings, g.secretFindings...)
	findings = append(findings, g.hardenFindings...)
	findings = append(findings, g.ingressFindings...)

	sort.Slice(findings, func(i, j int) bool {
		ri, rj := k8sSeverityRank(findings[i].Severity), k8sSeverityRank(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if findings[i].Namespace != findings[j].Namespace {
			return findings[i].Namespace < findings[j].Namespace
		}
		return findings[i].Title < findings[j].Title
	})
	return findings
}

func k8sSeverityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// k8sGetPodSpec extracts the pod spec map from a workload item.
func k8sGetPodSpec(kind string, item map[string]any) map[string]any {
	spec := mapField(item, "spec")
	switch kind {
	case "Pod":
		return spec
	case "Deployment", "StatefulSet", "DaemonSet", "Job":
		return getMapPath(spec, "template", "spec")
	case "CronJob":
		return getMapPath(spec, "jobTemplate", "spec", "template", "spec")
	}
	return nil
}

// isDatastoreImage returns true if the image name contains a known datastore substring.
func isDatastoreImage(image string) bool {
	low := strings.ToLower(image)
	for _, ds := range k8sDatastoreImages {
		if strings.Contains(low, ds) {
			return true
		}
	}
	return false
}

// k8sPortsAreDatastore returns true if any of the given port strings matches a
// well-known datastore port.
func k8sPortsAreDatastore(ports []string) bool {
	for _, p := range ports {
		if k8sDatastorePorts[p] {
			return true
		}
	}
	return false
}

// checkEnvSecrets scans a container's env list for literal values assigned to
// credential-named variables. Values are NEVER included in the output.
func checkEnvSecrets(ns, kind, workloadName string, c map[string]any) []K8sClusterFinding {
	cname, _ := strField(c, "name")
	var findings []K8sClusterFinding
	for _, ev := range listField(c, "env") {
		em, _ := ev.(map[string]any)
		ename, _ := strField(em, "name")
		evalue, _ := strField(em, "value")
		_, hasValueFrom := em["valueFrom"]
		if ename != "" && evalue != "" && !hasValueFrom && k8sEnvSecretKeyRe.MatchString(ename) {
			findings = append(findings, K8sClusterFinding{
				RuleID:    "k8s.secret_in_env",
				Namespace: ns, Kind: kind, Name: workloadName + "/" + cname,
				Severity: "critical", CWE: "312",
				Title:  "Secret literal in env: " + ename,
				Detail: "Container '" + cname + "' sets env var '" + ename + "' with a hardcoded literal value. Use secretKeyRef to reference a Kubernetes Secret — never store credentials in manifests.",
			})
		}
	}
	return findings
}

// checkAppHardening checks a container against the app hardening catalog.
// Values from forbidEnvPair comparisons are never included in findings.
func checkAppHardening(ns, workloadName string, c map[string]any) []K8sClusterFinding {
	image, _ := strField(c, "image")
	if image == "" {
		return nil
	}
	lowImage := strings.ToLower(image)
	cname, _ := strField(c, "name")

	envMap := map[string]string{}
	for _, ev := range listField(c, "env") {
		em, _ := ev.(map[string]any)
		k, _ := strField(em, "name")
		v, _ := strField(em, "value")
		if k != "" {
			envMap[k] = v
		}
	}

	var findings []K8sClusterFinding
	for _, entry := range k8sHardeningCatalog {
		if !strings.Contains(lowImage, strings.ToLower(entry.matchImage)) {
			continue
		}
		if len(entry.requireAnyEnv) > 0 {
			found := false
			for _, req := range entry.requireAnyEnv {
				if _, ok := envMap[req]; ok {
					found = true
					break
				}
			}
			if !found {
				findings = append(findings, K8sClusterFinding{
					RuleID:    "k8s.app_hardening",
					Namespace: ns, Kind: "Workload", Name: workloadName + "/" + cname,
					Severity: entry.severity, CWE: entry.cwe,
					Title: entry.title, Detail: entry.detail,
				})
			}
		}
		if entry.forbidEnvPair[0] != "" {
			if v, ok := envMap[entry.forbidEnvPair[0]]; ok && v == entry.forbidEnvPair[1] {
				findings = append(findings, K8sClusterFinding{
					RuleID:    "k8s.app_hardening",
					Namespace: ns, Kind: "Workload", Name: workloadName + "/" + cname,
					Severity: entry.severity, CWE: entry.cwe,
					Title: entry.title, Detail: entry.detail,
				})
			}
		}
	}
	return findings
}
