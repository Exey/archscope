package scanner

// devopslint.go implements a dependency-free static analysis of DevOps
// artefacts (Dockerfiles, docker-compose files, Helm charts) in the spirit of
// Hadolint / Dockle / KubeLinter / Checkov. Checks are line-based heuristics —
// good enough for a report card, not a replacement for the real tools.
//
// Statuses: "pass" (good), "warn" (attention), "fail" (bad), "na" (cannot be
// evaluated statically/offline, e.g. registry CVE counts).

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// DevOpsCheck is one evaluated metric row.
type DevOpsCheck struct {
	Category string // e.g. "Base Image Hygiene"
	Metric   string // e.g. "Pinned digest (FROM @sha256)"
	Status   string // pass | warn | fail | na
	Value    string // short value shown next to the metric, e.g. "2/3", "yes"
}

// DevOpsArtifactLint groups checks for one artefact kind.
type DevOpsArtifactLint struct {
	Kind   string   // "Dockerfile", "Docker Compose", "Helm Chart"
	Icon   string   // emoji for the column header
	Files  []string // repo-relative paths analyzed
	Checks []DevOpsCheck
}

// DevOpsLint is the full DevOps static-analysis result.
type DevOpsLint struct {
	Dockerfiles *DevOpsArtifactLint // nil when no Dockerfiles found
	Compose     *DevOpsArtifactLint // nil when no compose files found
	Helm        *DevOpsArtifactLint // nil when no Chart.yaml found
}

// Empty reports whether no artefacts were found at all.
func (l *DevOpsLint) Empty() bool {
	return l == nil || (l.Dockerfiles == nil && l.Compose == nil && l.Helm == nil)
}

// Score returns a 0–100 hygiene score across all evaluated checks
// (pass=1, warn=0.5, fail=0; "na" rows are excluded). ok=false when nothing
// was evaluable.
func (l *DevOpsLint) Score() (int, bool) {
	if l.Empty() {
		return 0, false
	}
	var pts float64
	var n int
	for _, a := range []*DevOpsArtifactLint{l.Dockerfiles, l.Compose, l.Helm} {
		if a == nil {
			continue
		}
		for _, c := range a.Checks {
			switch c.Status {
			case "pass":
				pts, n = pts+1, n+1
			case "warn":
				pts, n = pts+0.5, n+1
			case "fail":
				n++
			}
		}
	}
	if n == 0 {
		return 0, false
	}
	return int(pts/float64(n)*100 + 0.5), true
}

const devopsLintMaxFileSize = 512 * 1024 // skip pathological files
const devopsLintMaxDepth = 4

// ScanDevOpsLint walks rootPath (up to devopsLintMaxDepth levels) collecting
// Dockerfiles, docker-compose files, and Helm chart directories, then runs the
// static checks against them.
func ScanDevOpsLint(rootPath string) *DevOpsLint {
	var dockerfiles, composeFiles, chartDirs []string

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
				if depth < devopsLintMaxDepth && !strings.HasPrefix(name, ".") &&
					low != "node_modules" && low != "vendor" {
					walk(full, depth+1)
				}
				continue
			}
			switch {
			case low == "dockerfile" || low == "containerfile" ||
				strings.HasPrefix(low, "dockerfile.") || strings.HasSuffix(low, ".dockerfile"):
				dockerfiles = append(dockerfiles, full)
			case strings.HasPrefix(low, "docker-compose") &&
				(strings.HasSuffix(low, ".yml") || strings.HasSuffix(low, ".yaml")):
				composeFiles = append(composeFiles, full)
			case low == "compose.yml" || low == "compose.yaml":
				composeFiles = append(composeFiles, full)
			case low == "chart.yaml" || low == "chart.yml":
				chartDirs = append(chartDirs, dir)
			}
		}
	}
	walk(rootPath, 0)
	sort.Strings(dockerfiles)
	sort.Strings(composeFiles)
	sort.Strings(chartDirs)

	lint := &DevOpsLint{}
	if len(dockerfiles) > 0 {
		lint.Dockerfiles = lintDockerfiles(rootPath, dockerfiles)
	}
	if len(composeFiles) > 0 {
		lint.Compose = lintCompose(rootPath, composeFiles)
	}
	if len(chartDirs) > 0 {
		lint.Helm = lintHelm(rootPath, chartDirs)
	}
	if lint.Empty() {
		return nil
	}
	return lint
}

// ── helpers ─────────────────────────────────────────────────────────────────

func readSmall(path string) []string {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > devopsLintMaxFileSize {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(string(data), "\n")
}

func relPaths(root string, paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if r, err := filepath.Rel(root, p); err == nil {
			out = append(out, r)
		} else {
			out = append(out, p)
		}
	}
	return out
}

func boolStatus(good bool) string {
	if good {
		return "pass"
	}
	return "warn"
}

func ratio(n, total int) string { return strconv.Itoa(n) + "/" + strconv.Itoa(total) }

var secretKeyRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)\s*[=:]\s*\S+`)
var secretPlaceholderRe = regexp.MustCompile(`(?i)[=:]\s*("?\$\{?|''|""|<|\{\{)`) // env refs / templates / placeholders

func looksLikeHardcodedSecret(line string) bool {
	return secretKeyRe.MatchString(line) && !secretPlaceholderRe.MatchString(line)
}

// ── Dockerfile ──────────────────────────────────────────────────────────────

var (
	curlPipeShRe = regexp.MustCompile(`(?i)\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da|a)?sh\b`)
	chmod777Re   = regexp.MustCompile(`chmod\s+(-\w+\s+)*(0?777|a\+rwx)`)
	userRootRe   = regexp.MustCompile(`(?i)^user\s+(root|0)\b`)
	numericUIDRe = regexp.MustCompile(`(?i)^user\s+\d+`)
)

func lintDockerfiles(root string, paths []string) *DevOpsArtifactLint {
	total := len(paths)
	var (
		fromTotal, fromDigest, fromFloating int
		baseImages                          = map[string]bool{}
		runCount, maxRunPerFile             int
		addCount                            int
		healthFiles, userFiles, uidFiles    int
		secretLines, chmodBad               int
		copyCount, copyChown                int
		workdirAbsFiles, workdirFiles       int
		lowPorts                            int
		multiStageFiles                     int
		layerCount                          int
		aptInstall, aptNoRec                int
		apkAdd, apkNoCache                  int
		curlPipe                            int
		labelFiles                          int
	)

	for _, p := range paths {
		lines := readSmall(p)
		fromsInFile, runsInFile := 0, 0
		hasHealth, hasUser, hasUID, hasLabel, hasWorkdir, hasWorkdirAbs := false, false, false, false, false, false
		for _, raw := range lines {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			up := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(up, "FROM "):
				fromsInFile++
				fromTotal++
				img := strings.Fields(line)[1]
				if strings.Contains(img, "@sha256:") {
					fromDigest++
				} else if strings.HasSuffix(img, ":latest") || !strings.Contains(img, ":") {
					// scratch and stage refs (FROM builder) are fine
					lowImg := strings.ToLower(img)
					if lowImg != "scratch" && !isStageRef(lines, img) {
						fromFloating++
					}
				}
				base := strings.ToLower(strings.SplitN(strings.SplitN(img, ":", 2)[0], "@", 2)[0])
				if base != "" && base != "scratch" {
					baseImages[filepath.Base(base)] = true
				}
			case strings.HasPrefix(up, "RUN "):
				runsInFile++
				runCount++
				layerCount++
				if chmod777Re.MatchString(line) {
					chmodBad++
				}
				if curlPipeShRe.MatchString(line) {
					curlPipe++
				}
				if strings.Contains(line, "apt-get install") || strings.Contains(line, "apt install") {
					aptInstall++
					if strings.Contains(line, "--no-install-recommends") {
						aptNoRec++
					}
				}
				if strings.Contains(line, "apk add") {
					apkAdd++
					if strings.Contains(line, "--no-cache") {
						apkNoCache++
					}
				}
			case strings.HasPrefix(up, "ADD "):
				addCount++
				layerCount++
			case strings.HasPrefix(up, "COPY "):
				copyCount++
				layerCount++
				if strings.Contains(line, "--chown=") {
					copyChown++
				}
			case strings.HasPrefix(up, "HEALTHCHECK"):
				hasHealth = true
			case strings.HasPrefix(up, "LABEL"):
				hasLabel = true
			case strings.HasPrefix(up, "USER "):
				if !userRootRe.MatchString(line) {
					hasUser = true
					if numericUIDRe.MatchString(line) {
						hasUID = true
					}
				}
			case strings.HasPrefix(up, "WORKDIR "):
				hasWorkdir = true
				if strings.HasPrefix(strings.Fields(line)[1], "/") {
					hasWorkdirAbs = true
				}
			case strings.HasPrefix(up, "EXPOSE "):
				for _, f := range strings.Fields(line)[1:] {
					port := strings.SplitN(f, "/", 2)[0]
					if n, err := strconv.Atoi(port); err == nil && n < 1024 {
						lowPorts++
					}
				}
			}
			if strings.HasPrefix(up, "ENV ") || strings.HasPrefix(up, "ARG ") {
				if looksLikeHardcodedSecret(line) {
					secretLines++
				}
			}
		}
		if runsInFile > maxRunPerFile {
			maxRunPerFile = runsInFile
		}
		if fromsInFile >= 2 {
			multiStageFiles++
		}
		if hasHealth {
			healthFiles++
		}
		if hasUser {
			userFiles++
		}
		if hasUID {
			uidFiles++
		}
		if hasLabel {
			labelFiles++
		}
		if hasWorkdir {
			workdirFiles++
			if hasWorkdirAbs {
				workdirAbsFiles++
			}
		}
	}

	baseList := make([]string, 0, len(baseImages))
	for b := range baseImages {
		baseList = append(baseList, b)
	}
	sort.Strings(baseList)
	baseVal := strings.Join(baseList, ", ")
	if baseVal == "" {
		baseVal = "—"
	}

	var checks []DevOpsCheck
	add := func(cat, metric, status, value string) {
		checks = append(checks, DevOpsCheck{cat, metric, status, value})
	}

	// Base Image Hygiene
	pinStatus := "pass"
	if fromFloating > 0 {
		pinStatus = "fail"
	} else if fromDigest < fromTotal {
		pinStatus = "warn" // tagged but not digest-pinned
	}
	add("Base Image Hygiene", "Pinned digest (no :latest)", pinStatus, ratio(fromDigest, fromTotal)+" @sha256")
	add("Base Image Hygiene", "Base image distro", "na", baseVal)
	add("Base Image Hygiene", "Base image CVE count", "na", "registry scan")
	add("Base Image Hygiene", "Base image age", "na", "registry scan")

	// Build Best Practices
	runStatus := "pass"
	if maxRunPerFile > 8 {
		runStatus = "warn"
	}
	add("Build Best Practices", "RUN instructions", runStatus, strconv.Itoa(runCount)+" (max "+strconv.Itoa(maxRunPerFile)+"/file)")
	addStatus := "pass"
	if addCount > 0 {
		addStatus = "fail"
	}
	add("Build Best Practices", "ADD instead of COPY", addStatus, strconv.Itoa(addCount))
	add("Build Best Practices", "HEALTHCHECK present", boolStatus(healthFiles == total), ratio(healthFiles, total))
	secStatus := "pass"
	if secretLines > 0 {
		secStatus = "fail"
	}
	add("Build Best Practices", "Secrets in ARG/ENV", secStatus, strconv.Itoa(secretLines))

	// Privilege & Isolation
	userStatus := "fail"
	if userFiles == total {
		userStatus = "pass"
	} else if userFiles > 0 {
		userStatus = "warn"
	}
	add("Privilege & Isolation", "Non-root USER", userStatus, ratio(userFiles, total))
	add("Privilege & Isolation", "Numeric UID", boolStatus(uidFiles == total), ratio(uidFiles, total))

	// File System & Permissions
	chmodStatus := "pass"
	if chmodBad > 0 {
		chmodStatus = "fail"
	}
	add("File System & Permissions", "chmod 777 / world-writable", chmodStatus, strconv.Itoa(chmodBad))
	chownStatus := "pass"
	if copyCount > 0 && copyChown == 0 {
		chownStatus = "warn"
	}
	add("File System & Permissions", "COPY --chown set", chownStatus, ratio(copyChown, copyCount))
	add("File System & Permissions", "Absolute WORKDIR", boolStatus(workdirFiles > 0 && workdirAbsFiles == workdirFiles), ratio(workdirAbsFiles, total))

	// Network & Port Exposure
	portStatus := "pass"
	if lowPorts > 0 {
		portStatus = "warn"
	}
	add("Network & Port Exposure", "Privileged ports (<1024)", portStatus, strconv.Itoa(lowPorts))

	// Image Size & Efficiency
	add("Image Size & Efficiency", "Multi-stage build", boolStatus(multiStageFiles > 0), ratio(multiStageFiles, total))
	layerStatus := "pass"
	if layerCount > 20*total {
		layerStatus = "warn"
	}
	add("Image Size & Efficiency", "Layers (RUN/COPY/ADD)", layerStatus, strconv.Itoa(layerCount))
	add("Image Size & Efficiency", "Estimated image size", "na", "needs build")

	// Package Manager Hygiene
	if aptInstall > 0 {
		add("Package Manager Hygiene", "apt --no-install-recommends", boolStatus(aptNoRec == aptInstall), ratio(aptNoRec, aptInstall))
	} else {
		add("Package Manager Hygiene", "apt --no-install-recommends", "na", "no apt")
	}
	if apkAdd > 0 {
		add("Package Manager Hygiene", "apk --no-cache", boolStatus(apkNoCache == apkAdd), ratio(apkNoCache, apkAdd))
	} else {
		add("Package Manager Hygiene", "apk --no-cache", "na", "no apk")
	}
	curlStatus := "pass"
	if curlPipe > 0 {
		curlStatus = "fail"
	}
	add("Package Manager Hygiene", "curl | sh pipes", curlStatus, strconv.Itoa(curlPipe))

	// Metadata & Labelling
	add("Metadata & Labelling", "OCI LABELs present", boolStatus(labelFiles == total), ratio(labelFiles, total))

	return &DevOpsArtifactLint{Kind: "Dockerfile", Icon: "🐳", Files: relPaths(root, paths), Checks: checks}
}

// isStageRef reports whether img matches a named build stage (FROM x AS name).
func isStageRef(lines []string, img string) bool {
	needle := " as " + strings.ToLower(img)
	for _, l := range lines {
		low := strings.ToLower(strings.TrimSpace(l))
		if strings.HasPrefix(low, "from ") && strings.HasSuffix(low, needle) {
			return true
		}
	}
	return false
}

// ── Docker Compose ──────────────────────────────────────────────────────────

var (
	dangerousCaps  = []string{"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL", "DAC_READ_SEARCH"}
	composeVerRe   = regexp.MustCompile(`(?m)^version:\s*["']?(\d+)`)
	hostPortRe     = regexp.MustCompile(`-\s*["']?(\d{1,5}):(\d{1,5})`)
	explicitBindRe = regexp.MustCompile(`-\s*["']?(0\.0\.0\.0|127\.0\.0\.1|localhost):`)
)

func lintCompose(root string, paths []string) *DevOpsArtifactLint {
	var (
		obsoleteVer, legacyVer          int
		privileged, capBad, sockMounts  int
		secretLines                     int
		filesWithLimits, filesWithPorts int
		restartAlways                   int
		wildBinds                       int
		filesWithNetworks               int
	)
	total := len(paths)

	for _, p := range paths {
		lines := readSmall(p)
		content := strings.Join(lines, "\n")
		if m := composeVerRe.FindStringSubmatch(content); m != nil {
			switch m[1] {
			case "1", "2":
				obsoleteVer++
			default:
				legacyVer++ // version key itself is deprecated by the Compose Spec
			}
		}
		if strings.Contains(content, "limits:") {
			filesWithLimits++
		}
		if regexp.MustCompile(`(?m)^networks:`).MatchString(content) {
			filesWithNetworks++
		}
		inEnv := false
		hasPorts := false
		for _, raw := range lines {
			line := strings.TrimSpace(raw)
			low := strings.ToLower(line)
			switch {
			case strings.HasPrefix(low, "privileged:") && strings.Contains(low, "true"):
				privileged++
			case strings.HasPrefix(low, "restart:") && strings.Contains(low, "always"):
				restartAlways++
			case strings.Contains(line, "/var/run/docker.sock"):
				sockMounts++
			}
			for _, c := range dangerousCaps {
				if strings.Contains(line, c) && (strings.HasPrefix(low, "-") || strings.Contains(low, "cap_add")) {
					capBad++
					break
				}
			}
			if strings.HasPrefix(low, "environment:") {
				inEnv = true
			} else if !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t") && line != "" {
				inEnv = false
			}
			if inEnv && looksLikeHardcodedSecret(line) {
				secretLines++
			}
			if strings.HasPrefix(low, "ports:") {
				hasPorts = true
			}
			if hostPortRe.MatchString(line) && !explicitBindRe.MatchString(line) {
				wildBinds++ // host-published without an explicit interface → 0.0.0.0
			}
		}
		if hasPorts {
			filesWithPorts++
		}
	}

	var checks []DevOpsCheck
	add := func(cat, metric, status, value string) {
		checks = append(checks, DevOpsCheck{cat, metric, status, value})
	}

	verStatus, verVal := "pass", "compose spec"
	if obsoleteVer > 0 {
		verStatus, verVal = "fail", "v1/v2 found"
	} else if legacyVer > 0 {
		verStatus, verVal = "warn", "legacy version key"
	}
	add("Version & Syntax", "Obsolete compose version", verStatus, verVal)

	st := func(n int) string {
		if n > 0 {
			return "fail"
		}
		return "pass"
	}
	add("Security", "privileged: true services", st(privileged), strconv.Itoa(privileged))
	add("Security", "Dangerous cap_add", st(capBad), strconv.Itoa(capBad))
	add("Security", "docker.sock mounted", st(sockMounts), strconv.Itoa(sockMounts))
	add("Security", "Secrets in environment", st(secretLines), strconv.Itoa(secretLines))

	add("Resource Limits", "deploy.resources.limits", boolStatus(filesWithLimits == total), ratio(filesWithLimits, total))
	restartStatus := "pass"
	if restartAlways > 0 {
		restartStatus = "warn" // `always` can mask crash loops; prefer unless-stopped
	}
	add("Resource Limits", "restart: always usage", restartStatus, strconv.Itoa(restartAlways))

	bindStatus := "pass"
	if wildBinds > 0 {
		bindStatus = "warn"
	}
	add("Network Hygiene", "Ports on 0.0.0.0", bindStatus, strconv.Itoa(wildBinds))
	_ = filesWithPorts
	add("Network Hygiene", "Custom networks defined", boolStatus(filesWithNetworks == total), ratio(filesWithNetworks, total))

	return &DevOpsArtifactLint{Kind: "Docker Compose", Icon: "🐙", Files: relPaths(root, paths), Checks: checks}
}

// ── Helm Chart ──────────────────────────────────────────────────────────────

var deprecatedAPIs = []string{
	"extensions/v1beta1", "apps/v1beta1", "apps/v1beta2",
	"rbac.authorization.k8s.io/v1beta1", "networking.k8s.io/v1beta1",
	"policy/v1beta1", "batch/v1beta1",
}

var helmNamespaceRe = regexp.MustCompile(`(?m)^\s*namespace:\s*(\S+)`)

func lintHelm(root string, chartDirs []string) *DevOpsArtifactLint {
	total := len(chartDirs)
	var (
		chartFieldsOK, schemaOK, metaOK            int
		deprecatedHits, hardcodedNS                int
		reqOK, limOK                               int
		nonRootOK, roRootOK, escFalseOK, seccompOK int
		escTrue, privileged, capBad                int
		netpolOK, pdbOK, saOK, provOK              int
		lbCount                                    int
		ingressCharts, ingressTLSOK                int
		emptyDirCharts, emptyDirSized              int
		rbacWildcard                               int
		valuesComments                             int
	)

	for _, dir := range chartDirs {
		// Chart.yaml
		var chartContent string
		for _, n := range []string{"Chart.yaml", "chart.yaml", "Chart.yml"} {
			if lines := readSmall(filepath.Join(dir, n)); lines != nil {
				chartContent = strings.Join(lines, "\n")
				break
			}
		}
		if strings.Contains(chartContent, "apiVersion:") &&
			strings.Contains(chartContent, "name:") && strings.Contains(chartContent, "version:") {
			chartFieldsOK++
		}
		if strings.Contains(chartContent, "maintainers:") && strings.Contains(chartContent, "icon:") {
			metaOK++
		}
		if _, err := os.Stat(filepath.Join(dir, "values.schema.json")); err == nil {
			schemaOK++
		}
		if matches, _ := filepath.Glob(filepath.Join(dir, "*.prov")); len(matches) > 0 {
			provOK++
		} else if matches, _ := filepath.Glob(filepath.Join(filepath.Dir(dir), "*.prov")); len(matches) > 0 {
			provOK++
		}

		// values.yaml comment coverage
		for _, n := range []string{"values.yaml", "values.yml"} {
			for _, l := range readSmall(filepath.Join(dir, n)) {
				if strings.HasPrefix(strings.TrimSpace(l), "#") {
					valuesComments++
				}
			}
		}

		// templates/**.yaml (one level of subdirs is enough for typical charts)
		var tmpl strings.Builder
		globs := []string{
			filepath.Join(dir, "templates", "*.yaml"), filepath.Join(dir, "templates", "*.yml"),
			filepath.Join(dir, "templates", "*.tpl"),
			filepath.Join(dir, "templates", "*", "*.yaml"), filepath.Join(dir, "templates", "*", "*.yml"),
		}
		for _, g := range globs {
			matches, _ := filepath.Glob(g)
			for _, m := range matches {
				tmpl.WriteString(strings.Join(readSmall(m), "\n"))
				tmpl.WriteString("\n")
			}
		}
		t := tmpl.String()

		for _, api := range deprecatedAPIs {
			deprecatedHits += strings.Count(t, api)
		}
		for _, m := range helmNamespaceRe.FindAllStringSubmatch(t, -1) {
			if !strings.Contains(m[1], "{{") {
				hardcodedNS++
			}
		}
		if strings.Contains(t, "requests:") {
			reqOK++
		}
		if strings.Contains(t, "limits:") {
			limOK++
		}
		if strings.Contains(t, "runAsNonRoot: true") {
			nonRootOK++
		}
		if strings.Contains(t, "readOnlyRootFilesystem: true") {
			roRootOK++
		}
		if strings.Contains(t, "allowPrivilegeEscalation: false") {
			escFalseOK++
		}
		escTrue += strings.Count(t, "allowPrivilegeEscalation: true")
		privileged += strings.Count(t, "privileged: true")
		for _, c := range dangerousCaps {
			if c == "ALL" {
				continue // "- ALL" under drop: is good; too ambiguous line-based
			}
			capBad += strings.Count(t, c)
		}
		if strings.Contains(t, "seccompProfile") {
			seccompOK++
		}
		if strings.Contains(t, "kind: NetworkPolicy") {
			netpolOK++
		}
		if strings.Contains(t, "kind: PodDisruptionBudget") {
			pdbOK++
		}
		if strings.Contains(t, "serviceAccountName:") {
			saOK++
		}
		lbCount += strings.Count(t, "type: LoadBalancer")
		if strings.Contains(t, "kind: Ingress") {
			ingressCharts++
			if strings.Contains(t, "tls:") {
				ingressTLSOK++
			}
		}
		if strings.Contains(t, "emptyDir:") {
			emptyDirCharts++
			if strings.Contains(t, "sizeLimit") {
				emptyDirSized++
			}
		}
		if strings.Contains(t, "ClusterRole") &&
			(strings.Contains(t, `"*"`) || strings.Contains(t, "'*'") || regexp.MustCompile(`(?m)-\s*\*\s*$`).MatchString(t)) {
			rbacWildcard++
		}
	}

	var checks []DevOpsCheck
	add := func(cat, metric, status, value string) {
		checks = append(checks, DevOpsCheck{cat, metric, status, value})
	}
	allOf := func(n int) string {
		if n == total {
			return "pass"
		}
		if n > 0 {
			return "warn"
		}
		return "warn"
	}
	noneOf := func(n int) string {
		if n > 0 {
			return "fail"
		}
		return "pass"
	}

	add("Chart Structural Quality", "Chart.yaml required fields", boolStatus(chartFieldsOK == total), ratio(chartFieldsOK, total))
	add("Chart Structural Quality", "values.schema.json", allOf(schemaOK), ratio(schemaOK, total))
	add("Chart Structural Quality", "Maintainers & icon metadata", allOf(metaOK), ratio(metaOK, total))

	add("Template Correctness", "Deprecated K8s API versions", noneOf(deprecatedHits), strconv.Itoa(deprecatedHits))
	add("Template Correctness", "Hardcoded namespace", noneOf(hardcodedNS), strconv.Itoa(hardcodedNS))

	add("Resource Management", "resources.requests defined", allOf(reqOK), ratio(reqOK, total))
	add("Resource Management", "resources.limits defined", allOf(limOK), ratio(limOK, total))

	add("Security Contexts", "runAsNonRoot enforced", allOf(nonRootOK), ratio(nonRootOK, total))
	add("Security Contexts", "readOnlyRootFilesystem", allOf(roRootOK), ratio(roRootOK, total))
	escStatus := "warn"
	if escTrue > 0 {
		escStatus = "fail"
	} else if escFalseOK == total {
		escStatus = "pass"
	}
	add("Security Contexts", "allowPrivilegeEscalation: false", escStatus, ratio(escFalseOK, total))
	add("Security Contexts", "Privileged containers", noneOf(privileged), strconv.Itoa(privileged))
	add("Security Contexts", "Dangerous capabilities added", noneOf(capBad), strconv.Itoa(capBad))
	add("Security Contexts", "seccompProfile set", allOf(seccompOK), ratio(seccompOK, total))

	add("Network Policies & Exposure", "NetworkPolicy defined", allOf(netpolOK), ratio(netpolOK, total))
	lbStatus := "pass"
	if lbCount > 0 {
		lbStatus = "warn"
	}
	add("Network Policies & Exposure", "LoadBalancer services", lbStatus, strconv.Itoa(lbCount))
	if ingressCharts > 0 {
		add("Network Policies & Exposure", "Ingress TLS configured", boolStatus(ingressTLSOK == ingressCharts), ratio(ingressTLSOK, ingressCharts))
	} else {
		add("Network Policies & Exposure", "Ingress TLS configured", "na", "no Ingress")
	}

	add("Pod Disruption Budget", "PodDisruptionBudget defined", allOf(pdbOK), ratio(pdbOK, total))

	if emptyDirCharts > 0 {
		add("Storage & Persistence", "emptyDir sizeLimit", boolStatus(emptyDirSized == emptyDirCharts), ratio(emptyDirSized, emptyDirCharts))
	} else {
		add("Storage & Persistence", "emptyDir sizeLimit", "na", "no emptyDir")
	}

	add("RBAC & Service Accounts", "Dedicated serviceAccountName", allOf(saOK), ratio(saOK, total))
	add("RBAC & Service Accounts", "Wildcard ClusterRole rules", noneOf(rbacWildcard), strconv.Itoa(rbacWildcard))

	add("Chart Provenance", "Signed chart (*.prov)", allOf(provOK), ratio(provOK, total))

	commentStatus := "pass"
	if valuesComments == 0 {
		commentStatus = "warn"
	}
	add("Values Best Practices", "values.yaml documentation", commentStatus, strconv.Itoa(valuesComments)+" comments")

	return &DevOpsArtifactLint{Kind: "Helm Chart", Icon: "⛵", Files: relPaths(root, chartDirs), Checks: checks}
}
