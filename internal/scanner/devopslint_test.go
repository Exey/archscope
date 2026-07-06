package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func findCheck(t *testing.T, a *DevOpsArtifactLint, metric string) DevOpsCheck {
	t.Helper()
	if a == nil {
		t.Fatalf("artifact lint is nil (metric %q)", metric)
	}
	for _, c := range a.Checks {
		if c.Metric == metric {
			return c
		}
	}
	t.Fatalf("metric %q not found in %s checks", metric, a.Kind)
	return DevOpsCheck{}
}

func TestScanDevOpsLint(t *testing.T) {
	root := t.TempDir()

	writeFile(t, filepath.Join(root, "Dockerfile"), `FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o /app ./cmd

FROM alpine:latest
ENV API_TOKEN=supersecret123
ADD dist.tar.gz /opt
RUN apk add curl
RUN curl -sSf https://example.com/install.sh | sh
RUN chmod 777 /opt
EXPOSE 80
CMD ["/app"]
`)

	writeFile(t, filepath.Join(root, "docker-compose.yml"), `version: "2"
services:
  api:
    image: api:latest
    privileged: true
    restart: always
    ports:
      - "8080:8080"
    environment:
      - DB_PASSWORD=hunter2
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    cap_add:
      - SYS_ADMIN
`)

	writeFile(t, filepath.Join(root, "deploy/chart/Chart.yaml"), "apiVersion: v2\nname: demo\nversion: 0.1.0\n")
	writeFile(t, filepath.Join(root, "deploy/chart/values.yaml"), "# replica count\nreplicas: 1\n")
	writeFile(t, filepath.Join(root, "deploy/chart/templates/deployment.yaml"), `apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  namespace: prod
spec:
  template:
    spec:
      containers:
        - name: app
          securityContext:
            privileged: true
`)

	lint := ScanDevOpsLint(root)
	if lint.Empty() {
		t.Fatal("expected lint results, got empty")
	}

	// Dockerfile
	if c := findCheck(t, lint.Dockerfiles, "Pinned digest (no :latest)"); c.Status != "fail" {
		t.Errorf("pinned digest: want fail (alpine:latest), got %s (%s)", c.Status, c.Value)
	}
	if c := findCheck(t, lint.Dockerfiles, "ADD instead of COPY"); c.Status != "fail" {
		t.Errorf("ADD: want fail, got %s", c.Status)
	}
	if c := findCheck(t, lint.Dockerfiles, "Secrets in ARG/ENV"); c.Status != "fail" {
		t.Errorf("secrets: want fail, got %s", c.Status)
	}
	if c := findCheck(t, lint.Dockerfiles, "curl | sh pipes"); c.Status != "fail" {
		t.Errorf("curl|sh: want fail, got %s", c.Status)
	}
	if c := findCheck(t, lint.Dockerfiles, "chmod 777 / world-writable"); c.Status != "fail" {
		t.Errorf("chmod 777: want fail, got %s", c.Status)
	}
	if c := findCheck(t, lint.Dockerfiles, "apk --no-cache"); c.Status != "warn" {
		t.Errorf("apk --no-cache: want warn, got %s (%s)", c.Status, c.Value)
	}
	if c := findCheck(t, lint.Dockerfiles, "Multi-stage build"); c.Status != "pass" {
		t.Errorf("multi-stage: want pass, got %s", c.Status)
	}
	if c := findCheck(t, lint.Dockerfiles, "Privileged ports (<1024)"); c.Status != "warn" {
		t.Errorf("low ports: want warn, got %s", c.Status)
	}
	if c := findCheck(t, lint.Dockerfiles, "Base image CVE count"); c.Status != "na" {
		t.Errorf("CVE count: want na, got %s", c.Status)
	}

	// Compose
	if c := findCheck(t, lint.Compose, "Obsolete compose version"); c.Status != "fail" {
		t.Errorf("compose version: want fail, got %s", c.Status)
	}
	if c := findCheck(t, lint.Compose, "privileged: true services"); c.Status != "fail" {
		t.Errorf("privileged: want fail, got %s", c.Status)
	}
	if c := findCheck(t, lint.Compose, "docker.sock mounted"); c.Status != "fail" {
		t.Errorf("docker.sock: want fail, got %s", c.Status)
	}
	if c := findCheck(t, lint.Compose, "Secrets in environment"); c.Status != "fail" {
		t.Errorf("compose secrets: want fail, got %s", c.Status)
	}
	if c := findCheck(t, lint.Compose, "Dangerous cap_add"); c.Status != "fail" {
		t.Errorf("cap_add: want fail, got %s", c.Status)
	}
	if c := findCheck(t, lint.Compose, "Ports on 0.0.0.0"); c.Status != "warn" {
		t.Errorf("0.0.0.0 ports: want warn, got %s", c.Status)
	}

	// Helm
	if c := findCheck(t, lint.Helm, "Chart.yaml required fields"); c.Status != "pass" {
		t.Errorf("chart fields: want pass, got %s", c.Status)
	}
	if c := findCheck(t, lint.Helm, "Deprecated K8s API versions"); c.Status != "fail" {
		t.Errorf("deprecated APIs: want fail, got %s", c.Status)
	}
	if c := findCheck(t, lint.Helm, "Hardcoded namespace"); c.Status != "fail" {
		t.Errorf("hardcoded ns: want fail, got %s", c.Status)
	}
	if c := findCheck(t, lint.Helm, "Privileged containers"); c.Status != "fail" {
		t.Errorf("helm privileged: want fail, got %s", c.Status)
	}
	if c := findCheck(t, lint.Helm, "values.yaml documentation"); c.Status != "pass" {
		t.Errorf("values comments: want pass, got %s (%s)", c.Status, c.Value)
	}

	if score, ok := lint.Score(); !ok || score >= 100 {
		t.Errorf("score: want evaluable score below 100, got %d ok=%v", score, ok)
	}
}

// TestComposeCapDropNotFlagged ensures dropping capabilities (a security
// best practice, including "cap_drop: [ALL]") is never counted as a
// dangerous cap_add, and that cap_add is still correctly flagged when it
// actually adds a dangerous capability.
func TestComposeCapDropNotFlagged(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "docker-compose.yml"), `version: "3.8"
services:
  api:
    image: api:latest
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
  worker:
    image: worker:latest
    cap_add:
      - SYS_ADMIN
`)
	lint := ScanDevOpsLint(root)
	if c := findCheck(t, lint.Compose, "Dangerous cap_add"); c.Status != "fail" || c.Value != "1" {
		t.Errorf("cap_add: want fail with count 1 (only SYS_ADMIN, not cap_drop's ALL or the safe NET_BIND_SERVICE), got %s (%s)", c.Status, c.Value)
	}
}

// TestDockerfilePlatformFlag ensures a --platform flag on FROM doesn't get
// mistaken for the image reference.
func TestDockerfilePlatformFlag(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Dockerfile"), `FROM --platform=linux/amd64 alpine:3.19@sha256:1111111111111111111111111111111111111111111111111111111111abcd
CMD ["/bin/true"]
`)
	lint := ScanDevOpsLint(root)
	if c := findCheck(t, lint.Dockerfiles, "Pinned digest (no :latest)"); c.Status != "pass" {
		t.Errorf("pinned digest with --platform flag: want pass, got %s (%s)", c.Status, c.Value)
	}
}

// TestDockerfileLineContinuationSecret ensures a secret on a backslash
// continuation line of a multi-line ENV instruction is still detected.
func TestDockerfileLineContinuationSecret(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Dockerfile"), "FROM alpine\nENV FOO=bar \\\n    API_TOKEN=supersecret123\n")
	lint := ScanDevOpsLint(root)
	if c := findCheck(t, lint.Dockerfiles, "Secrets in ARG/ENV"); c.Status != "fail" {
		t.Errorf("secret on ENV continuation line: want fail, got %s (%s)", c.Status, c.Value)
	}
}

func TestScanDevOpsLintEmpty(t *testing.T) {
	if lint := ScanDevOpsLint(t.TempDir()); !lint.Empty() {
		t.Fatalf("expected nil/empty lint for empty dir, got %+v", lint)
	}
	var nilLint *DevOpsLint
	if _, ok := nilLint.Score(); ok {
		t.Fatal("nil lint must not report a score")
	}
}
