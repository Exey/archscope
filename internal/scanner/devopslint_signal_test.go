package scanner

import (
	"path/filepath"
	"testing"
)

// TestHasEnoughSignal_SingleLoneDockerfile ensures a lone Dockerfile with no
// compose file or Helm chart alongside it is still fully evaluated by
// ScanDevOpsLint (real check results, for callers that want them) but is
// flagged as not enough evidence for the report to display/score.
func TestHasEnoughSignal_SingleLoneDockerfile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Dockerfile"), `FROM alpine:3.19@sha256:1111111111111111111111111111111111111111111111111111111111abcd
CMD ["/bin/true"]
`)
	lint := ScanDevOpsLint(root)
	if lint == nil || lint.Dockerfiles == nil {
		t.Fatal("expected ScanDevOpsLint to still return real Dockerfile checks")
	}
	if lint.HasEnoughSignal() {
		t.Error("expected a single lone Dockerfile to not count as enough signal")
	}
}

// TestHasEnoughSignal_DockerfilePlusCompose ensures a Dockerfile alongside a
// compose file (a real deployment setup) still counts as enough signal.
func TestHasEnoughSignal_DockerfilePlusCompose(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Dockerfile"), "FROM alpine:3.19\nCMD [\"/bin/true\"]\n")
	writeFile(t, filepath.Join(root, "docker-compose.yml"), "services:\n  app:\n    build: .\n")
	lint := ScanDevOpsLint(root)
	if !lint.HasEnoughSignal() {
		t.Error("expected Dockerfile + compose to count as enough signal")
	}
}

// TestHasEnoughSignal_TwoDockerfiles ensures multiple Dockerfiles (even with
// no compose/Helm) still count as enough signal — the "lone" gate is only for
// exactly one.
func TestHasEnoughSignal_TwoDockerfiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Dockerfile"), "FROM alpine:3.19\nCMD [\"/bin/true\"]\n")
	writeFile(t, filepath.Join(root, "worker", "Dockerfile"), "FROM alpine:3.19\nCMD [\"/bin/true\"]\n")
	lint := ScanDevOpsLint(root)
	if !lint.HasEnoughSignal() {
		t.Error("expected two Dockerfiles to count as enough signal")
	}
}

func TestHasEnoughSignal_Nil(t *testing.T) {
	var lint *DevOpsLint
	if lint.HasEnoughSignal() {
		t.Error("expected nil DevOpsLint to report no signal")
	}
}
