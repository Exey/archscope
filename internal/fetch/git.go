// Package fetch resolves an analysis source — either a local path or a remote
// git URL — to an on-disk directory. Remote URLs are cloned into a temporary
// directory (requirement #5); the returned Cleanup removes it.
package fetch

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Source describes where to analyze. Exactly one of LocalPath / RemoteURL set.
type Source struct {
	LocalPath string
	RemoteURL string // https://github.com/org/repo(.git) or git@host:org/repo.git
	Ref       string // optional branch/tag/sha; "" = default branch
	Depth     int    // 0 = full history (git stats need it); >0 = shallow
}

// Resolved is an on-disk location plus cleanup.
type Resolved struct {
	Path     string
	Cleanup  func() error
	WasClone bool
}

// looksLikeSHA reports whether s is plausibly a git commit SHA (7–64 hex chars).
// git clone --branch rejects SHAs, so we skip --branch for these and rely on
// the post-clone checkout instead.
func looksLikeSHA(s string) bool {
	if len(s) < 7 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// IsRemoteURL reports whether arg looks like a git URL rather than a local path.
func IsRemoteURL(arg string) bool {
	return strings.HasPrefix(arg, "http://") ||
		strings.HasPrefix(arg, "https://") ||
		strings.HasPrefix(arg, "git@") ||
		strings.HasPrefix(arg, "ssh://") ||
		strings.HasPrefix(arg, "git://")
}

// FromArg builds a Source from a CLI argument and fetch options.
func FromArg(arg, ref string, depth int) Source {
	if IsRemoteURL(arg) {
		return Source{RemoteURL: arg, Ref: ref, Depth: depth}
	}
	return Source{LocalPath: arg}
}

// Resolve returns a local directory for src. For RemoteURL it shells out to
// `git clone` into a fresh temp dir, honoring Ref and Depth, and returns a
// Cleanup that removes the temp dir. For LocalPath the path is returned as-is
// with a no-op Cleanup.
func Resolve(src Source) (*Resolved, error) {
	if src.RemoteURL == "" {
		if src.LocalPath == "" {
			return nil, fmt.Errorf("fetch: empty source")
		}
		return &Resolved{Path: src.LocalPath, Cleanup: func() error { return nil }}, nil
	}
	if _, err := exec.LookPath("git"); err != nil {
		return nil, fmt.Errorf("fetch: git not found on PATH (required for remote URLs): %w", err)
	}

	// Reject refs that start with '-': git would interpret them as flags.
	if src.Ref != "" && strings.HasPrefix(src.Ref, "-") {
		return nil, fmt.Errorf("fetch: invalid ref %q: must not start with '-'", src.Ref)
	}

	dir, err := os.MkdirTemp("", "archscope-clone-*")
	if err != nil {
		return nil, err
	}
	cleanup := func() error { return os.RemoveAll(dir) }

	args := []string{"clone"}
	if src.Depth > 0 {
		args = append(args, "--depth", strconv.Itoa(src.Depth))
	}
	if src.Ref != "" && !looksLikeSHA(src.Ref) {
		// --branch works for branch/tag names; skip it for SHA refs (git rejects them).
		args = append(args, "--branch", src.Ref)
	}
	args = append(args, src.RemoteURL, dir)

	cmd := exec.Command("git", args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("fetch: git clone failed: %w", err)
	}

	// Always checkout the requested ref regardless of clone depth.
	// --branch handles branches/tags on the initial clone; this additionally
	// handles SHA refs and is a no-op when already on the right commit.
	// Pass -- so the ref cannot be misinterpreted as a flag.
	if src.Ref != "" {
		co := exec.Command("git", "-C", dir, "checkout", "--", src.Ref)
		co.Stderr = os.Stderr
		if err := co.Run(); err != nil {
			_ = cleanup()
			return nil, fmt.Errorf("fetch: git checkout %q failed: %w", src.Ref, err)
		}
	}

	return &Resolved{Path: dir, Cleanup: cleanup, WasClone: true}, nil
}
