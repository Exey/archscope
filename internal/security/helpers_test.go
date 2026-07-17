package security

import "testing"

func TestIsTestOrBenchPath(t *testing.T) {
	cases := map[string]bool{
		"/repo/src/main.go":            false,
		"/repo/Tests/main_test.go":     true,
		"/repo/tests/foo.swift":        true,
		"/repo/Benchmarks/bench.go":    true,
		"/repo/benchmark/bench.go":     true,
		"foo_test.go":                  true,
		"FooTests.swift":               true,
		"FooSpec.kt":                   true,
		"foo.spec.ts":                  true,
		"test_foo.py":                  true,
		"/repo/testdata/fixture.json":  true,
		"/repo/__tests__/App.test.tsx": true,
		// Go's own t.TempDir() embeds the test function name into the path
		// (e.g. ".../TestFooBar12345/001/f.go") — this must NOT match, or a
		// unit test verifying file inclusion would exclude its own fixture.
		"/tmp/TestFooBar12345/001/f.go": false,
		// A suffixed app-name test target (Xcode's common "MyAppTests"
		// convention) isn't an exact "Tests" directory component — outside
		// what was asked (an exact "_test"/"Tests"/"Benchmarks" match), so
		// this documents the current, narrower behavior rather than gets
		// widened into another prefix match (which is what caused the
		// TempDir collision above).
		"/repo/MyAppTests/Thing.swift": false,
		"widget_test.c":                true,
		"widget_test.cpp":              true,
		"widget_test.cc":               true,
		"widget_unittest.cc":           true,
		"/repo/src/widget.c":           false,
	}
	for path, want := range cases {
		if got := IsTestOrBenchPath(path); got != want {
			t.Errorf("IsTestOrBenchPath(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestIsTestPath_CAndCpp(t *testing.T) {
	cases := map[string]bool{
		"widget_test.c":       true,
		"widget_test.cpp":     true,
		"widget_test.cc":      true,
		"widget_unittest.cc":  true,
		"/repo/src/widget.c":  false,
		"/repo/test/widget.c": true,
	}
	for path, want := range cases {
		if got := IsTestPath(path); got != want {
			t.Errorf("IsTestPath(%q) = %v, want %v", path, got, want)
		}
	}
}
