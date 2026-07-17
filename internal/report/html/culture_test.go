package html

import "testing"

// TestCurveScore locks in the shared curve's shape (used by both 🛡️ Dangers
// and ⚡ Performance): a single HIGH-weight point source (7 points) should
// still just hold the 82%+ top band, a second one (14 points) should drop
// out of it, and a very bad platform (300 points, e.g. 20 HIGH + 80 MEDIUM)
// should settle near the 5% floor rather than a flat 0%.
func TestCurveScore(t *testing.T) {
	cases := []struct {
		points  int
		wantMin int
		wantMax int
	}{
		{0, 100, 100},
		{7, 82, 100},  // 1 HIGH alone still holds the top band
		{14, 60, 81},  // 2 HIGH drops out of the top band
		{300, 5, 10},  // very bad platform settles near the floor
		{10000, 5, 6}, // pathological case never truly hits 0
	}
	for _, c := range cases {
		got := curveScore(c.points)
		if got < c.wantMin || got > c.wantMax {
			t.Errorf("curveScore(%d) = %d, want in [%d, %d]", c.points, got, c.wantMin, c.wantMax)
		}
	}
}

func TestCurveScore_Monotonic(t *testing.T) {
	prev := curveScore(0)
	for p := 1; p <= 500; p++ {
		got := curveScore(p)
		if got > prev {
			t.Fatalf("curveScore not monotonically non-increasing at points=%d: prev=%d got=%d", p, prev, got)
		}
		prev = got
	}
}

// TestComplexityPoints_MirrorsDangerWeights locks in that 🅾️ Complexity
// weights O(N³)+ hotspots and O(N²) violations exactly like 🛡️ Dangers
// weights HIGH/MEDIUM security findings (×7 / ×2), additively.
func TestComplexityPoints_MirrorsDangerWeights(t *testing.T) {
	cases := []struct {
		name string
		row  cultureRow
		want int
	}{
		{"clean", cultureRow{}, 0},
		{"one O(N3)+", cultureRow{n3: 1}, 7},
		{"one O(N2)", cultureRow{n2: 1}, 2},
		{"22 O(N3)+ and 89 O(N2)", cultureRow{n3: 22, n2: 89}, 22*7 + 89*2},
	}
	for _, c := range cases {
		if got := complexityPoints(c.row); got != c.want {
			t.Errorf("%s: complexityPoints() = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestMemLeaksPoints_MirrorsDangerWeights mirrors the same HIGH×7 / MEDIUM×2
// convention for 💧 Memory Leaks' own weighted points.
func TestMemLeaksPoints_MirrorsDangerWeights(t *testing.T) {
	cases := []struct {
		name string
		row  cultureRow
		want int
	}{
		{"clean", cultureRow{}, 0},
		{"one HIGH leak", cultureRow{memLeaksHigh: 1}, 7},
		{"one MEDIUM leak", cultureRow{memLeaksMed: 1}, 2},
		{"20 HIGH + 80 MEDIUM", cultureRow{memLeaksHigh: 20, memLeaksMed: 80}, 20*7 + 80*2},
	}
	for _, c := range cases {
		if got := memLeaksPoints(c.row); got != c.want {
			t.Errorf("%s: memLeaksPoints() = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestMemoryLeaksWorth10PercentOfPerformance locks in the actual ask: 💧
// Memory Leaks is its own 10%-weighted slice of ⚡ Performance — a clean
// (0-leak) platform must score curveScore(0)=100 on that slice, contributing
// exactly perfMemLeaksWeightPct (10) points to r.perf, all else being equal.
func TestMemoryLeaksWorth10PercentOfPerformance(t *testing.T) {
	if perfComplexityWeightPct+perfMemLeaksWeightPct != 100 {
		t.Fatalf("perfComplexityWeightPct(%d) + perfMemLeaksWeightPct(%d) must sum to 100",
			perfComplexityWeightPct, perfMemLeaksWeightPct)
	}

	clean := cultureRow{n3: 5} // some fixed complexity signal, held constant below
	clean.complexityScore = curveScore(complexityPoints(clean))
	clean.memLeaksScore = curveScore(memLeaksPoints(clean)) // 0 leaks → 100
	cleanPerf := clampInt((clean.complexityScore*perfComplexityWeightPct+clean.memLeaksScore*perfMemLeaksWeightPct+50)/100, 0, 100)

	leaky := clean
	leaky.memLeaksHigh = 3 // introduce leaks, same complexity signal
	leaky.memLeaksScore = curveScore(memLeaksPoints(leaky))
	leakyPerf := clampInt((leaky.complexityScore*perfComplexityWeightPct+leaky.memLeaksScore*perfMemLeaksWeightPct+50)/100, 0, 100)

	if clean.memLeaksScore != 100 {
		t.Fatalf("a 0-leak platform's memLeaksScore = %d, want 100", clean.memLeaksScore)
	}
	wantDrop := (100 - leaky.memLeaksScore) * perfMemLeaksWeightPct / 100
	gotDrop := cleanPerf - leakyPerf
	if gotDrop < wantDrop-1 || gotDrop > wantDrop+1 { // ±1 for integer rounding
		t.Errorf("introducing leaks dropped Performance by %d, want ~%d (the 10%% slice moving from 100 to %d)",
			gotDrop, wantDrop, leaky.memLeaksScore)
	}
	if gotDrop <= 0 {
		t.Error("introducing memory leaks should lower the Performance score, it didn't move")
	}
}
