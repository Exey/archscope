package html

import (
	"testing"

	"github.com/exey/archscope/internal/modules/speccoverage"
	"github.com/exey/archscope/internal/modules/traffic"
)

func TestTrafficRESTfulnessNounsVsVerbs(t *testing.T) {
	inbound := []traffic.Entry{
		{URI: "/v1/users/{id}", Protocol: "REST"},
		{URI: "/getUsers", Protocol: "REST"},
	}
	score, _, ok := trafficRESTfulnessScore(inbound)
	if !ok {
		t.Fatal("expected a score")
	}
	// One noun-style (50%) + one versioned (50%) → (50+50)/2 = 50.
	if score != 50 {
		t.Errorf("expected score 50, got %d", score)
	}
}

func TestTrafficRESTDominantGate(t *testing.T) {
	if trafficRESTDominant(nil) {
		t.Error("expected false for empty input")
	}
	mostlyGRPC := []traffic.Entry{
		{Protocol: "gRPC"}, {Protocol: "gRPC"}, {Protocol: "REST"},
	}
	if trafficRESTDominant(mostlyGRPC) {
		t.Error("expected false when REST is a minority")
	}
	mostlyREST := []traffic.Entry{
		{Protocol: "REST"}, {Protocol: "REST"}, {Protocol: "gRPC"},
	}
	if !trafficRESTDominant(mostlyREST) {
		t.Error("expected true when REST is the majority")
	}
}

func TestTrafficModernityScore(t *testing.T) {
	inbound := []traffic.Entry{{Protocol: "REST"}, {Protocol: "gRPC"}}
	outbound := []traffic.Entry{{Protocol: "Kafka"}} // neutral, excluded from denominator
	score, _, ok := trafficModernityScore(inbound, outbound)
	if !ok || score != 100 {
		t.Errorf("expected 100%% modernity (Kafka excluded), got %d (ok=%v)", score, ok)
	}
}

func TestTrafficDependencyHealthInternalVsExternal(t *testing.T) {
	outbound := []traffic.Entry{
		{URI: "http://payments.internal/charge"},
		{URI: "https://api.stripe.com/v1/charges"},
	}
	score, detail, ok := trafficDependencyHealthScore(outbound)
	if !ok {
		t.Fatal("expected a score")
	}
	if detail == "" || score <= 0 {
		t.Errorf("unexpected result: score=%d detail=%q", score, detail)
	}
}

func TestComputeTrafficHealthSkipsClientOnlyCategories(t *testing.T) {
	tr := traffic.Result{
		Inbound:  []traffic.Entry{{URI: "/v1/users/{id}", Protocol: "REST"}},
		Outbound: []traffic.Entry{{URI: "https://api.example.com/x", Protocol: "REST"}},
	}
	spec := &speccoverage.Result{SpecReady: 80}

	full, ok := computeTrafficHealth(tr, spec, false)
	if !ok {
		t.Fatal("expected data")
	}
	client, ok := computeTrafficHealth(tr, spec, true)
	if !ok {
		t.Fatal("expected data")
	}
	if len(client.cats) >= len(full.cats) {
		t.Errorf("expected fewer categories for a client platform: full=%d client=%d", len(full.cats), len(client.cats))
	}
	for _, c := range client.cats {
		if c.label == "Documentation" || c.label == "Dependency Health" || c.label == "Observability" {
			t.Errorf("client platform must not include %q", c.label)
		}
	}
}

func TestComputeTrafficHealthNoData(t *testing.T) {
	if _, ok := computeTrafficHealth(traffic.Result{}, nil, false); ok {
		t.Error("expected ok=false for empty traffic result")
	}
}

func TestRenderTrafficHealthBlockEmpty(t *testing.T) {
	if out := renderTrafficHealthBlock(trafficHealth{}, false); out != "" {
		t.Errorf("expected empty render when ok=false, got %q", out)
	}
}
