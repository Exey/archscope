package traffic

import "testing"

// ── Swift ────────────────────────────────────────────────────────────────────

func TestSwiftInbound_VaporRoute(t *testing.T) {
	lines := []string{`app.get("/users") { req in }`}
	in, _ := ExtractSwiftTraffic("/app/routes.swift", lines)
	if len(in) != 1 || in[0].URI != "/users" || in[0].Protocol != "REST" {
		t.Fatalf("want 1 REST /users inbound, got %+v", in)
	}
}

func TestSwiftInbound_NWListener(t *testing.T) {
	lines := []string{`let listener = try NWListener(using: .tcp, on: 8080)`}
	in, _ := ExtractSwiftTraffic("/app/server.swift", lines)
	if len(in) != 1 || in[0].Protocol != "TCP" || in[0].Port != "8080" {
		t.Fatalf("want 1 TCP :8080 inbound, got %+v", in)
	}
}

func TestSwiftOutbound_HTTPSLiteral(t *testing.T) {
	lines := []string{`let url = URL(string: "https://api.example.com/v1/users")!`}
	_, out := ExtractSwiftTraffic("/app/client.swift", lines)
	if len(out) != 1 || out[0].Protocol != "REST" {
		t.Fatalf("want 1 REST outbound, got %+v", out)
	}
}

func TestSwiftOutbound_NWConnection(t *testing.T) {
	lines := []string{`let conn = NWConnection(host: "example.com", port: NWEndpoint.Port(443), using: .tcp)`}
	_, out := ExtractSwiftTraffic("/app/socket.swift", lines)
	if len(out) != 1 || out[0].Protocol != "TCP" {
		t.Fatalf("want 1 TCP outbound, got %+v", out)
	}
}

func TestSwiftSkipsBlockComments(t *testing.T) {
	lines := []string{
		`/*`,
		`app.get("/should-not-count") { }`,
		`*/`,
		`app.get("/real") { }`,
	}
	in, _ := ExtractSwiftTraffic("/app/routes.swift", lines)
	if len(in) != 1 || in[0].URI != "/real" {
		t.Fatalf("want only /real inbound, got %+v", in)
	}
}

// ── Kotlin ───────────────────────────────────────────────────────────────────

func TestKotlinInbound_KtorRoute(t *testing.T) {
	lines := []string{`    get("/users") {`}
	in, _ := ExtractKotlinTraffic("/app/Routes.kt", lines)
	if len(in) != 1 || in[0].URI != "/users" {
		t.Fatalf("want 1 /users inbound, got %+v", in)
	}
}

func TestKotlinInbound_SpringMapping(t *testing.T) {
	lines := []string{`@GetMapping("/orders/{id}")`}
	in, _ := ExtractKotlinTraffic("/app/OrderController.kt", lines)
	if len(in) != 1 || in[0].URI != "/orders/{id}" {
		t.Fatalf("want 1 /orders/{id} inbound, got %+v", in)
	}
}

func TestKotlinOutbound_RetrofitCall(t *testing.T) {
	lines := []string{`@GET("users/{id}")`}
	_, out := ExtractKotlinTraffic("/app/ApiService.kt", lines)
	if len(out) != 1 || out[0].URI != "/users/{id}" {
		t.Fatalf("want 1 /users/{id} outbound, got %+v", out)
	}
}

func TestKotlinOutbound_URLLiteral(t *testing.T) {
	lines := []string{`val base = "https://api.example.com/graphql"`}
	_, out := ExtractKotlinTraffic("/app/Client.kt", lines)
	if len(out) != 1 || out[0].Protocol != "GraphQL" {
		t.Fatalf("want 1 GraphQL outbound, got %+v", out)
	}
}

// ── TypeScript / JavaScript ──────────────────────────────────────────────────

func TestTSInbound_ExpressRoute(t *testing.T) {
	lines := []string{`app.get('/users/:id', (req, res) => {})`}
	in, _ := ExtractTypeScriptTraffic("/app/routes.ts", lines)
	if len(in) != 1 || in[0].URI != "/users/:id" {
		t.Fatalf("want 1 /users/:id inbound, got %+v", in)
	}
}

func TestTSInbound_FastifyRoute(t *testing.T) {
	lines := []string{"fastify.post(`/orders`, handler)"}
	in, _ := ExtractTypeScriptTraffic("/app/server.ts", lines)
	if len(in) != 1 || in[0].URI != "/orders" {
		t.Fatalf("want 1 /orders inbound, got %+v", in)
	}
}

func TestTSOutbound_FetchLiteral(t *testing.T) {
	lines := []string{`const res = await fetch("https://api.example.com/v1/users");`}
	_, out := ExtractTypeScriptTraffic("/app/client.ts", lines)
	if len(out) != 1 || out[0].Protocol != "REST" {
		t.Fatalf("want 1 REST outbound, got %+v", out)
	}
}

func TestTSOutbound_WebSocketLiteral(t *testing.T) {
	lines := []string{`const ws = new WebSocket("wss://stream.example.com/feed");`}
	_, out := ExtractTypeScriptTraffic("/app/socket.ts", lines)
	if len(out) != 1 || out[0].Protocol != "WebSocket" {
		t.Fatalf("want 1 WebSocket outbound, got %+v", out)
	}
}

func TestTrafficModuleAppliesToClientLanguages(t *testing.T) {
	m := Module{}
	for _, lang := range []string{"go", "python", "java", "swift", "kotlin", "ts"} {
		if !m.AppliesTo(lang) {
			t.Errorf("expected AppliesTo(%q) = true", lang)
		}
	}
	if m.AppliesTo("ruby") {
		t.Error("expected AppliesTo(\"ruby\") = false")
	}
}
