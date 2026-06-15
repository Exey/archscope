package traffic

import (
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

// ── Go inbound ───────────────────────────────────────────────────────────────

func TestGoInbound_ListenAndServe(t *testing.T) {
	lines := []string{`http.ListenAndServe(":8080", nil)`}
	in, out := ExtractGoTraffic("/app/server.go", lines, nil)
	if len(out) != 0 {
		t.Fatalf("want 0 outbound, got %d", len(out))
	}
	if len(in) != 1 {
		t.Fatalf("want 1 inbound, got %d", len(in))
	}
	e := in[0]
	if e.Protocol != "REST" {
		t.Errorf("protocol: want REST, got %s", e.Protocol)
	}
	if e.Port != "8080" {
		t.Errorf("port: want 8080, got %s", e.Port)
	}
}

func TestGoInbound_HTTPRoutes(t *testing.T) {
	lines := []string{
		`router.GET("/api/users", usersHandler)`,
		`router.POST("/api/orders", createOrder)`,
		`r.HandleFunc("/health", healthCheck)`,
	}
	in, _ := ExtractGoTraffic("/app/routes.go", lines, nil)
	if len(in) != 3 {
		t.Fatalf("want 3 inbound routes, got %d: %v", len(in), in)
	}
	uris := make(map[string]bool)
	for _, e := range in {
		uris[e.URI] = true
		if e.Protocol != "REST" {
			t.Errorf("expected REST, got %s for %s", e.Protocol, e.URI)
		}
	}
	for _, want := range []string{"GET /api/users", "POST /api/orders", "/health"} {
		if !uris[want] {
			t.Errorf("missing inbound URI %q", want)
		}
	}
}

func TestGoInbound_GRPCServer(t *testing.T) {
	lines := []string{
		`grpcServer := grpc.NewServer(opts...)`,
		`pb.RegisterOrderServiceServer(grpcServer, &orderServer{})`,
	}
	in, _ := ExtractGoTraffic("/app/grpc.go", lines, nil)
	protos := make(map[string]bool)
	uris := make(map[string]bool)
	for _, e := range in {
		protos[e.Protocol] = true
		uris[e.URI] = true
	}
	if !protos["gRPC"] {
		t.Errorf("want gRPC inbound, got: %v", in)
	}
	if !uris["OrderService"] {
		t.Errorf("want OrderService service name, got uris: %v", uris)
	}
}

func TestGoInbound_WebSocket(t *testing.T) {
	lines := []string{`var upgrader = websocket.Upgrader{CheckOrigin: ...}`}
	in, _ := ExtractGoTraffic("/app/ws.go", lines, []string{"github.com/gorilla/websocket"})
	if len(in) == 0 {
		t.Fatal("want at least 1 WebSocket inbound")
	}
	if in[0].Protocol != "WebSocket" {
		t.Errorf("want WebSocket, got %s", in[0].Protocol)
	}
}

// ── Go outbound ──────────────────────────────────────────────────────────────

func TestGoOutbound_HTTPGet(t *testing.T) {
	lines := []string{`resp, err := http.Get("https://api.stripe.com/v1/charges")`}
	_, out := ExtractGoTraffic("/app/payments.go", lines, []string{"encoding/json"})
	if len(out) != 1 {
		t.Fatalf("want 1 outbound, got %d", len(out))
	}
	e := out[0]
	if e.Protocol != "REST/TLS" {
		t.Errorf("want REST/TLS, got %s", e.Protocol)
	}
	if !strings.HasPrefix(e.URI, "https://") {
		t.Errorf("want https:// URI, got %s", e.URI)
	}
	if e.DataFmt != "JSON" {
		t.Errorf("want JSON (from encoding/json import), got %s", e.DataFmt)
	}
}

func TestGoOutbound_GRPCDial(t *testing.T) {
	lines := []string{`conn, err := grpc.Dial("inventory-service:50051", grpc.WithInsecure())`}
	_, out := ExtractGoTraffic("/app/client.go", lines, nil)
	if len(out) != 1 {
		t.Fatalf("want 1 outbound, got %d", len(out))
	}
	e := out[0]
	if e.Protocol != "gRPC" {
		t.Errorf("want gRPC, got %s", e.Protocol)
	}
	if e.Port != "50051" {
		t.Errorf("want port 50051, got %s", e.Port)
	}
	if e.DataFmt != "Protobuf" {
		t.Errorf("want Protobuf, got %s", e.DataFmt)
	}
}

func TestGoOutbound_Redis_MultiLine(t *testing.T) {
	lines := []string{
		`rdb := redis.NewClient(&redis.Options{`,
		`    Addr: "localhost:6379",`,
		`    DB:   0,`,
		`})`,
	}
	_, out := ExtractGoTraffic("/app/cache.go", lines, nil)
	if len(out) != 1 {
		t.Fatalf("want 1 Redis outbound, got %d", len(out))
	}
	e := out[0]
	if e.Protocol != "Redis" {
		t.Errorf("want Redis, got %s", e.Protocol)
	}
	if e.Port != "6379" {
		t.Errorf("want port 6379, got %s", e.Port)
	}
}

func TestGoOutbound_Kafka_MultiLine(t *testing.T) {
	lines := []string{
		`w := kafka.NewWriter(kafka.WriterConfig{`,
		`    Brokers: []string{"kafka:9092"},`,
		`    Topic:   "orders",`,
		`})`,
	}
	_, out := ExtractGoTraffic("/app/producer.go", lines, nil)
	if len(out) != 1 {
		t.Fatalf("want 1 Kafka outbound, got %d: %v", len(out), out)
	}
	e := out[0]
	if e.Protocol != "Kafka" {
		t.Errorf("want Kafka, got %s", e.Protocol)
	}
	if e.Port != "9092" {
		t.Errorf("want port 9092, got %s", e.Port)
	}
}

func TestGoOutbound_NATS(t *testing.T) {
	lines := []string{`nc, err := nats.Connect("nats://localhost:4222")`}
	_, out := ExtractGoTraffic("/app/events.go", lines, nil)
	if len(out) != 1 {
		t.Fatalf("want 1 NATS outbound, got %d", len(out))
	}
	if out[0].Protocol != "NATS" {
		t.Errorf("want NATS, got %s", out[0].Protocol)
	}
	if out[0].Port != "4222" {
		t.Errorf("want port 4222, got %s", out[0].Port)
	}
}

func TestGoOutbound_AMQP(t *testing.T) {
	lines := []string{`conn, err := amqp.Dial("amqp://guest:guest@rabbitmq:5672/")`}
	_, out := ExtractGoTraffic("/app/mq.go", lines, nil)
	if len(out) != 1 {
		t.Fatalf("want 1 AMQP outbound, got %d", len(out))
	}
	if out[0].Protocol != "AMQP" {
		t.Errorf("want AMQP, got %s", out[0].Protocol)
	}
}

// ── Go deduplication ─────────────────────────────────────────────────────────

func TestGoDeduplication(t *testing.T) {
	lines := []string{
		`router.GET("/api/users", handler1)`,
		`router.GET("/api/users", handler2)`, // duplicate URI+Protocol
	}
	in, _ := ExtractGoTraffic("/app/routes.go", lines, nil)
	if len(in) != 1 {
		t.Errorf("want 1 deduplicated entry, got %d", len(in))
	}
}

// ── Go comment skip ──────────────────────────────────────────────────────────

func TestGoCommentSkip(t *testing.T) {
	lines := []string{
		`// http.ListenAndServe(":8080", nil)`,
		`// resp, _ := http.Get("https://example.com")`,
	}
	in, out := ExtractGoTraffic("/app/doc.go", lines, nil)
	if len(in)+len(out) != 0 {
		t.Errorf("want no signals from comments, got in=%d out=%d", len(in), len(out))
	}
}

// ── Python inbound ───────────────────────────────────────────────────────────

func TestPythonInbound_FastAPIRoutes(t *testing.T) {
	lines := []string{
		`@router.get("/api/items")`,
		`async def list_items():`,
		`@router.post("/api/items")`,
		`async def create_item(item: Item):`,
	}
	in, _ := ExtractPythonTraffic("/app/routes.py", lines)
	if len(in) != 2 {
		t.Fatalf("want 2 inbound routes, got %d: %v", len(in), in)
	}
	uris := map[string]bool{}
	for _, e := range in {
		uris[e.URI] = true
		if e.Protocol != "REST" {
			t.Errorf("want REST, got %s", e.Protocol)
		}
	}
	if !uris["GET /api/items"] || !uris["POST /api/items"] {
		t.Errorf("unexpected uris: %v", uris)
	}
}

func TestPythonInbound_FlaskRoute(t *testing.T) {
	lines := []string{
		`@app.route('/orders', methods=['GET', 'POST'])`,
		`def orders():`,
	}
	in, _ := ExtractPythonTraffic("/app/views.py", lines)
	if len(in) != 1 {
		t.Fatalf("want 1 route, got %d", len(in))
	}
	if in[0].URI != "/orders" {
		t.Errorf("want /orders, got %s", in[0].URI)
	}
}

// ── Python outbound ──────────────────────────────────────────────────────────

func TestPythonOutbound_Requests(t *testing.T) {
	lines := []string{
		`resp = requests.get("https://api.github.com/user")`,
		`resp = requests.post("https://api.stripe.com/v1/charges", data=payload)`,
	}
	_, out := ExtractPythonTraffic("/app/client.py", lines)
	if len(out) != 2 {
		t.Fatalf("want 2 outbound, got %d", len(out))
	}
	for _, e := range out {
		if e.Protocol != "REST" {
			t.Errorf("want REST, got %s", e.Protocol)
		}
	}
}

func TestPythonOutbound_Redis(t *testing.T) {
	lines := []string{`r = redis.Redis(host='localhost', port=6379, db=0)`}
	_, out := ExtractPythonTraffic("/app/cache.py", lines)
	if len(out) != 1 {
		t.Fatalf("want 1 Redis outbound, got %d", len(out))
	}
	e := out[0]
	if e.Protocol != "Redis" {
		t.Errorf("want Redis, got %s", e.Protocol)
	}
	if e.Port != "6379" {
		t.Errorf("want port 6379, got %s", e.Port)
	}
}

func TestPythonOutbound_Kafka(t *testing.T) {
	lines := []string{`producer = KafkaProducer(bootstrap_servers='kafka:9092')`}
	_, out := ExtractPythonTraffic("/app/producer.py", lines)
	if len(out) != 1 {
		t.Fatalf("want 1 Kafka outbound, got %d", len(out))
	}
	if out[0].Protocol != "Kafka" {
		t.Errorf("want Kafka, got %s", out[0].Protocol)
	}
}

// ── Django inbound ────────────────────────────────────────────────────────────

func TestPythonInbound_DjangoPath(t *testing.T) {
	lines := []string{
		`    path('api/orders/', views.OrderListView.as_view(), name='order-list'),`,
		`    path('api/orders/<int:pk>/', views.OrderDetailView.as_view()),`,
	}
	in, _ := ExtractPythonTraffic("/app/urls.py", lines)
	if len(in) != 2 {
		t.Fatalf("want 2 Django path() inbound, got %d: %v", len(in), in)
	}
	uris := map[string]bool{}
	for _, e := range in {
		uris[e.URI] = true
		if e.Protocol != "REST" {
			t.Errorf("want REST, got %s for %s", e.Protocol, e.URI)
		}
	}
	if !uris["/api/orders/"] {
		t.Errorf("missing /api/orders/, got: %v", uris)
	}
}

func TestPythonInbound_DjangoRePath(t *testing.T) {
	lines := []string{
		`    re_path(r'^api/v1/users/$', views.UserView.as_view()),`,
	}
	in, _ := ExtractPythonTraffic("/app/urls.py", lines)
	if len(in) != 1 {
		t.Fatalf("want 1 re_path inbound, got %d", len(in))
	}
	if in[0].URI != "/api/v1/users/" {
		t.Errorf("want /api/v1/users/, got %s", in[0].URI)
	}
}

func TestPythonInbound_DRFRouter(t *testing.T) {
	lines := []string{
		`router.register(r'orders', OrderViewSet, basename='order')`,
		`router.register('items', ItemViewSet)`,
	}
	in, _ := ExtractPythonTraffic("/app/urls.py", lines)
	if len(in) != 2 {
		t.Fatalf("want 2 DRF router routes, got %d: %v", len(in), in)
	}
	uris := map[string]bool{}
	for _, e := range in {
		uris[e.URI] = true
	}
	if !uris["/orders"] {
		t.Errorf("missing /orders, got: %v", uris)
	}
	if !uris["/items"] {
		t.Errorf("missing /items, got: %v", uris)
	}
}

func TestPythonInbound_DRFRouterWithPrefix(t *testing.T) {
	lines := []string{
		`router_v3 = routers.DefaultRouter()`,
		`router_v3.register("stores", StoreViewSetNew, basename="stores")`,
		`router_v3.register("products", ProductViewSet, basename="products")`,
		`urlpatterns = [`,
		`    path('api/v3/', include(router_v3.urls)),`,
		`]`,
	}
	in, _ := ExtractPythonTraffic("/app/urls.py", lines)
	uris := map[string]bool{}
	for _, e := range in {
		uris[e.URI] = true
	}
	if !uris["/api/v3/stores"] {
		t.Errorf("missing /api/v3/stores, got: %v", uris)
	}
	if !uris["/api/v3/products"] {
		t.Errorf("missing /api/v3/products, got: %v", uris)
	}
}

func TestPythonInbound_DRFRouterMultiLine(t *testing.T) {
	// Multi-line router.register() calls with nested include prefix (api/v1/).
	lines := []string{
		`router = routers.DefaultRouter()`,
		`router.register(`,
		`    r"notification-settings",`,
		`    NotificationSettingsViewSet,`,
		`    basename="notification-settings",`,
		`)`,
		`router.register(r"pages", PageViewSet, basename="pages")`,
		`urlpatterns = [`,
		`    path(`,
		`        "api/v1/",`,
		`        include(`,
		`            (`,
		`                [`,
		`                    path("", include(router.urls)),`,
		`                ],`,
		`                "dtp",`,
		`            ),`,
		`        ),`,
		`    ),`,
		`]`,
	}
	in, _ := ExtractPythonTraffic("/app/urls.py", lines)
	uris := map[string]bool{}
	for _, e := range in {
		uris[e.URI] = true
	}
	if !uris["/api/v1/notification-settings"] {
		t.Errorf("missing /api/v1/notification-settings, got: %v", uris)
	}
	if !uris["/api/v1/pages"] {
		t.Errorf("missing /api/v1/pages, got: %v", uris)
	}
}

// ── Module.Analyze integration ───────────────────────────────────────────────

func TestAnalyze_Integration(t *testing.T) {
	m := Module{}
	inEntries := []Entry{
		{URI: "GET /api/orders", Protocol: "REST", FilePath: "/app/routes.go", Line: 12},
		{URI: "gRPC Server", Protocol: "gRPC", DataFmt: "Protobuf", FilePath: "/app/grpc.go", Line: 5},
	}
	outEntries := []Entry{
		{URI: "https://stripe.com/v1", Protocol: "REST/TLS", FilePath: "/app/payments.go", Line: 33},
	}
	files := []*parser.ParsedFile{
		{
			Extra: map[string]any{
				"trafficInbound":  inEntries,
				"trafficOutbound": outEntries,
			},
		},
	}
	res := m.Analyze(files)
	r, ok := res.(Result)
	if !ok {
		t.Fatal("Analyze did not return traffic.Result")
	}
	if len(r.Inbound) != 2 {
		t.Errorf("want 2 inbound, got %d", len(r.Inbound))
	}
	if len(r.Outbound) != 1 {
		t.Errorf("want 1 outbound, got %d", len(r.Outbound))
	}
}

func TestAnalyze_Empty(t *testing.T) {
	m := Module{}
	res := m.Analyze([]*parser.ParsedFile{{Extra: map[string]any{}}})
	r := res.(Result)
	if r.HasData() {
		t.Error("expected HasData() = false for empty files")
	}
}

// ── Java inbound ─────────────────────────────────────────────────────────────

func TestJavaInbound_SpringMVC(t *testing.T) {
	lines := []string{
		`@RestController`,
		`@RequestMapping("/api/v1")`,
		`public class UserController {`,
		`    @GetMapping("/users")`,
		`    public List<User> getUsers() { return null; }`,
		`    @PostMapping("/users")`,
		`    public User createUser(@RequestBody User u) { return null; }`,
		`    @DeleteMapping("/{id}")`,
		`    public void delete(@PathVariable Long id) {}`,
		`}`,
	}
	in, _ := ExtractJavaTraffic("/app/UserController.java", lines)
	uris := map[string]bool{}
	for _, e := range in {
		uris[e.URI] = true
	}
	if !uris["GET /api/v1/users"] {
		t.Errorf("missing GET /api/v1/users, got: %v", uris)
	}
	if !uris["POST /api/v1/users"] {
		t.Errorf("missing POST /api/v1/users, got: %v", uris)
	}
	if !uris["DELETE /api/v1/{id}"] {
		t.Errorf("missing DELETE /api/v1/{id}, got: %v", uris)
	}
}

func TestJavaInbound_SpringBootStartup(t *testing.T) {
	lines := []string{`SpringApplication.run(App.class, args);`}
	in, _ := ExtractJavaTraffic("/app/App.java", lines)
	if len(in) == 0 {
		t.Fatal("want at least 1 inbound (HTTP Server)")
	}
	if in[0].URI != "HTTP Server" || in[0].Protocol != "REST" {
		t.Errorf("unexpected: %+v", in[0])
	}
}

func TestJavaInbound_JAXRS(t *testing.T) {
	lines := []string{
		`@Path("/orders")`,
		`@GET`,
		`public Response listOrders() { return null; }`,
	}
	in, _ := ExtractJavaTraffic("/app/OrderResource.java", lines)
	if len(in) == 0 {
		t.Fatal("want inbound entry for @Path")
	}
	if in[0].URI != "GET /orders" {
		t.Errorf("want GET /orders, got %s", in[0].URI)
	}
}

func TestJavaInbound_gRPCServer(t *testing.T) {
	lines := []string{
		`Server server = ServerBuilder.forPort(50051)`,
		`    .addService(new OrderServiceImpl())`,
		`    .build().start();`,
	}
	in, _ := ExtractJavaTraffic("/app/GrpcServer.java", lines)
	protos := map[string]bool{}
	uris := map[string]bool{}
	for _, e := range in {
		protos[e.Protocol] = true
		uris[e.URI] = true
	}
	if !protos["gRPC"] {
		t.Errorf("want gRPC inbound, got: %v", in)
	}
	if !uris["gRPC Server"] && !uris["OrderService"] {
		t.Errorf("want gRPC Server or OrderService, got: %v", uris)
	}
}

func TestJavaInbound_KafkaListener(t *testing.T) {
	lines := []string{`@KafkaListener(topics = "order-events", groupId = "grp")`}
	in, _ := ExtractJavaTraffic("/app/Consumer.java", lines)
	if len(in) == 0 {
		t.Fatal("want KafkaListener inbound")
	}
	if in[0].Protocol != "Kafka" {
		t.Errorf("want Kafka, got %s", in[0].Protocol)
	}
	if in[0].URI != "order-events" {
		t.Errorf("want order-events, got %s", in[0].URI)
	}
}

// ── Java outbound ─────────────────────────────────────────────────────────────

func TestJavaOutbound_RestTemplate(t *testing.T) {
	lines := []string{
		`String result = restTemplate.getForObject("https://api.example.com/data", String.class);`,
	}
	_, out := ExtractJavaTraffic("/app/Client.java", lines)
	if len(out) != 1 {
		t.Fatalf("want 1 outbound, got %d: %v", len(out), out)
	}
	if out[0].Protocol != "REST" {
		t.Errorf("want REST, got %s", out[0].Protocol)
	}
	if out[0].URI != "https://api.example.com/data" {
		t.Errorf("unexpected URI: %s", out[0].URI)
	}
}

func TestJavaOutbound_HttpClientURI(t *testing.T) {
	lines := []string{
		`HttpRequest request = HttpRequest.newBuilder().uri(URI.create("https://payments.example.com/charge")).build();`,
	}
	_, out := ExtractJavaTraffic("/app/PaymentClient.java", lines)
	if len(out) == 0 {
		t.Fatal("want outbound for URI.create")
	}
	if out[0].Protocol != "REST" {
		t.Errorf("want REST, got %s", out[0].Protocol)
	}
}

func TestJavaOutbound_KafkaTemplate(t *testing.T) {
	lines := []string{`kafkaTemplate.send("payment-events", event);`}
	_, out := ExtractJavaTraffic("/app/Producer.java", lines)
	if len(out) == 0 {
		t.Fatal("want Kafka outbound")
	}
	if out[0].Protocol != "Kafka" {
		t.Errorf("want Kafka, got %s", out[0].Protocol)
	}
	if out[0].URI != "payment-events" {
		t.Errorf("want payment-events, got %s", out[0].URI)
	}
}

func TestJavaOutbound_Jedis(t *testing.T) {
	lines := []string{`Jedis jedis = new Jedis("localhost", 6379);`}
	_, out := ExtractJavaTraffic("/app/Cache.java", lines)
	if len(out) == 0 {
		t.Fatal("want Redis outbound")
	}
	if out[0].Protocol != "Redis" {
		t.Errorf("want Redis, got %s", out[0].Protocol)
	}
	if out[0].Port != "6379" {
		t.Errorf("want port 6379, got %s", out[0].Port)
	}
}

func TestJavaOutbound_gRPCChannel(t *testing.T) {
	lines := []string{
		`ManagedChannel channel = ManagedChannelBuilder.forAddress("inventory-service", 50051).usePlaintext().build();`,
	}
	_, out := ExtractJavaTraffic("/app/GrpcClient.java", lines)
	if len(out) == 0 {
		t.Fatal("want gRPC outbound")
	}
	if out[0].Protocol != "gRPC" {
		t.Errorf("want gRPC, got %s", out[0].Protocol)
	}
	if out[0].Port != "50051" {
		t.Errorf("want port 50051, got %s", out[0].Port)
	}
}

// ── RenderHTML ───────────────────────────────────────────────────────────────

func TestRenderHTML_EmptyReturnsNothing(t *testing.T) {
	m := Module{}
	html := m.RenderHTML(Result{})
	if html != "" {
		t.Errorf("expected empty HTML for empty result, got %q", html)
	}
}

func TestRenderHTML_TwoTables(t *testing.T) {
	m := Module{}
	r := Result{
		Inbound: []Entry{
			{URI: "GET /api/users", Protocol: "REST", DataFmt: "JSON", FilePath: "/app/routes.go", Line: 10},
		},
		Outbound: []Entry{
			{URI: "redis", Protocol: "Redis", FilePath: "/app/cache.go", Line: 5},
		},
	}
	html := m.RenderHTML(r)
	if !strings.Contains(html, "Inbound") {
		t.Error("expected 'Inbound' in HTML")
	}
	if !strings.Contains(html, "Outbound") {
		t.Error("expected 'Outbound' in HTML")
	}
	if !strings.Contains(html, "vscode://file/app/routes.go:10") {
		t.Error("expected vscode:// link in HTML")
	}
	if !strings.Contains(html, "background:#27ae60") {
		t.Error("expected REST protocol colour in HTML")
	}
	if !strings.Contains(html, "background:#e74c3c") {
		t.Error("expected Redis protocol colour in HTML")
	}
}

// ── SummaryCards ─────────────────────────────────────────────────────────────

func TestSummaryCards(t *testing.T) {
	m := Module{}
	r := Result{
		Inbound:  []Entry{{URI: "/api", Protocol: "REST"}},
		Outbound: []Entry{{URI: "kafka", Protocol: "Kafka"}, {URI: "redis", Protocol: "Redis"}},
	}
	cards := m.SummaryCards(r)
	if len(cards) != 1 {
		t.Fatalf("want 1 card, got %d", len(cards))
	}
	if cards[0].Num != "1 in · 2 out" {
		t.Errorf("want '1 in · 2 out', got %q", cards[0].Num)
	}
}
