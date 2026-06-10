package traffic

import "strings"

// ExtractGoTraffic scans Go source lines for inbound and outbound connection
// signals using string-literal matching only — no AST, no imports required.
// Called from goParseHook in internal/lang/golang.go after ParseUniversal
// has already populated pf.Imports.
func ExtractGoTraffic(filePath string, lines []string, imports []string) (inbound, outbound []Entry) {
	dfmt := goFileFmt(imports)
	httpProto := "REST"
	if containsAny(imports, "golang.org/x/net/http2") {
		httpProto = "REST/H2"
	}

	seenIn := map[string]bool{}
	seenOut := map[string]bool{}
	addIn := func(e Entry) {
		k := e.URI + "|" + e.Protocol
		if !seenIn[k] {
			seenIn[k] = true
			e.FilePath = filePath
			inbound = append(inbound, e)
		}
	}
	addOut := func(e Entry) {
		k := e.URI + "|" + e.Protocol
		if !seenOut[k] {
			seenOut[k] = true
			e.FilePath = filePath
			outbound = append(outbound, e)
		}
	}

	for i, raw := range lines {
		ln := strings.TrimSpace(raw)
		if strings.HasPrefix(ln, "//") {
			continue
		}
		no := i + 1
		win := lookahead(lines, i, 6)

		// ── Inbound: HTTP listen ──────────────────────────────────────────────
		if sfx, ok := substringAfter(ln, "http.ListenAndServe(", "http.ListenAndServeTLS("); ok {
			port := portFromAddr(firstStrLit(sfx))
			addIn(Entry{URI: "HTTP Server", Port: port, Protocol: httpProto, DataFmt: dfmt, Line: no})
		}

		// Addr field: srv.Addr = ":8080" | &http.Server{Addr: ":8080"}
		if (strings.Contains(ln, ".Addr") || strings.Contains(ln, "Addr:")) && strings.Contains(ln, `"`) {
			s := firstStrLit(ln)
			if strings.HasPrefix(s, ":") && allDigits(s[1:]) {
				addIn(Entry{URI: "HTTP Server", Port: s[1:], Protocol: httpProto, DataFmt: dfmt, Line: no})
			}
		}

		// ── Inbound: HTTP route registration ─────────────────────────────────
		if path, method := extractGoRoute(ln); path != "" {
			uri := path
			if method != "" {
				uri = method + " " + path
			}
			addIn(Entry{URI: uri, Protocol: httpProto, DataFmt: dfmt, Line: no})
		}

		// ── Inbound: gRPC server ──────────────────────────────────────────────
		if strings.Contains(ln, "grpc.NewServer(") {
			addIn(Entry{URI: "gRPC Server", Protocol: "gRPC", DataFmt: "Protobuf", Line: no})
		}
		// pb.RegisterOrderServiceServer(s, &impl{})
		if idx := strings.Index(ln, "Register"); idx >= 0 {
			rest := ln[idx+len("Register"):]
			if sidx := strings.Index(rest, "Server("); sidx >= 0 {
				svc := rest[:sidx]
				if svc != "" && !strings.ContainsAny(svc, " \t.()") {
					addIn(Entry{URI: svc, Protocol: "gRPC", DataFmt: "Protobuf", Line: no})
				}
			}
		}

		// ── Inbound: WebSocket ────────────────────────────────────────────────
		if strings.Contains(ln, "websocket.Upgrader") || strings.Contains(ln, "Upgrader{") {
			addIn(Entry{URI: "WebSocket", Protocol: "WebSocket", Line: no})
		}
		if strings.Contains(ln, ".Upgrade(") && containsAny(imports, "websocket") {
			addIn(Entry{URI: "WebSocket", Protocol: "WebSocket", Line: no})
		}

		// ── Inbound: GraphQL ──────────────────────────────────────────────────
		if strings.Contains(ln, "graphql.NewHandler") || strings.Contains(ln, "graphqlHandler") {
			path := firstStrLit(ln)
			if path == "" || !strings.HasPrefix(path, "/") {
				path = "/graphql"
			}
			addIn(Entry{URI: path, Protocol: "GraphQL", DataFmt: "JSON", Line: no})
		}

		// ── Outbound: HTTP ────────────────────────────────────────────────────
		if sfx, ok := substringAfter(ln,
			"http.Get(", "http.Post(", "http.Head(", "http.Put(",
			"client.Get(", "client.Post(",
		); ok {
			url := firstStrLit(sfx)
			if isHTTPURL(url) {
				proto := httpProto
				if strings.HasPrefix(url, "https://") {
					proto = "REST/TLS"
				}
				addOut(Entry{URI: url, Port: portFromURL(url), Protocol: proto, DataFmt: dfmt, Line: no})
			}
		}
		if sfx, ok := substringAfter(ln, "http.NewRequest(", "http.NewRequestWithContext("); ok {
			url := nthStrLit(sfx, 2)
			if isHTTPURL(url) {
				addOut(Entry{URI: url, Port: portFromURL(url), Protocol: httpProto, DataFmt: dfmt, Line: no})
			}
		}

		// ── Outbound: gRPC dial ───────────────────────────────────────────────
		if sfx, ok := substringAfter(ln, "grpc.Dial(", "grpc.DialContext(", "grpc.NewClient("); ok {
			addr := firstStrLit(sfx)
			if addr != "" && !strings.HasPrefix(addr, "/") {
				addOut(Entry{URI: addr, Port: portFromAddr(addr), Protocol: "gRPC", DataFmt: "Protobuf", Line: no})
			}
		}

		// ── Outbound: Redis ───────────────────────────────────────────────────
		if strings.Contains(ln, "redis.NewClient(") || strings.Contains(ln, "redis.NewUniversalClient(") ||
			strings.Contains(ln, "redis.NewClusterClient(") {
			addr := findKVInWindow(append([]string{ln}, win...), "Addr:", "Addrs:")
			if addr == "" {
				addr = "redis"
			}
			addOut(Entry{URI: addr, Port: portFromAddr(addr), Protocol: "Redis", Line: no})
		}
		if s := firstStrLit(ln); strings.HasPrefix(s, "redis://") || strings.HasPrefix(s, "rediss://") {
			addOut(Entry{URI: s, Port: portFromURL(s), Protocol: "Redis", Line: no})
		}

		// ── Outbound: Kafka ───────────────────────────────────────────────────
		if strings.Contains(ln, "kafka.NewWriter(") || strings.Contains(ln, "kafka.NewReader(") ||
			strings.Contains(ln, "sarama.NewSyncProducer(") || strings.Contains(ln, "sarama.NewAsyncProducer(") {
			broker := findKVInWindow(append([]string{ln}, win...), "Brokers:")
			if broker == "" {
				broker = "kafka"
			}
			addOut(Entry{URI: broker, Port: portFromAddr(broker), Protocol: "Kafka", Line: no})
		}

		// ── Outbound: NATS ────────────────────────────────────────────────────
		if sfx, ok := substringAfter(ln, "nats.Connect(", "stan.Connect("); ok {
			url := firstStrLit(sfx)
			if url != "" {
				addOut(Entry{URI: url, Port: portFromURL(url), Protocol: "NATS", Line: no})
			}
		}

		// ── Outbound: AMQP / RabbitMQ ────────────────────────────────────────
		if sfx, ok := substringAfter(ln, "amqp.Dial(", "amqp091.Dial(", "amqp.DialTLS("); ok {
			url := firstStrLit(sfx)
			if url != "" {
				addOut(Entry{URI: url, Port: portFromURL(url), Protocol: "AMQP", Line: no})
			}
		}

		// ── Outbound: WebSocket ───────────────────────────────────────────────
		if sfx, ok := substringAfter(ln, "websocket.Dial(", "dialer.Dial("); ok {
			url := firstStrLit(sfx)
			if strings.HasPrefix(url, "ws") {
				addOut(Entry{URI: url, Port: portFromURL(url), Protocol: "WebSocket", Line: no})
			}
		}
		if s := firstStrLit(ln); (strings.HasPrefix(s, "ws://") || strings.HasPrefix(s, "wss://")) &&
			!strings.HasPrefix(ln, "//") {
			addOut(Entry{URI: s, Port: portFromURL(s), Protocol: "WebSocket", Line: no})
		}
	}
	return inbound, outbound
}

// extractGoRoute detects HTTP route registration patterns (gorilla, gin, echo,
// chi, fiber, stdlib) and returns (path, METHOD) or ("", "").
func extractGoRoute(ln string) (path, method string) {
	methodPatterns := [][2]string{
		{".GET(", "GET"}, {".Get(", "GET"},
		{".POST(", "POST"}, {".Post(", "POST"},
		{".PUT(", "PUT"}, {".Put(", "PUT"},
		{".DELETE(", "DELETE"}, {".Delete(", "DELETE"},
		{".PATCH(", "PATCH"}, {".Patch(", "PATCH"},
		{".OPTIONS(", "OPTIONS"}, {".Options(", "OPTIONS"},
		{".HEAD(", "HEAD"}, {".Head(", "HEAD"},
	}
	for _, pair := range methodPatterns {
		if sfx, ok := substringAfter(ln, pair[0]); ok {
			p := firstStrLit(sfx)
			if p != "" && strings.HasPrefix(p, "/") {
				return p, pair[1]
			}
		}
	}
	for _, pat := range []string{".HandleFunc(", ".Handle(", ".Route(", ".Any("} {
		if sfx, ok := substringAfter(ln, pat); ok {
			p := firstStrLit(sfx)
			if p != "" && strings.HasPrefix(p, "/") {
				return p, ""
			}
		}
	}
	return "", ""
}

// ── Shared low-level helpers ─────────────────────────────────────────────────

// substringAfter finds the first occurrence of any needle in s and returns the
// portion of s after that needle. The second return is true when found.
func substringAfter(s string, needles ...string) (string, bool) {
	for _, n := range needles {
		if idx := strings.Index(s, n); idx >= 0 {
			return s[idx+len(n):], true
		}
	}
	return "", false
}

// firstStrLit returns the content of the first double-quoted string literal in s.
func firstStrLit(s string) string {
	i := strings.IndexByte(s, '"')
	if i < 0 {
		return ""
	}
	j := i + 1
	for j < len(s) {
		if s[j] == '\\' {
			j += 2
			continue
		}
		if s[j] == '"' {
			return s[i+1 : j]
		}
		j++
	}
	return ""
}

// nthStrLit returns the nth (1-indexed) double-quoted string literal in s.
func nthStrLit(s string, n int) string {
	count := 0
	for len(s) > 0 {
		i := strings.IndexByte(s, '"')
		if i < 0 {
			return ""
		}
		s = s[i+1:]
		j, done := 0, false
		for j < len(s) {
			if s[j] == '\\' {
				j += 2
				continue
			}
			if s[j] == '"' {
				done = true
				break
			}
			j++
		}
		if !done {
			return ""
		}
		count++
		if count == n {
			return s[:j]
		}
		s = s[j+1:]
	}
	return ""
}

// portFromAddr extracts the port string from "host:port" or ":port" patterns.
func portFromAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		p := addr[1:]
		if allDigits(p) {
			return p
		}
	}
	if idx := strings.LastIndexByte(addr, ':'); idx >= 0 {
		p := addr[idx+1:]
		if allDigits(p) && len(p) <= 5 {
			return p
		}
	}
	return ""
}

// portFromURL extracts the port from a URL like "http://host:8080/path".
func portFromURL(u string) string {
	if idx := strings.Index(u, "://"); idx >= 0 {
		u = u[idx+3:]
	}
	if idx := strings.IndexByte(u, '/'); idx >= 0 {
		u = u[:idx]
	}
	return portFromAddr(u)
}

// isHTTPURL reports whether s starts with http:// or https://.
func isHTTPURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// lookahead returns up to n lines after index i in lines.
func lookahead(lines []string, i, n int) []string {
	end := i + 1 + n
	if end > len(lines) {
		end = len(lines)
	}
	return lines[i+1 : end]
}

// findKVInWindow searches a window of lines for `key "value"` or `key: "value"`
// patterns and returns the first string literal found after any matching key.
func findKVInWindow(lines []string, keys ...string) string {
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "//") {
			continue
		}
		for _, k := range keys {
			if idx := strings.Index(t, k); idx >= 0 {
				if s := firstStrLit(t[idx:]); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

// allDigits reports whether s is non-empty and contains only ASCII digit characters.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// containsAny reports whether any element of ss contains any of the needles.
func containsAny(ss []string, needles ...string) bool {
	for _, s := range ss {
		for _, n := range needles {
			if strings.Contains(s, n) {
				return true
			}
		}
	}
	return false
}

// goFileFmt infers a data format from Go import paths.
func goFileFmt(imports []string) string {
	for _, imp := range imports {
		if imp == "encoding/json" || strings.HasSuffix(imp, "/json") {
			return "JSON"
		}
	}
	for _, imp := range imports {
		if imp == "encoding/xml" {
			return "XML"
		}
		if strings.Contains(imp, "google.golang.org/protobuf") ||
			strings.Contains(imp, "golang/protobuf") {
			return "Protobuf"
		}
	}
	return ""
}
