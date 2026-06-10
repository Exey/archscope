package traffic

import "strings"

// ExtractPythonTraffic scans Python source lines for inbound and outbound
// connection signals. Called from pythonParseHook in internal/lang/python.go.
func ExtractPythonTraffic(filePath string, lines []string) (inbound, outbound []Entry) {
	dfmt := pyFileFmt(lines)

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
		if strings.HasPrefix(ln, "#") {
			continue
		}
		no := i + 1
		win := lookahead(lines, i, 4)

		// ── Inbound: Flask / FastAPI route decorators ─────────────────────────
		if strings.HasPrefix(ln, "@") {
			if path, method := pyExtractRoute(ln); path != "" {
				uri := path
				if method != "" {
					uri = method + " " + path
				}
				addIn(Entry{URI: uri, Protocol: "REST", DataFmt: dfmt, Line: no})
			}
			// DRF @api_view decorator
			if strings.HasPrefix(ln, "@api_view(") {
				addIn(Entry{URI: "API endpoint", Protocol: "REST", DataFmt: dfmt, Line: no})
			}
		}

		// ── Inbound: Django URL patterns (urls.py) ────────────────────────────
		// re_path / url must be checked before path() because re_path contains "path("
		if sfx, ok := substringAfter(ln, "re_path(", "url("); ok {
			p := pyFirstStrLit(sfx)
			if p != "" {
				p = strings.TrimPrefix(p, "^")
				p = strings.TrimSuffix(p, "$")
				if !strings.HasPrefix(p, "/") {
					p = "/" + p
				}
				addIn(Entry{URI: p, Protocol: "REST", DataFmt: dfmt, Line: no})
			}
		} else if sfx, ok := substringAfter(ln, "path("); ok {
			// plain Django 2+ path() — only match url-like strings (contain / or <>)
			p := pyFirstStrLit(sfx)
			if p != "" && (strings.Contains(p, "/") || strings.Contains(p, "<")) {
				if !strings.HasPrefix(p, "/") {
					p = "/" + p
				}
				addIn(Entry{URI: p, Protocol: "REST", DataFmt: dfmt, Line: no})
			}
		}
		// DRF router.register(r'prefix', ViewSet)
		if sfx, ok := substringAfter(ln, "router.register("); ok {
			prefix := pyFirstStrLit(sfx)
			if prefix != "" {
				prefix = strings.TrimPrefix(prefix, "^")
				if !strings.HasPrefix(prefix, "/") {
					prefix = "/" + prefix
				}
				addIn(Entry{URI: prefix, Protocol: "REST", DataFmt: dfmt, Line: no})
			}
		}

		// ── Inbound: HTTP server startup ──────────────────────────────────────
		if strings.Contains(ln, "app.run(") || strings.Contains(ln, "uvicorn.run(") ||
			strings.Contains(ln, "gunicorn.run(") {
			port := pyExtractPort(append([]string{ln}, win...))
			addIn(Entry{URI: "HTTP Server", Port: port, Protocol: "REST", DataFmt: dfmt, Line: no})
		}
		// Django manage.py entry point
		if strings.Contains(ln, "execute_from_command_line(") {
			addIn(Entry{URI: "HTTP Server", Protocol: "REST", DataFmt: dfmt, Line: no})
		}

		// ── Inbound: gRPC server ──────────────────────────────────────────────
		if strings.Contains(ln, "grpc.server(") || strings.Contains(ln, "aio.server(") {
			addIn(Entry{URI: "gRPC Server", Protocol: "gRPC", DataFmt: "Protobuf", Line: no})
		}
		if sfx, ok := substringAfter(ln, "add_insecure_port(", "add_secure_port("); ok {
			addr := firstStrLit(sfx)
			if addr == "" {
				addr = pyFirstStrLit(sfx)
			}
			addIn(Entry{URI: "gRPC Server", Port: portFromAddr(addr), Protocol: "gRPC", DataFmt: "Protobuf", Line: no})
		}

		// ── Outbound: requests / httpx ────────────────────────────────────────
		if sfx, ok := substringAfter(ln,
			"requests.get(", "requests.post(", "requests.put(", "requests.delete(", "requests.patch(",
			"requests.request(", "httpx.get(", "httpx.post(", "httpx.put(", "httpx.delete(",
			"httpx.request(",
		); ok {
			url := pyFirstStrLit(sfx)
			if isHTTPURL(url) {
				addOut(Entry{URI: url, Port: portFromURL(url), Protocol: "REST", DataFmt: dfmt, Line: no})
			}
		}

		// aiohttp: session.get/post or ClientSession(base_url=...)
		if sfx, ok := substringAfter(ln, "session.get(", "session.post(", "aiohttp.ClientSession("); ok {
			url := pyFirstStrLit(sfx)
			if isHTTPURL(url) {
				addOut(Entry{URI: url, Port: portFromURL(url), Protocol: "REST", DataFmt: dfmt, Line: no})
			}
		}

		// ── Outbound: Redis ───────────────────────────────────────────────────
		if strings.Contains(ln, "redis.Redis(") || strings.Contains(ln, "StrictRedis(") ||
			strings.Contains(ln, "aioredis.from_url(") || strings.Contains(ln, "Redis.from_url(") {
			addr := pyRedisAddr(append([]string{ln}, win...))
			if addr == "" {
				addr = "redis"
			}
			addOut(Entry{URI: addr, Port: portFromAddr(addr), Protocol: "Redis", Line: no})
		}
		if sfx, ok := substringAfter(ln, "redis.from_url(", "redis.asyncio.from_url("); ok {
			url := pyFirstStrLit(sfx)
			if url != "" {
				addOut(Entry{URI: url, Port: portFromURL(url), Protocol: "Redis", Line: no})
			}
		}

		// ── Outbound: Kafka ───────────────────────────────────────────────────
		if strings.Contains(ln, "KafkaProducer(") || strings.Contains(ln, "KafkaConsumer(") ||
			strings.Contains(ln, "AIOKafkaProducer(") || strings.Contains(ln, "AIOKafkaConsumer(") {
			broker := findKVInWindow(append([]string{ln}, win...), "bootstrap_servers=", "bootstrap_servers:")
			if broker == "" {
				broker = pyFirstStrLit(append([]string{ln}, win...)...)
			}
			if broker == "" {
				broker = "kafka"
			}
			addOut(Entry{URI: broker, Port: portFromAddr(broker), Protocol: "Kafka", Line: no})
		}

		// ── Outbound: NATS ────────────────────────────────────────────────────
		if sfx, ok := substringAfter(ln, "nats.connect(", "nats.aio.connect("); ok {
			url := pyFirstStrLit(sfx)
			if url != "" {
				addOut(Entry{URI: url, Port: portFromURL(url), Protocol: "NATS", Line: no})
			}
		}

		// ── Outbound: AMQP / RabbitMQ ─────────────────────────────────────────
		if sfx, ok := substringAfter(ln, "pika.BlockingConnection(", "aio_pika.connect(", "aio_pika.connect_robust("); ok {
			url := pyFirstStrLit(sfx)
			if url != "" {
				addOut(Entry{URI: url, Port: portFromURL(url), Protocol: "AMQP", Line: no})
			}
		}

		// ── Outbound: WebSocket ───────────────────────────────────────────────
		if sfx, ok := substringAfter(ln,
			"websockets.connect(", "websocket.create_connection(", "websocket.WebSocketApp(",
		); ok {
			url := pyFirstStrLit(sfx)
			if url != "" {
				addOut(Entry{URI: url, Port: portFromURL(url), Protocol: "WebSocket", Line: no})
			}
		}
		if s := pyFirstStrLit(ln); (strings.HasPrefix(s, "ws://") || strings.HasPrefix(s, "wss://")) &&
			!strings.HasPrefix(ln, "#") {
			addOut(Entry{URI: s, Port: portFromURL(s), Protocol: "WebSocket", Line: no})
		}
	}
	return inbound, outbound
}

// pyExtractRoute parses a single-line Python decorator and returns (path, METHOD).
// Handles Flask @app.route, FastAPI @router.get/@app.get, Django path helpers.
func pyExtractRoute(ln string) (path, method string) {
	methodMap := map[string]string{
		".get(": "GET", ".post(": "POST", ".put(": "PUT",
		".delete(": "DELETE", ".patch(": "PATCH",
		".options(": "OPTIONS", ".head(": "HEAD",
		".websocket(": "WS",
	}
	// Method-specific decorators: @router.get("/path") @app.post("/path")
	for pat, m := range methodMap {
		if sfx, ok := substringAfter(ln, pat); ok {
			p := pyFirstStrLit(sfx)
			if p != "" && strings.HasPrefix(p, "/") {
				return p, m
			}
		}
	}
	// @app.route("/path") or @bp.route("/path")
	if sfx, ok := substringAfter(ln, ".route("); ok {
		p := pyFirstStrLit(sfx)
		if p != "" && strings.HasPrefix(p, "/") {
			return p, ""
		}
	}
	return "", ""
}

// pyExtractPort extracts port from app.run(port=8080) or uvicorn.run(app, port=8080).
func pyExtractPort(lines []string) string {
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if idx := strings.Index(t, "port="); idx >= 0 {
			rest := t[idx+5:]
			if len(rest) > 0 && rest[0] == '"' {
				return firstStrLit(rest)
			}
			if len(rest) > 0 && rest[0] == '\'' {
				return pyFirstStrLit(rest)
			}
			j := 0
			for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
				j++
			}
			if j > 0 {
				return rest[:j]
			}
		}
	}
	return ""
}

// pyRedisAddr extracts a host:port string from redis.Redis(host="...", port=...).
func pyRedisAddr(lines []string) string {
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if idx := strings.Index(t, "host="); idx >= 0 {
			host := pyFirstStrLit(t[idx:])
			port := ""
			if pidx := strings.Index(t, "port="); pidx >= 0 {
				rest := t[pidx+5:]
				j := 0
				for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
					j++
				}
				if j > 0 {
					port = rest[:j]
				}
			}
			if host != "" && port != "" {
				return host + ":" + port
			}
			if host != "" {
				return host
			}
		}
	}
	return ""
}

// pyFileFmt infers a data format by scanning a Python file for import keywords.
func pyFileFmt(lines []string) string {
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if strings.Contains(t, "import json") || strings.Contains(t, "from json") ||
			strings.Contains(t, "jsonify(") || strings.Contains(t, "json.dumps(") ||
			strings.Contains(t, "json.loads(") {
			return "JSON"
		}
		if strings.Contains(t, "import xml") || strings.Contains(t, "from xml") ||
			strings.Contains(t, "ElementTree") {
			return "XML"
		}
		if strings.Contains(t, "import grpc") || strings.Contains(t, "_pb2") {
			return "Protobuf"
		}
	}
	return ""
}

// pyFirstStrLit extracts the first single- or double-quoted string literal
// from s, preferring double quotes.
func pyFirstStrLit(ss ...string) string {
	for _, s := range ss {
		if r := firstStrLit(s); r != "" {
			return r
		}
		i := strings.IndexByte(s, '\'')
		if i < 0 {
			continue
		}
		j := i + 1
		for j < len(s) {
			if s[j] == '\\' {
				j += 2
				continue
			}
			if s[j] == '\'' {
				if v := s[i+1 : j]; v != "" {
					return v
				}
				break
			}
			j++
		}
	}
	return ""
}
