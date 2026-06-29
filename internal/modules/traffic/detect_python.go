package traffic

import "strings"

// ExtractPythonTraffic scans Python source lines for inbound and outbound
// connection signals. Called from pythonParseHook in internal/lang/python.go.
func ExtractPythonTraffic(filePath string, lines []string) (inbound, outbound []Entry) {
	dfmt := pyFileFmt(lines)
	routerPrefixes := pyBuildRouterPrefixMap(lines)

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
		// DRF router.register(r'prefix', ViewSet) — matches router_v3, api_router, etc.
		if strings.Contains(strings.ToLower(ln), "router") {
			if sfx, ok := substringAfter(ln, ".register("); ok {
				// Route string may be on the next line for multi-line calls
				route := pyFirstStrLit(append([]string{sfx}, win...)...)
				if route != "" {
					route = strings.TrimPrefix(route, "^")
					varName := pyRouterVarName(ln)
					urlPrefix := routerPrefixes[varName]
					var uri string
					if urlPrefix != "" {
						uri = "/" + strings.Trim(urlPrefix, "/") + "/" + strings.TrimPrefix(route, "/")
					} else {
						if !strings.HasPrefix(route, "/") {
							route = "/" + route
						}
						uri = route
					}
					addIn(Entry{URI: uri, Protocol: "REST", DataFmt: dfmt, Line: no})
				}
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

		// ── Inbound: Telegram bot long-polling ───────────────────────────────
		if strings.Contains(ln, "Bot(") &&
			(strings.Contains(strings.Join(win, " "), "polling") ||
				strings.Contains(ln, "aiogram") || strings.Contains(ln, "Dispatcher")) {
			addIn(Entry{URI: "Telegram API", Protocol: "Long Polling (HTTPS)", DataFmt: "JSON", Line: no})
		}
		if strings.Contains(ln, "application.run_polling(") || strings.Contains(ln, "executor.start_polling(") ||
			strings.Contains(ln, "dp.run_polling(") || strings.Contains(ln, "bot.polling(") ||
			strings.Contains(ln, "bot.infinity_polling(") {
			addIn(Entry{URI: "Telegram API", Protocol: "Long Polling (HTTPS)", DataFmt: "JSON", Line: no})
		}

		// ── Outbound: PostgreSQL ──────────────────────────────────────────────
		if sfx, ok := substringAfter(ln, "psycopg2.connect(", "asyncpg.connect(", "asyncpg.create_pool("); ok {
			addr := pyDSNHost(append([]string{sfx}, win...), "PostgreSQL")
			port := pyDSNPort(append([]string{sfx}, win...), "5432")
			addOut(Entry{URI: addr, Port: port, Protocol: "PostgreSQL", Line: no})
		}
		if sfx, ok := substringAfter(ln, "create_engine("); ok {
			url := pyFirstStrLit(sfx)
			if strings.HasPrefix(url, "postgresql") || strings.HasPrefix(url, "postgres") {
				addOut(Entry{URI: hostFromURL(url), Port: portFromURL(url), Protocol: "PostgreSQL", Line: no})
			} else if strings.HasPrefix(url, "mysql") {
				addOut(Entry{URI: hostFromURL(url), Port: portFromURL(url), Protocol: "MySQL", Line: no})
			} else if strings.HasPrefix(url, "sqlite") {
				addOut(Entry{URI: url, Protocol: "SQLite", Line: no})
			} else if url != "" {
				addOut(Entry{URI: url, Protocol: "Database", Line: no})
			}
		}
		// Raw postgresql:// URLs anywhere in line
		if s := pyFirstStrLit(ln); (strings.HasPrefix(s, "postgres://") || strings.HasPrefix(s, "postgresql://")) &&
			!strings.HasPrefix(ln, "#") {
			addOut(Entry{URI: hostFromURL(s), Port: portFromURL(s), Protocol: "PostgreSQL", Line: no})
		}

		// ── Outbound: MySQL ───────────────────────────────────────────────────
		if sfx, ok := substringAfter(ln, "pymysql.connect(", "aiomysql.connect(", "MySQLdb.connect("); ok {
			host := findKVInWindow(append([]string{sfx}, win...), "host=", "host:")
			if host == "" {
				host = "MySQL"
			}
			port := findKVInWindow(append([]string{sfx}, win...), "port=", "port:")
			if port == "" {
				port = "3306"
			}
			addOut(Entry{URI: host, Port: port, Protocol: "MySQL", Line: no})
		}

		// ── Outbound: SMTP ────────────────────────────────────────────────────
		if sfx, ok := substringAfter(ln, "smtplib.SMTP(", "smtplib.SMTP_SSL(", "smtplib.LMTP("); ok {
			host := pyFirstStrLit(sfx)
			port := ""
			// port is usually the second positional argument
			if i := strings.Index(sfx, ","); i >= 0 {
				rest := strings.TrimSpace(sfx[i+1:])
				port = pyFirstStrLit(rest)
				if port == "" {
					// might be a bare number
					for _, tok := range strings.Fields(rest) {
						tok = strings.TrimRight(tok, ",)")
						if allDigits(tok) {
							port = tok
							break
						}
					}
				}
			}
			addr := host
			if port != "" {
				addr = host + ":" + port
			}
			addOut(Entry{URI: addr, Port: port, Protocol: "SMTP", Line: no})
		}

		// ── Outbound: TCP socket ──────────────────────────────────────────────
		if sfx, ok := substringAfter(ln, "asyncio.open_connection("); ok {
			host := pyFirstStrLit(sfx)
			port := ""
			if i := strings.Index(sfx, ","); i >= 0 {
				rest := strings.TrimSpace(sfx[i+1:])
				for _, tok := range strings.Fields(rest) {
					tok = strings.TrimRight(tok, ",)")
					if allDigits(tok) {
						port = tok
						break
					}
				}
			}
			if host != "" {
				addr := host
				if port != "" {
					addr = host + ":" + port
				}
				addOut(Entry{URI: addr, Port: port, Protocol: "TCP", Line: no})
			}
		}
		if strings.Contains(ln, ".connect((") || strings.Contains(ln, ".connect((") {
			// socket.connect(("host", port))
			ctx := append([]string{ln}, win...)
			host := pyFirstStrLit(ctx...)
			if host != "" && !strings.HasPrefix(host, "/") {
				addOut(Entry{URI: host, Protocol: "TCP", Line: no})
			}
		}
	}
	return inbound, outbound
}

// pyDSNHost extracts host from psycopg2-style connect() kwargs.
func pyDSNHost(lines []string, fallback string) string {
	for _, ln := range lines {
		if h := findKVInWindow([]string{ln}, "host=", "host:"); h != "" {
			return h
		}
	}
	return fallback
}

// pyDSNPort extracts port from psycopg2-style connect() kwargs.
func pyDSNPort(lines []string, defaultPort string) string {
	for _, ln := range lines {
		if p := findKVInWindow([]string{ln}, "port=", "port:"); p != "" {
			return p
		}
	}
	return defaultPort
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

// pyBuildRouterPrefixMap scans lines for path('prefix/', include(router_name.urls))
// and returns a map of routerVarName → urlPrefix. Handles two cases:
//  1. Single-line: path("api/v3/", include(router_v3.urls))
//  2. Nested: path("", include(router.urls)) nested inside path("api/v1/", include(...))
func pyBuildRouterPrefixMap(lines []string) map[string]string {
	type pending struct {
		lineIdx int
		name    string
	}
	var needBackscan []pending
	prefixes := map[string]string{}

	for idx, raw := range lines {
		ln := strings.TrimSpace(raw)
		if strings.HasPrefix(ln, "#") {
			continue
		}
		includeIdx := strings.Index(ln, "include(")
		if includeIdx < 0 {
			continue
		}
		sfx := ln[includeIdx+len("include("):]
		dotIdx := strings.Index(sfx, ".urls")
		if dotIdx < 0 {
			continue
		}
		routerName := strings.TrimSpace(sfx[:dotIdx])
		if routerName == "" || strings.ContainsAny(routerName, " \t()\"',") {
			continue
		}
		if _, ok := substringAfter(ln, "path(", "url(", "re_path("); ok {
			if p := pyFirstStrLit(ln); p != "" {
				prefixes[routerName] = strings.TrimPrefix(p, "^")
				continue
			}
		}
		// Same-line prefix not found (empty string or no path() on this line);
		// queue for backward indent-aware scan.
		needBackscan = append(needBackscan, pending{idx, routerName})
	}

	for _, p := range needBackscan {
		if _, already := prefixes[p.name]; already {
			continue
		}
		myIndent := pyIndentLevel(lines[p.lineIdx])
		for j := p.lineIdx - 1; j >= 0; j-- {
			braw := lines[j]
			bln := strings.TrimSpace(braw)
			if bln == "" || strings.HasPrefix(bln, "#") {
				continue
			}
			if pyIndentLevel(braw) >= myIndent {
				continue // same or deeper — not an enclosing block
			}
			if !strings.Contains(bln, "path(") && !strings.Contains(bln, "url(") {
				continue
			}
			prefix := pyFirstStrLit(bln)
			if prefix == "" && j+1 < len(lines) {
				// path( on its own line; string is on the next line
				prefix = pyFirstStrLit(strings.TrimSpace(lines[j+1]))
			}
			if prefix != "" && strings.Contains(prefix, "/") {
				prefixes[p.name] = strings.TrimPrefix(prefix, "^")
				break
			}
		}
	}
	return prefixes
}

// pyIndentLevel returns the number of leading spaces/tabs in a raw (untrimmed) line.
func pyIndentLevel(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' && s[i] != '\t' {
			return i
		}
	}
	return len(s)
}

// pyRouterVarName extracts the variable name immediately before .register( in ln.
func pyRouterVarName(ln string) string {
	idx := strings.Index(ln, ".register(")
	if idx < 0 {
		return ""
	}
	i := idx - 1
	for i >= 0 && (ln[i] == '_' || (ln[i] >= 'a' && ln[i] <= 'z') || (ln[i] >= 'A' && ln[i] <= 'Z') || (ln[i] >= '0' && ln[i] <= '9')) {
		i--
	}
	return ln[i+1 : idx]
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
