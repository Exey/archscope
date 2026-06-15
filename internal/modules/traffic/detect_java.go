package traffic

import "strings"

// ExtractJavaTraffic scans Java source lines for inbound and outbound
// connection signals. Called from javaParseHook in internal/lang/java.go.
func ExtractJavaTraffic(filePath string, lines []string) (inbound, outbound []Entry) {
	dfmt := javaFileFmt(lines)
	classPrefix := javaClassRequestMapping(lines)

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
		if strings.HasPrefix(ln, "//") || strings.HasPrefix(ln, "*") {
			continue
		}
		no := i + 1
		win := lookahead(lines, i, 4)

		// ── Inbound: Spring MVC annotations ──────────────────────────────────
		if path, method := javaSpringMapping(ln); path != "" {
			full := javaJoinPath(classPrefix, path)
			uri := full
			if method != "" {
				uri = method + " " + full
			}
			addIn(Entry{URI: uri, Protocol: "REST", DataFmt: dfmt, Line: no})
		}

		// ── Inbound: JAX-RS @Path ─────────────────────────────────────────────
		if strings.HasPrefix(ln, "@Path(") {
			if path := javaFirstStrLit(ln); path != "" {
				full := javaJoinPath(classPrefix, path)
				method := ""
				for _, wl := range win {
					wt := strings.TrimSpace(wl)
					if m, ok := jaxRSMethod(wt); ok {
						method = m
						break
					}
					if strings.Contains(wt, " class ") || strings.Contains(wt, " interface ") {
						break
					}
				}
				uri := full
				if method != "" {
					uri = method + " " + full
				}
				addIn(Entry{URI: uri, Protocol: "REST", DataFmt: dfmt, Line: no})
			}
		}

		// ── Inbound: Spring Boot startup ──────────────────────────────────────
		if strings.Contains(ln, "SpringApplication.run(") {
			addIn(Entry{URI: "HTTP Server", Protocol: "REST", DataFmt: dfmt, Line: no})
		}

		// ── Inbound: gRPC server ──────────────────────────────────────────────
		if strings.Contains(ln, "ServerBuilder.forPort(") || strings.Contains(ln, "NettyServerBuilder.forPort(") {
			sfx, _ := substringAfter(ln, "forPort(")
			port := leadingDigits(sfx)
			addIn(Entry{URI: "gRPC Server", Port: port, Protocol: "gRPC", DataFmt: "Protobuf", Line: no})
		}
		if strings.Contains(ln, ".addService(") {
			if svc := javaServiceName(ln); svc != "" {
				addIn(Entry{URI: svc, Protocol: "gRPC", DataFmt: "Protobuf", Line: no})
			}
		}

		// ── Inbound: WebSocket server endpoint ────────────────────────────────
		if strings.HasPrefix(ln, "@ServerEndpoint(") {
			if path := javaFirstStrLit(ln); path != "" {
				addIn(Entry{URI: path, Protocol: "WebSocket", Line: no})
			}
		}

		// ── Inbound: Kafka consumer ───────────────────────────────────────────
		if strings.HasPrefix(ln, "@KafkaListener(") {
			topic := javaKVStr(append([]string{ln}, win...), "topics", "topicPattern")
			if topic == "" {
				topic = "kafka"
			}
			addIn(Entry{URI: topic, Protocol: "Kafka", Line: no})
		}

		// ── Inbound: RabbitMQ consumer ────────────────────────────────────────
		if strings.HasPrefix(ln, "@RabbitListener(") {
			queue := javaKVStr(append([]string{ln}, win...), "queues", "queuesToDeclare")
			if queue == "" {
				queue = "amqp"
			}
			addIn(Entry{URI: queue, Protocol: "AMQP", Line: no})
		}

		// ── Outbound: RestTemplate ────────────────────────────────────────────
		if sfx, ok := substringAfter(ln,
			".getForObject(", ".postForObject(", ".putForObject(",
			".getForEntity(", ".postForEntity(",
			".exchange(", ".execute(",
		); ok {
			if strings.Contains(ln, "restTemplate") || strings.Contains(ln, "RestTemplate") {
				if url := javaFirstStrLit(sfx); isHTTPURL(url) {
					addOut(Entry{URI: url, Port: portFromURL(url), Protocol: "REST", DataFmt: dfmt, Line: no})
				}
			}
		}

		// ── Outbound: WebClient (reactive) ────────────────────────────────────
		if strings.Contains(ln, ".uri(") {
			if url := javaFirstStrLit(ln); isHTTPURL(url) {
				addOut(Entry{URI: url, Port: portFromURL(url), Protocol: "REST", DataFmt: dfmt, Line: no})
			}
		}

		// ── Outbound: Java HttpClient (11+) URI.create ────────────────────────
		if sfx, ok := substringAfter(ln, "URI.create("); ok {
			if url := javaFirstStrLit(sfx); isHTTPURL(url) {
				addOut(Entry{URI: url, Port: portFromURL(url), Protocol: "REST", DataFmt: dfmt, Line: no})
			}
		}

		// ── Outbound: Apache HttpClient ───────────────────────────────────────
		if sfx, ok := substringAfter(ln, "new HttpGet(", "new HttpPost(", "new HttpPut(",
			"new HttpDelete(", "new HttpPatch("); ok {
			if url := javaFirstStrLit(sfx); isHTTPURL(url) {
				addOut(Entry{URI: url, Port: portFromURL(url), Protocol: "REST", DataFmt: dfmt, Line: no})
			}
		}

		// ── Outbound: OkHttp Request.Builder().url(…) ────────────────────────
		if sfx, ok := substringAfter(ln, ".url("); ok {
			if strings.Contains(ln, "Request") || strings.Contains(ln, "OkHttp") {
				if url := javaFirstStrLit(sfx); isHTTPURL(url) {
					addOut(Entry{URI: url, Port: portFromURL(url), Protocol: "REST", DataFmt: dfmt, Line: no})
				}
			}
		}

		// ── Outbound: Kafka producer ──────────────────────────────────────────
		if strings.Contains(ln, "kafkaTemplate.send(") || strings.Contains(ln, "KafkaTemplate") && strings.Contains(ln, ".send(") {
			sfx, _ := substringAfter(ln, ".send(")
			topic := javaFirstStrLit(sfx)
			if topic == "" {
				topic = "kafka"
			}
			addOut(Entry{URI: topic, Protocol: "Kafka", Line: no})
		}
		if strings.Contains(ln, "new KafkaProducer") {
			broker := findKVInWindow(append([]string{ln}, win...), "bootstrap.servers", "BOOTSTRAP_SERVERS_CONFIG")
			if broker == "" {
				broker = "kafka"
			}
			addOut(Entry{URI: broker, Port: portFromAddr(broker), Protocol: "Kafka", Line: no})
		}

		// ── Outbound: RabbitMQ ────────────────────────────────────────────────
		if strings.Contains(ln, "rabbitTemplate.convertAndSend(") || strings.Contains(ln, "RabbitTemplate") && strings.Contains(ln, ".send(") {
			sfx, _ := substringAfter(ln, ".convertAndSend(", ".send(")
			dest := javaFirstStrLit(sfx)
			if dest == "" {
				dest = "amqp"
			}
			addOut(Entry{URI: dest, Protocol: "AMQP", Line: no})
		}

		// ── Outbound: Redis (Jedis) ───────────────────────────────────────────
		if sfx, ok := substringAfter(ln, "new Jedis("); ok {
			host := javaFirstStrLit(sfx)
			port := ""
			if pidx := strings.Index(sfx, ","); pidx >= 0 {
				port = leadingDigits(strings.TrimSpace(sfx[pidx+1:]))
			}
			if host == "" {
				host = "redis"
			}
			addr := host
			if port != "" {
				addr = host + ":" + port
			}
			addOut(Entry{URI: addr, Port: port, Protocol: "Redis", Line: no})
		}
		if sfx, ok := substringAfter(ln, "RedisStandaloneConfiguration(", "RedisURI.create(", "new RedisClient("); ok {
			addr := javaFirstStrLit(sfx)
			if addr == "" {
				addr = "redis"
			}
			addOut(Entry{URI: addr, Port: portFromAddr(addr), Protocol: "Redis", Line: no})
		}

		// ── Outbound: gRPC client ─────────────────────────────────────────────
		if sfx, ok := substringAfter(ln, "ManagedChannelBuilder.forAddress(", "forTarget("); ok {
			host := javaFirstStrLit(sfx)
			port := ""
			if pidx := strings.Index(sfx, ","); pidx >= 0 {
				port = leadingDigits(strings.TrimSpace(sfx[pidx+1:]))
			}
			addr := host
			if port != "" && host != "" {
				addr = host + ":" + port
			}
			if addr == "" {
				addr = "grpc-service"
			}
			addOut(Entry{URI: addr, Port: port, Protocol: "gRPC", DataFmt: "Protobuf", Line: no})
		}

		// ── Outbound: NATS ────────────────────────────────────────────────────
		if sfx, ok := substringAfter(ln, "Nats.connect("); ok {
			if url := javaFirstStrLit(sfx); url != "" {
				addOut(Entry{URI: url, Port: portFromURL(url), Protocol: "NATS", Line: no})
			}
		}

		// ── Outbound: WebSocket strings ───────────────────────────────────────
		if s := javaFirstStrLit(ln); (strings.HasPrefix(s, "ws://") || strings.HasPrefix(s, "wss://")) &&
			!strings.HasPrefix(ln, "//") {
			addOut(Entry{URI: s, Port: portFromURL(s), Protocol: "WebSocket", Line: no})
		}
	}
	return inbound, outbound
}

// javaSpringMapping detects Spring MVC route annotations and returns (path, METHOD).
func javaSpringMapping(ln string) (path, method string) {
	type ann struct {
		prefix string
		method string
	}
	anns := []ann{
		{"@GetMapping(", "GET"},
		{"@PostMapping(", "POST"},
		{"@PutMapping(", "PUT"},
		{"@DeleteMapping(", "DELETE"},
		{"@PatchMapping(", "PATCH"},
		{"@RequestMapping(", ""},
	}
	for _, a := range anns {
		if sfx, ok := substringAfter(ln, a.prefix); ok {
			// @GetMapping("/path") or @GetMapping(value = "/path", ...)
			p := javaFirstStrLit(sfx)
			if p != "" {
				return p, a.method
			}
		}
	}
	return "", ""
}

// javaClassRequestMapping returns the @RequestMapping path found at class level
// (i.e., the annotation is followed within a few lines by a class declaration).
func javaClassRequestMapping(lines []string) string {
	for i, raw := range lines {
		ln := strings.TrimSpace(raw)
		sfx, ok := substringAfter(ln, "@RequestMapping(")
		if !ok {
			continue
		}
		prefix := javaFirstStrLit(sfx)
		if prefix == "" {
			continue
		}
		for j := i + 1; j < len(lines) && j <= i+6; j++ {
			t := strings.TrimSpace(lines[j])
			if t == "" || strings.HasPrefix(t, "@") || strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") {
				continue
			}
			if strings.Contains(t, " class ") || strings.Contains(t, " interface ") {
				return prefix
			}
			break
		}
	}
	return ""
}

// javaJoinPath combines a class-level prefix with a method-level path.
func javaJoinPath(prefix, path string) string {
	if prefix == "" {
		return path
	}
	p := strings.TrimRight(prefix, "/")
	s := strings.TrimLeft(path, "/")
	if s == "" {
		return p
	}
	return p + "/" + s
}

// jaxRSMethod returns the HTTP method for a JAX-RS annotation line (@GET, @POST, …).
func jaxRSMethod(ln string) (method string, ok bool) {
	for _, m := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"} {
		if ln == "@"+m || strings.HasPrefix(ln, "@"+m+" ") || strings.HasPrefix(ln, "@"+m+"\t") {
			return m, true
		}
	}
	return "", false
}

// javaServiceName extracts a gRPC service name from `.addService(impl)`.
func javaServiceName(ln string) string {
	sfx, _ := substringAfter(ln, ".addService(")
	sfx = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sfx), "new "))
	i := 0
	for i < len(sfx) && (sfx[i] == '_' || (sfx[i] >= 'A' && sfx[i] <= 'Z') ||
		(sfx[i] >= 'a' && sfx[i] <= 'z') || (sfx[i] >= '0' && sfx[i] <= '9')) {
		i++
	}
	name := sfx[:i]
	name = strings.TrimSuffix(name, "Impl")
	name = strings.TrimSuffix(name, "Grpc")
	name = strings.TrimSuffix(name, "Service")
	return name
}

// javaKVStr finds the first string value for any of the given keys in annotation lines.
// Handles: topics = "foo", topics = {"foo", "bar"}.
func javaKVStr(lines []string, keys ...string) string {
	for _, l := range lines {
		t := strings.TrimSpace(l)
		for _, key := range keys {
			idx := strings.Index(t, key)
			if idx < 0 {
				continue
			}
			sfx := strings.TrimLeft(t[idx+len(key):], " \t=")
			// Strip array braces: {"topic"} → "topic"
			sfx = strings.TrimPrefix(sfx, "{")
			if v := javaFirstStrLit(sfx); v != "" {
				return v
			}
		}
	}
	return ""
}

// javaFirstStrLit returns the first double- or single-quoted string literal in s.
func javaFirstStrLit(s string) string {
	if v := firstStrLit(s); v != "" {
		return v
	}
	return pyFirstStrLit(s)
}

// javaFileFmt infers data format by scanning imports/annotations.
func javaFileFmt(lines []string) string {
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") {
			continue
		}
		if strings.Contains(t, "ObjectMapper") || strings.Contains(t, "JsonNode") ||
			strings.Contains(t, "APPLICATION_JSON") || strings.Contains(t, "fasterxml.jackson") {
			return "JSON"
		}
		if strings.Contains(t, ".proto") || strings.Contains(t, "MessageLite") ||
			strings.Contains(t, "com.google.protobuf") {
			return "Protobuf"
		}
		if strings.Contains(t, "XmlRootElement") || strings.Contains(t, "JAXB") ||
			strings.Contains(t, "APPLICATION_XML") {
			return "XML"
		}
	}
	return ""
}

// leadingDigits returns the leading digit sequence from s.
func leadingDigits(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}
