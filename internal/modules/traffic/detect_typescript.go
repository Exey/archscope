package traffic

import (
	"regexp"
	"strings"
)

// ExtractTypeScriptTraffic scans TypeScript/JavaScript source lines for
// inbound and outbound connection signals:
//
//	Inbound: Express/Fastify-style route registration (app.get("/path", …),
//	router.post("/path", …), fastify.get("/path", …)).
//	Outbound: http/https/ws/wss URL string/template literals — this already
//	covers fetch("url"), axios.get("url"), and `new WebSocket("wss://…")`
//	since each passes a literal straight to scanOutboundURLs; no separate
//	fetch/axios detector is needed.
//
// Called from tsParseHook in internal/lang/typescript.go.
func ExtractTypeScriptTraffic(filePath string, lines []string) (inbound, outbound []Entry) {
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

	var bc clientBlockComment
	for i, raw := range lines {
		t := strings.TrimSpace(raw)
		if bc.skip(t) {
			continue
		}
		no := i + 1

		if e, ok := detectTSRoute(t, no); ok {
			addIn(e)
		}
		for _, e := range scanOutboundURLs(t, no) {
			addOut(e)
		}
	}
	return inbound, outbound
}

// reExpressRoute matches Express/Fastify-style route registration:
// app.get("/users", …), router.post('/orders', …), fastify.get(`/users`, …).
var reExpressRoute = regexp.MustCompile("(?:app|router|fastify|server)\\.(?:get|post|put|delete|patch|head|options|all)\\s*\\(\\s*[\"'`]([^\"'`]+)[\"'`]")

func detectTSRoute(line string, no int) (Entry, bool) {
	m := reExpressRoute.FindStringSubmatch(line)
	if m == nil || !strings.HasPrefix(m[1], "/") {
		return Entry{}, false
	}
	return Entry{URI: m[1], Protocol: "REST", DataFmt: "JSON", Line: no}, true
}
