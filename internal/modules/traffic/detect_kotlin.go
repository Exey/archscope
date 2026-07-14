package traffic

import (
	"regexp"
	"strings"
)

// ExtractKotlinTraffic scans Kotlin source lines for inbound and outbound
// connection signals:
//
//	Inbound: Ktor routing DSL (get("/path") { … }, post("/path") { … }) and
//	Spring MVC annotations (@GetMapping("/path"), @RequestMapping("/path")).
//	Outbound: http/https/ws/wss URL string literals, and Retrofit interface
//	method annotations (@GET("/path"), @POST("/path")) — a Retrofit method is
//	itself the definition of an outbound call the app makes to a backend.
//
// Called from kotlinParseHook in internal/lang/kotlin.go.
func ExtractKotlinTraffic(filePath string, lines []string) (inbound, outbound []Entry) {
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

		if e, ok := detectKotlinRoute(t, no); ok {
			addIn(e)
		}
		if e, ok := detectKotlinRetrofitCall(t, no); ok {
			addOut(e)
		}
		for _, e := range scanOutboundURLs(t, no) {
			addOut(e)
		}
	}
	return inbound, outbound
}

// reKtorRoute matches Ktor's routing DSL: get("/users") { … }.
var reKtorRoute = regexp.MustCompile(`(?:^|[^\w.])(?:get|post|put|delete|patch|head|options)\s*\(\s*"([^"]*)"`)

// reSpringMapping matches Spring MVC's mapping annotations, with or without
// an explicit "value =" label: @GetMapping("/users"), @RequestMapping(value = "/users").
var reSpringMapping = regexp.MustCompile(`@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?"([^"]*)"`)

// reRetrofitCall matches a Retrofit interface method's HTTP annotation:
// @GET("users/{id}"), @POST("orders").
var reRetrofitCall = regexp.MustCompile(`@(?:GET|POST|PUT|DELETE|PATCH|HEAD)\s*\(\s*"([^"]*)"`)

func detectKotlinRoute(line string, no int) (Entry, bool) {
	if m := reKtorRoute.FindStringSubmatch(line); m != nil && strings.HasPrefix(m[1], "/") {
		return Entry{URI: m[1], Protocol: "REST", DataFmt: "JSON", Line: no}, true
	}
	if m := reSpringMapping.FindStringSubmatch(line); m != nil {
		path := m[1]
		if path == "" {
			return Entry{}, false
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		return Entry{URI: path, Protocol: "REST", DataFmt: "JSON", Line: no}, true
	}
	return Entry{}, false
}

func detectKotlinRetrofitCall(line string, no int) (Entry, bool) {
	m := reRetrofitCall.FindStringSubmatch(line)
	if m == nil {
		return Entry{}, false
	}
	path := m[1]
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return Entry{URI: path, Protocol: "REST", DataFmt: "JSON", Line: no}, true
}
