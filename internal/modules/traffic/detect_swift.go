package traffic

import (
	"strconv"
	"strings"
)

// ExtractSwiftTraffic scans Swift source lines for inbound and outbound
// connection signals — ported from ArchSwiftScope's TrafficScanner
// (Sources/CodeContext/Core/TrafficScanner.swift):
//
//	Outbound: http/https/ws/wss URL string literals; NWConnection (TCP
//	client); NWPathMonitor (reachability); SCNetworkReachabilityCreateWith…
//	(SystemConfiguration); BSD SOCK_STREAM socket(); CFStreamCreatePairWith…
//	Inbound: Vapor-style route definitions (app.get/post/…); NWListener (TCP
//	server).
//
// Called from swiftParseHook in internal/lang/swift.go.
func ExtractSwiftTraffic(filePath string, lines []string) (inbound, outbound []Entry) {
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

		if e, ok := detectVaporRoute(t, no); ok {
			addIn(e)
			continue
		}
		if e, ok := detectSwiftTCPInbound(t, no); ok {
			addIn(e)
		}
		for _, e := range scanOutboundURLs(t, no) {
			addOut(e)
		}
		if e, ok := detectSwiftTCPOutbound(t, no); ok {
			addOut(e)
		}
	}
	return inbound, outbound
}

// detectVaporRoute recognizes Vapor-style server route registration:
// app.get("/path") { … }, routes.post("/path") { … }, etc.
func detectVaporRoute(line string, no int) (Entry, bool) {
	prefixes := []string{"app.", "routes.", "router.", "grouped."}
	methods := []string{"get", "post", "put", "patch", "delete", "on"}
	low := strings.ToLower(line)
	for _, prefix := range prefixes {
		if !strings.Contains(low, prefix) {
			continue
		}
		for _, method := range methods {
			marker := prefix + method + "("
			idx := strings.Index(low, marker)
			if idx < 0 {
				continue
			}
			path := firstStrLit(line[idx+len(marker):])
			if path != "" && strings.HasPrefix(path, "/") {
				return Entry{URI: path, Protocol: "REST", DataFmt: "JSON", Line: no}, true
			}
		}
	}
	return Entry{}, false
}

// detectSwiftTCPInbound recognizes Network.framework's NWListener TCP server.
func detectSwiftTCPInbound(line string, no int) (Entry, bool) {
	if !strings.Contains(line, "NWListener(") {
		return Entry{}, false
	}
	port := extractSwiftTCPPort(line)
	uri := "NWListener"
	if port != "" {
		uri = ":" + port
	}
	return Entry{URI: uri, Port: port, Protocol: "TCP", Line: no}, true
}

// detectSwiftTCPOutbound recognizes the raw-TCP client APIs ArchSwiftScope's
// scanner covers: NWConnection, NWPathMonitor, SCNetworkReachability, BSD
// SOCK_STREAM sockets, and CFStreamCreatePairWithSocketToHost.
func detectSwiftTCPOutbound(line string, no int) (Entry, bool) {
	if strings.Contains(line, "NWConnection(") {
		host := firstStrLit(line)
		port := extractSwiftTCPPort(line)
		uri := "NWConnection"
		switch {
		case host != "" && port != "":
			uri = host + ":" + port
		case host != "":
			uri = host
		}
		return Entry{URI: uri, Port: port, Protocol: "TCP", Line: no}, true
	}
	if strings.Contains(line, "NWPathMonitor(") {
		return Entry{URI: "NWPathMonitor", Protocol: "TCP", Line: no}, true
	}
	if strings.Contains(line, "SCNetworkReachabilityCreateWithName") ||
		strings.Contains(line, "SCNetworkReachabilityCreateWithAddress") {
		host := firstStrLit(line)
		uri := "SCNetworkReachability"
		if host != "" {
			uri = host
		}
		return Entry{URI: uri, Protocol: "TCP", Line: no}, true
	}
	low := strings.ToLower(line)
	if strings.Contains(low, "sock_stream") &&
		(strings.Contains(low, "af_inet") || strings.Contains(low, "af_inet6") || strings.Contains(low, "pf_inet")) {
		return Entry{URI: "BSD socket", Protocol: "TCP", Line: no}, true
	}
	if strings.Contains(line, "CFStreamCreatePairWithSocketToHost") {
		host := firstStrLit(line)
		port := extractSwiftTCPPort(line)
		uri := "CFStream"
		switch {
		case host != "" && port != "":
			uri = host + ":" + port
		case host != "":
			uri = host
		}
		return Entry{URI: uri, Port: port, Protocol: "TCP", Line: no}, true
	}
	return Entry{}, false
}

// extractSwiftTCPPort extracts a port from TCP API call patterns:
// rawValue: 443, NWEndpoint.Port(8080), port: 8080, on: 8080.
func extractSwiftTCPPort(line string) string {
	for _, label := range []string{"rawValue:", "NWEndpoint.Port(", "port:", " on:"} {
		idx := strings.Index(line, label)
		if idx < 0 {
			continue
		}
		rest := strings.TrimLeft(line[idx+len(label):], " \t")
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		digits := rest[:end]
		if digits == "" {
			continue
		}
		if n, err := strconv.Atoi(digits); err == nil && n > 0 && n <= 65535 {
			return digits
		}
	}
	return ""
}
