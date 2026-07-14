package traffic

import "strings"

// scanOutboundURLs finds every quoted string literal on a line (double,
// single, or backtick-delimited — TS/JS and Kotlin both use all three) and
// returns one Entry per http/https/ws/wss literal found, with protocol and
// data format inferred from the rest of the line and the port extracted from
// the literal itself. Shared by the Swift/Kotlin/TypeScript client-platform
// detectors — ported from ArchSwiftScope's TrafficScanner.detectOutboundURLs.
func scanOutboundURLs(line string, no int) []Entry {
	var out []Entry
	i := 0
	for i < len(line) {
		c := line[i]
		if c != '"' && c != '\'' && c != '`' {
			i++
			continue
		}
		j := strings.IndexByte(line[i+1:], c)
		if j < 0 {
			break
		}
		lit := line[i+1 : i+1+j]
		i = i + 1 + j + 1

		isHTTP := strings.HasPrefix(lit, "http://") || strings.HasPrefix(lit, "https://")
		isWS := strings.HasPrefix(lit, "ws://") || strings.HasPrefix(lit, "wss://")
		if !(isHTTP || isWS) || len(lit) < 10 {
			continue
		}
		proto := "WebSocket"
		dfmt := ""
		if !isWS {
			proto = classifyWebProtocol(line)
			dfmt = classifyDataFormat(line)
		}
		out = append(out, Entry{URI: lit, Port: portFromURL(lit), Protocol: proto, DataFmt: dfmt, Line: no})
	}
	return out
}

// classifyWebProtocol infers REST/gRPC/GraphQL/WebSocket from keywords
// anywhere on the line carrying the URL literal.
func classifyWebProtocol(line string) string {
	low := strings.ToLower(line)
	switch {
	case strings.Contains(low, "grpc"):
		return "gRPC"
	case strings.Contains(low, "graphql"):
		return "GraphQL"
	case strings.Contains(low, "websocket"):
		return "WebSocket"
	}
	return "REST"
}

// classifyDataFormat infers JSON/Protobuf/XML from keywords on the line.
func classifyDataFormat(line string) string {
	low := strings.ToLower(line)
	switch {
	case strings.Contains(low, "protobuf"), strings.Contains(low, ".proto"):
		return "Protobuf"
	case strings.Contains(low, "xml"):
		return "XML"
	case strings.Contains(low, "json"), strings.Contains(low, "codable"), strings.Contains(low, "decodable"):
		return "JSON"
	}
	return ""
}

// clientBlockComment tracks /* … */ state across a single-pass client-
// language line scan (Swift/Kotlin/TS all use C-style block comments).
type clientBlockComment struct{ inBlock bool }

// skip reports whether the trimmed line should be skipped as comment text,
// updating block-comment state as it goes.
func (c *clientBlockComment) skip(t string) bool {
	if c.inBlock {
		if strings.Contains(t, "*/") {
			c.inBlock = false
		}
		return true
	}
	if strings.HasPrefix(t, "/*") {
		if !strings.Contains(t, "*/") {
			c.inBlock = true
		}
		return true
	}
	return strings.HasPrefix(t, "//")
}
