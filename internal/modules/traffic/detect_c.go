package traffic

import "regexp"

// C/C++ traffic detection, string-literal only — same approach as the Swift
// raw-TCP detector: no semantic understanding of sockaddr structs or libcurl
// option chains, just recognizable call/literal shapes on a single line.
var (
	reCListenOrBind = regexp.MustCompile(`\b(listen|bind)\s*\(`)
	reCPortLiteral  = regexp.MustCompile(`\bhtons\s*\(\s*(\d+)\s*\)`)
	reCCurlURL      = regexp.MustCompile(`CURLOPT_URL\s*,\s*"([^"]+)"`)
	reCURLLiteral   = regexp.MustCompile(`"(https?://[^"\s]+)"`)
)

// ExtractCTraffic scans raw C/C++ source lines for socket-level bind/listen
// (inbound) and connect/libcurl URL (outbound) signals.
func ExtractCTraffic(filePath string, lines []string) (inbound, outbound []Entry) {
	for i, line := range lines {
		lineNo := i + 1

		if reCListenOrBind.MatchString(line) {
			port := ""
			if m := reCPortLiteral.FindStringSubmatch(line); len(m) > 1 {
				port = m[1]
			}
			inbound = append(inbound, Entry{
				URI: "socket", Port: port, Protocol: "TCP",
				FilePath: filePath, Line: lineNo,
			})
			continue
		}

		if m := reCCurlURL.FindStringSubmatch(line); len(m) > 1 {
			outbound = append(outbound, Entry{
				URI: m[1], Protocol: "HTTP", FilePath: filePath, Line: lineNo,
			})
			continue
		}
		if m := reCURLLiteral.FindStringSubmatch(line); len(m) > 1 {
			outbound = append(outbound, Entry{
				URI: m[1], Protocol: "HTTP", FilePath: filePath, Line: lineNo,
			})
		}
	}
	return inbound, outbound
}
