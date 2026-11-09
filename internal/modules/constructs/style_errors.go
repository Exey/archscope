// style_errors.go holds the error-handling health rules of the Style & design
// subcard, by the boundary the error crosses:
//
//   - OS: a failing os call whose error is dropped, or a library that exits the process,
//   - HTTP: calls with no timeout, a response whose status or body is never looked at,
//   - gRPC: handlers that return plain errors, which clients see as codes.Unknown.
//
// Lexical, like the rest of the subcard: a rule looks a few lines ahead inside the
// same function and stays quiet when it sees the handling.
package constructs

import (
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/security"
)

var (
	// os.Remove(path) on a line of its own, or `_ = os.Remove(path)`
	reGoOSDropped = regexp.MustCompile(`^\s*(?:_\s*(?:,\s*_\s*)?=\s*)?os\.(?:Remove|RemoveAll|Rename|Mkdir|MkdirAll|WriteFile|Chmod|Chown|Chdir|Setenv|Unsetenv|Truncate|Symlink|Link)\(`)
	reGoExit      = regexp.MustCompile(`\b(?:os\.Exit|log\.Fatal(?:f|ln)?)\(`)
	reGoHTTPCall  = regexp.MustCompile(`(\w+)\s*,\s*(?:err|_)\s*:?=\s*(?:http\.(?:Get|Post|PostForm|Head)|\w+\.Do)\(`)
	reGoDefClient = regexp.MustCompile(`\bhttp\.(?:Get|Post|PostForm|Head)\(|&?http\.Client\{\s*\}`)
	reGoHandler   = regexp.MustCompile(`^func\s*\([^)]*\)\s*(\w+)\s*\(\s*\w*\s*(?:context\.Context)\s*,[^)]*\)\s*\(\s*\*?[\w.]+\s*,\s*error\s*\)`)
	reGoPlainErr  = regexp.MustCompile(`\breturn\s+(?:nil|&?[\w.]+\{\}),\s*(?:errors\.New|fmt\.Errorf)\(`)
	rePyReqCall   = regexp.MustCompile(`\brequests\.(?:get|post|put|patch|delete|head|request)\(|\bhttpx\.(?:get|post|put|patch|delete|head)\(`)
	rePyReqAssign = regexp.MustCompile(`^\s*(\w+)\s*=\s*(?:requests|httpx)\.`)
)

// scanErrors runs the error-handling rules for Go and Python files.
func (c *styleCtx) scanErrors() {
	if security.IsTestOrBenchPath(c.path) {
		return
	}
	switch c.fe {
	case ".go":
		c.scanGoErrors()
	case ".py":
		c.scanPyHTTP()
	}
}

// window returns the code lines after i up to (excluding) the next top-level
// declaration, at most n of them.
func (c *styleCtx) window(i, n int, top string) string {
	var b strings.Builder
	for j := i + 1; j < len(c.m.code) && j <= i+n; j++ {
		if strings.HasPrefix(c.m.code[j], top) {
			break
		}
		b.WriteString(c.m.code[j])
		b.WriteByte('\n')
	}
	return b.String()
}

func (c *styleCtx) scanGoErrors() {
	rawFile := strings.Join(c.m.raw, "\n")
	grpc := strings.Contains(rawFile, `"google.golang.org/grpc`)
	isProgram := strings.Contains("/"+strings.ToLower(c.path), "/cmd/") || baseName(c.path) == "main.go"
	for _, l := range c.m.code {
		if strings.HasPrefix(strings.TrimSpace(l), "func main()") {
			isProgram = true
		}
	}
	inMain := false
	for i, l := range c.m.code {
		if strings.HasPrefix(l, "func ") {
			inMain = strings.HasPrefix(l, "func main(") || strings.HasPrefix(l, "func init(")
		}
		if reGoOSDropped.MatchString(l) {
			c.add(i, security.SevLow, "err-os-ignored", "Error from an os call is dropped",
				"os.Remove, Rename, Mkdir, WriteFile … fail on permissions, a full disk or a missing path. Check the error (or log it when a failure really is harmless) so the program does not carry on as if it had worked.", "os", false)
		}
		if !isProgram && !inMain && reGoExit.MatchString(l) {
			c.add(i, security.SevMedium, "err-os-exit", "Library code ends the process",
				"os.Exit and log.Fatal skip every deferred cleanup and take the decision away from the caller. Return the error and let main decide.", "exit", false)
		}
		if m := reGoHTTPCall.FindStringSubmatch(l); m != nil {
			w := c.window(i, 25, "func ")
			resp := regexp.QuoteMeta(m[1])
			if !rx(`\b`+resp+`\.(?:StatusCode|Status)\b`).MatchString(w) && !strings.Contains(w, "return "+m[1]) {
				c.add(i, security.SevMedium, "err-http-status", "HTTP status is never checked",
					"A 404 or 500 comes back with a nil error. Look at resp.StatusCode before using the body, or the failure shows up later as a confusing decode error.", "status", false)
			}
			if !rx(`\b`+resp+`\.Body\.Close\(`).MatchString(w) && !strings.Contains(w, "return "+m[1]) && !strings.Contains(w, "("+m[1]+")") {
				c.add(i, security.SevMedium, "err-http-body", "Response body is not closed",
					"Not closing resp.Body leaks the connection. `defer resp.Body.Close()` right after the error check.", "body", false)
			}
		}
		if reGoDefClient.MatchString(l) && !strings.Contains(l, "Timeout") {
			c.add(i, security.SevMedium, "err-http-timeout", "HTTP call without a timeout",
				"http.Get/http.Post and an empty http.Client{} wait forever on a stalled server. Use &http.Client{Timeout: …} or a request context with a deadline.", "timeout", false)
		}
		if grpc && reGoHandler.MatchString(l) {
			end := matchBraceEnd(c.m.code, i)
			for j := i + 1; end > i && j < end; j++ {
				if reGoPlainErr.MatchString(c.m.code[j]) {
					c.add(j, security.SevLow, "err-grpc-plain", "gRPC handler returns a plain error",
						"Clients see codes.Unknown with the message. Return status.Error(codes.InvalidArgument | NotFound | Internal …, msg) so they can react to the failure kind.", "grpc", false)
					break
				}
			}
		}
	}
}

func (c *styleCtx) scanPyHTTP() {
	for i, l := range c.m.code {
		if !rePyReqCall.MatchString(l) {
			continue
		}
		call := l
		for j := i + 1; j < len(c.m.code) && j <= i+4 && strings.Count(call, "(") > strings.Count(call, ")"); j++ {
			call += " " + c.m.code[j]
		}
		if !strings.Contains(call, "timeout") {
			c.add(i, security.SevMedium, "err-http-timeout", "HTTP call without a timeout",
				"requests and httpx wait forever by default (requests) or 5s (httpx). Pass timeout=… so a stalled server cannot hang the caller.", "timeout", false)
		}
		if m := rePyReqAssign.FindStringSubmatch(l); m != nil {
			w := c.window(i, 12, "def ")
			if !strings.Contains(w, m[1]+".raise_for_status") && !strings.Contains(w, m[1]+".status_code") && !strings.Contains(w, m[1]+".ok") {
				c.add(i, security.SevMedium, "err-http-status", "HTTP status is never checked",
					"A 404 or 500 does not raise by itself. Call response.raise_for_status() or look at status_code before using the body.", "status", false)
			}
		}
	}
}
