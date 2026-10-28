package parser

import "regexp"

// reTextSearch matches a line of code that SEARCHES text for a pattern —
// strings.Contains(line, "redis://"), re.search(...), x.includes("kafka") — the
// way detectors (and any other tool that reads source) are written. The literal
// on such a line is the thing being looked for, not something the program does.
var reTextSearch = regexp.MustCompile(`\bstrings\.(?:Contains|ContainsAny|HasPrefix|HasSuffix|Index|EqualFold|Count|Split|TrimPrefix|TrimSuffix)\(|\bcontainsAny\(|\bsubstringAfter\(|\.(?:MatchString|FindString|FindStringSubmatch)\(|\bregexp\.(?:MustCompile|Compile)\(|\bre\.(?:search|match|compile|findall|sub)\(|\.(?:startswith|endswith)\(|\.(?:contains|includes|startsWith|endsWith|indexOf)\(\s*["']`)

// SearchesText reports whether line looks up a literal in text rather than using it.
func SearchesText(line string) bool { return reTextSearch.MatchString(line) }
