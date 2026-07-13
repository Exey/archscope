package constructs

import (
	"fmt"
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
)

func init() { modules.Default.Register(MagicConstants{}) }

// MagicConstants detects well-known algorithm implementations from the "magic
// constants" they depend on — literal values baked into an algorithm's
// definition (hash primes, checksum polynomials, cryptographic initialization
// vectors, PRNG coefficients) that only ever show up in code implementing that
// exact algorithm.
//
// Precision over recall: the table omits short/low-entropy literals that
// collide with ordinary code, and every literal is matched by numeric value
// (not raw text) so 0x01000193, 0x1000193 and 16_777_619 all resolve to the
// same match — except values under 2^16, common enough in ordinary code
// (ports, counts, ids) that only their hex spelling counts as evidence.
//
// Ported from ArchSwiftScope's MagicConstantDetector; the numeric-value
// matching and per-function attribution follow it, generalized from Swift-only
// to every language ArchScope parses.
type MagicConstants struct{}

func (MagicConstants) ID() string                       { return "magicconstants" }
func (MagicConstants) Title() string                    { return "Magic Constants" }
func (MagicConstants) AppliesTo(languageID string) bool { return true } // universal

// mcCategory groups detected constants by the algorithm family they belong to.
type mcCategory struct {
	label string
	icon  string
}

var (
	mcHash     = mcCategory{"Hash Functions", "#️⃣"}
	mcChecksum = mcCategory{"Checksums", "🧮"}
	mcCrypto   = mcCategory{"Cryptographic", "🔐"}
	mcPRNG     = mcCategory{"Pseudo-Random Generators", "🎲"}
)

var mcCategoryOrder = []mcCategory{mcHash, mcChecksum, mcCrypto, mcPRNG}

// rawConstant maps a literal (by numeric value) to the algorithm it identifies.
type rawConstant struct {
	value    uint64
	name     string
	category mcCategory
}

// rawConstants is the magic-constant table. Several cryptographic hashes share
// their leading initialization words by design (MD5/SHA-1 both descend from the
// same Merkle–Damgård lineage), so those are labeled jointly.
var rawConstants = []rawConstant{
	// FNV-1 / FNV-1a
	{0x01000193, "FNV-1/1a (32-bit prime)", mcHash},
	{0x811c9dc5, "FNV-1/1a (32-bit offset basis)", mcHash},
	{0x00000100000001b3, "FNV-1/1a (64-bit prime)", mcHash},
	{0xcbf29ce484222325, "FNV-1/1a (64-bit offset basis)", mcHash},

	// Checksums
	{0xedb88320, "CRC-32 (reflected polynomial)", mcChecksum},
	{0x04c11db7, "CRC-32 (polynomial)", mcChecksum},
	{0x1edc6f41, "CRC-32C / Castagnoli (polynomial)", mcChecksum},
	{0x8005, "CRC-16/IBM (polynomial)", mcChecksum},
	{0x1021, "CRC-16/CCITT (polynomial)", mcChecksum},
	{0x42f0e1eba9ea3693, "CRC-64/XZ (polynomial)", mcChecksum},

	// MD5 / SHA
	{0x67452301, "MD5 / SHA-1 (initialization vector)", mcCrypto},
	{0xefcdab89, "MD5 / SHA-1 (initialization vector)", mcCrypto},
	{0x98badcfe, "MD5 / SHA-1 (initialization vector)", mcCrypto},
	{0x10325476, "MD5 / SHA-1 (initialization vector)", mcCrypto},
	{0xc3d2e1f0, "SHA-1 (initialization vector)", mcCrypto},
	{0x6a09e667, "SHA-256 (initialization vector)", mcCrypto},
	{0xbb67ae85, "SHA-256 (initialization vector)", mcCrypto},
	{0x3c6ef372, "SHA-256 (initialization vector)", mcCrypto},
	{0xa54ff53a, "SHA-256 (initialization vector)", mcCrypto},
	{0x510e527f, "SHA-256 (initialization vector)", mcCrypto},
	{0x9b05688c, "SHA-256 (initialization vector)", mcCrypto},
	{0x1f83d9ab, "SHA-256 (initialization vector)", mcCrypto},
	{0x5be0cd19, "SHA-256 (initialization vector)", mcCrypto},

	// PRNGs
	{0x9908b0df, "Mersenne Twister (MT19937 matrix A)", mcPRNG},
	{0x6c078965, "Mersenne Twister (MT19937 seed step)", mcPRNG},
	{0x2545f4914f6cdd1d, "xorshift64star", mcPRNG},
	{0x9e3779b9, "Fibonacci hashing (32-bit golden ratio)", mcHash},
	{0x9e3779b97f4a7c15, "Fibonacci hashing / SplitMix64 (64-bit golden ratio)", mcPRNG},
	{0xbf58476d1ce4e5b9, "SplitMix64 (mix constant)", mcPRNG},
	{0x94d049bb133111eb, "SplitMix64 (mix constant)", mcPRNG},

	// Non-cryptographic hashes
	{0x5bd1e995, "MurmurHash2", mcHash},
	{0xcc9e2d51, "MurmurHash3", mcHash},
	{0x1b873593, "MurmurHash3", mcHash},
	{0x85ebca6b, "MurmurHash3 (finalizer)", mcHash},
	{0xc2b2ae35, "MurmurHash3 (finalizer)", mcHash},
	{0xff51afd7ed558ccd, "MurmurHash3 (64-bit finalizer)", mcHash},
	{0xc4ceb9fe1a85ec53, "MurmurHash3 (64-bit finalizer)", mcHash},
	// djb2's seed (5381) is deliberately absent: it has no natural hex spelling
	// (nobody writes 0x1505), so it can't be hex-gated the way the low-entropy
	// CRC-16 polynomials are, and as a bare decimal it's indistinguishable from
	// an ordinary small integer literal.
}

// lowEntropyThreshold: below this, a literal is common enough in ordinary code
// (a port, a count, an id) that decimal form alone isn't evidence — 0x8005 and
// 0x1021 only count as hits when the source actually wrote them in hex.
const lowEntropyThreshold uint64 = 1 << 16

// numericConstant is a resolved table entry keyed by decimal-string value.
type numericConstant struct {
	name     string
	category mcCategory
}

// constantByValue maps a literal's decimal-string value to its algorithm.
var constantByValue = func() map[string]numericConstant {
	m := make(map[string]numericConstant, len(rawConstants))
	for _, rc := range rawConstants {
		key := strconv.FormatUint(rc.value, 10)
		if cur, ok := m[key]; ok {
			// Duplicate value: join labels rather than silently dropping one.
			m[key] = numericConstant{cur.name + " / " + rc.name, cur.category}
			continue
		}
		m[key] = numericConstant{rc.name, rc.category}
	}
	return m
}()

// stringConstants are string literals that only appear as an algorithm's fixed
// constant.
var stringConstants = map[string]numericConstant{
	"expand 32-byte k": {"ChaCha20 / Salsa20 (256-bit key constant)", mcCrypto},
	"expand 16-byte k": {"ChaCha20 / Salsa20 (128-bit key constant)", mcCrypto},
}

// Occurrence and Match for magic constants mirror the other detectors' shapes.
type mcOccurrence struct {
	Symbol   string // enclosing function, or "(top level)"
	FilePath string
	Line     int
}

type mcMatch struct {
	Name        string
	Category    mcCategory
	Count       int
	Occurrences []mcOccurrence
}

// MagicConstantResult is the module output.
type MagicConstantResult struct {
	Matches []mcMatch
}

func (r MagicConstantResult) HasDetection() bool { return len(r.Matches) > 0 }

// Analyze scans each file's stripped source and string literals for magic
// constants, attributing each hit to its enclosing function.
func (MagicConstants) Analyze(files []*parser.ParsedFile) any {
	cache := newSourceCache()
	found := map[string]*mcMatch{}

	record := func(nc numericConstant, symbol, path string, line int) {
		m := found[nc.name]
		if m == nil {
			m = &mcMatch{Name: nc.name, Category: nc.category}
			found[nc.name] = m
		}
		m.Count++
		m.Occurrences = append(m.Occurrences, mcOccurrence{Symbol: symbol, FilePath: path, Line: line})
	}

	for _, f := range files {
		// Skip a detector's own source: a file whose job is to spell out these
		// very literals would otherwise "detect" every algorithm in the table.
		if isConstructDetectorFile(f.FilePath) {
			continue
		}
		stripped := cache.lines(f.FilePath)
		if stripped == nil {
			continue
		}
		stringsByLine := cache.stringLiterals(f.FilePath)
		ranges := funcRanges(stripped)
		symbolAt := func(line int) string { return enclosingSymbol(ranges, line) }

		for i, code := range stripped {
			for _, tok := range numericTokens(code) {
				hit, ok := constantByValue[tok.value]
				if !ok {
					continue
				}
				// Below the threshold, decimal form alone isn't distinctive —
				// require the source to have actually written hex.
				if v, err := strconv.ParseUint(tok.value, 10, 64); err == nil &&
					v < lowEntropyThreshold && !tok.isHex {
					continue
				}
				record(hit, symbolAt(i), f.FilePath, i+1)
			}
			if stringsByLine != nil {
				for _, s := range stringsByLine[i] {
					if hit, ok := stringConstants[s]; ok {
						record(hit, symbolAt(i), f.FilePath, i+1)
					}
				}
			}
		}
	}

	matches := make([]mcMatch, 0, len(found))
	for _, m := range found {
		matches = append(matches, *m)
	}
	sort.SliceStable(matches, func(i, j int) bool {
		ci, cj := mcCategoryRank(matches[i].Category), mcCategoryRank(matches[j].Category)
		if ci != cj {
			return ci < cj
		}
		if matches[i].Count != matches[j].Count {
			return matches[i].Count > matches[j].Count
		}
		return matches[i].Name < matches[j].Name
	})
	return MagicConstantResult{Matches: matches}
}

// ── numeric literal extraction ───────────────────────────────────────────────

// reNumericLit matches a hex or decimal integer literal (underscores allowed).
// Go's RE2 has no lookaround, so the leading (^|[^\w.]) group rejects a
// preceding word char or '.', and trailing boundary checks (word char, or '.'
// followed by a digit — a float) are applied in numericTokens.
var reNumericLit = regexp.MustCompile(`(^|[^\w.])(0[xX][0-9a-fA-F_]+|[0-9][0-9_]*)`)

type numTok struct {
	value string // decimal-string form of the value
	isHex bool
}

// numericTokens extracts every integer literal on a line and normalizes it to
// its decimal value, so 0x0100_0193 and 16777619 compare equal.
func numericTokens(line string) []numTok {
	if !strings.ContainsAny(line, "0123456789") {
		return nil
	}
	var out []numTok
	for _, m := range reNumericLit.FindAllStringSubmatchIndex(line, -1) {
		// m[4],m[5] = group 2 (the literal) start/end.
		lit := line[m[4]:m[5]]
		end := m[5]
		// Trailing boundary: reject if immediately followed by a word char
		// (part of a longer identifier/number) or by ".<digit>" (a float).
		if end < len(line) {
			nb := line[end]
			if isIdentByte(nb) {
				continue
			}
			if nb == '.' && end+1 < len(line) && line[end+1] >= '0' && line[end+1] <= '9' {
				continue
			}
		}
		if v, hex, ok := normalizedValue(lit); ok {
			out = append(out, numTok{value: v, isHex: hex})
		}
	}
	return out
}

// normalizedValue parses a literal (underscores stripped) into its decimal
// string form, reporting whether it was written in hex.
func normalizedValue(raw string) (value string, isHex, ok bool) {
	cleaned := strings.ReplaceAll(raw, "_", "")
	if strings.HasPrefix(cleaned, "0x") || strings.HasPrefix(cleaned, "0X") {
		v, err := strconv.ParseUint(cleaned[2:], 16, 64)
		if err != nil {
			return "", false, false
		}
		return strconv.FormatUint(v, 10), true, true
	}
	v, err := strconv.ParseUint(cleaned, 10, 64)
	if err != nil {
		return "", false, false
	}
	return strconv.FormatUint(v, 10), false, true
}

// ── symbol attribution ───────────────────────────────────────────────────────

type funcRange struct {
	name       string
	start, end int // inclusive line indices
}

var reFuncDecl = regexp.MustCompile(`(^|[^\w.])(?:func|fn|fun|function)\s+(\w+)`)

// funcRanges brace-matches every function declaration to its body range, so a
// hit can be attributed to the innermost enclosing function.
func funcRanges(stripped []string) []funcRange {
	var ranges []funcRange
	for i, line := range stripped {
		m := reFuncDecl.FindStringSubmatch(line)
		if m == nil || m[2] == "" {
			continue
		}
		end := matchBraceEnd(stripped, i)
		if end < 0 {
			continue
		}
		ranges = append(ranges, funcRange{name: m[2], start: i, end: end})
	}
	return ranges
}

// matchBraceEnd returns the line index where the brace opened at/after startLine
// closes, or -1 when the function has no body braces on/after that line.
func matchBraceEnd(stripped []string, startLine int) int {
	depth, started := 0, false
	for j := startLine; j < len(stripped); j++ {
		for k := 0; k < len(stripped[j]); k++ {
			switch stripped[j][k] {
			case '{':
				depth++
				started = true
			case '}':
				depth--
			}
		}
		if started && depth <= 0 {
			return j
		}
	}
	if started {
		return len(stripped) - 1
	}
	return -1
}

// enclosingSymbol returns the name of the smallest function range covering the
// given line, or "(top level)".
func enclosingSymbol(ranges []funcRange, line int) string {
	best := ""
	bestSpan := 1 << 30
	for _, r := range ranges {
		if r.start <= line && line <= r.end {
			if span := r.end - r.start; span < bestSpan {
				bestSpan = span
				best = r.name
			}
		}
	}
	if best == "" {
		return "(top level)"
	}
	return best
}

// isConstructDetectorFile reports whether a path is a construct-detector source
// (its job is to spell out these literals), so it never self-triggers. Mirrors
// the Swift detector's *Detector/*Analyzer/*Scanner exclusion, plus this
// package's own detector filenames.
func isConstructDetectorFile(path string) bool {
	base := baseName(path)
	stem := base
	if i := strings.LastIndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	stem = strings.ToLower(stem)
	switch stem {
	case "magicconstants", "algorithms", "datastructures", "complexity", "designpattern":
		return true
	}
	return strings.HasSuffix(stem, "detector") ||
		strings.HasSuffix(stem, "analyzer") ||
		strings.HasSuffix(stem, "scanner")
}

func mcCategoryRank(c mcCategory) int {
	for i, x := range mcCategoryOrder {
		if x.label == c.label {
			return i
		}
	}
	return len(mcCategoryOrder)
}

// ── rendering ────────────────────────────────────────────────────────────────

func (MagicConstants) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(MagicConstantResult)
	if !ok || !r.HasDetection() {
		return nil
	}
	return []modules.SummaryCard{
		{Num: strconv.Itoa(len(r.Matches)), Label: plural(len(r.Matches), "constant", "constants")},
	}
}

func (MagicConstants) RenderMarkdown(res any) string {
	r, ok := res.(MagicConstantResult)
	if !ok || !r.HasDetection() {
		return ""
	}
	var b strings.Builder
	b.WriteString("| Constant | Count | Examples |\n")
	b.WriteString("|----------|------:|---------|\n")
	for _, m := range r.Matches {
		var ex []string
		for i, o := range m.Occurrences {
			if i == 6 {
				ex = append(ex, fmt.Sprintf("+%d more", len(m.Occurrences)-6))
				break
			}
			ex = append(ex, fmt.Sprintf("%s (%s:%d)", o.Symbol, baseName(o.FilePath), o.Line))
		}
		fmt.Fprintf(&b, "| %s | %d | %s |\n", m.Name, m.Count, strings.Join(ex, ", "))
	}
	b.WriteString("\n")
	return b.String()
}

const mcMaxLinks = 12

func (MagicConstants) RenderHTML(res any) string {
	r, ok := res.(MagicConstantResult)
	if !ok || !r.HasDetection() {
		return ""
	}
	byCat := map[string][]mcMatch{}
	for _, m := range r.Matches {
		byCat[m.Category.label] = append(byCat[m.Category.label], m)
	}
	var b strings.Builder
	b.WriteString(`<p class="as-section__sub">Well-known algorithms identified by the fixed literal values (hash primes, checksum polynomials, crypto IVs, PRNG coefficients) baked into their implementation.</p>`)
	b.WriteString(`<div class="as-dp">`)
	for _, cat := range mcCategoryOrder {
		ms := byCat[cat.label]
		if len(ms) == 0 {
			continue
		}
		fmt.Fprintf(&b, `<div class="as-dp__group"><h5 class="as-sub">%s %s</h5><div class="as-dp__items">`,
			cat.icon, html.EscapeString(cat.label))
		for _, m := range ms {
			fmt.Fprintf(&b, `<div class="as-dp__item"><span class="as-dp__name">%s</span><span class="as-dp__count">×%d</span>`,
				html.EscapeString(m.Name), m.Count)
			b.WriteString(`<span class="as-dp__ex">`)
			for i, o := range m.Occurrences {
				if i == mcMaxLinks {
					fmt.Fprintf(&b, ` +%d more`, len(m.Occurrences)-mcMaxLinks)
					break
				}
				if i > 0 {
					b.WriteString(` · `)
				}
				label := o.Symbol
				if label == "(top level)" {
					label = baseName(o.FilePath)
				}
				b.WriteString(occurrenceLink(label, o.FilePath, o.Line))
			}
			b.WriteString(`</span></div>`)
		}
		b.WriteString(`</div></div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}
