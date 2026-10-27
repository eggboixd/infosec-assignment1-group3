package web

import (
	"fmt"
	"io/fs"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Theme rule: every colour in style.css lives in its :root block and every
// colour in mascot.css in its .mascot block. The other rules only use
// var(), so the palette is defined in exactly one place per file.

var (
	cssComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	// colourLiteral matches hex colours, colour functions and the named
	// colours we would plausibly type. A named colour must stand alone as a
	// value, so "white-space", ".m-white" and "var(--m-white)" don't count.
	colourLiteral = regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b|\b(?:rgba?|hsla?|hwb|oklab|oklch|lab|lch)\(|(?:^|[\s:,(])(?:white|black)(?:[\s;,)!]|$)`)
)

// readStatic returns an embedded static file with comments removed and
// line endings normalised (Windows checkouts embed CRLF).
func readStatic(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(assets, "static/"+name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return cssComment.ReplaceAllString(strings.ReplaceAll(string(b), "\r\n", "\n"), "")
}

// splitTokenBlock returns the body of the rule whose selector is exactly sel
// (written at the start of a line) and the stylesheet without that rule.
// Comments must already be stripped.
func splitTokenBlock(css, sel string) (block, rest string, err error) {
	start := -1
	for _, prefix := range []string{"\n" + sel + " {", sel + " {"} {
		if i := strings.Index(css, prefix); i >= 0 && (prefix[0] == '\n' || i == 0) {
			start = i
			break
		}
	}
	if start < 0 {
		return "", "", fmt.Errorf("no %q rule", sel)
	}
	end := strings.IndexByte(css[start:], '}')
	if end < 0 {
		return "", "", fmt.Errorf("%q rule is not closed", sel)
	}
	end += start
	open := strings.IndexByte(css[start:], '{') + start
	return css[open+1 : end], css[:start] + css[end+1:], nil
}

// coloursOutsideTokens lists the colour literals outside the token rule.
func coloursOutsideTokens(css, sel string) ([]string, error) {
	_, rest, err := splitTokenBlock(css, sel)
	if err != nil {
		return nil, err
	}
	var found []string
	for _, line := range strings.Split(rest, "\n") {
		if colourLiteral.MatchString(line) {
			found = append(found, strings.TrimSpace(line))
		}
	}
	return found, nil
}

func TestColoursOutsideTokens(t *testing.T) {
	tests := []struct {
		name    string
		css     string
		want    int
		wantErr bool
	}{
		{name: "colours only in tokens", css: ":root {\n  --a: #fff;\n  --b: rgba(0, 0, 0, 0.1);\n}\np { color: var(--a); }", want: 0},
		{name: "hex outside", css: ":root { --a: #fff; }\np { color: #fff; }", want: 1},
		{name: "8-digit hex outside", css: ":root { --a: #fff; }\np { color: #ffffff80; }", want: 1},
		{name: "rgba outside", css: ":root { --a: #fff; }\np { box-shadow: 0 1px rgba(0, 0, 0, 0.1); }", want: 1},
		{name: "named colour outside", css: ":root { --a: #fff; }\np { color: white; }", want: 1},
		{name: "named colour in a shorthand", css: ":root { --a: #fff; }\np { border: 1px solid black; }", want: 1},
		{name: "white-space is not a colour", css: ":root { --a: #fff; }\np { white-space: nowrap; }", want: 0},
		{name: "token named white is not a colour", css: ":root { --a: #fff; }\n.m-white { fill: var(--m-white); }", want: 0},
		{name: "transparent is allowed", css: ":root { --a: #fff; }\np { background: transparent; }", want: 0},
		{name: "selector must match exactly", css: ".mascot--happy { --a: #fff; }\n.mascot {\n  --b: #000;\n}", want: 1},
		{name: "missing token block", css: "p { color: var(--a); }", wantErr: true},
		{name: "unclosed token block", css: ":root { --a: #fff;", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sel := ":root"
			if strings.Contains(tt.css, ".mascot") {
				sel = ".mascot"
			}
			got, err := coloursOutsideTokens(tt.css, sel)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if len(got) != tt.want {
				t.Errorf("found %q, want %d colour lines", got, tt.want)
			}
		})
	}
}

func TestStylesheetColoursOnlyInTokens(t *testing.T) {
	for _, tt := range []struct{ file, sel string }{
		{"style.css", ":root"},
		{"mascot.css", ".mascot"},
	} {
		t.Run(tt.file, func(t *testing.T) {
			found, err := coloursOutsideTokens(readStatic(t, tt.file), tt.sel)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range found {
				t.Errorf("colour outside the %s block (make it a token): %s", tt.sel, line)
			}
		})
	}
}

// ---------- Contrast (WCAG 2.2) ----------

var hexToken = regexp.MustCompile(`--([a-z0-9-]+):\s*(#[0-9a-fA-F]{3}|#[0-9a-fA-F]{6})\s*;`)

// hexTokens returns the "--name: #hex;" declarations in a token block,
// keyed by name without the dashes, with every value as lower-case #rrggbb.
func hexTokens(block string) map[string]string {
	tokens := map[string]string{}
	for _, m := range hexToken.FindAllStringSubmatch(block, -1) {
		tokens[m[1]] = normalizeHex(m[2])
	}
	return tokens
}

// normalizeHex turns #rgb or #rrggbb into lower-case #rrggbb.
func normalizeHex(h string) string {
	h = strings.ToLower(h)
	if len(h) == 4 {
		return "#" + strings.Repeat(h[1:2], 2) + strings.Repeat(h[2:3], 2) + strings.Repeat(h[3:4], 2)
	}
	return h
}

// relativeLuminance follows the WCAG 2.2 definition for an sRGB colour.
func relativeLuminance(t *testing.T, hex string) float64 {
	t.Helper()
	if len(hex) != 7 || hex[0] != '#' {
		t.Fatalf("not a #rrggbb colour: %q", hex)
	}
	var c [3]float64
	for i := range c {
		v, err := strconv.ParseUint(hex[1+2*i:3+2*i], 16, 8)
		if err != nil {
			t.Fatalf("bad colour %q: %v", hex, err)
		}
		s := float64(v) / 255
		if s <= 0.04045 {
			c[i] = s / 12.92
		} else {
			c[i] = math.Pow((s+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*c[0] + 0.7152*c[1] + 0.0722*c[2]
}

// contrastRatio is (L1 + 0.05) / (L2 + 0.05) with L1 the lighter colour,
// so the order of the arguments does not matter. Range 1 to 21.
func contrastRatio(t *testing.T, a, b string) float64 {
	t.Helper()
	la, lb := relativeLuminance(t, a), relativeLuminance(t, b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

func TestContrastRatio(t *testing.T) {
	tests := []struct {
		a, b string
		want float64
	}{
		{"#000000", "#ffffff", 21},
		{"#ffffff", "#000000", 21}, // order does not matter
		{"#47283a", "#47283a", 1},  // same colour
		{"#777777", "#ffffff", 4.48},
		{"#767676", "#ffffff", 4.54}, // the lightest grey that passes AA on white
	}
	for _, tt := range tests {
		if got := contrastRatio(t, tt.a, tt.b); math.Abs(got-tt.want) > 0.005 {
			t.Errorf("contrastRatio(%s, %s) = %.3f, want %.2f", tt.a, tt.b, got, tt.want)
		}
	}
	if got := normalizeHex("#FfF"); got != "#ffffff" {
		t.Errorf(`normalizeHex("#FfF") = %q`, got)
	}
}

// TestThemeContrast checks every text colour style.css draws against each
// background it is drawn on, and the form-field border against what is
// next to it.
func TestThemeContrast(t *testing.T) {
	block, _, err := splitTokenBlock(readStatic(t, "style.css"), ":root")
	if err != nil {
		t.Fatal(err)
	}
	tokens := hexTokens(block)

	const text, nonText = 4.5, 3.0 // WCAG 1.4.3 (AA) and 1.4.11
	pairs := []struct {
		fg, bg string
		min    float64
		use    string
	}{
		{"ink", "page", text, "body text, typed file name"},
		{"ink", "card", text, "body text"},
		{"ink", "field", text, "text typed in a field"},
		{"ink", "btn", text, "plain button"},
		{"ink", "accent-soft", text, "info flash, code, unknown kind"},
		{"ink", "butter", text, "missing badge, error code"},
		{"ink", "gold-soft", text, "username chip"},
		{"ink", "line", text, "closed badge"},
		{"ink", "sand", text, "ID card badge"},
		{"ink", "mint", text, "document badge, filled checklist slot"},
		{"ink", "sky", text, "video badge"},
		{"ink-soft", "card", text, "muted text, hints, table headers"},
		{"ink-soft", "page", text, "footer"},
		{"ink-soft", "mint", text, "hint in a filled checklist slot"},
		{"accent", "card", text, "links, download pills"},
		{"accent", "page", text, "links outside cards"},
		{"accent", "mint", text, "links in a filled slot or requirement"},
		{"accent", "accent-soft", text, "ready badge, download pill on hover"},
		{"on-accent", "accent", text, "header, nav, primary button, step numbers"},
		{"on-accent", "accent-hover", text, "nav and primary button on hover"},
		{"gold-ink", "card", text, "kicker, fact labels"},
		{"gold-ink", "gold-soft", text, "ribbon, submitted badge"},
		{"danger", "btn", text, "delete button"},
		{"danger", "danger-soft", text, "error flash, form errors, delete hover"},
		{"success", "success-soft", text, "success flash"},
		{"success", "card", text, "uploaded status"},
		{"field-line", "card", nonText, "field border on a card"},
		{"field-line", "page", nonText, "field border next to the file input's background"},
		{"field-line", "field", nonText, "field border against the field"},
		{"accent", "card", nonText, "focus ring"},
		{"gold", "accent", nonText, "focus ring in the header"},
	}
	for _, p := range pairs {
		fg, ok1 := tokens[p.fg]
		bg, ok2 := tokens[p.bg]
		if !ok1 || !ok2 {
			t.Errorf("%s: token --%s or --%s is missing or not a hex colour", p.use, p.fg, p.bg)
			continue
		}
		if r := contrastRatio(t, fg, bg); r < p.min {
			t.Errorf("%s: --%s %s on --%s %s is %.2f:1, want >= %.1f:1", p.use, p.fg, fg, p.bg, bg, r, p.min)
		}
	}
}

// TestFaviconMatchesMascot: favicon.svg can't use mascot.css (it is loaded
// as an image), so it repeats Toga's colours. Every colour it uses must be
// one of the .mascot variables, so a recolour can't miss the tab icon.
func TestFaviconMatchesMascot(t *testing.T) {
	block, _, err := splitTokenBlock(readStatic(t, "mascot.css"), ".mascot")
	if err != nil {
		t.Fatal(err)
	}
	palette := map[string]bool{}
	for _, v := range hexTokens(block) {
		palette[v] = true
	}
	b, err := fs.ReadFile(assets, "static/favicon.svg")
	if err != nil {
		t.Fatal(err)
	}
	used := regexp.MustCompile(`#[0-9a-fA-F]{6}\b|#[0-9a-fA-F]{3}\b`).FindAllString(string(b), -1)
	if len(used) == 0 {
		t.Fatal("favicon.svg uses no hex colours; did its format change?")
	}
	for _, c := range used {
		if !palette[normalizeHex(c)] {
			t.Errorf("favicon.svg uses %s, which is not a colour in mascot.css's .mascot block", c)
		}
	}
}
