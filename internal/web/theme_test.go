package web

import (
	"fmt"
	"io/fs"
	"regexp"
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
