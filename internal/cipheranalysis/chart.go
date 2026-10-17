package cipheranalysis

import (
	"fmt"
	"html"
	"strings"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// Colour-blind-safe (Okabe-Ito) colours, one per series.
var seriesColor = map[string]string{
	"plaintext":        "#6b6b6b",
	string(crypto.AES): "#0072B2",
	string(crypto.DES): "#E69F00",
	string(crypto.RC4): "#009E73",
}

const (
	svgFont  = `font-family="system-ui, -apple-system, Segoe UI, Arial, sans-serif"`
	svgInk   = "#1a1a1a"
	svgMuted = "#555555"
	svgGrid  = "#d0d0d0"
)

func svgOpen(b *strings.Builder, w, h int, title string) {
	fmt.Fprintf(b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-label="%s">`+"\n", w, h, w, h, html.EscapeString(title))
	fmt.Fprintf(b, `<rect width="%d" height="%d" fill="#ffffff"/>`+"\n", w, h)
}

func svgText(b *strings.Builder, x, y float64, size int, anchor, fill, s string) {
	fmt.Fprintf(b, `<text x="%.1f" y="%.1f" font-size="%d" text-anchor="%s" fill="%s" %s>%s</text>`+"\n", x, y, size, anchor, fill, svgFont, html.EscapeString(s))
}

// EntropyChart draws grouped bars: for each file, the plaintext entropy and
// the ciphertext entropy of every algorithm, with a reference line at 8
// bits/byte (the maximum). rows must be grouped by file in the order given.
func EntropyChart(rows []Row) string {
	var files []string
	byFile := map[string]map[crypto.Algorithm]Row{}
	for _, r := range rows {
		if byFile[r.File] == nil {
			byFile[r.File] = map[crypto.Algorithm]Row{}
			files = append(files, r.File)
		}
		byFile[r.File][r.Algorithm] = r
	}

	const (
		left, right, top, bottom = 60.0, 20.0, 50.0, 110.0
		barW                     = 14.0
		groupGap                 = 18.0
	)
	series := append([]string{"plaintext"}, algNames()...)
	groupW := barW*float64(len(series)) + groupGap
	w := int(left + right + groupW*float64(len(files)))
	if w < 520 {
		w = 520
	}
	h := 360
	plotH := float64(h) - top - bottom

	var b strings.Builder
	svgOpen(&b, w, h, "Shannon entropy per file")
	svgText(&b, float64(w)/2, 24, 15, "middle", svgInk, "Shannon entropy per file (bits per byte, 8 is the maximum)")

	y := func(v float64) float64 { return top + plotH*(1-v/8) }
	for v := 0; v <= 8; v += 2 {
		fmt.Fprintf(&b, `<line x1="%.0f" y1="%.1f" x2="%d" y2="%.1f" stroke="%s" stroke-width="1"/>`+"\n", left, y(float64(v)), w-int(right), y(float64(v)), svgGrid)
		svgText(&b, left-8, y(float64(v))+4, 11, "end", svgMuted, fmt.Sprint(v))
	}
	fmt.Fprintf(&b, `<line x1="%.0f" y1="%.1f" x2="%d" y2="%.1f" stroke="%s" stroke-width="1.5" stroke-dasharray="5 4"/>`+"\n", left, y(8), w-int(right), y(8), svgInk)

	for gi, f := range files {
		gx := left + groupGap/2 + groupW*float64(gi)
		for si, s := range series {
			var v float64
			if s == "plaintext" {
				v = byFile[f][crypto.AES].PlainEntropy
			} else {
				v = byFile[f][crypto.Algorithm(s)].CipherEntropy
			}
			x := gx + barW*float64(si)
			fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s"><title>%s %s: %.4f</title></rect>`+"\n",
				x, y(v), barW-2, top+plotH-y(v), seriesColor[s], html.EscapeString(f), s, v)
		}
		lx, ly := gx+barW*float64(len(series))/2, top+plotH+14
		fmt.Fprintf(&b, `<text transform="translate(%.1f %.1f) rotate(-40)" font-size="11" text-anchor="end" fill="%s" %s>%s</text>`+"\n", lx, ly, svgInk, svgFont, html.EscapeString(f))
	}

	// Legend, bottom left.
	lx := left
	for _, s := range series {
		name := s
		if s != "plaintext" {
			name = algLabel(crypto.Algorithm(s))
		}
		fmt.Fprintf(&b, `<rect x="%.0f" y="%d" width="12" height="12" fill="%s"/>`+"\n", lx, h-22, seriesColor[s])
		svgText(&b, lx+17, float64(h-12), 12, "start", svgInk, name)
		lx += 20 + float64(len(name))*7.2
	}
	b.WriteString("</svg>\n")
	return b.String()
}

func algNames() []string {
	var out []string
	for _, a := range crypto.All() {
		out = append(out, string(a))
	}
	return out
}

// HistogramChart draws the byte histogram of one file's plaintext and of its
// ciphertext under each algorithm, one panel each. A uniform histogram is a
// flat band at the dashed "expected" line.
func HistogramChart(file string, rows []Row) string {
	type panel struct {
		name, color string
		hist        [256]int
		n           int
	}
	var panels []panel
	for _, r := range rows {
		if r.File != file {
			continue
		}
		if len(panels) == 0 {
			panels = append(panels, panel{"Plaintext", seriesColor["plaintext"], r.PlainHist, r.PlainSize})
		}
		panels = append(panels, panel{algLabel(r.Algorithm) + " ciphertext", seriesColor[string(r.Algorithm)], r.CipherHist, r.CipherSize})
	}

	const (
		w, left, right = 720, 70.0, 20.0
		panelH, gap    = 110.0, 38.0
		top            = 46.0
	)
	h := int(top + float64(len(panels))*(panelH+gap) + 10)
	var b strings.Builder
	svgOpen(&b, w, h, "Byte histogram of "+file)
	svgText(&b, w/2, 24, 15, "middle", svgInk, "Byte histogram of "+file+" (how often each value 0-255 occurs)")

	plotW := float64(w) - left - right
	for i, p := range panels {
		py := top + float64(i)*(panelH+gap) + 16
		// Scale to at least twice the expected count, so random noise around a
		// flat band is not blown up to fill the panel.
		maxC := max(1, 2*p.n/256)
		for _, c := range p.hist {
			maxC = max(maxC, c)
		}
		svgText(&b, left, py-6, 12, "start", svgInk, p.name)
		fmt.Fprintf(&b, `<line x1="%.0f" y1="%.1f" x2="%.0f" y2="%.1f" stroke="%s"/>`+"\n", left, py+panelH, left+plotW, py+panelH, svgGrid)
		barW := plotW / 256
		for v, c := range p.hist {
			if c == 0 {
				continue
			}
			hh := panelH * float64(c) / float64(maxC)
			fmt.Fprintf(&b, `<rect x="%.2f" y="%.1f" width="%.2f" height="%.1f" fill="%s"/>`+"\n", left+float64(v)*barW, py+panelH-hh, barW, hh, p.color)
		}
		if p.n > 0 {
			exp := float64(p.n) / 256
			ey := py + panelH - panelH*exp/float64(maxC)
			fmt.Fprintf(&b, `<line x1="%.0f" y1="%.1f" x2="%.0f" y2="%.1f" stroke="%s" stroke-width="1.2" stroke-dasharray="5 4"/>`+"\n", left, ey, left+plotW, ey, svgInk)
		}
		svgText(&b, left-6, py+10, 10, "end", svgMuted, fmt.Sprint(maxC))
		svgText(&b, left-6, py+panelH, 10, "end", svgMuted, "0")
	}
	svgText(&b, left, float64(h)-4, 11, "start", svgMuted, "x axis: byte value 0 to 255. Dashed line: count expected if every value were equally likely.")
	b.WriteString("</svg>\n")
	return b.String()
}
