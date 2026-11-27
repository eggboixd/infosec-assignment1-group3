package pdfsign

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// newUpdate prepares an update of raw that adds one dictionary object and
// rewrites the catalog with an extra key pointing at it.
func newUpdate(t *testing.T, raw []byte) (*incrementalUpdate, int) {
	t.Helper()
	doc, err := readPDF(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	prev, isStream, err := lastXRef(raw)
	if err != nil {
		t.Fatal(err)
	}
	cat, rootRef, err := doc.catalog()
	if err != nil {
		t.Fatal(err)
	}
	nr := doc.nextObjectNumber()
	added, err := objectBody(types.Dict{"Marker": types.StringLiteral("added (by test)")})
	if err != nil {
		t.Fatal(err)
	}
	catBody, err := objectBody(withEntry(cat, "TestMarker", ref(nr, 0)))
	if err != nil {
		t.Fatal(err)
	}
	return &incrementalUpdate{
		base:       raw,
		prevXRef:   prev,
		xrefStream: isStream,
		nextNr:     nr + 1,
		root:       rootRef,
		info:       doc.xref.Info,
		id:         doc.xref.ID,
		objects: []updateObject{
			{nr: nr, gen: 0, body: added},
			{nr: rootRef.ObjectNumber.Value(), gen: rootRef.GenerationNumber.Value(), body: catBody},
		},
	}, nr
}

// xrefEntries decodes the update's own cross-reference section (classic
// or stream), independently of pdfcpu, so the test checks the offsets we
// wrote rather than ones a reader might have repaired.
func xrefEntries(t *testing.T, out []byte, isStream bool) map[int]int64 {
	t.Helper()
	off, gotStream, err := lastXRef(out)
	if err != nil || gotStream != isStream {
		t.Fatalf("startxref: off=%d stream=%v err=%v", off, gotStream, err)
	}
	entries := map[int]int64{}
	if !isStream {
		sec := out[off:]
		sec = sec[:bytes.Index(sec, []byte("trailer"))]
		lines := bytes.Split(bytes.TrimRight(sec, "\n"), []byte("\n"))[1:] // skip "xref"
		for i := 0; i < len(lines); {
			var start, count int
			if _, err := fmt.Sscanf(string(lines[i]), "%d %d", &start, &count); err != nil {
				t.Fatalf("subsection header %q: %v", lines[i], err)
			}
			for j := 0; j < count; j++ {
				line := lines[i+1+j]
				if len(line) != 19 { // 20 bytes with the "\n" we split on
					t.Fatalf("xref entry %q is not 20 bytes", line)
				}
				o, _ := strconv.ParseInt(string(line[:10]), 10, 64)
				entries[start+j] = o
			}
			i += 1 + count
		}
		return entries
	}
	obj := out[off:]
	idx := regexp.MustCompile(`/Index\s*\[([0-9 ]+)\]`).FindSubmatch(obj)
	if idx == nil {
		t.Fatalf("xref stream without /Index: %q", obj[:min(len(obj), 200)])
	}
	data := obj[bytes.Index(obj, []byte("stream\n"))+len("stream\n"):]
	var nums []int
	for _, f := range bytes.Fields(idx[1]) {
		n, _ := strconv.Atoi(string(f))
		nums = append(nums, n)
	}
	for k := 0; k+1 < len(nums); k += 2 {
		for j := 0; j < nums[k+1]; j++ {
			if data[0] != 1 {
				t.Fatalf("entry type %d, want 1", data[0])
			}
			entries[nums[k]+j] = int64(binary.BigEndian.Uint32(data[1:5]))
			data = data[7:]
		}
	}
	return entries
}

func TestIncrementalUpdate(t *testing.T) {
	ctx := context.Background()
	for name, raw := range map[string][]byte{
		"classic xref": simplePDF(),
		"form":         formPDF(),
		"xref stream":  xrefStreamPDF(t),
	} {
		u, addedNr := newUpdate(t, raw)
		w, err := u.write()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.HasPrefix(w.out, raw) {
			t.Fatalf("%s: the original bytes were changed", name)
		}

		// Every xref entry points at "N G obj", and the body offsets match.
		entries := xrefEntries(t, w.out, u.xrefStream)
		if len(entries) != len(u.objects)+map[bool]int{false: 0, true: 1}[u.xrefStream] {
			t.Fatalf("%s: %d xref entries for %d objects", name, len(entries), len(u.objects))
		}
		for nr, off := range entries {
			hdr := fmt.Sprintf("%d 0 obj\n", nr)
			if !bytes.HasPrefix(w.out[off:], []byte(hdr)) {
				t.Fatalf("%s: entry %d points at %q", name, nr, w.out[off:off+20])
			}
			if body, ok := w.bodyAt[nr]; ok && body != off+int64(len(hdr)) {
				t.Fatalf("%s: bodyAt[%d] = %d, want %d", name, nr, body, off+int64(len(hdr)))
			}
		}

		// pdfcpu reads the result and sees the new revision.
		doc, err := readPDF(ctx, w.out)
		if err != nil {
			t.Fatalf("%s: re-read: %v", name, err)
		}
		cat, _, _ := doc.catalog()
		mr, ok := cat["TestMarker"].(types.IndirectRef)
		if !ok || mr.ObjectNumber.Value() != addedNr {
			t.Fatalf("%s: catalog /TestMarker = %v", name, cat["TestMarker"])
		}
		added, err := doc.derefDict(mr)
		if err != nil || added["Marker"] != types.StringLiteral("added (by test)") {
			t.Fatalf("%s: added object = %v, %v", name, added, err)
		}
		if _, _, err := doc.firstPage(ctx); err != nil {
			t.Fatalf("%s: pages lost: %v", name, err)
		}

		// A second update on top of the first also works (signing twice).
		u2, _ := newUpdate(t, w.out)
		w2, err := u2.write()
		if err != nil {
			t.Fatalf("%s: second update: %v", name, err)
		}
		if _, err := readPDF(ctx, w2.out); err != nil {
			t.Fatalf("%s: second update unreadable: %v", name, err)
		}
	}
}

func TestIncrementalUpdateAddsNewlineAfterBase(t *testing.T) {
	raw := bytes.TrimRight(simplePDF(), "\n")
	u, _ := newUpdate(t, raw)
	w, err := u.write()
	if err != nil {
		t.Fatal(err)
	}
	if w.out[len(raw)] != '\n' {
		t.Fatalf("byte after base = %q, want newline", w.out[len(raw)])
	}
	if _, err := readPDF(context.Background(), w.out); err != nil {
		t.Fatal(err)
	}
}

func TestIncrementalUpdateRejects(t *testing.T) {
	base := simplePDF()
	root := ref(1, 0)
	for name, objs := range map[string][]updateObject{
		"none":          nil,
		"object 0":      {{nr: 0, body: []byte("null")}},
		"negative gen":  {{nr: 3, gen: -1, body: []byte("null")}},
		"gen too large": {{nr: 3, gen: 65536, body: []byte("null")}},
		"duplicate":     {{nr: 3, body: []byte("null")}, {nr: 3, body: []byte("null")}},
	} {
		u := &incrementalUpdate{base: base, prevXRef: 1, nextNr: 6, root: root, objects: objs}
		if _, err := u.write(); !errors.Is(err, ErrUnsupportedPDF) {
			t.Errorf("%s: err = %v, want ErrUnsupportedPDF", name, err)
		}
	}
}

func TestRuns(t *testing.T) {
	nrs := []int{1, 2, 3, 7, 8, 10}
	got := runs(len(nrs), func(i int) int { return nrs[i] })
	want := [][2]int{{0, 3}, {3, 5}, {5, 6}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("runs = %v, want %v", got, want)
	}
	if got := runs(0, nil); got != nil {
		t.Fatalf("runs(0) = %v", got)
	}
}

func TestWriteObject(t *testing.T) {
	cases := []struct {
		in   types.Object
		want string
	}{
		{nil, "null"},
		{types.Integer(-42), "-42"},
		{types.Float(612), "612"},
		{types.Float(-1.25), "-1.25"},
		{types.Float(0.000001), "0.000001"},
		{types.Boolean(true), "true"},
		{types.Name("Sig"), "/Sig"},
		{types.Name("A B#"), "/A#20B#23"},
		{types.StringLiteral(`a\(b\)`), `(a\(b\))`}, // kept escaped, as pdfcpu read it
		{types.HexLiteral("FEFF0041"), "<FEFF0041>"},
		{ref(12, 0), "12 0 R"},
		{types.Array{types.Integer(1), nil, types.Name("X"), types.Array{}}, "[1 null /X []]"},
		{types.Dict{"Z": types.Integer(1), "A": types.Dict{"K": ref(3, 1)}}, "<</A <</K 3 1 R>>/Z 1>>"},
	}
	for _, tc := range cases {
		got, err := objectBody(tc.in)
		if err != nil || string(got) != tc.want {
			t.Errorf("%#v: got %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}

	deep := types.Object(types.Integer(0))
	for range maxObjectDepth + 2 {
		deep = types.Array{deep}
	}
	for name, bad := range map[string]types.Object{
		"stream":      types.StreamDict{Dict: types.Dict{}},
		"NaN":         types.Float(math.NaN()),
		"+Inf":        types.Float(math.Inf(1)),
		"in a dict":   types.Dict{"S": types.StreamDict{}},
		"in an array": types.Array{types.StreamDict{}},
		"too deep":    deep,
	} {
		if _, err := objectBody(bad); !errors.Is(err, ErrUnsupportedPDF) {
			t.Errorf("%s: err = %v, want ErrUnsupportedPDF", name, err)
		}
	}
}

func TestWithEntryAndAppendRefCopy(t *testing.T) {
	d := types.Dict{"A": types.Integer(1)}
	d2 := withEntry(d, "B", types.Integer(2))
	if _, ok := d["B"]; ok || d2["A"] != types.Integer(1) || d2["B"] != types.Integer(2) {
		t.Fatalf("withEntry changed the original or lost entries: %v %v", d, d2)
	}
	a := make(types.Array, 1, 4)
	a[0] = types.Integer(1)
	a2 := appendRef(a, ref(5, 0))
	a3 := appendRef(a, ref(6, 0))
	if len(a) != 1 || a2[1] != ref(5, 0) || a3[1] != ref(6, 0) {
		t.Fatalf("appendRef shares storage: %v %v %v", a, a2, a3)
	}
}
