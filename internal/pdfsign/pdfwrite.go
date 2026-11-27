package pdfsign

// Writing an incremental update (ISO 32000-1 §7.5.6). The original file is
// copied byte for byte and a new section is appended after it: the new and
// changed objects, a cross-reference section that lists only them, and a
// trailer whose /Prev points at the previous section. Readers use the
// newest definition of each object, and every byte an earlier signature
// covers stays exactly where it was (D48).
//
// We write this part ourselves, rather than with pdfcpu's writer, because
// the signature needs exact control over byte positions: /ByteRange must
// name the offsets of the /Contents hole in the final file.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"strconv"

	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// maxObjectDepth bounds recursion when serialising objects read from an
// untrusted file.
const maxObjectDepth = 64

// updateObject is one object of the update section.
type updateObject struct {
	nr, gen int
	// body is the object's content between "N G obj\n" and "\nendobj".
	body []byte
}

// incrementalUpdate describes the section to append.
type incrementalUpdate struct {
	base     []byte // the original file, unchanged
	prevXRef int64  // offset of the base file's newest xref section
	// xrefStream selects a cross-reference stream instead of a classic
	// table. It must match the base file's newest section: a reader that
	// follows /Prev expects the same kind it started with.
	xrefStream bool
	// nextNr is the first free object number; the xref stream, if any, is
	// given the first number not used by objects.
	nextNr  int
	root    types.IndirectRef
	info    *types.IndirectRef
	id      types.Array
	objects []updateObject
}

// written is the result of writing an update.
type written struct {
	out []byte
	// bodyAt maps an object number to the offset of its body (the byte
	// after "N G obj\n") in out.
	bodyAt map[int]int64
}

// write returns base followed by the update section.
func (u *incrementalUpdate) write() (*written, error) {
	if len(u.objects) == 0 {
		return nil, fmt.Errorf("%w: empty update", ErrUnsupportedPDF)
	}
	objs := append([]updateObject(nil), u.objects...)
	sort.Slice(objs, func(i, j int) bool { return objs[i].nr < objs[j].nr })
	for i, o := range objs {
		if o.nr <= 0 || o.gen < 0 || o.gen > 65535 || (i > 0 && objs[i-1].nr == o.nr) {
			return nil, fmt.Errorf("%w: bad object number %d %d", ErrUnsupportedPDF, o.nr, o.gen)
		}
	}
	size := max(u.nextNr, objs[len(objs)-1].nr+1)

	var b bytes.Buffer
	b.Grow(len(u.base) + 4096)
	b.Write(u.base)
	// The update must start on a new line; most files already end with one.
	if n := len(u.base); n == 0 || (u.base[n-1] != '\n' && u.base[n-1] != '\r') {
		b.WriteByte('\n')
	}

	type entry struct {
		nr, gen int
		offset  int64
	}
	entries := make([]entry, 0, len(objs)+1)
	bodyAt := make(map[int]int64, len(objs))
	for _, o := range objs {
		offset := int64(b.Len())
		fmt.Fprintf(&b, "%d %d obj\n", o.nr, o.gen)
		bodyAt[o.nr] = int64(b.Len())
		b.Write(o.body)
		b.WriteString("\nendobj\n")
		entries = append(entries, entry{o.nr, o.gen, offset})
	}

	trailer := types.Dict{
		"Size": types.Integer(size),
		"Prev": types.Integer(u.prevXRef),
		"Root": u.root,
	}
	if u.info != nil {
		trailer["Info"] = *u.info
	}
	if len(u.id) == 2 {
		trailer["ID"] = u.id
	}

	xrefOffset := int64(b.Len())
	if !u.xrefStream {
		b.WriteString("xref\n")
		for _, run := range runs(len(entries), func(i int) int { return entries[i].nr }) {
			fmt.Fprintf(&b, "%d %d\n", entries[run[0]].nr, run[1]-run[0])
			for _, e := range entries[run[0]:run[1]] {
				// Exactly 20 bytes per entry, including the 2-byte EOL.
				fmt.Fprintf(&b, "%010d %05d n \n", e.offset, e.gen)
			}
		}
		b.WriteString("trailer\n")
		if err := writeObject(&b, trailer, 0); err != nil {
			return nil, err
		}
		b.WriteByte('\n')
	} else {
		// The xref stream is itself an object and lists its own offset.
		streamNr := size
		size++
		trailer["Size"] = types.Integer(size)
		entries = append(entries, entry{streamNr, 0, xrefOffset})

		// /W [1 4 2]: type (1 = in use at an offset), 4-byte offset,
		// 2-byte generation. 4 bytes address 4 GiB, far beyond MaxSize.
		var data bytes.Buffer
		var index types.Array
		for _, run := range runs(len(entries), func(i int) int { return entries[i].nr }) {
			index = append(index, types.Integer(entries[run[0]].nr), types.Integer(run[1]-run[0]))
			for _, e := range entries[run[0]:run[1]] {
				if e.offset > math.MaxUint32 {
					return nil, ErrTooLarge
				}
				data.WriteByte(1)
				_ = binary.Write(&data, binary.BigEndian, uint32(e.offset)) // #nosec G115 -- bounded above
				_ = binary.Write(&data, binary.BigEndian, uint16(e.gen))    // #nosec G115 -- 0..65535, checked above
			}
		}
		trailer["Type"] = types.Name("XRef")
		trailer["W"] = types.Array{types.Integer(1), types.Integer(4), types.Integer(2)}
		trailer["Index"] = index
		trailer["Length"] = types.Integer(data.Len())

		fmt.Fprintf(&b, "%d 0 obj\n", streamNr)
		if err := writeObject(&b, trailer, 0); err != nil {
			return nil, err
		}
		b.WriteString("\nstream\n")
		b.Write(data.Bytes())
		b.WriteString("\nendstream\nendobj\n")
	}
	fmt.Fprintf(&b, "startxref\n%d\n%%%%EOF\n", xrefOffset)

	if b.Len() > MaxSize {
		return nil, ErrTooLarge
	}
	return &written{out: b.Bytes(), bodyAt: bodyAt}, nil
}

// runs splits n sorted object numbers into runs of consecutive numbers,
// returned as [start, end) index pairs. Each run is one xref subsection.
func runs(n int, nr func(int) int) [][2]int {
	var out [][2]int
	start := 0
	for i := 1; i <= n; i++ {
		if i == n || nr(i) != nr(i-1)+1 {
			out = append(out, [2]int{start, i})
			start = i
		}
	}
	return out
}

// writeObject serialises o in PDF syntax. Leaf values use pdfcpu's
// PDFString, which reproduces strings exactly as they were in the file
// (pdfcpu keeps them escaped). Dictionaries and arrays are written here so
// that an object type we don't know is an error: pdfcpu's own Dict and
// Array serialisers silently drop such entries, which would corrupt a
// catalog or page without anyone noticing.
func writeObject(b *bytes.Buffer, o types.Object, depth int) error {
	if depth > maxObjectDepth {
		return fmt.Errorf("%w: objects nested too deeply", ErrUnsupportedPDF)
	}
	switch v := o.(type) {
	case nil:
		b.WriteString("null")
	case types.Dict:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic output
		b.WriteString("<<")
		for _, k := range keys {
			b.WriteString(types.Name(k).PDFString())
			b.WriteByte(' ')
			if err := writeObject(b, v[k], depth+1); err != nil {
				return err
			}
		}
		b.WriteString(">>")
	case types.Array:
		b.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				b.WriteByte(' ')
			}
			if err := writeObject(b, e, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case types.Integer:
		b.WriteString(strconv.Itoa(int(v)))
	case types.Float:
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return fmt.Errorf("%w: non-finite number", ErrUnsupportedPDF)
		}
		// PDF reals have no exponent notation.
		b.WriteString(strconv.FormatFloat(f, 'f', -1, 64))
	case types.Name, types.Boolean, types.StringLiteral, types.HexLiteral, types.IndirectRef:
		b.WriteString(v.PDFString())
	default:
		return fmt.Errorf("%w: cannot write a %T", ErrUnsupportedPDF, o)
	}
	return nil
}

// objectBody serialises o as an object body.
func objectBody(o types.Object) ([]byte, error) {
	var b bytes.Buffer
	if err := writeObject(&b, o, 0); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// withEntry returns a shallow copy of d with key set to v. Values read
// from pdfcpu are never modified in place.
func withEntry(d types.Dict, key string, v types.Object) types.Dict {
	out := make(types.Dict, len(d)+1)
	for k, val := range d {
		out[k] = val
	}
	out[key] = v
	return out
}

// appendRef returns a new array: a followed by ref.
func appendRef(a types.Array, ref types.IndirectRef) types.Array {
	out := make(types.Array, 0, len(a)+1)
	out = append(out, a...)
	return append(out, ref)
}

// ref builds an indirect reference.
func ref(nr, gen int) types.IndirectRef {
	return *types.NewIndirectRef(nr, gen)
}
