package benchmark

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// csvHeader is the first row of every export. The report's analysis reads
// these column names, so they must not change.
var csvHeader = []string{"created_at", "algorithm", "operation", "file_kind", "bytes", "crypto_ns", "total_ns"}

// CSVWriter writes records in the export format, one row at a time.
// Every value is a timestamp, an enum or a number, so no cell can start
// with a formula character.
type CSVWriter struct {
	w *csv.Writer
}

// NewCSVWriter writes the header row and returns a writer for the records.
func NewCSVWriter(w io.Writer) (*CSVWriter, error) {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return nil, err
	}
	return &CSVWriter{w: cw}, nil
}

// Write adds one record. Rows are buffered; call Flush at the end.
func (c *CSVWriter) Write(r Record) error {
	return c.w.Write([]string{
		r.CreatedAt.UTC().Format(time.RFC3339Nano),
		string(r.Algorithm),
		string(r.Operation),
		r.FileKind,
		strconv.FormatInt(r.Bytes, 10),
		strconv.FormatInt(int64(r.CryptoDuration), 10),
		strconv.FormatInt(int64(r.TotalDuration), 10),
	})
}

// Flush writes any buffered rows and returns the first write error.
func (c *CSVWriter) Flush() error {
	c.w.Flush()
	return c.w.Error()
}

// ErrCSVHeader is returned by ReadCSV when the first row is not the export
// header.
var ErrCSVHeader = errors.New("benchmark: not a benchmark export (unexpected header)")

// ReadCSV parses an export written by CSVWriter.
func ReadCSV(r io.Reader) ([]Record, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = len(csvHeader)
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("benchmark: read csv header: %w", err)
	}
	if !slices.Equal(header, csvHeader) {
		return nil, ErrCSVHeader
	}
	var out []Record
	for {
		row, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("benchmark: read csv: %w", err)
		}
		rec, err := parseRow(row)
		if err != nil {
			line, _ := cr.FieldPos(0)
			return nil, fmt.Errorf("benchmark: csv line %d: %w", line, err)
		}
		out = append(out, rec)
	}
}

func parseRow(row []string) (Record, error) {
	created, err := time.Parse(time.RFC3339Nano, row[0])
	if err != nil {
		return Record{}, fmt.Errorf("created_at: %w", err)
	}
	alg, err := crypto.ParseAlgorithm(row[1])
	if err != nil {
		return Record{}, err
	}
	var n [3]int64
	for i, col := range row[4:] {
		if n[i], err = strconv.ParseInt(col, 10, 64); err != nil {
			return Record{}, fmt.Errorf("%s: %w", csvHeader[4+i], err)
		}
	}
	return Record{
		Algorithm:      alg,
		Operation:      Operation(row[2]),
		FileKind:       row[3],
		Bytes:          n[0],
		CryptoDuration: time.Duration(n[1]),
		TotalDuration:  time.Duration(n[2]),
		CreatedAt:      created,
	}, nil
}
