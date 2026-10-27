// Command bench runs a controlled benchmark against a running app: it
// uploads fake videos of fixed sizes several times, downloads each size N
// times per algorithm, one request at a time, and saves the server's
// records for the run as CSV (docs/decisions.md D35).
//
// The files are a 24-byte MP4 header followed by crypto/rand bytes: valid
// enough for the upload type check, and nothing real. They are generated
// while uploading, so no test file is written to disk.
//
// Run from the repository root while the stack is up:
//
//	go run ./scripts/bench -n 10
//
// By default it registers a fresh account with a random password. To use
// an existing account, pass -user and set BENCH_PASSWORD.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/eggboixd/infosec-assignment1-group3/internal/benchmark"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

func main() {
	base := flag.String("url", "http://localhost:8080", "base URL of the running app")
	user := flag.String("user", "", "existing username (password from BENCH_PASSWORD); empty registers a new account")
	sizesFlag := flag.String("sizes", "1KiB,64KiB,1MiB,16MiB", "comma-separated file sizes (B, KiB, MiB, GiB)")
	n := flag.Int("n", 10, "downloads per file size per algorithm")
	uploads := flag.Int("uploads", 5, "uploads per file size (each gives one encrypt record per algorithm)")
	out := flag.String("out", "", "CSV output path (default bench-results/run-<UTC time>.csv)")
	keep := flag.Bool("keep", false, "keep the uploaded files instead of deleting them")
	flag.Parse()

	sizes, err := parseSizes(*sizesFlag)
	if err != nil {
		fatal(err)
	}
	if *n < 1 || *uploads < 1 {
		fatal(errors.New("-n and -uploads must be at least 1"))
	}
	if *out == "" {
		*out = filepath.Join("bench-results", "run-"+time.Now().UTC().Format("20060102T150405Z")+".csv")
	}
	c, err := newClient(*base)
	if err != nil {
		fatal(err)
	}
	if err := c.signIn(*user, os.Getenv("BENCH_PASSWORD")); err != nil {
		fatal(err)
	}

	// Warm-up: the first requests pay for connection set-up and cold
	// caches. They run before `since`, so they are not in the results.
	fmt.Println("warm-up ...")
	if err := c.warmUp(); err != nil {
		fatal(fmt.Errorf("warm-up: %w", err))
	}
	since := time.Now().UTC()
	fmt.Printf("since=%s  (use this on /benchmarks?since=...)\n", since.Format(time.RFC3339Nano))

	var ids []string
	for _, size := range sizes {
		var f uploaded
		for range *uploads {
			var err error
			if f, err = c.upload(size); err != nil {
				fatal(fmt.Errorf("upload %s: %w", formatSize(size), err))
			}
			ids = append(ids, f.id)
		}
		// Downloads use the last upload; every copy is the same size.
		for round := range *n {
			// Rotate the order each round, so no algorithm always goes
			// first after the upload.
			for i := range crypto.All() {
				alg := crypto.All()[(i+round)%len(crypto.All())]
				if err := c.download(f, alg); err != nil {
					fatal(fmt.Errorf("download %s %s: %w", formatSize(size), alg, err))
				}
			}
		}
		fmt.Printf("  %-9s uploaded %d×, downloaded %d× per algorithm, all identical\n", formatSize(size), *uploads, *n)
	}

	records, err := c.export(since, *out)
	if err != nil {
		fatal(err)
	}
	if !*keep {
		for _, id := range ids {
			if err := c.remove(id); err != nil {
				fatal(err)
			}
		}
	}
	if err := checkCounts(records, len(sizes), *uploads, *n); err != nil {
		fatal(err)
	}
	fmt.Printf("\n%d records saved to %s\n\n", len(records), *out)
	printSummary(benchmark.Summarize(records))
}

// client is a logged-in session with the app. It does not follow
// redirects, so each step can check the status it expects.
type client struct {
	base string
	http *http.Client
}

func newClient(base string) (*client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &client{
		base: strings.TrimRight(base, "/"),
		http: &http.Client{
			Jar:           jar,
			Timeout:       30 * time.Minute,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// signIn logs in as user, or registers and logs in a new account when user
// is empty.
func (c *client) signIn(user, password string) error {
	if user == "" {
		user = "bench" + randomHex(4)
		password = randomHex(16)
		form := url.Values{"username": {user}, "password": {password}, "confirm": {password}}
		if err := c.postForm("/register", form, "/login"); err != nil {
			return fmt.Errorf("register: %w", err)
		}
		fmt.Printf("registered account %s\n", user)
	} else if password == "" {
		return errors.New("-user needs BENCH_PASSWORD in the environment")
	}
	if err := c.postForm("/login", url.Values{"username": {user}, "password": {password}}, "/files"); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	return nil
}

func (c *client) postForm(path string, form url.Values, wantLocation string) error {
	resp, err := c.http.PostForm(c.base+path, form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != wantLocation {
		return fmt.Errorf("got %s to %q, want 303 to %s", resp.Status, resp.Header.Get("Location"), wantLocation)
	}
	return nil
}

func (c *client) warmUp() error {
	f, err := c.upload(1 << 20)
	if err != nil {
		return err
	}
	for _, alg := range crypto.All() {
		if err := c.download(f, alg); err != nil {
			return err
		}
	}
	return c.remove(f.id)
}

// uploaded is a file the server stored, with the hash of what was sent.
type uploaded struct {
	id   string
	size int64
	sum  [sha256.Size]byte
}

// mp4Header is an ftyp box ("mp42", compatible with isom and mp42), which
// is what http.DetectContentType needs to name the file video/mp4.
var mp4Header = []byte{
	0, 0, 0, 0x18, 'f', 't', 'y', 'p', 'm', 'p', '4', '2', 0, 0, 0, 0,
	'i', 's', 'o', 'm', 'm', 'p', '4', '2',
}

// fakeVideo returns size bytes: the MP4 header, then random bytes.
func fakeVideo(size int64) io.Reader {
	return io.LimitReader(io.MultiReader(bytes.NewReader(mp4Header), rand.Reader), size)
}

// upload streams a fake video of size bytes and returns its file id.
func (c *client) upload(size int64) (uploaded, error) {
	if size < int64(len(mp4Header)) {
		return uploaded{}, fmt.Errorf("files must be at least %d bytes", len(mp4Header))
	}
	name := "bench-" + formatSize(size) + "-" + randomHex(4) + ".mp4"
	h := sha256.New()
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		err := mw.WriteField("kind", "video")
		var part io.Writer
		if err == nil {
			part, err = mw.CreateFormFile("file", name)
		}
		if err == nil {
			_, err = io.Copy(io.MultiWriter(part, h), fakeVideo(size))
		}
		if err == nil {
			err = mw.Close()
		}
		_ = pw.CloseWithError(err) // always nil; nil closes with EOF
	}()
	resp, err := c.http.Post(c.base+"/files", mw.FormDataContentType(), pr)
	if err != nil {
		return uploaded{}, err
	}
	_ = resp.Body.Close() // the body is not needed; a close error changes nothing
	if resp.StatusCode != http.StatusSeeOther {
		return uploaded{}, fmt.Errorf("got %s, want 303", resp.Status)
	}
	id, err := c.findID(name)
	if err != nil {
		return uploaded{}, err
	}
	f := uploaded{id: id, size: size}
	h.Sum(f.sum[:0])
	return f, nil
}

// findID reads the file list and returns the id in the row named name.
// The list is HTML; each row has the name followed by its download links.
func (c *client) findID(name string) (string, error) {
	resp, err := c.http.Get(c.base + "/files")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	page, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`(?s)>` + regexp.QuoteMeta(name) + `<.*?/files/([0-9a-f]{24})/download`)
	m := re.FindSubmatch(page)
	if m == nil {
		return "", fmt.Errorf("uploaded %s but it is not in the file list", name)
	}
	return string(m[1]), nil
}

// download fetches f decrypted with alg and checks it matches what was sent.
func (c *client) download(f uploaded, alg crypto.Algorithm) error {
	resp, err := c.http.Get(c.base + "/files/" + f.id + "/download?alg=" + string(alg))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("got %s", resp.Status)
	}
	h := sha256.New()
	n, err := io.Copy(h, resp.Body)
	if err != nil {
		return err
	}
	if n != f.size || !bytes.Equal(h.Sum(nil), f.sum[:]) {
		return fmt.Errorf("got %d bytes that differ from the %d uploaded", n, f.size)
	}
	return nil
}

func (c *client) remove(id string) error {
	req, err := http.NewRequest(http.MethodDelete, c.base+"/files/"+id, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close() // the body is not needed; a close error changes nothing
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("delete %s: got %s", id, resp.Status)
	}
	return nil
}

// export saves the records since since to path and returns them.
func (c *client) export(since time.Time, path string) ([]benchmark.Record, error) {
	resp, err := c.http.Get(c.base + "/benchmarks/export.csv?since=" + url.QueryEscape(since.Format(time.RFC3339Nano)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("export: got %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	records, err := benchmark.ReadCSV(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	return records, os.WriteFile(path, body, 0o600)
}

// checkCounts fails if the server did not record exactly the operations of
// the run: per file size, one encrypt per algorithm per upload, and n
// decrypts and n downloads per algorithm.
func checkCounts(records []benchmark.Record, sizes, uploads, n int) error {
	got := map[benchmark.Operation]int{}
	for _, r := range records {
		got[r.Operation]++
	}
	algs := len(crypto.All())
	want := map[benchmark.Operation]int{
		benchmark.OpEncrypt:  sizes * algs * uploads,
		benchmark.OpDecrypt:  sizes * algs * n,
		benchmark.OpDownload: sizes * algs * n,
	}
	for op, w := range want {
		if got[op] != w {
			return fmt.Errorf("%d %s records, want %d (was another client using the app?)", got[op], op, w)
		}
	}
	if total := sizes * algs * (uploads + 2*n); len(records) != total {
		return fmt.Errorf("%d records, want %d (was another client using the app?)", len(records), total)
	}
	return nil
}

func printSummary(stats []benchmark.Stat) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(tw, "operation\tsize\talgorithm\truns\tcrypto ms (mean ± sd)\tcrypto MiB/s\ttotal ms\ttotal MiB/s\t")
	for _, s := range stats {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%.3f ± %.3f\t%.1f\t%.3f\t%.1f\t\n",
			s.Operation, s.Size.Label, s.Algorithm, s.Count,
			s.Crypto.MeanMS(), s.Crypto.StdDevMS(), s.CryptoMiBPerSec(),
			s.Total.MeanMS(), s.TotalMiBPerSec())
	}
	_ = tw.Flush()
}

// parseSizes parses "1KiB,64KiB,1MiB".
func parseSizes(s string) ([]int64, error) {
	units := []struct {
		suffix string
		mult   int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1}}
	var out []int64
	for _, field := range strings.Split(s, ",") {
		field = strings.TrimSpace(field)
		mult := int64(1)
		for _, u := range units {
			if num, ok := strings.CutSuffix(field, u.suffix); ok {
				field, mult = num, u.mult
				break
			}
		}
		v, err := strconv.ParseInt(field, 10, 64)
		if err != nil || v <= 0 || v > (2<<30)/mult {
			return nil, fmt.Errorf("bad size %q: want a positive size up to 2GiB, like 64KiB", field)
		}
		out = append(out, v*mult)
	}
	return out, nil
}

// formatSize is the inverse of parseSizes for whole units.
func formatSize(n int64) string {
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if n >= u.mult && n%u.mult == 0 {
			return strconv.FormatInt(n/u.mult, 10) + u.suffix
		}
	}
	return strconv.FormatInt(n, 10) + "B"
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		fatal(err)
	}
	return hex.EncodeToString(b)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "bench:", err)
	os.Exit(1)
}
