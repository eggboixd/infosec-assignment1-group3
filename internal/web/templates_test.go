package web

import (
	"bytes"
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
	"github.com/eggboixd/infosec-assignment1-group3/internal/benchmark"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
	"github.com/eggboixd/infosec-assignment1-group3/internal/files"
	"github.com/eggboixd/infosec-assignment1-group3/internal/profile"
)

// testFileRow has the fields files.html reads from each row: the
// FileRecord fields plus the decrypted Name that feature/file-storage
// provides.
type testFileRow struct {
	ID        bson.ObjectID
	Name      string
	Kind      files.Kind
	Size      int64
	CreatedAt time.Time
}

var (
	testFileID = bson.ObjectID{0x65, 0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2a}
	testFiles  = []testFileRow{
		{ID: testFileID, Name: "ktp.png", Kind: files.KindIDCard, Size: 1536, CreatedAt: time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)},
		{ID: bson.ObjectID{0x65, 0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2b}, Name: "report.pdf", Kind: files.KindDocument, Size: 3 << 20, CreatedAt: time.Date(2026, 10, 2, 14, 0, 0, 0, time.UTC)},
	}
)

// pageCase renders one page template with data and checks the output.
type pageCase struct {
	name    string
	page    string
	data    map[string]any
	mood    string         // starting mood of the page's main Gembi (data-gembi)
	want    []string       // substrings that must appear
	notWant []string       // substrings that must not appear
	count   map[string]int // substring -> exact number of occurrences
}

// stageMood returns the mood class of the mascot inside the page's
// data-gembi stage. The brand icon in the header is always "smiling", so
// tests must not just search the whole page for a mood class.
func stageMood(t *testing.T, out string) string {
	t.Helper()
	const stage, prefix = "data-gembi data-base-mood=", `class="mascot mascot--`
	i := strings.Index(out, stage)
	if i < 0 {
		t.Fatal("page has no data-gembi stage")
	}
	j := strings.Index(out[i:], prefix)
	if j < 0 {
		t.Fatal("data-gembi stage has no mascot")
	}
	rest := out[i+j+len(prefix):]
	return rest[:strings.IndexByte(rest, '"')]
}

func renderPage(t *testing.T, page string, data map[string]any) string {
	t.Helper()
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, page, data); err != nil {
		t.Fatalf("execute %s: %v", page, err)
	}
	return buf.String()
}

func runPageCases(t *testing.T, cases []pageCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			out := renderPage(t, tt.page, tt.data)
			if tt.mood != "" {
				if got := stageMood(t, out); got != tt.mood {
					t.Errorf("Gembi's mood = %q, want %q", got, tt.mood)
				}
			}
			for _, s := range tt.want {
				if !strings.Contains(out, s) {
					t.Errorf("output is missing %q", s)
				}
			}
			for _, s := range tt.notWant {
				if strings.Contains(out, s) {
					t.Errorf("output must not contain %q", s)
				}
			}
			for s, n := range tt.count {
				if got := strings.Count(out, s); got != n {
					t.Errorf("%q appears %d times, want %d", s, got, n)
				}
			}
		})
	}
}

func TestHomeTemplate(t *testing.T) {
	runPageCases(t, []pageCase{
		{
			name: "landing page: waves once, then smiles; calls to action and three cards",
			page: "home.html",
			data: map[string]any{},
			mood: "hello",
			want: []string{
				`data-base-mood="smiling"`, "<h1 id=\"home-title\">Secure Store</h1>",
				`href="/login"`, `href="/register"`, `href="/benchmarks"`,
				"AES-256", "DES", "RC4", "CTR", "HMAC", "ID card",
			},
			notWant: []string{"site-nav"},
			count:   map[string]int{`class="card feature `: 3},
		},
		{
			name: "with a user the nav shows",
			page: "home.html",
			data: map[string]any{"User": &auth.User{Username: "alice"}},
			want: []string{"site-nav", "alice"},
		},
	})
}

func TestAuthTemplates(t *testing.T) {
	runPageCases(t, []pageCase{
		{
			name:    "login without errors is suspicious",
			page:    "login.html",
			data:    map[string]any{"Title": "Log in"},
			mood:    "suspicious",
			want:    []string{`action="/login"`, `data-base-mood="suspicious"`},
			notWant: []string{"form-errors", "site-nav"},
			count:   map[string]int{"data-gembi-cover": 1},
		},
		{
			name: "login with errors is angry and refills the username",
			page: "login.html",
			data: map[string]any{
				"Errors":   []string{"Invalid username or password."},
				"Username": "alice",
			},
			mood: "angry",
			want: []string{`data-base-mood="suspicious"`, `role="alert"`, "Invalid username or password.", `value="alice"`},
		},
		{
			name: "login errors given as a map",
			page: "login.html",
			data: map[string]any{"Errors": map[string]string{"username": "Username is required."}},
			mood: "angry",
			want: []string{"Username is required."},
		},
		{
			name: "login escapes errors and the username",
			page: "login.html",
			data: map[string]any{
				"Errors":   []string{"<script>alert(1)</script>"},
				"Username": `"><script>alert(2)</script>`,
			},
			want:    []string{"&lt;script&gt;alert(1)&lt;/script&gt;"},
			notWant: []string{"<script>alert(1)", "<script>alert(2)"},
		},
		{
			name:    "register without errors covers eyes on both password fields",
			page:    "register.html",
			data:    map[string]any{"Title": "Register"},
			mood:    "suspicious",
			want:    []string{`action="/register"`, `name="confirm"`},
			notWant: []string{"form-errors"},
			count:   map[string]int{"data-gembi-cover": 2},
		},
		{
			name: "register with errors is angry",
			page: "register.html",
			data: map[string]any{"Errors": []string{"Passwords do not match."}, "Username": "bob"},
			mood: "angry",
			want: []string{"Passwords do not match.", `value="bob"`},
		},
	})
}

func TestFilesTemplate(t *testing.T) {
	hex := testFileID.Hex()
	runPageCases(t, []pageCase{
		{
			name: "with files: smiling, one row per file, three downloads each",
			page: "files.html",
			data: map[string]any{"Files": testFiles},
			mood: "smiling",
			want: []string{
				`data-base-mood="smiling"`,
				"ktp.png", "report.pdf", "ID card", "Document", "1.5 KiB", "3.0 MiB",
				`datetime="2026-10-01T09:30:00Z"`,
				"/files/" + hex + "/download?alg=aes",
				"/files/" + hex + "/download?alg=des",
				"/files/" + hex + "/download?alg=rc4",
				`hx-delete="/files/` + hex + `"`, `hx-target="closest tr"`, `hx-swap="outerHTML"`,
				"data-gembi-list", "data-gembi-empty hidden",
			},
			count: map[string]int{"data-gembi-download": 6, "hx-delete=": 2},
		},
		{
			name:    "no files: sleepy empty state and no table",
			page:    "files.html",
			data:    map[string]any{"Files": []testFileRow{}},
			mood:    "sleepy",
			want:    []string{`data-base-mood="sleepy"`, "Nothing stored yet."},
			notWant: []string{"<table", "data-gembi-empty hidden"},
		},
		{
			name:    "files not provided yet renders the empty state",
			page:    "files.html",
			data:    map[string]any{},
			mood:    "sleepy",
			want:    []string{"Nothing stored yet.", "Your files"},
			notWant: []string{"<table"},
		},
		{
			name: "just logged in: unlocks once, then settles on the base mood",
			page: "files.html",
			data: map[string]any{"Files": testFiles, "JustLoggedIn": true},
			mood: "unlocked",
			want: []string{`data-base-mood="smiling"`},
		},
		{
			name: "just logged in with no files settles to sleepy",
			page: "files.html",
			data: map[string]any{"JustLoggedIn": true},
			mood: "unlocked",
			want: []string{`data-base-mood="sleepy"`},
		},
		{
			name: "greets the user",
			page: "files.html",
			data: map[string]any{"User": &auth.User{Username: "alice"}},
			want: []string{"Hi, alice!", "site-nav"},
		},
		{
			name:    "file names are escaped",
			page:    "files.html",
			data:    map[string]any{"Files": []testFileRow{{ID: testFileID, Name: `<img src=x onerror=alert(1)>.pdf`, Kind: files.KindDocument}}},
			want:    []string{"&lt;img src=x onerror=alert(1)&gt;.pdf"},
			notWant: []string{"<img src=x"},
		},
		{
			name: "upload form keeps the multipart POST and shows Gembi busy",
			page: "files.html",
			data: map[string]any{},
			want: []string{`action="/files"`, `enctype="multipart/form-data"`, `data-gembi-busy="Locking it up…"`},
		},
	})
}

// The server validates "kind" before it reads any file bytes, so the
// form must send the kind part first.
func TestFilesFormSendsKindBeforeFile(t *testing.T) {
	out := renderPage(t, "files.html", map[string]any{})
	kind, file := strings.Index(out, `name="kind"`), strings.Index(out, `name="file"`)
	if kind < 0 || file < 0 || kind > file {
		t.Errorf(`name="kind" at %d, name="file" at %d: kind must come first`, kind, file)
	}
}

func TestProfileTemplate(t *testing.T) {
	// Obviously fake sample data; never put real personal data in tests.
	stored := &profile.PrivateData{
		FullName:    "Test Person",
		NIK:         "0000000000000001",
		DateOfBirth: "2000-01-31",
		Address:     "Jl. Contoh No. 1",
		Phone:       "081200000000",
		Email:       "test@example.com",
	}
	runPageCases(t, []pageCase{
		{
			name: "stored data is prefilled and the chosen algorithm is selected",
			page: "profile.html",
			data: map[string]any{"Profile": stored, "Alg": crypto.DES},
			mood: "smiling",
			want: []string{
				`value="Test Person"`, `value="0000000000000001"`, `value="2000-01-31"`,
				">Jl. Contoh No. 1</textarea>", `value="081200000000"`, `value="test@example.com"`,
				`<option value="des" selected>`, "decrypted with DES", "data-autosubmit",
			},
			notWant: []string{`<option value="aes" selected>`, `<option value="rc4" selected>`},
		},
		{
			name: "algorithm defaults to AES",
			page: "profile.html",
			data: map[string]any{"Profile": stored},
			want: []string{`<option value="aes" selected>`, "decrypted with AES-256"},
		},
		{
			name: "rc4 is selectable",
			page: "profile.html",
			data: map[string]any{"Profile": stored, "Alg": crypto.RC4},
			want: []string{`<option value="rc4" selected>`, "decrypted with RC4"},
		},
		{
			name:    "nothing stored yet: sleepy, empty form, no algorithm selector",
			page:    "profile.html",
			data:    map[string]any{},
			mood:    "sleepy",
			want:    []string{"Nothing stored yet.", `name="full_name" autocomplete="name" required maxlength="100" value=""`},
			notWant: []string{`name="alg"`, "Test Person"},
		},
		{
			name: "validation errors: confused",
			page: "profile.html",
			data: map[string]any{"Errors": []string{"NIK must be 16 digits."}},
			mood: "confused",
			want: []string{`role="alert"`, "NIK must be 16 digits."},
		},
		{
			name:    "stored values are escaped",
			page:    "profile.html",
			data:    map[string]any{"Profile": &profile.PrivateData{FullName: `"><script>alert(1)</script>`, Address: "</textarea><script>"}},
			want:    []string{"&lt;/textarea&gt;&lt;script&gt;"},
			notWant: []string{"<script>alert(1)", "</textarea><script>"},
		},
		{
			name: "save form shows Gembi busy",
			page: "profile.html",
			data: map[string]any{},
			want: []string{`method="post" action="/profile"`, `data-gembi-busy="Encrypting…"`},
		},
	})
}

func TestBenchmarksTemplate(t *testing.T) {
	runPageCases(t, []pageCase{
		{
			name:    "no records: sleepy empty state",
			page:    "benchmarks.html",
			data:    map[string]any{},
			mood:    "sleepy",
			want:    []string{"No measurements yet.", `href="/benchmarks/export.csv"`},
			notWant: []string{"<table"},
		},
		{
			name: "with records: smiling, table shown",
			page: "benchmarks.html",
			data: map[string]any{"Records": []benchmark.Record{{Algorithm: crypto.AES, Operation: benchmark.OpEncrypt}}},
			mood: "smiling",
			want: []string{"<table", "Crypto (ms)"},
		},
	})
}

func TestErrorTemplate(t *testing.T) {
	runPageCases(t, []pageCase{
		{
			name: "status and message",
			page: "error.html",
			data: map[string]any{"Status": 422, "Message": "This file failed its integrity check."},
			mood: "confused",
			want: []string{"Error 422", "This file failed its integrity check.", `href="/"`},
		},
		{
			name:    "defaults without data",
			page:    "error.html",
			data:    map[string]any{},
			mood:    "confused",
			want:    []string{"Something went wrong."},
			notWant: []string{"Error "},
		},
		{
			name:    "message is escaped",
			page:    "error.html",
			data:    map[string]any{"Message": "<b>boom</b>"},
			want:    []string{"&lt;b&gt;boom&lt;/b&gt;"},
			notWant: []string{"<b>boom"},
		},
	})
}

// The CSP (middleware.go) allows only same-origin scripts and styles, so an
// inline style, inline script or event-handler attribute would be blocked
// in the browser and silently break the page. This test catches them in CI.
var cspViolations = []struct {
	what string
	re   *regexp.Regexp
}{
	{"style attribute", regexp.MustCompile(`(?i)\sstyle\s*=`)},
	{"<style> element", regexp.MustCompile(`(?i)<style[\s>]`)},
	{"event-handler attribute", regexp.MustCompile(`(?i)\son[a-z]+\s*=`)},
	{"javascript: URL", regexp.MustCompile(`(?i)javascript:`)},
}

var scriptTag = regexp.MustCompile(`(?i)<script\b[^>]*>`)

func TestTemplatesAreCSPSafe(t *testing.T) {
	full := map[string]any{
		"Title":        "Test",
		"User":         &auth.User{Username: "u"},
		"Flash":        map[string]string{"Kind": "success", "Message": "Saved."},
		"Errors":       []string{"Something is wrong."},
		"Files":        testFiles,
		"JustLoggedIn": true,
		"Profile":      &profile.PrivateData{FullName: "Test Person"},
		"Alg":          crypto.AES,
		"Records":      []benchmark.Record{{}},
		"Status":       404,
		"Message":      "Not found.",
	}
	for _, page := range []string{"home.html", "login.html", "register.html", "files.html", "profile.html", "benchmarks.html", "error.html"} {
		for _, data := range []map[string]any{{}, full} {
			out := renderPage(t, page, data)
			for _, v := range cspViolations {
				if loc := v.re.FindStringIndex(out); loc != nil {
					t.Errorf("%s: %s near %q", page, v.what, out[loc[0]:min(loc[1]+40, len(out))])
				}
			}
			for _, tag := range scriptTag.FindAllString(out, -1) {
				if !strings.Contains(tag, " src=") {
					t.Errorf("%s: inline script %q", page, tag)
				}
			}
		}
	}
}

// An SVG served from our origin can carry script if it is ever opened
// directly, so the favicon must stay a plain picture: no script, no event
// handlers, nothing loaded from elsewhere.
func TestFaviconIsStaticSVG(t *testing.T) {
	b, err := fs.ReadFile(assets, "static/favicon.svg")
	if err != nil {
		t.Fatalf("read favicon: %v", err)
	}
	svg := string(b)
	if !strings.HasPrefix(svg, "<svg ") {
		t.Errorf("favicon does not start with <svg: %.20q", svg)
	}
	for _, v := range cspViolations {
		if v.re.MatchString(svg) {
			t.Errorf("favicon contains a %s", v.what)
		}
	}
	for _, bad := range []string{"<script", "<foreignObject", "href=", "url(", "<animate"} {
		if strings.Contains(svg, bad) {
			t.Errorf("favicon contains %q", bad)
		}
	}
}

func TestLayoutLinksFavicon(t *testing.T) {
	runPageCases(t, []pageCase{
		{
			name: "logged out",
			page: "login.html",
			data: map[string]any{},
			want: []string{`<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">`},
		},
		{
			name:  "logged in",
			page:  "files.html",
			data:  map[string]any{"User": &auth.User{Username: "u"}},
			want:  []string{`rel="icon"`},
			count: map[string]int{`rel="icon"`: 1},
		},
	})
}

func TestLayoutRendersFlash(t *testing.T) {
	runPageCases(t, []pageCase{
		{
			name: "flash with kind and message",
			page: "files.html",
			data: map[string]any{"Flash": map[string]string{"Kind": "success", "Message": "File deleted."}},
			want: []string{`class="flash flash--success"`, `role="status"`, "File deleted.", "data-dismiss"},
		},
		{
			name:    "no flash",
			page:    "files.html",
			data:    map[string]any{},
			notWant: []string{`class="flash`},
		},
		{
			name:    "flash message is escaped",
			page:    "login.html",
			data:    map[string]any{"Flash": map[string]string{"Kind": "error", "Message": "<i>x</i>"}},
			want:    []string{"&lt;i&gt;x&lt;/i&gt;"},
			notWant: []string{"<i>x</i>"},
		},
	})
}
