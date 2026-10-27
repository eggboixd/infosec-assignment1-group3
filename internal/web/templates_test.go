package web

import (
	"bytes"
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/applications"
	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
	"github.com/eggboixd/infosec-assignment1-group3/internal/benchmark"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
	"github.com/eggboixd/infosec-assignment1-group3/internal/files"
	"github.com/eggboixd/infosec-assignment1-group3/internal/profile"
)

// checklist builds the data files.html reads, from the same function the
// handler uses, so the template and the Go side can't drift apart.
func checklist(rows ...files.FileView) map[string]any {
	cl := files.BuildChecklist(rows)
	return map[string]any{"Slots": cl.Slots, "Others": cl.Others, "Uploaded": cl.Uploaded, "Total": cl.Total}
}

func withData(m map[string]any, extra map[string]any) map[string]any {
	for k, v := range extra {
		m[k] = v
	}
	return m
}

var (
	testFileID = bson.ObjectID{0x65, 0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2a}
	testFiles  = []files.FileView{
		{ID: testFileID, Name: "ktp.png", Kind: files.KindIDCard, Slot: files.SlotKTP, Size: 1536, CreatedAt: time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)},
		{ID: bson.ObjectID{0x65, 0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2b}, Name: "cv.pdf", Kind: files.KindDocument, Slot: files.SlotCV, Size: 3 << 20, CreatedAt: time.Date(2026, 10, 2, 14, 0, 0, 0, time.UTC)},
	}
)

// pageCase renders one page template with data and checks the output.
type pageCase struct {
	name    string
	page    string
	data    map[string]any
	mood    string         // starting mood of the page's main mascot (data-gembi)
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
					t.Errorf("mascot mood = %q, want %q", got, tt.mood)
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

// homeData builds what home.html reads with the function the handler uses.
func homeData(user *auth.User, r applications.Readiness, sub map[string]time.Time) map[string]any {
	return map[string]any{"User": user, "Cards": applications.BuildCards(user != nil, r, sub, beforeDeadline)}
}

// detailData builds what scholarship.html reads for the first scholarship.
func detailData(user *auth.User, r applications.Readiness, sub map[string]time.Time, now time.Time, errMsg string) map[string]any {
	card := applications.BuildCards(user != nil, r, sub, now)[0]
	return map[string]any{"User": user, "Card": card, "Readiness": r, "Error": errMsg}
}

var (
	beforeDeadline = time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	afterDeadline  = time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
	student        = &auth.User{Username: "alice"}
	readyStudent   = applications.Readiness{HasProfile: true, Uploaded: 6, Total: 6}
	halfwayStudent = applications.Readiness{Uploaded: 4, Total: 6, Missing: []string{"Parents' salary slip", "Self-introduction video"}}
	submittedFirst = map[string]time.Time{"prestasi-nusantara": time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)}
)

func TestHomeTemplate(t *testing.T) {
	runPageCases(t, []pageCase{
		{
			name: "visitor: Toga waves, two scholarship cards, register and log in",
			page: "home.html",
			data: homeData(nil, applications.Readiness{}, nil),
			mood: "hello",
			want: []string{
				`data-base-mood="smiling"`, "Pendaftaran Beasiswa 2027 dibuka",
				"Beasiswa Prestasi Nusantara", "Beasiswa Bakti Keluarga", "Yayasan Cendekia Nusantara",
				`href="/scholarships/prestasi-nusantara"`, `href="/scholarships/bakti-keluarga"`,
				`href="/login"`, `href="/register"`, `href="/benchmarks"`,
				"31 January 2027", "AES-256", "DES", "RC4", "CTR", "HMAC",
			},
			notWant: []string{"site-nav", "badge--", "Secure Store", "Gembi"},
			count:   map[string]int{`class="card certificate sch-card"`: 2, `class="ribbon"`: 2},
		},
		{
			name:    "student: nav and a status badge on every card",
			page:    "home.html",
			data:    homeData(student, halfwayStudent, submittedFirst),
			want:    []string{"site-nav", "alice", `href="/profile">My application`, "badge--submitted", "Submitted 20 Oct 2026", "3 items missing"},
			notWant: []string{`href="/register"`},
		},
		{
			name: "student ready to submit",
			page: "home.html",
			data: homeData(student, readyStudent, nil),
			want: []string{"Ready to submit"},
		},
		{
			name: "first page after login: Toga unlocks",
			page: "home.html",
			data: withData(homeData(student, readyStudent, nil), map[string]any{"JustLoggedIn": true}),
			mood: "unlocked",
		},
	})
}

func TestScholarshipTemplate(t *testing.T) {
	const form = `action="/scholarships/prestasi-nusantara/apply"`
	runPageCases(t, []pageCase{
		{
			name:    "visitor: details, log in to apply, no submit form",
			page:    "scholarship.html",
			data:    detailData(nil, applications.Readiness{}, nil, beforeDeadline, ""),
			mood:    "sleepy",
			want:    []string{"Beasiswa Prestasi Nusantara", "Rp 6.000.000 per semester", "31 January 2027, 23:59 WIB", "Log in to apply"},
			notWant: []string{form, "uploaded</span>"},
		},
		{
			name:    "incomplete: locked button and the missing documents",
			page:    "scholarship.html",
			data:    detailData(student, halfwayStudent, nil, beforeDeadline, ""),
			mood:    "sleepy",
			want:    []string{"btn--locked\" disabled", "4 of 6 uploaded", "Still missing: Parents&#39; salary slip, Self-introduction video.", "3 items missing"},
			notWant: []string{form},
		},
		{
			name: "ready: the submit form, sent busy",
			page: "scholarship.html",
			data: detailData(student, readyStudent, nil, beforeDeadline, ""),
			mood: "smiling",
			want: []string{form, `method="post"`, `data-gembi-busy=`, "Submit application", "6 of 6 uploaded"},
		},
		{
			name:    "submitted: the seal and the date, no form",
			page:    "scholarship.html",
			data:    detailData(student, readyStudent, submittedFirst, beforeDeadline, ""),
			mood:    "smiling",
			want:    []string{"badge--submitted", "20 October 2026 at 08:00 UTC"},
			notWant: []string{form, "btn--locked"},
		},
		{
			name:    "closed: no form",
			page:    "scholarship.html",
			data:    detailData(student, readyStudent, nil, afterDeadline, ""),
			want:    []string{"badge--closed", "deadline has passed"},
			notWant: []string{form},
		},
		{
			name: "refused submit: the message, Toga is confused",
			page: "scholarship.html",
			data: detailData(student, readyStudent, submittedFirst, beforeDeadline, "You have already applied to this scholarship."),
			mood: "confused",
			want: []string{`role="alert"`, "You have already applied to this scholarship."},
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
	legacy := files.FileView{ID: bson.ObjectID{0x65, 0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2c}, Name: "old-scan.pdf", Kind: files.KindDocument, Size: 100, CreatedAt: time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)}
	runPageCases(t, []pageCase{
		{
			name: "two of six uploaded: smiling, checklist with status, downloads and delete",
			page: "files.html",
			data: checklist(testFiles...),
			mood: "smiling",
			want: []string{
				`data-base-mood="smiling"`, "My application documents", "<strong>2 of 6</strong>",
				"KTP (ID card scan)", "CV", "Academic transcript", "Recommendation letter", "Parents&#39; salary slip", "Self-introduction video",
				"Accepted: JPG, JPEG, PNG", "Accepted: DOC, DOCX", "Accepted: XLS, XLSX", "Accepted: MP4, WEBM",
				"ktp.png", "cv.pdf", "1.5 KiB", "3.0 MiB", `datetime="2026-10-01T09:30:00Z"`,
				"/files/" + hex + "/download?alg=aes", "/files/" + hex + "/download?alg=des", "/files/" + hex + "/download?alg=rc4",
				`hx-delete="/files/` + hex + `"`, `hx-swap="none"`,
			},
			notWant: []string{"Other files"},
			count: map[string]int{
				"status--done\">Uploaded": 2, "status--missing\">Missing": 4,
				"data-gembi-download": 6, "hx-delete=": 2,
				`name="slot" value=`: 4, `type="file"`: 4,
			},
		},
		{
			name:    "nothing uploaded: sleepy and six upload forms, no downloads",
			page:    "files.html",
			data:    checklist(),
			mood:    "sleepy",
			want:    []string{`data-base-mood="sleepy"`, "<strong>0 of 6</strong>"},
			notWant: []string{"data-gembi-download", "hx-delete=", "Other files"},
			count:   map[string]int{`name="slot" value=`: 6, `enctype="multipart/form-data"`: 6},
		},
		{
			name: "slot is posted before the file, with the right picker filter",
			page: "files.html",
			data: checklist(),
			want: []string{
				`<input type="hidden" name="slot" value="salary">`, `accept=".xls,.xlsx"`,
				`<input type="hidden" name="slot" value="intro_video">`, `accept=".mp4,.webm"`,
				`action="/files"`, `data-gembi-busy="Locking it up…"`,
			},
		},
		{
			name:  "legacy and duplicate files show under Other files",
			page:  "files.html",
			data:  checklist(append([]files.FileView{legacy}, files.FileView{ID: bson.ObjectID{0x65, 0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2d}, Name: "cv-old.pdf", Kind: files.KindDocument, Slot: files.SlotCV, Size: 5}, testFiles[1])...),
			want:  []string{"Other files", "old-scan.pdf", "cv-old.pdf", "Document"},
			count: map[string]int{"<tr>": 3, "status--done\">Uploaded": 1},
		},
		{
			name: "just logged in: unlocks once, then settles on the base mood",
			page: "files.html",
			data: withData(checklist(testFiles...), map[string]any{"JustLoggedIn": true}),
			mood: "unlocked",
			want: []string{`data-base-mood="smiling"`},
		},
		{
			name: "just logged in with nothing uploaded settles to sleepy",
			page: "files.html",
			data: withData(checklist(), map[string]any{"JustLoggedIn": true}),
			mood: "unlocked",
			want: []string{`data-base-mood="sleepy"`},
		},
		{
			name: "greets the user",
			page: "files.html",
			data: withData(checklist(), map[string]any{"User": &auth.User{Username: "alice"}}),
			want: []string{"Hi, alice!", "site-nav"},
		},
		{
			name:    "file names are escaped",
			page:    "files.html",
			data:    checklist(files.FileView{ID: testFileID, Name: `<img src=x onerror=alert(1)>.pdf`, Kind: files.KindDocument, Slot: files.SlotCV}),
			want:    []string{"&lt;img src=x onerror=alert(1)&gt;.pdf"},
			notWant: []string{"<img src=x"},
		},
	})
}

// The server validates "slot" before it reads any file bytes, so every
// upload form must send the slot part first.
func TestFilesFormsSendSlotBeforeFile(t *testing.T) {
	out := renderPage(t, "files.html", checklist())
	forms := strings.Split(out, "<form")[1:]
	n := 0
	for _, f := range forms {
		if !strings.Contains(f, `enctype="multipart/form-data"`) {
			continue
		}
		n++
		slot, file := strings.Index(f, `name="slot"`), strings.Index(f, `name="file"`)
		if slot < 0 || file < 0 || slot > file {
			t.Errorf(`form %d: name="slot" at %d, name="file" at %d: slot must come first`, n, slot, file)
		}
	}
	if n != 6 {
		t.Errorf("%d upload forms, want 6", n)
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
				`<option value="des" selected>`, "decrypted with DES", "data-autosubmit", "<h1>Applicant data</h1>", "Your applicant data", "scholarship",
			},
			notWant: []string{`<option value="aes" selected>`, `<option value="rc4" selected>`, "Private data"},
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
			want:    []string{"Nothing stored yet.", "Add your applicant data", `name="full_name" autocomplete="name" required maxlength="100" value=""`},
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
		{
			name: "summary row",
			page: "benchmarks.html",
			data: map[string]any{
				"Summary": benchmark.Summarize([]benchmark.Record{{Algorithm: crypto.RC4, Operation: benchmark.OpDecrypt, Bytes: 1 << 20, CryptoDuration: time.Second, TotalDuration: 2 * time.Second}}),
				"Total":   benchmark.Stat{Count: 1, Bytes: 1 << 20},
				"Since":   "2026-10-27T09:00:00Z",
			},
			mood: "sleepy",
			want: []string{
				"1 records, 1.0 MiB processed", ">RC4<", "private data", "64 KiB–1 MiB", "1000.000 ± 0.000", ">1.0<", ">0.5<",
				`href="/benchmarks/export.csv?since=2026-10-27T09%3A00%3A00Z"`, `href="/benchmarks">Show all`,
			},
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
		"Slots":        files.BuildChecklist(testFiles).Slots,
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
