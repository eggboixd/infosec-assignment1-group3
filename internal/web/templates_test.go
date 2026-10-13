package web

import (
	"bytes"
	"strings"
	"testing"
)

// pageCase renders one page template with data and checks the output.
type pageCase struct {
	name    string
	page    string
	data    map[string]any
	want    []string       // substrings that must appear
	notWant []string       // substrings that must not appear
	count   map[string]int // substring -> exact number of occurrences
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

func TestAuthTemplates(t *testing.T) {
	runPageCases(t, []pageCase{
		{
			name:    "login without errors is suspicious",
			page:    "login.html",
			data:    map[string]any{"Title": "Log in"},
			want:    []string{`action="/login"`, "mascot--suspicious", `data-base-mood="suspicious"`},
			notWant: []string{"mascot--angry", "form-errors", "site-nav"},
			count:   map[string]int{"data-gembi-cover": 1},
		},
		{
			name: "login with errors is angry and refills the username",
			page: "login.html",
			data: map[string]any{
				"Errors":   []string{"Invalid username or password."},
				"Username": "alice",
			},
			want: []string{"mascot--angry", `role="alert"`, "Invalid username or password.", `value="alice"`},
		},
		{
			name: "login errors given as a map",
			page: "login.html",
			data: map[string]any{"Errors": map[string]string{"username": "Username is required."}},
			want: []string{"mascot--angry", "Username is required."},
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
			want:    []string{`action="/register"`, "mascot--suspicious", `name="confirm"`},
			notWant: []string{"mascot--angry", "form-errors"},
			count:   map[string]int{"data-gembi-cover": 2},
		},
		{
			name: "register with errors is angry",
			page: "register.html",
			data: map[string]any{"Errors": []string{"Passwords do not match."}, "Username": "bob"},
			want: []string{"mascot--angry", "Passwords do not match.", `value="bob"`},
		},
	})
}
