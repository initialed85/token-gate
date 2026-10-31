package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newGate(entries ...entry) *gate {
	return &gate{entries: entries, startedAt: time.Now(), denyAt: make(map[string]time.Time)}
}

func TestCheckTokenRejectsNonTokens(t *testing.T) {
	bad := []string{"", "short", "tcp://10.43.5.243:9999", "abc def", "a:b", "x/" + "y"}
	for _, v := range bad {
		if err := checkToken(v); err == nil {
			t.Errorf("checkToken(%q) accepted a value that is not a credential", v)
		}
	}
	good := "0123456789abcdef0123456789abcdef0123"
	if err := checkToken(good); err != nil {
		t.Errorf("checkToken(%q) rejected a real token: %v", good, err)
	}
}

func TestMatchIsExact(t *testing.T) {
	g := newGate(entry{name: "EDWARD", token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if got := g.match("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); got != "EDWARD" {
		t.Errorf("match exact: got %q, want EDWARD", got)
	}
	if got := g.match("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); got != "" {
		t.Errorf("match one character short: got %q, want no match", got)
	}
	if got := g.match(""); got != "" {
		t.Errorf("match empty token: got %q, want no match", got)
	}
}

func TestTokenFromPrefersTheHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/check", nil)
	r.Header.Set("Authorization", "Bearer header-token")
	r.Header.Set("X-Api-Key", "key-token")
	if tok, src := tokenFrom(r, "/render?token=query-token"); tok != "header-token" || src != "header" {
		t.Errorf("header precedence: got (%q,%q), want (header-token,header)", tok, src)
	}

	r = httptest.NewRequest(http.MethodGet, "/check", nil)
	r.Header.Set("x-api-key", "key-token")
	if tok, src := tokenFrom(r, ""); tok != "key-token" || src != "header" {
		t.Errorf("lower-case x-api-key: got (%q,%q), want (key-token,header)", tok, src)
	}

	r = httptest.NewRequest(http.MethodGet, "/check", nil)
	if tok, src := tokenFrom(r, "/render?url=https://example.com&token=query-token"); tok != "query-token" || src != "forwarded-query" {
		t.Errorf("forwarded query fallback: got (%q,%q), want (query-token,forwarded-query)", tok, src)
	}

	r = httptest.NewRequest(http.MethodGet, "/check?token=sub", nil)
	if tok, src := tokenFrom(r, ""); tok != "sub" || src != "subrequest-query" {
		t.Errorf("subrequest query: got (%q,%q), want (sub,subrequest-query)", tok, src)
	}

	r = httptest.NewRequest(http.MethodGet, "/check", nil)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	if tok, src := tokenFrom(r, ""); tok != "" || src != "none" {
		t.Errorf("Basic auth is not our scheme: got (%q,%q), want (,none)", tok, src)
	}
}

func TestRedactURIKeepsTokensOutOfLogs(t *testing.T) {
	const token = "supersecrettoken0123456789abcdef01234567"
	got := redactURI("/render?url=https://example.com&token=" + token)
	if strings.Contains(got, token) {
		t.Errorf("redactURI leaked the credential: %q", got)
	}
	if !strings.Contains(got, "token=") {
		t.Errorf("redactURI dropped the parameter name, which is the useful part: %q", got)
	}
	if !strings.Contains(got, "url=") {
		t.Errorf("redactURI must keep the rest of the query readable: %q", got)
	}
	plain := "/render?url=https://example.com"
	if redactURI(plain) != plain {
		t.Errorf("redactURI rewrote a URI with no token: %q", redactURI(plain))
	}
}

func TestCheckAnswers(t *testing.T) {
	g := newGate(entry{name: "EDWARD", token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/check", nil)
	r.Header.Set("Authorization", "Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	r.Header.Set("X-Forwarded-Uri", "/render?url=https://example.com")
	r.Header.Set("X-Forwarded-For", "192.168.137.177:51234")
	g.handle(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("allowed request: got %d, want 204", w.Code)
	}
	if got := w.Header().Get("X-Auth-Request-User"); got != "EDWARD" {
		t.Errorf("identity header: got %q, want EDWARD (Traefik only forwards listed headers)", got)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/check", nil)
	r.Header.Set("X-Forwarded-Uri", "/render?token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	g.handle(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("?token= fallback: got %d, want 204", w.Code)
	}

	w = httptest.NewRecorder()
	g.handle(w, httptest.NewRequest(http.MethodGet, "/check", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no credential: got %d, want 401", w.Code)
	}
	if got := w.Header().Get("www-authenticate"); got == "" {
		t.Error("401 without WWW-Authenticate leaves a curl with no hint")
	}

	w = httptest.NewRecorder()
	g.handle(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown path: got %d, want 404", w.Code)
	}

	w = httptest.NewRecorder()
	g.handle(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Errorf("/healthz: got %d, want 200 (kubelet probes must pass)", w.Code)
	}
}
