// token-gate answers Traefik's forwardAuth subrequest for the agent-facing APIs.
//
// It is the bearer-token half of the auth story: the Google gate (oauth2-proxy)
// is right for a browser and useless to a curl, and an IP allowlist is useless
// to an agent on a network you forgot to list. This answers with 204 when a
// token matches and 401 when it does not, and tells Traefik which token matched
// so an app can log *who* called.
//
// Tokens come from API_TOKEN_<NAME> environment variables (a Secret, mounted
// with envFrom), so one entry per consumer means revoking one consumer is a
// one-line change and a `kubectl rollout restart`.
package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// envPrefix names the tokens in the environment. API_TOKEN_EDWARD = "abc..."
	// is the token whose owner we call EDWARD.
	envPrefix = "API_TOKEN_"

	// minTokenLen is a floor, not a target. 32 hex characters is 128 bits.
	minTokenLen = 32

	// denyLogInterval keeps a scanner from writing one log line per probe.
	denyLogInterval = 30 * time.Second
)

// entry is one consumer: a name we can print and a secret we must not.
type entry struct {
	name  string
	token string
}

type gate struct {
	entries   []entry
	startedAt time.Time

	// denyAt guards the log, not the decision.
	mu     sync.Mutex
	denyAt map[string]time.Time
}

func main() {
	port := envOr("PORT", "8080")

	g := &gate{startedAt: time.Now(), denyAt: make(map[string]time.Time)}
	for _, kv := range os.Environ() {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(key, envPrefix) {
			continue
		}
		name := strings.TrimPrefix(key, envPrefix)
		if name == "" {
			log.Printf("ignoring %s: no name after the prefix", key)
			continue
		}
		if err := checkToken(value); err != nil {
			// A service-linked variable (TOKEN_GATE_PORT=tcp://...) can land in
			// this namespace's environment; a token that is not a token must
			// never become a credential that accepts a request.
			log.Printf("ignoring %s: %v", key, err)
			continue
		}
		g.entries = append(g.entries, entry{name: name, token: value})
	}
	if len(g.entries) == 0 {
		log.Fatalf("no usable %s variables: refusing to run a gate with no tokens", envPrefix)
	}
	names := make([]string, 0, len(g.entries))
	for _, e := range g.entries {
		names = append(names, e.name)
	}
	log.Printf("token-gate ready: %d token(s) %s", len(g.entries), strings.Join(names, ","))

	mux := http.NewServeMux()
	mux.HandleFunc("/", g.handle)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("token-gate stopped")
}

// checkToken rejects anything that is not plausibly a credential. It is what
// keeps an injected variable from becoming an accepted token.
func checkToken(token string) error {
	if len(token) < minTokenLen {
		return fmt.Errorf("shorter than %d characters", minTokenLen)
	}
	for _, r := range token {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return fmt.Errorf("contains %q, which is not a token character", r)
	}
	return nil
}

// match returns the owner of the token, or "" when nothing matches. Every
// entry is compared, so the time taken does not reveal which one matched.
func (g *gate) match(token string) string {
	if token == "" {
		return ""
	}
	got := ""
	t := []byte(token)
	for _, e := range g.entries {
		if subtle.ConstantTimeCompare(t, []byte(e.token)) == 1 {
			got = e.name
		}
	}
	return got
}

func (g *gate) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		w.Header().Set("content-type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"tokens":%d,"uptimeSeconds":%.0f}`,
			len(g.entries), time.Since(g.startedAt).Seconds())
		return
	case "/check":
		g.check(w, r)
		return
	default:
		http.Error(w, "token-gate: /check is the forwardAuth path, /healthz is the probe", http.StatusNotFound)
		return
	}
}

func (g *gate) check(w http.ResponseWriter, r *http.Request) {
	// Traefik forwards the original request's URI on this subrequest, so a
	// client that cannot set a header (?token= in a page URL, an <img> src)
	// still gets here. It is the fallback, not the preferred path: a token in a
	// URL ends up in access logs.
	token, source := tokenFrom(r, forwardedURI(r))
	owner := g.match(token)
	client := clientAddr(r)

	if owner != "" {
		w.Header().Set("X-Auth-Request-User", owner)
		w.WriteHeader(http.StatusNoContent)
		log.Printf("allow name=%s source=%s method=%s uri=%q client=%s",
			owner, source, r.Method, redactURI(forwardedURI(r)), client)
		return
	}

	w.Header().Set("www-authenticate", `Bearer realm="token-gate", error="invalid_token"`)
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintln(w, "token-gate: send 'Authorization: Bearer <token>' (or x-api-key, or ?token=)")

	g.mu.Lock()
	last, seen := g.denyAt[client]
	if !seen || time.Since(last) > denyLogInterval {
		g.denyAt[client] = time.Now()
		g.mu.Unlock()
		log.Printf("deny source=%s method=%s uri=%q client=%s presented=%s",
			source, r.Method, redactURI(forwardedURI(r)), client, preview(token))
	} else {
		g.mu.Unlock()
	}
}

// tokenFrom finds the credential: header first, then the query string of the
// forwarded URI, then this subrequest's own query. Returns the value and where
// it came from, because "the header was empty" and "the header was wrong" are
// different things to debug.
func tokenFrom(r *http.Request, forwarded string) (string, string) {
	if v := headerToken(r); v != "" {
		return v, "header"
	}
	if forwarded != "" {
		if u, err := url.Parse(forwarded); err == nil {
			if v := u.Query().Get("token"); v != "" {
				return v, "forwarded-query"
			}
		}
	}
	if v := r.URL.Query().Get("token"); v != "" {
		return v, "subrequest-query"
	}
	return "", "none"
}

func headerToken(r *http.Request) string {
	if v := r.Header.Get("Authorization"); v != "" {
		scheme, cred, ok := strings.Cut(v, " ")
		if ok && strings.EqualFold(scheme, "Bearer") {
			return strings.TrimSpace(cred)
		}
	}
	return r.Header.Get("X-Api-Key")
}

// forwardedURI is the original request URI as Traefik reports it.
func forwardedURI(r *http.Request) string {
	if u := r.Header.Get("X-Forwarded-Uri"); u != "" {
		return u
	}
	return r.URL.Path
}

func clientAddr(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		first, _, _ := strings.Cut(fwd, ",")
		return strings.TrimSpace(first)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// preview keeps a presented token out of the log while leaving enough to tell
// "nothing sent" from "the wrong one sent".
func preview(token string) string {
	if token == "" {
		return "none"
	}
	if len(token) <= 6 {
		return "short"
	}
	return token[:6] + "..."
}

// redactURI strips the value of a ?token= parameter out of a URI before it is
// logged. The path and the parameter name are the useful part; the credential
// is not, and a token in a URL is exactly the case that ends up in log files.
func redactURI(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	q := u.Query()
	if t := q.Get("token"); t != "" {
		q.Set("token", preview(t))
		u.RawQuery = q.Encode()
		return u.String()
	}
	return uri
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
