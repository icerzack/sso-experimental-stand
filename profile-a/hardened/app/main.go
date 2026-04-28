// Profile A — Hardened OIDC application
//
// Protections (each commented at the relevant line):
//
//	A6  Session cookie: HttpOnly + Secure + SameSite=Strict
//	A8  State parameter strictly verified; PKCE S256 enforced
//	A9  Post-login ?next= restricted to relative paths only (no external redirects)
//	A12 Security headers on every response (HSTS, X-Frame-Options, CSP, …)
//
// Complementary protections configured in the Keycloak realm:
//
//	A1/A2  bruteForceProtected = true (5 failures → 30s lockout)
//	A4     accessTokenLifespan = 300 (5 minutes)
//	A7     redirectUris strictly whitelisted
//	A8     PKCE S256 required (pkce.code.challenge.method = "S256")
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

var store *sessions.CookieStore

func main() {
	appBase := strings.TrimRight(getenv("APP_BASE_URL", "https://app-a-h.local"), "/")
	kcHost := getenv("KEYCLOAK_ISSUER_HOST", "keycloak.local")
	kcInternal := getenv("KEYCLOAK_INTERNAL_HOST", "keycloak")
	kcPort := getenv("KEYCLOAK_PORT", "8080")
	realm := getenv("PROFILE_A_REALM", "profile-a-hardened")
	clientID := getenv("PROFILE_A_CLIENT_ID", "sso-test-app")
	clientSecret := getenv("PROFILE_A_CLIENT_SECRET", "Str0ngCl!entS3cr3t_changeme")

	// HARDENED A6: all session security flags enabled.
	store = sessions.NewCookieStore([]byte(getenv("SESSION_SECRET", "replace-with-64-char-random-secret")))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   900,
		HttpOnly: true,                    // A6: JS cannot read the cookie
		Secure:   true,                    // A6: only sent over HTTPS
		SameSite: http.SameSiteLaxMode, // A6: Lax required for OIDC redirect callback; still blocks cross-site POST
	}

	httpClient := internalHTTPClient(kcHost, kcInternal)
	issuer := fmt.Sprintf("http://%s:%s/realms/%s", kcHost, kcPort, realm)

	provider, err := oidc.NewProvider(oidc.ClientContext(context.Background(), httpClient), issuer)
	if err != nil {
		log.Fatalf("OIDC discovery: %v", err)
	}

	oauth2Cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  appBase + "/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		render(w, homeTmpl, nil)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		state, err := randomString(32)
		if err != nil {
			http.Error(w, "failed to generate state", http.StatusInternalServerError)
			return
		}
		// HARDENED A8: PKCE verifier generated and stored in session.
		verifier := oauth2.GenerateVerifier()
		sess, _ := store.Get(r, "sess")
		sess.Values["state"] = state
		sess.Values["pkce_verifier"] = verifier
		// HARDENED A9: only store next if it is a safe relative path.
		if next := r.URL.Query().Get("next"); isSafeRedirect(next) {
			sess.Values["next"] = next
		}
		if err := sess.Save(r, w); err != nil {
			http.Error(w, "session save failed", http.StatusInternalServerError)
			return
		}
		// HARDENED A8: PKCE S256 challenge appended to auth URL.
		authURL := oauth2Cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
		http.Redirect(w, r, authURL, http.StatusFound)
	})
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, "sess")

		// HARDENED A8: state strictly verified.
		savedState, _ := sess.Values["state"].(string)
		if savedState == "" || r.URL.Query().Get("state") != savedState {
			http.Error(w, "invalid state parameter", http.StatusBadRequest)
			return
		}
		delete(sess.Values, "state")

		if errParam := r.URL.Query().Get("error"); errParam != "" {
			http.Error(w, "authorization error: "+errParam, http.StatusBadRequest)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code parameter", http.StatusBadRequest)
			return
		}

		// HARDENED A8: PKCE verifier used in token exchange.
		pkceVerifier, _ := sess.Values["pkce_verifier"].(string)
		delete(sess.Values, "pkce_verifier")

		token, err := oauth2Cfg.Exchange(
			oidc.ClientContext(r.Context(), httpClient),
			code,
			oauth2.VerifierOption(pkceVerifier),
		)
		if err != nil {
			http.Error(w, "token exchange failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawID, _ := token.Extra("id_token").(string)
		idToken, err := idTokenVerifier.Verify(r.Context(), rawID)
		if err != nil {
			http.Error(w, "token verification failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		var claims map[string]interface{}
		_ = idToken.Claims(&claims)
		user := firstNonEmpty(claimStr(claims, "email"), claimStr(claims, "preferred_username"), claimStr(claims, "sub"))
		sess.Values["user"] = user
		next, _ := sess.Values["next"].(string)
		delete(sess.Values, "next")
		if err := sess.Save(r, w); err != nil {
			http.Error(w, "session save failed", http.StatusInternalServerError)
			return
		}
		// HARDENED A9: next was already validated at /login; default to /protected.
		if next != "" {
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		http.Redirect(w, r, "/protected", http.StatusFound)
	})
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, "sess")
		user, _ := sess.Values["user"].(string)
		if user == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		render(w, protectedTmpl, user)
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, "sess")
		sess.Values = make(map[interface{}]interface{})
		sess.Options.MaxAge = -1
		_ = sess.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
	})

	port := getenv("PORT", "8080")
	log.Printf("profile-a/hardened listening on :%s", port)
	// HARDENED A12: security headers middleware wraps all responses.
	log.Fatal(http.ListenAndServe(":"+port, securityHeaders(mux)))
}

// isSafeRedirect accepts only relative paths, blocking all absolute-URL redirects.
// Rejects "//evil.com" and "/\evil.com" which browsers treat as absolute.
func isSafeRedirect(s string) bool {
	if len(s) == 0 || s[0] != '/' {
		return false
	}
	if len(s) > 1 && (s[1] == '/' || s[1] == '\\') {
		return false
	}
	return true
}

// securityHeaders adds OWASP-recommended response headers to every reply.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

func internalHTTPClient(externalHost, internalHost string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				addr = strings.ReplaceAll(addr, externalHost, internalHost)
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func claimStr(claims map[string]interface{}, key string) string {
	v, _ := claims[key].(string)
	return v
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func render(w http.ResponseWriter, tmpl string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t := template.Must(template.New("p").Parse(tmpl))
	if err := t.Execute(w, data); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

const homeTmpl = `<!DOCTYPE html>
<html><head><title>Profile A — Hardened</title></head>
<body>
  <h1>Profile A: Keycloak OIDC (hardened)</h1>
  <a href="/login">Login with Keycloak</a>
</body></html>`

const protectedTmpl = `<!DOCTYPE html>
<html><head><title>Protected</title></head>
<body>
  <h1>Protected resource</h1>
  <p>Logged in as <strong>{{.}}</strong></p>
  <a href="/logout">Logout</a>
</body></html>`
