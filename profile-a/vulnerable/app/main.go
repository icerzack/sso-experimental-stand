// Profile A — Vulnerable OIDC application
//
// Intentional weaknesses (each commented at the relevant line):
//
//	A6  Session cookie has no HttpOnly, no Secure, no SameSite
//	A8  State parameter is generated but NOT verified → CSRF on the OAuth flow
//	A9  Post-login ?next= redirect validated with strings.Contains → domain confusion
//	A12 No security headers in any response
//
// Complementary weaknesses configured in the Keycloak realm:
//
//	A1/A2  bruteForceProtected = false
//	A4     accessTokenLifespan = 3600 (1 hour)
//	A7     redirectUris = ["*"] wildcard
//	A8     PKCE not required (pkce.code.challenge.method = "")
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
	"net/url"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

var store *sessions.CookieStore

func main() {
	appBase := strings.TrimRight(getenv("APP_BASE_URL", "http://app-a-v.local:8081"), "/")
	kcHost := getenv("KEYCLOAK_ISSUER_HOST", "keycloak.local")
	kcInternal := getenv("KEYCLOAK_INTERNAL_HOST", "keycloak")
	kcPort := getenv("KEYCLOAK_PORT", "8080")
	realm := getenv("PROFILE_A_REALM", "profile-a-vulnerable")
	clientID := getenv("PROFILE_A_CLIENT_ID", "sso-test-app")
	clientSecret := getenv("PROFILE_A_CLIENT_SECRET", "testpass123")

	// VULNERABLE A6: session cookie has no security flags.
	store = sessions.NewCookieStore([]byte(getenv("SESSION_SECRET", "insecure-key")))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: false,                 // A6: JS can read the cookie
		Secure:   false,                 // A6: sent over plain HTTP
		SameSite: http.SameSiteNoneMode, // A6: cross-site requests allowed
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
	// VULNERABLE A12: no security headers added to any response

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		render(w, homeTmpl, nil)
	})

	allowedDomain := getenv("ALLOWED_REDIRECT_DOMAIN", "app-a-v.local")

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		state := randomString()
		sess, _ := store.Get(r, "sess")
		sess.Values["state"] = state
		// VULNERABLE A9: store ?next= without validating it here; validated later
		// with strings.Contains which allows domain confusion bypass.
		if next := r.URL.Query().Get("next"); next != "" {
			sess.Values["next"] = next
		}
		_ = sess.Save(r, w)
		// VULNERABLE A8: no PKCE — code_challenge absent from auth URL
		http.Redirect(w, r, oauth2Cfg.AuthCodeURL(state), http.StatusFound)
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, "sess")
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code parameter", http.StatusBadRequest)
			return
		}
		// VULNERABLE A8: state returned by IdP is NOT compared with stored state
		// → attacker can craft a callback URL to force-login a victim (CSRF)

		token, err := oauth2Cfg.Exchange(oidc.ClientContext(r.Context(), httpClient), code)
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
		_ = sess.Save(r, w)
		// VULNERABLE A9: strings.Contains allows "app-a-v.local.evil.com" to pass.
		if next != "" && isAllowedRedirect(next, allowedDomain) {
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
		sess.Options.MaxAge = -1
		_ = sess.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
	})

	port := getenv("PORT", "8080")
	log.Printf("profile-a/vulnerable listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
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

// isAllowedRedirect uses strings.Contains — VULNERABLE to domain confusion.
// "app-a-v.local.evil.com" passes because it contains "app-a-v.local".
func isAllowedRedirect(rawURL, allowedDomain string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.Contains(parsed.Host, allowedDomain)
}

func randomString() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "fallback-state"
	}
	return base64.RawURLEncoding.EncodeToString(b)
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
<html><head><title>Profile A — Vulnerable</title></head>
<body>
  <h1>Profile A: Keycloak OIDC (vulnerable)</h1>
  <p>This configuration is intentionally insecure for research purposes.</p>
  <a href="/login">Login with Keycloak</a>
</body></html>`

const protectedTmpl = `<!DOCTYPE html>
<html><head><title>Protected</title></head>
<body>
  <h1>Protected resource</h1>
  <p>Logged in as <strong>{{.}}</strong></p>
  <a href="/logout">Logout</a>
</body></html>`
