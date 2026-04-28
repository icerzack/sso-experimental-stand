package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type sessionStore struct {
	mu    sync.Mutex
	users map[string]string
}

func newSessionStore() *sessionStore {
	return &sessionStore{users: make(map[string]string)}
}

func (s *sessionStore) set(sessionID, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[sessionID] = user
}

func (s *sessionStore) get(sessionID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.users[sessionID]
}

func (s *sessionStore) delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, sessionID)
}

type rateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		hits:   make(map[string][]time.Time),
		max:    max,
		window: window,
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	valid := make([]time.Time, 0, len(rl.hits[ip]))
	for _, t := range rl.hits[ip] {
		if now.Sub(t) < rl.window {
			valid = append(valid, t)
		}
	}
	if len(valid) >= rl.max {
		rl.hits[ip] = valid
		return false
	}
	rl.hits[ip] = append(valid, now)
	return true
}

func main() {
	store := newSessionStore()
	loginEmail := getenv("PROFILE_C_EMAIL", "testuser@example.com")
	loginPassword := getenv("PROFILE_C_PASSWORD", "password123")
	limiter := newRateLimiter(5, time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		render(w, loginPage, nil)
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !limiter.allow(clientIP(r)) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		if !isValidCredentials(r.FormValue("email"), r.FormValue("password"), loginEmail, loginPassword) {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		sessionID := randomString()
		store.set(sessionID, loginEmail)
		http.SetCookie(w, &http.Cookie{
			Name:     "sess",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   900,
		})
		http.Redirect(w, r, "/protected", http.StatusFound)
	})

	mux.HandleFunc("/api/accounts/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !limiter.allow(clientIP(r)) {
			writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		email := r.FormValue("email")
		password := r.FormValue("password")
		if !isValidCredentials(email, password, loginEmail, loginPassword) {
			writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("sess")
		if err != nil || cookie.Value == "" || store.get(cookie.Value) == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		render(w, protectedPage, store.get(cookie.Value))
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("sess")
		if cookie != nil && cookie.Value != "" {
			store.delete(cookie.Value)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "sess",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		})
		http.Redirect(w, r, "/", http.StatusFound)
	})

	port := getenv("PORT", "8080")
	log.Printf("profile-c/hardened listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, securityHeaders(mux)))
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

func isValidCredentials(email, password, expectedEmail, expectedPassword string) bool {
	return email == expectedEmail && password == expectedPassword
}

func randomString() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "fallback-session"
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func render(w http.ResponseWriter, tmpl string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t := template.Must(template.New("page").Parse(tmpl))
	if err := t.Execute(w, data); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	writeJSON(w, map[string]string{"error": msg})
}

const loginPage = `<!DOCTYPE html>
<html><head><title>Profile C — Hardened</title></head>
<body>
  <h1>Profile C: Go app + Vaultwarden backend (hardened)</h1>
  <form method="post" action="/login">
    <label>E-mail <input name="email" type="email" required></label><br>
    <label>Password <input name="password" type="password" required></label><br>
    <button type="submit">Login</button>
  </form>
</body></html>`

const protectedPage = `<!DOCTYPE html>
<html><head><title>Protected</title></head>
<body>
  <h1>Protected resource</h1>
  <p>Logged in as <strong>{{.}}</strong></p>
  <a href="/logout">Logout</a>
</body></html>`
