package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/oauth2"
)

var (
	loginAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sso_login_attempts_total",
		Help: "Total number of login attempts",
	})

	loginErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sso_login_errors_total",
		Help: "Total number of login errors",
	})

	loginSuccess = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sso_login_success_total",
		Help: "Total number of successful logins",
	})

	loginDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "sso_login_duration_seconds",
		Help:    "Duration of login process in seconds",
		Buckets: prometheus.DefBuckets,
	})

	redirectCountMetric = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "sso_redirect_count",
		Help:    "Number of HTTP redirects in authentication flow",
		Buckets: []float64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	})

	sessionAccessDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "sso_session_access_duration_seconds",
		Help:    "Duration of accessing protected resource with valid session",
		Buckets: prometheus.DefBuckets,
	})

	requestDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "sso_request_duration_seconds",
		Help:    "Duration of each HTTP request",
		Buckets: prometheus.DefBuckets,
	})

	activeSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sso_active_sessions",
		Help: "Number of active sessions",
	})

	protocolPayloadSizeBytes = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "sso_protocol_payload_size_bytes",
		Help:    "Size of protocol payload (OIDC ID token) in bytes",
		Buckets: []float64{128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768},
	})
)

type server struct {
	oauth2Config    *oauth2.Config
	provider        *oidc.Provider
	verifier        *oidc.IDTokenVerifier
	sessionStore    *sessions.CookieStore
	mu              sync.Mutex
	loginStartTimes map[string]time.Time
	redirectCounts  map[string]int
}

func (s *server) initLoginTracking(requestID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loginStartTimes[requestID] = time.Now()
	s.redirectCounts[requestID] = 1
}

func (s *server) incRedirectCount(requestID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	rc := s.redirectCounts[requestID]
	rc++
	s.redirectCounts[requestID] = rc
	return rc
}

func (s *server) takeLoginStart(requestID string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.loginStartTimes[requestID]
	if ok {
		delete(s.loginStartTimes, requestID)
	}
	return st, ok
}

type logEvent struct {
	Timestamp     string `json:"timestamp"`
	RequestID     string `json:"request_id"`
	Service       string `json:"service"`
	Event         string `json:"event"`
	User          string `json:"user,omitempty"`
	DurationMs    int64  `json:"duration_ms,omitempty"`
	RedirectCount int    `json:"redirect_count,omitempty"`
	Status        string `json:"status"`
	Error         string `json:"error,omitempty"`
	Path          string `json:"path,omitempty"`
	Method        string `json:"method,omitempty"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	keycloakURL := os.Getenv("KEYCLOAK_URL")
	if keycloakURL == "" {
		keycloakURL = "http://keycloak:8080"
	}

	realm := os.Getenv("KEYCLOAK_REALM")
	if realm == "" {
		realm = "sso-test"
	}

	clientID := os.Getenv("OIDC_CLIENT_ID")
	if clientID == "" {
		clientID = "oidc-rp-client"
	}

	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	if clientSecret == "" {
		clientSecret = "change-me"
	}

	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		sessionSecret = "change-me-in-production"
	}

	sessionStore := sessions.NewCookieStore([]byte(sessionSecret))
	sessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600, // 1 hour
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	// Use issuer URL that matches Keycloak's configured hostname
	// Keycloak uses KC_HOSTNAME (keycloak.localhost) for issuer
	// We use custom HTTP transport to resolve keycloak.localhost to internal service
	issuerHost := os.Getenv("KEYCLOAK_ISSUER_HOST")
	if issuerHost == "" {
		issuerHost = "keycloak.localhost"
	}
	issuerURL := fmt.Sprintf("http://%s:8080/realms/%s", issuerHost, realm)
	// Use external URL through Caddy for browser redirects
	redirectURL := os.Getenv("OIDC_REDIRECT_URL")
	if redirectURL == "" {
		redirectURL = "http://oidc-rp.localhost/callback"
	}

	// Create HTTP client that resolves keycloak.localhost to internal service
	httpClient := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				// Replace keycloak.localhost with internal service name for connections
				addr = strings.ReplaceAll(addr, "keycloak.localhost", "keycloak")
				return net.Dial(network, addr)
			},
		},
	}
	ctx := oidc.ClientContext(context.Background(), httpClient)

	// Use issuer URL for discovery (connections will use internal address via transport)
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		log.Fatalf("Failed to discover OIDC provider: %v", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID},
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	s := &server{
		oauth2Config:    oauth2Config,
		provider:        provider,
		verifier:        verifier,
		sessionStore:    sessionStore,
		loginStartTimes: make(map[string]time.Time),
		redirectCounts:  make(map[string]int),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/public", s.handlePublic)
	mux.HandleFunc("/protected", s.handleProtected)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/callback", s.handleCallback)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/metrics", promhttp.Handler().ServeHTTP)

	log.Printf("OIDC RP server starting on port %s", port)
	log.Printf("Keycloak URL: %s", keycloakURL)
	log.Printf("Realm: %s", realm)
	log.Printf("Client ID: %s", clientID)
	log.Fatal(http.ListenAndServe(":"+port, s.loggingMiddleware(mux)))
}

func (s *server) logEvent(evt logEvent) {
	evt.Timestamp = time.Now().Format(time.RFC3339)
	if evt.Service == "" {
		evt.Service = "oidc-rp"
	}
	jsonData, _ := json.Marshal(evt)
	log.Println(string(jsonData))
}

func (s *server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := fmt.Sprintf("req-%d", time.Now().UnixNano())

		s.logEvent(logEvent{
			RequestID: requestID,
			Event:     "request_start",
			Method:    r.Method,
			Path:      r.URL.Path,
			Status:    "info",
		})

		next.ServeHTTP(w, r)

		duration := time.Since(start)
		requestDuration.Observe(duration.Seconds())

		s.logEvent(logEvent{
			RequestID:  requestID,
			Event:      "request_complete",
			Method:     r.Method,
			Path:       r.URL.Path,
			DurationMs: duration.Milliseconds(),
			Status:     "success",
		})
	})
}

func (s *server) handlePublic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	if _, err := fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>OIDC RP - Public</title>
</head>
<body>
    <h1>OIDC RP - Public Endpoint</h1>
    <p>This endpoint is publicly accessible.</p>
    <p><a href="/protected">Go to Protected Endpoint</a></p>
</body>
</html>
`); err != nil {
		s.logEvent(logEvent{
			Event:  "response_write_error",
			Error:  err.Error(),
			Status: "error",
		})
	}
}

func (s *server) handleProtected(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := fmt.Sprintf("req-%d", time.Now().UnixNano())

	session, _ := s.sessionStore.Get(r, "session")
	user, ok := session.Values["user"].(string)
	if !ok {
		s.logEvent(logEvent{
			RequestID: requestID,
			Event:     "login_required",
			Path:      r.URL.Path,
			Status:    "info",
		})
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	duration := time.Since(start)
	sessionAccessDuration.Observe(duration.Seconds())
	s.logEvent(logEvent{
		RequestID:  requestID,
		Event:      "session_access",
		User:       user,
		Path:       r.URL.Path,
		DurationMs: duration.Milliseconds(),
		Status:     "success",
	})

	// Deserialize attributes from JSON string
	attributesJSON, _ := session.Values["attributes"].(string)
	var attributes map[string]string
	if attributesJSON != "" {
		if err := json.Unmarshal([]byte(attributesJSON), &attributes); err != nil {
			s.logEvent(logEvent{
				RequestID: requestID,
				Event:     "attributes_unmarshal_error",
				Error:     err.Error(),
				Status:    "error",
			})
			attributes = nil
		}
	}
	if attributes == nil {
		attributes = make(map[string]string)
	}

	w.Header().Set("Content-Type", "text/html")
	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>OIDC RP - Protected</title>
</head>
<body>
    <h1>OIDC RP - Protected Endpoint</h1>
    <p>Welcome, <strong>{{.User}}</strong>!</p>
    <h2>User Attributes:</h2>
    <ul>
        {{range $key, $value := .Attributes}}
        <li><strong>{{$key}}:</strong> {{$value}}</li>
        {{end}}
    </ul>
    <p><a href="/logout">Logout</a></p>
</body>
</html>
`
	t, err := template.New("protected").Parse(tmpl)
	if err != nil {
		s.logEvent(logEvent{
			RequestID: requestID,
			Event:     "template_parse_error",
			Error:     err.Error(),
			Status:    "error",
		})
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
		return
	}
	if err := t.Execute(w, map[string]interface{}{
		"User":       user,
		"Attributes": attributes,
	}); err != nil {
		s.logEvent(logEvent{
			RequestID: requestID,
			Event:     "template_execute_error",
			Error:     err.Error(),
			Status:    "error",
		})
	}
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	loginAttempts.Inc()
	requestID := fmt.Sprintf("req-%d", time.Now().UnixNano())
	s.initLoginTracking(requestID)

	s.logEvent(logEvent{
		RequestID:     requestID,
		Event:         "login_start",
		Path:          r.URL.Path,
		RedirectCount: 1,
		Status:        "info",
	})

	state, err := generateRandomString(32)
	if err != nil {
		loginErrors.Inc()
		s.logEvent(logEvent{
			RequestID: requestID,
			Event:     "login_error",
			Error:     err.Error(),
			Status:    "error",
		})
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	session, _ := s.sessionStore.Get(r, "session")
	session.Values["oauth_state"] = state
	session.Values["correlation_id"] = requestID
	if err := session.Save(r, w); err != nil {
		loginErrors.Inc()
		s.logEvent(logEvent{
			RequestID: requestID,
			Event:     "session_save_error",
			Error:     err.Error(),
			Status:    "error",
		})
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	s.logEvent(logEvent{
		RequestID:     requestID,
		Event:         "redirect_to_idp",
		RedirectCount: 1,
		Status:        "info",
	})

	authURL := s.oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *server) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := fmt.Sprintf("req-%d", time.Now().UnixNano())
	session, _ := s.sessionStore.Get(r, "session")
	correlationID, _ := session.Values["correlation_id"].(string)
	if correlationID != "" {
		requestID = correlationID
	}
	redirectCount := s.incRedirectCount(requestID)

	s.logEvent(logEvent{
		RequestID:     requestID,
		Event:         "callback_received",
		Method:        r.Method,
		Path:          r.URL.Path,
		RedirectCount: redirectCount,
		Status:        "info",
	})

	state := r.URL.Query().Get("state")
	savedState, ok := session.Values["oauth_state"].(string)
	if !ok || state != savedState {
		loginErrors.Inc()
		s.logEvent(logEvent{
			RequestID:     requestID,
			Event:         "callback_error",
			Error:         "invalid_state",
			RedirectCount: redirectCount,
			Status:        "error",
		})
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		loginErrors.Inc()
		errorDescription := r.URL.Query().Get("error_description")
		s.logEvent(logEvent{
			RequestID:     requestID,
			Event:         "callback_error",
			Error:         fmt.Sprintf("%s: %s", errMsg, errorDescription),
			RedirectCount: redirectCount,
			Status:        "error",
		})
		http.Error(w, fmt.Sprintf("Authorization error: %s", errMsg), http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	// Use the same HTTP client with custom transport for token exchange
	httpClient := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				// Replace keycloak.localhost with internal service name for connections
				addr = strings.ReplaceAll(addr, "keycloak.localhost", "keycloak")
				return net.Dial(network, addr)
			},
		},
	}
	tokenCtx := oidc.ClientContext(ctx, httpClient)
	oauth2Token, err := s.oauth2Config.Exchange(tokenCtx, code)
	if err != nil {
		loginErrors.Inc()
		s.logEvent(logEvent{
			RequestID:     requestID,
			Event:         "callback_error",
			Error:         fmt.Sprintf("token_exchange_failed: %v", err),
			RedirectCount: redirectCount,
			Status:        "error",
		})
		http.Error(w, "Failed to exchange authorization code", http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		loginErrors.Inc()
		s.logEvent(logEvent{
			RequestID:     requestID,
			Event:         "callback_error",
			Error:         "id_token_missing",
			RedirectCount: redirectCount,
			Status:        "error",
		})
		http.Error(w, "ID token not found", http.StatusInternalServerError)
		return
	}

	// Record ID token size for protocol overhead comparisons.
	protocolPayloadSizeBytes.Observe(float64(len(rawIDToken)))

	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		loginErrors.Inc()
		s.logEvent(logEvent{
			RequestID:     requestID,
			Event:         "callback_error",
			Error:         fmt.Sprintf("id_token_verification_failed: %v", err),
			RedirectCount: redirectCount,
			Status:        "error",
		})
		http.Error(w, "Failed to verify ID token", http.StatusInternalServerError)
		return
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		loginErrors.Inc()
		s.logEvent(logEvent{
			RequestID:     requestID,
			Event:         "callback_error",
			Error:         fmt.Sprintf("claims_extraction_failed: %v", err),
			RedirectCount: redirectCount,
			Status:        "error",
		})
		http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
		return
	}

	userInfo, err := s.provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
	if err == nil {
		var userInfoClaims map[string]interface{}
		if err := userInfo.Claims(&userInfoClaims); err == nil {
			for k, v := range userInfoClaims {
				claims[k] = v
			}
		}
	}

	userName := ""
	if email, ok := claims["email"].(string); ok && email != "" {
		userName = email
	} else if preferredUsername, ok := claims["preferred_username"].(string); ok && preferredUsername != "" {
		userName = preferredUsername
	} else if sub, ok := claims["sub"].(string); ok {
		userName = sub
	}

	// Store attributes as JSON string to avoid gob serialization issues
	attributes := make(map[string]string)
	for k, v := range claims {
		if strVal, ok := v.(string); ok {
			attributes[k] = strVal
		} else {
			attributes[k] = fmt.Sprintf("%v", v)
		}
	}

	// Serialize attributes to JSON for session storage
	attributesJSON, err := json.Marshal(attributes)
	if err != nil {
		loginErrors.Inc()
		s.logEvent(logEvent{
			RequestID:     requestID,
			Event:         "callback_error",
			Error:         fmt.Sprintf("failed to marshal attributes: %v", err),
			RedirectCount: redirectCount,
			Status:        "error",
		})
		http.Error(w, "Failed to process attributes", http.StatusInternalServerError)
		return
	}

	var duration time.Duration
	if startTime, ok := s.takeLoginStart(requestID); ok {
		duration = time.Since(startTime)
		loginDuration.Observe(duration.Seconds())
	} else {
		duration = 0
	}

	session.Values["user"] = userName
	session.Values["attributes"] = string(attributesJSON)
	session.Values["authenticated"] = true
	delete(session.Values, "oauth_state")
	if err := session.Save(r, w); err != nil {
		loginErrors.Inc()
		s.logEvent(logEvent{
			RequestID:     requestID,
			Event:         "session_save_error",
			Error:         err.Error(),
			RedirectCount: redirectCount,
			Status:        "error",
		})
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	activeSessions.Inc()
	loginSuccess.Inc()
	redirectCountMetric.Observe(float64(redirectCount))

	s.logEvent(logEvent{
		RequestID:     requestID,
		Event:         "login_success",
		User:          userName,
		DurationMs:    duration.Milliseconds(),
		RedirectCount: redirectCount,
		Status:        "success",
	})

	http.Redirect(w, r, "/protected", http.StatusFound)
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	requestID := fmt.Sprintf("req-%d", time.Now().UnixNano())
	session, _ := s.sessionStore.Get(r, "session")
	user, _ := session.Values["user"].(string)

	if session.Values["authenticated"] == true {
		activeSessions.Dec()
	}

	session.Values = make(map[interface{}]interface{})
	session.Options.MaxAge = -1
	if err := session.Save(r, w); err != nil {
		s.logEvent(logEvent{
			RequestID: requestID,
			Event:     "session_save_error",
			Error:     err.Error(),
			Status:    "error",
		})
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	s.logEvent(logEvent{
		RequestID: requestID,
		Event:     "logout",
		User:      user,
		Status:    "success",
	})

	http.Redirect(w, r, "/public", http.StatusFound)
}

func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
