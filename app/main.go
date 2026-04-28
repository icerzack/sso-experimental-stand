package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/sessions"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

const (
	profileKindOIDC     = "oidc"
	profileKindLocal    = "local"
	profileKindWebAuthn = "webauthn"
)

var (
	loginAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sso_login_attempts_total",
		Help: "Total number of login attempts by authentication profile",
	}, []string{"profile"})

	loginErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sso_login_errors_total",
		Help: "Total number of login errors by authentication profile",
	}, []string{"profile"})

	loginSuccess = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sso_login_success_total",
		Help: "Total number of successful logins by authentication profile",
	}, []string{"profile"})

	loginDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sso_login_duration_seconds",
		Help:    "Duration of login process in seconds by authentication profile",
		Buckets: prometheus.DefBuckets,
	}, []string{"profile"})

	redirectCountMetric = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sso_redirect_count",
		Help:    "Number of HTTP redirects in authentication flow by authentication profile",
		Buckets: []float64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	}, []string{"profile"})

	sessionAccessDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sso_session_access_duration_seconds",
		Help:    "Duration of accessing protected resource with valid session by authentication profile",
		Buckets: prometheus.DefBuckets,
	}, []string{"profile"})

	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sso_request_duration_seconds",
		Help:    "Duration of each HTTP request",
		Buckets: prometheus.DefBuckets,
	}, []string{"path"})

	activeSessions = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sso_active_sessions",
		Help: "Number of active sessions by authentication profile",
	}, []string{"profile"})

	protocolPayloadSizeBytes = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sso_protocol_payload_size_bytes",
		Help:    "Size of OIDC ID token payload in bytes by authentication profile",
		Buckets: []float64{128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768},
	}, []string{"profile"})
)

type authProfile struct {
	ID               string
	Name             string
	Description      string
	Kind             string
	Config           *oauth2.Config
	Provider         *oidc.Provider
	Verifier         *oidc.IDTokenVerifier
}

type loginTracking struct {
	StartedAt time.Time
	ProfileID string
	Redirects int
}

type server struct {
	sessionStore    *sessions.CookieStore
	profiles        map[string]*authProfile
	store           appStore
	webAuthn        *webauthn.WebAuthn
	webAuthnUserID  string
	loginStart      map[string]loginTracking
	webAuthnSession map[string]webAuthnTracking
	mu              sync.Mutex
}

type webAuthnTracking struct {
	Session   webauthn.SessionData
	UserID    string
	StartedAt time.Time
	ProfileID string
}

type webAuthnUser struct {
	id          string
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte {
	return []byte(u.id)
}

func (u *webAuthnUser) WebAuthnName() string {
	return u.name
}

func (u *webAuthnUser) WebAuthnDisplayName() string {
	return u.displayName
}

func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

type appStore interface {
	EnsureSchema(context.Context) error
	UpsertLocalUser(context.Context, string, string) error
	AuthenticateLocalUser(context.Context, string, string) (bool, error)
	GetOrCreateWebAuthnUser(context.Context, string) (*webAuthnUser, error)
	SaveWebAuthnCredential(context.Context, string, webauthn.Credential) error
	FindWebAuthnUserByCredential(context.Context, []byte, []byte) (*webAuthnUser, error)
	UpdateWebAuthnCredential(context.Context, string, webauthn.Credential) error
}

type logEvent struct {
	Timestamp     string `json:"timestamp"`
	RequestID     string `json:"request_id"`
	Profile       string `json:"profile,omitempty"`
	Event         string `json:"event"`
	User          string `json:"user,omitempty"`
	DurationMs    int64  `json:"duration_ms,omitempty"`
	RedirectCount int    `json:"redirect_count,omitempty"`
	Status        string `json:"status"`
	Error         string `json:"error,omitempty"`
	Path          string `json:"path,omitempty"`
	Method        string `json:"method,omitempty"`
}

type memoryStore struct {
	mu                  sync.Mutex
	localPasswordHashes map[string][]byte
	webAuthnUsers       map[string]*webAuthnUser
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		localPasswordHashes: make(map[string][]byte),
		webAuthnUsers:       make(map[string]*webAuthnUser),
	}
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (s *memoryStore) EnsureSchema(context.Context) error {
	return nil
}

func (s *memoryStore) UpsertLocalUser(ctx context.Context, username, password string) error {
	_ = normalizeContext(ctx)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash local password: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localPasswordHashes[username] = hash
	return nil
}

func (s *memoryStore) AuthenticateLocalUser(ctx context.Context, username, password string) (bool, error) {
	_ = normalizeContext(ctx)
	s.mu.Lock()
	hash := append([]byte(nil), s.localPasswordHashes[username]...)
	s.mu.Unlock()
	if len(hash) == 0 {
		return false, nil
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		return false, nil
	}
	return true, nil
}

func (s *memoryStore) GetOrCreateWebAuthnUser(ctx context.Context, userID string) (*webAuthnUser, error) {
	_ = normalizeContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.webAuthnUsers[userID]
	if !ok {
		user = &webAuthnUser{id: userID, name: userID, displayName: userID}
		s.webAuthnUsers[userID] = user
	}
	return cloneWebAuthnUser(user), nil
}

func (s *memoryStore) SaveWebAuthnCredential(ctx context.Context, userID string, credential webauthn.Credential) error {
	_ = normalizeContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.webAuthnUsers[userID]
	if !ok {
		user = &webAuthnUser{id: userID, name: userID, displayName: userID}
		s.webAuthnUsers[userID] = user
	}
	for i := range user.credentials {
		if bytes.Equal(user.credentials[i].ID, credential.ID) {
			user.credentials[i] = credential
			return nil
		}
	}
	user.credentials = append(user.credentials, credential)
	return nil
}

func (s *memoryStore) FindWebAuthnUserByCredential(ctx context.Context, rawID, userHandle []byte) (*webAuthnUser, error) {
	_ = normalizeContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(userHandle) > 0 {
		if user, ok := s.webAuthnUsers[string(userHandle)]; ok {
			return cloneWebAuthnUser(user), nil
		}
	}
	for _, user := range s.webAuthnUsers {
		for _, credential := range user.credentials {
			if bytes.Equal(credential.ID, rawID) {
				return cloneWebAuthnUser(user), nil
			}
		}
	}
	return nil, errors.New("webauthn user not found")
}

func (s *memoryStore) UpdateWebAuthnCredential(ctx context.Context, userID string, credential webauthn.Credential) error {
	return s.SaveWebAuthnCredential(ctx, userID, credential)
}

type postgresStore struct {
	pool *pgxpool.Pool
}

func newPostgresStore(ctx context.Context, databaseURL string) (*postgresStore, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect app database: %w", err)
	}
	return &postgresStore{pool: pool}, nil
}

func (s *postgresStore) EnsureSchema(ctx context.Context) error {
	ctx = normalizeContext(ctx)
	_, err := s.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS local_users (
	username TEXT PRIMARY KEY,
	password_hash BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS webauthn_credentials (
	user_id TEXT NOT NULL,
	credential_id BYTEA PRIMARY KEY,
	public_key BYTEA NOT NULL,
	sign_count INTEGER NOT NULL,
	credential_json JSONB NOT NULL
);`)
	if err != nil {
		return fmt.Errorf("ensure app schema: %w", err)
	}
	return nil
}

func (s *postgresStore) UpsertLocalUser(ctx context.Context, username, password string) error {
	ctx = normalizeContext(ctx)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash local password: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO local_users (username, password_hash)
VALUES ($1, $2)
ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash`, username, hash)
	if err != nil {
		return fmt.Errorf("upsert local user: %w", err)
	}
	return nil
}

func (s *postgresStore) AuthenticateLocalUser(ctx context.Context, username, password string) (bool, error) {
	ctx = normalizeContext(ctx)
	var hash []byte
	if err := s.pool.QueryRow(ctx, `SELECT password_hash FROM local_users WHERE username = $1`, username).Scan(&hash); err != nil {
		return false, nil
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		return false, nil
	}
	return true, nil
}

func (s *postgresStore) GetOrCreateWebAuthnUser(ctx context.Context, userID string) (*webAuthnUser, error) {
	ctx = normalizeContext(ctx)
	credentials, err := s.loadCredentials(ctx, `WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	return &webAuthnUser{id: userID, name: userID, displayName: userID, credentials: credentials}, nil
}

func (s *postgresStore) SaveWebAuthnCredential(ctx context.Context, userID string, credential webauthn.Credential) error {
	ctx = normalizeContext(ctx)
	data, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("marshal webauthn credential: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, credential_json)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (credential_id) DO UPDATE
SET user_id = EXCLUDED.user_id,
    public_key = EXCLUDED.public_key,
    sign_count = EXCLUDED.sign_count,
    credential_json = EXCLUDED.credential_json`,
		userID, credential.ID, credential.PublicKey, credential.Authenticator.SignCount, data)
	if err != nil {
		return fmt.Errorf("save webauthn credential: %w", err)
	}
	return nil
}

func (s *postgresStore) FindWebAuthnUserByCredential(ctx context.Context, rawID, userHandle []byte) (*webAuthnUser, error) {
	ctx = normalizeContext(ctx)
	if len(userHandle) > 0 {
		return s.GetOrCreateWebAuthnUser(ctx, string(userHandle))
	}
	var userID string
	if err := s.pool.QueryRow(ctx, `SELECT user_id FROM webauthn_credentials WHERE credential_id = $1`, rawID).Scan(&userID); err != nil {
		return nil, fmt.Errorf("find webauthn credential owner: %w", err)
	}
	return s.GetOrCreateWebAuthnUser(ctx, userID)
}

func (s *postgresStore) UpdateWebAuthnCredential(ctx context.Context, userID string, credential webauthn.Credential) error {
	return s.SaveWebAuthnCredential(ctx, userID, credential)
}

func (s *postgresStore) loadCredentials(ctx context.Context, where string, args ...interface{}) ([]webauthn.Credential, error) {
	rows, err := s.pool.Query(ctx, `SELECT credential_json FROM webauthn_credentials `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("load webauthn credentials: %w", err)
	}
	defer rows.Close()

	var credentials []webauthn.Credential
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("scan webauthn credential: %w", err)
		}
		var credential webauthn.Credential
		if err := json.Unmarshal(data, &credential); err != nil {
			return nil, fmt.Errorf("decode webauthn credential: %w", err)
		}
		credentials = append(credentials, credential)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate webauthn credentials: %w", err)
	}
	return credentials, nil
}

func cloneWebAuthnUser(user *webAuthnUser) *webAuthnUser {
	clone := *user
	clone.credentials = append([]webauthn.Credential(nil), user.credentials...)
	return &clone
}

func main() {
	s, err := newServerFromEnv(context.Background())
	if err != nil {
		log.Fatalf("init app: %v", err)
	}

	port := getenv("PORT", "8080")
	log.Printf("SSO test app starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, s.loggingMiddleware(s.routes())))
}

func newServerFromEnv(ctx context.Context) (*server, error) {
	appBaseURL := strings.TrimRight(getenv("APP_BASE_URL", "http://app.localhost"), "/")
	keycloakHost := getenv("KEYCLOAK_ISSUER_HOST", "keycloak.localhost")
	keycloakInternalHost := getenv("KEYCLOAK_INTERNAL_HOST", "keycloak")
	keycloakPort := getenv("KEYCLOAK_PORT", "8080")

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				addr = strings.ReplaceAll(addr, keycloakHost, keycloakInternalHost)
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
	oidcCtx := oidc.ClientContext(ctx, httpClient)

	profileA, err := buildOIDCProfile(oidcCtx, "profile-a", "Profile A: Keycloak password", "Federated OpenID Connect login with username and password.", appBaseURL, keycloakHost, keycloakPort, getenv("PROFILE_A_REALM", "profile-a"), getenv("PROFILE_A_CLIENT_ID", "sso-test-app"), getenv("PROFILE_A_CLIENT_SECRET", "profile-a-secret"))
	if err != nil {
		return nil, err
	}

	store, err := newStoreFromEnv(ctx)
	if err != nil {
		return nil, err
	}
	if err := store.EnsureSchema(ctx); err != nil {
		return nil, err
	}
	if err := store.UpsertLocalUser(ctx, getenv("LOCAL_LOGIN_USERNAME", "testuser1"), getenv("LOCAL_LOGIN_PASSWORD", "password123")); err != nil {
		return nil, err
	}

	webAuthn, err := newWebAuthnProvider(getenv("WEBAUTHN_RP_ID", "localhost"), splitCSV(getenv("WEBAUTHN_RP_ORIGINS", "http://localhost:8081,https://localhost:8443")))
	if err != nil {
		return nil, err
	}

	sessionStore := sessions.NewCookieStore([]byte(getenv("SESSION_SECRET", "change-me-in-production")))
	sessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	return &server{
		sessionStore: sessionStore,
		profiles: map[string]*authProfile{
			profileA.ID: profileA,
			"profile-b": {
				ID:          "profile-b",
				Name:        "Profile B: WebAuthn/FIDO2 Passkeys",
				Description: "Direct browser-to-application WebAuthn passkey login without Keycloak or OIDC redirects.",
				Kind:        profileKindWebAuthn,
			},
			"profile-c": {
				ID:          "profile-c",
				Name:        "Profile C: Vaultwarden credentials",
				Description: "Vaultwarden-assisted local login checked against the application database.",
				Kind:        profileKindLocal,
			},
		},
		store:           store,
		webAuthn:        webAuthn,
		webAuthnUserID:  getenv("WEBAUTHN_USER_ID", "passkey-user"),
		loginStart:      make(map[string]loginTracking),
		webAuthnSession: make(map[string]webAuthnTracking),
	}, nil
}

func newStoreFromEnv(ctx context.Context) (appStore, error) {
	databaseURL := os.Getenv("APP_DATABASE_URL")
	if databaseURL == "" {
		return newMemoryStore(), nil
	}
	return newPostgresStore(ctx, databaseURL)
}

func newWebAuthnProvider(rpID string, origins []string) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPDisplayName: "SSO Testbed",
		RPID:          rpID,
		RPOrigins:     origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
	})
}

func buildOIDCProfile(ctx context.Context, id, name, description, appBaseURL, keycloakHost, keycloakPort, realm, clientID, clientSecret string) (*authProfile, error) {
	issuerURL := fmt.Sprintf("http://%s:%s/realms/%s", keycloakHost, keycloakPort, realm)
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover %s provider: %w", id, err)
	}

	return &authProfile{
		ID:          id,
		Name:        name,
		Description: description,
		Kind:        profileKindOIDC,
		Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  fmt.Sprintf("%s/callback/%s", appBaseURL, id),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		Provider: provider,
		Verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
	}, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleProfiles)
	mux.HandleFunc("/profiles", s.handleProfiles)
	mux.HandleFunc("/protected", s.handleProtected)
	mux.HandleFunc("/webauthn/register/begin", s.handleWebAuthnRegisterBegin)
	mux.HandleFunc("/webauthn/register/finish", s.handleWebAuthnRegisterFinish)
	mux.HandleFunc("/webauthn/login/begin", s.handleWebAuthnLoginBegin)
	mux.HandleFunc("/webauthn/login/finish", s.handleWebAuthnLoginFinish)
	mux.HandleFunc("/login/", s.handleLogin)
	mux.HandleFunc("/callback/", s.handleCallback)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/metrics", promhttp.Handler().ServeHTTP)
	return mux
}

func (s *server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/profiles" {
		http.NotFound(w, r)
		return
	}
	profiles := make([]*authProfile, 0, len(s.profiles))
	for _, profile := range s.profiles {
		profiles = append(profiles, profile)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })

	renderHTML(w, profilesTemplate, map[string]interface{}{
		"Profiles": profiles,
	})
}

func (s *server) handleProtected(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	session, _ := s.sessionStore.Get(r, "session")
	user, _ := session.Values["user"].(string)
	profileID, _ := session.Values["profile"].(string)
	if user == "" || profileID == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	sessionAccessDuration.WithLabelValues(profileID).Observe(time.Since(start).Seconds())
	renderHTML(w, protectedTemplate, map[string]interface{}{
		"User":    user,
		"Profile": profileID,
	})
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	profileID := strings.TrimPrefix(r.URL.Path, "/login/")
	profile, ok := s.profiles[profileID]
	if !ok {
		http.NotFound(w, r)
		return
	}

	switch profile.Kind {
	case profileKindOIDC:
		s.startOIDCLogin(w, r, profile)
	case profileKindLocal:
		s.handleLocalLogin(w, r, profile)
	case profileKindWebAuthn:
		s.handleWebAuthnLoginPage(w, r, profile)
	default:
		http.Error(w, "Unsupported authentication profile", http.StatusBadRequest)
	}
}

func (s *server) handleWebAuthnLoginPage(w http.ResponseWriter, r *http.Request, profile *authProfile) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	renderHTML(w, webAuthnTemplate, map[string]interface{}{"Profile": profile})
}

func (s *server) startOIDCLogin(w http.ResponseWriter, r *http.Request, profile *authProfile) {
	loginAttempts.WithLabelValues(profile.ID).Inc()
	requestID := newRequestID()
	state, err := randomString(32)
	if err != nil {
		loginErrors.WithLabelValues(profile.ID).Inc()
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	s.startTracking(requestID, profile.ID, 1)
	session, _ := s.sessionStore.Get(r, "session")
	session.Values["oauth_state"] = state
	session.Values["correlation_id"] = requestID
	session.Values["profile"] = profile.ID
	if err := session.Save(r, w); err != nil {
		loginErrors.WithLabelValues(profile.ID).Inc()
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	s.logEvent(logEvent{RequestID: requestID, Profile: profile.ID, Event: "redirect_to_idp", RedirectCount: 1, Status: "info"})
	http.Redirect(w, r, profile.Config.AuthCodeURL(state, oauth2.AccessTypeOffline), http.StatusFound)
}

func (s *server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, err := s.store.GetOrCreateWebAuthnUser(r.Context(), s.webAuthnUserID)
	if err != nil {
		http.Error(w, "Failed to load WebAuthn user", http.StatusInternalServerError)
		return
	}
	creation, sessionData, err := s.webAuthn.BeginRegistration(
		user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExclusions(webauthn.Credentials(user.WebAuthnCredentials()).CredentialDescriptors()),
	)
	if err != nil {
		http.Error(w, "Failed to begin WebAuthn registration", http.StatusInternalServerError)
		return
	}

	flowID, err := randomString(32)
	if err != nil {
		http.Error(w, "Failed to create WebAuthn flow", http.StatusInternalServerError)
		return
	}
	s.saveWebAuthnFlow(flowID, webAuthnTracking{Session: *sessionData, UserID: user.id, ProfileID: "profile-b"})
	session, _ := s.sessionStore.Get(r, "session")
	session.Values["webauthn_register_flow"] = flowID
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	writeJSON(w, creation)
}

func (s *server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session, _ := s.sessionStore.Get(r, "session")
	flowID, _ := session.Values["webauthn_register_flow"].(string)
	tracking, ok := s.consumeWebAuthnFlow(flowID)
	if !ok {
		http.Error(w, "Missing WebAuthn registration session", http.StatusBadRequest)
		return
	}
	user, err := s.store.GetOrCreateWebAuthnUser(r.Context(), tracking.UserID)
	if err != nil {
		http.Error(w, "Failed to load WebAuthn user", http.StatusInternalServerError)
		return
	}
	credential, err := s.webAuthn.FinishRegistration(user, tracking.Session, r)
	if err != nil {
		loginErrors.WithLabelValues("profile-b").Inc()
		http.Error(w, "Failed to finish WebAuthn registration", http.StatusBadRequest)
		return
	}
	if err := s.store.SaveWebAuthnCredential(r.Context(), user.id, *credential); err != nil {
		http.Error(w, "Failed to save WebAuthn credential", http.StatusInternalServerError)
		return
	}
	if err := s.setAuthenticatedSession(r, w, session, user.id, "profile-b"); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"redirect": "/protected"})
}

func (s *server) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	loginAttempts.WithLabelValues("profile-b").Inc()
	requestID := newRequestID()
	assertion, sessionData, err := s.webAuthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		loginErrors.WithLabelValues("profile-b").Inc()
		http.Error(w, "Failed to begin WebAuthn login", http.StatusInternalServerError)
		return
	}

	flowID, err := randomString(32)
	if err != nil {
		loginErrors.WithLabelValues("profile-b").Inc()
		http.Error(w, "Failed to create WebAuthn flow", http.StatusInternalServerError)
		return
	}
	s.saveWebAuthnFlow(flowID, webAuthnTracking{Session: *sessionData, StartedAt: time.Now(), ProfileID: "profile-b"})
	session, _ := s.sessionStore.Get(r, "session")
	session.Values["webauthn_login_flow"] = flowID
	session.Values["correlation_id"] = requestID
	if err := session.Save(r, w); err != nil {
		loginErrors.WithLabelValues("profile-b").Inc()
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	writeJSON(w, assertion)
}

func (s *server) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session, _ := s.sessionStore.Get(r, "session")
	flowID, _ := session.Values["webauthn_login_flow"].(string)
	tracking, ok := s.consumeWebAuthnFlow(flowID)
	if !ok {
		loginErrors.WithLabelValues("profile-b").Inc()
		http.Error(w, "Missing WebAuthn login session", http.StatusBadRequest)
		return
	}

	var authenticatedUser *webAuthnUser
	user, credential, err := s.webAuthn.FinishPasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		loadedUser, loadErr := s.store.FindWebAuthnUserByCredential(r.Context(), rawID, userHandle)
		if loadErr != nil {
			return nil, loadErr
		}
		authenticatedUser = loadedUser
		return loadedUser, nil
	}, tracking.Session, r)
	if err != nil {
		loginErrors.WithLabelValues("profile-b").Inc()
		http.Error(w, "Failed to finish WebAuthn login", http.StatusUnauthorized)
		return
	}
	if authenticatedUser == nil {
		var ok bool
		authenticatedUser, ok = user.(*webAuthnUser)
		if !ok {
			loginErrors.WithLabelValues("profile-b").Inc()
			http.Error(w, "Failed to resolve WebAuthn user", http.StatusInternalServerError)
			return
		}
	}
	if err := s.store.UpdateWebAuthnCredential(r.Context(), authenticatedUser.id, *credential); err != nil {
		http.Error(w, "Failed to update WebAuthn credential", http.StatusInternalServerError)
		return
	}
	if !tracking.StartedAt.IsZero() {
		loginDuration.WithLabelValues("profile-b").Observe(time.Since(tracking.StartedAt).Seconds())
	}
	redirectCountMetric.WithLabelValues("profile-b").Observe(0)
	loginSuccess.WithLabelValues("profile-b").Inc()
	activeSessions.WithLabelValues("profile-b").Inc()
	if err := s.setAuthenticatedSession(r, w, session, authenticatedUser.id, "profile-b"); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"redirect": "/protected"})
}

func (s *server) handleLocalLogin(w http.ResponseWriter, r *http.Request, profile *authProfile) {
	if r.Method == http.MethodGet {
		renderHTML(w, localLoginTemplate, map[string]interface{}{"Profile": profile})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	loginAttempts.WithLabelValues(profile.ID).Inc()
	start := time.Now()
	if err := r.ParseForm(); err != nil {
		loginErrors.WithLabelValues(profile.ID).Inc()
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	username := r.Form.Get("username")
	ok, err := s.store.AuthenticateLocalUser(r.Context(), username, r.Form.Get("password"))
	if err != nil {
		loginErrors.WithLabelValues(profile.ID).Inc()
		http.Error(w, "Failed to check credentials", http.StatusInternalServerError)
		return
	}
	if !ok {
		loginErrors.WithLabelValues(profile.ID).Inc()
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	session, _ := s.sessionStore.Get(r, "session")
	if err := s.setAuthenticatedSession(r, w, session, username, profile.ID); err != nil {
		loginErrors.WithLabelValues(profile.ID).Inc()
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	loginDuration.WithLabelValues(profile.ID).Observe(time.Since(start).Seconds())
	redirectCountMetric.WithLabelValues(profile.ID).Observe(0)
	loginSuccess.WithLabelValues(profile.ID).Inc()
	activeSessions.WithLabelValues(profile.ID).Inc()
	http.Redirect(w, r, "/protected", http.StatusFound)
}

func (s *server) handleCallback(w http.ResponseWriter, r *http.Request) {
	profileID := strings.TrimPrefix(r.URL.Path, "/callback/")
	profile, ok := s.profiles[profileID]
	if !ok || profile.Kind != profileKindOIDC {
		http.NotFound(w, r)
		return
	}

	session, _ := s.sessionStore.Get(r, "session")
	correlationID, _ := session.Values["correlation_id"].(string)
	if correlationID == "" {
		correlationID = newRequestID()
	}
	tracking := s.incrementRedirects(correlationID)

	state := r.URL.Query().Get("state")
	savedState, _ := session.Values["oauth_state"].(string)
	if savedState == "" || state != savedState {
		loginErrors.WithLabelValues(profile.ID).Inc()
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		loginErrors.WithLabelValues(profile.ID).Inc()
		http.Error(w, fmt.Sprintf("Authorization error: %s", errMsg), http.StatusBadRequest)
		return
	}

	tokenConfig := profile.Config
	verifier := profile.Verifier
	oauth2Token, err := tokenConfig.Exchange(oidc.ClientContext(r.Context(), oidcHTTPClient()), r.URL.Query().Get("code"))
	if err != nil {
		loginErrors.WithLabelValues(profile.ID).Inc()
		http.Error(w, "Failed to exchange authorization code", http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		loginErrors.WithLabelValues(profile.ID).Inc()
		http.Error(w, "ID token not found", http.StatusInternalServerError)
		return
	}
	protocolPayloadSizeBytes.WithLabelValues(profile.ID).Observe(float64(len(rawIDToken)))

	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		loginErrors.WithLabelValues(profile.ID).Inc()
		http.Error(w, "Failed to verify ID token", http.StatusInternalServerError)
		return
	}
	claims := make(map[string]interface{})
	if err := idToken.Claims(&claims); err != nil {
		loginErrors.WithLabelValues(profile.ID).Inc()
		http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
		return
	}

	user := claimString(claims, "email")
	if user == "" {
		user = claimString(claims, "preferred_username")
	}
	if user == "" {
		user = claimString(claims, "sub")
	}

	session.Values["user"] = user
	session.Values["profile"] = profile.ID
	session.Values["authenticated"] = true
	delete(session.Values, "oauth_state")
	if err := session.Save(r, w); err != nil {
		loginErrors.WithLabelValues(profile.ID).Inc()
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	if !tracking.StartedAt.IsZero() {
		loginDuration.WithLabelValues(profile.ID).Observe(time.Since(tracking.StartedAt).Seconds())
	}
	redirectCountMetric.WithLabelValues(profile.ID).Observe(float64(tracking.Redirects))
	loginSuccess.WithLabelValues(profile.ID).Inc()
	activeSessions.WithLabelValues(profile.ID).Inc()
	s.logEvent(logEvent{RequestID: correlationID, Profile: profile.ID, Event: "login_success", User: user, RedirectCount: tracking.Redirects, Status: "success"})
	http.Redirect(w, r, "/protected", http.StatusFound)
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := s.sessionStore.Get(r, "session")
	profileID, _ := session.Values["profile"].(string)
	if session.Values["authenticated"] == true && profileID != "" {
		activeSessions.WithLabelValues(profileID).Dec()
	}
	session.Values = make(map[interface{}]interface{})
	session.Options.MaxAge = -1
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *server) startTracking(requestID, profileID string, redirects int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loginStart[requestID] = loginTracking{StartedAt: time.Now(), ProfileID: profileID, Redirects: redirects}
}

func (s *server) incrementRedirects(requestID string) loginTracking {
	s.mu.Lock()
	defer s.mu.Unlock()
	tracking := s.loginStart[requestID]
	tracking.Redirects++
	delete(s.loginStart, requestID)
	return tracking
}

func (s *server) saveWebAuthnFlow(flowID string, tracking webAuthnTracking) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webAuthnSession[flowID] = tracking
}

func (s *server) consumeWebAuthnFlow(flowID string) (webAuthnTracking, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tracking, ok := s.webAuthnSession[flowID]
	if ok {
		delete(s.webAuthnSession, flowID)
	}
	return tracking, ok
}

func (s *server) setAuthenticatedSession(r *http.Request, w http.ResponseWriter, session *sessions.Session, user, profileID string) error {
	session.Values["user"] = user
	session.Values["profile"] = profileID
	session.Values["authenticated"] = true
	delete(session.Values, "webauthn_register_flow")
	delete(session.Values, "webauthn_login_flow")
	return session.Save(r, w)
}

func (s *server) logEvent(evt logEvent) {
	evt.Timestamp = time.Now().Format(time.RFC3339)
	data, err := json.Marshal(evt)
	if err != nil {
		log.Printf(`{"event":"log_marshal_error","error":%q}`, err.Error())
		return
	}
	log.Println(string(data))
}

func (s *server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		requestDuration.WithLabelValues(r.URL.Path).Observe(time.Since(start).Seconds())
	})
}

func renderHTML(w http.ResponseWriter, tmpl string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t := template.Must(template.New("page").Parse(tmpl))
	if err := t.Execute(w, data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)
	}
}

func oidcHTTPClient() *http.Client {
	keycloakHost := getenv("KEYCLOAK_ISSUER_HOST", "keycloak.localhost")
	keycloakInternalHost := getenv("KEYCLOAK_INTERNAL_HOST", "keycloak")
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				addr = strings.ReplaceAll(addr, keycloakHost, keycloakInternalHost)
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
}

func claimString(claims map[string]interface{}, key string) string {
	value, ok := claims[key].(string)
	if !ok {
		return ""
	}
	return value
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func newRequestID() string {
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

const profilesTemplate = `<!DOCTYPE html>
<html>
<head><title>SSO Test Stand</title></head>
<body>
  <h1>SSO Authentication Profiles</h1>
  <p>Select an authentication profile for the protected application.</p>
  <ul>
    {{range .Profiles}}
    <li data-profile="{{.ID}}">
      <h2>{{.Name}}</h2>
      <p>{{.Description}}</p>
      <a href="/login/{{.ID}}">Login with {{.Name}}</a>
    </li>
    {{end}}
  </ul>
</body>
</html>`

const protectedTemplate = `<!DOCTYPE html>
<html>
<head><title>Protected Resource</title></head>
<body>
  <h1>Protected Resource</h1>
  <p>Welcome, <strong>{{.User}}</strong>.</p>
  <p>Authenticated with <strong>{{.Profile}}</strong>.</p>
  <p><a href="/logout">Logout</a></p>
</body>
</html>`

const localLoginTemplate = `<!DOCTYPE html>
<html>
<head><title>{{.Profile.Name}}</title></head>
<body>
  <h1>{{.Profile.Name}}</h1>
  <p>Use credentials stored in Vaultwarden/Bitwarden to fill this form.</p>
  <form method="post" action="/login/{{.Profile.ID}}">
    <label>Username <input name="username" autocomplete="username"></label>
    <label>Password <input name="password" type="password" autocomplete="current-password"></label>
    <button type="submit">Login</button>
  </form>
</body>
</html>`

const webAuthnTemplate = `<!DOCTYPE html>
<html>
<head><title>{{.Profile.Name}}</title></head>
<body>
  <h1>{{.Profile.Name}}</h1>
  <p>This profile uses direct WebAuthn/FIDO2 passkeys. There is no Keycloak, OIDC redirect, callback, token, or password.</p>
  <button id="register-passkey" type="button">Register passkey</button>
  <button id="login-passkey" type="button">Login with passkey</button>
  <p id="status" role="status"></p>
  <script>
    function decodeBase64URL(value) {
      const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
      const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
      const binary = atob(padded);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes.buffer;
    }

    function encodeBase64URL(buffer) {
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (const byte of bytes) {
        binary += String.fromCharCode(byte);
      }
      return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }

    function prepareCreationOptions(options) {
      const publicKey = options.publicKey;
      publicKey.challenge = decodeBase64URL(publicKey.challenge);
      publicKey.user.id = decodeBase64URL(publicKey.user.id);
      if (publicKey.excludeCredentials) {
        publicKey.excludeCredentials = publicKey.excludeCredentials.map((credential) => ({
          ...credential,
          id: decodeBase64URL(credential.id),
        }));
      }
      return publicKey;
    }

    function prepareRequestOptions(options) {
      const publicKey = options.publicKey;
      publicKey.challenge = decodeBase64URL(publicKey.challenge);
      if (publicKey.allowCredentials) {
        publicKey.allowCredentials = publicKey.allowCredentials.map((credential) => ({
          ...credential,
          id: decodeBase64URL(credential.id),
        }));
      }
      return publicKey;
    }

    function credentialToJSON(credential) {
      const response = credential.response;
      const json = {
        id: credential.id,
        rawId: encodeBase64URL(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: encodeBase64URL(response.clientDataJSON),
        },
      };
      if (response.attestationObject) {
        json.response.attestationObject = encodeBase64URL(response.attestationObject);
      }
      if (response.authenticatorData) {
        json.response.authenticatorData = encodeBase64URL(response.authenticatorData);
        json.response.signature = encodeBase64URL(response.signature);
        json.response.userHandle = response.userHandle ? encodeBase64URL(response.userHandle) : null;
      }
      return json;
    }

    async function postJSON(url, payload) {
      const response = await fetch(url, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: payload ? JSON.stringify(payload) : undefined,
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      return response.json();
    }

    async function registerPasskey() {
      document.getElementById('status').textContent = 'Registering passkey...';
      const options = await postJSON('/webauthn/register/begin');
      const credential = await navigator.credentials.create({publicKey: prepareCreationOptions(options)});
      const result = await postJSON('/webauthn/register/finish', credentialToJSON(credential));
      window.location.href = result.redirect || '/protected';
    }

    async function loginPasskey() {
      document.getElementById('status').textContent = 'Waiting for passkey...';
      const options = await postJSON('/webauthn/login/begin');
      const credential = await navigator.credentials.get({publicKey: prepareRequestOptions(options)});
      const result = await postJSON('/webauthn/login/finish', credentialToJSON(credential));
      window.location.href = result.redirect || '/protected';
    }

    document.getElementById('register-passkey').addEventListener('click', () => registerPasskey().catch((error) => {
      document.getElementById('status').textContent = error.message;
    }));
    document.getElementById('login-passkey').addEventListener('click', () => loginPasskey().catch((error) => {
      document.getElementById('status').textContent = error.message;
    }));
  </script>
</body>
</html>`
