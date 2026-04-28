package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
)

func newTestServer() *server {
	store := newMemoryStore()
	if err := store.EnsureSchema(context.Background()); err != nil {
		panic(err)
	}
	if err := store.UpsertLocalUser(context.Background(), "testuser1", "password123"); err != nil {
		panic(err)
	}
	webAuthn, err := newWebAuthnProvider("localhost", []string{"https://localhost:8443"})
	if err != nil {
		panic(err)
	}
	return &server{
		sessionStore: sessions.NewCookieStore([]byte("test-session-secret")),
		profiles: map[string]*authProfile{
			"profile-a": {ID: "profile-a", Name: "Profile A", Kind: profileKindOIDC},
			"profile-b": {ID: "profile-b", Name: "Profile B", Kind: profileKindWebAuthn},
			"profile-c": {ID: "profile-c", Name: "Profile C", Kind: profileKindLocal},
		},
		store:           store,
		webAuthn:        webAuthn,
		webAuthnUserID:  "passkey-user",
		loginStart:      make(map[string]loginTracking),
		webAuthnSession: make(map[string]webAuthnTracking),
	}
}

func TestProfilesPageListsAllAuthenticationProfiles(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	for _, profileID := range []string{"profile-a", "profile-b", "profile-c"} {
		if !strings.Contains(body, `data-profile="`+profileID+`"`) {
			t.Fatalf("expected profiles page to contain %s, body: %s", profileID, body)
		}
	}
}

func TestProfilesPageLinksProfileBToDirectWebAuthnPage(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	s.routes().ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, `/register-passkey/profile-b`) {
		t.Fatalf("expected old Keycloak passkey registration link to be removed, body: %s", body)
	}
	if loginIndex := strings.Index(body, `/login/profile-b`); loginIndex < 0 {
		t.Fatalf("expected profile B login link, body: %s", body)
	}
}

func TestProfileBLoginRendersWebAuthnPageWithoutKeycloakRedirect(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/login/profile-b", nil)
	rec := httptest.NewRecorder()

	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "keycloak") || strings.Contains(body, "/callback/profile-b") {
		t.Fatalf("expected profile B page to be independent from Keycloak, body: %s", body)
	}
	for _, expected := range []string{"/webauthn/register/begin", "/webauthn/register/finish", "/webauthn/login/begin", "/webauthn/login/finish"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected profile B page to reference %s, body: %s", expected, body)
		}
	}
}

func TestWebAuthnRegisterBeginReturnsChallengeForLocalRelyingParty(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/begin", nil)
	rec := httptest.NewRecorder()

	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	response, ok := payload["publicKey"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected publicKey options, got: %#v", payload)
	}
	rp, ok := response["rp"].(map[string]interface{})
	if !ok || rp["id"] != "localhost" {
		t.Fatalf("expected localhost relying party, got: %#v", response["rp"])
	}
}

func TestProtectedRedirectsAnonymousUserToProfilesPage(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()

	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rec.Code)
	}
	if location := rec.Header().Get("Location"); location != "/" {
		t.Fatalf("expected redirect to /, got %q", location)
	}
}

func TestProfileCLocalLoginAuthenticatesUser(t *testing.T) {
	s := newTestServer()
	form := url.Values{}
	form.Set("username", "testuser1")
	form.Set("password", "password123")
	req := httptest.NewRequest(http.MethodPost, "/login/profile-c", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rec.Code)
	}
	if location := rec.Header().Get("Location"); location != "/protected" {
		t.Fatalf("expected redirect to /protected, got %q", location)
	}

	protectedReq := httptest.NewRequest(http.MethodGet, "/protected", nil)
	for _, cookie := range rec.Result().Cookies() {
		protectedReq.AddCookie(cookie)
	}
	protectedRec := httptest.NewRecorder()

	s.routes().ServeHTTP(protectedRec, protectedReq)

	if protectedRec.Code != http.StatusOK {
		t.Fatalf("expected protected status %d, got %d", http.StatusOK, protectedRec.Code)
	}
	if body := protectedRec.Body.String(); !strings.Contains(body, "testuser1") || !strings.Contains(body, "profile-c") {
		t.Fatalf("expected protected page to include user and profile, body: %s", body)
	}
}

func TestProfileCLocalLoginRejectsPasswordAfterDatabaseChange(t *testing.T) {
	s := newTestServer()
	if err := s.store.UpsertLocalUser(context.Background(), "testuser1", "changed-password"); err != nil {
		t.Fatalf("update local user: %v", err)
	}
	form := url.Values{}
	form.Set("username", "testuser1")
	form.Set("password", "password123")
	req := httptest.NewRequest(http.MethodPost, "/login/profile-c", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}
