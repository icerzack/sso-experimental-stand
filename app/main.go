package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

var store *sessions.CookieStore

func main() {
	authMode := getenv("AUTH_MODE", "oidc")
	hardened := getenv("HARDENED", "false") == "true"
	port := getenv("PORT", "8080")

	sessionSecret := getenv("SESSION_SECRET", "insecure-key")
	if hardened {
		sessionSecret = getenv("SESSION_SECRET", "replace-with-64-char-random-secret")
	}
	store = sessions.NewCookieStore([]byte(sessionSecret))

	switch authMode {
	case "oidc":
		runOIDC(hardened, port)
	case "saml":
		runSAML(hardened, port)
	case "forward-auth":
		runForwardAuth(hardened, port)
	default:
		log.Fatalf("unknown AUTH_MODE: %s (expected 'oidc', 'saml', or 'forward-auth')", authMode)
	}
}

func runOIDC(hardened bool, port string) {
	appBase := strings.TrimRight(getenv("APP_BASE_URL", "https://app.sso-lab.local"), "/")
	idpExternalHost := getenv("IDP_ISSUER_HOST", "keycloak.sso-lab.local")
	idpInternalHost := getenv("IDP_INTERNAL_HOST", "idp")
	idpPort := getenv("IDP_PORT", "8080")
	realm := getenv("OIDC_REALM", "master")
	clientID := getenv("CLIENT_ID", "sso-test-app")
	clientSecret := getenv("CLIENT_SECRET", "testpass123")
	allowedDomain := getenv("ALLOWED_REDIRECT_DOMAIN", "app.sso-lab.local")
	idpScheme := getenv("IDP_SCHEME", "https")

	setupSessionOptions(hardened)

	httpClient := internalHTTPClientWithPort(idpExternalHost, idpInternalHost, idpPort)

	// Build the OIDC issuer URL.
	// IDP_EXTERNAL_URL takes priority — use it when the full URL is known
	// (avoids issues with port numbers in reverse-proxy setups).
	// Otherwise fall back to constructing from parts.
	var issuer string
	if extURL := getenv("IDP_EXTERNAL_URL", ""); extURL != "" {
		// Do NOT strip the trailing slash — some IdPs (e.g. Authentik) include
		// it in their issuer string and the go-oidc library does an exact match.
		issuer = extURL
	} else {
		issuer = buildIssuerURL(idpScheme, idpExternalHost, realm)
	}

	provider, err := oidc.NewProvider(oidc.ClientContext(context.Background(), httpClient), issuer)
	if err != nil {
		// Retry: if the issuer mismatch is only a scheme difference (http vs https),
		// the IdP is behind a TLS-terminating reverse proxy and returns http URLs
		// in its discovery document while we connect via https.
		if strings.Contains(err.Error(), "issuer URL") {
			var altIssuer string
			if strings.HasPrefix(issuer, "https://") {
				altIssuer = "http://" + strings.TrimPrefix(issuer, "https://")
			} else if strings.HasPrefix(issuer, "http://") {
				altIssuer = "https://" + strings.TrimPrefix(issuer, "http://")
			}
			if altIssuer != "" {
				log.Printf("[oidc] issuer mismatch – retrying discovery with %s", altIssuer)
				altProvider, altErr := oidc.NewProvider(oidc.ClientContext(context.Background(), httpClient), altIssuer)
				if altErr == nil {
					log.Printf("[oidc] retry succeeded; overriding provider issuer to %s", issuer)
					provider = altProvider
					err = nil
				} else {
					log.Printf("[oidc] retry also failed: %v", altErr)
				}
			}
		}
		if err != nil {
			log.Fatalf("OIDC discovery failed for %s: %v", issuer, err)
		}
	}

	// Override the provider's endpoint URLs to use the correct scheme.
	// When the IdP sits behind a TLS-terminating proxy it may advertise
	// http:// endpoints in its discovery doc, but browser traffic actually
	// goes over https.  Patch auth/token/keys URLs so redirects work.
	ep := provider.Endpoint()
	patchEndpointScheme(&ep, idpScheme)
	oauth2Cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     ep,
		RedirectURL:  appBase + "/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	// Extract end_session_endpoint from the discovery document.
	var providerClaims struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&providerClaims); err != nil {
		log.Printf("[oidc] WARNING: could not parse provider claims for end_session_endpoint: %v", err)
	}
	// Patch the end_session_endpoint scheme too (same http→https issue).
	if providerClaims.EndSessionEndpoint != "" {
		providerClaims.EndSessionEndpoint = replaceScheme(providerClaims.EndSessionEndpoint, idpScheme)
	}

	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		render(w, homeTmpl, map[string]interface{}{
			"AuthMode":  "OIDC",
			"Hardened":  hardened,
			"LoginURL":  "/login",
		})
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		state, err := randomString(32)
		if err != nil {
			http.Error(w, "failed to generate state", http.StatusInternalServerError)
			return
		}

		sess, _ := store.Get(r, "sess")
		sess.Values["state"] = state

		var authURL string
		if hardened {
			verifier := oauth2.GenerateVerifier()
			sess.Values["pkce_verifier"] = verifier
			if next := r.URL.Query().Get("next"); isSafeRedirect(next) {
				sess.Values["next"] = next
			}
			if err := sess.Save(r, w); err != nil {
				http.Error(w, "session save failed", http.StatusInternalServerError)
				return
			}
			authURL = oauth2Cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
		} else {
			if next := r.URL.Query().Get("next"); next != "" && isAllowedRedirectVuln(next, allowedDomain) {
				sess.Values["next"] = next
			}
			_ = sess.Save(r, w)
			authURL = oauth2Cfg.AuthCodeURL(state)
		}

		http.Redirect(w, r, authURL, http.StatusFound)
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, "sess")

		if hardened {
			savedState, _ := sess.Values["state"].(string)
			if savedState == "" || r.URL.Query().Get("state") != savedState {
				http.Error(w, "invalid state parameter", http.StatusBadRequest)
				return
			}
			delete(sess.Values, "state")
		} else {
			delete(sess.Values, "state")
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code parameter", http.StatusBadRequest)
			return
		}

		var token *oauth2.Token
		var exchangeErr error

		if hardened {
			pkceVerifier, _ := sess.Values["pkce_verifier"].(string)
			delete(sess.Values, "pkce_verifier")
			token, exchangeErr = oauth2Cfg.Exchange(
				oidc.ClientContext(r.Context(), httpClient),
				code,
				oauth2.VerifierOption(pkceVerifier),
			)
		} else {
			token, exchangeErr = oauth2Cfg.Exchange(
				oidc.ClientContext(r.Context(), httpClient),
				code,
			)
		}

		if exchangeErr != nil {
			http.Error(w, "token exchange failed: "+exchangeErr.Error(), http.StatusBadRequest)
			return
		}

		rawID, _ := token.Extra("id_token").(string)
		idToken, err := idTokenVerifier.Verify(r.Context(), rawID)
		if err != nil {
			http.Error(w, "token verification failed: "+err.Error(), http.StatusBadRequest)
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

		if next != "" {
			if hardened && !isSafeRedirect(next) {
				next = "/dashboard"
			} else if !hardened && !isAllowedRedirectVuln(next, allowedDomain) {
				next = "/dashboard"
			}
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})

	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, "sess")
		user, _ := sess.Values["user"].(string)
		if user == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		render(w, dashboardTmpl, map[string]interface{}{
			"User":     user,
			"AuthMode": "OIDC",
			"Hardened": hardened,
		})
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, "sess")
		if hardened {
			sess.Values = make(map[interface{}]interface{})
		}
		sess.Options.MaxAge = -1
		_ = sess.Save(r, w)

		if hardened && providerClaims.EndSessionEndpoint != "" {
			// Use the end_session_endpoint from OIDC discovery — works with
			// any IdP (Keycloak, Authentik, Authelia, Zitadel, etc.).
			logoutURL := providerClaims.EndSessionEndpoint +
				"?client_id=" + url.QueryEscape(clientID) +
				"&post_logout_redirect_uri=" + url.QueryEscape(appBase)
			http.Redirect(w, r, logoutURL, http.StatusFound)
		} else {
			http.Redirect(w, r, "/", http.StatusFound)
		}
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	registerWebAuthnRoutes(mux, hardened)

	var handler http.Handler = mux
	if hardened {
		handler = securityHeaders(mux)
	}

	log.Printf("starting OIDC app on :%s (hardened=%v)", port, hardened)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

func runForwardAuth(hardened bool, port string) {
	remoteUserHeader := getenv("REMOTE_USER_HEADER", "X-Remote-User")
	allowedDomain := getenv("ALLOWED_REDIRECT_DOMAIN", "app.sso-lab.local")

	setupSessionOptions(hardened)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		render(w, homeTmpl, map[string]interface{}{
			"AuthMode":  "Forward Auth",
			"Hardened":  hardened,
			"LoginURL":  "/login",
		})
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, "sess")
		if next := r.URL.Query().Get("next"); next != "" {
			if hardened && isSafeRedirect(next) {
				sess.Values["next"] = next
			} else if !hardened && isAllowedRedirectVuln(next, allowedDomain) {
				sess.Values["next"] = next
			}
		}
		_ = sess.Save(r, w)
		http.Redirect(w, r, "/api/auth-check", http.StatusFound)
	})

	mux.HandleFunc("/api/auth-check", func(w http.ResponseWriter, r *http.Request) {
		remoteUser := r.Header.Get(remoteUserHeader)

		if !hardened {
			for _, h := range r.Header {
				log.Printf("[forward-auth] header received (vulnerable — trusting all headers): %v", h)
			}
		}

		if remoteUser == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"error":"unauthenticated","header":"%s"}`, remoteUserHeader)
			return
		}

		sess, _ := store.Get(r, "sess")
		sess.Values["user"] = remoteUser

		next, _ := sess.Values["next"].(string)
		delete(sess.Values, "next")
		if err := sess.Save(r, w); err != nil {
			http.Error(w, "session save failed", http.StatusInternalServerError)
			return
		}

		if next != "" {
			if !hardened && !isAllowedRedirectVuln(next, allowedDomain) {
				next = "/dashboard"
			} else if hardened && !isSafeRedirect(next) {
				next = "/dashboard"
			}
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})

	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, "sess")
		user, _ := sess.Values["user"].(string)
		if user == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		render(w, dashboardTmpl, map[string]interface{}{
			"User":     user,
			"AuthMode": "Forward Auth",
			"Hardened": hardened,
		})
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, "sess")
		if hardened {
			sess.Values = make(map[interface{}]interface{})
		}
		sess.Options.MaxAge = -1
		_ = sess.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	registerWebAuthnRoutes(mux, hardened)

	var handler http.Handler = mux
	if hardened {
		handler = securityHeaders(mux)
	}

	log.Printf("starting Forward Auth app on :%s (hardened=%v)", port, hardened)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

// ── SAML types and handlers ────────────────────────────────────────────

// samlAssertion represents the parsed SAML Assertion element.
type samlAssertion struct {
	XMLName         xml.Name           `xml:"Assertion"`
	ID              string             `xml:",attr"`
	Version         string             `xml:",attr"`
	IssueInstant    string             `xml:",attr"`
	Issuer          samlIssuer         `xml:"Issuer"`
	Subject         *samlSubject       `xml:"Subject"`
	Conditions      *samlConditions   `xml:"Conditions"`
	AttributeStmt   *samlAttributeStatement `xml:"AttributeStatement"`
	AuthnStatement  *samlAuthnStatement     `xml:"AuthnStatement"`
}

type samlIssuer struct {
	Value string `xml:",chardata"`
}

type samlSubject struct {
	NameID          samlNameID              `xml:"NameID"`
	SubjectConfirmations []samlSubjectConfirmation `xml:"SubjectConfirmation"`
}

type samlNameID struct {
	Format string `xml:",attr"`
	Value  string `xml:",chardata"`
}

type samlSubjectConfirmation struct {
	Method    string                    `xml:",attr"`
	Data      samlSubjectConfirmationData `xml:"SubjectConfirmationData"`
}

type samlSubjectConfirmationData struct {
	InResponseTo string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
	Recipient    string `xml:",attr"`
}

type samlConditions struct {
	NotBefore    string               `xml:",attr"`
	NotOnOrAfter string               `xml:",attr"`
	Audiences    []samlAudienceRestriction `xml:"AudienceRestriction"`
}

type samlAudienceRestriction struct {
	Audience string `xml:"Audience"`
}

type samlAttributeStatement struct {
	Attributes []samlAttribute `xml:"Attribute"`
}

type samlAttribute struct {
	Name   string   `xml:",attr"`
	Values []string `xml:"AttributeValue"`
}

type samlAuthnStatement struct {
	AuthnInstant    string `xml:",attr"`
	SessionIndex    string `xml:",attr"`
	SessionNotOnOrAfter string `xml:",attr"`
}

// samlResponse wraps a full SAML Response (used for Signature Wrapping attack).
type samlResponse struct {
	XMLName    xml.Name       `xml:"Response"`
	Destination string        `xml:",attr"`
	ID          string         `xml:",attr"`
	InResponseTo string       `xml:",attr"`
	IssueInstant string        `xml:",attr"`
	Issuer      samlIssuer    `xml:"Issuer"`
	Assertions  []samlAssertion `xml:"Assertion"`
}

// usedAssertionIDs tracks consumed assertion IDs to prevent replay.
var (
	usedAssertionIDs   = make(map[string]time.Time)
	usedAssertionIDsMu sync.Mutex
)

func init() {
	// Periodically clean expired assertion IDs (older than 5 minutes).
	go func() {
		for range time.Tick(5 * time.Minute) {
			usedAssertionIDsMu.Lock()
			cutoff := time.Now().Add(-5 * time.Minute)
			for id, t := range usedAssertionIDs {
				if t.Before(cutoff) {
					delete(usedAssertionIDs, id)
				}
			}
			usedAssertionIDsMu.Unlock()
		}
	}()
}

// runSAML starts the app in SAML SP-initiated mode.
func runSAML(hardened bool, port string) {
	appBase := strings.TrimRight(getenv("APP_BASE_URL", "https://app.sso-lab.local"), "/")
	idpExternalHost := getenv("IDP_ISSUER_HOST", "idp.sso-lab.local")
	idpInternalHost := getenv("IDP_INTERNAL_HOST", "idp")
	idpPort := getenv("IDP_PORT", "8080")
	realm := getenv("SAML_REALM", "sso-lab")
	clientID := getenv("SAML_CLIENT_ID", "sso-test-app-saml")
	idpScheme := getenv("IDP_SCHEME", "https")
	allowedDomain := getenv("ALLOWED_REDIRECT_DOMAIN", "app.sso-lab.local")

	setupSessionOptions(hardened)

	httpClient := internalHTTPClientWithPort(idpExternalHost, idpInternalHost, idpPort)
	_ = httpClient // used for metadata fetch if needed

	// Build IdP URLs.
	// Browser-facing URLs should not include non-standard ports since
	// traffic goes through Traefik on standard ports.
	samlSSOURL := fmt.Sprintf("%s://%s/realms/%s/protocol/saml",
		idpScheme, idpExternalHost, realm)
	samlInternalSSOURL := fmt.Sprintf("http://%s:%s/realms/%s/protocol/saml",
		idpInternalHost, idpPort, realm)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		render(w, homeTmpl, map[string]interface{}{
			"AuthMode":  "SAML",
			"Hardened":  hardened,
			"LoginURL":  "/login",
		})
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		requestID, err := randomString(16)
		if err != nil {
			http.Error(w, "failed to generate request ID", http.StatusInternalServerError)
			return
		}

		sess, _ := store.Get(r, "sess")
		sess.Values["saml_request_id"] = requestID

		if next := r.URL.Query().Get("next"); next != "" {
			if hardened && isSafeRedirect(next) {
				sess.Values["next"] = next
			} else if !hardened && isAllowedRedirectVuln(next, allowedDomain) {
				sess.Values["next"] = next
			}
		}
		if err := sess.Save(r, w); err != nil {
			http.Error(w, "session save failed", http.StatusInternalServerError)
			return
		}

		// SP-initiated: redirect to IdP SSO URL with SAMLRequest parameter.
		// We use Redirect binding (GET) for simplicity.
		authReq := buildSAMLAuthRequest(clientID, requestID, samlSSOURL, appBase+"/saml/acs")

		encodedRequest := base64.StdEncoding.EncodeToString([]byte(authReq))
		redirectURL := fmt.Sprintf("%s?SAMLRequest=%s", samlSSOURL,
			url.QueryEscape(encodedRequest))

		log.Printf("[saml] redirecting to IdP: %s (requestID=%s)", samlSSOURL, requestID)
		http.Redirect(w, r, redirectURL, http.StatusFound)

		// Keep internal URL in case we need it later
		_ = samlInternalSSOURL
	})

	mux.HandleFunc("/saml/acs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		samlResponseB64 := r.FormValue("SAMLResponse")
		if samlResponseB64 == "" {
			http.Error(w, "missing SAMLResponse", http.StatusBadRequest)
			return
		}

		responseXML, err := base64.StdEncoding.DecodeString(samlResponseB64)
		if err != nil {
			http.Error(w, "invalid base64 in SAMLResponse: "+err.Error(), http.StatusBadRequest)
			return
		}

		log.Printf("[saml] received SAML response (%d bytes)", len(responseXML))

		user, assertionID, err := processSAMLResponse(responseXML, hardened, clientID, appBase+"/saml/acs", r)
		if err != nil {
			log.Printf("[saml] REJECTED: %v", err)
			http.Error(w, "SAML assertion rejected: "+err.Error(), http.StatusForbidden)
			return
		}

		// ── HARDENED ONLY: check replay (assertion ID already used) ──
		if hardened {
			usedAssertionIDsMu.Lock()
			if _, seen := usedAssertionIDs[assertionID]; seen {
				usedAssertionIDsMu.Unlock()
				log.Printf("[saml] REJECTED: assertion ID %q already used (replay)", assertionID)
				http.Error(w, "assertion replay detected", http.StatusForbidden)
				return
			}
			usedAssertionIDs[assertionID] = time.Now()
			usedAssertionIDsMu.Unlock()
		} else {
			log.Printf("[saml] WARNING: not checking assertion ID replay in vulnerable mode")
		}

		sess, _ := store.Get(r, "sess")
		sess.Values["user"] = user
		delete(sess.Values, "saml_request_id")

		next, _ := sess.Values["next"].(string)
		delete(sess.Values, "next")
		if err := sess.Save(r, w); err != nil {
			http.Error(w, "session save failed", http.StatusInternalServerError)
			return
		}

		if next != "" {
			if hardened && !isSafeRedirect(next) {
				next = "/dashboard"
			} else if !hardened && !isAllowedRedirectVuln(next, allowedDomain) {
				next = "/dashboard"
			}
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})

	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, "sess")
		user, _ := sess.Values["user"].(string)
		if user == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		render(w, dashboardTmpl, map[string]interface{}{
			"User":     user,
			"AuthMode": "SAML",
			"Hardened": hardened,
		})
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, "sess")
		if hardened {
			sess.Values = make(map[interface{}]interface{})
		}
		sess.Options.MaxAge = -1
		_ = sess.Save(r, w)

		if hardened {
			// SAML Global Logout (SP-initiated)
			idpScheme := getenv("IDP_SCHEME", "https")
			logoutURL := fmt.Sprintf("%s://%s/realms/%s/protocol/saml",
				idpScheme,
				getenv("IDP_ISSUER_HOST", "idp.sso-lab.local"),
				getenv("SAML_REALM", "sso-lab"),
			)
			logoutReq := buildSAMLLogoutRequest(clientID, appBase)
			encodedRequest := base64.StdEncoding.EncodeToString([]byte(logoutReq))
			redirectURL := fmt.Sprintf("%s?SAMLRequest=%s&RelayState=%s",
				logoutURL,
				url.QueryEscape(encodedRequest),
				url.QueryEscape(appBase))
			http.Redirect(w, r, redirectURL, http.StatusFound)
		} else {
			http.Redirect(w, r, "/", http.StatusFound)
		}
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	registerWebAuthnRoutes(mux, hardened)

	var handler http.Handler = mux
	if hardened {
		handler = securityHeaders(mux)
	}

	log.Printf("starting SAML app on :%s (hardened=%v)", port, hardened)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

// processSAMLResponse parses and validates a SAML Response XML.
// Returns (username, assertionID, error).
//
// Vulnerable mode:
//   - No InResponseTo check
//   - No NotOnOrAfter expiry check
//   - No Audience restriction check
//   - Accepts ANY assertion inside the Response without checking wrapping
//
// Hardened mode:
//   - All of the above checks are enforced
func processSAMLResponse(responseXML []byte, hardened bool, expectedAudience, expectedRecipient string, r *http.Request) (string, string, error) {
	// Try parsing as full Response first (contains Assertions)
	var resp samlResponse
	if err := xml.Unmarshal(responseXML, &resp); err != nil {
		return "", "", fmt.Errorf("failed to parse SAML Response: %w", err)
	}

	if len(resp.Assertions) == 0 {
		return "", "", fmt.Errorf("no assertions found in SAML Response")
	}

	// VULNERABLE PATH: just take the FIRST assertion — this makes us susceptible
	// to Signature Wrapping attacks where an attacker injects an unsigned
	// assertion alongside or inside a signed one.
	assertion := resp.Assertions[0]

	// Log all assertions found (useful for detecting wrapping attacks)
	for i, a := range resp.Assertions {
		log.Printf("[saml] found assertion[%d]: id=%s subject=%s",
			i, a.ID, getAssertionUsername(&a))
	}

	// If more than one assertion, log it (potential wrapping attack indicator)
	if len(resp.Assertions) > 1 && !hardened {
		log.Printf("[saml] WARNING: multiple assertions found (%d), taking first one (vulnerable to wrapping)", len(resp.Assertions))
	}

	username := getAssertionUsername(&assertion)
	if username == "" {
		return "", "", fmt.Errorf("could not extract username from assertion")
	}

	// ── ALWAYS: basic structural checks ──
	if assertion.Version != "2.0" {
		return "", assertion.ID, fmt.Errorf("unsupported SAML version: %s", assertion.Version)
	}

	// ── HARDENED ONLY: InResponseTo must match our stored request ID ──
	if hardened {
		sess, _ := store.Get(r, "sess")
		storedRequestID, _ := sess.Values["saml_request_id"].(string)
		if storedRequestID == "" {
			return "", assertion.ID, fmt.Errorf("no stored SAML request ID in session")
		}

		inResponseToMatch := false
		if assertion.Subject != nil {
			for _, sc := range assertion.Subject.SubjectConfirmations {
				if sc.Data.InResponseTo == storedRequestID {
					inResponseToMatch = true
					break
				}
			}
		}
		if !inResponseToMatch {
			log.Printf("[saml] REJECTED: InResponseTo does not match stored request ID")
			return "", assertion.ID, fmt.Errorf("InResponseTo mismatch (expected %s)", storedRequestID)
		}

		// ── HARDENED ONLY: NotOnOrAfter expiry check ──
		if assertion.Conditions != nil && assertion.Conditions.NotOnOrAfter != "" {
			expiry, err := time.Parse(time.RFC3339Nano, assertion.Conditions.NotOnOrAfter)
			if err != nil {
				// Try alternative format
				expiry, err = time.Parse("2006-01-02T15:04:05.999Z", assertion.Conditions.NotOnOrAfter)
				if err != nil {
					log.Printf("[saml] WARNING: could not parse NotOnOrAfter: %s", assertion.Conditions.NotOnOrAfter)
				}
			}
			if err == nil && !time.Now().Before(expiry) {
				log.Printf("[saml] REJECTED: assertion expired (NotOnOrAfter=%s)", assertion.Conditions.NotOnOrAfter)
				return "", assertion.ID, fmt.Errorf("assertion has expired")
			}
		}

		// ── HARDENED ONLY: SubjectConfirmationData.Recipient check ──
		if assertion.Subject != nil {
			recipientOK := false
			for _, sc := range assertion.Subject.SubjectConfirmations {
				if sc.Data.Recipient == expectedRecipient {
					recipientOK = true
					break
				}
			}
			if !recipientOK {
				log.Printf("[saml] REJECTED: Recipient does not match expected ACS URL")
				return "", assertion.ID, fmt.Errorf("recipient mismatch (expected %s)", expectedRecipient)
			}
		}

		// ── HARDENED ONLY: Audience restriction ──
		if assertion.Conditions != nil {
			audienceOK := false
			for _, ar := range assertion.Conditions.Audiences {
				if ar.Audience == expectedAudience || ar.Audience == strings.TrimPrefix(expectedAudience, "https://") {
					audienceOK = true
					break
				}
			}
			if !audienceOK && len(assertion.Conditions.Audiences) > 0 {
				log.Printf("[saml] REJECTED: audience restriction not satisfied")
				return "", assertion.ID, fmt.Errorf("audience restriction not met")
			}
		}

		// ── HARDENED ONLY: reject multiple assertions (wrapping attack) ──
		if len(resp.Assertions) > 1 {
			log.Printf("[saml] REJECTED: multiple assertions in response (possible wrapping attack)")
			return "", assertion.ID, fmt.Errorf("multiple assertions rejected")
		}

		// ── HARDENED ONLY: deep wrapping detection ──
		// Check if there's an embedded Response within Response (common wrapping pattern)
		if bytes.Count(responseXML, []byte("<Assertion")) > len(resp.Assertions) {
			log.Printf("[saml] REJECTED: assertion count mismatch (possible nested/wrapped assertions)")
			return "", assertion.ID, fmt.Errorf("nested assertion detected")
		}
	} else {
		// Vulnerable path warnings
		if assertion.Subject != nil {
			for _, sc := range assertion.Subject.SubjectConfirmations {
				if sc.Data.InResponseTo != "" {
					log.Printf("[saml] WARNING: InResponseTo=%s present but NOT validated in vulnerable mode", sc.Data.InResponseTo)
				}
			}
		}
		if assertion.Conditions != nil && assertion.Conditions.NotOnOrAfter != "" {
			log.Printf("[saml] WARNING: NotOnOrAfter=%s present but NOT checked in vulnerable mode", assertion.Conditions.NotOnOrAfter)
		}
	}

	return username, assertion.ID, nil
}

// getAssertionUsername extracts the username from a SAML Assertion.
func getAssertionUsername(a *samlAssertion) string {
	// First try NameID from Subject
	if a.Subject != nil && a.Subject.NameID.Value != "" {
		return a.Subject.NameID.Value
	}
	// Then try AttributeStatement for username attribute
	if a.AttributeStmt != nil {
		for _, attr := range a.AttributeStmt.Attributes {
			if attr.Name == "username" && len(attr.Values) > 0 {
				return attr.Values[0]
			}
			if attr.Name == "email" && len(attr.Values) > 0 {
				return attr.Values[0]
			}
		}
	}
	return ""
}

// buildSAMLAuthRequest constructs a minimal SAML AuthnRequest XML (Redirect binding).
func buildSAMLAuthRequest(spID, requestID, destination, acsURL string) string {
	issueInstant := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	return fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_%s" Version="2.0" IssueInstant="%s"
  Destination="%s"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  AssertionConsumerServiceURL="%s">
  <saml:Issuer>%s</saml:Issuer>
</samlp:AuthnRequest>`, requestID, issueInstant, destination, acsURL, spID)
}

// buildSAMLLogoutRequest constructs a minimal SAML LogoutRequest XML.
func buildSAMLLogoutRequest(spID, appBase string) string {
	requestID, _ := randomString(16)
	issueInstant := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	return fmt.Sprintf(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_%s" Version="2.0" IssueInstant="%s"
  Destination="">
  <saml:Issuer>%s</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"></saml:NameID>
  <samlp:SessionIndex></samlp:SessionIndex>
</samlp:LogoutRequest>`, requestID, issueInstant, spID)
}

// ── WebAuthn types and handlers ────────────────────────────────────────────

// webauthnClientData represents the clientDataJSON payload from the browser.
type webauthnClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
}

// webauthnBeginResponse is returned by /webauthn/login/begin.
type webauthnBeginResponse struct {
	PublicKey webauthnPublicKey `json:"publicKey"`
}

type webauthnPublicKey struct {
	Challenge        string              `json:"challenge"`
	RpID             string              `json:"rpId,omitempty"`
	AllowCredentials []webauthnCredDesc  `json:"allowCredentials,omitempty"`
	Timeout          int                 `json:"timeout,omitempty"`
	UserVerification string              `json:"userVerification,omitempty"`
}

type webauthnCredDesc struct {
	Type string   `json:"type"`
	ID   string   `json:"id"`
}

// webauthnFinishRequest is sent by the browser to /webauthn/login/finish.
type webauthnFinishRequest struct {
	ID       string                `json:"id"`
	RawID    string                `json:"rawId"`
	Type     string                `json:"type"`
	Response webauthnFinishResponse `json:"response"`
}

type webauthnFinishResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

// registerWebAuthnRoutes adds /webauthn/* endpoints to the given mux.
// In vulnerable mode: no origin/RP ID validation in finish.
// In hardened mode: strict origin + rpIdHash checks.
func registerWebAuthnRoutes(mux *http.ServeMux, hardened bool) {
	expectedOrigin := getenv("APP_BASE_URL", "https://app.sso-lab.local")
	rpID := getenv("WEBAUTHN_RP_ID", "sso-lab.local")

	// POST /webauthn/login/begin — returns a challenge for the browser.
	mux.HandleFunc("/webauthn/login/begin", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		challenge, err := randomString(32)
		if err != nil {
			http.Error(w, "failed to generate challenge", http.StatusInternalServerError)
			return
		}

		// Store challenge in session so we can verify it later
		sess, _ := store.Get(r, "sess")
		sess.Values["webauthn_challenge"] = challenge
		_ = sess.Save(r, w)

		resp := webauthnBeginResponse{
			PublicKey: webauthnPublicKey{
				Challenge: challenge,
				Timeout:   60000,
				AllowCredentials: []webauthnCredDesc{{
					Type: "public-key",
					ID:   "AAAAAAAAAAAAAAAAAAAAAA",
				}},
			},
		}
		if hardened {
			resp.PublicKey.RpID = rpID
			resp.PublicKey.UserVerification = "required"
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// POST /webauthn/login/finish — verifies the browser's assertion.
	mux.HandleFunc("/webauthn/login/finish", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req webauthnFinishRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.Type != "public-key" {
			http.Error(w, "invalid credential type", http.StatusBadRequest)
			return
		}

		// Decode clientDataJSON
		clientDataB64 := req.Response.ClientDataJSON
		clientDataJSON, err := b64urlDecode(clientDataB64)
		if err != nil {
			http.Error(w, "invalid clientDataJSON encoding", http.StatusBadRequest)
			return
		}

		var clientData webauthnClientData
		if err := json.Unmarshal(clientDataJSON, &clientData); err != nil {
			http.Error(w, "invalid clientDataJSON", http.StatusBadRequest)
			return
		}

		log.Printf("[webauthn] finish: type=%s origin=%s challenge=%s",
			clientData.Type, clientData.Origin, clientData.Challenge)

		// ── ALWAYS: verify the operation type ──
		if clientData.Type != "webauthn.get" {
			http.Error(w, `{"error":"invalid_type","detail":"expected webauthn.get"}`, http.StatusBadRequest)
			return
		}

		// ── ALWAYS: verify the challenge matches what we issued ──
		sess, _ := store.Get(r, "sess")
		storedChallenge, _ := sess.Values["webauthn_challenge"].(string)
		delete(sess.Values, "webauthn_challenge")
		_ = sess.Save(r, w)

		if storedChallenge == "" || clientData.Challenge != storedChallenge {
			http.Error(w, `{"error":"challenge_mismatch","detail":"challenge does not match"}`, http.StatusBadRequest)
			return
		}

		// ── HARDENED ONLY: verify origin matches expected RP ──
		if hardened && clientData.Origin != expectedOrigin {
			log.Printf("[webauthn] REJECTED: origin %q != expected %q", clientData.Origin, expectedOrigin)
			http.Error(w,
				fmt.Sprintf(`{"error":"origin_mismatch","detail":"origin must be %s"}`, expectedOrigin),
				http.StatusForbidden)
			return
		}

		// ── HARDENED ONLY: verify rpIdHash in authenticatorData ──
		if hardened && req.Response.AuthenticatorData != "" {
			authDataBytes, err := b64urlDecode(req.Response.AuthenticatorData)
			if err != nil || len(authDataBytes) < 32 {
				http.Error(w, `{"error":"invalid_auth_data","detail":"authenticator data too short"}`,
					http.StatusBadRequest)
				return
			}
			rpIDHash := sha256.Sum256([]byte(rpID))
			actualHash := authDataBytes[:32]

			match := true
			for i := 0; i < 32; i++ {
				if actualHash[i] != rpIDHash[i] {
					match = false
					break
				}
			}
			if !match {
				log.Printf("[webauthn] REJECTED: rpIdHash mismatch (expected for %s)", rpID)
				http.Error(w,
					fmt.Sprintf(`{"error":"rp_id_mismatch","detail":"rpIdHash does not match %s"}`, rpID),
					http.StatusForbidden)
				return
			}
		}

		// VULNERABLE PATH: if not hardened, we accept ANY origin without checking.
		if !hardened && clientData.Origin != expectedOrigin {
			log.Printf("[webauthn] WARNING: accepting assertion from unexpected origin %q (not validated in vulnerable mode)", clientData.Origin)
		}

		// Success — set user in session
		sess2, _ := store.Get(r, "sess")
		sess2.Values["user"] = "webauthn-user"
		_ = sess2.Save(r, w)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok","user":"webauthn-user"}`)
	})
}

// b64urlDecode decodes a base64url-encoded string (no padding).
func b64urlDecode(s string) ([]byte, error) {
	// Add padding
	pad := len(s) % 4
	if pad > 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(s)
}

func setupSessionOptions(hardened bool) {
	if hardened {
		store.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   900,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}
	} else {
		store.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   3600,
			HttpOnly: false,
			Secure:   false,
			SameSite: http.SameSiteNoneMode,
		}
	}
}

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

func isSafeRedirect(s string) bool {
	if len(s) == 0 || s[0] != '/' {
		return false
	}
	if len(s) > 1 && (s[1] == '/' || s[1] == '\\') {
		return false
	}
	return true
}

func isAllowedRedirectVuln(rawURL, allowedDomain string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.Contains(parsed.Host, allowedDomain)
}

// internalHTTPClientWithPort creates an HTTP client that routes requests for
// externalHost to internalHost:internalPort over plain HTTP, regardless of
// the original scheme.  Inside Docker the IdP listens on HTTP; Traefik
// terminates TLS externally.  Without this rewrite the OIDC discovery request
// would attempt a TLS handshake to an HTTP-only endpoint and fail with:
//   "http: server gave HTTP response to HTTPS client"
func internalHTTPClientWithPort(externalHost, internalHost, internalPort string) *http.Client {
	return &http.Client{
		Transport: &rewriteTransport{
			base:         http.DefaultTransport,
			externalHost: externalHost,
			internalAddr: internalHost + ":" + internalPort,
		},
	}
}

// rewriteTransport is a http.RoundTripper that rewrites requests targeting
// externalHost to use plain HTTP on internalAddr instead.
type rewriteTransport struct {
	base         http.RoundTripper
	externalHost string
	internalAddr string
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request so we don't mutate the original.
	r := req.Clone(req.Context())
	if r.URL.Host == rt.externalHost || strings.HasPrefix(r.URL.Host, rt.externalHost+":") {
		r.URL.Scheme = "http"
		r.URL.Host = rt.internalAddr
		// Add forwarding headers so the IdP can generate correct URLs
		// in its discovery document even when accessed internally over HTTP.
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", rt.externalHost)
		r.Header.Set("X-Forwarded-Port", "443")
	}
	return rt.base.RoundTrip(r)
}

// buildIssuerURL constructs the OIDC issuer URL based on scheme and realm.
// The URL is browser-facing so it does NOT include non-standard ports
// (Traefik terminates TLS on standard ports).
// For Keycloak-style IdPs:   <scheme>://<host>/realms/<realm>
// For Zitadel-style IdPs:    <scheme>://<host>  (when realm is empty)
func buildIssuerURL(scheme, host, realm string) string {
	if realm == "" {
		return fmt.Sprintf("%s://%s", scheme, host)
	}
	return fmt.Sprintf("%s://%s/realms/%s", scheme, host, realm)
}

// patchEndpointScheme rewrites the scheme of OAuth2 endpoint URLs
// when the IdP advertises http:// behind a TLS-terminating proxy.
func patchEndpointScheme(ep *oauth2.Endpoint, wantScheme string) {
	ep.AuthURL = replaceScheme(ep.AuthURL, wantScheme)
	ep.TokenURL = replaceScheme(ep.TokenURL, wantScheme)
	// DeviceAuthURL may be empty; that's fine.
	if ep.DeviceAuthURL != "" {
		ep.DeviceAuthURL = replaceScheme(ep.DeviceAuthURL, wantScheme)
	}
}

func replaceScheme(rawurl, wantScheme string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return rawurl
	}
	u.Scheme = wantScheme
	return u.String()
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
<html><head><title>SSO Test App</title></head>
<body>
  <h1>SSO Test App</h1>
  <p>Authentication mode: <strong>{{.AuthMode}}</strong> | Hardened: <strong>{{.Hardened}}</strong></p>
  <a href="{{.LoginURL}}">Login</a>
</body></html>`

const dashboardTmpl = `<!DOCTYPE html>
<html><head><title>Dashboard</title></head>
<body>
  <h1>Dashboard</h1>
  <p>Welcome, <strong>{{.User}}</strong></p>
  <p>Auth mode: {{.AuthMode}} | Hardened: {{.Hardened}}</p>
  <a href="/logout">Logout</a>
</body></html>`
