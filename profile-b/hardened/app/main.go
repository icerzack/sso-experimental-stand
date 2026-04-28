// Profile B — Hardened WebAuthn/FIDO2 application
//
// Protections (each commented at the relevant line):
//
//	A1/A2  Rate limiting: max 5 requests/min per IP on auth endpoints
//	A3     rpID = "app-b-h.local" — strict origin binding, phishing-resistant
//	A6     Session cookie: HttpOnly + Secure + SameSite=Strict
//	A9     Post-auth ?next= restricted to relative paths only
//	A12    Security headers on every response (HSTS, X-Frame-Options, CSP, …)
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/sessions"
)

// ---------- domain types ----------

type appUser struct {
	id          string
	credentials []webauthn.Credential
}

func (u *appUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u *appUser) WebAuthnName() string                       { return u.id }
func (u *appUser) WebAuthnDisplayName() string                { return u.id }
func (u *appUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

type flowData struct {
	session *webauthn.SessionData
	userID  string
}

type appStore struct {
	mu    sync.Mutex
	users map[string]*appUser
	flows map[string]*flowData
}

func newStore() *appStore {
	return &appStore{
		users: make(map[string]*appUser),
		flows: make(map[string]*flowData),
	}
}

func (s *appStore) getOrCreateUser(id string) *appUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[id]; ok {
		return cloneUser(u)
	}
	u := &appUser{id: id}
	s.users[id] = u
	return cloneUser(u)
}

func (s *appStore) saveCredential(userID string, cred webauthn.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[userID]
	if u == nil {
		u = &appUser{id: userID}
		s.users[userID] = u
	}
	for i, c := range u.credentials {
		if bytes.Equal(c.ID, cred.ID) {
			u.credentials[i] = cred
			return
		}
	}
	u.credentials = append(u.credentials, cred)
}

func (s *appStore) findByCredential(rawID, userHandle []byte) (*appUser, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(userHandle) > 0 {
		if u, ok := s.users[string(userHandle)]; ok {
			return cloneUser(u), true
		}
	}
	for _, u := range s.users {
		for _, c := range u.credentials {
			if bytes.Equal(c.ID, rawID) {
				return cloneUser(u), true
			}
		}
	}
	return nil, false
}

func (s *appStore) saveFlow(id string, data *flowData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows[id] = data
}

func (s *appStore) consumeFlow(id string) (*flowData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.flows[id]
	if ok {
		delete(s.flows, id)
	}
	return d, ok
}

func cloneUser(u *appUser) *appUser {
	clone := *u
	clone.credentials = append([]webauthn.Credential(nil), u.credentials...)
	return &clone
}

// ---------- rate limiter ----------

// HARDENED A1/A2: simple per-IP sliding-window rate limiter.
type rateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	return &rateLimiter{hits: make(map[string][]time.Time), max: max, window: window}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	var valid []time.Time
	for _, t := range rl.hits[key] {
		if now.Sub(t) < rl.window {
			valid = append(valid, t)
		}
	}
	if len(valid) >= rl.max {
		rl.hits[key] = valid
		return false
	}
	rl.hits[key] = append(valid, now)
	return true
}

func withRateLimit(rl *rateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if i := strings.LastIndex(ip, ":"); i > 0 {
			ip = ip[:i]
		}
		if !rl.allow(ip) {
			http.Error(w, "rate limit exceeded — try again later", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// ---------- main ----------

var sessionStore *sessions.CookieStore

func main() {
	// HARDENED A3: strict rpID = "app-b-h.local" — origin-bound credential.
	rpID := getenv("WEBAUTHN_RP_ID", "app-b-h.local")
	rpOrigins := splitCSV(getenv("WEBAUTHN_RP_ORIGINS", "https://app-b-h.local"))

	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Profile B (hardened)",
		RPID:          rpID,
		RPOrigins:     rpOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
	})
	if err != nil {
		log.Fatalf("webauthn init: %v", err)
	}

	db := newStore()

	// HARDENED A6: all session security flags enabled.
	sessionStore = sessions.NewCookieStore([]byte(getenv("SESSION_SECRET", "replace-with-64-char-random-secret")))
	sessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   900,
		HttpOnly: true,                    // A6: JS cannot read the cookie
		Secure:   true,                    // A6: only sent over HTTPS
		SameSite: http.SameSiteStrictMode, // A6: blocks cross-site request forgery
	}

	userID := getenv("WEBAUTHN_USER_ID", "demo-user")

	// HARDENED A1/A2: 5 requests per minute per IP on auth endpoints.
	authLimiter := newRateLimiter(5, time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// HARDENED A9: only store next if it is a safe relative path.
		if next := r.URL.Query().Get("next"); isSafeRedirect(next) {
			s, _ := sessionStore.Get(r, "sess")
			s.Values["next"] = next
			_ = s.Save(r, w)
		}
		render(w, pageTmpl, nil)
	})

	mux.HandleFunc("/webauthn/register/begin", withRateLimit(authLimiter, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		user := db.getOrCreateUser(userID)
		cred, sess, err := wa.BeginRegistration(user,
			webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
			webauthn.WithExclusions(webauthn.Credentials(user.WebAuthnCredentials()).CredentialDescriptors()),
		)
		if err != nil {
			http.Error(w, "begin registration: "+err.Error(), http.StatusInternalServerError)
			return
		}
		flowID := randomString()
		db.saveFlow(flowID, &flowData{session: sess, userID: userID})
		s, _ := sessionStore.Get(r, "sess")
		s.Values["reg_flow"] = flowID
		_ = s.Save(r, w)
		writeJSON(w, cred)
	}))

	mux.HandleFunc("/webauthn/register/finish", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s, _ := sessionStore.Get(r, "sess")
		flowID, _ := s.Values["reg_flow"].(string)
		flow, ok := db.consumeFlow(flowID)
		if !ok {
			http.Error(w, "no registration session", http.StatusBadRequest)
			return
		}
		user := db.getOrCreateUser(flow.userID)
		cred, err := wa.FinishRegistration(user, *flow.session, r)
		if err != nil {
			http.Error(w, "finish registration: "+err.Error(), http.StatusBadRequest)
			return
		}
		db.saveCredential(flow.userID, *cred)
		s.Values["user"] = flow.userID
		next, _ := s.Values["next"].(string)
		delete(s.Values, "next")
		_ = s.Save(r, w)
		dest := "/protected"
		// HARDENED A9: next was validated at GET / — safe to use directly.
		if next != "" {
			dest = next
		}
		writeJSON(w, map[string]string{"redirect": dest})
	})

	mux.HandleFunc("/webauthn/login/begin", withRateLimit(authLimiter, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		assertion, sess, err := wa.BeginDiscoverableLogin(
			webauthn.WithUserVerification(protocol.VerificationRequired),
		)
		if err != nil {
			http.Error(w, "begin login: "+err.Error(), http.StatusInternalServerError)
			return
		}
		flowID := randomString()
		db.saveFlow(flowID, &flowData{session: sess})
		s, _ := sessionStore.Get(r, "sess")
		s.Values["login_flow"] = flowID
		_ = s.Save(r, w)
		writeJSON(w, assertion)
	}))

	mux.HandleFunc("/webauthn/login/finish", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s, _ := sessionStore.Get(r, "sess")
		flowID, _ := s.Values["login_flow"].(string)
		flow, ok := db.consumeFlow(flowID)
		if !ok {
			http.Error(w, "no login session", http.StatusBadRequest)
			return
		}
		var authedUser *appUser
		_, cred, err := wa.FinishPasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
			u, found := db.findByCredential(rawID, userHandle)
			if !found {
				return nil, context.DeadlineExceeded
			}
			authedUser = u
			return u, nil
		}, *flow.session, r)
		if err != nil {
			http.Error(w, "finish login: "+err.Error(), http.StatusUnauthorized)
			return
		}
		db.saveCredential(authedUser.id, *cred)
		s.Values["user"] = authedUser.id
		next, _ := s.Values["next"].(string)
		delete(s.Values, "next")
		_ = s.Save(r, w)
		dest := "/protected"
		// HARDENED A9: next was validated at GET / — safe to use directly.
		if next != "" {
			dest = next
		}
		writeJSON(w, map[string]string{"redirect": dest})
	})

	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		s, _ := sessionStore.Get(r, "sess")
		user, _ := s.Values["user"].(string)
		if user == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		render(w, protectedTmpl, user)
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		s, _ := sessionStore.Get(r, "sess")
		s.Values = make(map[interface{}]interface{})
		s.Options.MaxAge = -1
		_ = s.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
	})

	port := getenv("PORT", "8080")
	log.Printf("profile-b/hardened listening on :%s  rpID=%s", port, rpID)
	// HARDENED A12: security headers middleware wraps all responses.
	log.Fatal(http.ListenAndServe(":"+port, securityHeaders(mux)))
}

// isSafeRedirect accepts only relative paths, blocking all external redirects.
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// ---------- helpers ----------

func randomString() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "fallback"
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func render(w http.ResponseWriter, tmpl string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t := template.Must(template.New("p").Parse(tmpl))
	if err := t.Execute(w, data); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

const pageTmpl = `<!DOCTYPE html>
<html><head><title>Profile B — Hardened</title></head>
<body>
  <h1>Profile B: WebAuthn / FIDO2 (hardened)</h1>
  <button id="reg">Register passkey</button>
  <button id="login">Login with passkey</button>
  <p id="status"></p>
  <script>` + webAuthnJS + `</script>
</body></html>`

const protectedTmpl = `<!DOCTYPE html>
<html><head><title>Protected</title></head>
<body>
  <h1>Protected resource</h1>
  <p>Logged in as <strong>{{.}}</strong></p>
  <a href="/logout">Logout</a>
</body></html>`

const webAuthnJS = `
function b64dec(v){const b=v.replace(/-/g,'+').replace(/_/g,'/');const p=b+'='.repeat((4-b.length%4)%4);const s=atob(p);const a=new Uint8Array(s.length);for(let i=0;i<s.length;i++)a[i]=s.charCodeAt(i);return a.buffer}
function b64enc(b){const a=new Uint8Array(b);let s='';for(const x of a)s+=String.fromCharCode(x);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function prepCreate(o){const k=o.publicKey;k.challenge=b64dec(k.challenge);k.user.id=b64dec(k.user.id);if(k.excludeCredentials)k.excludeCredentials=k.excludeCredentials.map(c=>({...c,id:b64dec(c.id)}));return k}
function prepGet(o){const k=o.publicKey;k.challenge=b64dec(k.challenge);if(k.allowCredentials)k.allowCredentials=k.allowCredentials.map(c=>({...c,id:b64dec(c.id)}));return k}
function credJSON(c){const r=c.response;const o={id:c.id,rawId:b64enc(c.rawId),type:c.type,response:{clientDataJSON:b64enc(r.clientDataJSON)}};if(r.attestationObject)o.response.attestationObject=b64enc(r.attestationObject);if(r.authenticatorData){o.response.authenticatorData=b64enc(r.authenticatorData);o.response.signature=b64enc(r.signature);o.response.userHandle=r.userHandle?b64enc(r.userHandle):null}return o}
async function post(url,body){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});if(!r.ok)throw new Error(await r.text());return r.json()}
async function register(){document.getElementById('status').textContent='Registering…';const opts=await post('/webauthn/register/begin');const cred=await navigator.credentials.create({publicKey:prepCreate(opts)});const res=await post('/webauthn/register/finish',credJSON(cred));window.location.href=res.redirect||'/protected'}
async function login(){document.getElementById('status').textContent='Authenticating…';const opts=await post('/webauthn/login/begin');const cred=await navigator.credentials.get({publicKey:prepGet(opts)});const res=await post('/webauthn/login/finish',credJSON(cred));window.location.href=res.redirect||'/protected'}
document.getElementById('reg').onclick=()=>register().catch(e=>{document.getElementById('status').textContent=e.message});
document.getElementById('login').onclick=()=>login().catch(e=>{document.getElementById('status').textContent=e.message});
`
