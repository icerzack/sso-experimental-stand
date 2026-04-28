// Profile B — Vulnerable WebAuthn/FIDO2 application
//
// Intentional weaknesses (each commented at the relevant line):
//
//	A1/A2  No rate limiting on register/login endpoints
//	A6     Session cookie has no HttpOnly, no Secure, no SameSite
//	A9     Post-auth ?next= validated with strings.Contains → domain confusion
//	A12    No security headers in any response
//
// Note on A3 (phishing resistance):
//
//	rpID = "app-b-v.local" — intentionally weaker setup for the vulnerable profile.
//	can potentially trigger credential use. By contrast, hardened uses
//	rpID = "app-b-h.local" which is strictly origin-bound.
//	WebAuthn by design prevents credentials from being used on a
//	different effective domain (evil-clone.local), so the phishing
//	check (A3) will show PROTECTED in both variants — this is the
//	protocol's inherent guarantee, not a configuration choice.
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
	"net/url"
	"os"
	"strings"
	"sync"

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
	users map[string]*appUser  // userID → user+credentials
	flows map[string]*flowData // flowID → pending session
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

// ---------- main ----------

var sessionStore *sessions.CookieStore

func main() {
	rpID := getenv("WEBAUTHN_RP_ID", "app-b-v.local")
	rpOrigins := splitCSV(getenv("WEBAUTHN_RP_ORIGINS", "http://app-b-v.local:8082"))

	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Profile B (vulnerable)",
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

	// VULNERABLE A6: session cookie has no security flags.
	sessionStore = sessions.NewCookieStore([]byte(getenv("SESSION_SECRET", "insecure-key")))
	sessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: false,                 // A6: JS can read the cookie
		Secure:   false,                 // A6: sent over plain HTTP
		SameSite: http.SameSiteNoneMode, // A6: cross-site requests allowed
	}

	userID := getenv("WEBAUTHN_USER_ID", "demo-user")
	allowedDomain := getenv("ALLOWED_REDIRECT_DOMAIN", "app-b-v.local")

	mux := http.NewServeMux()
	// VULNERABLE A12: no security headers middleware

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// VULNERABLE A9: store ?next= without domain-safe validation.
		if next := r.URL.Query().Get("next"); next != "" {
			s, _ := sessionStore.Get(r, "sess")
			s.Values["next"] = next
			_ = s.Save(r, w)
		}
		render(w, pageTmpl, nil)
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// VULNERABLE A9: /login?next= validates with strings.Contains → domain confusion.
		if next := r.URL.Query().Get("next"); next != "" {
			s, _ := sessionStore.Get(r, "sess")
			s.Values["next"] = next
			_ = s.Save(r, w)
			if isAllowedRedirect(next, allowedDomain) {
				http.Redirect(w, r, next, http.StatusFound)
				return
			}
		}
		render(w, pageTmpl, nil)
	})

	// VULNERABLE A1/A2: no rate limiting on registration endpoint
	mux.HandleFunc("/webauthn/register/begin", func(w http.ResponseWriter, r *http.Request) {
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
	})

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
		// VULNERABLE A9: strings.Contains allows "localhost.evil.com" to pass.
		if next != "" && isAllowedRedirect(next, allowedDomain) {
			dest = next
		}
		writeJSON(w, map[string]string{"redirect": dest})
	})

	// VULNERABLE A1/A2: no rate limiting on login endpoint
	mux.HandleFunc("/webauthn/login/begin", func(w http.ResponseWriter, r *http.Request) {
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
	})

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
				return nil, context.DeadlineExceeded // reuse error type for simplicity
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
		// VULNERABLE A9: strings.Contains allows "localhost.evil.com" to pass.
		if next != "" && isAllowedRedirect(next, allowedDomain) {
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
		s.Options.MaxAge = -1
		_ = s.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
	})

	port := getenv("PORT", "8080")
	log.Printf("profile-b/vulnerable listening on :%s  rpID=%s", port, rpID)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

// ---------- helpers ----------

// isAllowedRedirect uses strings.Contains — VULNERABLE to domain confusion.
// "localhost.evil.com" passes because it contains "localhost".
func isAllowedRedirect(rawURL, allowedDomain string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.Contains(parsed.Host, allowedDomain)
}

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
<html><head><title>Profile B — Vulnerable</title></head>
<body>
  <h1>Profile B: WebAuthn / FIDO2 (vulnerable)</h1>
  <p>This configuration is intentionally insecure for research purposes.</p>
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
