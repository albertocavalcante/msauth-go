package msauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// pkce holds a PKCE verifier and its S256 challenge, plus a CSRF state value.
type pkce struct {
	verifier  string
	challenge string
	state     string
}

func newPKCE() pkce {
	verifier := randB64(32)
	sum := sha256.Sum256([]byte(verifier))
	return pkce{
		verifier:  verifier,
		challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
		state:     randB64(16),
	}
}

// randB64 returns n cryptographically-random bytes as unpadded base64url.
func randB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// successPage is shown in the browser after the loopback redirect is captured.
const successPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Signed in</title>
<style>
  :root { color-scheme: light dark; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
         font-family: ui-sans-serif, -apple-system, system-ui, sans-serif;
         background: radial-gradient(1200px 600px at 50% -10%, #1e3a8a22, transparent), #0b1020;
         color:#e5e7eb; }
  .card { text-align:center; padding:2.5rem 3rem; border-radius:20px;
          background:#111827cc; box-shadow:0 20px 60px #0008; border:1px solid #ffffff14;
          backdrop-filter: blur(8px); max-width:26rem; }
  .check { width:64px; height:64px; border-radius:50%; margin:0 auto 1rem;
           display:grid; place-items:center; background:#10b98122; border:1px solid #10b98155; }
  .check svg { width:34px; height:34px; stroke:#34d399; }
  h1 { font-size:1.35rem; margin:.25rem 0 .4rem; }
  p  { margin:.2rem 0; color:#9ca3af; font-size:.95rem; }
</style></head>
<body><div class="card">
  <div class="check"><svg viewBox="0 0 24 24" fill="none" stroke-width="3"
       stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg></div>
  <h1>Signed in</h1>
  <p>Authentication succeeded.</p>
  <p>You can close this tab and return to the terminal.</p>
</div></body></html>`
