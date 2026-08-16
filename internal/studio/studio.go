package studio

import (
	"encoding/json"
	"html/template"
	"net/http"
	"time"

	"github.com/privat655/VPSmith/internal/releaseinfo"
)

type BuildIdentity struct {
	Version  string               `json:"version"`
	Revision string               `json:"revision"`
	BuiltAt  string               `json:"built_at"`
	Embedded releaseinfo.Embedded `json:"embedded"`
}

func Handler(identity BuildIdentity) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /version", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(true)
		_ = encoder.Encode(identity)
	})
	mux.HandleFunc("GET /", func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		_ = startPage.Execute(writer, identity)
	})
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(writer, request)
	})
}

var startPage = template.Must(template.New("start").Funcs(template.FuncMap{
	"shortSHA": func(value string) string {
		if len(value) <= 16 {
			return value
		}
		return value[:16] + "…"
	},
	"builtAt": func(value string) string {
		if value == "" {
			return "not set"
		}
		if parsed, err := time.Parse(time.RFC3339, value); err == nil {
			return parsed.UTC().Format(time.RFC3339)
		}
		return value
	},
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VPSmith Studio</title>
<style>
:root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, sans-serif; }
body { max-width: 58rem; margin: 4rem auto; padding: 0 1.5rem; line-height: 1.5; }
header { margin-bottom: 2.5rem; }
h1 { margin-bottom: .25rem; }
.badge { display: inline-block; padding: .2rem .55rem; border: 1px solid currentColor; border-radius: 999px; font-size: .85rem; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); gap: 1rem; }
.card { border: 1px solid color-mix(in srgb, currentColor 25%, transparent); border-radius: .6rem; padding: 1rem; }
code { overflow-wrap: anywhere; }
small { opacity: .75; }
</style>
</head>
<body>
<header>
  <span class="badge">Local only</span>
  <h1>VPSmith Studio</h1>
  <p>Foundation build {{.Version}}. This step exposes build identity only; Ziel-VPS operations are intentionally not implemented yet.</p>
  <small>Revision {{if .Revision}}{{.Revision}}{{else}}unknown{{end}} · Built {{builtAt .BuiltAt}}</small>
</header>
<main>
  <h2>Embedded basis snapshots</h2>
  <div class="grid">
    <section class="card"><h3>Cloud-init</h3><p>{{.Embedded.CloudInit.Version}}</p><code>sha256:{{shortSHA .Embedded.CloudInit.SHA256}}</code></section>
    <section class="card"><h3>Core</h3><p>{{.Embedded.Core.Version}}</p><code>sha256:{{shortSHA .Embedded.Core.SHA256}}</code></section>
    <section class="card"><h3>n8n example module</h3><p>{{.Embedded.N8N.Version}}</p><code>sha256:{{shortSHA .Embedded.N8N.SHA256}}</code></section>
  </div>
</main>
</body>
</html>`))
