package studio

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/privat655/VPSmith/internal/bootstrap"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/releaseinfo"
	"github.com/privat655/VPSmith/internal/targetgateway"
)

type BuildIdentity struct {
	Version  string               `json:"version"`
	Revision string               `json:"revision"`
	BuiltAt  string               `json:"built_at"`
	Embedded releaseinfo.Embedded `json:"embedded"`
}

// TargetApplication is the small domain interface needed by the Step-7 Studio
// adapter. Observe and Confirm are deliberately separate calls: no HTTP route
// can establish TOFU trust merely by observing a host key.
type TargetApplication interface {
	PrepareNewTarget(context.Context, bootstrap.NewTargetRequest) (bootstrap.PreparedTarget, error)
	SetTargetAddress(context.Context, managementstate.TargetID, string) error
	ObserveHostKey(context.Context, managementstate.TargetID) (targetgateway.HostKeyObservation, error)
	ConfirmHostKey(context.Context, managementstate.TargetID, targetgateway.HostKeyObservation) error
	Enroll(context.Context, managementstate.TargetID) (targetgateway.EnrollmentResult, error)
}

// Handler accepts the application variadically only to retain the Step-1
// health/version construction contract used by old callers. Production Studio
// always injects exactly one TargetApplication.
func Handler(identity BuildIdentity, applications ...TargetApplication) http.Handler {
	var app TargetApplication
	if len(applications) == 1 {
		app = applications[0]
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /version", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, identity)
	})
	mux.HandleFunc("POST /api/targets", func(writer http.ResponseWriter, request *http.Request) {
		if !requireApplication(writer, app) || !requireJSON(writer, request) {
			return
		}
		var input struct{ Hostname, Timezone, Administrator string }
		if err := decodeJSON(request, &input); err != nil {
			writeError(writer, http.StatusBadRequest, err)
			return
		}
		prepared, err := app.PrepareNewTarget(request.Context(), bootstrap.NewTargetRequest{Hostname: input.Hostname, Timezone: input.Timezone, Administrator: input.Administrator})
		if err != nil {
			writeError(writer, http.StatusUnprocessableEntity, err)
			return
		}
		writeJSON(writer, http.StatusCreated, struct {
			TargetID             managementstate.TargetID         `json:"target_id"`
			CloudInitSourceID    managementstate.SourceSnapshotID `json:"cloud_init_source_id"`
			CloudInitVersion     string                           `json:"cloud_init_version"`
			CloudInitSourceSHA   string                           `json:"cloud_init_source_sha256"`
			CloudInitRenderedSHA string                           `json:"cloud_init_rendered_sha256"`
			CloudInit            string                           `json:"cloud_init"`
		}{prepared.TargetID, prepared.CloudInitSource.ID, prepared.CloudInitSource.Version, prepared.CloudInitSource.SHA256, prepared.CloudInit.SHA256, string(prepared.CloudInit.Bytes)})
	})
	mux.HandleFunc("POST /api/targets/{target}/host-key/observe", func(writer http.ResponseWriter, request *http.Request) {
		if !requireApplication(writer, app) || !requireJSON(writer, request) {
			return
		}
		id := managementstate.TargetID(request.PathValue("target"))
		var input struct{ Address string `json:"address"` }
		if err := decodeJSON(request, &input); err != nil {
			writeError(writer, http.StatusBadRequest, err)
			return
		}
		if err := app.SetTargetAddress(request.Context(), id, input.Address); err != nil {
			writeError(writer, http.StatusUnprocessableEntity, err)
			return
		}
		observation, err := app.ObserveHostKey(request.Context(), id)
		if err != nil {
			writeError(writer, http.StatusBadGateway, err)
			return
		}
		writeJSON(writer, http.StatusOK, observation)
	})
	mux.HandleFunc("POST /api/targets/{target}/host-key/confirm", func(writer http.ResponseWriter, request *http.Request) {
		if !requireApplication(writer, app) || !requireJSON(writer, request) {
			return
		}
		id := managementstate.TargetID(request.PathValue("target"))
		var observation targetgateway.HostKeyObservation
		if err := decodeJSON(request, &observation); err != nil {
			writeError(writer, http.StatusBadRequest, err)
			return
		}
		if err := app.ConfirmHostKey(request.Context(), id, observation); err != nil {
			writeError(writer, http.StatusConflict, err)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]string{"status": "confirmed"})
	})
	mux.HandleFunc("POST /api/targets/{target}/enroll", func(writer http.ResponseWriter, request *http.Request) {
		if !requireApplication(writer, app) || !requireJSON(writer, request) {
			return
		}
		id := managementstate.TargetID(request.PathValue("target"))
		result, err := app.Enroll(request.Context(), id)
		if err != nil {
			status := http.StatusUnprocessableEntity
			if errors.Is(err, targetgateway.ErrTrustRequired) {
				status = http.StatusPreconditionRequired
			}
			writeError(writer, status, err)
			return
		}
		writeJSON(writer, http.StatusOK, result)
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

func requireApplication(writer http.ResponseWriter, app TargetApplication) bool {
	if app != nil {
		return true
	}
	writeError(writer, http.StatusServiceUnavailable, errors.New("VPSmith target application is unavailable"))
	return false
}

func requireJSON(writer http.ResponseWriter, request *http.Request) bool {
	if strings.HasPrefix(strings.ToLower(request.Header.Get("Content-Type")), "application/json") {
		return true
	}
	writeError(writer, http.StatusUnsupportedMediaType, errors.New("application/json is required"))
	return false
}

func decodeJSON(request *http.Request, out any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(nilResponseWriter{}, request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("request must contain one JSON object")
	}
	return nil
}

// nilResponseWriter is used only for MaxBytesReader's optional overflow error
// response. The route writes its own structured error after Decode returns.
type nilResponseWriter struct{}
func (nilResponseWriter) Header() http.Header { return make(http.Header) }
func (nilResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (nilResponseWriter) WriteHeader(int) {}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(value)
}

func writeError(writer http.ResponseWriter, status int, err error) {
	writeJSON(writer, status, map[string]string{"error": err.Error()})
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
		if len(value) <= 16 { return value }
		return value[:16] + "…"
	},
	"builtAt": func(value string) string {
		if value == "" { return "not set" }
		if parsed, err := time.Parse(time.RFC3339, value); err == nil { return parsed.UTC().Format(time.RFC3339) }
		return value
	},
}).Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>VPSmith Studio</title>
<style>:root{color-scheme:light dark;font-family:ui-sans-serif,system-ui,sans-serif}body{max-width:58rem;margin:4rem auto;padding:0 1.5rem;line-height:1.5}header{margin-bottom:2.5rem}h1{margin-bottom:.25rem}.badge{display:inline-block;padding:.2rem .55rem;border:1px solid currentColor;border-radius:999px;font-size:.85rem}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(15rem,1fr));gap:1rem}.card{border:1px solid color-mix(in srgb,currentColor 25%,transparent);border-radius:.6rem;padding:1rem}code{overflow-wrap:anywhere}small{opacity:.75}</style></head>
<body><header><span class="badge">Local only</span><h1>VPSmith Studio</h1><p>VPSmith Platform build {{.Version}}. Target bootstrap is wired through the canonical application modules; TOFU confirmation remains an explicit separate action.</p><small>Revision {{if .Revision}}{{.Revision}}{{else}}unknown{{end}} · Built {{builtAt .BuiltAt}}</small></header>
<main><h2>Embedded basis snapshots</h2><div class="grid"><section class="card"><h3>Cloud-init</h3><p>{{.Embedded.CloudInit.Version}}</p><code>sha256:{{shortSHA .Embedded.CloudInit.SHA256}}</code></section><section class="card"><h3>Core</h3><p>{{.Embedded.Core.Version}}</p><code>sha256:{{shortSHA .Embedded.Core.SHA256}}</code></section><section class="card"><h3>n8n example module</h3><p>{{.Embedded.N8N.Version}}</p><code>sha256:{{shortSHA .Embedded.N8N.SHA256}}</code></section></div></main></body></html>`))
