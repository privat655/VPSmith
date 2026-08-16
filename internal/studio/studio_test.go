package studio_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/releaseinfo"
	"github.com/privat655/VPSmith/internal/studio"
)

func TestHandlerPublishesHealthAndBuildIdentity(t *testing.T) {
	identity := studio.BuildIdentity{
		Version:  "0.1.0-dev.1",
		Revision: "abc1234",
		BuiltAt:  "2026-08-15T18:00:00Z",
		Embedded: releaseinfo.Embedded{
			CloudInit: releaseinfo.Source{Version: "cloud-v1", SHA256: strings.Repeat("a", 64)},
			Core:      releaseinfo.Source{Version: "core-v1", SHA256: strings.Repeat("b", 64)},
			N8N:       releaseinfo.Source{Version: "n8n-v1", SHA256: strings.Repeat("c", 64)},
		},
	}
	server := httptest.NewServer(studio.Handler(identity))
	defer server.Close()

	response, err := http.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(body) != "ok\n" {
		t.Fatalf("health = %d %q", response.StatusCode, body)
	}

	response, err = http.Get(server.URL + "/version")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var got studio.BuildIdentity
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Version != identity.Version || got.Embedded.Core.SHA256 != identity.Embedded.Core.SHA256 {
		t.Fatalf("version response = %#v", got)
	}
}

func TestHandlerStartPageStaysAFoundationPage(t *testing.T) {
	identity := studio.BuildIdentity{
		Version: "0.1.0-dev.1",
		Embedded: releaseinfo.Embedded{
			CloudInit: releaseinfo.Source{Version: "cloud-v1", SHA256: strings.Repeat("a", 64)},
			Core:      releaseinfo.Source{Version: "core-v1", SHA256: strings.Repeat("b", 64)},
			N8N:       releaseinfo.Source{Version: "n8n-v1", SHA256: strings.Repeat("c", 64)},
		},
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	studio.Handler(identity).ServeHTTP(response, request)
	body := response.Body.String()

	for _, want := range []string{"VPSmith Studio", "0.1.0-dev.1", "cloud-v1", "core-v1", "n8n-v1", "Local only"} {
		if !strings.Contains(body, want) {
			t.Fatalf("start page missing %q", want)
		}
	}
	for _, forbidden := range []string{"SSH verbinden", "Core installieren", "Modul installieren", "Backup erstellen"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("start page must not expose later-step operation %q", forbidden)
		}
	}
}
