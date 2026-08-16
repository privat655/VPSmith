package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveFreezesRegistryDigest(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2}`)
	sum := sha256.Sum256(manifest)
	want := "sha256:" + hex.EncodeToString(sum[:])
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/v2/acme/app/manifests/1.2.3", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token-1" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="registry.test",scope="repository:acme/app:pull"`, server.URL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Docker-Content-Digest", want)
		_, _ = w.Write(manifest)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("scope") != "repository:acme/app:pull" {
			t.Fatalf("missing scope: %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"token":"token-1"}`))
	})
	adapter := newOCI(server.Client(), map[string]string{"registry.test": server.URL})
	got, err := adapter.Resolve(context.Background(), "registry.test/acme/app:1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("digest = %s, want %s", got, want)
	}
}

func TestResolveComputesDigestWhenRegistryOmitsHeader(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2,"config":{}}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifest) }))
	defer server.Close()
	adapter := newOCI(server.Client(), map[string]string{"registry.test": server.URL})
	got, err := adapter.Resolve(context.Background(), "registry.test/acme/app:1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(manifest)
	want := "sha256:" + hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("digest = %s, want %s", got, want)
	}
}

func TestResolveRejectsMovingOrUnpinnedReference(t *testing.T) {
	adapter := NewOCI(nil)
	for _, ref := range []string{"registry.test/acme/app:latest", "registry.test/acme/app:^2", "registry.test/acme/app"} {
		if _, err := adapter.Resolve(context.Background(), ref); err == nil {
			t.Fatalf("expected rejection for %s", ref)
		}
	}
}
