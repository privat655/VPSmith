package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const manifestAccept = "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json"

type OCI struct {
	client    *http.Client
	endpoints map[string]string
}

func NewOCI(client *http.Client) *OCI {
	if client == nil {
		client = http.DefaultClient
	}
	return &OCI{client: client, endpoints: map[string]string{}}
}

func newOCI(client *http.Client, endpoints map[string]string) *OCI {
	if client == nil {
		client = http.DefaultClient
	}
	return &OCI{client: client, endpoints: endpoints}
}

func (o *OCI) Resolve(ctx context.Context, ref string) (string, error) {
	image, err := parseReference(ref)
	if err != nil {
		return "", err
	}
	endpoint := o.endpoints[image.registry]
	if endpoint == "" {
		host := image.registry
		if host == "docker.io" {
			host = "registry-1.docker.io"
		}
		endpoint = "https://" + host
	}
	manifestURL := strings.TrimRight(endpoint, "/") + "/v2/" + image.repository + "/manifests/" + url.PathEscape(image.tag)
	resp, err := o.manifestRequest(ctx, manifestURL, "")
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("WWW-Authenticate")
		_ = resp.Body.Close()
		token, err := o.bearerToken(ctx, challenge)
		if err != nil {
			return "", err
		}
		resp, err = o.manifestRequest(ctx, manifestURL, token)
		if err != nil {
			return "", err
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry manifest request returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return "", fmt.Errorf("read registry manifest: %w", err)
	}
	digest := strings.TrimSpace(resp.Header.Get("Docker-Content-Digest"))
	if digest == "" {
		sum := sha256.Sum256(body)
		digest = "sha256:" + hex.EncodeToString(sum[:])
	}
	if !validSHA256Digest(digest) {
		return "", errors.New("registry returned invalid manifest digest")
	}
	return strings.ToLower(digest), nil
}

func (o *OCI) manifestRequest(ctx context.Context, target, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", manifestAccept)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request registry manifest: %w", err)
	}
	return resp, nil
}

func (o *OCI) bearerToken(ctx context.Context, challenge string) (string, error) {
	realm, params, err := parseBearerChallenge(challenge)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(realm)
	if err != nil || u.Scheme != "https" && u.Scheme != "http" || u.Host == "" {
		return "", errors.New("registry bearer challenge has invalid realm")
	}
	q := u.Query()
	for _, key := range []string{"service", "scope"} {
		if params[key] != "" {
			q.Set(key, params[key])
		}
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request registry bearer token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry token request returned %s", resp.Status)
	}
	var payload struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode registry bearer token: %w", err)
	}
	if payload.Token == "" {
		payload.Token = payload.AccessToken
	}
	if payload.Token == "" || strings.ContainsAny(payload.Token, "\r\n") {
		return "", errors.New("registry bearer token is empty or invalid")
	}
	return payload.Token, nil
}
