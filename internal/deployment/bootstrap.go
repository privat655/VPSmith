package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"github.com/privat655/VPSmith/internal/managementstate"
)

const MaxCloudInitBytes = 16 * 1024

var (
	safeBootstrapToken   = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	safeDefinitionToken  = regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)
	safeTimezoneToken    = regexp.MustCompile(`^[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*$`)
	lowercaseSHA256Token = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type BootstrapSource struct {
	Version  string
	SHA256   string
	Template []byte
}

type BootstrapRequest struct {
	TargetID     string
	Desired      managementstate.CloudInitDesiredState
	SSHPublicKey string
	Source       BootstrapSource
}

// PrepareBootstrap compiles the complete provider-facing Cloud-init document
// from one frozen source snapshot. Cloud-init is deliberately not an execution
// bundle: it runs before SSH trust exists and contains only Part 1.
func (c *Compiler) PrepareBootstrap(req BootstrapRequest) (BootstrapArtifact, error) {
	if c == nil {
		return BootstrapArtifact{}, errors.New("deployment compiler is required")
	}
	if err := validateBootstrapRequest(req); err != nil {
		return BootstrapArtifact{}, err
	}
	data, err := renderCloudInit(req)
	if err != nil {
		return BootstrapArtifact{}, err
	}
	if len(data) >= MaxCloudInitBytes {
		return BootstrapArtifact{}, fmt.Errorf("cloud-init is %d bytes; must be smaller than %d", len(data), MaxCloudInitBytes)
	}
	sum := sha256.Sum256(data)
	return BootstrapArtifact{Identity: req.Source.Version, SHA256: hex.EncodeToString(sum[:]), Bytes: data}, nil
}

func validateBootstrapRequest(req BootstrapRequest) error {
	for name, value := range map[string]string{
		"target id":      req.TargetID,
		"hostname":       req.Desired.Hostname,
		"timezone":       req.Desired.Timezone,
		"administrator":  req.Desired.Administrator,
		"source version": req.Source.Version,
		"source sha256":  req.Source.SHA256,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if !safeBootstrapToken.MatchString(req.Desired.Hostname) || !safeBootstrapToken.MatchString(req.Desired.Administrator) {
		return errors.New("hostname and administrator must use safe characters")
	}
	if !safeTimezoneToken.MatchString(req.Desired.Timezone) || strings.Contains(req.Desired.Timezone, "..") {
		return errors.New("invalid timezone")
	}
	if !safeDefinitionToken.MatchString(req.Source.Version) {
		return errors.New("cloud-init source version contains unsafe characters")
	}
	if !lowercaseSHA256Token.MatchString(req.Source.SHA256) {
		return errors.New("cloud-init source sha256 must be lowercase hexadecimal")
	}
	if len(req.Source.Template) == 0 {
		return errors.New("cloud-init source template is required")
	}
	if req.Desired.DefinitionVersion != "" && req.Desired.DefinitionVersion != req.Source.Version {
		return errors.New("cloud-init desired version does not match frozen source version")
	}
	fields := strings.Fields(req.SSHPublicKey)
	if len(fields) < 2 || fields[0] != "ssh-ed25519" || strings.ContainsAny(req.SSHPublicKey, "\r\n\x00") {
		return errors.New("complete ssh-ed25519 public key is required")
	}
	return nil
}

func renderCloudInit(req BootstrapRequest) ([]byte, error) {
	tmpl, err := template.New("cloud-init").Option("missingkey=error").Parse(string(req.Source.Template))
	if err != nil {
		return nil, fmt.Errorf("parse Cloud-init source template: %w", err)
	}
	data := struct {
		Hostname          string
		Timezone          string
		Administrator     string
		SSHPublicKey      string
		DefinitionVersion string
	}{
		Hostname: req.Desired.Hostname, Timezone: req.Desired.Timezone,
		Administrator: req.Desired.Administrator, SSHPublicKey: req.SSHPublicKey,
		DefinitionVersion: req.Source.Version,
	}
	var rendered bytes.Buffer
	if err := tmpl.Execute(&rendered, data); err != nil {
		return nil, fmt.Errorf("render Cloud-init source template: %w", err)
	}
	if !bytes.HasPrefix(rendered.Bytes(), []byte("#cloud-config\n")) {
		return nil, errors.New("Cloud-init source must render a #cloud-config document")
	}
	return rendered.Bytes(), nil
}
