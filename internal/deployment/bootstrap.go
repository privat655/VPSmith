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
	safeAdministratorToken = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	safeDefinitionToken    = regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)
	safeTimezoneToken      = regexp.MustCompile(`^[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*$`)
	lowercaseSHA256Token   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	sshBase64Token         = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
)

type BootstrapSource struct {
	SnapshotID managementstate.SourceSnapshotID
	Version    string
	SHA256     string
	Template   []byte
}

type BootstrapRequest struct {
	TargetID     string
	Desired      managementstate.CloudInitDesiredState
	SSHPublicKey string
	Source       BootstrapSource
}

func ValidateBootstrapDesired(desired managementstate.CloudInitDesiredState) error {
	if strings.TrimSpace(desired.Hostname) == "" {
		return errors.New("hostname is required")
	}
	if !validHostname(desired.Hostname) {
		return errors.New("hostname must be a valid lowercase DNS hostname")
	}
	if strings.TrimSpace(desired.Timezone) == "" {
		return errors.New("timezone is required")
	}
	if !safeTimezoneToken.MatchString(desired.Timezone) || strings.Contains(desired.Timezone, "..") {
		return errors.New("invalid timezone")
	}
	if strings.TrimSpace(desired.Administrator) == "" {
		return errors.New("administrator is required")
	}
	if desired.Administrator == "root" || !safeAdministratorToken.MatchString(desired.Administrator) {
		return errors.New("administrator must be a non-root lowercase account name using only letters, digits, underscore, or hyphen")
	}
	return nil
}

// PrepareBootstrap renders target-specific bytes from exactly one frozen source
// snapshot. The source snapshot identity and source digest are validated before
// rendering so provenance cannot be replaced by the rendered document digest.
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
	if strings.TrimSpace(req.TargetID) == "" {
		return errors.New("target id is required")
	}
	if err := ValidateBootstrapDesired(req.Desired); err != nil {
		return err
	}
	if req.Source.SnapshotID == "" {
		return errors.New("source snapshot id is required")
	}
	if strings.TrimSpace(req.Source.Version) == "" {
		return errors.New("source version is required")
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
	if req.Desired.SourceSnapshotID != req.Source.SnapshotID {
		return errors.New("cloud-init desired source snapshot does not match frozen source")
	}
	if req.Desired.DefinitionVersion != req.Source.Version {
		return errors.New("cloud-init desired version does not match frozen source version")
	}
	if req.Desired.SourceSHA256 != req.Source.SHA256 {
		return errors.New("cloud-init desired source sha256 does not match frozen source")
	}
	fields := strings.Fields(req.SSHPublicKey)
	if len(fields) < 2 || fields[0] != "ssh-ed25519" || !sshBase64Token.MatchString(fields[1]) || strings.ContainsAny(req.SSHPublicKey, "\r\n\x00") {
		return errors.New("complete ssh-ed25519 public key is required")
	}
	return nil
}

func validHostname(value string) bool {
	if len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func renderCloudInit(req BootstrapRequest) ([]byte, error) {
	tmpl, err := template.New("cloud-init").Option("missingkey=error").Parse(string(req.Source.Template))
	if err != nil {
		return nil, fmt.Errorf("parse Cloud-init source template: %w", err)
	}
	keyFields := strings.Fields(req.SSHPublicKey)
	data := struct{ Hostname, Timezone, Administrator, SSHPublicKey, SSHPublicKeyMaterial, DefinitionVersion string }{
		Hostname: req.Desired.Hostname, Timezone: req.Desired.Timezone, Administrator: req.Desired.Administrator,
		SSHPublicKey: req.SSHPublicKey, SSHPublicKeyMaterial: keyFields[0] + " " + keyFields[1], DefinitionVersion: req.Source.Version,
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
