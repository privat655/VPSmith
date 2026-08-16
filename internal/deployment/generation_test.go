package deployment

import (
	"bytes"
	"context"
	"testing"

	"github.com/privat655/VPSmith/internal/executionbundle"
)

func TestPrepareRegeneratesWholeCaddyAndAuthelia(t *testing.T) {
	req := baseRequest()
	c := newCompiler(t, "docker.io/example/n8n:2.0.0")
	p, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, a := range p.Artifacts {
		files[a.Path] = a.Data
	}
	wantCaddy := "{\n\tadmin off\n}\n\nn8n.example.test {\n\tforward_auth authelia:9091 {\n\t\tcopy_headers Remote-User Remote-Groups Remote-Email Remote-Name\n\t}\n\treverse_proxy vpsmith-n8n-1-app:8080\n}\n\n"
	if string(files["artifacts/core/Caddyfile"]) != wantCaddy {
		t.Fatalf("Caddy golden mismatch:\n%s", files["artifacts/core/Caddyfile"])
	}
	wantAuthelia := "access_control:\n  default_policy: deny\n  rules:\n    - domain: n8n.example.test\n      policy: two_factor\n      subject:\n        - 'group:admins'\n"
	if string(files["artifacts/core/authelia-access-control.yml"]) != wantAuthelia {
		t.Fatalf("Authelia golden mismatch:\n%s", files["artifacts/core/authelia-access-control.yml"])
	}
}

func TestPrepareQuadletUsesDigestResourcesEnvironmentAndSecretReferences(t *testing.T) {
	req := baseRequest()
	req.DesiredModules[0].SecretIDs["key"] = "secret-stable-id"
	c := newCompiler(t, "docker.io/example/n8n:2.0.0")
	p, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var quadlet []byte
	for _, a := range p.Artifacts {
		if a.Path == "artifacts/quadlet/vpsmith-n8n-1-app.container" {
			quadlet = a.Data
		}
	}
	for _, want := range [][]byte{
		[]byte("Image=docker.io/example/n8n:2.0.0@" + digestA),
		[]byte("UserNS=nomap"), []byte("DropCapability=ALL"), []byte("Environment=TZ=Europe/Berlin"),
		[]byte("EnvironmentFile=/var/lib/vpsmith/secrets/n8n-1/secret-stable-id.env"),
	} {
		if !bytes.Contains(quadlet, want) {
			t.Fatalf("quadlet missing %q:\n%s", want, quadlet)
		}
	}
}

func TestPrepareBundleContainsOnlySecretIDsNotPlaintext(t *testing.T) {
	req := baseRequest()
	req.DesiredModules[0].SecretIDs["key"] = "secret-stable-id"
	c := newCompiler(t, "docker.io/example/n8n:2.0.0")
	p, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(p.Bundle.Bytes, []byte("known-plaintext-secret-value")) {
		t.Fatal("secret plaintext leaked")
	}
	if !bytes.Contains(p.Bundle.Bytes, []byte("secret-stable-id")) {
		t.Fatal("stable SecretID missing")
	}
}

func TestPrepareSameVersionDifferentPackageSHAIsSourceChange(t *testing.T) {
	req := baseRequest()
	req.Observed.Modules = []ObservedModule{{InstanceID: "n8n-1", ModuleID: "n8n", Version: "2.0.0", PackageSHA256: "different"}}
	c := newCompiler(t, "docker.io/example/n8n:2.0.0")
	p, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range p.ExpectedChanges {
		if f.Kind == "source_changed" {
			return
		}
	}
	t.Fatal("same version with changed package SHA not reported as source change")
}

func TestPrepareValidationBundleIsReadOnlyAndNeedsNoPlan(t *testing.T) {
	req := baseRequest()
	req.Operation = Validate
	c := newCompiler(t, "docker.io/example/n8n:2.0.0")
	p, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if p.PlanRequired || p.Bundle.Kind != executionbundle.Validation {
		t.Fatal("validation should be direct/read-only bundle")
	}
	for _, s := range p.Bundle.Manifest.Steps {
		if s.Mutating || s.Kind == "apply-artifact" {
			t.Fatalf("validation contains structural step %#v", s)
		}
	}
}

func TestPrepareUsesCorrectBundleKindsForPersistentOperations(t *testing.T) {
	for _, tc := range []struct {
		op   OperationKind
		kind executionbundle.Kind
	}{{Install, executionbundle.Installation}, {Reconfigure, executionbundle.Migration}, {Restore, executionbundle.Migration}} {
		req := baseRequest()
		req.Operation = tc.op
		c := newCompiler(t, "docker.io/example/n8n:2.0.0")
		p, err := c.Prepare(context.Background(), req)
		if err != nil {
			t.Fatalf("%s: %v", tc.op, err)
		}
		if p.Bundle.Kind != tc.kind || !p.PlanRequired {
			t.Fatalf("%s: bundle kind=%s plan=%t", tc.op, p.Bundle.Kind, p.PlanRequired)
		}
	}

	req := baseRequest()
	req.Operation = Uninstall
	req.DesiredModules = nil
	source := reqSource("n8n-1", "n8n", "2.0.0", "[]")
	req.SubjectSource = &source
	req.SubjectSecretIDs = map[string]string{"key": "secret-n8n-1"}
	req.Observed.Modules = []ObservedModule{{InstanceID: "n8n-1", ModuleID: "n8n", PackageID: source.PackageID, Version: "2.0.0", PackageSHA256: source.PackageSHA256, ImageDigests: map[string]string{"app": digestA}}}
	c := newCompiler(t, "docker.io/example/n8n:2.0.0")
	p, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if p.Bundle.Kind != executionbundle.Migration || !p.PlanRequired {
		t.Fatalf("uninstall: bundle kind=%s plan=%t", p.Bundle.Kind, p.PlanRequired)
	}
}

func TestPrepareDiffIncludesRuntimeObjects(t *testing.T) {
	req := baseRequest()
	req.Observed.Modules = []ObservedModule{{
		InstanceID: "n8n-1", ModuleID: "n8n", Version: "2.0.0", PackageSHA256: hashChar("n8n-1"),
		ImageDigests: map[string]string{"app": digestA}, RuntimeObjects: []string{"container:unexpected"},
	}}
	c := newCompiler(t, "docker.io/example/n8n:2.0.0")
	p, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var missing, unexpected bool
	for _, fact := range p.ExpectedChanges {
		missing = missing || fact.Kind == "runtime_missing"
		unexpected = unexpected || fact.Kind == "runtime_unexpected"
	}
	if !missing || !unexpected {
		t.Fatalf("runtime diff incomplete: %#v", p.ExpectedChanges)
	}
}

func TestPrepareInventoryCarriesDeclarativePrimaryHealthcheck(t *testing.T) {
	req := baseRequest()
	c := newCompiler(t, "docker.io/example/n8n:2.0.0")
	prepared, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var inventory []byte
	for _, artifact := range prepared.Artifacts {
		if artifact.TargetPath == "/var/lib/vpsmith/inventory/modules.json" {
			inventory = artifact.Data
			break
		}
	}
	if len(inventory) == 0 {
		t.Fatal("module inventory artifact missing")
	}
	for _, want := range [][]byte{
		[]byte(`"healthcheck":{"type":"tcp","container":"app","port":8080}`),
		[]byte(`"instance_id":"n8n-1"`),
	} {
		if !bytes.Contains(inventory, want) {
			t.Fatalf("module inventory missing %s: %s", want, inventory)
		}
	}
}
