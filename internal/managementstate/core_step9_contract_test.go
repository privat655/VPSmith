package managementstate

import "testing"

func TestStep9CoreDesiredRequiresExactCaddyAndAutheliaImageLocks(t *testing.T) {
	base := DesiredState{Core: CoreDesiredState{
		SourceID:     "source_core",
		Version:      "1.0.0",
		CoreContract: "1",
		Domain:       "example.test",
		ACMEEmail:    "ops@example.test",
		Authelia:     CoreAutheliaDesiredState{Enrollment: "self-service-totp"},
		Secrets: CoreSecretReferences{
			AutheliaSession:       "secret_session",
			AutheliaStorage:       "secret_storage",
			AutheliaResetPassword: "secret_reset",
			AutheliaUsersDatabase: "secret_users",
		},
	}}
	base.Core.Images = map[string]CoreImageIdentity{
		"caddy": {Ref: "docker.io/library/caddy:2.11.4-alpine", Digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	}
	if err := validateDesired(base); err == nil {
		t.Fatal("partial Core image lock set was accepted")
	}

	base.Core.Images["authelia"] = CoreImageIdentity{Ref: "docker.io/authelia/authelia:4.39.20", Digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
	if err := validateDesired(base); err != nil {
		t.Fatalf("complete exact Core image lock set rejected: %v", err)
	}
}
