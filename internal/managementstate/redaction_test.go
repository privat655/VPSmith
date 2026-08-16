package managementstate_test

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestSecretPlaintextNeverAppearsInManagementStateLogsOrErrors(t *testing.T) {
	ctx := context.Background()
	store, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var logs bytes.Buffer
	oldWriter := log.Writer()
	oldFlags := log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
	})

	plaintext := "log-leak-sentinel-42"
	var id managementstate.SecretID
	if err := store.Change(ctx, func(change *managementstate.Change) error {
		var err error
		id, err = change.CreateSecret("log-test", managementstate.SecretUser)
		if err != nil {
			return err
		}
		return change.SetSecret(id, []byte(plaintext))
	}); err != nil {
		t.Fatal(err)
	}

	err = store.ResolveSecret(ctx, id, func(material managementstate.SecretMaterial) error {
		log.Printf("resolved material: %v", material)
		return &secretConsumerError{material: plaintext}
	})
	if err == nil {
		t.Fatal("expected secret consumer error")
	}
	if strings.Contains(err.Error(), plaintext) {
		t.Fatalf("public error leaked secret: %v", err)
	}
	if strings.Contains(logs.String(), plaintext) {
		t.Fatalf("formatted SecretMaterial leaked plaintext into log: %q", logs.String())
	}
}

type secretConsumerError struct{ material string }

func (e *secretConsumerError) Error() string { return e.material }
