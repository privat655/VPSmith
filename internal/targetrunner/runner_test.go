package targetrunner

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestEmbeddedRunnerIdentityMatchesBytes(t *testing.T) {
	data := Bytes()
	if len(data) == 0 {
		t.Fatal("embedded target runner is empty")
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != SHA256() {
		t.Fatalf("runner sha256=%s want %s", SHA256(), got)
	}
	if Path != "runtime/runner.py" || Version != "1" {
		t.Fatalf("unexpected runner identity path=%q version=%q", Path, Version)
	}
}
