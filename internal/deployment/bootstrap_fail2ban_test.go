package deployment

import (
	"strings"
	"testing"
)

func TestPrepareBootstrapRestartsFail2banAfterDeferredConfiguration(t *testing.T) {
	c := newCompiler(t, "docker.io/example/unused:1")
	artifact, err := c.PrepareBootstrap(testBootstrapRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	text := string(artifact.Bytes)
	validate := strings.Index(text, "fail2ban-client -t")
	enable := strings.Index(text, "systemctl enable fail2ban.service")
	restart := strings.Index(text, "systemctl restart fail2ban.service")
	sshdStatus := strings.Index(text, "fail2ban-client status sshd")
	recidiveStatus := strings.Index(text, "fail2ban-client status recidive")
	success := strings.Index(text, "status=ok")
	if validate < 0 || enable < 0 || restart < 0 || sshdStatus < 0 || recidiveStatus < 0 || success < 0 || !(validate < enable && enable < restart && restart < sshdStatus && sshdStatus < recidiveStatus && recidiveStatus < success) {
		t.Fatalf("fail2ban activation ordering is unsafe: validate=%d enable=%d restart=%d sshd=%d recidive=%d success=%d", validate, enable, restart, sshdStatus, recidiveStatus, success)
	}
	if strings.Contains(text, "systemctl enable --now fail2ban.service") {
		t.Fatal("deferred fail2ban configuration must be loaded by an explicit restart")
	}
}
