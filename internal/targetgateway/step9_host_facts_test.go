package targetgateway

import (
	"bytes"
	"context"
	"testing"
)

func TestProductionInspectionReportsEffectiveCoreHostFacts(t *testing.T) {
	base := inspectionFixture(t)
	runner := &captureRunner{}
	runner.hook = func(name string, args []string) ([]byte, []byte, error) {
		command := args[len(args)-1]
		if isStep9HostFactsCommand(command) {
			return []byte(step9HostFactsFixture), nil, nil
		}
		return base(name, args)
	}
	transport := newSSHTransportAt(t.TempDir(), runner)
	key := testHostObservation(4)
	observed, err := transport.Inspect(context.Background(), session{endpoint: endpoint{Address: "203.0.113.11", SSHUser: "dev"}, HostKey: key.PublicKey, IdentitySeed: bytes.Repeat([]byte{6}, 32)})
	if err != nil {
		t.Fatal(err)
	}

	hardening := observed.Host.SecondaryHardening
	if !hardening.AppArmorEnabled || !hardening.AuditdActive || !hardening.ChronyActive {
		t.Fatalf("secondary service facts = %#v", hardening)
	}
	if !hardening.JournalPersistent || hardening.JournalSystemMaxUseBytes != 200<<20 || hardening.JournalRuntimeMaxUseBytes != 50<<20 {
		t.Fatalf("journald facts = %#v", hardening)
	}
	if !hardening.CoredumpDisabled || !hardening.ApportDisabled || !hardening.TmpTmpfs || !hardening.TmpNoExec || !hardening.TmpNoSuid || !hardening.TmpNoDev {
		t.Fatalf("filesystem/crash facts = %#v", hardening)
	}
	if !hardening.BlockedModulesEffective || !hardening.IPv6Disabled || hardening.UnprivilegedPortStart != 1024 {
		t.Fatalf("kernel facts = %#v", hardening)
	}
	if !hardening.DockerAbsent || !hardening.ContainerdAbsent || !hardening.SubUIDRangePresent || !hardening.SubGIDRangePresent || !hardening.LingerEnabled {
		t.Fatalf("runtime foundation facts = %#v", hardening)
	}

	if len(observed.Host.SwapDevices) != 2 {
		t.Fatalf("swap devices = %#v", observed.Host.SwapDevices)
	}
	if observed.Host.SwapDevices[0].Path != "/dev/vdb" || observed.Host.SwapDevices[0].CoreManaged {
		t.Fatalf("foreign swap = %#v", observed.Host.SwapDevices[0])
	}
	if observed.Host.SwapDevices[1].Path != "/var/lib/vpsmith/swapfile" || !observed.Host.SwapDevices[1].CoreManaged || observed.Host.SwapDevices[1].UsedBytes != 4096 {
		t.Fatalf("Core swap = %#v", observed.Host.SwapDevices[1])
	}

	if len(observed.Host.Listeners) != 4 {
		t.Fatalf("listeners = %#v", observed.Host.Listeners)
	}
	if !observed.Host.Listeners[0].Public || observed.Host.Listeners[0].Port != 80 {
		t.Fatalf("public listener = %#v", observed.Host.Listeners[0])
	}
	if !observed.Host.Listeners[2].Loopback || observed.Host.Listeners[2].Public || observed.Host.Listeners[2].Port != 8080 {
		t.Fatalf("loopback listener = %#v", observed.Host.Listeners[2])
	}
}

func isStep9HostFactsCommand(command string) bool {
	return len(command) > 0 && containsAll(command, "vpsmith_step9_host_facts", "swapon --show", "ss -H -ltn", "aa-enabled")
}

func containsAll(value string, parts ...string) bool {
	for _, part := range parts {
		if !bytes.Contains([]byte(value), []byte(part)) {
			return false
		}
	}
	return true
}

const step9HostFactsFixture = "" +
	"hardening\tapp_armor_enabled\t1\n" +
	"hardening\tauditd_active\t1\n" +
	"hardening\tchrony_active\t1\n" +
	"hardening\tjournal_persistent\t1\n" +
	"hardening\tjournal_system_max_use\t200M\n" +
	"hardening\tjournal_runtime_max_use\t50M\n" +
	"hardening\tcoredump_disabled\t1\n" +
	"hardening\tapport_disabled\t1\n" +
	"hardening\ttmp_fstype\ttmpfs\n" +
	"hardening\ttmp_options\trw,nosuid,nodev,noexec,relatime\n" +
	"hardening\tblocked_modules_effective\t1\n" +
	"hardening\tipv6_disabled\t1\n" +
	"hardening\tunprivileged_port_start\t1024\n" +
	"hardening\tdocker_absent\t1\n" +
	"hardening\tcontainerd_absent\t1\n" +
	"hardening\tsubuid_range_present\t1\n" +
	"hardening\tsubgid_range_present\t1\n" +
	"hardening\tlinger_enabled\t1\n" +
	"swap\t/dev/vdb\tpartition\t1073741824\t0\t-2\n" +
	"swap\t/var/lib/vpsmith/swapfile\tfile\t2147483648\t4096\t-3\n" +
	"listener\ttcp\t0.0.0.0:80\n" +
	"listener\ttcp\t0.0.0.0:443\n" +
	"listener\ttcp\t127.0.0.1:8080\n" +
	"listener\ttcp\t127.0.0.1:8443\n"
