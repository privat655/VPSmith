package deployment

import (
	"context"
	"testing"
)

func TestPrepareBlocksMissingAndAmbiguousProvider(t *testing.T) {
	dep := "[{target_module: provider, interface: api, consumer: app}]"
	consumer := desired("consumer-1", "consumer", "2.0.0", dep)
	c := newCompiler(t, "docker.io/example/consumer:2.0.0")
	req := Request{Operation: Install, TargetID: "target-1", SubjectInstance: "consumer-1", DesiredModules: []DesiredModule{consumer}, Observed: ObservedState{TargetID: "target-1"}, CoreContract: "1.0"}
	if _, err := c.Prepare(context.Background(), req); err == nil {
		t.Fatal("expected missing provider rejection")
	}
	p1 := desired("provider-1", "provider", "2.0.0", "[]")
	p2 := desired("provider-2", "provider", "2.0.0", "[]")
	c = newCompiler(t, "docker.io/example/consumer:2.0.0", "docker.io/example/provider:2.0.0")
	req.DesiredModules = []DesiredModule{consumer, p1, p2}
	if _, err := c.Prepare(context.Background(), req); err == nil {
		t.Fatal("expected ambiguous provider rejection")
	}
}

func TestPrepareCreatesExactlyOneStableLinkForDeclaredRelationship(t *testing.T) {
	provider := desired("provider-1", "provider", "2.0.0", "[]")
	consumer := desired("consumer-1", "consumer", "2.0.0", "[{target_module: provider, interface: api, consumer: app}]")
	c := newCompiler(t, "docker.io/example/provider:2.0.0", "docker.io/example/consumer:2.0.0")
	req := Request{Operation: Install, TargetID: "target-1", SubjectInstance: "consumer-1", DesiredModules: []DesiredModule{provider, consumer}, Observed: ObservedState{TargetID: "target-1"}, CoreContract: "1.0"}
	p, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.LinkNetworks) != 1 {
		t.Fatalf("got %d Link-Net networks", len(p.LinkNetworks))
	}
	link := p.LinkNetworks[0]
	req.Observed.Networks = []ObservedNetwork{{Name: link.Name, Subnet: link.Subnet, Relationship: link.Relationship}}
	again, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if again.LinkNetworks[0] != link {
		t.Fatalf("existing declared Link-Net changed: %#v -> %#v", link, again.LinkNetworks[0])
	}
}

func TestPrepareUnconnectedModulesHaveNoLink(t *testing.T) {
	a := desired("a-1", "alpha", "2.0.0", "[]")
	b := desired("b-1", "beta", "2.0.0", "[]")
	c := newCompiler(t, "docker.io/example/alpha:2.0.0", "docker.io/example/beta:2.0.0")
	p, err := c.Prepare(context.Background(), Request{Operation: Install, TargetID: "target-1", SubjectInstance: "a-1", DesiredModules: []DesiredModule{a, b}, Observed: ObservedState{TargetID: "target-1"}, CoreContract: "1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.LinkNetworks) != 0 {
		t.Fatal("unconnected modules received a Link-Net")
	}
}

func TestPrepareBlocksNeededProviderUninstall(t *testing.T) {
	consumer := desired("consumer-1", "consumer", "2.0.0", "[{target_module: provider, interface: api, consumer: app}]")
	c := newCompiler(t, "docker.io/example/consumer:2.0.0", "docker.io/example/provider:2.0.0")
	source := reqSource("provider-1", "provider", "2.0.0", "[]")
	req := Request{
		Operation: Uninstall, TargetID: "target-1", SubjectInstance: "provider-1", DesiredModules: []DesiredModule{consumer}, CoreContract: "1.0",
		SubjectSource: &source, SubjectSecretIDs: map[string]string{"key": "secret-provider-1"},
		Observed: ObservedState{TargetID: "target-1", Modules: []ObservedModule{{InstanceID: "provider-1", ModuleID: "provider", PackageID: source.PackageID, Version: "2.0.0", PackageSHA256: source.PackageSHA256, ImageDigests: map[string]string{"app": digestB}}}},
	}
	if _, err := c.Prepare(context.Background(), req); err == nil {
		t.Fatal("required provider uninstall must be blocked")
	}
}

func TestPrepareBlocksForeignObservedLinkNameAndSubnetCollisions(t *testing.T) {
	provider := desired("provider-1", "provider", "2.0.0", "[]")
	consumer := desired("consumer-1", "consumer", "2.0.0", "[{target_module: provider, interface: api, consumer: app}]")
	c := newCompiler(t, "docker.io/example/provider:2.0.0", "docker.io/example/consumer:2.0.0")
	req := Request{Operation: Install, TargetID: "target-1", SubjectInstance: "consumer-1", DesiredModules: []DesiredModule{provider, consumer}, Observed: ObservedState{TargetID: "target-1"}, CoreContract: "1.0"}
	prepared, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	link := prepared.LinkNetworks[0]
	req.Observed.Networks = []ObservedNetwork{{Name: link.Name, Subnet: "10.250.1.0/24"}}
	if _, err := c.Prepare(context.Background(), req); err == nil {
		t.Fatal("foreign observed network using stable Link-Net name must block")
	}
	req.Observed.Networks = []ObservedNetwork{{Name: "foreign", Subnet: link.Subnet}}
	prepared, err = c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.LinkNetworks[0].Subnet == link.Subnet {
		t.Fatal("foreign observed subnet must not be reused")
	}
}
