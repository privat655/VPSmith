package targetgateway

import "testing"

func TestParseUFWDefaultsIgnoresOrderAndWhitespace(t *testing.T) {
	incoming, outgoing, routed, err := parseUFWDefaults(" deny (routed),  allow (outgoing), deny (incoming) ")
	if err != nil {
		t.Fatal(err)
	}
	if incoming != "deny" || outgoing != "allow" || routed != "deny" {
		t.Fatalf("defaults = incoming:%q outgoing:%q routed:%q", incoming, outgoing, routed)
	}
}

func TestParseUFWDefaultsPreservesUnexpectedPolicy(t *testing.T) {
	incoming, outgoing, routed, err := parseUFWDefaults("deny (incoming), allow (outgoing), disabled (routed)")
	if err != nil {
		t.Fatal(err)
	}
	if incoming != "deny" || outgoing != "allow" || routed != "disabled" {
		t.Fatalf("defaults = incoming:%q outgoing:%q routed:%q", incoming, outgoing, routed)
	}
}

func TestParseUFWDefaultsRejectsMissingDirection(t *testing.T) {
	if _, _, _, err := parseUFWDefaults("deny (incoming), allow (outgoing)"); err == nil {
		t.Fatal("missing routed policy accepted")
	}
}
