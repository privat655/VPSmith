package corelifecycle

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

type dnsResolverStub struct {
	ips []net.IP
	err error
}

func (r dnsResolverStub) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return append([]net.IP(nil), r.ips...), r.err
}

func TestRequireDNSARecordMatchesTargetPublicIPv4(t *testing.T) {
	resolver := dnsResolverStub{ips: []net.IP{net.ParseIP("203.0.113.10")}}
	if err := requireDNSARecord(context.Background(), resolver, "auth.example.test", "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	if err := requireDNSARecord(context.Background(), resolver, "auth.example.test", "203.0.113.10:2222"); err != nil {
		t.Fatal(err)
	}
}

func TestRequireDNSARecordExplainsMissingOrWrongARecord(t *testing.T) {
	tests := []struct {
		name     string
		resolver dnsResolverStub
		address  string
		want     string
	}{
		{"wrong address", dnsResolverStub{ips: []net.IP{net.ParseIP("203.0.113.11")}}, "203.0.113.10", "must point"},
		{"lookup failure", dnsResolverStub{err: errors.New("no such host")}, "203.0.113.10", "resolve DNS A record"},
		{"ipv6 target", dnsResolverStub{ips: []net.IP{net.ParseIP("203.0.113.10")}}, "2001:db8::1", "public IPv4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := requireDNSARecord(context.Background(), tt.resolver, "auth.example.test", tt.address)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}
