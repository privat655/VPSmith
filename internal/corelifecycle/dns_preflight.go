package corelifecycle

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

type dnsResolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

func requireDNSARecord(ctx context.Context, resolver dnsResolver, hostname, targetAddress string) error {
	if resolver == nil {
		return errors.New("DNS resolver is required")
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return errors.New("DNS hostname is required")
	}
	target, err := targetPublicIPv4(targetAddress)
	if err != nil {
		return err
	}
	ips, err := resolver.LookupIP(ctx, "ip4", hostname)
	if err != nil {
		return fmt.Errorf("resolve DNS A record for %s: %w", hostname, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil && v4.Equal(target) {
			return nil
		}
	}
	return fmt.Errorf("DNS A record for %s must point to target public IPv4 %s", hostname, target.String())
}

func targetPublicIPv4(address string) (net.IP, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, errors.New("target public IPv4 is required")
	}
	host := address
	if parsedHost, _, err := net.SplitHostPort(address); err == nil {
		host = parsedHost
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || ip.To4() == nil {
		return nil, errors.New("Core DNS preflight requires a target public IPv4 address")
	}
	return ip.To4(), nil
}
