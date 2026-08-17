package main

import "testing"

func TestPrimaryFailureMarkerFindsCloudInitFailure(t *testing.T) {
	logText := "before\ncloud-init[1]: vpsmith-primary-failed stage=verify-ufw-default-routed rc=1\nafter\n"
	got := primaryFailureMarker(logText)
	want := "vpsmith-primary-failed stage=verify-ufw-default-routed rc=1"
	if got != want {
		t.Fatalf("marker = %q, want %q", got, want)
	}
}

func TestPrimaryFailureMarkerIgnoresSuccessfulStageLogs(t *testing.T) {
	if got := primaryFailureMarker("vpsmith-primary-stage=verify-ufw-default-routed\n"); got != "" {
		t.Fatalf("unexpected marker %q", got)
	}
}
