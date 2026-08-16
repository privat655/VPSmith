package deploymentinput

import (
	"reflect"
	"testing"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestNetworksPreservesManagedRelationshipAndForeignSubnets(t *testing.T) {
	observed := managementstate.ObservedState{
		PodmanNetworks: []managementstate.NetworkObservedState{
			{Name: "vpsmith-link-aabbcc", Present: true, Subnets: []string{"10.240.1.0/24"}, Relationship: "provider-1/api->consumer-1/app"},
			{Name: "foreign-net", Present: true, Subnets: []string{"10.240.2.0/24"}},
		},
		LinkNetworks: []managementstate.LinkNetworkObservedState{
			{Name: "vpsmith-link-aabbcc", Present: true, Subnet: "10.240.1.0/24", Relationship: "provider-1/api->consumer-1/app", DefinitionMatches: true},
		},
	}

	got, err := Networks(observed)
	if err != nil {
		t.Fatal(err)
	}
	want := []deployment.ObservedNetwork{
		{Name: "foreign-net", Subnet: "10.240.2.0/24"},
		{Name: "vpsmith-link-aabbcc", Subnet: "10.240.1.0/24", Relationship: "provider-1/api->consumer-1/app"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("networks = %#v, want %#v", got, want)
	}
}

func TestNetworksRejectsManagedLinkDefinitionDrift(t *testing.T) {
	observed := managementstate.ObservedState{
		PodmanNetworks: []managementstate.NetworkObservedState{
			{Name: "vpsmith-link-aabbcc", Present: true, Subnets: []string{"10.240.99.0/24"}},
		},
		LinkNetworks: []managementstate.LinkNetworkObservedState{
			{Name: "vpsmith-link-aabbcc", Present: true, Subnet: "10.240.99.0/24", Relationship: "", DefinitionMatches: false},
		},
	}

	if _, err := Networks(observed); err == nil {
		t.Fatal("drifted managed Link-Net must not be reusable")
	}
}
