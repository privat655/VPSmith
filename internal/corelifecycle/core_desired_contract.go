package corelifecycle

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/managementstate"
)

func deploymentAuthelia(value managementstate.CoreAutheliaDesiredState) deployment.CoreAutheliaConfiguration {
	return deployment.CoreAutheliaConfiguration{
		Users: append([]string(nil), value.Users...), Groups: append([]string(nil), value.Groups...), Enrollment: value.Enrollment,
	}
}

func desiredAuthelia(value deployment.CoreAutheliaConfiguration) managementstate.CoreAutheliaDesiredState {
	return managementstate.CoreAutheliaDesiredState{
		Users: append([]string(nil), value.Users...), Groups: append([]string(nil), value.Groups...), Enrollment: value.Enrollment,
	}
}

func desiredCoreImages(images []executionbundle.ImageIdentity) (map[string]managementstate.CoreImageIdentity, error) {
	if len(images) != 2 {
		return nil, errors.New("Core bundle must contain exactly Caddy and Authelia image identities")
	}
	out := make(map[string]managementstate.CoreImageIdentity, len(images))
	for _, image := range images {
		if image.Name != "caddy" && image.Name != "authelia" {
			return nil, fmt.Errorf("unexpected Core image %s", image.Name)
		}
		if strings.TrimSpace(image.Ref) == "" || !validCoreImageDigest(image.Digest) {
			return nil, fmt.Errorf("incomplete Core image identity for %s", image.Name)
		}
		if _, duplicate := out[image.Name]; duplicate {
			return nil, fmt.Errorf("duplicate Core image identity for %s", image.Name)
		}
		out[image.Name] = managementstate.CoreImageIdentity{Ref: image.Ref, Digest: image.Digest}
	}
	for _, name := range []string{"caddy", "authelia"} {
		if _, ok := out[name]; !ok {
			return nil, fmt.Errorf("Core bundle is missing %s image identity", name)
		}
	}
	return out, nil
}

func frozenCoreImages(value map[string]managementstate.CoreImageIdentity) (map[string]deployment.FrozenCoreImage, error) {
	if len(value) != 2 {
		return nil, errors.New("canonical Core desired state requires exact Caddy and Authelia image locks")
	}
	out := make(map[string]deployment.FrozenCoreImage, len(value))
	for _, name := range []string{"caddy", "authelia"} {
		image, ok := value[name]
		if !ok || strings.TrimSpace(image.Ref) == "" || !validCoreImageDigest(image.Digest) {
			return nil, fmt.Errorf("canonical Core desired image lock for %s is incomplete", name)
		}
		out[name] = deployment.FrozenCoreImage{Ref: image.Ref, Digest: image.Digest}
	}
	return out, nil
}

func normalizeDesiredAuthelia(value managementstate.CoreAutheliaDesiredState) managementstate.CoreAutheliaDesiredState {
	value.Users = uniqueSortedStrings(value.Users)
	value.Groups = uniqueSortedStrings(value.Groups)
	if value.Enrollment == "" {
		value.Enrollment = deployment.CoreAutheliaEnrollmentSelfServiceTOTP
	}
	return value
}

func uniqueSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func completeCoreDesiredRuntime(value managementstate.CoreDesiredState) error {
	if value.SourceID == "" || value.Version == "" || value.CoreContract == "" || value.Domain == "" || value.ACMEEmail == "" {
		return errors.New("canonical Core desired identity and configuration are incomplete")
	}
	if _, err := frozenCoreImages(value.Images); err != nil {
		return err
	}
	if normalizeDesiredAuthelia(value.Authelia).Enrollment != deployment.CoreAutheliaEnrollmentSelfServiceTOTP {
		return errors.New("canonical Core Authelia enrollment is unsupported")
	}
	for _, id := range value.Secrets.IDs() {
		if id == "" {
			return errors.New("canonical Core desired secret references are incomplete")
		}
	}
	return nil
}

func coreSecretRefsAny(value managementstate.CoreSecretReferences) bool {
	for _, id := range value.IDs() {
		if id != "" {
			return true
		}
	}
	return false
}
