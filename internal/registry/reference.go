package registry

import (
	"errors"
	"strings"
)

type imageReference struct {
	registry   string
	repository string
	tag        string
}

func parseReference(ref string) (imageReference, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.ContainsAny(ref, "@?#\r\n\x00") {
		return imageReference{}, errors.New("image reference must be a fixed tagged reference")
	}
	slash := strings.IndexByte(ref, '/')
	if slash <= 0 || slash == len(ref)-1 {
		return imageReference{}, errors.New("image reference must include registry and repository")
	}
	registry := ref[:slash]
	remainder := ref[slash+1:]
	colon := strings.LastIndexByte(remainder, ':')
	if colon <= 0 || colon == len(remainder)-1 {
		return imageReference{}, errors.New("image reference must include explicit tag")
	}
	repository, tag := remainder[:colon], remainder[colon+1:]
	if strings.Contains(repository, "..") || strings.HasPrefix(repository, "/") || strings.ContainsAny(repository, " \t") {
		return imageReference{}, errors.New("image repository is invalid")
	}
	if strings.EqualFold(tag, "latest") || strings.ContainsAny(tag, "*<>=^~| ") {
		return imageReference{}, errors.New("image tag must be fixed and must not be latest")
	}
	return imageReference{registry: strings.ToLower(registry), repository: repository, tag: tag}, nil
}

func validSHA256Digest(v string) bool {
	if len(v) != len("sha256:")+64 || !strings.HasPrefix(strings.ToLower(v), "sha256:") {
		return false
	}
	for _, r := range v[len("sha256:"):] {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' {
			continue
		}
		return false
	}
	return true
}
