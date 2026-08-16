package registry

import (
	"errors"
	"strings"
)

func parseBearerChallenge(value string) (string, map[string]string, error) {
	value = strings.TrimSpace(value)
	if len(value) < 7 || !strings.EqualFold(value[:6], "Bearer") {
		return "", nil, errors.New("registry did not provide a supported Bearer challenge")
	}
	rest := strings.TrimSpace(value[6:])
	params := map[string]string{}
	for len(rest) > 0 {
		eq := strings.IndexByte(rest, '=')
		if eq <= 0 {
			return "", nil, errors.New("invalid registry Bearer challenge")
		}
		key := strings.TrimSpace(rest[:eq])
		rest = strings.TrimSpace(rest[eq+1:])
		if !strings.HasPrefix(rest, `"`) {
			return "", nil, errors.New("invalid registry Bearer challenge value")
		}
		rest = rest[1:]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			return "", nil, errors.New("unterminated registry Bearer challenge value")
		}
		params[key] = rest[:end]
		rest = strings.TrimSpace(rest[end+1:])
		if rest == "" {
			break
		}
		if rest[0] != ',' {
			return "", nil, errors.New("invalid registry Bearer challenge separator")
		}
		rest = strings.TrimSpace(rest[1:])
	}
	if params["realm"] == "" {
		return "", nil, errors.New("registry Bearer challenge has no realm")
	}
	return params["realm"], params, nil
}
