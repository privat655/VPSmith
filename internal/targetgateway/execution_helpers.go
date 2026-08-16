package targetgateway

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/privat655/VPSmith/internal/execution"
)

func encodeSecretStream(values []execution.SecretValue) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString(secretStreamMagic)
	seen := map[string]struct{}{}
	for _, value := range values {
		if value.ID == "" || len(value.ID) > 4096 || len(value.Value) == 0 {
			return nil, errors.New("invalid execution secret value")
		}
		if _, exists := seen[value.ID]; exists {
			return nil, errors.New("duplicate execution secret id")
		}
		seen[value.ID] = struct{}{}
		if err := binary.Write(&out, binary.BigEndian, uint32(len(value.ID))); err != nil {
			return nil, err
		}
		out.WriteString(value.ID)
		if err := binary.Write(&out, binary.BigEndian, uint64(len(value.Value))); err != nil {
			return nil, err
		}
		out.Write(value.Value)
	}
	if err := binary.Write(&out, binary.BigEndian, uint32(0)); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func safeExecutionID(value string) bool {
	if value == "" || len(value) > 96 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func safeBundlePath(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || strings.Contains(value, "\x00") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func boundedRemoteError(stderr []byte) string {
	text := strings.TrimSpace(string(stderr))
	if text == "" {
		return ""
	}
	if len(text) > 512 {
		text = text[:512] + "..."
	}
	return ": " + text
}
