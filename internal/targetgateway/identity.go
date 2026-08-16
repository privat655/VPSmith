package targetgateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

const sshEd25519 = "ssh-ed25519"

func publicIdentity(targetID string, seed []byte) (SSHIdentity, error) {
	if len(seed) != ed25519.SeedSize {
		return SSHIdentity{}, errors.New("invalid ed25519 seed")
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	blob := sshPublicBlob(publicKey)
	comment := "vpsmith:" + targetID
	return SSHIdentity{
		PublicKey:   sshEd25519 + " " + base64.StdEncoding.EncodeToString(blob) + " " + comment,
		Fingerprint: sshFingerprint(blob),
	}, nil
}

func sshPublicBlob(publicKey ed25519.PublicKey) []byte {
	var out bytes.Buffer
	writeSSHString(&out, []byte(sshEd25519))
	writeSSHString(&out, publicKey)
	return out.Bytes()
}

func sshFingerprint(blob []byte) string {
	digest := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

func parsePublicKey(key string) (algorithm string, blob []byte, fingerprint string, err error) {
	fields := strings.Fields(key)
	if len(fields) != 2 {
		return "", nil, "", errors.New("host key must contain algorithm and base64 payload")
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", nil, "", errors.New("host key has invalid base64 payload")
	}
	wireAlgorithm, rest, err := readSSHString(decoded)
	if err != nil {
		return "", nil, "", err
	}
	if string(wireAlgorithm) != fields[0] {
		return "", nil, "", errors.New("host key algorithm does not match wire payload")
	}
	if len(rest) == 0 {
		return "", nil, "", errors.New("host key payload is incomplete")
	}
	return fields[0], decoded, sshFingerprint(decoded), nil
}

func marshalOpenSSHPrivateKey(targetComment string, seed []byte) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("invalid ed25519 seed")
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	publicBlob := sshPublicBlob(publicKey)

	var checkBytes [4]byte
	if _, err := rand.Read(checkBytes[:]); err != nil {
		return nil, fmt.Errorf("generate openssh private key check value: %w", err)
	}
	check := binary.BigEndian.Uint32(checkBytes[:])

	var private bytes.Buffer
	_ = binary.Write(&private, binary.BigEndian, check)
	_ = binary.Write(&private, binary.BigEndian, check)
	writeSSHString(&private, []byte(sshEd25519))
	writeSSHString(&private, publicKey)
	writeSSHString(&private, privateKey)
	writeSSHString(&private, []byte(targetComment))
	for padding := byte(1); private.Len()%8 != 0; padding++ {
		private.WriteByte(padding)
	}

	var payload bytes.Buffer
	payload.WriteString("openssh-key-v1\x00")
	writeSSHString(&payload, []byte("none"))
	writeSSHString(&payload, []byte("none"))
	writeSSHString(&payload, nil)
	_ = binary.Write(&payload, binary.BigEndian, uint32(1))
	writeSSHString(&payload, publicBlob)
	writeSSHString(&payload, private.Bytes())

	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: payload.Bytes()}), nil
}

func writeSSHString(out *bytes.Buffer, value []byte) {
	_ = binary.Write(out, binary.BigEndian, uint32(len(value)))
	_, _ = out.Write(value)
}

func readSSHString(value []byte) ([]byte, []byte, error) {
	if len(value) < 4 {
		return nil, nil, errors.New("invalid ssh wire string")
	}
	length := int(binary.BigEndian.Uint32(value[:4]))
	if length < 0 || len(value) < 4+length {
		return nil, nil, errors.New("invalid ssh wire string length")
	}
	return value[4 : 4+length], value[4+length:], nil
}
