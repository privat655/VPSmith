package targetrunner

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"sort"
)

const (
	Version = "1"
	Path    = "runtime/runner.py"
)

//go:embed parts/*.inc
var parts embed.FS

func Bytes() []byte {
	names := make([]string, 0, 8)
	_ = fs.WalkDir(parts, "parts", func(path string, entry fs.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			names = append(names, path)
		}
		return err
	})
	sort.Strings(names)
	var out []byte
	for _, name := range names {
		data, err := parts.ReadFile(name)
		if err != nil {
			panic(err)
		}
		out = append(out, data...)
	}
	return out
}

func SHA256() string {
	sum := sha256.Sum256(Bytes())
	return hex.EncodeToString(sum[:])
}
