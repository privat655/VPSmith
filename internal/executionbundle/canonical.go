package executionbundle

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

func canonicalJSON(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		return nil, err
	}
	return compact.Bytes(), nil
}

func checksumDocument(files []File) []byte {
	copyFiles := append([]File(nil), files...)
	sort.Slice(copyFiles, func(i, j int) bool { return copyFiles[i].Path < copyFiles[j].Path })
	var b strings.Builder
	for _, f := range copyFiles {
		s := sha256.Sum256(f.Data)
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(s[:]), f.Path)
	}
	return []byte(b.String())
}

func deterministicTar(files []File) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	epoch := time.Unix(0, 0).UTC()
	for _, f := range files {
		h := &tar.Header{
			Name: f.Path, Mode: f.Mode, Size: int64(len(f.Data)),
			ModTime: epoch, AccessTime: epoch, ChangeTime: epoch,
			Uid: 0, Gid: 0, Uname: "", Gname: "", Format: tar.FormatPAX,
		}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if _, err := io.Copy(tw, bytes.NewReader(f.Data)); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
