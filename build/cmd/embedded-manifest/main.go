package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/privat655/VPSmith/internal/releaseinfo"
)

func main() {
	root := flag.String("root", "embedded", "embedded source root")
	manifest := flag.String("manifest", "embedded/manifest.json", "release manifest path")
	write := flag.Bool("write", false, "update the manifest atomically")
	check := flag.Bool("check", false, "fail if the manifest is not current")
	flag.Parse()
	if *write == *check {
		fatalf("choose exactly one of -write or -check")
	}

	data, err := os.ReadFile(*manifest)
	if err != nil {
		fatalf("read manifest: %v", err)
	}
	var info releaseinfo.Info
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&info); err != nil {
		fatalf("decode manifest: %v", err)
	}

	updated, err := releaseinfo.Refresh(*root, info)
	if err != nil {
		fatalf("refresh embedded identities: %v", err)
	}
	encoded, err := json.MarshalIndent(updated, "", "  ")
	if err != nil {
		fatalf("encode manifest: %v", err)
	}
	encoded = append(encoded, '\n')

	if *check {
		if !bytes.Equal(data, encoded) {
			fatalf("%s is stale; run build/update-embedded-manifest.sh; expected:\n%s", *manifest, encoded)
		}
		if _, err := releaseinfo.Load(*root); err != nil {
			fatalf("verify manifest: %v", err)
		}
		return
	}

	temporary, err := os.CreateTemp(filepath.Dir(*manifest), ".manifest-*.json")
	if err != nil {
		fatalf("create temporary manifest: %v", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if _, err := temporary.Write(encoded); err != nil {
		fatalf("write temporary manifest: %v", err)
	}
	if err := temporary.Chmod(0o644); err != nil {
		fatalf("chmod temporary manifest: %v", err)
	}
	if err := temporary.Close(); err != nil {
		fatalf("close temporary manifest: %v", err)
	}
	if err := os.Rename(temporaryName, *manifest); err != nil {
		fatalf("replace manifest: %v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
