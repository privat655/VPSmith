package modulecontract

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"go.yaml.in/yaml/v3"
)

func (Compiler) Compile(pkg Package) (Module, error) {
	if pkg.FS == nil {
		return Module{}, errors.New("module package filesystem is required")
	}
	rawBytes, err := fs.ReadFile(pkg.FS, "module.yaml")
	if err != nil {
		return Module{}, fmt.Errorf("read module.yaml: %w", err)
	}
	if bytes.Contains(rawBytes, []byte{0}) {
		return Module{}, errors.New("module.yaml contains NUL byte")
	}
	dec := yaml.NewDecoder(bytes.NewReader(rawBytes))
	dec.KnownFields(true)
	var raw rawModule
	if err := dec.Decode(&raw); err != nil {
		return Module{}, fmt.Errorf("decode module.yaml: %w", err)
	}
	var extra any
	err = dec.Decode(&extra)
	if err == nil {
		return Module{}, errors.New("module.yaml must contain exactly one YAML document")
	}
	if !errors.Is(err, io.EOF) {
		return Module{}, fmt.Errorf("decode trailing module.yaml document: %w", err)
	}

	m := Module{
		ID: raw.ModuleID, Version: raw.ModuleVersion, CoreContract: raw.CoreContract,
		Images: raw.Images, Containers: raw.Containers, Persistent: raw.Persistent,
		Secrets: raw.Secrets, Resources: raw.Resources, Networks: raw.Networks,
		Egress: raw.Egress, PublicRoutes: raw.PublicRoutes, Healthcheck: raw.Healthcheck,
		ServiceChecks: raw.ServiceChecks, ValidationAction: raw.ValidationAction,
		Interfaces: raw.Interfaces, Dependencies: raw.Dependencies, Actions: raw.Actions,
		UpdateFrom: raw.UpdateFrom, Uninstall: raw.Uninstall, ActionFiles: map[string][]byte{},
	}
	if err := validate(&m); err != nil {
		return Module{}, err
	}
	for id, rel := range m.Actions {
		content, err := fs.ReadFile(pkg.FS, rel)
		if err != nil {
			return Module{}, fmt.Errorf("action %s: read %s: %w", id, rel, err)
		}
		m.ActionFiles[id] = append([]byte(nil), content...)
	}
	normalize(&m)
	return m, nil
}
