package targetgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/privat655/VPSmith/internal/managementstate"
)

const (
	coreInventoryPath   = "/var/lib/vpsmith/core/current/inventory.json"
	moduleInventoryPath = "/var/lib/vpsmith/modules/inventory.json"
	cloudInitStatusPath = "/var/lib/vpsmith/cloud-init/status"
)

type targetFacts struct {
	Hostname         string
	Kernel           string
	OSRelease        map[string]string
	Swap             managementstate.SwapObservedState
	RootPasswordLock bool
	SSHConfigValid   bool
	SSHValues        map[string]string
	UFW              managementstate.PrimaryHardeningObservedState
	Fail2ban         managementstate.PrimaryHardeningObservedState
	Updates          managementstate.PrimaryHardeningObservedState
}

func inspectTarget(ctx context.Context, transport transport, sess session) (managementstate.ObservedState, error) {
	facts, err := transport.Inspect(ctx, sess)
	if err != nil {
		return managementstate.ObservedState{}, err
	}
	managementstate.NormalizeObservedState(&facts)
	return facts, nil
}

func parseKeyValueDocument(data []byte) map[string]string {
	result := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		result[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return result
}

func parseCloudInitStatus(data []byte) (managementstate.CloudInitObservedState, error) {
	values := parseKeyValueDocument(data)
	if len(values) == 0 {
		return managementstate.CloudInitObservedState{}, errors.New("cloud-init status is empty")
	}
	return managementstate.CloudInitObservedState{
		Present:    true,
		Status:     values["status"],
		Version:    values["version"],
		FinishedAt: values["finished_at"],
	}, nil
}

func parseSwapBytes(data []byte) (managementstate.SwapObservedState, error) {
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return managementstate.SwapObservedState{}, errors.New("swap total is empty")
	}
	value, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return managementstate.SwapObservedState{}, fmt.Errorf("parse swap total: %w", err)
	}
	return managementstate.SwapObservedState{TotalBytes: value}, nil
}

func parseJSON[T any](data []byte, out *T) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func sortedUnique(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func readAllLimited(reader io.Reader, limit int64) ([]byte, error) {
	limited := io.LimitReader(reader, limit+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("inspection response exceeds size limit")
	}
	return data, nil
}

func scanLines(data []byte) ([]string, error) {
	var result []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			result = append(result, line)
		}
	}
	return result, scanner.Err()
}

type unitRef struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
}

type caddyRef struct {
	Unit       unitRef `json:"unit"`
	Container  string  `json:"container"`
	ConfigPath string  `json:"config_path"`
}

type serviceRef struct {
	Unit      unitRef `json:"unit"`
	Container string  `json:"container"`
}

type coreInventory struct {
	SourceID         managementstate.SourceSnapshotID              `json:"source_id"`
	Version          string                                        `json:"version"`
	PackageSHA256    string                                        `json:"package_sha256"`
	Units            []unitRef                                     `json:"units"`
	Containers       []string                                      `json:"containers"`
	Networks         []string                                      `json:"networks"`
	Caddy            *caddyRef                                     `json:"caddy,omitempty"`
	Authelia         *serviceRef                                   `json:"authelia,omitempty"`
	ManagedArtifacts []string                                      `json:"managed_artifacts"`
	ExecutionProofs  []managementstate.ExecutionProofObservedState `json:"execution_proofs"`
}

type moduleInventoryDocument struct {
	Modules []moduleInventory `json:"modules"`
}

type moduleInventory struct {
	InstanceID       managementstate.ModuleInstanceID `json:"instance_id"`
	PackageID        managementstate.ModulePackageID  `json:"package_id"`
	Version          string                           `json:"version"`
	PackageSHA256    string                           `json:"package_sha256"`
	Units            []unitRef                        `json:"units"`
	Containers       []string                         `json:"containers"`
	Networks         []string                         `json:"networks"`
	ManagedArtifacts []string                         `json:"managed_artifacts"`
}
