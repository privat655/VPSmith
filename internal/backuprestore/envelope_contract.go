package backuprestore

import (
	"errors"
	"sort"
	"strings"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func validateCreateRequest(request CreateRequest) error {
	if request.TargetID == "" {
		return errors.New("backup target id is required")
	}
	if request.Producer == nil {
		return errors.New("backup payload producer is required")
	}
	switch request.Type {
	case managementstate.BackupRecoveryPackage, managementstate.BackupCore:
		if request.ModuleInstanceID != "" {
			return errors.New("non-module backup must not carry module instance id")
		}
		if len(request.Passphrase) == 0 {
			return errors.New("recovery passphrase is required")
		}
	case managementstate.BackupModule:
		if request.ModuleInstanceID == "" {
			return errors.New("module backup requires module instance id")
		}
		if len(request.Passphrase) == 0 {
			return errors.New("recovery passphrase is required")
		}
	case managementstate.BackupSystemRestorePoint:
		if request.ModuleInstanceID == "" {
			return errors.New("system restore point requires module instance id")
		}
		if len(request.Passphrase) != 0 {
			return errors.New("system restore point is not a long-term encrypted backup")
		}
	default:
		return errors.New("unknown backup artifact type")
	}
	return nil
}

func isLongTermType(value managementstate.BackupArtifactType) bool {
	switch value {
	case managementstate.BackupRecoveryPackage, managementstate.BackupCore, managementstate.BackupModule:
		return true
	default:
		return false
	}
}

func sortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
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

func inventory(entries []archiveEntry) []PayloadItem {
	out := make([]PayloadItem, 0, len(entries))
	for _, entry := range entries {
		kind := "unknown"
		switch entry.Type {
		case 0, '0':
			kind = "file"
		case '5':
			kind = "directory"
		case '2':
			kind = "symlink"
		case '1':
			kind = "hardlink"
		}
		out = append(out, PayloadItem{Path: entry.Name, Kind: kind, LinkName: entry.LinkName})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func sameInventory(left, right []PayloadItem) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
