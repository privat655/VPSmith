package targetgateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/privat655/VPSmith/internal/managementstate"
)

const maxHealthcheckCapture = 16 * 1024

type healthcheckRef struct {
	Type      string   `json:"type"`
	Container string   `json:"container"`
	URL       string   `json:"url,omitempty"`
	Port      int      `json:"port,omitempty"`
	Command   []string `json:"command,omitempty"`
}

type runtimeModuleInventoryDocument struct {
	Modules []runtimeModuleInventory `json:"modules"`
}

type runtimeModuleInventory struct {
	InstanceID  managementstate.ModuleInstanceID `json:"instance_id"`
	Units       []unitRef                        `json:"units"`
	Containers  []string                         `json:"containers"`
	Healthcheck healthcheckRef                   `json:"healthcheck"`
}

func (t *sshTransport) ControlModuleRuntime(ctx context.Context, sess session, moduleID managementstate.ModuleInstanceID, action RuntimeAction) (RuntimeResult, error) {
	inventory, err := t.moduleRuntimeInventory(ctx, sess, moduleID)
	if err != nil {
		return RuntimeResult{}, err
	}
	if len(inventory.Units) == 0 {
		return RuntimeResult{}, fmt.Errorf("module %s has no inventoried runtime units", moduleID)
	}
	units := append([]unitRef(nil), inventory.Units...)
	commands := make([]string, 0, len(units)*2)
	appendUnits := func(verb string, values []unitRef) error {
		for _, ref := range values {
			command, err := runtimeUnitCommand(ref, verb)
			if err != nil {
				return err
			}
			commands = append(commands, command)
		}
		return nil
	}
	switch action {
	case RuntimeStart:
		if err := appendUnits("start", units); err != nil {
			return RuntimeResult{}, err
		}
	case RuntimeStop:
		reverseUnits(units)
		if err := appendUnits("stop", units); err != nil {
			return RuntimeResult{}, err
		}
	case RuntimeRestart:
		stop := append([]unitRef(nil), units...)
		reverseUnits(stop)
		if err := appendUnits("stop", stop); err != nil {
			return RuntimeResult{}, err
		}
		if err := appendUnits("start", units); err != nil {
			return RuntimeResult{}, err
		}
	default:
		return RuntimeResult{}, errors.New("unsupported runtime action")
	}
	if _, err := t.runRemote(ctx, sess, "set -eu; "+strings.Join(commands, "; ")); err != nil {
		return RuntimeResult{}, fmt.Errorf("%s module %s: %w", action, moduleID, err)
	}
	resultUnits := make([]string, 0, len(inventory.Units))
	for _, ref := range inventory.Units {
		resultUnits = append(resultUnits, ref.Name)
	}
	return RuntimeResult{ModuleInstanceID: moduleID, Action: action, Units: resultUnits}, nil
}

func (t *sshTransport) HealthcheckModule(ctx context.Context, sess session, moduleID managementstate.ModuleInstanceID) (HealthcheckResult, error) {
	inventory, err := t.moduleRuntimeInventory(ctx, sess, moduleID)
	if err != nil {
		return HealthcheckResult{}, err
	}
	check := inventory.Healthcheck
	if err := validateHealthcheckRef(check); err != nil {
		return HealthcheckResult{}, fmt.Errorf("module %s inventory healthcheck: %w", moduleID, err)
	}
	container := "vpsmith-" + string(moduleID) + "-" + check.Container
	if !safeObjectName(container) || !containsString(inventory.Containers, container) {
		return HealthcheckResult{}, errors.New("module healthcheck container is not present in inventory")
	}
	command, err := healthcheckCommand(check, container)
	if err != nil {
		return HealthcheckResult{}, err
	}
	stdout, err := t.runRemote(ctx, sess, boundedHealthcheckScript(command))
	if err != nil {
		return HealthcheckResult{}, fmt.Errorf("run module healthcheck: %w", err)
	}
	code, out, stderr, err := parseHealthcheckOutput(stdout)
	if err != nil {
		return HealthcheckResult{}, err
	}
	return HealthcheckResult{
		ModuleInstanceID: moduleID,
		Type:             check.Type,
		Container:        container,
		Healthy:          code == 0,
		ExitCode:         code,
		Stdout:           out,
		Stderr:           stderr,
	}, nil
}

func (t *sshTransport) moduleRuntimeInventory(ctx context.Context, sess session, moduleID managementstate.ModuleInstanceID) (runtimeModuleInventory, error) {
	raw, err := t.readOptional(ctx, sess, moduleInventoryPath)
	if err != nil {
		return runtimeModuleInventory{}, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return runtimeModuleInventory{}, errors.New("module inventory is missing")
	}
	var document runtimeModuleInventoryDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return runtimeModuleInventory{}, fmt.Errorf("decode module inventory: %w", err)
	}
	for _, inventory := range document.Modules {
		if inventory.InstanceID == moduleID {
			return inventory, nil
		}
	}
	return runtimeModuleInventory{}, fmt.Errorf("module %s is not present in target inventory", moduleID)
}

func runtimeUnitCommand(ref unitRef, verb string) (string, error) {
	if !safeObjectName(ref.Name) {
		return "", errors.New("module inventory contains invalid unit name")
	}
	if verb != "start" && verb != "stop" {
		return "", errors.New("unsupported systemd runtime verb")
	}
	switch ref.Scope {
	case "", "user":
		return "systemctl --user " + verb + " " + shellQuote(ref.Name), nil
	case "system":
		return "sudo -n systemctl " + verb + " " + shellQuote(ref.Name), nil
	default:
		return "", errors.New("module inventory contains invalid unit scope")
	}
}

func reverseUnits(values []unitRef) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func validateHealthcheckRef(check healthcheckRef) error {
	if !safeObjectName(check.Container) {
		return errors.New("invalid container id")
	}
	switch check.Type {
	case "http":
		parsed, err := url.Parse(check.URL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return errors.New("invalid http healthcheck url")
		}
	case "tcp":
		if check.Port < 1 || check.Port > 65535 {
			return errors.New("invalid tcp healthcheck port")
		}
	case "command":
		if len(check.Command) == 0 || strings.TrimSpace(check.Command[0]) == "" {
			return errors.New("invalid command healthcheck")
		}
		for _, arg := range check.Command {
			if strings.ContainsRune(arg, '\x00') {
				return errors.New("command healthcheck contains NUL")
			}
		}
	default:
		return errors.New("unsupported healthcheck type")
	}
	return nil
}

func healthcheckCommand(check healthcheckRef, container string) (string, error) {
	switch check.Type {
	case "command":
		parts := []string{"podman", "exec", "--", shellQuote(container)}
		for _, arg := range check.Command {
			parts = append(parts, shellQuote(arg))
		}
		return strings.Join(parts, " "), nil
	case "http":
		probe := `import sys,urllib.request; r=urllib.request.urlopen(sys.argv[1],timeout=5); sys.stdout.write(str(r.status)); r.close()`
		return networkNamespaceCommand(container, probe, check.URL), nil
	case "tcp":
		probe := `import socket,sys; s=socket.create_connection(("127.0.0.1",int(sys.argv[1])),timeout=5); s.close()`
		return networkNamespaceCommand(container, probe, strconv.Itoa(check.Port)), nil
	default:
		return "", errors.New("unsupported healthcheck type")
	}
}

func networkNamespaceCommand(container, python, argument string) string {
	return "pid=$(podman inspect --format '{{.State.Pid}}' " + shellQuote(container) + "); " +
		"case $pid in ''|*[!0-9]*) exit 97;; esac; [ \"$pid\" -gt 0 ] || exit 97; " +
		"sudo -n nsenter -t \"$pid\" -n -- python3 -c " + shellQuote(python) + " " + shellQuote(argument)
}

func boundedHealthcheckScript(command string) string {
	return `set -eu
umask 077
out=$(mktemp)
err=$(mktemp)
cleanup() { rm -f -- "$out" "$err"; }
trap cleanup EXIT HUP INT TERM
set +e
timeout 10s sh -c ` + shellQuote(command) + ` >"$out" 2>"$err"
code=$?
set -e
printf 'CODE\t%s\n' "$code"
printf 'STDOUT\t'; head -c ` + strconv.Itoa(maxHealthcheckCapture) + ` "$out" | base64 | tr -d '\n'; printf '\n'
printf 'STDERR\t'; head -c ` + strconv.Itoa(maxHealthcheckCapture) + ` "$err" | base64 | tr -d '\n'; printf '\n'`
}

func parseHealthcheckOutput(raw []byte) (int, string, string, error) {
	values, err := parseTabFacts(raw)
	if err != nil {
		return 0, "", "", err
	}
	if len(values) != 3 || values["CODE"] == "" {
		return 0, "", "", errors.New("incomplete healthcheck result")
	}
	code, err := strconv.Atoi(values["CODE"])
	if err != nil || code < 0 || code > 255 {
		return 0, "", "", errors.New("invalid healthcheck exit code")
	}
	decode := func(name string) (string, error) {
		data, err := base64.StdEncoding.DecodeString(values[name])
		if err != nil {
			return "", fmt.Errorf("decode healthcheck %s: %w", strings.ToLower(name), err)
		}
		return string(data), nil
	}
	out, err := decode("STDOUT")
	if err != nil {
		return 0, "", "", err
	}
	stderr, err := decode("STDERR")
	if err != nil {
		return 0, "", "", err
	}
	return code, out, stderr, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
