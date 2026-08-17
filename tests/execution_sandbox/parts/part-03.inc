r)
		}
		if _, err := controller.Control(ctx, sandboxTargetID, "sandbox", targetgateway.RuntimeStart); err != nil {
			t.Fatal(err)
		}
		health, err := controller.Healthcheck(ctx, sandboxTargetID, "sandbox")
		if err != nil || !health.Healthy || !strings.Contains(health.Stdout, "healthy") {
			t.Fatalf("health=%#v err=%v", health, err)
		}
		if _, err := controller.Control(ctx, sandboxTargetID, "sandbox", targetgateway.RuntimeRestart); err != nil {
			t.Fatal(err)
		}
		if _, err := controller.Control(ctx, sandboxTargetID, "sandbox", targetgateway.RuntimeStop); err != nil {
			t.Fatal(err)
		}
		health, err = controller.Healthcheck(ctx, sandboxTargetID, "sandbox")
		if err != nil {
			t.Fatal(err)
		}
		if health.Healthy {
			t.Fatalf("stopped module reported healthy: %#v", health)
		}
		if _, err := controller.Control(ctx, sandboxTargetID, "sandbox", targetgateway.RuntimeAction("shell")); err == nil {
			t.Fatal("arbitrary runtime action accepted")
		}
	})
}

func actionBundle(identity, actionID, script string, following []executionbundle.Step) executionbundle.Input {
	steps := []executionbundle.Step{{ID: "action:" + actionID, Kind: "action", Action: actionID, Mutating: true}}
	steps = append(steps, following...)
	return executionbundle.Input{
		Kind: executionbundle.Migration, TargetID: string(sandboxTargetID), SubjectKind: "core", SubjectID: "core", SubjectIdentity: identity, Version: "1.0.0",
		Actions: []executionbundle.File{{Path: "actions/" + actionID + ".sh", Mode: 0o555, Data: []byte(script)}}, ActionIDs: []string{actionID},
		Preconditions: []executionbundle.Precondition{{Kind: "target", Subject: string(sandboxTargetID), Expected: "same-target"}}, ExpectedPost: map[string]any{"artifacts": map[string]string{}}, Steps: steps,
	}
}

func assemble(t *testing.T, a *executionbundle.Assembler, in executionbundle.Input) executionbundle.Bundle {
	t.Helper()
	b, err := a.Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func executor(t *testing.T, target execution.Target, history *executionstate.Adapter, id string) *execution.Executor {
	t.Helper()
	e, err := execution.New(target, history, history, execution.Options{PollInterval: 50 * time.Millisecond, NewRunID: func() (string, error) { return id, nil }})
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func waitObservation(t *testing.T, target execution.Target, runID string, ok func(execution.Observation) bool) execution.Observation {
	t.Helper()
	var last execution.Observation
	waitCommand(t, 30*time.Second, func() bool {
		o, err := target.Observe(context.Background(), string(sandboxTargetID), runID)
		if err != nil {
			return false
		}
		last = o
		return ok(o)
	}, "execution observation did not reach expected state")
	return last
}

func waitTCP(t *testing.T, address string) {
	t.Helper()
	waitCommand(t, 20*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}, "sandbox ssh port did not open")
}
func waitCommand(t *testing.T, timeout time.Duration, fn func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal(message)
}
func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}
func dockerInput(t *testing.T, cid string, input []byte, args ...string) {
	t.Helper()
	all := append([]string{"exec", "-i", cid}, args...)
	cmd := exec.Command("docker", all...)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %v: %v\n%s", all, err, out)
	}
}
func dockerRead(t *testing.T, cid, path string) string {
	t.Helper()
	return run(t, "docker", "exec", cid, "cat", path)
}
func dockerExists(t *testing.T, cid, path string) bool {
	t.Helper()
	return exec.Command("docker", "exec", cid, "test", "-e", path).Run() == nil