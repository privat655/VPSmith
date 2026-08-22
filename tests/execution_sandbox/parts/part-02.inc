locked, err := executor(t, target, history, "run_lock_2").Execute(ctx, string(sandboxTargetID), second)
		if err == nil || blocked.Status != execution.StatusFailed {
			t.Fatalf("concurrent run status=%s err=%v", blocked.Status, err)
		}
		if dockerExists(t, cid, secondPath) {
			t.Fatal("concurrent blocked run mutated target")
		}
		wg.Wait()
		if firstErr != nil || first.Status != execution.StatusSuccess {
			t.Fatalf("first structural run status=%s err=%v", first.Status, firstErr)
		}
	})

	t.Run("action-failure-stops-following-step-and-reports-bounded-redacted-output", func(t *testing.T) {
		path := "/var/tmp/vpsmith-sandbox/after-failure-must-not-exist"
		data := []byte("late\n")
		secretValue := []byte(fmt.Sprintf("sandbox-redaction-marker-%d", time.Now().UnixNano()))
		var secretID managementstate.SecretID
		if err := store.Change(ctx, func(change *managementstate.Change) error {
			id, err := change.CreateSecret("execution sandbox action output", managementstate.SecretSystem)
			if err != nil {
				return err
			}
			if err := change.SetSecret(id, secretValue); err != nil {
				return err
			}
			secretID = id
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		secretPath := "/var/lib/vpsmith/secrets/core/" + string(secretID) + ".env"
		script := fmt.Sprintf(`#!/bin/sh
set -eu
printf 'useful-stdout\n'
sudo -n cat %s
head -c 65536 /dev/zero | tr '\000' O
printf 'useful-stderr\n' >&2
sudo -n cat %s >&2
head -c 65536 /dev/zero | tr '\000' E >&2
exit 7
`, secretPath, secretPath)
		in := actionBundle("fail-action", "fail-action", script, []executionbundle.Step{{ID: "apply:late", Kind: "apply-artifact", Artifact: "artifacts/late.txt", Mutating: true}})
		in.Secrets = []executionbundle.SecretReference{{SecretID: string(secretID), Container: "core/action", Delivery: "environment", Target: "SANDBOX_MARKER"}}
		in.Files = []executionbundle.File{{Path: "artifacts/late.txt", TargetPath: path, Mode: 0o644, Data: data}}
		in.ExpectedPost = map[string]any{"artifacts": map[string]string{path: digest(data)}}
		bundle := assemble(t, assembler, in)
		r, err := executor(t, target, history, "run_failure").Execute(ctx, string(sandboxTargetID), bundle)
		if err == nil || r.Status != execution.StatusFailed {
			t.Fatalf("failure run status=%s err=%v", r.Status, err)
		}
		if !strings.Contains(err.Error(), "useful-stdout") || !strings.Contains(err.Error(), "useful-stderr") {
			t.Fatalf("failure error lost action output: %v", err)
		}
		if strings.Contains(err.Error(), string(secretValue)) {
			t.Fatal("failure error leaked action secret")
		}
		obs, observeErr := target.Observe(ctx, string(sandboxTargetID), "run_failure")
		if observeErr != nil || obs.Proof == nil || len(obs.Proof.Steps) == 0 {
			t.Fatalf("failure proof=%#v err=%v", obs.Proof, observeErr)
		}
		step := obs.Proof.Steps[0]
		if step.ExitCode != 7 || !strings.Contains(step.Stdout, "useful-stdout") || !strings.Contains(step.Stderr, "useful-stderr") {
			t.Fatalf("failure step=%#v", step)
		}
		for name, output := range map[string]string{"stdout": step.Stdout, "stderr": step.Stderr, "proof error": obs.Proof.Error} {
			if strings.Contains(output, string(secretValue)) {
				t.Fatalf("%s leaked action secret", name)
			}
			if !strings.Contains(output, "[REDACTED]") {
				t.Fatalf("%s did not preserve redaction evidence: %q", name, output)
			}
		}
		const maxCapture = 16 * 1024
		maxBounded := maxCapture + len("\n[TRUNCATED]")
		if len(step.Stdout) > maxBounded || len(step.Stderr) > maxBounded || len(obs.Proof.Error) > maxBounded {
			t.Fatalf("failure output is not bounded: stdout=%d stderr=%d error=%d", len(step.Stdout), len(step.Stderr), len(obs.Proof.Error))
		}
		if !strings.Contains(step.Stdout, "[TRUNCATED]") || !strings.Contains(step.Stderr, "[TRUNCATED]") {
			t.Fatalf("large action output was not deterministically truncated: stdout=%d stderr=%d", len(step.Stdout), len(step.Stderr))
		}
		if dockerExists(t, cid, path) {
			t.Fatal("step after action failure executed")
		}
	})

	t.Run("successful-action-output-and-status-are-unchanged", func(t *testing.T) {
		bundle := assemble(t, assembler, actionBundle("success-action", "success-action", "#!/bin/sh\nprintf 'success-stdout\\n'\nprintf 'success-stderr\\n' >&2\n", nil))
		r, err := executor(t, target, history, "run_success_action").Execute(ctx, string(sandboxTargetID), bundle)
		if err != nil || r.Status != execution.StatusSuccess {
			t.Fatalf("success action status=%s err=%v", r.Status, err)
		}
		obs, err := target.Observe(ctx, string(sandboxTargetID), "run_success_action")
		if err != nil || obs.Proof == nil || len(obs.Proof.Steps) == 0 {
			t.Fatalf("success proof=%#v err=%v", obs.Proof, err)
		}
		step := obs.Proof.Steps[0]
		if step.ExitCode != 0 || step.Stdout != "success-stdout\n" || step.Stderr != "success-stderr\n" {
			t.Fatalf("success step=%#v", step)
		}
	})

	t.Run("disconnect-reconciles-without-double-apply", func(t *testing.T) {
		counter := "/var/tmp/vpsmith-disconnect-counter"
		bundle := assemble(t, assembler, actionBundle("disconnect", "disconnect", "#!/bin/sh\nset -eu\nprintf x >> /var/tmp/vpsmith-disconnect-counter\nsleep 4\n", nil))
		runCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		var started execution.Run
		var startErr error
		go func() {
			started, startErr = executor(t, target, history, "run_disconnect").Execute(runCtx, string(sandboxTargetID), bundle)
			close(done)
		}()
		waitObservation(t, target, "run_disconnect", func(o execution.Observation) bool { return o.Proof != nil && o.Proof.Phase == "steps" })
		cancel()
		<-done
		if !errors.Is(startErr, execution.ErrStatusUnknown) || started.Status != execution.StatusUnknown {
			t.Fatalf("disconnect status=%s err=%v", started.Status, startErr)
		}
		var reconciled execution.Run
		waitCommand(t, 15*time.Second, func() bool {
			var err error
			reconciled, err = executor(t, target, history, "unused").Reconcile(context.Background(), string(sandboxTargetID), "run_disconnect", bundle.ID, bundle.SHA256)
			return err == nil && reconciled.Status == execution.StatusSuccess
		}, "disconnected execution did not reconcile to success")
		if got := dockerRead(t, cid, counter); got != "x" {
			t.Fatalf("disconnect action applied %d times: %q", len(got), got)
		}
		snapshot, err := store.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, record := range snapshot.ExecutionRecords {
			if record.ID == "run_disconnect" && record.Outcome == "success" {
				found = true
			}
		}
		if !found {
			t.Fatal("reconciled target proof was not imported into local history")
		}
	})

	t.Run("direct-runtime-control-and-healthcheck-are-inventory-bound", func(t *testing.T) {
		inventory := `{"modules":[{"instance_id":"sandbox","units":[{"name":"vpsmith-sandbox-app.service","scope":"system"}],"containers":["vpsmith-sandbox-app"],"healthcheck":{"type":"command","container":"app","command":["sh","-c","test -f /run/vpsmith-sandbox-app.active && printf healthy"]}}]}` + "\n"
		dockerInput(t, cid, []byte(inventory), "sh", "-c", "install -d -m 0755 /var/lib/vpsmith/inventory && cat >/var/lib/vpsmith/inventory/modules.json")
		controller, err := targetgateway.NewRuntimeController(gateway)
		if err != nil {
			t.Fatal(er