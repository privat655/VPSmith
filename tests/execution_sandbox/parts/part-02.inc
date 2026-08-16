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

	t.Run("action-failure-stops-following-step", func(t *testing.T) {
		path := "/var/tmp/vpsmith-sandbox/after-failure-must-not-exist"
		data := []byte("late\n")
		in := actionBundle("fail-action", "fail-action", "#!/bin/sh\necho action-failed >&2\nexit 7\n", []executionbundle.Step{{ID: "apply:late", Kind: "apply-artifact", Artifact: "artifacts/late.txt", Mutating: true}})
		in.Files = []executionbundle.File{{Path: "artifacts/late.txt", TargetPath: path, Mode: 0o644, Data: data}}
		in.ExpectedPost = map[string]any{"artifacts": map[string]string{path: digest(data)}}
		bundle := assemble(t, assembler, in)
		r, err := executor(t, target, history, "run_failure").Execute(ctx, string(sandboxTargetID), bundle)
		if err == nil || r.Status != execution.StatusFailed {
			t.Fatalf("failure run status=%s err=%v", r.Status, err)
		}
		obs, err := target.Observe(ctx, string(sandboxTargetID), "run_failure")
		if err != nil || obs.Proof == nil || len(obs.Proof.Steps) == 0 {
			t.Fatalf("failure proof=%#v err=%v", obs.Proof, err)
		}
		if obs.Proof.Steps[0].ExitCode != 7 || !strings.Contains(obs.Proof.Steps[0].Stderr, "action-failed") {
			t.Fatalf("failure step=%#v", obs.Proof.Steps[0])
		}
		if dockerExists(t, cid, path) {
			t.Fatal("step after action failure executed")
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