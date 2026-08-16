t := dockerRead(t, cid, path); got != string(data) {
			t.Fatalf("managed artifact=%q", got)
		}
		run(t, "docker", "exec", cid, "test", "-f", "/var/lib/vpsmith/execution/.active")
		run(t, "docker", "exec", cid, "test", "-f", "/var/lib/vpsmith/execution/bundles/"+bundle.ID+".tar")
		run(t, "docker", "exec", cid, "test", "-f", "/var/lib/vpsmith/execution/proofs/run_core_1.json")
	})

	t.Run("validation-is-repeatable-and-read-only", func(t *testing.T) {
		path := "/var/tmp/vpsmith-sandbox/managed.txt"
		expected := digest([]byte("core-v1\n"))
		bundle := assemble(t, assembler, executionbundle.Input{
			Kind: executionbundle.Validation, TargetID: string(sandboxTargetID), SubjectKind: "core", SubjectID: "core", SubjectIdentity: "core-v1", Version: "1.0.0",
			Preconditions: []executionbundle.Precondition{{Kind: "target", Subject: string(sandboxTargetID), Expected: "same-target"}, {Kind: "artifact-sha256", Subject: path, Expected: expected}},
			ExpectedPost:  map[string]any{"artifacts": map[string]string{path: expected}},
		})
		for _, id := range []string{"run_validate_1", "run_validate_2"} {
			r, err := executor(t, target, history, id).Execute(ctx, string(sandboxTargetID), bundle)
			if err != nil || r.Status != execution.StatusSuccess {
				t.Fatalf("validation %s status=%s err=%v", id, r.Status, err)
			}
		}
	})

	t.Run("tampered-upload-is-rejected-before-runner", func(t *testing.T) {
		path := "/var/tmp/vpsmith-sandbox/tamper-must-not-exist"
		data := []byte("never\n")
		bundle := assemble(t, assembler, executionbundle.Input{
			Kind: executionbundle.Migration, TargetID: string(sandboxTargetID), SubjectKind: "core", SubjectID: "core", SubjectIdentity: "core-v2", Version: "1.0.1",
			Files:         []executionbundle.File{{Path: "artifacts/tamper.txt", TargetPath: path, Mode: 0o644, Data: data}},
			Preconditions: []executionbundle.Precondition{{Kind: "target", Subject: string(sandboxTargetID), Expected: "same-target"}},
			ExpectedPost:  map[string]any{"artifacts": map[string]string{path: digest(data)}},
			Steps:         []executionbundle.Step{{ID: "apply:tamper", Kind: "apply-artifact", Artifact: "artifacts/tamper.txt", Mutating: true}},
		})
		if err := target.Upload(ctx, string(sandboxTargetID), bundle); err != nil {
			t.Fatal(err)
		}
		run(t, "docker", "exec", cid, "sh", "-c", "printf x >> /var/lib/vpsmith/execution/bundles/"+bundle.ID+".tar")
		err := target.Start(ctx, string(sandboxTargetID), execution.StartRequest{RunID: "run_tamper", BundleID: bundle.ID, BundleSHA256: bundle.SHA256, TargetID: string(sandboxTargetID), Runner: bundle.Manifest.Runner})
		if err == nil {
			t.Fatal("tampered remote bundle was started")
		}
		if dockerExists(t, cid, path) {
			t.Fatal("tampered bundle mutated target")
		}
	})

	t.Run("structural-lock-blocks-concurrent-run", func(t *testing.T) {
		long := assemble(t, assembler, actionBundle("lock-long", "run-long", "#!/bin/sh\nset -eu\nsleep 4\n", nil))
		secondPath := "/var/tmp/vpsmith-sandbox/concurrent-must-not-exist"
		secondData := []byte("blocked\n")
		second := assemble(t, assembler, executionbundle.Input{
			Kind: executionbundle.Migration, TargetID: string(sandboxTargetID), SubjectKind: "core", SubjectID: "core", SubjectIdentity: "lock-second", Version: "1.0.2",
			Files:         []executionbundle.File{{Path: "artifacts/concurrent.txt", TargetPath: secondPath, Mode: 0o644, Data: secondData}},
			Preconditions: []executionbundle.Precondition{{Kind: "target", Subject: string(sandboxTargetID), Expected: "same-target"}},
			ExpectedPost:  map[string]any{"artifacts": map[string]string{secondPath: digest(secondData)}},
			Steps:         []executionbundle.Step{{ID: "apply:concurrent", Kind: "apply-artifact", Artifact: "artifacts/concurrent.txt", Mutating: true}},
		})
		var wg sync.WaitGroup
		wg.Add(1)
		var first execution.Run
		var firstErr error
		go func() {
			defer wg.Done()
			first, firstErr = executor(t, target, history, "run_lock_1").Execute(context.Background(), string(sandboxTargetID), long)
		}()
		waitObservation(t, target, "run_lock_1", func(o execution.Observation) bool {
			return o.LockHeld && o.Proof != nil && o.Proof.Status == execution.StatusRunning
		})
		b