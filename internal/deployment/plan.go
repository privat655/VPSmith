package deployment

import (
	"errors"
	"fmt"
	"path"

	"github.com/privat655/VPSmith/internal/executionbundle"
)

func buildPlan(req Request, mods []compiledModule, artifacts []GeneratedArtifact, updateActions []string) ([]PlanStep, []executionbundle.Step, []executionbundle.File, []string, error) {
	var plan []PlanStep
	var steps []executionbundle.Step
	if req.Operation != Validate {
		for _, a := range artifacts {
			id := "apply:" + a.Path
			plan = append(plan, PlanStep{ID: id, Description: "Generate and apply " + a.Path, Mutating: true})
			steps = append(steps, executionbundle.Step{ID: id, Kind: "apply-artifact", Artifact: a.Path, Mutating: true})
		}
	}
	var target *compiledModule
	for i := range mods {
		if mods[i].Desired.InstanceID == req.SubjectInstance {
			target = &mods[i]
			break
		}
	}
	var actionFiles []executionbundle.File
	var actionIDs []string
	seenActionFile := map[string]struct{}{}
	appendAction := func(id string, mutating bool) error {
		if target == nil {
			return errors.New("subject module action requested without desired subject")
		}
		rel, ok := target.Contract.Actions[id]
		if !ok {
			return fmt.Errorf("unknown action %s", id)
		}
		if _, seen := seenActionFile[id]; !seen {
			bundlePath := "actions/" + req.SubjectInstance + "/" + path.Base(rel)
			actionFiles = append(actionFiles, executionbundle.File{Path: bundlePath, Mode: 0o555, Data: target.Contract.ActionFiles[id]})
			actionIDs = append(actionIDs, id)
			seenActionFile[id] = struct{}{}
		}
		plan = append(plan, PlanStep{ID: "action:" + id, Description: "Run registered action " + id, Mutating: mutating})
		steps = append(steps, executionbundle.Step{ID: "action:" + id, Kind: "action", Action: id, Mutating: mutating})
		return nil
	}
	for _, id := range updateActions {
		if err := appendAction(id, true); err != nil {
			return nil, nil, nil, nil, err
		}
	}
	if target != nil {
		if err := appendAction(target.Contract.ValidationAction, false); err != nil {
			return nil, nil, nil, nil, err
		}
	}
	return plan, steps, actionFiles, actionIDs, nil
}

func validationSpecs(req Request, mods []compiledModule) []executionbundle.ValidationSpec {
	out := make([]executionbundle.ValidationSpec, 0, len(mods))
	for _, m := range mods {
		if m.Desired.InstanceID == req.SubjectInstance {
			out = append(out, executionbundle.ValidationSpec{ID: m.Desired.InstanceID + ":" + m.Contract.ValidationAction, ReadOnly: true})
		}
	}
	return out
}

func bundleKind(op OperationKind) executionbundle.Kind {
	if op == Install {
		return executionbundle.Installation
	}
	if op == Validate {
		return executionbundle.Validation
	}
	return executionbundle.Migration
}
