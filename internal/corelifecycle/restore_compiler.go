package corelifecycle

import (
	"context"
	"errors"

	"github.com/privat655/VPSmith/internal/deployment"
)

type coreRestoreCompiler interface {
	PrepareCoreRestore(context.Context, deployment.CoreRequest, map[string]deployment.FrozenCoreImage) (deployment.PreparedCoreOperation, error)
}

func prepareCoreOperation(ctx context.Context, compiler Compiler, kind deployment.OperationKind, req deployment.CoreRequest, backup *verifiedBackup) (deployment.PreparedCoreOperation, error) {
	if kind != deployment.Restore {
		return compiler.PrepareCore(ctx, req)
	}
	if backup == nil {
		return deployment.PreparedCoreOperation{}, errors.New("Core restore requires verified backup image locks")
	}
	restoreCompiler, ok := compiler.(coreRestoreCompiler)
	if !ok {
		return deployment.PreparedCoreOperation{}, errors.New("Core compiler does not support exact restore image locks")
	}
	locks := make(map[string]deployment.FrozenCoreImage, len(backup.ImageLocks.Images))
	for name, image := range backup.ImageLocks.Images {
		locks[name] = deployment.FrozenCoreImage{Ref: image.Ref, Digest: image.Digest}
	}
	return restoreCompiler.PrepareCoreRestore(ctx, req, locks)
}
