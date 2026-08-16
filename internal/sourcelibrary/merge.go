package sourcelibrary

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func threeWayMerge(ctx context.Context, oldBase, local, newBase string) (string, []string, error) {
	work, err := os.MkdirTemp("", "vpsmith-core-merge-*")
	if err != nil {
		return "", nil, err
	}
	defer os.RemoveAll(work)
	if err := runGit(ctx, work, "", "init", "-q"); err != nil {
		return "", nil, err
	}
	if err := replaceTree(work, oldBase); err != nil {
		return "", nil, err
	}
	if err := runGit(ctx, work, "", "add", "-A"); err != nil {
		return "", nil, err
	}
	if err := runGit(ctx, work, "", "-c", "user.name=VPSmith Studio", "-c", "user.email=vpsmith@localhost", "commit", "-q", "-m", "old embedded base"); err != nil {
		return "", nil, err
	}
	base, err := gitOutput(ctx, work, "", "rev-parse", "HEAD")
	if err != nil {
		return "", nil, err
	}
	if err := runGit(ctx, work, "", "checkout", "-q", "-b", "local"); err != nil {
		return "", nil, err
	}
	if err := replaceTree(work, local); err != nil {
		return "", nil, err
	}
	if err := runGit(ctx, work, "", "add", "-A"); err != nil {
		return "", nil, err
	}
	changed, err := gitChanged(ctx, work, "")
	if err != nil {
		return "", nil, err
	}
	if changed {
		if err := runGit(ctx, work, "", "-c", "user.name=VPSmith Studio", "-c", "user.email=vpsmith@localhost", "commit", "-q", "-m", "local workspace"); err != nil {
			return "", nil, err
		}
	}
	if err := runGit(ctx, work, "", "checkout", "-q", "-b", "upstream", base); err != nil {
		return "", nil, err
	}
	if err := replaceTree(work, newBase); err != nil {
		return "", nil, err
	}
	if err := runGit(ctx, work, "", "add", "-A"); err != nil {
		return "", nil, err
	}
	changed, err = gitChanged(ctx, work, "")
	if err != nil {
		return "", nil, err
	}
	if changed {
		if err := runGit(ctx, work, "", "-c", "user.name=VPSmith Studio", "-c", "user.email=vpsmith@localhost", "commit", "-q", "-m", "new embedded base"); err != nil {
			return "", nil, err
		}
	}
	if err := runGit(ctx, work, "", "checkout", "-q", "local"); err != nil {
		return "", nil, err
	}
	mergeErr := runGit(ctx, work, "", "-c", "user.name=VPSmith Studio", "-c", "user.email=vpsmith@localhost", "merge", "--no-commit", "--no-ff", "upstream")
	conflicts, err := gitOutput(ctx, work, "", "diff", "--name-only", "--diff-filter=U")
	if err != nil {
		return "", nil, err
	}
	var list []string
	if strings.TrimSpace(conflicts) != "" {
		list = strings.Split(conflicts, "\n")
		sort.Strings(list)
	}
	if mergeErr != nil && len(list) == 0 {
		return "", nil, mergeErr
	}
	payload, err := os.MkdirTemp("", "vpsmith-core-candidate-*")
	if err != nil {
		return "", nil, err
	}
	if err := copyTreeExcludingGit(work, payload); err != nil {
		_ = os.RemoveAll(payload)
		return "", nil, err
	}
	return payload, list, nil
}

func replaceTree(dst, src string) error {
	entries, err := os.ReadDir(dst)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == ".git" {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dst, entry.Name())); err != nil {
			return err
		}
	}
	tmp, err := os.MkdirTemp("", "vpsmith-replace-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := copyTree(src, tmp); err != nil {
		return err
	}
	entries, err = os.ReadDir(tmp)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := os.Rename(filepath.Join(tmp, entry.Name()), filepath.Join(dst, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func copyTreeExcludingGit(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == ".git" {
			continue
		}
		from := filepath.Join(src, entry.Name())
		to := filepath.Join(dst, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := copyTree(from, to); err != nil {
				return err
			}
			continue
		}
		if err := copyTreeFile(from, to, info.Mode()); err != nil {
			return err
		}
	}
	return nil
}

func copyTreeFile(src, dst string, mode os.FileMode) error {
	if mode&os.ModeSymlink != 0 {
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		return os.Symlink(target, dst)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, mode.Perm()); err != nil {
		return fmt.Errorf("copy merge file: %w", err)
	}
	return nil
}
