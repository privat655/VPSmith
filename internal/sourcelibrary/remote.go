package sourcelibrary

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type RemoteConfig struct {
	Owner      string
	Repository string
	Ref        string
	Token      string
}

type FetchResult struct {
	Commit string
	Path   string
}

type PushRequest struct {
	Config        RemoteConfig
	PackagePath   string
	WorkspacePath string
	BaseCommit    string
	Message       string
}

type PushResult struct {
	Commit       string
	RemoteCommit string
}

type Remote interface {
	Fetch(context.Context, RemoteConfig, string) (FetchResult, error)
	Push(context.Context, PushRequest) (PushResult, error)
}

type gitRemote struct {
	fixedURL   string
	beforePush func()
}

func NewGithubRemote() Remote { return &gitRemote{} }
func NewLocalGitRemote(url string) Remote {
	return &gitRemote{fixedURL: url}
}

func (r *gitRemote) Fetch(ctx context.Context, cfg RemoteConfig, packagePath string) (FetchResult, error) {
	if err := validatePackagePath(packagePath); err != nil {
		return FetchResult{}, err
	}
	work, err := os.MkdirTemp("", "vpsmith-fetch-*")
	if err != nil {
		return FetchResult{}, err
	}
	defer os.RemoveAll(work)
	if err := runGit(ctx, work, cfg.Token, "init", "-q"); err != nil {
		return FetchResult{}, err
	}
	url, err := r.url(cfg)
	if err != nil {
		return FetchResult{}, err
	}
	if err := runGit(ctx, work, cfg.Token, "fetch", "--no-tags", url, cfg.Ref); err != nil {
		return FetchResult{}, fmt.Errorf("fetch configured custom module ref: %w", err)
	}
	commit, err := gitOutput(ctx, work, cfg.Token, "rev-parse", "FETCH_HEAD")
	if err != nil {
		return FetchResult{}, err
	}
	if err := runGit(ctx, work, cfg.Token, "checkout", "-q", "--detach", commit); err != nil {
		return FetchResult{}, err
	}
	src := filepath.Join(work, filepath.FromSlash(packagePath))
	if info, err := os.Stat(src); err != nil || !info.IsDir() {
		return FetchResult{}, fmt.Errorf("custom module package %q is not present at commit %s", packagePath, commit)
	}
	out, err := os.MkdirTemp("", "vpsmith-package-*")
	if err != nil {
		return FetchResult{}, err
	}
	if err := copyTree(src, out); err != nil {
		_ = os.RemoveAll(out)
		return FetchResult{}, err
	}
	return FetchResult{Commit: commit, Path: out}, nil
}

func (r *gitRemote) Push(ctx context.Context, req PushRequest) (PushResult, error) {
	if strings.TrimSpace(req.Message) == "" {
		return PushResult{}, errors.New("commit message is required")
	}
	if err := validatePackagePath(req.PackagePath); err != nil {
		return PushResult{}, err
	}
	work, err := os.MkdirTemp("", "vpsmith-push-*")
	if err != nil {
		return PushResult{}, err
	}
	defer os.RemoveAll(work)
	if err := runGit(ctx, work, req.Config.Token, "init", "-q"); err != nil {
		return PushResult{}, err
	}
	url, err := r.url(req.Config)
	if err != nil {
		return PushResult{}, err
	}
	if err := runGit(ctx, work, req.Config.Token, "fetch", "--no-tags", url, req.Config.Ref); err != nil {
		return PushResult{}, err
	}
	actual, err := gitOutput(ctx, work, req.Config.Token, "rev-parse", "FETCH_HEAD")
	if err != nil {
		return PushResult{}, err
	}
	if actual != req.BaseCommit {
		// Return drift as data instead of a callback error. managementstate intentionally
		// redacts arbitrary secret-consumer errors; the Library turns this mismatch into
		// the structured RemoteDriftError after the PAT has left scope.
		return PushResult{Commit: req.BaseCommit, RemoteCommit: actual}, nil
	}
	if err := runGit(ctx, work, req.Config.Token, "checkout", "-q", "--detach", actual); err != nil {
		return PushResult{}, err
	}
	dst := filepath.Join(work, filepath.FromSlash(req.PackagePath))
	if err := os.RemoveAll(dst); err != nil {
		return PushResult{}, err
	}
	if err := copyTree(req.WorkspacePath, dst); err != nil {
		return PushResult{}, err
	}
	if err := runGit(ctx, work, req.Config.Token, "add", "--", req.PackagePath); err != nil {
		return PushResult{}, err
	}
	changed, err := gitChanged(ctx, work, req.Config.Token)
	if err != nil {
		return PushResult{}, err
	}
	if !changed {
		return PushResult{}, errors.New("workspace has no changes to push")
	}
	if err := runGit(ctx, work, req.Config.Token,
		"-c", "user.name=VPSmith Studio",
		"-c", "user.email=vpsmith@localhost",
		"commit", "-q", "-m", req.Message, "--", req.PackagePath,
	); err != nil {
		return PushResult{}, err
	}
	commit, err := gitOutput(ctx, work, req.Config.Token, "rev-parse", "HEAD")
	if err != nil {
		return PushResult{}, err
	}
	if r.beforePush != nil {
		r.beforePush()
	}
	pushRef, err := branchDestination(req.Config.Ref)
	if err != nil {
		return PushResult{}, err
	}
	if err := runGit(ctx, work, req.Config.Token, "push", url, "HEAD:"+pushRef); err != nil {
		observed, _ := r.readRemoteRef(ctx, req.Config, url)
		if observed != "" && observed != req.BaseCommit {
			return PushResult{Commit: req.BaseCommit, RemoteCommit: observed}, nil
		}
		return PushResult{}, fmt.Errorf("push custom module commit rejected: %w", err)
	}
	remoteCommit, err := r.readRemoteRef(ctx, req.Config, url)
	if err != nil {
		return PushResult{}, err
	}
	return PushResult{Commit: commit, RemoteCommit: remoteCommit}, nil
}

func (r *gitRemote) readRemoteRef(ctx context.Context, cfg RemoteConfig, url string) (string, error) {
	ref, err := branchDestination(cfg.Ref)
	if err != nil {
		return "", err
	}
	out, err := gitOutput(ctx, "", cfg.Token, "ls-remote", "--refs", url, ref)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(out)
	if len(fields) != 2 {
		return "", errors.New("configured remote ref did not resolve exactly once")
	}
	return fields[0], nil
}

func (r *gitRemote) url(cfg RemoteConfig) (string, error) {
	if r.fixedURL != "" {
		return r.fixedURL, nil
	}
	if strings.TrimSpace(cfg.Owner) == "" || strings.TrimSpace(cfg.Repository) == "" {
		return "", errors.New("custom module github owner and repository are required")
	}
	if strings.ContainsAny(cfg.Owner+cfg.Repository, "/\\?#@ ") {
		return "", errors.New("invalid custom module github repository identity")
	}
	return "https://github.com/" + cfg.Owner + "/" + cfg.Repository + ".git", nil
}

func branchDestination(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, "refs/heads/") {
		return ref, nil
	}
	if ref != "" && !strings.Contains(ref, "/") {
		return "refs/heads/" + ref, nil
	}
	return "", fmt.Errorf("push requires a branch ref, got %q", ref)
}

func validatePackagePath(v string) error {
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(v)))
	if v == "" || clean == "." || clean != v || strings.HasPrefix(v, "/") || v == ".." || strings.HasPrefix(v, "../") {
		return fmt.Errorf("package path %q must be a clean relative path", v)
	}
	return nil
}

func runGit(ctx context.Context, dir, token string, args ...string) error {
	_, err := gitCommand(ctx, dir, token, args...)
	return err
}

func gitOutput(ctx context.Context, dir, token string, args ...string) (string, error) {
	out, err := gitCommand(ctx, dir, token, args...)
	return strings.TrimSpace(string(out)), err
}

func gitChanged(ctx context.Context, dir, token string) (bool, error) {
	cmd := exec.CommandContext(ctx, "git", "diff", "--cached", "--quiet", "--exit-code")
	cmd.Dir = dir
	cmd.Env = gitEnv(token)
	err := cmd.Run()
	if err == nil {
		return false, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return true, nil
	}
	return false, fmt.Errorf("inspect staged git diff: %w", err)
}

func gitCommand(ctx context.Context, dir, token string, args ...string) ([]byte, error) {
	for _, arg := range args {
		if arg == "--force" || arg == "--force-with-lease" || strings.HasPrefix(arg, "+") {
			return nil, errors.New("unsafe git push option is forbidden")
		}
	}
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv(token)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git command failed: %w", err)
	}
	return stdout.Bytes(), nil
}

func gitEnv(token string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=/nonexistent",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
	}
	if token != "" {
		env = append(env, "VPSMITH_GIT_PAT="+token, "GIT_ASKPASS="+askPassPath())
	}
	return env
}

func askPassPath() string { return "/usr/local/libexec/vpsmith-git-askpass" }
