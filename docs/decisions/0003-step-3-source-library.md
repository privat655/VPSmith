# ADR 0003 — Step 3 canonical source library

Status: accepted for VPSmith Platform step 3

## Context

VPSmith Studio must keep three truths separate: immutable source identity, mutable local workspace state, and the identity observed later on a Ziel-VPS. Runtime Studio may read and write exactly one configured Custom Module Github, but it has no runtime path to VPSmith Github. Embedded Cloud-init, Core, and n8n sources enter Studio only through the released container image.

Step 5 will need to freeze exact source identities in deployment planning. Step 3 therefore owns the identity boundary now: a custom module source is identified by its exact Git commit plus its canonical package SHA-256; embedded sources are identified by release version plus canonical SHA-256.

## Decisions

### One canonical package hashing pipeline

`internal/sourcehash` is the only package-tree identity implementation. Release tooling and runtime source-library code both call it.

The canonical digest sorts clean POSIX-relative paths. A regular file contributes entry type, relative path, Unix permission bits, byte size, and SHA-256 of its bytes. A symlink contributes entry type, relative path, and relative target; unsafe, absolute, dangling, or escaping symlinks fail closed. Directory metadata and timestamps do not contribute.

The following workstation-only noise is excluded from both package hashing and structured source diffs: `.git` metadata, `.idea`, `.vscode`, `.DS_Store`, `Thumbs.db`, editor backup files ending in `~`, Vim `.swp`/`.swo` files, and Emacs lock files beginning with `.#`. The exclusion set is code-defined rather than user-configurable so source identity cannot silently change through local ignore configuration.

### Content-addressed immutable snapshots and separate workspaces

Immutable payloads are stored below `snapshots/sha256/<digest>` in the existing `/var/lib/vpsmith/sources` persistence mount. Imports are copied to a sibling temporary directory, hashed again, and published with a same-filesystem rename. An existing snapshot path is never overwritten. Every use of a registered immutable snapshot verifies its content again and fails closed if the stored tree no longer matches the registered digest.

Mutable workspaces live separately below `workspaces/<workspace-id>`. The canonical management-state database owns their metadata. A workspace permanently records its original base snapshot; custom-module workspaces additionally permanently record the `base_commit`. Editing a workspace never changes its base artifact, pushes, deploys, or changes a Ziel-VPS.

Schema v2 adds immutable source-artifact metadata, mutable workspace metadata, and the singleton Custom Module Github configuration to the existing management-state database. There is no second source-state database.

### Real Git behind one remote seam

VPSmith delegates Git semantics to the Git CLI instead of reimplementing fetch, commits, non-fast-forward protection, or three-way merge. The external source-library seam has two adapters: the production Custom Module Github adapter and a local Git-remote adapter used by tests. Callers never construct Git commands or parse Git output.

The runtime image installs Git 2.39.5 from the fixed Debian snapshot `20260713T000000Z`. HTTPS trust for the initial snapshot access is bootstrapped from the already digest-pinned Debian Bookworm Go builder CA bundle; certificate verification is never disabled.

### PAT isolation

Only a `SecretID` is stored in normal management state. The PAT value is resolved just for the remote operation. The production Git adapter uses `GIT_ASKPASS`; the token is not included in a repository URL or Git argv. Interactive prompting and ambient system/global Git configuration are disabled. Git stderr is not reflected into domain errors, preventing accidental credential echo.

Rotating or replacing the PAT changes only local secret/configuration state and does not invoke source loading, pushing, or deployment.

### Update loading

A Custom Module Github update fetches the configured ref, resolves the exact fetched commit, materializes only the selected module directory, computes its canonical package SHA-256, publishes an immutable local snapshot, then registers the immutable identity in management state. It never talks to a Ziel-VPS.

### Optimistic concurrency and fail-closed push

A custom-module workspace push requires a non-empty commit message. Immediately before committing/pushing, the adapter fetches the configured branch and compares the exact remote commit with the workspace's immutable `base_commit`. Drift fails closed with a structured error.

The adapter creates a commit containing only the configured module path and performs a normal Git branch push. `--force`, `--force-with-lease`, and `+refspec` are rejected by the Git command implementation. No pull, automatic merge, or automatic rebase exists in this path.

A normal non-fast-forward push rejection closes the race between the pre-push fetch and the actual push. On rejection the adapter reads the remote ref again and exposes drift. After a successful push it reads the remote ref again with `ls-remote`; management state is marked synchronized only when that ref exactly equals the commit VPSmith expected to publish.

### Core three-way merge

Embedded Core snapshots have no runtime remote. A Core workspace permanently retains its old embedded base. When a new embedded Core arrives, VPSmith asks Git for a true three-way merge of old embedded base, local workspace, and new embedded base. A clean result becomes a new local candidate workspace based on the new embedded source. The original workspace is retained. Conflicts are returned explicitly and remain unresolved; there is no automatic deployment.

Cloud-init uses the same immutable-snapshot/workspace machinery but has no push operation. Neither Core nor Cloud-init has any runtime repository adapter for VPSmith Github.

## Rejected alternatives

- A second SQLite/JSON source database: rejected because management state is already the canonical persistence owner.
- `go-git` as the primary implementation: rejected because VPSmith needs the real three-way merge semantics and push behavior already implemented by Git; adding missing merge behavior in VPSmith would create unnecessary Git complexity.
- Force-with-lease: rejected because VPSmith's required behavior is stricter. Any remote drift must stop and require a later explicit user decision.
- Automatic merge/rebase on push: rejected by the product contract.
- A runtime VPSmith-Github remote: forbidden by the platform boundary.

## Consequences

Step 5 can consume immutable source identities without knowing Git commands or source-library paths. The source library earns its depth by localizing hashing, immutable publication, workspace ancestry, structured diffs, remote concurrency, PAT handling, and Core merge behavior behind a small caller surface.
