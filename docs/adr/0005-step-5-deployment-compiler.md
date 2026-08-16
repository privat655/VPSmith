# ADR 0005 — Step 5 Sollzustand, Modulvertrag und Ausführungsbündel

## Status

Accepted for Step 5.

## Context

Step 5 must turn the canonical Sollzustand, immutable source snapshots and read-only Ist-Zustand into deterministic Prepared Operations. The VPSmith specs are authoritative: `module.yaml` is the only module description; generated files are replaced as complete outputs; Actions are only `action-id -> actions/<file>.sh`; fixed image tags are resolved to exact digests; SHA-256 is the only bundle-integrity mechanism; Secret plaintext never enters historical bundles.

## Decision

### Deep modules and seams

`internal/modulecontract` exposes one compile operation from an immutable package filesystem to a normalized module model. YAML parsing, strict field handling, package layout, Action loading and semantic validation remain inside the implementation.

`internal/deployment` exposes one planning operation returning a `PreparedOperation`. Dependency resolution, Link-Net derivation, Claims, resource merging, generator specializations, structured Soll/Ist diff and operation planning remain private implementation details.

`internal/executionbundle` owns canonical manifest serialization, deterministic archive construction, `SHA256SUMS`, content-derived bundle IDs and immutable local storage.

`internal/registry` is the real variant seam for image resolution. The production Adapter speaks the OCI Distribution protocol; tests use a deterministic Adapter.

### YAML

Use `go.yaml.in/yaml/v3` with `KnownFields(true)`. The YAML organization maintains this fork; v3 remains a stable/security-fix line. VPSmith additionally applies typed semantic validation after decoding. No second schema or second module metadata source is introduced.

### Determinism

Set-like domain collections are normalized before generation. Sequences with explicit semantics, especially `update_from.actions` and execution steps, keep declaration order. Generated Quadlets, networks, Caddy, Authelia and inventory are complete outputs. The bundle archive uses lexical file order, fixed ownership and fixed timestamps so equal canonical inputs produce equal bytes.

### Image identities

A readable fixed tag remains in `module.yaml`; planning resolves it through the registry Adapter and freezes the returned `sha256:` manifest digest in the Prepared Operation and bundle. `latest`, digest-only module declarations and free version/range syntax are rejected before planning.

### Link-Net and Claims

Provider/consumer relationships are resolved from offered interfaces and declared dependencies. Each relationship derives exactly one stable relationship ID, network name and DNS alias. Existing observed Link-Net state is reusable only when bound to the same relationship. Foreign names/subnets block or force a deterministic collision-free candidate. Claims are recomputed from Sollzustand every compile and are never persisted as a second truth.

### Secret boundary

The compiler accepts stable platform Secret IDs bound to module-local secret declarations. Generated artifacts and manifests contain only those IDs and target references. Secret values are intentionally absent from the bundle input types.

### Deinstallation planning

When the target Sollzustand no longer contains the module, the operation must still receive the exact frozen installed module package. Its `module.yaml`, package SHA-256, version and observed image identities are verified before the migration bundle is prepared. This preserves `module.yaml` as the single description without treating Ist-Zustand inventory as a second module contract. Actual module lifecycle orchestration remains a later step.

## Consequences

- Core/module lifecycle, backup/restore and VPSmith Studio can consume the same normalized model and Prepared Operation seam.
- Generator code has no text-patch interface.
- Historical bundles are byte-comparable and cannot be silently replaced.
- The compiler has enough structure for later lifecycle orchestration without implementing Cloud-init hardening, Core installation, module lifecycle, backup/restore or any module-specific special case in Step 5.
