# VPSmith Core basis snapshot

Version: `0.1.0`

This directory is the canonical embedded Core source for VPSmith Platform Step 9. `core.json` declares the exact Core contract and image references. The `actions/` scripts are the only Core package actions that the Deployment Compiler may place into an immutable execution bundle.

VPSmith Studio still owns generation and orchestration. The Core package does not create a second SSH path, a second desired-state model, or module-specific behavior. The target VPS still consists of exactly Cloud-init, Core, and Modules.

The first Step-9 tracer intentionally keeps mutating actions fail-closed until all generated runtime artifacts and their runtime validation are implemented. This prevents a partial Core package from being accepted as a successful installation.
