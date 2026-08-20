# VPSmith Core basis snapshot

Version: `0.1.0`

This directory is the canonical embedded Core source for VPSmith Platform Step 9. `core.json` declares the exact Core contract and image references. `actions/runtime.sh` contains the shared target-side activation logic. The operation entrypoints call that shared runtime after VPSmith Studio has generated and frozen the complete Core runtime into the immutable execution bundle.

VPSmith Studio owns desired state, generation, source selection, image resolution, orchestration, backup selection, and SSH execution. The Core package does not create a second SSH path, a second desired-state model, or module-specific behavior. The target VPS still consists of exactly Cloud-init, Core, and Modules.

Install, update, reconfigure, and read-only validation now use the same runtime contract. Restore remains fail-closed until the verified Step-8 backup payload is wired into the replace-not-merge restore path. Fresh-VPS runtime acceptance is still mandatory before Step 9 can be considered complete.
