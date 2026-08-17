# Cloud-init released basis

Version: `0.1.0`

This directory is the canonical released Cloud-init source snapshot for VPSmith Primary Host Hardening. `cloud-init.yaml.tmpl` is a trusted build input. VPSmith Studio renders target-specific values into this template through the Deployment Compiler.

The source must not contain credentials, SSH private keys, password hashes, provider API integration, or runtime downloaders. Target-specific public SSH keys are inserted only into generated provider-facing Cloud-init output.
