# VPSmith Step 9 live acceptance driver

`vpsmith-step9-live` is the CI-only driver used by `.github/workflows/step9-live.yml` to exercise the Step 9 Core lifecycle against a fresh Ubuntu 24.04 VM through the production VPSmith application composition and real SSH/systemd/Podman paths.

The workflow generates only ephemeral CI credentials and test material at runtime. Do not add real target addresses, SSH keys, fingerprints, domains, credentials, or other identifying data to this directory or to workflow artifacts.
