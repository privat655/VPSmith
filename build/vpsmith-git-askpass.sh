#!/bin/sh
set -eu
case "${1:-}" in
  *Username*) printf '%s\n' 'x-access-token' ;;
  *Password*) printf '%s\n' "${VPSMITH_GIT_PAT:?missing VPSmith Git credential}" ;;
  *) exit 1 ;;
esac
