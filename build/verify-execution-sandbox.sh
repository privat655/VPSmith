#!/bin/sh
set -eu

GO_IMAGE='golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651'
mkdir -p dist
rm -f dist/execution-sandbox.test tests/execution_sandbox/sandbox_test.go
cat tests/execution_sandbox/parts/*.inc > tests/execution_sandbox/sandbox_test.go
trap 'rm -f tests/execution_sandbox/sandbox_test.go' EXIT HUP INT TERM

docker run --rm \
  --volume "$PWD:/src" \
  --workdir /src \
  "$GO_IMAGE" \
  sh -eu -c 'go version && go test -tags=execution_sandbox -c -o dist/execution-sandbox.test ./tests/execution_sandbox'

VPSMITH_EXECUTION_SANDBOX=1 ./dist/execution-sandbox.test -test.v -test.timeout=4m
