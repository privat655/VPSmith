GO ?= go

.PHONY: fmt fmt-check vet test build embedded-update embedded-check verify-go verify-docker verify-podman verify-containers verify-repro-docker verify-repro-podman verify-execution-sandbox verify-ci

fmt:
	$(GO) fmt ./...

fmt-check:
	@files="$$(gofmt -l cmd internal build/cmd tests)"; \
	if [ -n "$$files" ]; then printf 'gofmt required:\n%s\n' "$$files" >&2; exit 1; fi

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

build:
	mkdir -p dist
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -o dist/vpsmith-studio ./cmd/vpsmith-studio

embedded-update:
	./build/update-embedded-manifest.sh

embedded-check:
	./build/verify-embedded-manifest.sh

verify-go: fmt-check vet test embedded-check build

verify-docker:
	./build/verify-container.sh docker

verify-podman:
	./build/verify-container.sh podman

verify-containers: verify-docker verify-podman

verify-repro-docker:
	./build/verify-reproducible-image.sh docker

verify-repro-podman:
	./build/verify-reproducible-image.sh podman

verify-execution-sandbox:
	./build/verify-execution-sandbox.sh

verify-ci: verify-go verify-containers verify-repro-docker verify-repro-podman verify-execution-sandbox
