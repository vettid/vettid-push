GO        ?= go
BIN       ?= bin
IMAGE     ?= vettid-push:dev
PLATFORMS ?= linux/amd64,linux/arm64
VERSION   ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null)
LDFLAGS   := -s -w -buildid= -X main.version=$(VERSION)
CONTAINER ?= $(shell command -v docker || command -v podman)
# The image's timestamps: the commit's, so that two builds of one commit
# are the same image (make image-repro).
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
# Tests run two packages at a time: several suites generate RSA and EC
# keys, and a developer machine has other work to do.
TESTFLAGS ?= -p 2

.PHONY: all build test race lint vet staticcheck scan image image-multiarch image-repro tidy clean

all: lint test build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o $(BIN)/vettid-push ./cmd/vettid-push
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o $(BIN)/pushctl ./cmd/pushctl

test:
	$(GO) test $(TESTFLAGS) ./...

race:
	$(GO) test -race -p 1 -count=1 ./...

vet:
	$(GO) vet ./...

# staticcheck is run at a pinned version via `go run` (fetched on first use).
staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...

lint: vet staticcheck

scan:
	gitleaks git --redact .

image:
	$(CONTAINER) build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

image-multiarch:
	docker buildx build --platform $(PLATFORMS) --build-arg VERSION=$(VERSION) -t $(IMAGE) .

# Two clean builds (no layer cache) of the working tree with the commit's
# timestamp; fails unless both give the same image id. podman takes the
# timestamp with --timestamp; docker (BuildKit) takes SOURCE_DATE_EPOCH
# and rewrites layer timestamps.
image-repro:
	@set -e; \
	if $(CONTAINER) --version | grep -qi podman; then \
	  build() { $(CONTAINER) build --no-cache --timestamp $(SOURCE_DATE_EPOCH) --build-arg VERSION=$(VERSION) -t $$1 . >/dev/null; }; \
	else \
	  build() { SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) $(CONTAINER) buildx build --no-cache --build-arg VERSION=$(VERSION) \
	    --output type=docker,name=$$1,rewrite-timestamp=true . >/dev/null; }; \
	fi; \
	build vettid-push:repro-a; build vettid-push:repro-b; \
	a=$$($(CONTAINER) image inspect --format '{{.Id}}' vettid-push:repro-a); \
	b=$$($(CONTAINER) image inspect --format '{{.Id}}' vettid-push:repro-b); \
	echo "build A: $$a"; echo "build B: $$b"; \
	$(CONTAINER) rmi vettid-push:repro-a vettid-push:repro-b >/dev/null 2>&1 || true; \
	test "$$a" = "$$b" && echo "reproducible" || { echo "NOT reproducible"; exit 1; }

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BIN)
