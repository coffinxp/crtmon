.PHONY: build build-all install clean release

VERSION ?= 1.1.0
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILD_DATE := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS := -ldflags "-X 'main.Version=$(VERSION)' -X 'main.GitCommit=$(GIT_COMMIT)' -X 'main.BuildDate=$(BUILD_DATE)' -s -w"
BINARY := crtmon
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

build:
	@go build $(LDFLAGS) -o $(BINARY) .

build-all: clean
	@mkdir -p build
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) -o build/$(BINARY)-$$os-$$arch$$ext .; \
	done

install: build
	@sudo install -m 755 $(BINARY) /usr/local/bin/$(BINARY)

clean:
	@rm -f $(BINARY)
	@rm -rf build

release: build-all
	@cd build && sha256sum $(BINARY)-* > checksums.txt
