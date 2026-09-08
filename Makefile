# conflux — a thin CLI over anchor.
#
# Target names mirror anchor's Makefile so muscle memory transfers between the two
# repositories: build, test, race, vet, lint, cross, dist, release, clean.

GO      ?= go
BIN     ?= bin
DIST    ?= dist
# VERSION is the file, not the tag. A tag is a claim about a commit; the file is a
# claim about the tree, and it is the tree that gets built. release.yml still wins by
# passing VERSION=<tag> on the command line, which ?= leaves it free to do.
VERSION ?= $(shell cat $(CURDIR)/VERSION 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)

LDFLAGS := -s -w \
	-X github.com/veil-net/conflux/internal/version.Version=$(VERSION) \
	-X github.com/veil-net/conflux/internal/version.Commit=$(COMMIT)

# The eight platforms anchor/bin carries binaries for. A target absent from here is
# a target conflux cannot embed an anchor pair for.
TARGETS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 \
           windows/amd64 windows/arm64 freebsd/amd64 openbsd/amd64

# The size gate. One anchor pair is about 43 MB, so a conflux outside this range is
# either missing its binaries or -- far more likely -- embedded all sixteen because
# somebody wrote //go:embed bin instead of naming the two files.
MIN_MB := 30
MAX_MB := 75

ANCHOR_SRC ?= ../anchor

.PHONY: all anchor-bins build test race vet fmt fmtcheck lint vulncheck tidycheck golden cross dist clean help

all: fmtcheck vet lint tidycheck test cross dist

# anchor-bins puts the anchor binaries where //go:embed can find them. They are not in
# git -- sixteen release builds are about 324 MB -- so a fresh clone runs this once
# before its first build. With no anchor checkout it writes placeholders, which
# compile and are caught by the size gate in dist.
anchor-bins:
	@ANCHOR_SRC=$(ANCHOR_SRC) ./scripts/anchor-bins.sh

build:
	@mkdir -p $(BIN)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/conflux .
	@ls -l $(BIN)/conflux | awk '{printf "  %.1f MB  $(BIN)/conflux\n", $$5/1048576}'

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

fmtcheck:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint:
	@command -v staticcheck >/dev/null 2>&1 || { echo "staticcheck not installed; skipping"; exit 0; }
	staticcheck ./...

vulncheck:
	@command -v govulncheck >/dev/null 2>&1 || { echo "govulncheck not installed; skipping"; exit 0; }
	govulncheck ./...

tidycheck:
	@cp go.mod go.mod.bak && cp go.sum go.sum.bak 2>/dev/null || true
	@$(GO) mod tidy
	@if ! diff -q go.mod go.mod.bak >/dev/null; then \
		mv go.mod.bak go.mod; mv go.sum.bak go.sum 2>/dev/null || true; \
		echo "go.mod is not tidy; run: go mod tidy"; exit 1; fi
	@rm -f go.mod.bak go.sum.bak

# golden rewrites the argv fixtures. CI runs `git diff --exit-code testdata/`
# afterwards, so a change to what conflux passes anchorctl shows up as a reviewable
# text diff rather than as a runtime failure on somebody else's machine.
golden:
	$(GO) test ./internal/anchorctl -update

# cross vets and compiles every target. `go build ./...` does not compile test files,
# so vet is what catches a platform-specific test that no longer builds.
#
# Deliberately does not produce artifacts or run the size gate: that is `dist`, which
# needs the real anchor binaries. This target is useful with placeholders, which is
# what CI has.
cross:
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) vet ./... 2>&1 | grep -v '^#' && exit 1; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -o /dev/null . || exit 1; \
		echo "  ok   $$t"; \
	done

dist:
	@mkdir -p $(DIST)
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; ext=""; \
		[ "$$os" = windows ] && ext=.exe; \
		out=$(DIST)/conflux-$$os-$$arch$$ext; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $$out . || exit 1; \
		mb=$$(( $$(stat -c%s $$out 2>/dev/null || stat -f%z $$out) / 1048576 )); \
		if [ $$mb -lt $(MIN_MB) ]; then \
			echo "  FAIL $$out is $${mb} MB, under $(MIN_MB) MB"; \
			echo "       anchor/bin holds placeholders, not binaries. Run:"; \
			echo "         make anchor-bins ANCHOR_SRC=/path/to/anchor"; \
			exit 1; \
		fi; \
		if [ $$mb -gt $(MAX_MB) ]; then \
			echo "  FAIL $$out is $${mb} MB, over $(MAX_MB) MB"; \
			echo "       one anchor pair is ~43 MB; check that anchor/*.go names two files and not the directory"; \
			exit 1; \
		fi; \
		echo "  ok   $$out  $${mb} MB"; \
	done
	@cd $(DIST) && (sha256sum * > SHA256SUMS 2>/dev/null || shasum -a 256 * > SHA256SUMS)
	@echo "  wrote $(DIST)/SHA256SUMS"

clean:
	rm -rf $(BIN) $(DIST)

help:
	@echo "conflux"
	@echo "  make anchor-bins populate anchor/bin from a local anchor checkout (do this first)"
	@echo "                   ANCHOR_SRC=/path/to/anchor, default ../anchor"
	@echo "  make build       build for this machine"
	@echo "  make test        run the tests"
	@echo "  make race        run them under the race detector"
	@echo "  make cross       vet and compile all 8 targets (works with placeholders)"
	@echo "  make dist        build all 8 into $(DIST)/ with SHA256SUMS and the size gate"
	@echo "                   (needs real binaries: make anchor-bins first)"
	@echo "  make golden      rewrite the argv fixtures after an intended change"
	@echo "  make all         everything CI runs"
