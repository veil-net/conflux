# conflux — a thin CLI over anchor.
#
# Target names mirror anchor's Makefile so muscle memory transfers between the two
# repositories: build, test, race, vet, lint, cross, dist, release, clean.

GO      ?= go
BIN     ?= bin
DIST    ?= dist
# VERSION is the file, not the tag. A tag is a claim about a commit; the file is a
# claim about the tree, and it is the tree that gets built. release.yml tags the release
# with this same file, so the number in the binary and the number on the release cannot
# disagree. ?= still leaves it free to be overridden by hand.
VERSION ?= $(shell cat $(CURDIR)/VERSION 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)

LDFLAGS := -s -w \
	-X github.com/veil-net/conflux/internal/version.Version=$(VERSION) \
	-X github.com/veil-net/conflux/internal/version.Commit=$(COMMIT)

# The seven platforms anchor/bin carries binaries for. A target absent from here is
# a target conflux cannot embed an anchor pair for. darwin/amd64 is absent
# deliberately: no runner executes Intel macOS, so shipping it would ship a target
# nothing ever runs.
TARGETS := linux/amd64 linux/arm64 darwin/arm64 \
           windows/amd64 windows/arm64 freebsd/amd64 openbsd/amd64

# The size gate. One anchor pair is about 45 MB, so a conflux outside this range is
# either missing its binaries or -- far more likely -- embedded all fourteen because
# somebody wrote //go:embed bin instead of naming the two files.
MIN_MB := 30
MAX_MB := 75

ANCHOR_SRC ?= ../anchor

# FETCH=1 downloads the pinned binaries from anchor's `shelf` release when no local
# anchor build is available. Opt-in, because it needs ANCHOR_RELEASE_TOKEN -- anchor is
# private -- and a clone with neither a checkout nor a token should still build against
# placeholders. The three below are empty by default so the values live in
# internal/shelf rather than being repeated here. ONLY=darwin-arm64 (and so on)
# narrows a fetch to the pairs one platform needs; DEST moves where it lands.
FETCH ?= 0
ANCHOR_API ?=
ANCHOR_REPO ?=
ANCHOR_TAG ?=

# The tag `make image` builds and the two suites run. Overridable so a second checkout
# on one machine does not race the first for the name.
IMAGE ?= conflux-systemd-test

.PHONY: all anchor-bins build test race vet fmt fmtcheck lint vulncheck tidycheck docscheck golden cross dist image service-test integration clean help

# Every check that needs neither Docker nor the network. The utility checks --
# fmtcheck, lint, tidycheck, docscheck -- run here and not in CI, which verifies that
# the code builds and runs; vet is part of cross, once per target.
all: fmtcheck lint tidycheck docscheck test cross dist

# anchor-bins puts the anchor binaries where //go:embed can find them. They are not in
# git -- fourteen release builds are about 300 MB -- so a fresh clone runs this once
# before its first build.
#
# Three sources in order: a local release/ (pinned), a local dist/ (unpinned, taken
# loudly), then with FETCH=1 anchor's `shelf` release, which serves the pinned build and
# needs no checkout -- but does need a token, since anchor is private. With none of them
# it writes placeholders, which compile and are caught by the size gate in dist.
anchor-bins:
	@ANCHOR_SRC=$(ANCHOR_SRC) FETCH=$(FETCH) \
		ANCHOR_API=$(ANCHOR_API) ANCHOR_REPO=$(ANCHOR_REPO) ANCHOR_TAG=$(ANCHOR_TAG) \
		./scripts/anchor-bins.sh

# CGO_ENABLED=0 here for the same reason dist sets it: so that the binary a developer
# builds and installs is the same *kind* of binary as the one that ships. Without it
# `make build` inherits the host default, which on any machine with a C toolchain is cgo
# -- a dynamically linked conflux with a libc dependency the release artifact does not
# have, that the release pipeline never tests.
build:
	@mkdir -p $(BIN)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/conflux .
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

# lint runs staticcheck once per operating system conflux targets: code behind a
# build tag is only checked where the tag is true.
lint:
	@command -v staticcheck >/dev/null 2>&1 || { echo "staticcheck not installed; skipping"; exit 0; }
	@for os in $(sort $(foreach t,$(TARGETS),$(firstword $(subst /, ,$(t))))); do \
		echo "staticcheck ($$os)"; GOOS=$$os staticcheck ./... || exit 1; \
	done

vulncheck:
	@command -v govulncheck >/dev/null 2>&1 || { echo "govulncheck not installed; skipping"; exit 0; }
	govulncheck ./...

tidycheck:
	@cp go.mod go.mod.bak && cp go.sum go.sum.bak
	@$(GO) mod tidy
	@if ! diff -q go.mod go.mod.bak >/dev/null || ! diff -q go.sum go.sum.bak >/dev/null; then \
		mv go.mod.bak go.mod; mv go.sum.bak go.sum; \
		echo "go.mod or go.sum is not tidy; run: go mod tidy"; exit 1; fi
	@rm -f go.mod.bak go.sum.bak

# docscheck holds README.md and docs/ to each other: every page linked from the
# README, every page the README links to present, and every link between pages
# resolving.
docscheck:
	@fail=0; \
	for f in docs/*.md; do \
		grep -q "$$(basename $$f)" README.md || { echo "$$f is not linked from README.md"; fail=1; }; \
	done; \
	for p in $$(grep -o 'docs/[a-z-]*\.md' README.md | sort -u); do \
		[ -f "$$p" ] || { echo "README.md links to $$p, which does not exist"; fail=1; }; \
	done; \
	for f in docs/*.md; do \
		for p in $$(grep -o '](\([a-z-]*\.md\)' $$f | sed 's/](//' | sort -u); do \
			[ -f "docs/$$p" ] || { echo "$$f links to $$p, which does not exist"; fail=1; }; \
		done; \
	done; \
	exit $$fail

# golden rewrites the argv fixtures after an intended change, so a change to what
# conflux passes anchorctl shows up as a reviewable text diff; TestArgvGoldens fails on
# any other.
golden:
	$(GO) test ./internal/anchorctl -update

# cross vets every target, which compiles each one's packages and test files -- `go
# build ./...` compiles no test files, so vet is what catches a platform-specific test
# that no longer builds. It works with placeholders. Linking each target, with the real
# binaries and the size gate, is dist's.
cross:
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) vet ./... 2>&1 | grep -v '^#' && exit 1; \
		echo "  ok   $$t"; \
	done

dist:
	@mkdir -p $(DIST)
	@# Clear the previous run first. release.yml uploads dist/conflux-*, so an
	@# artifact left over from a target that has since been dropped would be
	@# checksummed and published alongside the real ones.
	@rm -f $(DIST)/conflux-* $(DIST)/SHA256SUMS
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
			echo "       one anchor pair is ~45 MB; check that anchor/*.go names two files and not the directory"; \
			exit 1; \
		fi; \
		echo "  ok   $$out  $${mb} MB"; \
	done
	@cd $(DIST) && (sha256sum conflux-* > SHA256SUMS 2>/dev/null || shasum -a 256 conflux-* > SHA256SUMS)
	@echo "  wrote $(DIST)/SHA256SUMS"

# The systemd test image, and the two suites that run in it. Docker, /dev/net/tun, a
# cgroup mount and real anchor binaries, so deliberately not in `make all`. CI runs the
# same targets a developer does.
image: dist
	@cp $(DIST)/conflux-linux-amd64 test/systemd/conflux
	@docker build -q -t $(IMAGE) test/systemd >/dev/null
	@echo "  built $(IMAGE) from $(DIST)/conflux-linux-amd64"

# The boot service on its own: install registers without starting, uninstall leaves
# nothing. Cheaper than `integration` and it enrols nothing, so it is the one to run
# when the question is only about the unit.
service-test: image
	@IMAGE=$(IMAGE) ./test/service.sh

integration: image
	@IMAGE=$(IMAGE) ./test/integration.sh

clean:
	rm -rf $(BIN) $(DIST) test/systemd/conflux

help:
	@echo "conflux"
	@echo "  make anchor-bins populate anchor/bin (do this first)"
	@echo "                   ANCHOR_SRC=/path/to/anchor, default ../anchor"
	@echo "                   FETCH=1 to fetch the pinned binaries from anchor's release"
	@echo "                   (needs ANCHOR_RELEASE_TOKEN; anchor is private)"
	@echo "  make build       build for this machine"
	@echo "  make test        run the tests"
	@echo "  make race        run them under the race detector"
	@echo "  make cross       vet all 7 targets, test files included (works with placeholders)"
	@echo "  make dist        build all 7 into $(DIST)/ with SHA256SUMS and the size gate"
	@echo "                   (needs real binaries: make anchor-bins first)"
	@echo "  make golden      rewrite the argv fixtures after an intended change"
	@echo "  make image       build the systemd test image from $(DIST)/conflux-linux-amd64"
	@echo "  make service-test  install and uninstall in a container that boots systemd"
	@echo "  make integration   three nodes, one taint, over the real API (needs Docker)"
	@echo "  make docscheck   README.md and docs/ link to each other and to what exists"
	@echo "  make all         every check that needs neither Docker nor the network"
