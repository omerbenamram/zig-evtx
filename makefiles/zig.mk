.PHONY: all build run test fmt clean bench bench-zbench sample xml json jsonl todo build-all package-all

all: build

build: build-zig build-py

# Only build Zig artifacts (skip Python extension)
.PHONY: build-zig
build-zig:
	$(ZIG) build -Dtarget=$(TARGET) -Doptimize=$(OPT) -Duse-c-alloc=$(USE_C_ALLOC_BOOL) -Dwith-python=false

# Build Python-related artifacts (requires uv/pydust). Kept separate to allow skipping.
.PHONY: build-py
build-py: py-ensure-pydust
	$(ZIG) build -Dtarget=$(TARGET) -Doptimize=$(OPT) -Dpython-exe=$(PYTHON_EXE) -Duse-c-alloc=$(USE_C_ALLOC_BOOL) -Dwith-python=true

run: build-zig
	$(ZIG) build run -Dtarget=$(TARGET) -Doptimize=$(OPT) -Duse-c-alloc=$(USE_C_ALLOC_BOOL) -- $(ARGS)

sample:
	@if [ -z "$(FILE)" ]; then echo "Usage: make sample FILE=path/to/file.evtx [FORMAT=xml|json|jsonl] [VERBOSE=1]"; exit 1; fi; \
	fmt="$(FORMAT)"; args=""; \
	if [ "$(VERBOSE)" = "1" ]; then args="$$args -v"; fi; \
	args="$$args -o $$fmt $(FILE)"; \
	$(ZIG) build run -Dtarget=$(TARGET) -Doptimize=$(OPT) -- $$args

xml:
	@$(MAKE) sample FILE="$(FILE)" FORMAT=xml VERBOSE=$(VERBOSE)

json:
	@$(MAKE) sample FILE="$(FILE)" FORMAT=json VERBOSE=$(VERBOSE)

jsonl:
	@$(MAKE) sample FILE="$(FILE)" FORMAT=jsonl VERBOSE=$(VERBOSE)

TEST_SUMMARY ?= all
TEST_COLOR ?= on
TEST_FILTER ?=
TEST_FILE ?= src/tests.zig
NO_CACHE ?= 0

test:
	@# Optionally drop caches to rerun everything fresh
	@if [ "$(NO_CACHE)" = "1" ]; then rm -rf zig-out .zig-cache; fi
	@# Run tests directly against aggregator to ensure summary on 0.14.1
	$(ZIG) test -O $(TEST_OPT) $(TEST_FILE)

fmt:
	$(ZIG) fmt src/**/*.zig

clean:
	rm -rf zig-out .zig-cache

bench:
	@mkdir -p out
	$(ZIG) build bench-zbench -Dtarget=$(TARGET) -Doptimize=$(OPT) -Dpython-exe=$(PYTHON_EXE) | tee out/bench-zbench.txt

todo:
	@echo "Open TODOs:" && rg -n "TODO|FIXME" -S || true
	@echo "\nSee TODO.md for the full checklist."

# ----- Cross-build convenience -----
build-all: py-ensure-pydust
	@set -euo pipefail; \
	mkdir -p artifacts; \
	for t in $(TARGETS); do \
	  echo "==> Building for $$t"; \
	  $(ZIG) build -Dtarget=$$t -Doptimize=$(OPT) -Dpython-exe=$(PYTHON_EXE) -Duse-c-alloc=$(USE_C_ALLOC_BOOL) -Dwith-python=$(WITH_PYTHON_BOOL); \
	  out_dir="artifacts/$$t"; \
	  mkdir -p "$$out_dir"; \
	  cp -a zig-out/bin/* "$$out_dir/"; \
	done; \
	echo "All targets built into ./artifacts/<target>"

package-all:
	@set -euo pipefail; \
	shopt -s nullglob; \
	for d in artifacts/*; do \
	  [ -d "$$d" ] || continue; \
	  base=$$(basename "$$d"); \
	  (cd artifacts && tar -czf evtx-zig-$$base.tar.gz $$base); \
	done; \
	echo "Artifacts packaged under ./artifacts/*.tar.gz"


