ZIG ?= zig
TARGET ?= native
OPT ?= ReleaseFast
FORMAT ?= xml
VERBOSE ?= 0
PYTHON ?= python3

# Use bash for complex recipes (avoids fish/sh incompatibilities)
SHELL := /bin/bash

.PHONY: all build run test fmt clean bench

all: build

build:
	$(ZIG) build -Dtarget=$(TARGET) -Doptimize=$(OPT)

run:
	$(ZIG) build run -Dtarget=$(TARGET) -Doptimize=$(OPT) -- $(ARGS)

.PHONY: sample xml json jsonl
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

test:
	$(ZIG) build test -Dtarget=$(TARGET) -Doptimize=$(MODE)

fmt:
	$(ZIG) fmt src/**/*.zig

clean:
	rm -rf zig-out zig-cache

bench:
	@echo "Benchmark harness TBD. Use: make run ARGS='-o json sample.evtx'"

.PHONY: todo
todo:
	@echo "Open TODOs:" && rg -n "TODO|FIXME" -S || true
	@echo "\nSee TODO.md for the full checklist."


# --- Compare against Rust evtx_dump ---
EVTX_DUMP ?= evtx_dump
OUT_DIR ?= out
DIFF ?= diff -u

# --- Flamegraph (macOS via `sample`) ---
.PHONY: install-flamegraph flamegraph

FLAMEGRAPH_REPO_URL ?= https://github.com/brendangregg/FlameGraph.git
FLAMEGRAPH_DIR ?= scripts/FlameGraph
FLAME_FILE ?= samples/security_big_sample.evtx
DURATION ?= 30
SAMPLE_FILE ?= $(OUT_DIR)/sample.txt
FOLDED_FILE ?= $(OUT_DIR)/stacks.folded
SVG_FILE ?= $(OUT_DIR)/flamegraph.svg
BIN ?= zig-out/bin/evtx_dump_zig

install-flamegraph:
	@mkdir -p scripts
	@if [ ! -d "$(FLAMEGRAPH_DIR)" ]; then \
	  echo "Cloning FlameGraph scripts..."; \
	  git clone "$(FLAMEGRAPH_REPO_URL)" "$(FLAMEGRAPH_DIR)" >/dev/null; \
	else \
	  echo "FlameGraph already present"; \
	fi

# Generate a flamegraph SVG at $(SVG_FILE).
# Usage: make flamegraph [FLAME_FILE=path/to/file.evtx] [DURATION=30] [FORMAT=xml|json|jsonl]
flamegraph: install-flamegraph
	@set -euo pipefail; \
	mkdir -p "$(OUT_DIR)"; \
	echo "Building Debug for better symbols..."; \
	$(MAKE) build OPT=Debug >/dev/null; \
	if [ ! -f "$(FLAME_FILE)" ]; then echo "Missing FLAME_FILE: $(FLAME_FILE)"; exit 1; fi; \
	echo "Starting target on $(FLAME_FILE)..."; \
	"$(BIN)" -o $(FORMAT) "$(FLAME_FILE)" >/dev/null 2>&1 & echo $$! > "$(OUT_DIR)/app.pid"; \
	pid=$$(cat "$(OUT_DIR)/app.pid"); echo "PID: $$pid"; \
	echo "Sampling for $(DURATION)s..."; \
	sample $$pid $(DURATION) -file "$(SAMPLE_FILE)" >/dev/null 2>&1 || true; \
	if kill -0 $$pid >/dev/null 2>&1; then kill -INT $$pid >/dev/null 2>&1 || true; fi; \
	wait $$pid || true; \
	echo "Collapsing stacks..."; \
	awk -f "$(FLAMEGRAPH_DIR)/stackcollapse-sample.awk" "$(SAMPLE_FILE)" > "$(FOLDED_FILE)"; \
	echo "Generating flamegraph SVG..."; \
	"$(FLAMEGRAPH_DIR)/flamegraph.pl" "$(FOLDED_FILE)" > "$(SVG_FILE)"; \
	echo "Computing hotspot summaries..."; \
	awk '{ n=$$NF; sub(/ [0-9]+$$/,"",$$0); len=split($$0, a, ";"); for (i=1;i<=len;i++) counts[a[i]] += n } END { for (k in counts) print counts[k], k }' "$(FOLDED_FILE)" | sort -nr | head -n 30 > "$(OUT_DIR)/top_functions.txt"; \
	awk '{ n=$$NF; sub(/ [0-9]+$$/,"",$$0); len=split($$0, a, ";"); leaf=a[len]; leaf_counts[leaf]+=n } END { for (k in leaf_counts) print leaf_counts[k], k }' "$(FOLDED_FILE)" | sort -nr | head -n 30 > "$(OUT_DIR)/top_leaf.txt"; \
	perl -ne 'if (/<title>([^<]+) \((\d+(?:\.\d+)?)%\)/) { print $$2, " ", $$1, "\n" }' "$(SVG_FILE)" | sort -nr | head -n 30 > "$(OUT_DIR)/top_titles.txt"; \
	echo "Done. Outputs:"; \
	ls -lh "$(OUT_DIR)" | cat

.PHONY: flamegraph-prod
# Production-like flamegraph: ReleaseFast with symbols (strip=false)
flamegraph-prod: install-flamegraph
	@set -euo pipefail; \
	mkdir -p "$(OUT_DIR)"; \
	echo "Building ReleaseFast..."; \
	$(MAKE) build OPT=ReleaseFast >/dev/null; \
	if [ ! -f "$(FLAME_FILE)" ]; then echo "Missing FLAME_FILE: $(FLAME_FILE)"; exit 1; fi; \
	echo "Starting target on $(FLAME_FILE)..."; \
	"$(BIN)" -o $(FORMAT) "$(FLAME_FILE)" >/dev/null 2>&1 & echo $$! > "$(OUT_DIR)/app.pid"; \
	pid=$$(cat "$(OUT_DIR)/app.pid"); echo "PID: $$pid"; \
	echo "Sampling for $(DURATION)s..."; \
	sample $$pid $(DURATION) -file "$(SAMPLE_FILE)" >/dev/null 2>&1 || true; \
	if kill -0 $$pid >/dev/null 2>&1; then kill -INT $$pid >/dev/null 2>&1 || true; fi; \
	wait $$pid || true; \
	echo "Collapsing stacks..."; \
	awk -f "$(FLAMEGRAPH_DIR)/stackcollapse-sample.awk" "$(SAMPLE_FILE)" > "$(FOLDED_FILE)"; \
	echo "Generating flamegraph SVG..."; \
	"$(FLAMEGRAPH_DIR)/flamegraph.pl" "$(FOLDED_FILE)" > "$(SVG_FILE)"; \
	echo "Computing hotspot summaries..."; \
	awk '{ n=$$NF; sub(/ [0-9]+$$/,"",$$0); len=split($$0, a, ";"); for (i=1;i<=len;i++) counts[a[i]] += n } END { for (k in counts) print counts[k], k }' "$(FOLDED_FILE)" | sort -nr | head -n 30 > "$(OUT_DIR)/top_functions.txt"; \
	awk '{ n=$$NF; sub(/ [0-9]+$$/,"",$$0); len=split($$0, a, ";"); leaf=a[len]; leaf_counts[leaf]+=n } END { for (k in leaf_counts) print leaf_counts[k], k }' "$(FOLDED_FILE)" | sort -nr | head -n 30 > "$(OUT_DIR)/top_leaf.txt"; \
	perl -ne 'if (/<title>([^<]+) \((\d+(?:\.\d+)?)%\)/) { print $$2, " ", $$1, "\n" }' "$(SVG_FILE)" | sort -nr | head -n 30 > "$(OUT_DIR)/top_titles.txt"; \
	echo "Done. Outputs:"; \
	ls -lh "$(OUT_DIR)" | cat

.PHONY: install-evtx xml-rs xml-zig compare-first

install-evtx:
	@command -v $(EVTX_DUMP) >/dev/null 2>&1 || cargo install evtx >/dev/null 2>&1 || true

xml-rs: install-evtx
	@if [ -z "$(FILE)" ]; then echo "Usage: make xml-rs FILE=path/to/file.evtx"; exit 1; fi; \
	mkdir -p $(OUT_DIR); \
	name=$$(basename "$(FILE)"); \
	rm -f "$(OUT_DIR)/$$name.rs.xml"; \
	$(EVTX_DUMP) -t 1 -o xml -f "$(OUT_DIR)/$$name.rs.xml" "$(FILE)"

xml-zig:
	@if [ -z "$(FILE)" ]; then echo "Usage: make xml-zig FILE=path/to/file.evtx"; exit 1; fi; \
	mkdir -p $(OUT_DIR); \
	name=$$(basename "$(FILE)"); \
	$(ZIG) build -Dtarget=$(TARGET) -Doptimize=$(OPT); \
	zig-out/bin/evtx_dump_zig -o xml -n 1 "$(FILE)" > "$(OUT_DIR)/$$name.zig.xml"

compare-first: xml-rs xml-zig
	name=$$(basename "$(FILE)"); \
	$(PYTHON) scripts/record_diff.py --rs "$(OUT_DIR)/$$name.rs.xml" --zig "$(OUT_DIR)/$$name.zig.xml" --index 1 --out-dir "$(OUT_DIR)" --name "$$name"

# --- Full file comparison over all records ---
.PHONY: xml-all-rs xml-all-zig compare-all

xml-all-rs: install-evtx
	@if [ -z "$(FILE)" ]; then echo "Usage: make xml-all-rs FILE=path/to/file.evtx"; exit 1; fi; \
	mkdir -p $(OUT_DIR); \
	name=$$(basename "$(FILE)"); \
	rm -f "$(OUT_DIR)/$$name.rs.xml"; \
	$(EVTX_DUMP) -t 1 -o xml -f "$(OUT_DIR)/$$name.rs.xml" "$(FILE)" 2> "$(OUT_DIR)/$$name.rs.log"

xml-all-zig:
	@if [ -z "$(FILE)" ]; then echo "Usage: make xml-all-zig FILE=path/to/file.evtx"; exit 1; fi; \
	mkdir -p $(OUT_DIR); \
	name=$$(basename "$(FILE)"); \
	$(ZIG) build -Dtarget=$(TARGET) -Doptimize=$(OPT); \
	args="-o xml"; \
	if [ "$(VERBOSE)" = "1" ]; then args="$$args -v"; fi; \
	zig-out/bin/evtx_dump_zig $$args "$(FILE)" > "$(OUT_DIR)/$$name.zig.xml" 2> "$(OUT_DIR)/$$name.zig.log"

# Normalize XML for fair comparison:
# - Remove XML prolog
# - Expand self-closing tags: <Tag .../> -> <Tag ...></Tag>
define NORMALIZE_XML
sed -E 's#<([A-Za-z0-9:_-]+)([^>/]*)/\>#<\1\2></\1>#g' "$1" | sed '/^<\?xml /d' | sed -E '/^Record [0-9]+$$/d'
endef

compare-all: xml-all-rs xml-all-zig
	@set -e; \
	name=$$(basename "$(FILE)"); \
	rs_raw="$(OUT_DIR)/$$name.rs.xml"; \
	zig_raw="$(OUT_DIR)/$$name.zig.xml"; \
	rs_norm="$(OUT_DIR)/$$name.rs.norm.xml"; \
	zig_norm="$(OUT_DIR)/$$name.zig.norm.xml"; \
	$(call NORMALIZE_XML,$$rs_raw) > "$$rs_norm"; \
	$(call NORMALIZE_XML,$$zig_raw) > "$$zig_norm"; \
	rs_cnt=$$(grep -Ec "<Event( |>)" "$$rs_norm" || true); \
	zig_cnt=$$(grep -Ec "<Event( |>)" "$$zig_norm" || true); \
	echo "Record counts -> rust: $$rs_cnt | zig: $$zig_cnt"; \
	if [ "$$rs_cnt" != "$$zig_cnt" ]; then \
	  echo "WARNING: record count mismatch"; \
	fi; \
	diff_out="$(OUT_DIR)/$$name.diff"; \
	$(DIFF) "$$rs_norm" "$$zig_norm" | tee "$$diff_out" || true; \
	echo "Diff written to $$diff_out";

# Extract and compare a single record by EventRecordID (RID=...) or by ordinal (N=...)
.PHONY: record
record:
	@bash -lc 'set -euo pipefail; \
	if [ -z "$(FILE)" ]; then echo "Usage: make record FILE=path/to/file.evtx [RID=1234 | N=5]"; exit 1; fi; \
	if [ -z "$(RID)" ] && [ -z "$(N)" ]; then echo "Provide RID=<EventRecordID> or N=<ordinal>"; exit 1; fi; \
	name=$$(basename "$(FILE)"); \
	rs_raw="$(OUT_DIR)/$${name}.rs.xml"; \
	zig_raw="$(OUT_DIR)/$${name}.zig.xml"; \
	mkdir -p "$(OUT_DIR)"; \
	if [ ! -f "$${rs_raw}" ] || [ "$(FORCE)" = "1" ]; then \
	  $(MAKE) xml-all-rs FILE="$(FILE)" >/dev/null 2>&1; \
	fi; \
	if [ ! -f "$${zig_raw}" ] || [ "$(FORCE)" = "1" ]; then \
	  $(MAKE) xml-all-zig FILE="$(FILE)" VERBOSE=$(VERBOSE) >/dev/null 2>&1; \
	fi; \
	if [ -n "$(RID)" ]; then \
	  $(PYTHON) scripts/record_diff.py --rs "$${rs_raw}" --zig "$${zig_raw}" --rid "$(RID)" --out-dir "$(OUT_DIR)" --name "$${name}"; \
	else \
	  $(PYTHON) scripts/record_diff.py --rs "$${rs_raw}" --zig "$${zig_raw}" --index "$(N)" --out-dir "$(OUT_DIR)" --name "$${name}"; \
	fi'

