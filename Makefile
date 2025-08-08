ZIG ?= zig
TARGET ?= native
OPT ?= ReleaseFast
FORMAT ?= xml
VERBOSE ?= 0
PYTHON ?= python3

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
	awk 'BEGIN{RS="</Event>"; ORS="</Event>\n"} NR==1 {print}' "$(OUT_DIR)/$$name.rs.xml" | sed '/^<\?xml /d' > "$(OUT_DIR)/$$name.rs.one.xml"; \
	awk 'BEGIN{RS="</Event>"; ORS="</Event>\n"} NR==1 {print}' "$(OUT_DIR)/$$name.zig.xml" | sed '/^<\?xml /d' > "$(OUT_DIR)/$$name.zig.one.xml"; \
	$(DIFF) "$(OUT_DIR)/$$name.rs.one.xml" "$(OUT_DIR)/$$name.zig.one.xml" || true

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

