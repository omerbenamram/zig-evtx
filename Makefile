ZIG ?= zig
TARGET ?= native
OPT ?= ReleaseFast
FORMAT ?= xml
VERBOSE ?= 0

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
	cargo install evtx || true

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

