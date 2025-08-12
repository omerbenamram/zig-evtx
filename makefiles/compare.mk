.PHONY: install-evtx xml-rs xml-zig compare-first xml-all-rs xml-all-zig compare-all record compare-time time-zig time-rust json-rs json-zig compare-json jsonl-rs jsonl-zig compare-jsonl

EVTX_DUMP ?= evtx_dump
OUT_DIR ?= out
DIFF ?= diff -u

install-evtx:
	@command -v $(EVTX_DUMP) >/dev/null 2>&1 || cargo install evtx >/dev/null 2>&1 || true

xml-rs: install-evtx
	@if [ -z "$(FILE)" ]; then echo "Usage: make xml-rs FILE=path/to/file.evtx"; exit 1; fi; \
	mkdir -p $(OUT_DIR); \
	name=$$(basename "$(FILE)"); \
	rm -f "$(OUT_DIR)/$$name.rs.xml"; \
	$(EVTX_DUMP) -t 1 -o xml -f "$(OUT_DIR)/$$name.rs.xml" "$(FILE)"

xml-zig: build-zig
	@if [ -z "$(FILE)" ]; then echo "Usage: make xml-zig FILE=path/to/file.evtx"; exit 1; fi; \
	mkdir -p $(OUT_DIR); \
	name=$$(basename "$(FILE)"); \
    	# built via build-zig above; ensure binary exists
	zig-out/bin/evtx_dump_zig -o xml -n 1 "$(FILE)" > "$(OUT_DIR)/$$name.zig.xml"

compare-first: xml-rs xml-zig
	name=$$(basename "$(FILE)"); \
	$(PYTHON) scripts/record_diff.py --rs "$(OUT_DIR)/$$name.rs.xml" --zig "$(OUT_DIR)/$$name.zig.xml" --index 1 --out-dir "$(OUT_DIR)" --name "$$name"

xml-all-rs: install-evtx
	@if [ -z "$(FILE)" ]; then echo "Usage: make xml-all-rs FILE=path/to/file.evtx"; exit 1; fi; \
	mkdir -p $(OUT_DIR); \
	name=$$(basename "$(FILE)"); \
	rm -f "$(OUT_DIR)/$$name.rs.xml"; \
	$(EVTX_DUMP) -t 1 -o xml -f "$(OUT_DIR)/$$name.rs.xml" "$(FILE)" 2> "$(OUT_DIR)/$$name.rs.log"

xml-all-zig: build-zig
	@if [ -z "$(FILE)" ]; then echo "Usage: make xml-all-zig FILE=path/to/file.evtx"; exit 1; fi; \
	mkdir -p $(OUT_DIR); \
	name=$$(basename "$(FILE)"); \
    	# built via build-zig above; ensure binary exists
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

record:
	@bash -lc 'set -euo pipefail; \
	if [ -z "$(FILE)" ]; then echo "Usage: make record FILE=path/to/file.evtx [RID=1234 | N=5]"; exit 1; fi; \
	if [ -z "$(RID)" ] && [ -z "$(N)" ]; then echo "Provide RID=<EventRecordID> or N=<ordinal>"; exit 1; fi; \
	name=$$(basename "$(FILE)"); \
	rs_raw="$(OUT_DIR)/$${name}.rs.xml"; \
	zig_raw="$(OUT_DIR)/$${name}.zig.xml"; \
	mkdir -p "$(OUT_DIR)"; \
	if [ ! -f "$$rs_raw" ] || [ "$(FORCE)" = "1" ]; then \
	  $(MAKE) xml-all-rs FILE="$(FILE)" >/dev/null 2>&1; \
	fi; \
	if [ ! -f "$$zig_raw" ] || [ "$(FORCE)" = "1" ]; then \
	  $(MAKE) xml-all-zig FILE="$(FILE)" VERBOSE=$(VERBOSE) >/dev/null 2>&1; \
	fi; \
	if [ -n "$(RID)" ]; then \
	  $(PYTHON) scripts/record_diff.py --rs "$$rs_raw" --zig "$$zig_raw" --rid "$(RID)" --out-dir "$(OUT_DIR)" --name "$$name"; \
	else \
	  $(PYTHON) scripts/record_diff.py --rs "$$rs_raw" --zig "$$zig_raw" --index "$(N)" --out-dir "$(OUT_DIR)" --name "$$name"; \
	fi'

compare-time: install-evtx time-zig time-rust
	@set -euo pipefail; \
	zig_file="$(OUT_DIR)/time-zig.txt"; \
	rs_file="$(OUT_DIR)/time-rs.txt"; \
	norm_z="$(OUT_DIR)/time-zig.norm.tsv"; \
	norm_r="$(OUT_DIR)/time-rs.norm.tsv"; \
	# Normalize both time outputs into TAB-separated "Metric<TAB>Value" lines; \
	# handle both the real/user/sys line and the macOS -l resource lines. \
	awk 'function emit(k,v){ printf "%s\t%s\n", k, v } { if ($$0 ~ /[0-9.]+[[:space:]]+real/ && $$0 ~ /user/ && $$0 ~ /sys/) { for (i=1;i<=NF;i+=2){ v=$$(i); k=$$(i+1); if (k=="real"||k=="user"||k=="sys") emit(k,v) } } else if (match($$0,/^([0-9.]+)[[:space:]]+(.*)$$/,m)) { emit(m[2], m[1]) } }' "$$zig_file" | sort > "$$norm_z"; \
	awk 'function emit(k,v){ printf "%s\t%s\n", k, v } { if ($$0 ~ /[0-9.]+[[:space:]]+real/ && $$0 ~ /user/ && $$0 ~ /sys/) { for (i=1;i<=NF;i+=2){ v=$$(i); k=$$(i+1); if (k=="real"||k=="user"||k=="sys") emit(k,v) } } else if (match($$0,/^([0-9.]+)[[:space:]]+(.*)$$/,m)) { emit(m[2], m[1]) } }' "$$rs_file" | sort > "$$norm_r"; \
	out_tsv="$(OUT_DIR)/time-compare.tsv"; \
	{ echo -e "Metric\tZig\tRust"; \
	  join -t $$'\t' -a1 -a2 -e '-' -o '0,1.2,2.2' "$$norm_z" "$$norm_r" | sort; \
	} > "$$out_tsv"; \
	echo "--- time comparison ---"; \
	if command -v column >/dev/null 2>&1; then column -t -s $$'\t' "$$out_tsv" | sed 's/^/  /'; else cat "$$out_tsv"; fi; \
	echo "Wrote $$out_tsv"

time-zig: py-ensure-pydust
	@set -euo pipefail; \
	if [ -z "$(FILE)" ]; then echo "Usage: make time-zig FILE=path/to/file.evtx [OPT=ReleaseFast]"; exit 1; fi; \
	mkdir -p $(OUT_DIR); \
	echo "Building Zig ($(OPT))..."; \
		$(ZIG) build -Dtarget=$(TARGET) -Doptimize=$(OPT) -Dpython-exe=$(PYTHON_EXE) -Duse-c-alloc=$(USE_C_ALLOC) -Dwith-python=$(WITH_PYTHON) >/dev/null; \
	echo "Timing Zig..."; \
	/usr/bin/time -l zig-out/bin/evtx_dump_zig --no-checks -t 1 -o xml "$(FILE)" >/dev/null 2> "$(OUT_DIR)/time-zig.txt"; \
	echo "--- tail(time-zig) ---"; tail -n 8 "$(OUT_DIR)/time-zig.txt" | cat; \
	echo "Output written to $(OUT_DIR)/time-zig.txt"

time-rust: install-evtx
	@set -euo pipefail; \
	if [ -z "$(FILE)" ]; then echo "Usage: make time-rust FILE=path/to/file.evtx"; exit 1; fi; \
	mkdir -p $(OUT_DIR); \
	echo "Timing Rust (evtx_dump)..."; \
	/usr/bin/time -l $(EVTX_DUMP) -t 1 -o xml "$(FILE)" >/dev/null 2> "$(OUT_DIR)/time-rs.txt"; \
	echo "--- tail(time-rs) ---"; tail -n 8 "$(OUT_DIR)/time-rs.txt" | cat; \
	echo "Output written to $(OUT_DIR)/time-rs.txt"

json-rs: install-evtx
	@if [ -z "$(FILE)" ]; then echo "Usage: make json-rs FILE=path/to/file.evtx"; exit 1; fi; \
	mkdir -p $(OUT_DIR); \
	name=$$(basename "$(FILE)"); \
	rm -f "$(OUT_DIR)/$$name.rs.jsonl"; \
	$(EVTX_DUMP) -t 1 -o jsonl "$(FILE)" > "$(OUT_DIR)/$$name.rs.jsonl"

json-zig: build-zig
	@if [ -z "$(FILE)" ]; then echo "Usage: make json-zig FILE=path/to/file.evtx [STYLE=default|evtxrs]"; exit 1; fi; \
	mkdir -p $(OUT_DIR); \
	name=$$(basename "$(FILE)"); \
	STYLE=$${STYLE:-evtxrs}; \
	args="-o jsonl"; \
	if [ "$$STYLE" = "evtxrs" ]; then args="$$args --json-style evtxrs"; fi; \
	zig-out/bin/evtx_dump_zig $$args "$(FILE)" > "$(OUT_DIR)/$$name.zig.jsonl"

compare-json: json-rs json-zig
	@set -e; \
	name=$$(basename "$(FILE)"); \
	jq -c . < "$(OUT_DIR)/$$name.rs.jsonl" > "$(OUT_DIR)/$$name.rs.norm.jsonl"; \
	jq -c . < "$(OUT_DIR)/$$name.zig.jsonl" > "$(OUT_DIR)/$$name.zig.norm.jsonl"; \
	$(DIFF) "$(OUT_DIR)/$$name.rs.norm.jsonl" "$(OUT_DIR)/$$name.zig.norm.jsonl" | tee "$(OUT_DIR)/$$name.json.diff" || true; \
	echo "JSON diff written to $(OUT_DIR)/$$name.json.diff"

jsonl-rs: install-evtx
	@if [ -z "$(FILE)" ]; then echo "Usage: make jsonl-rs FILE=path/to/file.evtx"; exit 1; fi; \
	mkdir -p $(OUT_DIR); \
	name=$$(basename "$(FILE)"); \
	rm -f "$(OUT_DIR)/$$name.rs.jsonl"; \
	$(EVTX_DUMP) -t 1 -o jsonl "$(FILE)" > "$(OUT_DIR)/$$name.rs.jsonl"

jsonl-zig: build-zig
	@if [ -z "$(FILE)" ]; then echo "Usage: make jsonl-zig FILE=path/to/file.evtx [STYLE=default|evtxrs]"; exit 1; fi; \
	mkdir -p $(OUT_DIR); \
	name=$$(basename "$(FILE)"); \
	STYLE=$${STYLE:-evtxrs}; \
	args="-o jsonl"; \
	if [ "$$STYLE" = "evtxrs" ]; then args="$$args --json-style evtxrs"; fi; \
	zig-out/bin/evtx_dump_zig $$args "$(FILE)" > "$(OUT_DIR)/$$name.zig.jsonl"

compare-jsonl: jsonl-rs jsonl-zig
	@set -e; \
	name=$$(basename "$(FILE)"); \
	jq -c . < "$(OUT_DIR)/$$name.rs.jsonl" > "$(OUT_DIR)/$$name.rs.norm.jsonl"; \
	jq -c . < "$(OUT_DIR)/$$name.zig.jsonl" > "$(OUT_DIR)/$$name.zig.norm.jsonl"; \
	$(DIFF) "$(OUT_DIR)/$$name.rs.norm.jsonl" "$(OUT_DIR)/$$name.zig.norm.jsonl" | tee "$(OUT_DIR)/$$name.jsonl.diff" || true; \
	echo "JSONL diff written to $(OUT_DIR)/$$name.jsonl.diff"


