.PHONY: install-flamegraph flamegraph flamegraph-prod

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
	rm -rf "$(OUT_DIR)" || true; \
	mkdir -p "$(OUT_DIR)"; \
	echo "Building Debug for better symbols..."; \
	$(MAKE) build OPT=Debug >/dev/null; \
	if [ ! -f "$(FLAME_FILE)" ]; then echo "Missing FLAME_FILE: $(FLAME_FILE)"; exit 1; fi; \
	echo "Starting target on $(FLAME_FILE)..."; \
	"$(BIN)" -t 1 -o $(FORMAT) "$(FLAME_FILE)" >/dev/null 2>&1 & echo $$! > "$(OUT_DIR)/app.pid"; \
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
	perl -ne 'if (/<title>([^<]+) \((\d+(?:\.[\d]+)?)%\)/) { print $$2, " ", $$1, "\n" }' "$(SVG_FILE)" | sort -nr | head -n 30 > "$(OUT_DIR)/top_titles.txt"; \
	echo "Done. Outputs:"; \
	ls -lh "$(OUT_DIR)" | cat

.PHONY: flamegraph-prod
# Production-like flamegraph: ReleaseFast with symbols (strip=false)
flamegraph-prod: install-flamegraph
	@set -euo pipefail; \
	rm -rf "$(OUT_DIR)" || true; \
	mkdir -p "$(OUT_DIR)"; \
	echo "Building ReleaseFast..."; \
	$(MAKE) build OPT=ReleaseFast >/dev/null; \
	if [ ! -f "$(FLAME_FILE)" ]; then echo "Missing FLAME_FILE: $(FLAME_FILE)"; exit 1; fi; \
	echo "Starting target on $(FLAME_FILE)..."; \
	"$(BIN)" -t 1 -o $(FORMAT) "$(FLAME_FILE)" >/dev/null 2>&1 & echo $$! > "$(OUT_DIR)/app.pid"; \
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
	perl -ne 'if (/<title>([^<]+) \((\d+(?:\.[\d]+)?)%\)/) { print $$2, " ", $$1, "\n" }' "$(SVG_FILE)" | sort -nr | head -n 30 > "$(OUT_DIR)/top_titles.txt"; \
	echo "Done. Outputs:"; \
	ls -lh "$(OUT_DIR)" | cat


