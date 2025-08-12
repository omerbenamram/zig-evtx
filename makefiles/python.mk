.PHONY: py-wheel py-sdist py-install py-editable py-uv-venv py-ensure-pydust py-wheel-dump

UV ?= uv
VENV ?= .venv
PYTHON_EXE ?= $(VENV)/bin/python

py-uv-venv:
	@set -euo pipefail; \
	if ! command -v $(UV) >/dev/null 2>&1; then echo "uv not found. Install via: brew install uv"; exit 1; fi; \
	$(UV) venv $(VENV) >/dev/null; \
	echo "venv ready at $(VENV)"

# Ensure pydust (ziggy-pydust) is available for the Zig build script's Python discovery
py-ensure-pydust: py-uv-venv
	@set -euo pipefail; \
	$(UV) pip install "ziggy-pydust==0.25.1" >/dev/null; \
	echo "pydust ready in $(VENV)"

py-wheel: py-ensure-pydust
	@set -euo pipefail; \
	$(ZIG) build -Dtarget=$(TARGET) -Doptimize=$(OPT) -Dpython-exe=$(PYTHON_EXE) -Duse-c-alloc=$(USE_C_ALLOC_BOOL) -Dwith-python=true >/dev/null; \
	$(UV) pip install build >/dev/null; \
	$(UV) run -m build -w

py-sdist: py-ensure-pydust
	@set -euo pipefail; \
	$(ZIG) build -Dtarget=$(TARGET) -Doptimize=$(OPT) -Dpython-exe=$(PYTHON_EXE) -Duse-c-alloc=$(USE_C_ALLOC_BOOL) -Dwith-python=false >/dev/null; \
	$(UV) pip install build >/dev/null; \
	$(UV) run -m build -s

py-install: py-ensure-pydust
	@set -euo pipefail; \
	$(ZIG) build -Dtarget=$(TARGET) -Doptimize=$(OPT) -Dpython-exe=$(PYTHON_EXE) -Duse-c-alloc=$(USE_C_ALLOC_BOOL) -Dwith-python=true >/dev/null; \
	$(UV) pip install .

py-editable: py-ensure-pydust
	@set -euo pipefail; \
	$(ZIG) build -Dtarget=$(TARGET) -Doptimize=$(OPT) -Dpython-exe=$(PYTHON_EXE) -Duse-c-alloc=$(USE_C_ALLOC_BOOL) -Dwith-python=true >/dev/null; \
	$(UV) pip install -e .


# Run the Python CLI against a sample using the freshly built wheel via uv --with
# Usage: make py-wheel-dump [FILE=path/to/file.evtx] [FORMAT=xml|json|jsonl] [VERBOSE=0|1|2|3] [SKIP_FIRST=N] [MAX_RECORDS=N] [NO_CHECKS=1]
py-wheel-dump: py-wheel
	@set -euo pipefail; \
	WHEEL=$$(ls -t dist/*.whl | head -1); \
	file="$${FILE:-samples/system.evtx}"; \
	fmt="$${FORMAT:-xml}"; \
	vflag=""; \
	case "$${VERBOSE:-0}" in \
	  1) vflag="-v";; \
	  2) vflag="-vv";; \
	  3) vflag="-vvv";; \
	  *) vflag="";; \
	esac; \
	cmd=( $(UV) run --with "$$WHEEL" python -u scripts/evtx_dump.py ); \
	if [ -n "$$vflag" ]; then cmd+=( "$$vflag" ); fi; \
	cmd+=( -o "$$fmt" ); \
	if [ -n "$${SKIP_FIRST:-}" ]; then cmd+=( -s "$${SKIP_FIRST}" ); fi; \
	if [ -n "$${MAX_RECORDS:-}" ]; then cmd+=( -n "$${MAX_RECORDS}" ); fi; \
	if [ "$${NO_CHECKS:-0}" = "1" ]; then cmd+=( --no-checks ); fi; \
	cmd+=( "$$file" ); \
	echo "Running: $${cmd[*]}"; \
	"$${cmd[@]}"


