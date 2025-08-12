.PHONY: py-wheel py-sdist py-install py-editable py-uv-venv py-ensure-pydust

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


