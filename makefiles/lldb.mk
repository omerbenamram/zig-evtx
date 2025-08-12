.PHONY: lldb lldb-py

lldb:
		@set -u; \
		if ! command -v lldb >/dev/null 2>&1; then echo "lldb not found"; exit 1; fi; \
		$(MAKE) build OPT=Debug >/dev/null; \
		args="$(ARGS)"; \
		if [ -z "$$args" ]; then args="-vv -t 1 -o xml ./samples/system.evtx"; fi; \
		lldb --batch \
		  -o "settings set auto-confirm true" \
		  -k "bt all" \
		  -k "thread list" \
		  -k "register read" \
		  -k "quit" \
		  -o "run" \
		  -- zig-out/bin/evtx_dump_zig $$args 2>&1 | cat || true

lldb-py:
	@set -u; \
	if ! command -v lldb >/dev/null 2>&1; then echo "lldb not found"; exit 1; fi; \
	$(MAKE) build OPT=Debug >/dev/null; \
	exe="$(PYTHON_EXE)"; \
	if [ ! -x "$$exe" ]; then exe=".venv/bin/python"; fi; \
	script="$(PWD)/scripts/py_iter_from_io.py"; \
	lldb --batch \
	  -o "settings set auto-confirm true" \
	  -k "bt all" \
	  -k "thread list" \
	  -k "register read" \
	  -k "quit" \
	  -o "run" \
	  -- $$exe $$script 2>&1 | cat || true


