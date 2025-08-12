### Top-level Makefile (thin) -> includes modular fragments in makefiles/

# ---- Environment (kept at top) ----
ZIG ?= zig
TARGET ?= native
OPT ?= ReleaseFast
TEST_OPT ?= Debug
FORMAT ?= xml
VERBOSE ?= 0
PYTHON ?= python3

# Control libc usage and python extension via env
# USE_C_ALLOC=1 uses std.heap.c_allocator and links libc
# WITH_PYTHON=1 builds the pydust extension module
USE_C_ALLOC ?= 1
WITH_PYTHON ?= 0
# Map numeric env to Zig booleans
ifeq ($(USE_C_ALLOC),1)
  USE_C_ALLOC_BOOL := true
else
  USE_C_ALLOC_BOOL := false
endif
ifeq ($(WITH_PYTHON),1)
  WITH_PYTHON_BOOL := true
else
  WITH_PYTHON_BOOL := false
endif

# Always clear venvs non-interactively when using uv
export UV_VENV_CLEAR=1

# Use bash for complex recipes (avoids fish/sh incompatibilities)
SHELL := /bin/bash

# Compare tools
EVTX_DUMP ?= evtx_dump
OUT_DIR ?= out
DIFF ?= diff -u

# Python tooling
UV ?= uv
VENV ?= .venv
# Default to venv python; caller can override. This is used by zig build via -Dpython-exe
PYTHON_EXE ?= $(VENV)/bin/python

# Default multi-target set; override from CLI if needed
TARGETS ?= x86_64-linux aarch64-linux x86_64-windows aarch64-windows x86_64-macos aarch64-macos

# ---- Includes ----
include makefiles/zig.mk
include makefiles/flamegraph.mk
include makefiles/compare.mk
include makefiles/lldb.mk
include makefiles/python.mk


