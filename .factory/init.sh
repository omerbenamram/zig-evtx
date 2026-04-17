#!/bin/sh
set -eu

if [ ! -d ".venv" ]; then
  uv venv .venv >/dev/null
fi
