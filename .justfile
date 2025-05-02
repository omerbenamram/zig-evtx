isort:
    uvx isort --length-sort --profile black --line-length 120 Evtx/ tests/ scripts/

black:
    uvx black --line-length 120 Evtx/ tests/ scripts/

ruff:
    uvx ruff check --line-length 120 Evtx/ tests/ scripts/

mypy:
    uvx mypy --check-untyped-defs --ignore-missing-imports Evtx/ tests/ scripts/

lint:
    -just isort
    -just black
    -just ruff
    # this doesn't pass cleanly today
    #-just mypy

test:
    uv run pytest tests/
