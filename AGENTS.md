# Agent Instructions

This file contains setup, test, and style instructions for agents working on this repository.

## Setup

1. Ensure Python 3.14 is installed.
2. Install the project dependencies:
   ```shell
   pip install -r requirement.txt
   pip install -r tests/test-requirement.txt
   ```
   Alternatively, using `uv`:
   ```shell
   uv pip install -r requirement.txt
   uv pip install -r tests/test-requirement.txt
   ```

## Testing

Run the test suite with pytest:
```shell
pytest -m "not docker" --cov=./ --cov-report=xml:coverage.xml --cov-report=term-missing
```

Run static type checking with mypy:
```shell
mypy
```

Run the linter and formatter checks with ruff:
```shell
ruff format --check
ruff check
```

## Style

- Follow the existing Python code style.
- All code must pass `ruff check` and `ruff format --check`.
- All code must pass `mypy` with the strict configuration defined in `.mypy.ini`.
