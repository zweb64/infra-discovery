# Infrastructure Discovery

Requires Python 3.11 or newer.

## Development

From the repository root, create and activate a virtual environment (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest
```

The `dev` extra installs pytest. Installing the project makes its `src` package
available to Python and the tests.

## Continuous integration

GitHub Actions runs on pull requests targeting `main` and pushes to `main`.
It uses Python 3.14 on Ubuntu, installs the project and test dependencies with
`python -m pip install ".[dev]"`, and runs the complete suite with
`python -m pytest`.
