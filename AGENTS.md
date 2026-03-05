# AWS Security Hub MCP Server Development Guidelines

## Python Environment & Dependency Management (Strict Rules)
This project strictly uses `uv` for Python virtual environment and dependency management. 
**Do NOT** use the system's global `python`, `pip`, or standard `venv` commands under any situation.

Please adhere to the following command mappings for any Python-related operations:
* **Running tests/scripts:** Always use `uv run <command>`. (e.g., `uv run pytest`, `uv run python script.py`)
* **Adding packages:** Always use `uv add <package>`. Do NOT use `pip install`.
* **Adding dev packages:** Always use `uv add --dev <package>`.
* **Syncing environment:** Use `uv sync --all-extras`.

Failure to use `uv` will result in broken dependencies. Always prepend `uv run` to execute anything within the project's virtual environment.

## Repository Structure

```
├── src/
│   └── aws_securityhub_mcp_server/
│       └── server.py        # MCP Server main implementation
└── tests/                   # Tests
```
