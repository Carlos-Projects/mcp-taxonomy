# Contributing to mcp-taxonomy

We welcome contributions! This document outlines how to contribute.

## Development Setup

```bash
git clone https://github.com/Carlos-Projects/mcp-taxonomy.git
cd mcp-taxonomy
pip install -e ".[dev]"
```

## Code Style

- Type hints required for all public functions
- Follow PEP 8 (enforced by ruff)
- All new adapters must include tests

## Testing

```bash
python -m pytest tests/ -v
```

## Adding a New Adapter

1. Create adapter function in `mcp_taxonomy/`
2. Export from `mcp_taxonomy/__init__.py`
3. Add tests in `tests/`
4. Update the adapter table in README.md

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run `ruff check . && python -m pytest`
5. Commit with descriptive message
6. Push to your fork and open a PR

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md).
