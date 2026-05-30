# Contributing to mcp-taxonomy

👋 **Welcome to MCP Taxonomy!**

Thank you for contributing to the canonical classification taxonomy for the MCP security ecosystem. Whether you're adding a new adapter, improving enum coverage, or fixing a bug — your work helps unify how security findings are classified across all our tools.

## First Time Contributor?

Here's how to get started:

- Look for issues labeled `good first issue`
- Add a new adapter for a security tool — the pattern is well-documented
- Improve test coverage or add edge cases
- Help improve documentation or add more adapter examples

We welcome contributors of all backgrounds. Your perspective makes this taxonomy better!

## Need Help?

Questions or feedback?

- Open a [GitHub Issue](https://github.com/Carlos-Projects/mcp-taxonomy/issues)
- Check existing issues first
- Include details about what you're building and what's not working

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

---

💡 This project is governed by a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold its principles.
