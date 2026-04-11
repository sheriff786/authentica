# Contributing to Authentica

Thank you for your interest in contributing! 🎉

## Development setup

```bash
git clone https://github.com/yourusername/authentica
cd authentica
pip install -e ".[dev]"
pre-commit install
```

## Running tests

```bash
pytest                          # all tests with coverage
pytest tests/unit/ -v          # unit tests only
pytest -k "test_c2pa" -v       # filter by name
```

## Code style

We use `ruff` for linting and formatting:

```bash
ruff check src/
ruff format src/
```

Type annotations are required on all public functions. Run mypy:

```bash
mypy src/authentica
```

## Adding a new analyzer

1. Create `src/authentica/<module>/your_analyzer.py`
2. Define a `YourResult` dataclass with `to_dict()` and `detected: bool`
3. Define a `YourAnalyzer` class with `detect(path: Path) -> YourResult`
4. Export from the module `__init__.py`
5. Wire into `core.py`'s `scan()` and `cli/main.py`
6. Add unit tests in `tests/unit/`

## Planned modules (great first contributions!)

| Module | Description |
|--------|-------------|
| `authentica.llm` | LLM text detector — perplexity + KGW watermark |
| `authentica.video` | Frame-level scan for MP4/MOV |
| `authentica.synthid` | Google SynthID watermark detection |

## Publishing to PyPI

```bash
pip install build twine
python -m build
twine upload dist/*
```
