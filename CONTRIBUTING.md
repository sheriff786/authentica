# 🤝 Contributing to Authentica

Thank you for your interest in contributing to Authentica! We welcome all types of contributions. This is a community project, and we'd love your help. Whether it's code, docs, bug reports, or ideas — we appreciate it! 🙌

## ⭐ How to Contribute

- **Report bugs** — Found an issue? Open a GitHub issue
- **Suggest features** — Have an idea? Start a discussion
- **Improve docs** — Help others learn
- **Add tests** — Increase code coverage
- **Submit code** — Implement planned features or fix bugs

---

## 🐛 Reporting Bugs

Found a bug? Here's how to report it:

1. **Check existing issues** — don't create duplicates
2. **Use the bug template** when creating a new issue
3. **Include details**:
   - Python version (`python --version`)
   - OS (Windows, macOS, Linux)
   - Minimal code to reproduce the issue
   - Full error traceback
   - Expected vs actual behavior
4. **Label it**: `bug`, `c2pa`, `watermark`, or `forensics`

---

## 💡 Suggesting Features

Have an idea? We'd love to hear it!

1. **Check the roadmap** (README → planned modules)
2. **Start a discussion** — describe your feature idea
3. **Explain the use case** — why is this important?
4. **Provide examples** — bonus points for code samples

---

## 🔧 Development Setup

### Prerequisites
- Python 3.10+
- Git
- pip or conda

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/authentica.git
cd authentica

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in dev mode with all dependencies
pip install -e ".[dev]"

# (Optional) Install pre-commit hooks
pre-commit install
```

---

## ✅ Running Tests

```bash
# Run all tests with coverage
pytest --cov=src/authentica

# Run specific test file
pytest tests/unit/test_c2pa.py -v

# Run tests matching a pattern
pytest -k "watermark" -v

# Run with verbose output
pytest -vv

# Check coverage report
coverage report
```

**Goal:** Maintain 80%+ code coverage. Always add tests for new features!

---

## 🎨 Code Style & Quality

### Format Code

```bash
# Check for issues
ruff check src/

# Auto-fix
ruff format src/
```

### Type Checking

```bash
mypy src/authentica
```

### Requirements
- ✅ **Type hints** on all public functions
- ✅ **Docstrings** for public APIs (Google style)
- ✅ **Max 100 chars** per line
- ✅ **Clear variable names**

### Example

```python
def detect(self, path: Path | str) -> WatermarkResult:
    """
    Run passive watermark detection on an image.
    
    Args:
        path: Path to image file (JPEG, PNG, WebP, etc).
    
    Returns:
        WatermarkResult containing:
        - detected: bool — watermark found
        - confidence: float — 0-1 confidence score
        - heatmap: 2D array of per-pixel influence
    
    Raises:
        FileNotFoundError: If image doesn't exist.
        ValueError: If image file is corrupted.
    """
    path = Path(path)
    # implementation...
```

---

## 🛠️ Development Setup

---

## 🛠️ Adding a New Analyzer

Want to add a new detection technique? Here's the process:

### Step 1: Create the analyzer
```python
# src/authentica/newmodule/new_analyzer.py
from dataclasses import dataclass
from pathlib import Path

@dataclass
class NewResult:
    detected: bool
    confidence: float  # 0-1
    details: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return asdict(self)

class NewAnalyzer:
    def analyze(self, path: Path | str) -> NewResult:
        path = Path(path)
        # Your logic here
        return NewResult(...)
```

### Step 2: Export from module
```python
# src/authentica/newmodule/__init__.py
from .new_analyzer import NewAnalyzer, NewResult
__all__ = ["NewAnalyzer", "NewResult"]
```

### Step 3: Integrate into core
- Add field to `ScanResult` dataclass
- Wire into `scan()` function
- Update CLI if applicable

### Step 4: Write tests
```python
# tests/unit/test_new_analyzer.py
def test_detect_with_valid_image():
    result = NewAnalyzer().analyze("test.jpg")
    assert result.detected is bool
    assert 0 <= result.confidence <= 1
```

### Step 5: Document
- Add example to README
- Update ARCHITECTURE.md
- Add docstring to classes

### Step 6: Submit PR!

---

## 🏆 Good First Issues

Looking for something to work on?

| Task | Difficulty | Impact |
|------|-----------|--------|
| **Fix documentation typos** | ⭐ Easy | 📚 |
| **Add more unit tests** | ⭐ Easy | 🧪 |
| **Improve error messages** | ⭐ Easy | 👥 |
| **Add CLI documentation** | ⭐⭐ Medium | 📖 |
| **Performance optimizations** | ⭐⭐ Medium | ⚡ |
| **GPU support** | ⭐⭐⭐ Hard | 🚀 |
| **Video support** | ⭐⭐⭐ Hard | 🎬 |

---

## 🤖 Planned Modules

Great opportunities for first-time contributors:

| Module | Description | Status |
|--------|-------------|--------|
| `authentica.llm` | Detect AI-generated text | 🚧 Started |
| `authentica.video` | Frame-level analysis | 📋 Planned |
| `authentica.synthid` | SynthID watermarks | 📋 Planned |

---

## 📝 Commit Guidelines

- Use **descriptive messages**: "Add GPU support for forensics" not "fix bug"
- **Reference issues**: "Fixes #42" or "Closes #123"
- **Keep changes focused**: One feature per commit
- **Template**: `"[Type] Description (#issue)"`

Examples:
- `feat: Add GPU support for FFT analysis (#456)`
- `fix: Handle corrupted PNG files gracefully (#123)`
- `docs: Add watermark detection guide`
- `test: Improve forensics test coverage to 90%`

---

## 🔄 Pull Request Process

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```

2. **Make your changes** following our style guide

3. **Add tests** — new code must have tests

4. **Run tests locally**:
   ```bash
   pytest --cov
   ruff check src/
   mypy src/
   ```

5. **Commit with clear messages**

6. **Push and create a Pull Request**:
   ```bash
   git push origin feature/my-feature
   ```

7. **Describe what you changed** — reference related issues

8. **Respond to review feedback** — maintainers will give tips

9. **Enjoy!** — Your code is merged and shipped 🚀

---

## 📞 Getting Help

- **Questions?** → Open a discussion (not an issue)
- **Stuck?** → Tag a maintainer: @yourusername
- **Chat?** → Discord/Slack (coming soon)
- **Docs** → See README and docstrings

---

## 🙏 Thanks!

Every contribution — big or small — makes Authentica better. Thank you for being part of this community! 💙
