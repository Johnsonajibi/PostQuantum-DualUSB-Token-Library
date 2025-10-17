# Contributing to the PQC Dual USB Library

Thank you for your interest in contributing! This document provides guidelines for contributing to this project. By participating, you are expected to uphold our Code of Conduct.

## How to Contribute

We welcome contributions in the form of bug reports, feature suggestions, and pull requests.

### Reporting Bugs & Suggesting Features
-   **Use GitHub Issues**: Please use the issue templates for bugs or feature requests.
-   **Be Detailed**: For bugs, provide steps to reproduce, your OS, Python version, and any relevant logs. For features, explain the use case and security implications.

### Development Process

1.  **Fork & Clone**: Fork the repository and clone it to your local machine.
    ```bash
    git clone https://github.com/YOUR_USERNAME/PostQuantum-DualUSB-Token-Library.git
    cd PostQuantum-DualUSB-Token-Library
    ```

2.  **Set up Development Environment**: Create a virtual environment and install the library in editable mode with development dependencies.
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    pip install -e ".[dev]"
    ```

3.  **Install Pre-commit Hooks**: This will automatically format and lint your code before each commit.
    ```bash
    pre-commit install
    ```

4.  **Create a Feature Branch**:
    ```bash
    git checkout -b feature/your-awesome-feature
    ```

5.  **Make Your Changes**:
    -   Write clean, readable code that follows PEP 8.
    -   Add or update tests for any new functionality.
    -   Update documentation (`README.md`, docstrings) as needed.
    -   Always prioritize security.

6.  **Test Your Changes**: Run the full test suite and linters to ensure everything is working correctly.
    ```bash
    # Run all unit tests with verbose output
    python -m pytest tests/ -v

    # Check code formatting and style
    black --check .
    isort --check .
    flake8 .
    ```

7.  **Submit a Pull Request**:
    -   Push your branch to your fork and open a pull request.
    -   Provide a clear description of your changes and reference any related issues.
    -   Ensure all automated checks (CI) are passing.

## Development Guidelines

### Security First
-   **Input Validation is Mandatory**: Never trust external input.
-   **Secure Memory Handling**: Use the provided utilities to clear sensitive data from memory after use.
-   **Constant-Time Operations**: Use constant-time comparisons for cryptographic secrets to prevent timing attacks.
-   **Review Cryptographic Code**: All changes to cryptographic functions require careful review.

### Code Quality
-   **Test Coverage**: Aim to maintain or increase test coverage.
-   **Type Hinting**: All new functions and methods should include type hints.
-   **Docstrings**: Public APIs must have clear and comprehensive docstrings.

## Testing

The project uses `pytest` for testing. Tests are located in the `tests/` directory.

### Running Tests
```bash
# Install test dependencies (included in the 'dev' extra)
pip install -e ".[dev]"
