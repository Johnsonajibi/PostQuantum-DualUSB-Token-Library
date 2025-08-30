# Contributing to PostQuantum DualUSB Token Library

Thank you for your interest in contributing! This document provides guidelines for contributing to this project.

## Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow:
- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## How to Contribute

### Reporting Bugs
- Use the GitHub Issues template
- Include steps to reproduce
- Provide system information (OS, Python version)
- Include relevant log outputs

### Suggesting Features
- Check existing issues first
- Provide clear use cases
- Consider security implications
- Discuss implementation approach

### Development Process

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YOUR_USERNAME/PostQuantum-DualUSB-Token-Library.git
   cd PostQuantum-DualUSB-Token-Library
   ```

2. **Set up Development Environment**
   ```bash
   pip install -e ".[dev]"
   pre-commit install
   ```

3. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Make Changes**
   - Follow PEP 8 style guidelines
   - Add tests for new functionality
   - Update documentation as needed
   - Ensure security best practices

5. **Test Your Changes**
   ```bash
   python -m pytest tests/ -v
   python simple_test.py
   black --check .
   ruff check .
   ```

6. **Submit Pull Request**
   - Use clear, descriptive commit messages
   - Reference related issues
   - Include test results
   - Update CHANGELOG.md

## Development Guidelines

### Security First
- All cryptographic operations must be reviewed
- Memory management must be secure
- Input validation is mandatory
- Timing attacks must be considered

### Code Quality
- Minimum 80% test coverage
- Type hints required
- Docstrings for all public APIs
- Error handling must be comprehensive

### Performance
- Profile memory usage
- Benchmark cryptographic operations
- Test on multiple platforms
- Consider USB device variations

## Testing

### Test Categories
- **Unit Tests**: Core functionality
- **Integration Tests**: USB device interaction
- **Security Tests**: Cryptographic validation
- **Performance Tests**: Benchmarking

### Running Tests
```bash
# All tests
python -m pytest tests/ -v --cov=dual_usb_backup

# Security-specific tests
python simple_test.py

# Performance benchmarks
python tests/benchmark.py
```

## Security Considerations

### Sensitive Data Handling
- Never log passphrases or keys
- Use secure memory allocation
- Clear sensitive data after use
- Validate all inputs thoroughly

### Cryptographic Standards
- Use only well-established algorithms
- Follow NIST recommendations
- Consider post-quantum implications
- Regular security audits

## Documentation

- Update README.md for user-facing changes
- Add docstrings for new functions
- Include usage examples
- Document security considerations

## Release Process

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Create release tag
4. Build and upload to PyPI
5. Create GitHub release

Thank you for contributing to the security of digital assets!
