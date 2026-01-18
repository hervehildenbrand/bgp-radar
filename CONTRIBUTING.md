# Contributing to bgp-radar

Thank you for your interest in contributing to bgp-radar!

## How to Contribute

### Reporting Bugs

- Check if the bug has already been reported in [Issues](https://github.com/hervehildenbrand/bgp-radar/issues)
- If not, create a new issue with:
  - Clear title and description
  - Steps to reproduce
  - Expected vs actual behavior
  - Version information (`bgp-radar --version`)

### Suggesting Features

- Open an issue describing the feature
- Explain the use case and benefits
- Be open to discussion about implementation

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test`)
5. Run linter (`make lint`)
6. Commit with a clear message
7. Push to your fork
8. Open a Pull Request

### Code Style

- Follow standard Go conventions
- Run `gofmt -s -w .` before committing
- Add tests for new functionality
- Keep commits atomic and well-described

### Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run linter
make lint
```

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/bgp-radar.git
cd bgp-radar

# Install dependencies
go mod download

# Build
make build

# Run tests
make test
```

## Code of Conduct

Be respectful and constructive in all interactions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
