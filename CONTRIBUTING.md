# Contribution guidelines

Contributing to this project should be as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features

## Github is used for everything

Github is used to host code, to track issues and feature requests, as well as accept pull requests.

Pull requests are the best way to propose changes to the codebase.

1. Fork the repo and create your branch from `main`.
2. If you've changed something, update the documentation.
3. Make sure your code lints (using `scripts/lint`).
4. Test you contribution.
5. Issue that pull request!

## Any contributions you make will be under the MIT Software License

In short, when you submit code changes, your submissions are understood to be under the same [MIT License](http://choosealicense.com/licenses/mit/) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using Github's [issues](../../issues)

GitHub issues are used to track public bugs.
Report a bug by [opening a new issue](../../issues/new/choose); it's that easy!

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can.
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

People *love* thorough bug reports. I'm not even kidding.

## Use a Consistent Coding Style

Use [black](https://github.com/ambv/black) to make sure the code follows the style.

## Test your code modification

This custom component is based on [integration_blueprint template](https://github.com/ludeeus/integration_blueprint).

It comes with development environment in a container, easy to launch
if you use Visual Studio Code. With this container you will have a stand alone
Home Assistant instance running and already configured with the included
[`configuration.yaml`](./config/configuration.yaml)
file.

### Running Tests

The project includes a comprehensive test suite to ensure code quality and functionality.

#### Prerequisites

Make sure you have the required dependencies installed:

```bash
pip install -r requirements.txt
```

#### Running Tests Locally

You can run tests using the provided script:

```bash
./scripts/test
```

Or run pytest directly:

```bash
python -m pytest tests/ -v --tb=short
```

#### Test Structure

- `tests/` - Contains all test files
- `tests/conftest.py` - Test configuration and shared fixtures
- `tests/test_init.py` - Integration initialization tests
- `pytest.ini` - Pytest configuration

#### Writing Tests

When adding new features or fixing bugs, please add corresponding tests:

1. Create test files following the pattern `test_*.py`
2. Use the provided fixtures in `conftest.py` for common test setup
3. Follow Home Assistant testing guidelines
4. Ensure tests are fast and don't require external dependencies

#### Continuous Integration

Tests are automatically run on every push and pull request using GitHub Actions.
The CI runs tests on Python 3.11 and 3.12, and includes linting checks.

## License

By contributing, you agree that your contributions will be licensed under its MIT License.
