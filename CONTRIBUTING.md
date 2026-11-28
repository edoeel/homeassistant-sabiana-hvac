# Contributing to Home Assistant Sabiana HVAC

Thank you for your interest in contributing to the Home Assistant Sabiana HVAC integration! This document provides guidelines and instructions for contributing to this project.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Environment Setup](#development-environment-setup)
- [AI-assisted contributions](#ai-assisted-contributions)
- [Code of Conduct](#code-of-conduct)
- [License](#license)


## Getting Started

### Prerequisites

- [Docker](https://www.docker.com/) installed on your system
- [Git](https://git-scm.com/) for version control
- [Visual Studio Code](https://code.visualstudio.com/) (recommended)
- [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) for VS Code

### Fork and Clone the Repository

1. Fork the repository
2. Clone your fork
3. Add the upstream remote
4. Create a new branch for your changes

## Development Environment Setup

This custom component is based on the [integration_blueprint template](https://github.com/ludeeus/integration_blueprint).

### VS Code with Dev Containers

1. **Open the project in VS Code**
   ```bash
   code .
   ```

2. **Reopen in Container**
   - When prompted, click "Reopen in Container"
   - Or use Command Palette (`Ctrl+Shift+P`) and select "Dev Containers: Reopen in Container"
   - Wait for the container to build and start

3. **Start Home Assistant**
   ```bash
   scripts/develop
   ```
   - This command will start the Home Assistant development environment
   - Wait for Home Assistant to fully initialize

### Local Setup without Dev Containers

You can also run everything directly on your machine (Linux, macOS, WSL2).

1. **Install a recent Python**

   The pinned Home Assistant version (see `requirements.txt`) requires **Python 3.14.2 or newer**. Older interpreters fail with `No matching distribution found for homeassistant==...`.
   The easiest way is [`uv`](https://docs.astral.sh/uv/), which downloads the right interpreter for you without touching the system Python.

2. **Create the virtual environment and install dependencies**

   With `uv`:
   ```bash
   uv venv --python 3.14 .venv
   source .venv/bin/activate
   uv pip install -r requirements.txt
   ```

   Without `uv` (requires Python 3.14.2+ already installed):
   ```bash
   python3.14 -m venv .venv
   source .venv/bin/activate
   scripts/setup
   ```

   `.venv` is git-ignored. Check that `python --version` reports 3.14.x and that `which hass` points to `.venv/bin/hass`. If you recreate the environment, run `deactivate && hash -r` and activate it again.

3. **Start Home Assistant**
   ```bash
   scripts/develop
   ```
   `scripts/develop` adds `custom_components/` to `PYTHONPATH` and starts `hass` with the `config/` directory in debug mode. The `hass` command must be on your `PATH`, so keep the virtual environment activated.
   Home Assistant is then available at `http://localhost:8123` (under WSL2 the port is forwarded to Windows automatically).

   Restart `scripts/develop` after changing Python code.

### Running the Tests

The tests need neither a running Home Assistant nor a real device: HTTP calls are mocked with `pytest-httpx` and Socket.IO frames are simulated in `tests/frames.py`.

```bash
source .venv/bin/activate
pytest tests/ -v
scripts/lint    # ruff format + ruff check --fix
```

### Debug Logging

Debug logging for the integration is already enabled in `config/configuration.yaml` (`custom_components.sabiana_hvac: debug`). Logs are written to `config/home-assistant.log`. Testing against a real unit requires Sabiana account credentials and a device reachable through the Sabiana cloud.

### Verify the Setup

1. **Check Home Assistant is running**
   - Navigate to `http://localhost:8123`
   - Complete the initial setup if prompted

2. **Install the custom component**
   - The development environment should automatically include the component
   - If not, copy `custom_components/sabiana_hvac/` to your Home Assistant's `custom_components/` folder

3. **Add the integration**
   - Go to Settings → Devices & Services → Add Integration
   - Search for "Sabiana HVAC" and follow the setup wizard

## AI-assisted contributions

Using AI coding assistants is fine. Submitting their output unchanged is not.

Treat anything a model generates as a **draft** you are responsible for—not finished work. Before you open a pull request:

- **Understand every change you submit.** You should be able to explain what your code does, why it is needed, and how it fits the integration. “The AI wrote it” is not an acceptable answer in review.
- **Read with a critical eye.** Generated code often adds noise: unused imports, redundant comments, overly defensive `try/except` blocks, generic abstractions, or refactors that go beyond the task. Remove what does not serve the change.
- **Stay aligned with this project.** Match existing naming, structure, error handling, and test patterns. Do not paste in generic “best practices” that fight the style already here.

AI can speed you up; only **you** decide what is good enough to merge.

## Code of Conduct

This project follows the [Home Assistant Code of Conduct](https://www.home-assistant.io/code_of_conduct/). By participating, you are expected to uphold this code.

## License

### MIT License

By contributing to this project, you agree that your contributions will be licensed under the [MIT License](https://opensource.org/licenses/MIT).
