# Contributing to Home Assistant Sabiana HVAC

Thank you for your interest in contributing to the Home Assistant Sabiana HVAC integration! This document provides guidelines and instructions for contributing to this project.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Environment Setup](#development-environment-setup)
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

## Code of Conduct

This project follows the [Home Assistant Code of Conduct](https://www.home-assistant.io/code_of_conduct/). By participating, you are expected to uphold this code.

## License

### MIT License

By contributing to this project, you agree that your contributions will be licensed under the [MIT License](https://opensource.org/licenses/MIT).
