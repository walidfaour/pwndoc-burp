# Contributing to PwnDoc Burp

First off, thank you for considering contributing to PwnDoc Burp! It's people like you that make this tool better for everyone in the security community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Style Guidelines](#style-guidelines)

## Code of Conduct

This project and everyone participating in it is governed by our commitment to creating a welcoming and inclusive environment. Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- Java JDK 21 or higher
- Git
- A code editor (IntelliJ IDEA recommended for Java development)
- Burp Suite (Professional or Community) for testing

### Development Setup

1. **Fork the repository** on GitHub

2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/pwndoc-burp.git
   cd pwndoc-burp
   ```

3. **Build the project**:
   ```bash
   ./gradlew build
   ```

4. **Import into your IDE**:
   - IntelliJ IDEA: File → Open → Select the `build.gradle.kts` file
   - Eclipse: File → Import → Gradle → Existing Gradle Project

5. **Test your changes**:
   - Build: `./gradlew build`
   - The JAR will be in `build/libs/`
   - Load it in Burp Suite to test

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates.

**When reporting a bug, include:**
- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior vs actual behavior
- Your environment (Burp Suite version, Java version, OS, PwnDoc version)
- Screenshots if applicable
- Error messages from Burp's Output tab

### Suggesting Features

Feature suggestions are welcome! Please include:
- A clear description of the feature
- The use case and why it would be helpful
- Any implementation ideas you have

### Code Contributions

1. **Find an issue** to work on, or create one first
2. **Comment on the issue** to let others know you're working on it
3. **Create a branch** for your work
4. **Make your changes**
5. **Test thoroughly**
6. **Submit a pull request**

## Pull Request Process

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** with clear, atomic commits

3. **Test your changes**:
   - Ensure the project builds: `./gradlew build`
   - Test in Burp Suite manually
   - Test with different PwnDoc configurations if possible

4. **Update documentation** if needed

5. **Push your branch**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request** with:
   - A clear title and description
   - Reference to any related issues
   - Screenshots/GIFs if UI changes are involved

## Style Guidelines

### Java Code Style

- Use 4 spaces for indentation (no tabs)
- Follow standard Java naming conventions:
  - `camelCase` for methods and variables
  - `PascalCase` for classes
  - `UPPER_SNAKE_CASE` for constants
- Add Javadoc comments for public methods
- Keep methods focused and reasonably short
- Use meaningful variable names

### Commit Messages

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- First line should be 50 characters or less
- Reference issues when relevant: "Fix #123: ..."

**Examples:**
```
Add CVSS 3.1 calculator to finding editor

Fix #42: Resolve authentication timeout issue

Update README with macOS build instructions
```

### Documentation

- Use Markdown for documentation
- Include code examples where helpful
- Keep documentation up to date with code changes

## Project Structure

```
pwndoc-burp/
├── src/main/java/com/walidfaour/pwndoc/
│   ├── api/                 # API client and data models
│   ├── config/              # Configuration management
│   ├── context/             # Context menu and finding editor
│   ├── ui/                  # Main UI components
│   │   ├── components/      # Reusable UI components
│   │   └── panels/          # Main tab panels
│   └── util/                # Utility classes (CVSS calculator, etc.)
├── build.gradle.kts         # Gradle build configuration
├── README.md                # Main documentation
└── CONTRIBUTING.md          # This file
```

## Questions?

Feel free to open an issue with your question or reach out to the maintainers.

Thank you for contributing! 🎉
