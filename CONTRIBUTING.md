# Contributing to [Project Name]

Thank you for your interest in contributing to [Project Name]! We welcome contributions from the community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Contributor License Agreement](#contributor-license-agreement)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We expect all contributors to:

- Be respectful and constructive
- Welcome newcomers and help them get started
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/[project-name].git
   cd [project-name]
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/ainvirion/[project-name].git
   ```
4. **Install dependencies**:
   ```bash
   npm install
   ```
5. **Create a branch** for your work:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## How to Contribute

### Reporting Bugs

Before creating a bug report:
- Check the [existing issues](https://github.com/ainvirion/[project-name]/issues) to avoid duplicates
- Collect information about the bug (version, OS, error messages, etc.)

When filing a bug report, include:
- Clear title and description
- Steps to reproduce
- Expected vs actual behavior
- Screenshots (if applicable)
- Environment details

### Suggesting Enhancements

Enhancement suggestions are welcome! Please:
- Check existing issues and discussions first
- Provide a clear use case
- Explain why this enhancement would be useful
- Consider backward compatibility

### Code Contributions

We welcome code contributions for:
- Bug fixes
- New features
- Performance improvements
- Documentation improvements
- Test coverage

## Development Workflow

1. **Sync with upstream**:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes** following our coding standards

4. **Write tests** for new functionality

5. **Run tests** to ensure nothing breaks:
   ```bash
   npm test
   ```

6. **Run linter**:
   ```bash
   npm run lint
   ```

7. **Commit your changes** following commit guidelines

8. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

9. **Open a Pull Request** on GitHub

## Coding Standards

### General Guidelines

- Write clear, readable, and maintainable code
- Follow existing code style and patterns
- Add comments for complex logic
- Keep functions small and focused
- Avoid code duplication

### Language-Specific Standards

[Add specific coding standards for your project's primary language]

### Testing

- Write unit tests for new functionality
- Maintain or improve test coverage
- Ensure all tests pass before submitting PR
- Include integration tests where appropriate

## Commit Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, missing semicolons, etc.)
- **refactor**: Code refactoring
- **perf**: Performance improvements
- **test**: Adding or updating tests
- **chore**: Maintenance tasks

### Examples

```
feat(auth): add OAuth2 authentication

Implement OAuth2 authentication flow using the authorization code grant.
Includes token refresh and revocation.

Closes #123
```

```
fix(api): handle null response in user endpoint

Add null check to prevent crash when API returns empty response.

Fixes #456
```

## Pull Request Process

1. **Update documentation** if needed
2. **Add tests** for new functionality
3. **Ensure CI passes** (all tests and linting)
4. **Update CHANGELOG.md** with your changes
5. **Request review** from maintainers
6. **Address feedback** promptly and professionally
7. **Squash commits** if requested (we may do this when merging)

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] Tests added/updated and passing
- [ ] Documentation updated
- [ ] Commits follow commit guidelines
- [ ] No breaking changes (or documented if necessary)
- [ ] CHANGELOG.md updated

## Contributor License Agreement

By contributing to this project, you agree that your contributions will be licensed under the Apache License 2.0. You also certify that:

- You created the contribution or have the right to submit it
- You grant AInvirion and the community the right to use your contribution under the Apache License 2.0
- Your contribution does not violate any third-party rights

For significant contributions, you may be asked to sign a formal Contributor License Agreement (CLA).

## Questions?

If you have questions about contributing, please:
- Check existing documentation
- Search closed issues
- Ask in GitHub Discussions
- Contact us at contact@ainvirion.com

---

Thank you for contributing to [Project Name]!
