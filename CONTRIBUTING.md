# Contributing to Security Checker Agent 🛡️

Thank you for your interest in contributing to Security Checker Agent! This document provides guidelines and information for contributors.

## 🎯 How to Contribute

We welcome contributions in many forms:
- 🐛 **Bug Reports**: Help us identify and fix issues
- ✨ **Feature Requests**: Suggest new functionality
- 🛡️ **Security Rules**: Propose new OWASP security rules
- 📝 **Documentation**: Improve our guides and examples
- 💻 **Code Contributions**: Submit bug fixes and enhancements
- 🧪 **Testing**: Help test new features and report issues
- 🌐 **Translations**: Help make the extension accessible in more languages

## 🚀 Getting Started

### Prerequisites

- **Node.js**: Version 18.x or higher
- **VS Code**: Latest stable version recommended
- **Git**: For version control
- **TypeScript**: Knowledge helpful for code contributions

### Development Setup

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/security-checker-agent.git
   cd security-checker-agent
   ```

3. **Install** dependencies:
   ```bash
   npm install
   ```

4. **Build** the extension:
   ```bash
   npm run build
   ```

5. **Test** your setup:
   ```bash
   npm test
   ```

### Development Commands

```bash
# Development build with watch mode
npm run watch

# Run tests
npm test

# Lint code
npm run lint

# Fix linting issues
npm run lint:fix

# Package extension for testing
npm run package

# Clean build artifacts
npm run clean
```

## 🐛 Reporting Issues

### Before Reporting
- Search [existing issues](https://github.com/nisalgunawardhana/security-checker-agent/issues) to avoid duplicates
- Use the latest version of the extension
- Test in a clean VS Code environment if possible

### Bug Reports
Use our [Bug Report Template](https://github.com/nisalgunawardhana/security-checker-agent/issues/new?template=bug_report.md) and include:
- Clear reproduction steps
- Expected vs actual behavior
- Environment information
- Code samples that trigger the issue
- Screenshots or error messages

### Feature Requests
Use our [Feature Request Template](https://github.com/nisalgunawardhana/security-checker-agent/issues/new?template=feature_request.md) and include:
- Clear problem statement
- Proposed solution
- Use cases and examples
- Implementation ideas (if any)

### Security Rule Requests
Use our [Security Rule Template](https://github.com/nisalgunawardhana/security-checker-agent/issues/new?template=security_rule_request.md) and include:
- OWASP category
- Vulnerable code examples
- Secure alternatives
- Security references

## 💻 Code Contributions

### Workflow

1. **Create a branch** for your feature/fix:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```

2. **Make your changes** following our coding standards

3. **Write/update tests** for your changes

4. **Test thoroughly**:
   ```bash
   npm test
   npm run lint
   ```

5. **Commit** with descriptive messages:
   ```bash
   git commit -m "Add: New XSS detection rule for React components"
   # or
   git commit -m "Fix: False positive in SQL injection detection"
   ```

6. **Push** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request** with:
   - Clear title and description
   - Reference to related issues
   - Screenshots/examples if applicable

### Coding Standards

#### TypeScript Style
- Use TypeScript strict mode
- Follow existing code patterns
- Add type annotations for public APIs
- Use meaningful variable and function names

#### Security Rules
- Follow the existing `SecurityRule` interface
- Include comprehensive test cases
- Add both positive and negative test scenarios
- Document the security impact
- Provide secure code alternatives

#### Testing
- Write unit tests for new functionality
- Update integration tests if needed
- Ensure all tests pass before submitting
- Add edge case testing

#### Documentation
- Update README.md for user-facing changes
- Add JSDoc comments for public APIs
- Include code examples where helpful
- Keep documentation concise but complete

## 🛡️ Adding Security Rules

Security rules are the core of this extension. When adding new rules:

### Rule Structure
```typescript
export interface SecurityRule {
  id: string;           // Unique identifier
  name: string;         // Human-readable name
  description: string;  // What vulnerability it detects
  category: OwaspCategory;  // OWASP Top 10 category
  severity: 'low' | 'medium' | 'high' | 'critical';
  languages: string[];  // Supported languages
  pattern: RegExp;      // Detection pattern
  message: string;      // User-facing message
  recommendation: string; // How to fix
  references: string[]; // Security references
}
```

### Testing Security Rules
```typescript
// Example test structure
describe('SQL Injection Rule', () => {
  it('should detect basic SQL injection', () => {
    const code = 'SELECT * FROM users WHERE id = ' + userId;
    const result = analyzeCode(code, rules.sqlInjection);
    expect(result.vulnerabilities).toHaveLength(1);
  });

  it('should not trigger on parameterized queries', () => {
    const code = 'SELECT * FROM users WHERE id = ?';
    const result = analyzeCode(code, rules.sqlInjection);
    expect(result.vulnerabilities).toHaveLength(0);
  });
});
```

## 🧪 Testing Guidelines

### Running Tests
```bash
# Run all tests
npm test

# Run specific test file
npm test -- --testNamePattern="SecurityRule"

# Run with coverage
npm run test:coverage

# Run in watch mode
npm run test:watch
```

### Test Categories
- **Unit Tests**: Test individual functions and classes
- **Integration Tests**: Test feature interactions
- **Security Rule Tests**: Test vulnerability detection accuracy
- **UI Tests**: Test VS Code integration

### Test Requirements
- All new code must have tests
- Maintain or improve code coverage
- Include both positive and negative test cases
- Test edge cases and error conditions

## 📝 Documentation

### Types of Documentation
- **README.md**: User-facing documentation
- **Code Comments**: Inline documentation
- **Wiki**: Detailed guides and tutorials
- **CHANGELOG.md**: Version history

### Documentation Standards
- Use clear, concise language
- Include practical examples
- Keep content up-to-date
- Consider non-native English speakers

## 🎯 Pull Request Guidelines

### Before Submitting
- [ ] Code follows project standards
- [ ] All tests pass
- [ ] Documentation updated
- [ ] No linting errors
- [ ] Feature is complete and tested

### PR Description Template
```markdown
## Changes Made
Brief description of what was changed

## Related Issues
Fixes #issue_number

## Testing
- [ ] Unit tests added/updated
- [ ] Manual testing completed
- [ ] No regression in existing functionality

## Screenshots (if applicable)
Include screenshots for UI changes

## Checklist
- [ ] Code follows style guidelines
- [ ] Tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if needed)
```

## 🏆 Recognition

Contributors will be recognized in:
- Project README.md
- Release notes for significant contributions
- GitHub contributors page
- Special thanks in documentation

## 📞 Getting Help

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and community support
- **Email**: contact@getasyntax.dev for direct contact
- **Code Review**: Maintainers will provide feedback on PRs

## 📄 License

By contributing, you agree that your contributions will be licensed under the same Custom License as the project. See [LICENSE.md](LICENSE.md) for details.

## 🤝 Code of Conduct

We are committed to providing a welcoming and inclusive environment for all contributors. Please be respectful and constructive in all interactions.

### Our Standards
- Be respectful and inclusive
- Provide constructive feedback
- Focus on the best interests of the community
- Show empathy towards other contributors

---

<div align="center">
  <strong>Thank you for contributing to Security Checker Agent! 🛡️</strong>
  <br>
  <sub>Together, we're making secure coding more accessible to everyone</sub>
</div>
