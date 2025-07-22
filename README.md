# 🛡️ Security Checker Agent

**AI-powered security analysis extension for VS Code that detects vulnerabilities using OWASP Top 10 guidelines**

[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/getasyntax.security-checker-agent?label=VS%20Code%20Marketplace&logo=visual-studio-code)](https://marketplace.visualstudio.com/items?itemName=getasyntax.security-checker-agent)
[![Downloads](https://img.shields.io/visual-studio-marketplace/d/getasyntax.security-checker-agent)](https://marketplace.visualstudio.com/items?itemName=getasyntax.security-checker-agent)
[![Rating](https://img.shields.io/visual-studio-marketplace/r/getasyntax.security-checker-agent)](https://marketplace.visualstudio.com/items?itemName=getasyntax.security-checker-agent)
[![License](https://img.shields.io/badge/license-Custom-blue)](LICENSE.md)
[![GitHub Issues](https://img.shields.io/github/issues/nisalgunawardhana/security-checker-agent)](https://github.com/nisalgunawardhana/security-checker-agent/issues)
[![GitHub Stars](https://img.shields.io/github/stars/nisalgunawardhana/security-checker-agent)](https://github.com/nisalgunawardhana/security-checker-agent)


Security Checker Agent is a comprehensive VS Code extension that automatically analyzes your code for security vulnerabilities based on the **OWASP Top 10** security risks. It provides real-time security analysis, actionable suggestions, and integrates seamlessly with **GitHub Copilot**.

## ✨ Key Features

### 🔍 **Comprehensive Security Analysis**
- **Multi-language support**: JavaScript, TypeScript, Python, Java, C#, PHP, Ruby, Go, C/C++
- **OWASP Top 10 coverage**: All 10 categories with 50+ security rules
- **AST-based analysis**: Deep code understanding beyond simple pattern matching
- **Real-time detection**: Instant feedback as you code

### 🤖 **GitHub Copilot Integration**
Chat with the security agent using natural language:
```
@security-checker-agent audit    # Analyze entire workspace
@security-checker-agent check    # Analyze current file
@security-checker-agent help     # Get help and commands
```

### 📊 **Interactive Security Reports**
- **Security scoring**: 0-100 rating based on vulnerability severity
- **Visual dashboards**: HTML reports with vulnerability breakdowns
- **Tree view navigation**: Organized by OWASP categories
- **Inline diagnostics**: VS Code Problems panel integration

### ⚡ **Smart Analysis Engine**
- **Pattern matching**: Regex-based vulnerability detection
- **Context awareness**: Reduces false positives
- **Configurable rules**: Enable/disable specific security checks
- **Performance optimized**: Non-blocking background analysis

## 🏆 OWASP Top 10 Security Coverage

| Category | Description | Examples Detected |
|----------|-------------|-------------------|
| **A01: Broken Access Control** | Authorization flaws | Hardcoded roles, missing auth checks |
| **A02: Cryptographic Failures** | Weak crypto implementation | MD5/SHA1 usage, hardcoded secrets |
| **A03: Injection** | Code injection vulnerabilities | SQL injection, command injection, XSS |
| **A04: Insecure Design** | Security design flaws | Missing input validation, weak architecture |
| **A05: Security Misconfiguration** | Insecure configurations | Debug mode enabled, default passwords |
| **A06: Vulnerable Components** | Outdated dependencies | Known vulnerable packages |
| **A07: Authentication Failures** | Auth implementation issues | Weak passwords, session management |
| **A08: Data Integrity Failures** | Data validation issues | Unsafe deserialization, tampering |
| **A09: Logging/Monitoring Failures** | Insufficient logging | Missing security event logs |
| **A10: Server-Side Request Forgery** | SSRF vulnerabilities | Unvalidated URL requests |

## � Getting Started

### Installation
1. Install from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=getasyntax.security-checker-agent)
2. Open any workspace with code files
3. The extension activates automatically

### Quick Usage

#### 1. **Analyze Your Workspace**
- **Command Palette**: `Security Checker: Audit Workspace`
- **Chat Command**: `@security-checker-agent audit`

#### 2. **Check Current File**
- **Command Palette**: `Security Checker: Audit Current File`  
- **Chat Command**: `@security-checker-agent check`

#### 3. **View Security Report**
- **Command Palette**: `Security Checker: Show Security Report`
- Click on vulnerabilities in the Problems panel

#### 4. **Navigate Vulnerabilities**
- Use the **Security Analysis** tree view in the Explorer
- Click on any vulnerability to jump to the code location

## ⚙️ Configuration

Customize the extension behavior in VS Code settings:

```json
{
  "securityChecker.enableRealTimeAnalysis": true,
  "securityChecker.riskThreshold": "medium",
  "securityChecker.enabledRules": [
    "injection",
    "broken-auth",
    "sensitive-data",
    "xxe",
    "broken-access",
    "security-config",
    "xss",
    "insecure-deserialization",
    "vulnerable-components",
    "logging-monitoring"
  ]
}
```

### Configuration Options

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enableRealTimeAnalysis` | boolean | `true` | Enable automatic analysis on file changes |
| `riskThreshold` | string | `"medium"` | Minimum risk level to display (`low`, `medium`, `high`) |
| `enabledRules` | array | All rules | Specific OWASP categories to check |

## 📋 Example Detections

### ❌ Vulnerable Code
```javascript
// A02: Hardcoded Secret
const API_KEY = 'sk-1234567890abcdef';

// A03: SQL Injection
const query = `SELECT * FROM users WHERE id = ${userId}`;

// A01: Hardcoded Role
const user = { role: 'admin' };

// A03: Command Injection
exec('ls -la ' + userInput);
```

### ✅ Secure Code (Recommended)
```javascript
// A02: Environment Variable
const API_KEY = process.env.API_KEY;

// A03: Parameterized Query
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [userId]);

// A01: Dynamic Role Check
const userRole = await getUserRole(userId);

// A03: Safe Command Execution
execFile('ls', ['-la', sanitizedInput]);
```

## 🔧 Commands

| Command | Description | Keybinding |
|---------|-------------|------------|
| `Security Checker: Audit Workspace` | Analyze all files in workspace | |
| `Security Checker: Audit Current File` | Analyze currently open file | |
| `Security Checker: Show Security Report` | Display detailed HTML report | |
| `Security Checker: Clear Diagnostics` | Clear all security diagnostics | |

## 📊 Security Scoring

The extension calculates a security score from **0-100** based on detected vulnerabilities:

- **Critical**: -20 points each 🚨
- **High**: -10 points each ⚠️
- **Medium**: -5 points each 💛
- **Low**: -2 points each ℹ️

### Score Levels
- **90-100**: 🟢 Excellent - Highly secure code
- **70-89**: 🔵 Good - Minor security improvements needed
- **50-69**: 🟡 Fair - Several security issues to address
- **30-49**: 🟠 Poor - Significant security vulnerabilities
- **0-29**: 🔴 Critical - Immediate security attention required

## 🎯 Supported Languages

| Language | File Extensions | Analysis Type |
|----------|----------------|---------------|
| **JavaScript** | `.js`, `.jsx` | AST + Pattern |
| **TypeScript** | `.ts`, `.tsx` | AST + Pattern |
| **Python** | `.py` | Pattern |
| **Java** | `.java` | Pattern |
| **C#** | `.cs` | Pattern |
| **PHP** | `.php` | Pattern |
| **Ruby** | `.rb` | Pattern |
| **Go** | `.go` | Pattern |
| **C/C++** | `.c`, `.cpp` | Pattern |

## 🤝 Contributing

We welcome and encourage contributions from the community! Whether you're fixing bugs, adding new features, improving documentation, or suggesting security rules, your help makes this extension better for everyone.

### Ways to Contribute

- 🐛 **Report Bugs**: Found an issue? [Create a bug report](https://github.com/nisalgunawardhana/security-checker-agent/issues/new?template=bug_report.md)
- ✨ **Request Features**: Have an idea? [Submit a feature request](https://github.com/nisalgunawardhana/security-checker-agent/issues/new?template=feature_request.md)
- 🛡️ **Suggest Security Rules**: Propose new OWASP rules or improvements
- 📝 **Improve Documentation**: Help make our docs clearer and more comprehensive
- 💻 **Code Contributions**: Submit pull requests for bug fixes or new features

### Getting Started for Contributors

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
4. **Create** a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
5. **Make** your changes and test thoroughly
6. **Commit** with clear, descriptive messages:
   ```bash
   git commit -m "Add: New OWASP rule for detecting XSS vulnerabilities"
   ```
7. **Push** to your fork and create a pull request

### Development Setup

```bash
# Install dependencies
npm install

# Build the extension
npm run build

# Watch for changes during development
npm run watch

# Run tests
npm test

# Package the extension
npm run package

# Lint code
npm run lint
```

### Coding Guidelines

- Follow TypeScript best practices
- Add tests for new security rules
- Update documentation for new features
- Ensure all tests pass before submitting PR
- Follow the existing code style and patterns

### Pull Request Process

1. Ensure your PR description clearly describes the problem and solution
2. Include the relevant issue number if applicable
3. Make sure all tests pass and no linting errors exist
4. Update the README.md if you change functionality
5. Your PR will be reviewed by maintainers before merging

## 🐛 Reporting Bugs

If you encounter any bugs or issues, please help us improve by reporting them:

### Before Reporting
- Check if the issue already exists in [GitHub Issues](https://github.com/nisalgunawardhana/security-checker-agent/issues)
- Make sure you're using the latest version of the extension
- Try reproducing the issue in a clean environment

### How to Report
Use our **Bug Report Template**: [Create Bug Report](https://github.com/nisalgunawardhana/security-checker-agent/issues/new?template=bug_report.md)

Please include:
- Clear description of the bug
- Steps to reproduce the issue
- Expected vs actual behavior
- Screenshots or error messages
- Your environment details (VS Code version, OS, etc.)
- Sample code that triggers the issue

## ✨ Feature Requests

Have an idea to make Security Checker Agent even better? We'd love to hear it!

### Request a Feature
Use our **Feature Request Template**: [Request Feature](https://github.com/nisalgunawardhana/security-checker-agent/issues/new?template=feature_request.md)

Please include:
- Clear description of the requested feature
- Use case or problem it solves
- Proposed solution or implementation ideas
- Any additional context or examples

### Popular Feature Requests
- Additional language support
- Custom security rule creation
- Integration with other security tools
- Advanced reporting features
- Team collaboration features

## 📚 Resources

- 📖 [OWASP Top 10](https://owasp.org/Top10/) - Official OWASP security guidelines
- 🔒 [Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/) - Best practices guide
- 💬 [GitHub Discussions](https://github.com/nisalgunawardhana/security-checker-agent/discussions) - Community support
- 🐛 [Issue Tracker](https://github.com/nisalgunawardhana/security-checker-agent/issues) - Bug reports and features

## 🆘 Support

- **Documentation**: Visit our [GitHub Wiki](https://github.com/nisalgunawardhana/security-checker-agent/wiki)
- **Issues**: Report bugs using our [Bug Report Template](https://github.com/nisalgunawardhana/security-checker-agent/issues/new?template=bug_report.md)
- **Feature Requests**: Submit ideas using our [Feature Request Template](https://github.com/nisalgunawardhana/security-checker-agent/issues/new?template=feature_request.md)
- **Discussions**: Join our [community discussions](https://github.com/nisalgunawardhana/security-checker-agent/discussions)
- **Email**: contact@getasyntax.dev

## 📄 License

This project is licensed under a Custom License - see the [LICENSE.md](LICENSE.md) file for details.

**TL;DR**: Free to use, study, and contribute. Cannot be republished or commercially redistributed without permission.

## 🌟 Acknowledgments

- **OWASP Foundation** for security guidelines and best practices
- **VS Code Team** for the excellent extensibility platform
- **GitHub Copilot** for AI integration capabilities
- **Security Community** for continuous vulnerability research and feedback

## 🚀 Follow Me

Stay updated with the latest news, releases, and tips:

- **GitHub**: [nisalgunawardhana](https://github.com/nisalgunawardhana)
- **Twitter**: [@thenisals](https://twitter.com/thenisals)
- **LinkedIn**: [Nisal Gunawardhana](https://www.linkedin.com/in/nisalgunawardhana/)
- **Twitter**: [@getasyntax](https://twitter.com/getasyntax)
- **LinkedIn**: [GetAsyntax](https://www.linkedin.com/company/getasyntax)


Join our community and never miss an update!

---

<div align="center">
  <strong>🛡️ Developed with getasyntax by <a href="https://github.com/nisalgunawardhana">Nisal Gunawardhana</a> (@nisalgunawardhana)</strong>
  <br>
  <sub>Making secure coding accessible to everyone</sub>
  <br><br>
  <strong>Star ⭐ this project on GitHub if it helps you write more secure code!</strong>
</div>

