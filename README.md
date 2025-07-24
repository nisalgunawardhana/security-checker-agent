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
- **Multi-language support**: JavaScript, TypeScript, Python, Java, C#, PHP, Ruby, Go, C/C++, Vue.js, Rust, Kotlin
- **OWASP Top 10 coverage**: All 10 categories with 70+ security rules
- **Modern frameworks**: React, Vue.js, Angular specific vulnerability detection
- **API security**: GraphQL, REST API, CORS vulnerability scanning
- **Cloud security**: AWS, Docker, container security patterns
- **AST-based analysis**: Deep code understanding beyond simple pattern matching
- **Real-time detection**: Instant feedback as you code

### 🤖 **GitHub Copilot Integration**
Chat with the security agent using natural language:
```
@security-checker-agent audit         # Analyze entire workspace
@security-checker-agent check         # Analyze current file
@security-checker-agent learn XSS     # Learn about security topics
@security-checker-agent fix SQL       # Get specific fix suggestions
@security-checker-agent help          # Get help and commands
```

### 📊 **Interactive Security Reports**
- **Security scoring**: 0-100 rating based on vulnerability severity
- **Visual dashboards**: HTML reports with vulnerability breakdowns
- **Tree view navigation**: Organized by OWASP categories
- **Inline diagnostics**: VS Code Problems panel integration
- **Knowledge base**: Interactive learning with examples and fixes

### 🎓 **Learning Dashboard**
- **Interactive security education**: Dedicated learning center with guided tutorials
- **Knowledge base access**: Quick access to 7+ security topics with examples
- **Learning statistics**: Track your security education progress
- **One-click learning**: Start interactive sessions directly from dashboard
- **GitHub Copilot integration**: Seamless transition to chat-based learning
- **Visual learning resources**: Color-coded interface with progress tracking

### ⚡ **Smart Analysis Engine**
- **Pattern matching**: Regex-based vulnerability detection
- **Data flow analysis**: Track tainted variables through code
- **Context awareness**: Reduces false positives with AST analysis
- **Framework-specific rules**: Tailored detection for React, Vue, Angular
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

## 🎯 Modern Framework Security

### React Security Patterns
- **dangerouslySetInnerHTML XSS**: Detects unsafe HTML injection in React components
- **href XSS vulnerabilities**: Identifies dynamic href attributes that can lead to XSS
- **State mutation issues**: Catches direct state modifications that bypass React's update cycle

### Vue.js Security Patterns  
- **v-html XSS risks**: Detects unsafe use of v-html directive with user input
- **Template injection**: Identifies dynamic template compilation vulnerabilities

### Angular Security Patterns
- **innerHTML XSS**: Catches unsafe innerHTML binding with user data
- **Trust bypass issues**: Detects misuse of Angular's security bypass methods

### API Security Patterns
- **GraphQL vulnerabilities**: Query complexity attacks, injection risks
- **CORS misconfigurations**: Overly permissive cross-origin policies  
- **Rate limiting gaps**: Missing rate limiting on API endpoints
- **JWT security issues**: Weak secrets, missing verification

### Cloud Security Patterns
- **AWS S3 misconfigurations**: Public bucket access, insecure policies
- **Docker security**: Root user containers, exposed secrets
- **Lambda security**: Environment variable exposure, privilege escalation

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

#### 5. **Access Learning Dashboard**
- **Command Palette**: `Security Checker: Show Dashboard`
- Click **"Start Learning"** in the Learning Center card
- Access **Knowledge Base** for topic-specific education
- Track your learning progress with built-in statistics

#### 6. **Interactive Learning**
- **Chat Commands**: 
  - `@security learn sql-injection` - Learn about SQL injection
  - `@security learn xss` - XSS prevention techniques
  - `@security learn authentication` - Authentication security
- **Dashboard Features**:
  - One-click learning mode activation
  - Quick access to 7+ security topics
  - Visual progress tracking

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

// React XSS
<div dangerouslySetInnerHTML={{__html: userInput}} />

// Vue.js XSS
<div v-html="userContent"></div>

// GraphQL Injection
const query = `{ user(id: "${req.params.id}") { name } }`;

// JWT Security Issues
const token = jwt.decode(userToken); // No verification
const secret = 'weak-secret'; // Weak secret
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

// React Security
<div>{userInput}</div> // Auto-escaped
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />

// Vue.js Security
<div>{{ userContent }}</div> // Auto-escaped

// GraphQL Security
const query = 'query($id: ID!) { user(id: $id) { name } }';
graphql(schema, query, null, null, { id: userId });

// JWT Security
const decoded = jwt.verify(token, strongSecret); // Proper verification
const secret = crypto.randomBytes(64).toString('hex'); // Strong secret
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
| **Vue.js** | `.vue` | Pattern |
| **Python** | `.py` | Pattern |
| **Java** | `.java` | Pattern |
| **C#** | `.cs` | Pattern |
| **PHP** | `.php` | Pattern |
| **Ruby** | `.rb` | Pattern |
| **Go** | `.go` | Pattern |
| **C/C++** | `.c`, `.cpp` | Pattern |
| **Rust** | `.rs` | Pattern |
| **Kotlin** | `.kt` | Pattern |
| **Docker** | `Dockerfile` | Pattern |
| **YAML/JSON** | `.yaml`, `.json` | Pattern |

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

