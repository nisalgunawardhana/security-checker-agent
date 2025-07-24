# Changelog

All notable changes to the Security Checker Agent extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-07-24

### 🎯 Major Enhancements

#### Modern Framework Security Support
- **React Security**: Added detection for `dangerouslySetInnerHTML` XSS vulnerabilities, unsafe href attributes, and direct state mutations
- **Vue.js Security**: Implemented v-html XSS detection and template injection vulnerability scanning
- **Angular Security**: Added innerHTML XSS detection and unsafe trust bypass method identification

#### Advanced API Security
- **GraphQL Security**: Query complexity analysis, injection vulnerability detection, and DoS prevention
- **REST API Security**: CORS misconfiguration detection, missing rate limiting identification
- **JWT Security**: Weak secret detection, verification bypass identification, insecure token handling

#### Cloud & Container Security
- **AWS Security**: S3 public access detection, Lambda environment variable exposure scanning
- **Docker Security**: Root user container detection, security misconfiguration identification
- **Infrastructure Security**: YAML/JSON configuration vulnerability scanning

#### Enhanced Security Analysis
- **Data Flow Analysis**: Advanced AST-based tainted variable tracking
- **Context-Aware Detection**: Reduced false positives through intelligent code analysis
- **NoSQL Injection**: MongoDB and NoSQL database vulnerability detection
- **Cryptographic Enhancements**: Advanced JWT analysis, weak random generation detection

### 📚 Interactive Knowledge Base
- **Security Learning**: New `@security-checker-agent learn [topic]` command for interactive security education
- **Fix Suggestions**: Enhanced `@security-checker-agent fix [issue]` command with step-by-step remediation
- **Knowledge Integration**: 7 comprehensive security knowledge entries with examples and references
- **CWE Mapping**: Common Weakness Enumeration integration for standard vulnerability classification

### 🔧 Enhanced Chat Experience
- **Expanded Commands**: Added `learn` and `fix` commands to the chat interface
- **Better Help**: Comprehensive help system with framework-specific guidance
- **Improved Responses**: More detailed and actionable security recommendations
- **Interactive Examples**: Vulnerable and secure code examples for better understanding

### 🎨 Improved Language Support
- **New File Types**: Added support for `.vue`, `.dockerfile`, `.yaml`, `.json`, `.rs`, `.kt`, `.swift`
- **Enhanced Parsing**: Better file detection and language-specific analysis
- **Framework Detection**: Automatic framework identification for targeted security analysis

### 🎓 Learning Dashboard
- **Interactive Learning Center**: New dedicated dashboard card for security education
- **Visual Learning Interface**: Color-coded learning statistics and progress tracking
- **One-Click Learning**: Direct access to GitHub Copilot learning sessions from dashboard
- **Knowledge Base Integration**: Quick access to 7+ security topics with guided learning
- **Learning Progress Tracking**: Visual statistics showing completed topics and learning metrics
- **Seamless Chat Integration**: Smooth transition from dashboard to interactive learning sessions

### 🚀 Performance & Analysis Improvements
- **70+ Security Rules**: Expanded from 50+ to 70+ comprehensive security patterns
- **Advanced AST Analysis**: Enhanced JavaScript/TypeScript analysis with taint tracking
- **Better Pattern Matching**: More accurate vulnerability detection with reduced false positives
- **Enhanced Suggestions**: Context-aware remediation suggestions for each vulnerability type

### 📋 New Security Rules Added
- `react-xss-1`: React dangerouslySetInnerHTML XSS detection
- `react-xss-2`: React href XSS vulnerability detection  
- `react-state-1`: React direct state mutation detection
- `vue-xss-1`: Vue.js v-html XSS risk detection
- `vue-injection-1`: Vue.js template injection detection
- `angular-xss-1`: Angular innerHTML XSS risk detection
- `angular-trust-1`: Angular unsafe trust bypass detection
- `api-graphql-1`: GraphQL query complexity analysis
- `api-graphql-2`: GraphQL injection risk detection
- `api-cors-1`: Insecure CORS configuration detection
- `api-rate-limit-1`: Missing API rate limiting detection
- `cloud-aws-s3-1`: AWS S3 public read access detection
- `cloud-aws-lambda-1`: AWS Lambda environment variable exposure
- `cloud-docker-1`: Docker container root user detection
- `jwt-weak-secret-1`: JWT weak secret detection
- `jwt-no-verify-1`: JWT verification bypass detection
- `nosql-injection-1`: NoSQL injection risk detection

### 🛠️ Technical Improvements
- **Enhanced AST Analysis**: More sophisticated Abstract Syntax Tree traversal with vulnerability pattern detection
- **Knowledge Base System**: Comprehensive security knowledge management with search and categorization
- **Improved Error Handling**: Better error messages and graceful degradation
- **Code Organization**: Modular architecture for better maintainability

### 📖 Documentation Updates
- **Updated README**: Comprehensive documentation reflecting all new features
- **Enhanced Examples**: Both vulnerable and secure code examples for all supported frameworks
- **Framework Guides**: Specific security guidance for React, Vue.js, Angular, and API development
- **Chat Command Documentation**: Complete guide to all available chat commands

## [1.0.2] - 2025-07-22

### Added
- 🔔 **Smart Installation Notification**
  - Welcome notification appears only on first installation
  - Quick action buttons: "Audit Workspace" and "Open Dashboard"
  - Improved onboarding experience for new users

### Changed
- 🎨 **OWASP Card Styling**
  - Updated OWASP Top 10 coverage card with modern green color scheme
  - Enhanced visual appeal and better contrast
  - Professional gradient design for security focus

### Removed
- ❌ **Streamlined Notifications**
  - Removed "Learn More" button from welcome notification
  - Simplified user experience with direct action options

## [1.0.1] - 2025-07-22

### Added
- 🎛️ **Security Dashboard Interface**
  - Interactive dashboard with visual buttons for all main functions
  - Easy access to audit workspace, current file, and generate reports
  - Quick stats overview with OWASP Top 10 coverage display
  - Recent activity tracking for user actions
  
- 📊 **Enhanced User Experience** 
  - Status bar integration with "Security" button for quick dashboard access
  - One-click access to all extension features without command palette
  - Visual buttons replacing command-only interface
  
- 📄 **PDF Export Functionality**
  - Export security reports to PDF format
  - HTML-based reports that can be converted to PDF via browser
  - Professional report templates with branding
  - Automatic report saving to `.security-reports` directory

### Improved
- **User Interface**: Dashboard provides intuitive button-based access to all features
- **Accessibility**: No longer need to remember command palette commands
- **Workflow**: Streamlined user experience with visual dashboard
- **Reporting**: Professional report generation with export capabilities

### Technical Enhancements
- New `SecurityDashboardProvider` class for webview dashboard management
- `PdfExporter` utility class for report export functionality
- Status bar integration for quick access
- Enhanced command registration with dashboard integration

## [1.0.0] - 2025-07-22

### Added
- 🛡️ **Complete OWASP Top 10 Security Analysis**
  - 50+ security rules covering all OWASP Top 10 categories
  - Multi-language support (JavaScript, TypeScript, Python, Java, C#, PHP, Ruby, Go, C/C++)
  - Real-time vulnerability detection with file save integration
  
- 🤖 **GitHub Copilot Chat Integration**
  - Natural language security queries with `@security` participant
  - AI-powered vulnerability explanations and recommendations
  - Context-aware security guidance
  
- 📊 **Rich Visual Interface**
  - Security Tree View with OWASP category organization
  - VS Code Diagnostics integration with inline error highlighting
  - Interactive HTML security reports with 0-100 scoring system
  - Progress tracking for workspace scans with cancellation support
  
- ⚡ **Advanced Analysis Engine**
  - AST-based code parsing using Babel and Acorn
  - Dynamic import system for optimal performance
  - Context-aware vulnerability detection to reduce false positives
  - Configurable rule sets and severity thresholds
  
- 🎯 **Developer Experience**
  - Zero-configuration setup with intelligent defaults
  - Command palette integration for all features
  - Professional documentation and contribution guidelines
  - Issue templates for structured community feedback
  
- 🛡️ **Security Rule Categories**
  - **A01 Broken Access Control**: 8 rules for authorization flaws
  - **A02 Cryptographic Failures**: 6 rules for weak crypto and exposed secrets
  - **A03 Injection**: 12 rules for SQL, XSS, command injection, and more
  - **A04 Insecure Design**: 4 rules for design-level security issues
  - **A05 Security Misconfiguration**: 5 rules for configuration problems
  - **A06 Vulnerable Components**: 3 rules for dependency issues
  - **A07 Authentication Failures**: 7 rules for auth implementation flaws
  - **A08 Software Integrity Failures**: 2 rules for deserialization issues
  - **A09 Logging Failures**: 4 rules for insufficient logging/monitoring
  - **A10 SSRF**: 3 rules for server-side request forgery

### Technical Features
- Multi-language AST parsing with fallback mechanisms
- Performance-optimized scanning with progress indicators
- Native VS Code integration (diagnostics, tree views, commands)
- Extensible architecture for custom security rules
- Comprehensive error handling and graceful degradation
- Full TypeScript implementation with strict type checking

### Developer Information
- **Author**: Nisal Gunawardhana (@nisalgunawardhana)
- **Publisher**: getasyntax
- **License**: Custom License (Free to use/contribute, no republishing)
- **Repository**: https://github.com/nisalgunawardhana/security-checker-agent
- **Contact**: contact@getasyntax.dev

### Features
- **Security Analysis**: Comprehensive code scanning using OWASP Top 10 guidelines
- **Multi-Language**: Support for 9+ programming languages
- **AI Integration**: Natural language commands via GitHub Copilot
- **Real-Time**: Instant feedback as you code
- **Reporting**: Beautiful HTML reports with vulnerability breakdowns
- **Scoring**: Security score calculation based on vulnerability severity
- **Configurability**: Customizable rules and thresholds

### Security Categories Covered
- A01: Broken Access Control
- A02: Cryptographic Failures  
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable and Outdated Components
- A07: Identification and Authentication Failures
- A08: Software and Data Integrity Failures
- A09: Security Logging and Monitoring Failures
- A10: Server-Side Request Forgery (SSRF)

### Commands
- `Security Checker: Audit Workspace` - Analyze entire workspace
- `Security Checker: Audit Current File` - Analyze current file
- `Security Checker: Show Security Report` - Display HTML report
- `Security Checker: Clear Diagnostics` - Clear security diagnostics

### Chat Commands
- `@security-checker-agent audit` - Full workspace analysis
- `@security-checker-agent check` - Current file analysis
- `@security-checker-agent help` - Show available commands

### Configuration Options
- `securityChecker.enableRealTimeAnalysis` - Enable/disable real-time analysis
- `securityChecker.riskThreshold` - Set minimum risk level (low/medium/high)
- `securityChecker.enabledRules` - Select which OWASP categories to check