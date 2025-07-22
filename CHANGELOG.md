# Changelog

All notable changes to the Security Checker Agent extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### Changed
- Performance optimizations in development

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