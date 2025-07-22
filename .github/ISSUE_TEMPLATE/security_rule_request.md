---
name: 🛡️ Security Rule Request
about: Suggest a new security rule or improvement to existing rules
title: '[SECURITY RULE] '
labels: ['security-rule', 'enhancement', 'needs-review']
assignees: ['nisalgunawardhana']
---

## 🛡️ Security Rule Request

### 📋 Rule Category
Which OWASP Top 10 category does this rule belong to?
- [ ] A01: Broken Access Control
- [ ] A02: Cryptographic Failures
- [ ] A03: Injection
- [ ] A04: Insecure Design
- [ ] A05: Security Misconfiguration
- [ ] A06: Vulnerable and Outdated Components
- [ ] A07: Identification and Authentication Failures
- [ ] A08: Software and Data Integrity Failures
- [ ] A09: Security Logging and Monitoring Failures
- [ ] A10: Server-Side Request Forgery (SSRF)
- [ ] Other (specify below)

### 🎯 Vulnerability Description
Describe the security vulnerability this rule would detect:

### 💻 Languages Affected
Which programming languages should this rule support?
- [ ] JavaScript/TypeScript
- [ ] Python
- [ ] Java
- [ ] C#
- [ ] PHP
- [ ] Ruby
- [ ] Go
- [ ] C/C++
- [ ] Other: ___________

### ❌ Vulnerable Code Examples
Provide examples of code that should trigger this security rule:

```javascript
// Example 1: Vulnerable code
```

```python
# Example 2: Vulnerable code (if multi-language)
```

### ✅ Secure Code Examples
Provide examples of secure alternatives:

```javascript
// Example 1: Secure alternative
```

```python
# Example 2: Secure alternative (if multi-language)
```

### 📊 Severity Level
What severity level should this rule have?
- [ ] 🔴 Critical - Immediate security risk
- [ ] 🟠 High - Significant security concern
- [ ] 🟡 Medium - Moderate security issue  
- [ ] 🟢 Low - Minor security improvement

### 🔍 Detection Pattern
If you have ideas for the regex pattern or AST detection logic:

```regex
// Regex pattern suggestion
```

### 📚 References
Provide relevant security references:
- [ ] OWASP Documentation: [link]
- [ ] CVE Numbers: [if applicable]
- [ ] Security advisories: [links]
- [ ] Academic papers: [links]
- [ ] Other security tools that detect this: [tool names]

### 🎯 Real-World Impact
Describe the potential impact if this vulnerability is exploited:

### 🧪 False Positive Considerations
Are there legitimate use cases where this pattern might appear but not be a vulnerability?

### 📋 Additional Context
Any other information that would help in implementing this security rule:

### ✔️ Checklist
- [ ] I have provided vulnerable code examples
- [ ] I have provided secure code alternatives
- [ ] I have included relevant security references
- [ ] I have considered false positive scenarios
- [ ] This rule addresses a real security concern
