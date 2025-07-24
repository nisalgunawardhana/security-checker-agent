import * as vscode from 'vscode';
import { MultiLanguageParser } from '../security/parser';
import { OwaspSecurityAnalyzer, SecurityVulnerability } from '../security/owaspRules';
import { SecurityReportGenerator, SecurityReport } from '../security/reportGenerator';
import { SecurityKnowledgeProvider } from '../security/knowledgeBase';

interface SecurityChatResult extends vscode.ChatResult {
    metadata: {
        command: string;
        vulnerabilitiesFound: number;
        securityScore: number;
    };
}

export class SecurityChatParticipant {
    private parser: MultiLanguageParser;
    private reportGenerator: SecurityReportGenerator;
    private knowledgeProvider: SecurityKnowledgeProvider;

    constructor() {
        this.parser = new MultiLanguageParser();
        this.reportGenerator = new SecurityReportGenerator();
        this.knowledgeProvider = new SecurityKnowledgeProvider();
    }

    async handleChatRequest(
        request: vscode.ChatRequest,
        context: vscode.ChatContext,
        stream: vscode.ChatResponseStream,
        token: vscode.CancellationToken
    ): Promise<SecurityChatResult> {
        const command = request.prompt.trim().toLowerCase();

        try {
            if (command === 'audit' || command === 'analyze' || command === 'scan') {
                return await this.handleAuditCommand(request, stream, token);
            } else if (command.startsWith('check')) {
                return await this.handleCheckCommand(request, stream, token);
            } else if (command === 'help' || command === '') {
                return this.handleHelpCommand(stream);
            } else if (command.startsWith('learn') || command.startsWith('explain')) {
                return this.handleLearnCommand(request, stream);
            } else if (command.startsWith('secure') || command.startsWith('fix')) {
                return this.handleSecureCommand(request, stream);
            } else {
                return this.handleUnknownCommand(stream, command);
            }
        } catch (error) {
            stream.markdown(`❌ **Error:** ${error instanceof Error ? error.message : 'Unknown error occurred'}`);
            return {
                metadata: {
                    command,
                    vulnerabilitiesFound: 0,
                    securityScore: 0
                }
            };
        }
    }

    private async handleAuditCommand(
        request: vscode.ChatRequest,
        stream: vscode.ChatResponseStream,
        token: vscode.CancellationToken
    ): Promise<SecurityChatResult> {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0) {
            stream.markdown('❌ **No workspace found.** Please open a workspace to analyze.');
            return { metadata: { command: 'audit', vulnerabilitiesFound: 0, securityScore: 0 } };
        }

        stream.markdown('🔍 **Starting comprehensive security analysis...**\\n\\n');
        
        // Show progress
        stream.markdown('📂 Scanning workspace files...\\n');
        
        let allVulnerabilities: SecurityVulnerability[] = [];
        let totalFiles = 0;

        for (const workspaceFolder of workspaceFolders) {
            if (token.isCancellationRequested) {
                stream.markdown('❌ **Analysis cancelled by user.**');
                return { metadata: { command: 'audit', vulnerabilitiesFound: 0, securityScore: 0 } };
            }

            try {
                const parsedFiles = await this.parser.parseWorkspace(workspaceFolder.uri);
                totalFiles += parsedFiles.length;
                
                stream.markdown(`📄 Found ${parsedFiles.length} code files in ${workspaceFolder.name}\\n`);
                
                for (const file of parsedFiles) {
                    allVulnerabilities.push(...file.vulnerabilities);
                    
                    // Perform AST analysis for JavaScript/TypeScript
                    if (file.ast && (file.language === 'javascript' || file.language === 'typescript')) {
                        const astVulnerabilities = await this.parser.performAdvancedASTAnalysis(file.ast, file.language);
                        allVulnerabilities.push(...astVulnerabilities.map(v => ({ ...v, filePath: file.filePath })));
                    }
                }
            } catch (error) {
                stream.markdown(`⚠️ **Warning:** Could not analyze ${workspaceFolder.name}: ${error instanceof Error ? error.message : 'Unknown error'}\\n`);
            }
        }

        // Calculate security score
        const analyzer = new OwaspSecurityAnalyzer();
        const scoreData = analyzer.calculateSecurityScore(allVulnerabilities);
        
        // Generate report
        const report = this.reportGenerator.generateReport(
            allVulnerabilities,
            workspaceFolders[0].name,
            totalFiles,
            scoreData
        );

        // Display results
        await this.displayAnalysisResults(stream, report);

        return {
            metadata: {
                command: 'audit',
                vulnerabilitiesFound: allVulnerabilities.length,
                securityScore: scoreData.score
            }
        };
    }

    private async handleCheckCommand(
        request: vscode.ChatRequest,
        stream: vscode.ChatResponseStream,
        token: vscode.CancellationToken
    ): Promise<SecurityChatResult> {
        const activeEditor = vscode.window.activeTextEditor;
        if (!activeEditor) {
            stream.markdown('❌ **No active file found.** Please open a file to analyze.');
            return { metadata: { command: 'check', vulnerabilitiesFound: 0, securityScore: 0 } };
        }

        stream.markdown(`🔍 **Analyzing current file:** ${activeEditor.document.fileName.split('/').pop()}\\n\\n`);

        try {
            const parsedFile = await this.parser.parseFile(activeEditor.document.uri);
            
            if (!parsedFile) {
                stream.markdown('❌ **Unsupported file type.** This extension supports JavaScript, TypeScript, Python, Java, C#, PHP, and more.');
                return { metadata: { command: 'check', vulnerabilitiesFound: 0, securityScore: 0 } };
            }

            let vulnerabilities = parsedFile.vulnerabilities;

            // Perform AST analysis for JavaScript/TypeScript
            if (parsedFile.ast && (parsedFile.language === 'javascript' || parsedFile.language === 'typescript')) {
                const astVulnerabilities = await this.parser.performAdvancedASTAnalysis(parsedFile.ast, parsedFile.language);
                vulnerabilities.push(...astVulnerabilities.map(v => ({ ...v, filePath: parsedFile.filePath })));
            }

            // Calculate security score
            const analyzer = new OwaspSecurityAnalyzer();
            const scoreData = analyzer.calculateSecurityScore(vulnerabilities);

            // Generate and display report
            const report = this.reportGenerator.generateReport(
                vulnerabilities,
                activeEditor.document.fileName.split('/').pop() || 'Unknown',
                1,
                scoreData
            );

            await this.displayAnalysisResults(stream, report, true);

            return {
                metadata: {
                    command: 'check',
                    vulnerabilitiesFound: vulnerabilities.length,
                    securityScore: scoreData.score
                }
            };
        } catch (error) {
            stream.markdown(`❌ **Error analyzing file:** ${error instanceof Error ? error.message : 'Unknown error'}`);
            return { metadata: { command: 'check', vulnerabilitiesFound: 0, securityScore: 0 } };
        }
    }

    private handleHelpCommand(stream: vscode.ChatResponseStream): SecurityChatResult {
        stream.markdown(`# 🛡️ Security Checker Agent

**Available Commands:**

🔍 \`@security-checker-agent audit\` - Analyze entire workspace for security vulnerabilities
📄 \`@security-checker-agent check\` - Analyze current file only
🎓 \`@security-checker-agent learn [topic]\` - Learn about security concepts and best practices
🔧 \`@security-checker-agent fix [issue]\` - Get specific security fix recommendations
❓ \`@security-checker-agent help\` - Show this help message

**New Enhanced Features:**
- 🎯 **Modern Framework Support**: React, Vue.js, Angular security analysis
- 🌐 **API Security**: GraphQL, REST API, CORS vulnerability detection
- ☁️ **Cloud Security**: AWS, Docker container security checks
- 🔐 **Enhanced Crypto**: JWT, NoSQL injection, advanced crypto failures
- 📚 **Interactive Knowledge Base**: Learn and fix security issues
- 🧠 **Advanced AST Analysis**: Data flow tracking and context-aware detection

**Framework-Specific Analysis:**
- **React**: XSS via dangerouslySetInnerHTML, state mutations, unsafe hrefs
- **Vue.js**: v-html XSS risks, template injection vulnerabilities
- **Angular**: innerHTML XSS, unsafe trust bypass methods
- **GraphQL**: Query complexity attacks, injection vulnerabilities
- **JWT**: Weak secrets, verification bypasses, insecure configurations

**Features:**
- **OWASP Top 10** compliance checking with 70+ security rules
- **Multi-language support** (JavaScript, TypeScript, Python, Java, C#, PHP, Vue, etc.)
- **Real-time vulnerability detection** with inline suggestions
- **Comprehensive security reports** with actionable recommendations
- **AST-based analysis** for deep code inspection

**Security Categories Covered:**
- 🚨 A01: Broken Access Control
- 🔐 A02: Cryptographic Failures  
- 💉 A03: Injection
- 🏗️ A04: Insecure Design
- ⚙️ A05: Security Misconfiguration
- 📦 A06: Vulnerable Components
- 🔒 A07: Authentication Failures
- 🔄 A08: Software/Data Integrity Failures
- 📊 A09: Security Logging/Monitoring Failures
- 🌐 A10: Server-Side Request Forgery (SSRF)

**Getting Started:**
Type \`@security-checker-agent audit\` to scan your entire workspace for security issues!
Try \`@security-checker-agent learn XSS\` to learn about Cross-Site Scripting prevention!`);

        return {
            metadata: {
                command: 'help',
                vulnerabilitiesFound: 0,
                securityScore: 100
            }
        };
    }

    private handleUnknownCommand(stream: vscode.ChatResponseStream, command: string): SecurityChatResult {
        stream.markdown(`❓ **Unknown command:** "${command}"

**Available commands:**
- \`audit\` - Analyze entire workspace
- \`check\` - Analyze current file
- \`help\` - Show help information

Type \`@security-checker-agent help\` for detailed information.`);

        return {
            metadata: {
                command,
                vulnerabilitiesFound: 0,
                securityScore: 0
            }
        };
    }

    private async displayAnalysisResults(stream: vscode.ChatResponseStream, report: SecurityReport, singleFile = false): Promise<void> {
        const emoji = report.scoreData.score >= 85 ? '🟢' : report.scoreData.score >= 70 ? '🟡' : '🔴';
        
        stream.markdown(`## ${emoji} Security Analysis Results

**Security Score:** ${report.scoreData.score}/100 (${report.scoreData.level})
**Files Analyzed:** ${report.totalFiles}
**Vulnerabilities Found:** ${report.totalVulnerabilities}

`);

        if (report.totalVulnerabilities === 0) {
            stream.markdown(`🎉 **Excellent!** No security vulnerabilities detected.

Your code appears to follow security best practices according to the OWASP Top 10 guidelines.`);
            return;
        }

        // Show severity breakdown
        stream.markdown(`### 📊 Severity Breakdown
- 🚨 **Critical:** ${report.summary.critical || 0}
- ⚠️ **High:** ${report.summary.high || 0}
- 💛 **Medium:** ${report.summary.medium || 0}
- ℹ️ **Low:** ${report.summary.low || 0}

`);

        // Show OWASP categories with issues
        const categoriesWithIssues = Object.entries(report.scoreData.breakdown)
            .filter(([_, count]) => count > 0)
            .sort((a, b) => b[1] - a[1]);

        if (categoriesWithIssues.length > 0) {
            stream.markdown(`### 🏷️ OWASP Categories with Issues
`);
            for (const [category, count] of categoriesWithIssues) {
                stream.markdown(`- **${category}:** ${count} issue${count > 1 ? 's' : ''}\\n`);
            }
            stream.markdown('\\n');
        }

        // Show top vulnerabilities (limit to 5 for chat)
        const topVulnerabilities = report.vulnerabilities
            .sort((a, b) => {
                const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
                return (severityOrder[b.rule.severity as keyof typeof severityOrder] || 0) - 
                       (severityOrder[a.rule.severity as keyof typeof severityOrder] || 0);
            })
            .slice(0, singleFile ? 10 : 5);

        stream.markdown(`### 🔍 ${singleFile ? 'Vulnerabilities Found' : 'Top Vulnerabilities'}
`);

        for (const vuln of topVulnerabilities) {
            const severityEmoji = {
                critical: '🚨',
                high: '⚠️',
                medium: '💛',
                low: 'ℹ️'
            }[vuln.rule.severity] || 'ℹ️';

            const fileName = vuln.filePath.split('/').pop();
            
            stream.markdown(`#### ${severityEmoji} ${vuln.rule.name}
**File:** \`${fileName}:${vuln.line}:${vuln.column}\`
**Category:** ${vuln.rule.owaspCategory}
**Description:** ${vuln.rule.description}

**Code:**
\`\`\`
${vuln.text}
\`\`\`

💡 **Suggestion:** ${vuln.suggestion}

---

`);
        }

        if (!singleFile && report.vulnerabilities.length > 5) {
            stream.markdown(`*... and ${report.vulnerabilities.length - 5} more vulnerabilities. Run the command on individual files for detailed analysis.*

`);
        }

        // Provide action buttons
        stream.button({
            command: 'security-checker-agent.showSecurityReport',
            title: '📋 View Full Report'
        });

        if (!singleFile) {
            stream.button({
                command: 'security-checker-agent.auditCurrentFile',
                title: '📄 Analyze Current File'
            });
        }
    }

    private handleLearnCommand(
        request: vscode.ChatRequest,
        stream: vscode.ChatResponseStream
    ): SecurityChatResult {
        const query = request.prompt.replace(/^(learn|explain)\s*/i, '').trim();
        
        if (!query) {
            stream.markdown('🎓 **Security Learning Center**\\n\\n');
            stream.markdown('Ask me to explain any security concept! Examples:\\n');
            stream.markdown('- `@security-checker-agent learn XSS`\\n');
            stream.markdown('- `@security-checker-agent explain SQL injection`\\n');
            stream.markdown('- `@security-checker-agent learn JWT security`\\n');
            stream.markdown('- `@security-checker-agent explain React security`\\n\\n');
            
            const allKnowledge = this.knowledgeProvider.getAllKnowledge();
            stream.markdown('**Available Topics:**\\n');
            allKnowledge.forEach(kb => {
                stream.markdown(`- ${kb.title}\\n`);
            });
            
            return { metadata: { command: 'learn', vulnerabilitiesFound: 0, securityScore: 0 } };
        }

        const knowledge = this.knowledgeProvider.searchKnowledge(query);
        
        if (knowledge.length === 0) {
            stream.markdown(`❌ **No knowledge found for "${query}"**\\n\\n`);
            stream.markdown('Try searching for terms like: XSS, SQL injection, JWT, React security, API security, etc.');
            return { metadata: { command: 'learn', vulnerabilitiesFound: 0, securityScore: 0 } };
        }

        stream.markdown(`📚 **Security Knowledge: ${knowledge[0].title}**\\n\\n`);
        stream.markdown(`**Category:** ${knowledge[0].category}\\n`);
        stream.markdown(`**Severity:** ${knowledge[0].severity}\\n`);
        if (knowledge[0].cweId) {
            stream.markdown(`**CWE ID:** ${knowledge[0].cweId}\\n`);
        }
        stream.markdown(`\\n${knowledge[0].description}\\n\\n`);

        stream.markdown('### ❌ Vulnerable Code Example\\n');
        stream.markdown(`\`\`\`javascript\\n${knowledge[0].examples.vulnerable}\\n\`\`\`\\n\\n`);

        stream.markdown('### ✅ Secure Code Example\\n');
        stream.markdown(`\`\`\`javascript\\n${knowledge[0].examples.secure}\\n\`\`\`\\n\\n`);

        stream.markdown('### 📖 Additional Resources\\n');
        knowledge[0].references.forEach(ref => {
            stream.markdown(`- [${ref}](${ref})\\n`);
        });

        return { metadata: { command: 'learn', vulnerabilitiesFound: 0, securityScore: 0 } };
    }

    private handleSecureCommand(
        request: vscode.ChatRequest,
        stream: vscode.ChatResponseStream
    ): SecurityChatResult {
        const query = request.prompt.replace(/^(secure|fix)\s*/i, '').trim();
        
        if (!query) {
            stream.markdown('🔧 **Security Fix Suggestions**\\n\\n');
            stream.markdown('Describe your security issue and I will provide specific fix recommendations!\\n\\n');
            stream.markdown('Examples:\\n');
            stream.markdown('- `@security-checker-agent fix SQL injection in my query`\\n');
            stream.markdown('- `@security-checker-agent secure my React component`\\n');
            stream.markdown('- `@security-checker-agent fix XSS vulnerability`\\n');
            return { metadata: { command: 'secure', vulnerabilitiesFound: 0, securityScore: 0 } };
        }

        // Search for relevant knowledge based on the query
        const knowledge = this.knowledgeProvider.searchKnowledge(query);
        
        if (knowledge.length === 0) {
            stream.markdown(`🔍 **Generic Security Recommendations for "${query}"**\\n\\n`);
            
            // Provide general security advice
            stream.markdown('### General Security Best Practices:\\n');
            stream.markdown('1. **Input Validation**: Always validate and sanitize user input\\n');
            stream.markdown('2. **Authentication**: Implement proper authentication and authorization\\n');
            stream.markdown('3. **Encryption**: Use strong encryption for sensitive data\\n');
            stream.markdown('4. **Error Handling**: Do not expose sensitive information in errors\\n');
            stream.markdown('5. **Security Headers**: Implement proper security headers\\n');
            stream.markdown('6. **Dependencies**: Keep dependencies updated and scan for vulnerabilities\\n\\n');
            
            stream.markdown('💡 **Tip**: Be more specific about your security concern for targeted advice!');
            return { metadata: { command: 'secure', vulnerabilitiesFound: 0, securityScore: 0 } };
        }

        const kb = knowledge[0];
        stream.markdown(`🛠️ **How to Fix: ${kb.title}**\\n\\n`);
        
        stream.markdown('### 🎯 Quick Fix\\n');
        stream.markdown(`\`\`\`javascript\\n${kb.examples.secure}\\n\`\`\`\\n\\n`);
        
        stream.markdown('### 📋 Step-by-Step Fix\\n');
        const steps = this.generateFixSteps(kb);
        steps.forEach((step, index) => {
            stream.markdown(`${index + 1}. ${step}\\n`);
        });
        
        stream.markdown('\\n### ⚠️ Common Mistakes to Avoid\\n');
        stream.markdown(`\`\`\`javascript\\n${kb.examples.vulnerable}\\n\`\`\`\\n\\n`);
        
        stream.markdown('### 🔗 Learn More\\n');
        kb.references.forEach(ref => {
            stream.markdown(`- [${ref}](${ref})\\n`);
        });

        return { metadata: { command: 'secure', vulnerabilitiesFound: 0, securityScore: 0 } };
    }

    private generateFixSteps(knowledge: any): string[] {
        const commonSteps: Record<string, string[]> = {
            'xss-prevention': [
                'Replace innerHTML with textContent for plain text content',
                'If HTML is needed, use a sanitization library like DOMPurify',
                'In React, use JSX auto-escaping instead of dangerouslySetInnerHTML',
                'Validate and escape all user input on both client and server side',
                'Implement Content Security Policy (CSP) headers'
            ],
            'sql-injection-prevention': [
                'Replace string concatenation with parameterized queries',
                'Use prepared statements or ORM methods that handle escaping',
                'Validate input types and formats before using in queries',
                'Implement least privilege principle for database connections',
                'Use stored procedures where appropriate'
            ],
            'jwt-security': [
                'Generate a strong, random secret key (at least 256 bits)',
                'Always verify JWT tokens using jwt.verify()',
                'Set appropriate expiration times for tokens',
                'Use HTTPS to prevent token interception',
                'Implement token refresh mechanisms for long-lived sessions'
            ],
            'react-security': [
                'Use JSX auto-escaping for user content',
                'Validate props and state before rendering',
                'Use useCallback and useMemo to prevent unnecessary re-renders',
                'Implement proper error boundaries to prevent information leakage',
                'Sanitize any HTML content before using dangerouslySetInnerHTML'
            ],
            'api-security': [
                'Implement rate limiting on all endpoints',
                'Add authentication middleware to protected routes',
                'Validate all input using schema validation libraries',
                'Use CORS with specific origins instead of wildcard',
                'Implement proper error handling without exposing internal details'
            ]
        };

        return commonSteps[knowledge.id] || [
            'Identify the source of the vulnerability',
            'Implement proper input validation',
            'Use secure coding practices for the specific technology',
            'Test the fix thoroughly',
            'Consider implementing monitoring and logging'
        ];
    }
}
