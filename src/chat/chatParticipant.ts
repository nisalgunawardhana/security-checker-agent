import * as vscode from 'vscode';
import { MultiLanguageParser } from '../security/parser';
import { OwaspSecurityAnalyzer, SecurityVulnerability } from '../security/owaspRules';
import { SecurityReportGenerator, SecurityReport } from '../security/reportGenerator';

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

    constructor() {
        this.parser = new MultiLanguageParser();
        this.reportGenerator = new SecurityReportGenerator();
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
❓ \`@security-checker-agent help\` - Show this help message

**Features:**
- **OWASP Top 10** compliance checking
- **Multi-language support** (JavaScript, TypeScript, Python, Java, C#, PHP, etc.)
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
Type \`@security-checker-agent audit\` to scan your entire workspace for security issues!`);

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
}
