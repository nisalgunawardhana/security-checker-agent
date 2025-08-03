import * as vscode from 'vscode';
import { MCPServerDetector, MCPServerInfo } from './mcpDetector';
import { MCPSecurityAnalyzer, MCPVulnerability } from './mcpRules';
import { MultiLanguageParser } from './parser';
import * as fs from 'fs';
import * as path from 'path';

export interface MCPSecurityReport {
    servers: MCPServerInfo[];
    vulnerabilities: MCPVulnerability[];
    summary: {
        totalVulnerabilities: number;
        criticalCount: number;
        highCount: number;
        mediumCount: number;
        lowCount: number;
        owaspLLMCategories: string[];
        affectedServers: number;
    };
    recommendations: string[];
    timestamp: Date;
}

export class MCPSecurityScanner {
    private workspacePath: string;
    private detector: MCPServerDetector;
    private analyzer: MCPSecurityAnalyzer;
    private parser: MultiLanguageParser;
    private statusBarItem: vscode.StatusBarItem;
    private outputChannel: vscode.OutputChannel;

    constructor(workspacePath: string) {
        this.workspacePath = workspacePath;
        this.detector = new MCPServerDetector(workspacePath);
        this.analyzer = new MCPSecurityAnalyzer();
        this.parser = new MultiLanguageParser();
        
        // Create status bar item for MCP scanning
        this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 10);
        this.statusBarItem.text = "$(shield) MCP Security";
        this.statusBarItem.tooltip = "MCP Security Scanner";
        this.statusBarItem.command = 'security-checker-agent.scanMCP';
        
        // Create output channel for detailed logs
        this.outputChannel = vscode.window.createOutputChannel('MCP Security Scanner');
    }

    public async scanMCPSecurity(showProgress: boolean = true): Promise<MCPSecurityReport> {
        let progressReporter: vscode.Progress<{
            message?: string;
            increment?: number;
        }> | undefined;

        if (showProgress) {
            return vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: "MCP Security Scan",
                cancellable: false
            }, async (progress, token) => {
                progressReporter = progress;
                return this.performScan(progressReporter);
            });
        } else {
            return this.performScan();
        }
    }

    private async performScan(progress?: vscode.Progress<{
        message?: string;
        increment?: number;
    }>): Promise<MCPSecurityReport> {
        
        this.outputChannel.show(true);
        this.outputChannel.appendLine('🔍 Starting MCP Security Scan...');
        this.outputChannel.appendLine(`📁 Workspace: ${this.workspacePath}`);
        this.outputChannel.appendLine('');

        // Phase 1: Detect MCP Servers
        progress?.report({ message: "🔍 Detecting MCP servers...", increment: 10 });
        this.statusBarItem.text = "$(loading~spin) Detecting MCP...";
        this.statusBarItem.show();
        
        await this.animateProgress("Scanning for MCP servers", 1000);
        
        const servers = await this.detector.detectMCPServers();
        
        this.outputChannel.appendLine(`🎯 Found ${servers.length} MCP server(s):`);
        servers.forEach((server, index) => {
            this.outputChannel.appendLine(`  ${index + 1}. ${server.name} (${server.type}) - ${server.path}`);
            if (server.tools && server.tools.length > 0) {
                this.outputChannel.appendLine(`     Tools: ${server.tools.join(', ')}`);
            }
        });
        this.outputChannel.appendLine('');

        if (servers.length === 0) {
            progress?.report({ message: "✅ No MCP servers detected", increment: 100 });
            this.statusBarItem.text = "$(shield) No MCP Detected";
            
            const report: MCPSecurityReport = {
                servers: [],
                vulnerabilities: [],
                summary: {
                    totalVulnerabilities: 0,
                    criticalCount: 0,
                    highCount: 0,
                    mediumCount: 0,
                    lowCount: 0,
                    owaspLLMCategories: [],
                    affectedServers: 0
                },
                recommendations: ['No MCP servers detected in the workspace'],
                timestamp: new Date()
            };

            this.outputChannel.appendLine('✅ Scan completed - No MCP servers found');
            return report;
        }

        // Phase 2: Analyze Security
        progress?.report({ message: "🔒 Analyzing MCP security...", increment: 20 });
        this.statusBarItem.text = "$(loading~spin) Analyzing Security...";
        
        await this.animateProgress("Analyzing security vulnerabilities", 1500);
        
        const allVulnerabilities: MCPVulnerability[] = [];
        
        for (let i = 0; i < servers.length; i++) {
            const server = servers[i];
            progress?.report({ 
                message: `🔍 Scanning ${server.name}...`, 
                increment: Math.floor(40 / servers.length)
            });
            
            this.outputChannel.appendLine(`🔍 Analyzing server: ${server.name}`);
            
            try {
                const vulnerabilities = await this.analyzeServerSecurity(server);
                allVulnerabilities.push(...vulnerabilities);
                
                this.outputChannel.appendLine(`  📊 Found ${vulnerabilities.length} potential issues`);
                
                // Log critical and high severity issues
                const criticalIssues = vulnerabilities.filter(v => v.rule.severity === 'critical');
                const highIssues = vulnerabilities.filter(v => v.rule.severity === 'high');
                
                if (criticalIssues.length > 0) {
                    this.outputChannel.appendLine(`  🚨 Critical issues: ${criticalIssues.length}`);
                    criticalIssues.forEach(issue => {
                        this.outputChannel.appendLine(`    - ${issue.rule.name} (Line ${issue.line})`);
                    });
                }
                
                if (highIssues.length > 0) {
                    this.outputChannel.appendLine(`  ⚠️  High severity issues: ${highIssues.length}`);
                    highIssues.forEach(issue => {
                        this.outputChannel.appendLine(`    - ${issue.rule.name} (Line ${issue.line})`);
                    });
                }
                
            } catch (error) {
                this.outputChannel.appendLine(`  ❌ Error analyzing ${server.name}: ${error}`);
            }
        }

        // Phase 3: OWASP LLM Analysis
        progress?.report({ message: "🧠 Running OWASP LLM analysis...", increment: 15 });
        this.statusBarItem.text = "$(loading~spin) OWASP LLM Check...";
        
        await this.animateProgress("Checking against OWASP LLM Top 10", 1000);
        
        const owaspCategories = this.extractOWASPLLMCategories(allVulnerabilities);
        
        this.outputChannel.appendLine('');
        this.outputChannel.appendLine('🧠 OWASP LLM Top 10 Analysis:');
        if (owaspCategories.length > 0) {
            owaspCategories.forEach(category => {
                this.outputChannel.appendLine(`  - ${category}`);
            });
        } else {
            this.outputChannel.appendLine('  ✅ No OWASP LLM violations detected');
        }

        // Phase 4: Generate Report
        progress?.report({ message: "📊 Generating security report...", increment: 10 });
        this.statusBarItem.text = "$(loading~spin) Generating Report...";
        
        await this.animateProgress("Compiling security report", 800);
        
        const summary = this.generateSummary(allVulnerabilities, servers.length);
        const recommendations = this.generateRecommendations(allVulnerabilities, servers);
        
        const report: MCPSecurityReport = {
            servers,
            vulnerabilities: allVulnerabilities,
            summary,
            recommendations,
            timestamp: new Date()
        };

        // Final status update
        progress?.report({ message: "✅ Scan completed", increment: 5 });
        
        const statusText = summary.totalVulnerabilities > 0 
            ? `$(warning) MCP: ${summary.totalVulnerabilities} issues` 
            : "$(shield) MCP: Secure";
        
        this.statusBarItem.text = statusText;
        this.statusBarItem.tooltip = `MCP Security: ${summary.totalVulnerabilities} vulnerabilities found`;

        // Log final summary
        this.outputChannel.appendLine('');
        this.outputChannel.appendLine('📊 Scan Summary:');
        this.outputChannel.appendLine(`  Total vulnerabilities: ${summary.totalVulnerabilities}`);
        this.outputChannel.appendLine(`  Critical: ${summary.criticalCount}`);
        this.outputChannel.appendLine(`  High: ${summary.highCount}`);
        this.outputChannel.appendLine(`  Medium: ${summary.mediumCount}`);
        this.outputChannel.appendLine(`  Low: ${summary.lowCount}`);
        this.outputChannel.appendLine(`  Affected servers: ${summary.affectedServers}`);
        this.outputChannel.appendLine('');
        this.outputChannel.appendLine('✅ MCP Security Scan completed successfully!');

        return report;
    }

    private async analyzeServerSecurity(server: MCPServerInfo): Promise<MCPVulnerability[]> {
        const vulnerabilities: MCPVulnerability[] = [];
        
        try {
            // Read and analyze the main server file
            const content = await fs.promises.readFile(server.path, 'utf-8');
            const language = this.getLanguageFromFile(server.path);
            
            const serverVulns = this.analyzer.analyzeCode(content, server.path, language);
            vulnerabilities.push(...serverVulns);
            
            // Analyze configuration files
            for (const configFile of server.configFiles) {
                try {
                    const configContent = await fs.promises.readFile(configFile, 'utf-8');
                    const configLang = this.getLanguageFromFile(configFile);
                    const configVulns = this.analyzer.analyzeCode(configContent, configFile, configLang);
                    vulnerabilities.push(...configVulns);
                } catch (error) {
                    console.warn(`Failed to analyze config file ${configFile}:`, error);
                }
            }
            
            // Analyze related files in the same directory
            const serverDir = path.dirname(server.path);
            const relatedFiles = await this.findRelatedFiles(serverDir);
            
            for (const file of relatedFiles) {
                try {
                    const fileContent = await fs.promises.readFile(file, 'utf-8');
                    const fileLang = this.getLanguageFromFile(file);
                    const fileVulns = this.analyzer.analyzeCode(fileContent, file, fileLang);
                    vulnerabilities.push(...fileVulns);
                } catch (error) {
                    console.warn(`Failed to analyze related file ${file}:`, error);
                }
            }
            
        } catch (error) {
            console.error(`Failed to analyze server ${server.name}:`, error);
        }
        
        return vulnerabilities;
    }

    private async findRelatedFiles(directory: string): Promise<string[]> {
        const relatedFiles: string[] = [];
        const extensions = ['.py', '.js', '.ts', '.json', '.yaml', '.yml'];
        
        try {
            const files = await fs.promises.readdir(directory);
            for (const file of files) {
                const filePath = path.join(directory, file);
                const stat = await fs.promises.stat(filePath);
                
                if (stat.isFile() && extensions.some(ext => file.endsWith(ext))) {
                    relatedFiles.push(filePath);
                }
            }
        } catch (error) {
            console.warn(`Failed to read directory ${directory}:`, error);
        }
        
        return relatedFiles;
    }

    private getLanguageFromFile(filePath: string): string {
        const ext = path.extname(filePath).toLowerCase();
        const langMap: { [key: string]: string } = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.json': 'json',
            '.yaml': 'yaml',
            '.yml': 'yaml'
        };
        
        return langMap[ext] || 'text';
    }

    private extractOWASPLLMCategories(vulnerabilities: MCPVulnerability[]): string[] {
        const categories = new Set<string>();
        
        for (const vuln of vulnerabilities) {
            if (vuln.rule.owaspLLMCategory) {
                categories.add(vuln.rule.owaspLLMCategory);
            }
        }
        
        return Array.from(categories).sort();
    }

    private generateSummary(vulnerabilities: MCPVulnerability[], serverCount: number) {
        const summary = {
            totalVulnerabilities: vulnerabilities.length,
            criticalCount: vulnerabilities.filter(v => v.rule.severity === 'critical').length,
            highCount: vulnerabilities.filter(v => v.rule.severity === 'high').length,
            mediumCount: vulnerabilities.filter(v => v.rule.severity === 'medium').length,
            lowCount: vulnerabilities.filter(v => v.rule.severity === 'low').length,
            owaspLLMCategories: this.extractOWASPLLMCategories(vulnerabilities),
            affectedServers: new Set(vulnerabilities.map(v => v.filePath)).size
        };
        
        return summary;
    }

    private generateRecommendations(vulnerabilities: MCPVulnerability[], servers: MCPServerInfo[]): string[] {
        const recommendations: string[] = [];
        
        // General MCP security recommendations
        recommendations.push('🔒 Implement proper input validation for all user inputs');
        recommendations.push('🛡️ Use parameterized prompt templates to prevent injection attacks');
        recommendations.push('🔑 Implement strong authentication and authorization mechanisms');
        recommendations.push('📊 Apply principle of least privilege for tool permissions');
        recommendations.push('🔍 Regular security audits and dependency updates');
        
        // Specific recommendations based on findings
        const categories = this.analyzer.getVulnerabilitiesByCategory();
        
        Object.keys(categories).forEach(category => {
            const categoryVulns = categories[category];
            if (categoryVulns.length > 0) {
                switch (category) {
                    case 'Prompt Injection':
                        recommendations.push('⚠️ Critical: Fix prompt injection vulnerabilities immediately');
                        break;
                    case 'Tool Poisoning':
                        recommendations.push('🚨 High Priority: Implement tool validation and whitelisting');
                        break;
                    case 'Authentication & Authorization':
                        recommendations.push('🔐 Essential: Add proper authentication to all endpoints');
                        break;
                    case 'Excessive Permissions':
                        recommendations.push('🎯 Review and minimize tool permissions');
                        break;
                    case 'Supply Chain Vulnerabilities':
                        recommendations.push('📦 Update dependencies and use trusted package sources');
                        break;
                }
            }
        });
        
        return recommendations;
    }

    private async animateProgress(message: string, duration: number): Promise<void> {
        const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        let frameIndex = 0;
        
        const interval = setInterval(() => {
            this.statusBarItem.text = `${frames[frameIndex]} ${message}`;
            frameIndex = (frameIndex + 1) % frames.length;
        }, 100);
        
        await new Promise(resolve => setTimeout(resolve, duration));
        clearInterval(interval);
    }

    public showStatusBar(): void {
        this.statusBarItem.show();
    }

    public hideStatusBar(): void {
        this.statusBarItem.hide();
    }

    public dispose(): void {
        this.statusBarItem.dispose();
        this.outputChannel.dispose();
    }
}
