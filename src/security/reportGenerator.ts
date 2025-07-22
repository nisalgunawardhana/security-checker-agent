import * as vscode from 'vscode';
import { SecurityVulnerability } from './owaspRules';

export interface SecurityReport {
    timestamp: Date;
    workspaceName: string;
    totalFiles: number;
    totalVulnerabilities: number;
    vulnerabilities: SecurityVulnerability[];
    scoreData: {
        score: number;
        level: string;
        breakdown: Record<string, number>;
    };
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
}

export class SecurityReportGenerator {
    generateReport(
        vulnerabilities: SecurityVulnerability[], 
        workspaceName: string, 
        totalFiles: number,
        scoreData: { score: number; level: string }
    ): SecurityReport {
        const summary = this.generateSummary(vulnerabilities);
        const breakdown = this.generateBreakdown(vulnerabilities);

        return {
            timestamp: new Date(),
            workspaceName,
            totalFiles,
            totalVulnerabilities: vulnerabilities.length,
            vulnerabilities,
            scoreData: { ...scoreData, breakdown },
            summary
        };
    }

    private generateSummary(vulnerabilities: SecurityVulnerability[]): { critical: number; high: number; medium: number; low: number; } {
        const summary = vulnerabilities.reduce((acc, vuln) => {
            acc[vuln.rule.severity] = (acc[vuln.rule.severity] || 0) + 1;
            return acc;
        }, {} as Record<string, number>);

        return {
            critical: summary.critical || 0,
            high: summary.high || 0,
            medium: summary.medium || 0,
            low: summary.low || 0
        };
    }

    private generateBreakdown(vulnerabilities: SecurityVulnerability[]): Record<string, number> {
        return vulnerabilities.reduce((acc, vuln) => {
            const category = vuln.rule.owaspCategory;
            acc[category] = (acc[category] || 0) + 1;
            return acc;
        }, {} as Record<string, number>);
    }

    generateHTMLReport(report: SecurityReport): string {
        const severityColors = {
            critical: '#dc3545',
            high: '#fd7e14',
            medium: '#ffc107',
            low: '#28a745'
        };

        const levelColors = {
            excellent: '#28a745',
            good: '#6f42c1',
            fair: '#ffc107',
            poor: '#fd7e14',
            critical: '#dc3545'
        };

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: var(--vscode-editor-background);
            color: var(--vscode-editor-foreground);
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header p {
            margin: 10px 0 0 0;
            font-size: 1.1em;
            opacity: 0.9;
        }
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .metric-card {
            background: var(--vscode-editor-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .metric-value {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .metric-label {
            font-size: 0.9em;
            color: var(--vscode-descriptionForeground);
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .score-card {
            background: ${levelColors[report.scoreData.level as keyof typeof levelColors] || '#6c757d'};
            color: white;
        }
        .severity-breakdown {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .severity-card {
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            color: white;
            font-weight: bold;
        }
        .severity-critical { background-color: ${severityColors.critical}; }
        .severity-high { background-color: ${severityColors.high}; }
        .severity-medium { background-color: ${severityColors.medium}; }
        .severity-low { background-color: ${severityColors.low}; }
        .owasp-breakdown {
            background: var(--vscode-editor-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }
        .owasp-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid var(--vscode-panel-border);
        }
        .owasp-item:last-child {
            border-bottom: none;
        }
        .vulnerability-list {
            background: var(--vscode-editor-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 8px;
            overflow: hidden;
        }
        .vulnerability-item {
            padding: 15px;
            border-bottom: 1px solid var(--vscode-panel-border);
            cursor: pointer;
            transition: background-color 0.2s ease;
        }
        .vulnerability-item:hover {
            background-color: var(--vscode-list-hoverBackground);
        }
        .vulnerability-item:last-child {
            border-bottom: none;
        }
        .clickable-location {
            color: var(--vscode-textLink-foreground);
            text-decoration: underline;
            font-weight: bold;
        }
        .click-hint {
            font-size: 0.8em;
            color: var(--vscode-descriptionForeground);
            margin-left: 10px;
        }
        .vulnerability-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .vulnerability-title {
            font-weight: bold;
            font-size: 1.1em;
        }
        .vulnerability-severity {
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
            color: white;
        }
        .vulnerability-details {
            margin-bottom: 10px;
            color: var(--vscode-descriptionForeground);
        }
        .vulnerability-suggestion {
            background: var(--vscode-textCodeBlock-background);
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9em;
            border-left: 4px solid var(--vscode-charts-blue);
        }
        .vulnerability-location {
            font-family: monospace;
            font-size: 0.9em;
            color: var(--vscode-descriptionForeground);
        }
        h2 {
            color: var(--vscode-foreground);
            border-bottom: 2px solid var(--vscode-panel-border);
            padding-bottom: 10px;
            margin-top: 30px;
        }
        .no-vulnerabilities {
            text-align: center;
            padding: 50px;
            background: var(--vscode-editor-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 8px;
            color: var(--vscode-descriptionForeground);
        }
        .no-vulnerabilities h3 {
            color: #28a745;
            font-size: 1.5em;
            margin-bottom: 10px;
        }
        @media (max-width: 768px) {
            body {
                padding: 10px;
            }
            .metrics {
                grid-template-columns: 1fr;
            }
            .header h1 {
                font-size: 2em;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Security Analysis Report</h1>
        <p>${report.workspaceName} • ${report.timestamp.toLocaleString()}</p>
    </div>

    <div class="metrics">
        <div class="metric-card score-card">
            <div class="metric-value">${report.scoreData.score}/100</div>
            <div class="metric-label">Security Score (${report.scoreData.level})</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">${report.totalFiles}</div>
            <div class="metric-label">Files Analyzed</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">${report.totalVulnerabilities}</div>
            <div class="metric-label">Vulnerabilities Found</div>
        </div>
    </div>

    <h2>Severity Breakdown</h2>
    <div class="severity-breakdown">
        <div class="severity-card severity-critical">
            <div style="font-size: 1.5em;">${report.summary.critical || 0}</div>
            <div>Critical</div>
        </div>
        <div class="severity-card severity-high">
            <div style="font-size: 1.5em;">${report.summary.high || 0}</div>
            <div>High</div>
        </div>
        <div class="severity-card severity-medium">
            <div style="font-size: 1.5em;">${report.summary.medium || 0}</div>
            <div>Medium</div>
        </div>
        <div class="severity-card severity-low">
            <div style="font-size: 1.5em;">${report.summary.low || 0}</div>
            <div>Low</div>
        </div>
    </div>

    <h2>OWASP Top 10 Breakdown</h2>
    <div class="owasp-breakdown">
        ${Object.entries(report.scoreData.breakdown).map(([category, count]) => `
            <div class="owasp-item">
                <span>${category}</span>
                <span style="font-weight: bold; color: ${count > 0 ? '#dc3545' : '#28a745'};">${count} issues</span>
            </div>
        `).join('')}
    </div>

    <h2>Vulnerabilities</h2>
    ${report.vulnerabilities.length === 0 ? `
        <div class="no-vulnerabilities">
            <h3>🎉 No Vulnerabilities Found!</h3>
            <p>Your code appears to be secure based on OWASP Top 10 analysis.</p>
        </div>
    ` : `
        <div class="vulnerability-list">
            ${report.vulnerabilities.map((vuln, index) => `
                <div class="vulnerability-item" onclick="navigateToVulnerability('${vuln.filePath}', ${vuln.line}, ${vuln.column}, '${vuln.suggestion.replace(/'/g, "\\'")}')">
                    <div class="vulnerability-header">
                        <div class="vulnerability-title">${vuln.rule.name}</div>
                        <div class="vulnerability-severity severity-${vuln.rule.severity}" style="background-color: ${severityColors[vuln.rule.severity as keyof typeof severityColors]};">
                            ${vuln.rule.severity}
                        </div>
                    </div>
                    <div class="vulnerability-details">
                        <div><strong>Category:</strong> ${vuln.rule.owaspCategory}</div>
                        <div><strong>Description:</strong> ${vuln.rule.description}</div>
                        <div class="vulnerability-location">
                            <strong>📍 Location:</strong> <span class="clickable-location">${vuln.filePath.split('/').pop()}:${vuln.line}:${vuln.column}</span>
                            <span class="click-hint">👆 Click to navigate</span>
                        </div>
                        <div><strong>Code:</strong> <code>${vuln.text}</code></div>
                    </div>
                    <div class="vulnerability-suggestion">
                        <strong>💡 Suggestion:</strong> ${vuln.suggestion}
                    </div>
                </div>
            `).join('')}
        </div>
    `}

    <script>
        const vscode = acquireVsCodeApi();
        
        function navigateToVulnerability(filePath, line, column, suggestion) {
            vscode.postMessage({
                command: 'navigateToVulnerability',
                filePath: filePath,
                line: line,
                column: column,
                suggestion: suggestion
            });
        }
        
        // Add click effect
        document.addEventListener('DOMContentLoaded', function() {
            const vulnerabilityItems = document.querySelectorAll('.vulnerability-item');
            vulnerabilityItems.forEach(item => {
                item.addEventListener('click', function(e) {
                    // Add visual feedback
                    this.style.backgroundColor = 'var(--vscode-list-activeSelectionBackground)';
                    setTimeout(() => {
                        this.style.backgroundColor = '';
                    }, 200);
                });
            });
        });
    </script>

    <div style="text-align: center; margin-top: 40px; padding: 20px; color: var(--vscode-descriptionForeground); font-size: 0.9em;">
        Generated by Security Checker Agent • Report ID: ${Date.now()}
    </div>
</body>
</html>`;
    }
}
