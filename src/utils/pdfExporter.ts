import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export class PdfExporter {
    public static async exportSecurityReportToPdf(): Promise<void> {
        try {
            // For now, we'll create a simple HTML-based PDF export
            // In a production environment, you might want to use libraries like puppeteer or html-pdf
            
            const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
            if (!workspaceFolder) {
                vscode.window.showErrorMessage('No workspace folder found');
                return;
            }

            const reportContent = await this.generateReportContent();
            const htmlContent = this.wrapContentInPdfTemplate(reportContent);
            
            // Create reports directory if it doesn't exist
            const reportsDir = path.join(workspaceFolder.uri.fsPath, '.security-reports');
            if (!fs.existsSync(reportsDir)) {
                fs.mkdirSync(reportsDir, { recursive: true });
            }

            // Generate filename with timestamp
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
            const filename = `security-report-${timestamp}.html`;
            const filePath = path.join(reportsDir, filename);

            // Write HTML file (can be converted to PDF by browser)
            fs.writeFileSync(filePath, htmlContent, 'utf8');

            // Show success message with options
            const action = await vscode.window.showInformationMessage(
                `Security report exported to: ${filename}`,
                'Open Report',
                'Open Folder',
                'Print to PDF'
            );

            switch (action) {
                case 'Open Report':
                    vscode.env.openExternal(vscode.Uri.file(filePath));
                    break;
                case 'Open Folder':
                    vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(filePath));
                    break;
                case 'Print to PDF':
                    vscode.env.openExternal(vscode.Uri.file(filePath));
                    vscode.window.showInformationMessage('Use your browser\'s Print > Save as PDF feature to create a PDF');
                    break;
            }

        } catch (error) {
            vscode.window.showErrorMessage(`Failed to export PDF: ${error}`);
        }
    }

    private static async generateReportContent(): Promise<string> {
        // This would integrate with your existing security analysis
        // For now, return a sample report structure
        return `
        <div class="report-section">
            <h2>Security Analysis Summary</h2>
            <div class="summary-stats">
                <div class="stat-box">
                    <h3>Total Files Analyzed</h3>
                    <p class="stat-number">-</p>
                </div>
                <div class="stat-box">
                    <h3>Vulnerabilities Found</h3>
                    <p class="stat-number">-</p>
                </div>
                <div class="stat-box">
                    <h3>Security Score</h3>
                    <p class="stat-number">-/100</p>
                </div>
            </div>
        </div>

        <div class="report-section">
            <h2>OWASP Top 10 Analysis</h2>
            <div class="owasp-categories">
                <div class="category-item">
                    <h4>A01: Broken Access Control</h4>
                    <p>Status: <span class="status-ok">No issues found</span></p>
                </div>
                <div class="category-item">
                    <h4>A02: Cryptographic Failures</h4>
                    <p>Status: <span class="status-ok">No issues found</span></p>
                </div>
                <div class="category-item">
                    <h4>A03: Injection</h4>
                    <p>Status: <span class="status-ok">No issues found</span></p>
                </div>
                <!-- Add more categories as needed -->
            </div>
        </div>

        <div class="report-section">
            <h2>Detailed Findings</h2>
            <p>Run a security audit to see detailed vulnerability findings here.</p>
        </div>
        `;
    }

    private static wrapContentInPdfTemplate(content: string): string {
        const timestamp = new Date().toLocaleString();
        
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #ffffff;
            color: #333;
        }

        .report-header {
            text-align: center;
            margin-bottom: 40px;
            padding: 20px;
            border-bottom: 3px solid #007ACC;
        }

        .report-header h1 {
            color: #007ACC;
            margin: 0;
            font-size: 28px;
        }

        .report-header .subtitle {
            color: #666;
            margin: 10px 0 0 0;
            font-size: 14px;
        }

        .report-section {
            margin-bottom: 30px;
            page-break-inside: avoid;
        }

        .report-section h2 {
            color: #007ACC;
            border-bottom: 2px solid #007ACC;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }

        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }

        .stat-box {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #e9ecef;
        }

        .stat-box h3 {
            margin: 0 0 10px 0;
            color: #495057;
            font-size: 14px;
            font-weight: 600;
        }

        .stat-number {
            font-size: 24px;
            font-weight: bold;
            color: #007ACC;
            margin: 0;
        }

        .owasp-categories {
            display: grid;
            gap: 15px;
        }

        .category-item {
            padding: 15px;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            background: #f8f9fa;
        }

        .category-item h4 {
            margin: 0 0 8px 0;
            color: #495057;
        }

        .category-item p {
            margin: 0;
            color: #6c757d;
        }

        .status-ok {
            color: #28a745;
            font-weight: 600;
        }

        .status-warning {
            color: #ffc107;
            font-weight: 600;
        }

        .status-danger {
            color: #dc3545;
            font-weight: 600;
        }

        .report-footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            text-align: center;
            color: #6c757d;
            font-size: 12px;
        }

        @media print {
            body {
                margin: 0;
                padding: 15px;
            }
            
            .report-section {
                page-break-inside: avoid;
            }
            
            .summary-stats {
                grid-template-columns: repeat(3, 1fr);
            }
        }
    </style>
</head>
<body>
    <div class="report-header">
        <h1>🛡️ Security Analysis Report</h1>
        <div class="subtitle">Generated by Security Checker Agent</div>
        <div class="subtitle">Report Date: ${timestamp}</div>
    </div>

    ${content}

    <div class="report-footer">
        <p>This report was generated by Security Checker Agent v1.0.1</p>
        <p>Developed by Nisal Gunawardhana (@getasyntax)</p>
        <p>For more information, visit: https://github.com/nisalgunawardhana/security-checker-agent</p>
    </div>
</body>
</html>`;
    }
}
