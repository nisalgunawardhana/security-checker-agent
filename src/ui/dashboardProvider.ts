import * as vscode from 'vscode';

class SecurityDashboardProvider {
    private panel: vscode.WebviewPanel | undefined;
    private readonly extensionUri: vscode.Uri;

    constructor(extensionUri: vscode.Uri) {
        this.extensionUri = extensionUri;
    }

    public show(): void {
        if (this.panel) {
            this.panel.reveal();
            return;
        }

        this.panel = vscode.window.createWebviewPanel(
            'securityDashboard',
            'Security Checker Dashboard',
            vscode.ViewColumn.One,
            {
                enableScripts: true,
                localResourceRoots: [this.extensionUri]
            }
        );

        this.panel.webview.html = this.getHtmlContent();
        this.panel.onDidDispose(() => {
            this.panel = undefined;
        });

        // Handle messages from the webview
        this.panel.webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'auditWorkspace':
                        vscode.commands.executeCommand('security-checker-agent.auditWorkspace');
                        break;
                    case 'auditCurrentFile':
                        vscode.commands.executeCommand('security-checker-agent.auditCurrentFile');
                        break;
                    case 'showReport':
                        vscode.commands.executeCommand('security-checker-agent.showSecurityReport');
                        break;
                    case 'clearDiagnostics':
                        vscode.commands.executeCommand('security-checker-agent.clearDiagnostics');
                        break;
                    case 'exportPdf':
                        vscode.commands.executeCommand('security-checker-agent.exportToPdf');
                        break;
                }
            },
            undefined,
            []
        );
    }

    public updateScanResults(vulnerabilityCount: number, score: number): void {
        if (this.panel) {
            this.panel.webview.postMessage({
                command: 'updateScanResults',
                vulnerabilities: vulnerabilityCount,
                score: score
            });
        }
    }

    private getHtmlContent(): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Checker Dashboard</title>
    <style>
        * {
            box-sizing: border-box;
        }
        
        body {
            font-family: var(--vscode-font-family);
            font-size: var(--vscode-font-size);
            background-color: var(--vscode-editor-background);
            color: var(--vscode-editor-foreground);
            margin: 0;
            padding: 20px;
        }

        .dashboard-header {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            border-bottom: 1px solid var(--vscode-panel-border);
        }

        .dashboard-header h1 {
            margin: 0;
            color: var(--vscode-foreground);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }

        .shield-icon {
            font-size: 24px;
        }

        .dashboard-subtitle {
            color: var(--vscode-descriptionForeground);
            margin-top: 8px;
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }

        .full-width-card {
            grid-column: 1 / -1;
        }

        .dashboard-card {
            background-color: var(--vscode-sideBar-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 8px;
            padding: 20px;
            transition: all 0.2s ease;
        }

        .dashboard-card:hover {
            border-color: var(--vscode-focusBorder);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }

        .card-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 15px;
        }

        .card-icon {
            font-size: 18px;
            color: var(--vscode-symbolIcon-colorForeground);
        }

        .card-title {
            font-size: 16px;
            font-weight: 600;
            margin: 0;
            color: var(--vscode-foreground);
        }

        .card-description {
            color: var(--vscode-descriptionForeground);
            margin-bottom: 15px;
            line-height: 1.4;
        }

        .btn {
            background-color: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            padding: 10px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
            transition: background-color 0.2s ease;
            margin-right: 8px;
            margin-bottom: 8px;
        }

        .btn:hover {
            background-color: var(--vscode-button-hoverBackground);
        }

        .btn-secondary {
            background-color: var(--vscode-button-secondaryBackground);
            color: var(--vscode-button-secondaryForeground);
        }

        .btn-secondary:hover {
            background-color: var(--vscode-button-secondaryHoverBackground);
        }

        .btn-icon {
            margin-right: 6px;
        }

        .quick-stats {
            background: linear-gradient(135deg, var(--vscode-button-background), var(--vscode-button-hoverBackground));
            color: var(--vscode-button-foreground);
            text-align: center;
            padding: 30px;
            border-radius: 8px;
            grid-column: 1 / -1;
            margin-bottom: 10px;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .stat-item {
            text-align: center;
        }

        .stat-number {
            font-size: 28px;
            font-weight: bold;
            display: block;
        }

        .stat-label {
            font-size: 12px;
            opacity: 0.8;
            margin-top: 4px;
        }

        .recent-activity {
            grid-column: 1 / -1;
        }

        .owasp-coverage-card {
            grid-column: 1 / -1;
            background: linear-gradient(135deg, #0e0e0eff, #232323ff);
            color: #ffffff;
            border: 1px solid rgba(40, 167, 69, 0.3);
        }

        .owasp-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }

        .owasp-item {
            background: rgba(255, 255, 255, 0.15);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.25);
            transition: all 0.2s ease;
        }

        .owasp-item:hover {
            background: rgba(255, 255, 255, 0.25);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }

        .owasp-item-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 8px;
        }

        .owasp-item-title {
            font-weight: 600;
            font-size: 14px;
        }

        .owasp-status {
            font-size: 12px;
            padding: 3px 8px;
            border-radius: 12px;
            background: rgba(255, 255, 255, 0.3);
            font-weight: 600;
        }

        .owasp-description {
            font-size: 12px;
            opacity: 0.9;
            line-height: 1.4;
        }

        .activity-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 0;
            border-bottom: 1px solid var(--vscode-panel-border);
        }

        .activity-item:last-child {
            border-bottom: none;
        }

        .activity-icon {
            color: var(--vscode-symbolIcon-colorForeground);
        }

        .activity-text {
            flex: 1;
            color: var(--vscode-foreground);
        }

        .activity-time {
            color: var(--vscode-descriptionForeground);
            font-size: 12px;
        }

        .instruction-tip {
            margin-top: 15px;
            padding: 12px;
            background: var(--vscode-textBlockQuote-background);
            border-left: 4px solid var(--vscode-focusBorder);
            font-size: 12px;
            border-radius: 0 4px 4px 0;
        }

        .instruction-tip strong {
            color: var(--vscode-focusBorder);
        }

        .instruction-tip code {
            background: var(--vscode-textCodeBlock-background);
            padding: 2px 6px;
            border-radius: 3px;
            font-family: var(--vscode-editor-font-family);
        }

        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .owasp-grid {
                grid-template-columns: 1fr;
            }

            .full-width-card {
                grid-column: 1;
            }
        }
    </style>
</head>
<body>
    <div class="dashboard-header">
        <h1>
            <span class="shield-icon">🛡️</span>
            Security Checker Dashboard
        </h1>
        <div class="dashboard-subtitle">Comprehensive security analysis for your codebase</div>
    </div>

    <div class="dashboard-grid">
        <!-- Quick Stats -->
        <div class="quick-stats full-width-card">
            <h2 style="margin-top: 0;">Security Overview</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <span class="stat-number" id="totalRules">50+</span>
                    <div class="stat-label">Security Rules</div>
                </div>
                <div class="stat-item">
                    <span class="stat-number" id="owaspCategories">10</span>
                    <div class="stat-label">OWASP Categories</div>
                </div>
                <div class="stat-item">
                    <span class="stat-number" id="languagesSupported">9+</span>
                    <div class="stat-label">Languages</div>
                </div>
                <div class="stat-item">
                    <span class="stat-number" id="lastScanScore">Not scanned</span>
                    <div class="stat-label">Last Scan</div>
                </div>
            </div>
        </div>

        <!-- Security Analysis -->
        <div class="dashboard-card">
            <div class="card-header">
                <span class="card-icon">🔍</span>
                <h3 class="card-title">Security Analysis</h3>
            </div>
            <div class="card-description">
                Run comprehensive security audits on your codebase to detect OWASP Top 10 vulnerabilities.
            </div>
            <button class="btn" onclick="auditWorkspace()">
                <span class="btn-icon">📁</span>Audit Entire Workspace
            </button>
            <div class="instruction-tip">
                <strong>💡 Tip:</strong> To audit current file, navigate to the file and use <code>Cmd+Shift+P</code> → <code>Security Checker: Audit Current File</code>
            </div>
        </div>

        <!-- Security Reports -->
        <div class="dashboard-card">
            <div class="card-header">
                <span class="card-icon">📊</span>
                <h3 class="card-title">Security Reports</h3>
            </div>
            <div class="card-description">
                Generate detailed security reports and export them for documentation or compliance.
            </div>
            <button class="btn" onclick="showReport()">
                <span class="btn-icon">📈</span>View Security Report
            </button>
            <button class="btn btn-secondary" onclick="exportPdf()">
                <span class="btn-icon">📄</span>Export to PDF
            </button>
        </div>

        <!-- OWASP Top 10 Coverage -->
        <div class="dashboard-card owasp-coverage-card full-width-card">
            <div class="card-header">
                <span class="card-icon">🛡️</span>
                <h3 class="card-title">OWASP Top 10 2021 - Complete Security Coverage</h3>
            </div>
            <div class="card-description">
                Comprehensive analysis covering all OWASP Top 10 security vulnerabilities with 50+ predefined detection rules and real-time monitoring.
            </div>
            <div class="owasp-grid">
                <div class="owasp-item">
                    <div class="owasp-item-header">
                        <div class="owasp-item-title">A01: Broken Access Control</div>
                        <div class="owasp-status">✓ Active</div>
                    </div>
                    <div class="owasp-description">Detects unauthorized access, privilege escalation, and permission bypasses</div>
                </div>
                <div class="owasp-item">
                    <div class="owasp-item-header">
                        <div class="owasp-item-title">A02: Cryptographic Failures</div>
                        <div class="owasp-status">✓ Active</div>
                    </div>
                    <div class="owasp-description">Identifies weak encryption, exposed keys, and insecure crypto implementations</div>
                </div>
                <div class="owasp-item">
                    <div class="owasp-item-header">
                        <div class="owasp-item-title">A03: Injection Attacks</div>
                        <div class="owasp-status">✓ Active</div>
                    </div>
                    <div class="owasp-description">SQL injection, NoSQL injection, command injection, and LDAP injection detection</div>
                </div>
                <div class="owasp-item">
                    <div class="owasp-item-header">
                        <div class="owasp-item-title">A04: Insecure Design</div>
                        <div class="owasp-status">✓ Active</div>
                    </div>
                    <div class="owasp-description">Architectural flaws and insecure design patterns identification</div>
                </div>
                <div class="owasp-item">
                    <div class="owasp-item-header">
                        <div class="owasp-item-title">A05: Security Misconfiguration</div>
                        <div class="owasp-status">✓ Active</div>
                    </div>
                    <div class="owasp-description">Default configurations, verbose errors, and insecure server setups</div>
                </div>
                <div class="owasp-item">
                    <div class="owasp-item-header">
                        <div class="owasp-item-title">A06: Vulnerable Components</div>
                        <div class="owasp-status">✓ Active</div>
                    </div>
                    <div class="owasp-description">Outdated libraries, vulnerable dependencies, and insecure APIs</div>
                </div>
                <div class="owasp-item">
                    <div class="owasp-item-header">
                        <div class="owasp-item-title">A07: Authentication Failures</div>
                        <div class="owasp-status">✓ Active</div>
                    </div>
                    <div class="owasp-description">Weak passwords, broken session management, and credential stuffing</div>
                </div>
                <div class="owasp-item">
                    <div class="owasp-item-header">
                        <div class="owasp-item-title">A08: Software Integrity Failures</div>
                        <div class="owasp-status">✓ Active</div>
                    </div>
                    <div class="owasp-description">Code tampering, malicious updates, and supply chain attacks</div>
                </div>
                <div class="owasp-item">
                    <div class="owasp-item-header">
                        <div class="owasp-item-title">A09: Security Logging Failures</div>
                        <div class="owasp-status">✓ Active</div>
                    </div>
                    <div class="owasp-description">Insufficient logging, monitoring gaps, and incident response issues</div>
                </div>
                <div class="owasp-item">
                    <div class="owasp-item-header">
                        <div class="owasp-item-title">A10: Server-Side Request Forgery</div>
                        <div class="owasp-status">✓ Active</div>
                    </div>
                    <div class="owasp-description">SSRF attacks, internal service exploitation, and network boundary bypass</div>
                </div>
            </div>
        </div>

        <!-- Recent Activity -->
        <div class="dashboard-card recent-activity full-width-card">
            <div class="card-header">
                <span class="card-icon">📝</span>
                <h3 class="card-title">Recent Activity</h3>
            </div>
            <div class="card-description">
                Track your recent security analysis activities and findings.
            </div>
            <button class="btn btn-secondary" onclick="clearDiagnostics()" style="margin-bottom: 15px;">
                <span class="btn-icon">🗑️</span>Clear Diagnostics
            </button>
            <div id="recentActivity">
                <div class="activity-item">
                    <span class="activity-icon">🔍</span>
                    <span class="activity-text">Welcome to Security Checker Dashboard!</span>
                    <span class="activity-time">Just now</span>
                </div>
                <div class="activity-item">
                    <span class="activity-icon">ℹ️</span>
                    <span class="activity-text">Click "Audit Workspace" to start your first security scan</span>
                    <span class="activity-time">-</span>
                </div>
            </div>
        </div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();

        function auditWorkspace() {
            vscode.postMessage({
                command: 'auditWorkspace'
            });
            addActivity('🔍', 'Started workspace security audit');
            updateScanStatus('Scanning...');
        }

        function showReport() {
            vscode.postMessage({
                command: 'showReport'
            });
            addActivity('📊', 'Opened security report');
        }

        function exportPdf() {
            vscode.postMessage({
                command: 'exportPdf'
            });
            addActivity('📄', 'Exported security report to PDF');
        }

        function clearDiagnostics() {
            vscode.postMessage({
                command: 'clearDiagnostics'
            });
            addActivity('🗑️', 'Cleared security diagnostics');
            updateScanStatus('Not scanned');
        }

        function updateScanStatus(status) {
            const scoreElement = document.getElementById('lastScanScore');
            if (scoreElement) {
                scoreElement.textContent = status;
            }
        }

        function addActivity(icon, text) {
            const activityContainer = document.getElementById('recentActivity');
            const newActivity = document.createElement('div');
            newActivity.className = 'activity-item';
            newActivity.innerHTML = \`
                <span class="activity-icon">\${icon}</span>
                <span class="activity-text">\${text}</span>
                <span class="activity-time">Just now</span>
            \`;
            activityContainer.insertBefore(newActivity, activityContainer.firstChild);
            
            // Keep only the last 5 activities
            const activities = activityContainer.querySelectorAll('.activity-item');
            if (activities.length > 5) {
                activityContainer.removeChild(activities[activities.length - 1]);
            }
        }

        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            console.log('Security Checker Dashboard loaded');
        });

        // Listen for messages from the extension
        window.addEventListener('message', event => {
            const message = event.data;
            switch (message.command) {
                case 'updateScanResults':
                    updateScanResults(message.vulnerabilities, message.score);
                    break;
            }
        });

        function updateScanResults(vulnerabilityCount, score) {
            const scoreElement = document.getElementById('lastScanScore');
            if (scoreElement) {
                if (score >= 0) {
                    scoreElement.textContent = score + '/100';
                    scoreElement.style.color = score >= 70 ? '#28a745' : score >= 50 ? '#ffc107' : '#dc3545';
                } else {
                    scoreElement.textContent = vulnerabilityCount === 0 ? '✅ Clean' : vulnerabilityCount + ' issues';
                    scoreElement.style.color = vulnerabilityCount === 0 ? '#28a745' : '#dc3545';
                }
            }
            
            // Add activity for completed scan
            addActivity('✅', \`Scan completed: \${vulnerabilityCount} vulnerabilities found\`);
        }
    </script>
</body>
</html>`;
    }
}

export { SecurityDashboardProvider };
