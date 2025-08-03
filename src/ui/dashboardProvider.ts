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
                    case 'openLearningMode':
                        this.openLearningMode();
                        break;
                    case 'viewKnowledgeBase':
                        this.viewKnowledgeBase();
                        break;
                    case 'learnTopic':
                        this.learnSpecificTopic(message.topic);
                        break;
                    case 'scanMCP':
                        vscode.commands.executeCommand('security-checker-agent.scanMCP');
                        break;
                    case 'stopMCPScan':
                        vscode.commands.executeCommand('security-checker-agent.stopMCPScan');
                        break;
                    case 'learnMCPSecurity':
                        this.learnMCPSecurity();
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

    public updateMCPScanResults(serverCount: number, vulnerabilityCount: number, score: number): void {
        if (this.panel) {
            this.panel.webview.postMessage({
                command: 'updateMCPScanResults',
                servers: serverCount,
                vulnerabilities: vulnerabilityCount,
                score: score
            });
        }
    }

    private learnMCPSecurity(): void {
        // Open GitHub Copilot Chat with MCP security learning prompt
        vscode.window.showInformationMessage(
            'Opening MCP Security Learning Mode...',
            'Start Learning with Copilot'
        ).then(selection => {
            if (selection === 'Start Learning with Copilot') {
                vscode.commands.executeCommand('workbench.panel.chat.view.copilot.focus');
                // Pre-fill with MCP security learning command
                vscode.commands.executeCommand('workbench.action.chat.openInSidebar', {
                    query: '@security learn mcp-security: Tell me about Model Context Protocol security best practices, OWASP LLM Top 10, and how to prevent prompt injection attacks in MCP servers.'
                });
            }
        });
    }

    private openLearningMode(): void {
        // Open GitHub Copilot Chat with a learning prompt
        vscode.window.showInformationMessage(
            'Opening Security Learning Mode...',
            'Start Learning with Copilot'
        ).then(selection => {
            if (selection === 'Start Learning with Copilot') {
                vscode.commands.executeCommand('workbench.panel.chat.view.copilot.focus');
                // Optionally pre-fill with a learning command
                vscode.commands.executeCommand('workbench.action.chat.openInSidebar', {
                    query: '@security help'
                });
            }
        });
    }

    private viewKnowledgeBase(): void {
        // Show quick pick with knowledge base topics
        const knowledgeTopics = [
            'SQL Injection Prevention',
            'XSS Protection',
            'Authentication Security',
            'Input Validation',
            'Cryptography Best Practices',
            'CORS Configuration',
            'File Upload Security'
        ];

        vscode.window.showQuickPick(knowledgeTopics, {
            placeHolder: 'Select a security topic to learn about',
            title: 'Security Knowledge Base'
        }).then(selection => {
            if (selection) {
                // Open chat with specific learning topic
                vscode.commands.executeCommand('workbench.panel.chat.view.copilot.focus');
                vscode.commands.executeCommand('workbench.action.chat.openInSidebar', {
                    query: `@security learn ${selection.toLowerCase().replace(/\s+/g, '-')}`
                });
            }
        });
    }

    private learnSpecificTopic(topic: string): void {
        // Directly open GitHub Copilot Chat with specific topic
        vscode.commands.executeCommand('workbench.panel.chat.view.copilot.focus');
        vscode.commands.executeCommand('workbench.action.chat.openInSidebar', {
            query: `@security learn ${topic}`
        });
        
        // Show a brief notification
        vscode.window.showInformationMessage(`🎓 Learning about ${topic.replace('-', ' ')} with Copilot Chat`);
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

        .btn-danger {
            background-color: #dc3545;
            color: #ffffff;
        }

        .btn-danger:hover {
            background-color: #c82333;
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

        /* MCP Security Card Styles */
        .mcp-security-card {
            background: linear-gradient(135deg, #0e0e0eff, #1a1d29);
            color: #ffffff;
            border: 2px solid rgba(255, 87, 34, 0.6);
            border-radius: 12px;
            position: relative;
            overflow: hidden;
        }

        .mcp-security-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #ff5722, #ff9800, #ffc107);
        }

        .new-feature-badge {
            background: linear-gradient(45deg, #ff6b6b, #ee5a24);
            color: white;
            font-size: 10px;
            font-weight: bold;
            padding: 2px 8px;
            border-radius: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-left: auto;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }

        .mcp-status-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin: 20px 0;
            padding: 15px;
            background: var(--vscode-input-background);
            border-radius: 8px;
            border: 1px solid var(--vscode-panel-border);
        }

        .mcp-status-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px;
            background: var(--vscode-editor-background);
            border-radius: 6px;
            border: 1px solid var(--vscode-panel-border);
        }

        .mcp-status-icon {
            font-size: 20px;
            width: 30px;
            text-align: center;
        }

        .mcp-status-text {
            flex: 1;
        }

        .mcp-status-title {
            font-size: 11px;
            color: var(--vscode-descriptionForeground);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 2px;
        }

        .mcp-status-value {
            font-size: 13px;
            font-weight: 600;
            color: var(--vscode-foreground);
        }

        .mcp-action-buttons {
            display: flex;
            gap: 10px;
            margin: 15px 0;
            flex-wrap: wrap;
        }

        .mcp-action-buttons .btn {
            flex: 1;
            min-width: 180px;
        }

        .mcp-vulnerability-categories {
            margin: 20px 0;
        }

        .mcp-vulnerability-categories h4 {
            color: #ff5722;
            margin-bottom: 15px;
            font-size: 14px;
        }

        .mcp-categories-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 8px;
        }

        .mcp-category {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 8px 10px;
            background: var(--vscode-input-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 6px;
            font-size: 11px;
            transition: all 0.2s ease;
        }

        .mcp-category:hover {
            background: var(--vscode-list-hoverBackground);
            border-color: #ff5722;
        }

        .category-icon {
            font-size: 12px;
        }

        .category-name {
            flex: 1;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .mcp-scanning {
            animation: mcpScan 3s infinite;
        }

        @keyframes mcpScan {
            0% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.1); opacity: 0.8; }
            100% { transform: scale(1); opacity: 1; }
        }

        /* MCP Scan Progress Styles */
        .mcp-scan-progress {
            margin: 20px 0;
            padding: 15px;
            background: var(--vscode-input-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 8px;
        }

        .scan-progress-bar {
            width: 100%;
            height: 8px;
            background: var(--vscode-progressBar-background);
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 10px;
        }

        .scan-progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #ff5722, #ff9800);
            border-radius: 4px;
            animation: progressPulse 2s infinite;
            width: 0%;
            transition: width 0.3s ease;
        }

        @keyframes progressPulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }

        .scan-progress-text {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
        }

        #mcpScanStage {
            font-weight: 600;
            color: var(--vscode-foreground);
        }

        #mcpScanTime {
            color: #ff5722;
            font-weight: 600;
        }

        /* MCP Notifications Styles */
        .mcp-notifications {
            margin-top: 15px;
        }

        .mcp-notification {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 15px;
            margin-bottom: 10px;
            border-radius: 6px;
            font-size: 13px;
            animation: slideIn 0.3s ease;
        }

        .mcp-notification.info {
            background: rgba(13, 110, 253, 0.1);
            border: 1px solid rgba(13, 110, 253, 0.3);
            color: #0d6efd;
        }

        .mcp-notification.success {
            background: rgba(25, 135, 84, 0.1);
            border: 1px solid rgba(25, 135, 84, 0.3);
            color: #198754;
        }

        .mcp-notification.warning {
            background: rgba(255, 193, 7, 0.1);
            border: 1px solid rgba(255, 193, 7, 0.3);
            color: #ffc107;
        }

        .mcp-notification.error {
            background: rgba(220, 53, 69, 0.1);
            border: 1px solid rgba(220, 53, 69, 0.3);
            color: #dc3545;
        }

        .notification-content {
            flex: 1;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .notification-close {
            background: none;
            border: none;
            color: inherit;
            cursor: pointer;
            font-size: 16px;
            padding: 0;
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 3px;
            transition: background-color 0.2s ease;
        }

        .notification-close:hover {
            background: rgba(255, 255, 255, 0.1);
        }

        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }

        @keyframes slideOut {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(100%);
                opacity: 0;
            }
        }

        /* Button States */
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        .btn.btn-scanning {
            background: linear-gradient(45deg, #ff5722, #ff9800);
            animation: scanningPulse 1.5s infinite;
        }

        @keyframes scanningPulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.05); opacity: 0.9; }
        }

        @media (max-width: 1024px) {
            .mcp-status-grid {
                grid-template-columns: 1fr;
            }
            
            .mcp-categories-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        @media (max-width: 768px) {
            .mcp-action-buttons {
                flex-direction: column;
            }
            
            .mcp-action-buttons .btn {
                min-width: unset;
            }
            
            .mcp-categories-grid {
                grid-template-columns: 1fr;
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

        <!-- MCP Security Checker -->
        <div class="dashboard-card mcp-security-card full-width-card">
            <div class="card-header">
                <span class="card-icon">🤖</span>
                <h3 class="card-title">MCP Security Checker</h3>
                <span class="new-feature-badge">NEW</span>
            </div>
            <div class="card-description">
                Comprehensive security analysis for Model Context Protocol (MCP) servers. Detects 10 critical MCP security vulnerabilities including prompt injection, tool poisoning, and OWASP LLM Top 10 violations.
            </div>
            
            <div class="mcp-status-grid">
                <div class="mcp-status-item">
                    <div class="mcp-status-icon" id="mcpDetectionStatus">🔍</div>
                    <div class="mcp-status-text">
                        <div class="mcp-status-title">MCP Detection</div>
                        <div class="mcp-status-value" id="mcpServersFound">Checking...</div>
                    </div>
                </div>
                <div class="mcp-status-item">
                    <div class="mcp-status-icon" id="mcpSecurityStatus">🛡️</div>
                    <div class="mcp-status-text">
                        <div class="mcp-status-title">Security Status</div>
                        <div class="mcp-status-value" id="mcpVulnerabilities">Not scanned</div>
                    </div>
                </div>
                <div class="mcp-status-item">
                    <div class="mcp-status-icon" id="mcpOwaspStatus">📋</div>
                    <div class="mcp-status-text">
                        <div class="mcp-status-title">OWASP LLM</div>
                        <div class="mcp-status-value" id="mcpOwaspCompliance">Pending</div>
                    </div>
                </div>
            </div>

            <div class="mcp-action-buttons">
                <button class="btn btn-primary" onclick="scanMCP()" id="mcpScanButton">
                    <span class="btn-icon">🔍</span>Start MCP Security Scan
                </button>
                <button class="btn btn-danger" onclick="stopMCPScan()" id="mcpStopButton" style="display: none;">
                    <span class="btn-icon">⏹️</span>Stop Scan
                </button>
                <button class="btn btn-secondary" onclick="learnMCPSecurity()">
                    <span class="btn-icon">🎓</span>Learn MCP Security
                </button>
            </div>

            <!-- MCP Scan Progress Indicator -->
            <div id="mcpScanProgress" class="mcp-scan-progress" style="display: none;">
                <div class="scan-progress-bar">
                    <div class="scan-progress-fill"></div>
                </div>
                <div class="scan-progress-text">
                    <span id="mcpScanStage">Initializing scan...</span>
                    <span id="mcpScanTime">0s</span>
                </div>
            </div>

            <!-- MCP Notifications -->
            <div id="mcpNotifications" class="mcp-notifications"></div>

            <div class="mcp-vulnerability-categories">
                <h4>🛡️ MCP Security Coverage:</h4>
                <div class="mcp-categories-grid">
                    <div class="mcp-category">
                        <span class="category-icon">⚡</span>
                        <span class="category-name">Prompt Injection</span>
                    </div>
                    <div class="mcp-category">
                        <span class="category-icon">🧪</span>
                        <span class="category-name">Tool Poisoning</span>
                    </div>
                    <div class="mcp-category">
                        <span class="category-icon">🔄</span>
                        <span class="category-name">Dynamic Tool Changes</span>
                    </div>
                    <div class="mcp-category">
                        <span class="category-icon">🔐</span>
                        <span class="category-name">Auth & Authorization</span>
                    </div>
                    <div class="mcp-category">
                        <span class="category-icon">🎯</span>
                        <span class="category-name">Excessive Permissions</span>
                    </div>
                    <div class="mcp-category">
                        <span class="category-icon">🔗</span>
                        <span class="category-name">Indirect Injections</span>
                    </div>
                    <div class="mcp-category">
                        <span class="category-icon">🚪</span>
                        <span class="category-name">Session Hijacking</span>
                    </div>
                    <div class="mcp-category">
                        <span class="category-icon">👥</span>
                        <span class="category-name">Confused Deputy</span>
                    </div>
                    <div class="mcp-category">
                        <span class="category-icon">🎫</span>
                        <span class="category-name">Token Passthrough</span>
                    </div>
                    <div class="mcp-category">
                        <span class="category-icon">📦</span>
                        <span class="category-name">Supply Chain</span>
                    </div>
                </div>
            </div>

            <div class="instruction-tip">
                <strong>🤖 MCP Security:</strong> This scanner analyzes Model Context Protocol implementations against OWASP LLM Top 10 and emerging MCP-specific threats.
            </div>
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

        function openLearningMode() {
            vscode.postMessage({
                command: 'openLearningMode'
            });
            addActivity('🎓', 'Started interactive learning session');
        }

        function viewKnowledgeBase() {
            vscode.postMessage({
                command: 'viewKnowledgeBase'
            });
            addActivity('🧠', 'Accessed security knowledge base');
        }

        function learnTopic(topic) {
            vscode.postMessage({
                command: 'learnTopic',
                topic: topic
            });
            addActivity('📚', \`Started learning: \${topic.replace('-', ' ').toUpperCase()}\`);
        }

        function clearDiagnostics() {
            vscode.postMessage({
                command: 'clearDiagnostics'
            });
            addActivity('🗑️', 'Cleared security diagnostics');
            updateScanStatus('Not scanned');
        }

        function scanMCP() {
            vscode.postMessage({
                command: 'scanMCP'
            });
            addActivity('🤖', 'Started MCP security scan');
            updateMCPScanUI(true);
            startScanProgress();
            showNotification('info', '🔍', 'MCP security scan initiated...');
        }

        function stopMCPScan() {
            vscode.postMessage({
                command: 'stopMCPScan'
            });
            updateMCPScanUI(false);
            stopScanProgress();
            showNotification('warning', '⏹️', 'MCP scan stopped by user');
            addActivity('⏹️', 'Stopped MCP security scan');
        }

        function learnMCPSecurity() {
            vscode.postMessage({
                command: 'learnMCPSecurity'
            });
            addActivity('🎓', 'Started MCP security learning session');
        }

        function updateMCPScanUI(isScanning) {
            const scanButton = document.getElementById('mcpScanButton');
            const stopButton = document.getElementById('mcpStopButton');
            const detectionStatus = document.getElementById('mcpDetectionStatus');
            const securityStatus = document.getElementById('mcpSecurityStatus');
            const owaspStatus = document.getElementById('mcpOwaspStatus');
            
            if (isScanning) {
                scanButton.innerHTML = '<span class="btn-icon">⏳</span>Scanning...';
                scanButton.disabled = true;
                scanButton.classList.add('btn-scanning');
                stopButton.style.display = 'inline-block';
                
                detectionStatus.className = 'mcp-status-icon mcp-scanning';
                securityStatus.className = 'mcp-status-icon mcp-scanning';
                owaspStatus.className = 'mcp-status-icon mcp-scanning';
                
                document.getElementById('mcpServersFound').textContent = 'Detecting...';
                document.getElementById('mcpVulnerabilities').textContent = 'Analyzing...';
                document.getElementById('mcpOwaspCompliance').textContent = 'Checking...';
            } else {
                scanButton.innerHTML = '<span class="btn-icon">🔍</span>Start MCP Security Scan';
                scanButton.disabled = false;
                scanButton.classList.remove('btn-scanning');
                stopButton.style.display = 'none';
                
                detectionStatus.className = 'mcp-status-icon';
                securityStatus.className = 'mcp-status-icon';
                owaspStatus.className = 'mcp-status-icon';
            }
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
                case 'updateMCPScanResults':
                    updateMCPScanResults(message.servers, message.vulnerabilities, message.score);
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

        function updateMCPScanResults(serverCount, vulnerabilityCount, score) {
            updateMCPScanUI(false);
            stopScanProgress();
            
            // Update MCP status displays
            const serversElement = document.getElementById('mcpServersFound');
            const vulnerabilitiesElement = document.getElementById('mcpVulnerabilities');
            const owaspElement = document.getElementById('mcpOwaspCompliance');
            
            if (serversElement) {
                serversElement.textContent = serverCount === 0 ? 'None detected' : \`\${serverCount} found\`;
                serversElement.style.color = serverCount === 0 ? '#6c757d' : '#28a745';
            }
            
            if (vulnerabilitiesElement) {
                vulnerabilitiesElement.textContent = vulnerabilityCount === 0 ? '✅ Secure' : \`\${vulnerabilityCount} issues\`;
                vulnerabilitiesElement.style.color = vulnerabilityCount === 0 ? '#28a745' : vulnerabilityCount > 5 ? '#dc3545' : '#ffc107';
            }
            
            if (owaspElement) {
                owaspElement.textContent = vulnerabilityCount === 0 ? '✅ Compliant' : '⚠️ Issues found';
                owaspElement.style.color = vulnerabilityCount === 0 ? '#28a745' : '#dc3545';
            }
            
            // Show completion notification
            if (serverCount === 0) {
                showNotification('info', '🔍', 'MCP scan completed: No MCP servers detected in workspace');
                addActivity('🤖', 'MCP scan completed: No MCP servers detected');
            } else {
                const notificationType = vulnerabilityCount === 0 ? 'success' : vulnerabilityCount > 5 ? 'error' : 'warning';
                const notificationIcon = vulnerabilityCount === 0 ? '✅' : '⚠️';
                showNotification(notificationType, notificationIcon, \`MCP scan completed: \${serverCount} servers analyzed, \${vulnerabilityCount} vulnerabilities found\`);
                addActivity('🤖', \`MCP scan completed: \${serverCount} servers, \${vulnerabilityCount} vulnerabilities\`);
            }
        }

        // Scan Progress Management
        let scanTimer = null;
        let scanStartTime = null;
        let currentScanStage = 0;
        const scanStages = [
            'Initializing scan...',
            'Detecting MCP servers...',
            'Analyzing configurations...',
            'Checking OWASP compliance...',
            'Generating security report...',
            'Finalizing results...'
        ];

        function startScanProgress() {
            const progressElement = document.getElementById('mcpScanProgress');
            const progressFill = document.querySelector('.scan-progress-fill');
            const stageElement = document.getElementById('mcpScanStage');
            const timeElement = document.getElementById('mcpScanTime');
            
            progressElement.style.display = 'block';
            scanStartTime = Date.now();
            currentScanStage = 0;
            
            // Update progress every 2 seconds
            scanTimer = setInterval(() => {
                const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
                timeElement.textContent = \`\${elapsed}s\`;
                
                // Progress through stages
                if (currentScanStage < scanStages.length - 1 && elapsed % 3 === 0 && elapsed > 0) {
                    currentScanStage++;
                    stageElement.textContent = scanStages[currentScanStage];
                }
                
                // Update progress bar (simulate progress)
                const progress = Math.min(90, (elapsed / 20) * 100);
                progressFill.style.width = \`\${progress}%\`;
                
                // Show timeout warning after 30 seconds
                if (elapsed === 30) {
                    showNotification('warning', '⏱️', 'Scan is taking longer than expected. You can stop it if needed.');
                }
            }, 1000);
        }

        function stopScanProgress() {
            const progressElement = document.getElementById('mcpScanProgress');
            const progressFill = document.querySelector('.scan-progress-fill');
            
            if (scanTimer) {
                clearInterval(scanTimer);
                scanTimer = null;
            }
            
            // Complete the progress bar
            progressFill.style.width = '100%';
            
            // Hide progress after a short delay
            setTimeout(() => {
                progressElement.style.display = 'none';
                progressFill.style.width = '0%';
            }, 1500);
        }

        // Notification Management
        function showNotification(type, icon, message) {
            const notificationsContainer = document.getElementById('mcpNotifications');
            const notification = document.createElement('div');
            notification.className = \`mcp-notification \${type}\`;
            
            notification.innerHTML = \`
                <div class="notification-content">
                    <span>\${icon}</span>
                    <span>\${message}</span>
                </div>
                <button class="notification-close" onclick="closeNotification(this)">×</button>
            \`;
            
            notificationsContainer.appendChild(notification);
            
            // Auto-remove after 10 seconds for info/success, 15 seconds for warning/error
            const autoRemoveTime = (type === 'info' || type === 'success') ? 10000 : 15000;
            setTimeout(() => {
                if (notification.parentNode) {
                    closeNotification(notification.querySelector('.notification-close'));
                }
            }, autoRemoveTime);
        }

        function closeNotification(closeButton) {
            const notification = closeButton.parentNode;
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }
    </script>
</body>
</html>`;
    }
}

export { SecurityDashboardProvider };
