import * as vscode from 'vscode';
import { MultiLanguageParser } from './security/parser';
import { OwaspSecurityAnalyzer, SecurityVulnerability } from './security/owaspRules';
import { SecurityReportGenerator, SecurityReport } from './security/reportGenerator';
import { SecurityDiagnosticsProvider, SecurityTreeDataProvider } from './ui/diagnostics';
import { DashboardTreeDataProvider } from './ui/dashboardTreeProvider';
import { SecurityChatParticipant } from './chat/chatParticipant';
import { SecurityDashboardProvider } from './ui/dashboardProvider';
import { PdfExporter } from './utils/pdfExporter';

let diagnosticsProvider: SecurityDiagnosticsProvider;
let treeDataProvider: SecurityTreeDataProvider;
let dashboardProvider: SecurityDashboardProvider;
let statusBarItem: vscode.StatusBarItem;
let reportWebviewPanel: vscode.WebviewPanel | undefined;
let currentReport: SecurityReport | undefined;

export function activate(context: vscode.ExtensionContext) {
    console.log('Security Checker Agent extension is now active!');

    // Initialize providers
    diagnosticsProvider = new SecurityDiagnosticsProvider();
    treeDataProvider = new SecurityTreeDataProvider();
    dashboardProvider = new SecurityDashboardProvider(context.extensionUri);

    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.text = "$(shield) Security";
    statusBarItem.tooltip = "Open Security Checker Dashboard";
    statusBarItem.command = 'security-checker-agent.openDashboard';
    statusBarItem.show();
    
    // Register tree view
    const treeView = vscode.window.createTreeView('securityCheckerView', {
        treeDataProvider: treeDataProvider,
        showCollapseAll: true
    });

    // Register dashboard view (empty tree data provider for the dashboard view)
    const dashboardTreeDataProvider = new DashboardTreeDataProvider();
    
    const dashboardView = vscode.window.createTreeView('securityDashboardView', {
        treeDataProvider: dashboardTreeDataProvider,
        showCollapseAll: false
    });

    // Auto-open dashboard when the Security Checker activity bar is opened
    dashboardView.onDidChangeVisibility((e) => {
        if (e.visible) {
            // Small delay to ensure the view is fully rendered
            setTimeout(() => {
                dashboardProvider.show();
            }, 100);
        }
    });

    treeView.onDidChangeVisibility((e) => {
        if (e.visible) {
            // Small delay to ensure the view is fully rendered
            setTimeout(() => {
                dashboardProvider.show();
            }, 100);
        }
    });

    // Register chat participant
    const chatParticipant = new SecurityChatParticipant();
    const participant = vscode.chat.createChatParticipant('security-checker-agent', chatParticipant.handleChatRequest.bind(chatParticipant));
    participant.iconPath = new vscode.ThemeIcon('shield');

    // Register commands
    const openDashboardCommand = vscode.commands.registerCommand('security-checker-agent.openDashboard', () => {
        dashboardProvider.show();
    });

    const auditWorkspaceCommand = vscode.commands.registerCommand('security-checker-agent.auditWorkspace', async () => {
        await auditWorkspace();
    });

    const auditCurrentFileCommand = vscode.commands.registerCommand('security-checker-agent.auditCurrentFile', async () => {
        await auditCurrentFile();
    });

    const showSecurityReportCommand = vscode.commands.registerCommand('security-checker-agent.showSecurityReport', async () => {
        await showSecurityReport();
    });

    const clearDiagnosticsCommand = vscode.commands.registerCommand('security-checker-agent.clearDiagnostics', () => {
        clearDiagnostics();
    });

    const exportToPdfCommand = vscode.commands.registerCommand('security-checker-agent.exportToPdf', async () => {
        await PdfExporter.exportSecurityReportToPdf(currentReport);
    });

    // Auto-analysis on file save (if enabled)
    const onDidSaveDocument = vscode.workspace.onDidSaveTextDocument(async (document: vscode.TextDocument) => {
        const config = vscode.workspace.getConfiguration('securityChecker');
        const enableRealTime = config.get<boolean>('enableRealTimeAnalysis', true);
        
        if (enableRealTime && document.uri.scheme === 'file') {
            await analyzeDocument(document);
        }
    });

    // Auto-analysis on active editor change (if enabled)
    const onDidChangeActiveTextEditor = vscode.window.onDidChangeActiveTextEditor(async (editor: vscode.TextEditor | undefined) => {
        const config = vscode.workspace.getConfiguration('securityChecker');
        const enableRealTime = config.get<boolean>('enableRealTimeAnalysis', true);
        
        if (enableRealTime && editor?.document.uri.scheme === 'file') {
            await analyzeDocument(editor.document);
        }
    });

    // Register all disposables
    context.subscriptions.push(
        diagnosticsProvider,
        treeView,
        dashboardView,
        participant,
        statusBarItem,
        openDashboardCommand,
        auditWorkspaceCommand,
        auditCurrentFileCommand,
        showSecurityReportCommand,
        clearDiagnosticsCommand,
        exportToPdfCommand,
        onDidSaveDocument,
        onDidChangeActiveTextEditor
    );

    // Show welcome message
    showWelcomeNotification(context);
}

async function showWelcomeNotification(context: vscode.ExtensionContext): Promise<void> {
    // Check if this is a new installation by looking for a flag in global state
    const hasShownWelcome = context.globalState.get<boolean>('hasShownWelcome', false);
    
    if (!hasShownWelcome) {
        // Mark as shown so it doesn't appear again
        await context.globalState.update('hasShownWelcome', true);
        
        // Show the welcome notification
        vscode.window.showInformationMessage(
            '🛡️ Welcome to Security Checker Agent v1.0.2! Start securing your code with comprehensive OWASP Top 10 analysis.',
            'Audit Workspace',
            'Open Dashboard'
        ).then((selection: string | undefined) => {
            if (selection === 'Audit Workspace') {
                vscode.commands.executeCommand('security-checker-agent.auditWorkspace');
            } else if (selection === 'Open Dashboard') {
                vscode.commands.executeCommand('security-checker-agent.openDashboard');
            }
        });
    }
}

async function auditWorkspace(): Promise<void> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        vscode.window.showErrorMessage('No workspace folder found. Please open a workspace to analyze.');
        return;
    }

    return vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Security Analysis',
        cancellable: true
    }, async (progress: vscode.Progress<{ message?: string; increment?: number }>, token: vscode.CancellationToken) => {
        progress.report({ increment: 0, message: 'Starting security analysis...' });

        try {
            const config = vscode.workspace.getConfiguration('securityChecker');
            const enabledRules = config.get<string[]>('enabledRules');
            
            const parser = new MultiLanguageParser(enabledRules);
            const analyzer = new OwaspSecurityAnalyzer(enabledRules);
            const reportGenerator = new SecurityReportGenerator();

            let allVulnerabilities: SecurityVulnerability[] = [];
            let totalFiles = 0;

            for (let i = 0; i < workspaceFolders.length; i++) {
                if (token.isCancellationRequested) {
                    return;
                }

                const workspaceFolder = workspaceFolders[i];
                progress.report({ 
                    increment: (i / workspaceFolders.length) * 50, 
                    message: `Analyzing ${workspaceFolder.name}...` 
                });

                const parsedFiles = await parser.parseWorkspace(workspaceFolder.uri);
                totalFiles += parsedFiles.length;

                for (const file of parsedFiles) {
                    if (token.isCancellationRequested) {
                        return;
                    }

                    allVulnerabilities.push(...file.vulnerabilities);

                    // Perform AST analysis for JavaScript/TypeScript
                    if (file.ast && (file.language === 'javascript' || file.language === 'typescript')) {
                        const astVulnerabilities = await parser.performAdvancedASTAnalysis(file.ast, file.language);
                        allVulnerabilities.push(...astVulnerabilities.map(v => ({ ...v, filePath: file.filePath })));
                    }
                }
            }

            progress.report({ increment: 75, message: 'Generating security report...' });

            // Calculate security score
            const scoreData = analyzer.calculateSecurityScore(allVulnerabilities);

            // Generate report
            currentReport = reportGenerator.generateReport(
                allVulnerabilities,
                workspaceFolders[0].name,
                totalFiles,
                scoreData
            );

            // Update UI
            diagnosticsProvider.updateDiagnostics(allVulnerabilities);
            treeDataProvider.updateVulnerabilities(allVulnerabilities);
            dashboardProvider.updateScanResults(allVulnerabilities.length, scoreData.score);

            progress.report({ increment: 100, message: 'Analysis complete!' });

            // Show summary
            const emoji = scoreData.score >= 85 ? '🟢' : scoreData.score >= 70 ? '🟡' : '🔴';
            const message = `${emoji} Security Analysis Complete!\\n\\nScore: ${scoreData.score}/100 (${scoreData.level})\\nVulnerabilities: ${allVulnerabilities.length}\\nFiles: ${totalFiles}`;
            
            const action = await vscode.window.showInformationMessage(
                message,
                'View Report',
                'Show Problems'
            );

            if (action === 'View Report') {
                await showSecurityReport();
            } else if (action === 'Show Problems') {
                vscode.commands.executeCommand('workbench.action.problems.focus');
            }

        } catch (error) {
            vscode.window.showErrorMessage(`Security analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    });
}

async function auditCurrentFile(): Promise<void> {
    const activeEditor = vscode.window.activeTextEditor;
    if (!activeEditor) {
        vscode.window.showErrorMessage('No active file. Please open a file to analyze.');
        return;
    }

    return vscode.window.withProgress({
        location: vscode.ProgressLocation.Window,
        title: 'Analyzing current file...',
        cancellable: false
    }, async (progress: vscode.Progress<{ message?: string }>) => {
        try {
            await analyzeDocument(activeEditor.document);
            
            const fileName = activeEditor.document.fileName.split('/').pop();
            vscode.window.showInformationMessage(`✅ Security analysis complete for ${fileName}`);
        } catch (error) {
            vscode.window.showErrorMessage(`Analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    });
}

async function analyzeDocument(document: vscode.TextDocument): Promise<void> {
    if (document.uri.scheme !== 'file') {
        return;
    }

    try {
        const config = vscode.workspace.getConfiguration('securityChecker');
        const enabledRules = config.get<string[]>('enabledRules');
        
        const parser = new MultiLanguageParser(enabledRules);
        const parsedFile = await parser.parseFile(document.uri);
        
        if (!parsedFile) {
            return; // Unsupported file type
        }

        let vulnerabilities = parsedFile.vulnerabilities;

        // Perform AST analysis for JavaScript/TypeScript
        if (parsedFile.ast && (parsedFile.language === 'javascript' || parsedFile.language === 'typescript')) {
            const astVulnerabilities = await parser.performAdvancedASTAnalysis(parsedFile.ast, parsedFile.language);
            vulnerabilities.push(...astVulnerabilities.map(v => ({ ...v, filePath: parsedFile.filePath })));
        }

        // Update diagnostics for this file
        diagnosticsProvider.updateDiagnostics([parsedFile].flatMap(f => f.vulnerabilities));
        
        // Update tree view if there are vulnerabilities
        if (vulnerabilities.length > 0) {
            treeDataProvider.updateVulnerabilities(vulnerabilities);
        }

        // Update dashboard with current file analysis results
        const analyzer = new OwaspSecurityAnalyzer();
        const scoreData = analyzer.calculateSecurityScore(vulnerabilities);
        dashboardProvider.updateScanResults(vulnerabilities.length, scoreData.score);

    } catch (error) {
        console.error('Error analyzing document:', error);
    }
}

async function showSecurityReport(): Promise<void> {
    if (!currentReport) {
        vscode.window.showWarningMessage('No security report available. Please run an analysis first.');
        return;
    }

    // Create or reveal webview panel
    if (reportWebviewPanel) {
        reportWebviewPanel.reveal(vscode.ViewColumn.Two);
    } else {
        reportWebviewPanel = vscode.window.createWebviewPanel(
            'securityReport',
            'Security Analysis Report',
            vscode.ViewColumn.Two,
            {
                enableScripts: true,
                retainContextWhenHidden: true
            }
        );

        // Handle messages from the webview
        reportWebviewPanel.webview.onDidReceiveMessage(
            async message => {
                switch (message.command) {
                    case 'navigateToVulnerability':
                        await navigateToVulnerability(message.filePath, message.line, message.column, message.suggestion);
                        break;
                }
            }
        );

        reportWebviewPanel.onDidDispose(() => {
            reportWebviewPanel = undefined;
        });
    }

    // Generate and set HTML content
    const reportGenerator = new SecurityReportGenerator();
    const htmlContent = reportGenerator.generateHTMLReport(currentReport);
    reportWebviewPanel.webview.html = htmlContent;
}

function clearDiagnostics(): void {
    diagnosticsProvider.clearDiagnostics();
    treeDataProvider.updateVulnerabilities([]);
    dashboardProvider.updateScanResults(0, 0);
    vscode.window.showInformationMessage('Security diagnostics cleared.');
}

async function navigateToVulnerability(filePath: string, line: number, column: number, suggestion: string): Promise<void> {
    try {
        // Open the file
        const document = await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
        const editor = await vscode.window.showTextDocument(document, vscode.ViewColumn.One);
        
        // Navigate to the specific line and column
        const position = new vscode.Position(Math.max(0, line - 1), Math.max(0, column - 1));
        const range = new vscode.Range(position, position);
        
        // Move cursor to the position
        editor.selection = new vscode.Selection(position, position);
        editor.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
        
        // Add a comment with the suggestion
        const lineText = document.lineAt(position.line).text;
        const commentPrefix = getCommentPrefix(filePath);
        const suggestionComment = `${commentPrefix} 🛡️ Security Suggestion: ${suggestion}`;
        
        // Insert the comment above the vulnerable line
        await editor.edit(editBuilder => {
            const commentPosition = new vscode.Position(position.line, 0);
            const indentation = lineText.match(/^\s*/)?.[0] || '';
            editBuilder.insert(commentPosition, `${indentation}${suggestionComment}\n`);
        });
        
        // Show success message
        vscode.window.showInformationMessage(`Navigated to vulnerability and added security suggestion as comment.`);
        
    } catch (error) {
        vscode.window.showErrorMessage(`Failed to navigate to vulnerability: ${error}`);
    }
}

function getCommentPrefix(filePath: string): string {
    const extension = filePath.split('.').pop()?.toLowerCase();
    
    switch (extension) {
        case 'js':
        case 'jsx':
        case 'ts':
        case 'tsx':
        case 'java':
        case 'c':
        case 'cpp':
        case 'cs':
        case 'go':
        case 'php':
            return '//';
        case 'py':
        case 'rb':
            return '#';
        case 'html':
        case 'xml':
            return '<!--';
        default:
            return '//';
    }
}

export function deactivate() {
    if (reportWebviewPanel) {
        reportWebviewPanel.dispose();
    }
}
