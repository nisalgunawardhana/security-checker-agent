import * as vscode from 'vscode';
import { MultiLanguageParser } from './security/parser';
import { OwaspSecurityAnalyzer, SecurityVulnerability } from './security/owaspRules';
import { SecurityReportGenerator, SecurityReport } from './security/reportGenerator';
import { SecurityDiagnosticsProvider, SecurityTreeDataProvider } from './ui/diagnostics';
import { SecurityChatParticipant } from './chat/chatParticipant';

let diagnosticsProvider: SecurityDiagnosticsProvider;
let treeDataProvider: SecurityTreeDataProvider;
let reportWebviewPanel: vscode.WebviewPanel | undefined;
let currentReport: SecurityReport | undefined;

export function activate(context: vscode.ExtensionContext) {
    console.log('Security Checker Agent extension is now active!');

    // Initialize providers
    diagnosticsProvider = new SecurityDiagnosticsProvider();
    treeDataProvider = new SecurityTreeDataProvider();
    
    // Register tree view
    const treeView = vscode.window.createTreeView('securityCheckerView', {
        treeDataProvider: treeDataProvider,
        showCollapseAll: true
    });

    // Register chat participant
    const chatParticipant = new SecurityChatParticipant();
    const participant = vscode.chat.createChatParticipant('security-checker-agent', chatParticipant.handleChatRequest.bind(chatParticipant));
    participant.iconPath = new vscode.ThemeIcon('shield');

    // Register commands
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
        participant,
        auditWorkspaceCommand,
        auditCurrentFileCommand,
        showSecurityReportCommand,
        clearDiagnosticsCommand,
        onDidSaveDocument,
        onDidChangeActiveTextEditor
    );

    // Show welcome message
    vscode.window.showInformationMessage(
        '🛡️ Security Checker Agent is now active! Use @security-checker-agent in chat to analyze your code.',
        'Learn More',
        'Audit Workspace'
    ).then((selection: string | undefined) => {
        if (selection === 'Learn More') {
            vscode.env.openExternal(vscode.Uri.parse('https://owasp.org/Top10/'));
        } else if (selection === 'Audit Workspace') {
            vscode.commands.executeCommand('security-checker-agent.auditWorkspace');
        }
    });
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
    vscode.window.showInformationMessage('Security diagnostics cleared.');
}

export function deactivate() {
    if (reportWebviewPanel) {
        reportWebviewPanel.dispose();
    }
}
