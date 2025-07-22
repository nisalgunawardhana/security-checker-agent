import * as vscode from 'vscode';
import { SecurityVulnerability } from '../security/owaspRules';

export class SecurityDiagnosticsProvider {
    private diagnosticCollection: vscode.DiagnosticCollection;

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('security-checker');
    }

    updateDiagnostics(vulnerabilities: SecurityVulnerability[]): void {
        this.diagnosticCollection.clear();

        // Group vulnerabilities by file
        const fileVulnerabilities = new Map<string, SecurityVulnerability[]>();
        for (const vuln of vulnerabilities) {
            const existing = fileVulnerabilities.get(vuln.filePath) || [];
            existing.push(vuln);
            fileVulnerabilities.set(vuln.filePath, existing);
        }

        // Create diagnostics for each file
        for (const [filePath, vulns] of fileVulnerabilities) {
            const diagnostics: vscode.Diagnostic[] = vulns.map(vuln => {
                const range = new vscode.Range(
                    new vscode.Position(Math.max(0, vuln.line - 1), Math.max(0, vuln.column - 1)),
                    new vscode.Position(Math.max(0, vuln.line - 1), Math.max(0, vuln.column - 1 + vuln.text.length))
                );

                const diagnostic = new vscode.Diagnostic(
                    range,
                    `${vuln.rule.name}: ${vuln.rule.description}`,
                    this.getSeverityLevel(vuln.rule.severity)
                );

                diagnostic.source = 'Security Checker';
                diagnostic.code = {
                    value: vuln.rule.id,
                    target: vscode.Uri.parse(`https://owasp.org/Top10/`)
                };

                // Add related information with the suggestion
                diagnostic.relatedInformation = [
                    new vscode.DiagnosticRelatedInformation(
                        new vscode.Location(vscode.Uri.file(filePath), range),
                        `💡 Suggestion: ${vuln.suggestion}`
                    )
                ];

                return diagnostic;
            });

            this.diagnosticCollection.set(vscode.Uri.file(filePath), diagnostics);
        }
    }

    private getSeverityLevel(severity: string): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'critical':
                return vscode.DiagnosticSeverity.Error;
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Information;
        }
    }

    clearDiagnostics(): void {
        this.diagnosticCollection.clear();
    }

    dispose(): void {
        this.diagnosticCollection.dispose();
    }
}

export interface SecurityTreeItem {
    label: string;
    severity: string;
    category: string;
    count: number;
    vulnerabilities: SecurityVulnerability[];
}

export class SecurityTreeDataProvider implements vscode.TreeDataProvider<SecurityTreeItem | SecurityVulnerability> {
    private _onDidChangeTreeData: vscode.EventEmitter<SecurityTreeItem | SecurityVulnerability | undefined | null | void> = new vscode.EventEmitter<SecurityTreeItem | SecurityVulnerability | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<SecurityTreeItem | SecurityVulnerability | undefined | null | void> = this._onDidChangeTreeData.event;

    private vulnerabilities: SecurityVulnerability[] = [];

    updateVulnerabilities(vulnerabilities: SecurityVulnerability[]): void {
        this.vulnerabilities = vulnerabilities;
        this._onDidChangeTreeData.fire();
    }

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: SecurityTreeItem | SecurityVulnerability): vscode.TreeItem {
        if ('rule' in element) {
            // This is a SecurityVulnerability
            const vuln = element as SecurityVulnerability;
            const item = new vscode.TreeItem(
                `${vuln.rule.name} (${vuln.filePath.split('/').pop()}:${vuln.line})`,
                vscode.TreeItemCollapsibleState.None
            );
            
            item.description = vuln.rule.severity;
            item.tooltip = `${vuln.rule.description}\\n\\n💡 ${vuln.suggestion}`;
            item.contextValue = 'vulnerability';
            
            // Set icon based on severity
            item.iconPath = this.getIconForSeverity(vuln.rule.severity);
            
            // Command to navigate to the vulnerability
            item.command = {
                command: 'vscode.open',
                title: 'Open',
                arguments: [
                    vscode.Uri.file(vuln.filePath),
                    {
                        selection: new vscode.Range(
                            new vscode.Position(vuln.line - 1, vuln.column - 1),
                            new vscode.Position(vuln.line - 1, vuln.column - 1 + vuln.text.length)
                        )
                    }
                ]
            };

            return item;
        } else {
            // This is a SecurityTreeItem (category)
            const treeItem = element as SecurityTreeItem;
            const item = new vscode.TreeItem(
                `${treeItem.label} (${treeItem.count})`,
                treeItem.vulnerabilities.length > 0 ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.None
            );
            
            item.description = treeItem.severity;
            item.contextValue = 'category';
            item.iconPath = new vscode.ThemeIcon('folder');
            
            return item;
        }
    }

    getChildren(element?: SecurityTreeItem | SecurityVulnerability): Promise<(SecurityTreeItem | SecurityVulnerability)[]> {
        if (!element) {
            // Return root level items (categories)
            return Promise.resolve(this.getCategories());
        } else if ('vulnerabilities' in element) {
            // Return vulnerabilities for this category
            const treeItem = element as SecurityTreeItem;
            return Promise.resolve(treeItem.vulnerabilities);
        }
        
        return Promise.resolve([]);
    }

    private getCategories(): SecurityTreeItem[] {
        const categoryMap = new Map<string, SecurityVulnerability[]>();
        
        for (const vuln of this.vulnerabilities) {
            const category = vuln.rule.owaspCategory;
            const existing = categoryMap.get(category) || [];
            existing.push(vuln);
            categoryMap.set(category, existing);
        }

        return Array.from(categoryMap.entries()).map(([category, vulns]) => ({
            label: category,
            severity: this.getHighestSeverity(vulns),
            category,
            count: vulns.length,
            vulnerabilities: vulns
        }));
    }

    private getHighestSeverity(vulnerabilities: SecurityVulnerability[]): string {
        const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        let highest = 'low';
        let highestValue = 1;

        for (const vuln of vulnerabilities) {
            const value = severityOrder[vuln.rule.severity as keyof typeof severityOrder] || 1;
            if (value > highestValue) {
                highest = vuln.rule.severity;
                highestValue = value;
            }
        }

        return highest;
    }

    private getIconForSeverity(severity: string): vscode.ThemeIcon {
        switch (severity) {
            case 'critical':
                return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
            case 'high':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('problemsWarningIcon.foreground'));
            case 'medium':
                return new vscode.ThemeIcon('info', new vscode.ThemeColor('problemsInfoIcon.foreground'));
            case 'low':
                return new vscode.ThemeIcon('lightbulb');
            default:
                return new vscode.ThemeIcon('question');
        }
    }
}
