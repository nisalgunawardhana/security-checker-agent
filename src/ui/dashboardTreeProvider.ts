import * as vscode from 'vscode';

export interface DashboardItem {
    label: string;
    description?: string;
    command?: string;
    icon?: vscode.ThemeIcon;
}

export class DashboardTreeDataProvider implements vscode.TreeDataProvider<DashboardItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<DashboardItem | undefined | null | void> = new vscode.EventEmitter<DashboardItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<DashboardItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private dashboardItems: DashboardItem[] = [
        {
            label: "Open Security Dashboard",
            description: "Launch interactive dashboard",
            command: "security-checker-agent.openDashboard",
            icon: new vscode.ThemeIcon('dashboard')
        },
        {
            label: "Audit Workspace",
            description: "Scan all files for security issues",
            command: "security-checker-agent.auditWorkspace",
            icon: new vscode.ThemeIcon('search')
        },
        {
            label: "View Security Report",
            description: "Show detailed security analysis",
            command: "security-checker-agent.showSecurityReport",
            icon: new vscode.ThemeIcon('graph')
        },
        {
            label: "Export to PDF",
            description: "Generate PDF report",
            command: "security-checker-agent.exportToPdf",
            icon: new vscode.ThemeIcon('export')
        }
    ];

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: DashboardItem): vscode.TreeItem {
        const item = new vscode.TreeItem(element.label, vscode.TreeItemCollapsibleState.None);
        item.description = element.description;
        item.iconPath = element.icon;
        item.tooltip = element.description;
        
        if (element.command) {
            item.command = {
                command: element.command,
                title: element.label
            };
        }

        return item;
    }

    getChildren(element?: DashboardItem): Thenable<DashboardItem[]> {
        if (!element) {
            return Promise.resolve(this.dashboardItems);
        }
        return Promise.resolve([]);
    }
}
