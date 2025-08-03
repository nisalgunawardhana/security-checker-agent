import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export interface MCPServerInfo {
    name: string;
    path: string;
    type: 'python' | 'javascript' | 'typescript' | 'unknown';
    version?: string;
    tools?: string[];
    hasConfigFile: boolean;
    configFiles: string[];
    dependencies: string[];
    ports?: number[];
}

export class MCPServerDetector {
    private workspacePath: string;

    constructor(workspacePath: string) {
        this.workspacePath = workspacePath;
    }

    public async detectMCPServers(): Promise<MCPServerInfo[]> {
        const servers: MCPServerInfo[] = [];

        try {
            // Check for common MCP server patterns
            await this.scanForPythonMCPServers(servers);
            await this.scanForJavaScriptMCPServers(servers);
            await this.scanForConfigFiles(servers);
            await this.scanForContainerizedMCP(servers);
            
        } catch (error) {
            console.error('Error detecting MCP servers:', error);
        }

        return servers;
    }

    private async scanForPythonMCPServers(servers: MCPServerInfo[]): Promise<void> {
        const pythonFiles = await this.findFiles('**/*.py');
        
        for (const file of pythonFiles) {
            try {
                const content = await fs.promises.readFile(file, 'utf-8');
                
                // Check for MCP server indicators
                if (this.isPythonMCPServer(content)) {
                    const serverInfo = await this.analyzePythonMCPServer(file, content);
                    servers.push(serverInfo);
                }
            } catch (error) {
                console.warn(`Failed to read file ${file}:`, error);
            }
        }
    }

    private async scanForJavaScriptMCPServers(servers: MCPServerInfo[]): Promise<void> {
        const jsFiles = await this.findFiles('**/*.{js,ts}');
        
        for (const file of jsFiles) {
            try {
                const content = await fs.promises.readFile(file, 'utf-8');
                
                if (this.isJavaScriptMCPServer(content)) {
                    const serverInfo = await this.analyzeJavaScriptMCPServer(file, content);
                    servers.push(serverInfo);
                }
            } catch (error) {
                console.warn(`Failed to read file ${file}:`, error);
            }
        }
    }

    private async scanForConfigFiles(servers: MCPServerInfo[]): Promise<void> {
        const configPatterns = [
            '**/mcp.json',
            '**/mcp.yaml',
            '**/mcp.yml',
            '**/mcp-server.json',
            '**/mcp_config.json',
            '**/.mcp/**',
            '**/anthropic_mcp.json'
        ];

        for (const pattern of configPatterns) {
            const files = await this.findFiles(pattern);
            for (const file of files) {
                try {
                    const content = await fs.promises.readFile(file, 'utf-8');
                    const configInfo = this.parseConfigFile(file, content);
                    if (configInfo) {
                        servers.push(configInfo);
                    }
                } catch (error) {
                    console.warn(`Failed to read config file ${file}:`, error);
                }
            }
        }
    }

    private async scanForContainerizedMCP(servers: MCPServerInfo[]): Promise<void> {
        const dockerFiles = await this.findFiles('**/Dockerfile*');
        const composeFiles = await this.findFiles('**/docker-compose*.{yml,yaml}');
        
        const containerFiles = [...dockerFiles, ...composeFiles];
        
        for (const file of containerFiles) {
            try {
                const content = await fs.promises.readFile(file, 'utf-8');
                
                if (this.isContainerizedMCP(content)) {
                    const serverInfo = this.analyzeContainerizedMCP(file, content);
                    if (serverInfo) {
                        servers.push(serverInfo);
                    }
                }
            } catch (error) {
                console.warn(`Failed to read container file ${file}:`, error);
            }
        }
    }

    private isPythonMCPServer(content: string): boolean {
        const mcpPatterns = [
            /import\s+mcp/gi,
            /from\s+mcp\s+import/gi,
            /MCPServer/gi,
            /mcp\.server/gi,
            /@mcp\.tool/gi,
            /anthropic.*mcp/gi,
            /model.*context.*protocol/gi,
            /class.*Server.*MCP/gi
        ];

        return mcpPatterns.some(pattern => pattern.test(content));
    }

    private isJavaScriptMCPServer(content: string): boolean {
        const mcpPatterns = [
            /require\(['"`]@modelcontextprotocol/gi,
            /import.*from.*['"`]@modelcontextprotocol/gi,
            /import.*mcp/gi,
            /MCPServer/gi,
            /ModelContextProtocol/gi,
            /anthropic.*mcp/gi,
            /new.*Server.*MCP/gi,
            /mcp\.createServer/gi
        ];

        return mcpPatterns.some(pattern => pattern.test(content));
    }

    private isContainerizedMCP(content: string): boolean {
        const containerMCPPatterns = [
            /FROM.*mcp/gi,
            /pip install.*mcp/gi,
            /npm install.*mcp/gi,
            /EXPOSE.*8000/gi, // Common MCP port
            /CMD.*mcp/gi,
            /anthropic.*mcp/gi
        ];

        return containerMCPPatterns.some(pattern => pattern.test(content));
    }

    private async analyzePythonMCPServer(filePath: string, content: string): Promise<MCPServerInfo> {
        const tools = this.extractPythonTools(content);
        const dependencies = await this.getPythonDependencies();
        const ports = this.extractPorts(content);
        
        return {
            name: path.basename(filePath, '.py'),
            path: filePath,
            type: 'python',
            tools,
            hasConfigFile: false,
            configFiles: [],
            dependencies,
            ports
        };
    }

    private async analyzeJavaScriptMCPServer(filePath: string, content: string): Promise<MCPServerInfo> {
        const tools = this.extractJavaScriptTools(content);
        const dependencies = await this.getJavaScriptDependencies();
        const ports = this.extractPorts(content);
        
        return {
            name: path.basename(filePath).replace(/\.(js|ts)$/, ''),
            path: filePath,
            type: filePath.endsWith('.ts') ? 'typescript' : 'javascript',
            tools,
            hasConfigFile: false,
            configFiles: [],
            dependencies,
            ports
        };
    }

    private parseConfigFile(filePath: string, content: string): MCPServerInfo | null {
        try {
            let config: any;
            
            if (filePath.endsWith('.json')) {
                config = JSON.parse(content);
            } else if (filePath.endsWith('.yml') || filePath.endsWith('.yaml')) {
                // Simple YAML parsing for basic structures
                config = this.parseSimpleYAML(content);
            }

            if (config && (config.mcp || config.server || config.tools)) {
                return {
                    name: config.name || path.basename(filePath),
                    path: filePath,
                    type: 'unknown',
                    tools: config.tools || [],
                    hasConfigFile: true,
                    configFiles: [filePath],
                    dependencies: config.dependencies || [],
                    ports: config.ports || []
                };
            }
        } catch (error) {
            console.warn(`Failed to parse config file ${filePath}:`, error);
        }
        
        return null;
    }

    private analyzeContainerizedMCP(filePath: string, content: string): MCPServerInfo | null {
        const name = path.basename(path.dirname(filePath));
        const ports = this.extractPorts(content);
        
        return {
            name: `${name} (containerized)`,
            path: filePath,
            type: 'unknown',
            tools: [],
            hasConfigFile: false,
            configFiles: [],
            dependencies: [],
            ports
        };
    }

    private extractPythonTools(content: string): string[] {
        const tools: string[] = [];
        const toolPatterns = [
            /@mcp\.tool\s*\n\s*def\s+(\w+)/gi,
            /def\s+(\w+_tool)\s*\(/gi,
            /register_tool\(['"`](\w+)['"`]/gi,
            /tools\s*=\s*\[([^\]]*)\]/gi
        ];

        for (const pattern of toolPatterns) {
            let match;
            while ((match = pattern.exec(content)) !== null) {
                if (match[1]) {
                    tools.push(match[1]);
                }
            }
        }

        return [...new Set(tools)]; // Remove duplicates
    }

    private extractJavaScriptTools(content: string): string[] {
        const tools: string[] = [];
        const toolPatterns = [
            /registerTool\(['"`](\w+)['"`]/gi,
            /addTool\(['"`](\w+)['"`]/gi,
            /tools:\s*\[([^\]]*)\]/gi,
            /function\s+(\w+Tool)\s*\(/gi
        ];

        for (const pattern of toolPatterns) {
            let match;
            while ((match = pattern.exec(content)) !== null) {
                if (match[1]) {
                    tools.push(match[1]);
                }
            }
        }

        return [...new Set(tools)];
    }

    private extractPorts(content: string): number[] {
        const ports: number[] = [];
        const portPatterns = [
            /port\s*=\s*(\d+)/gi,
            /listen\s*\(\s*(\d+)/gi,
            /EXPOSE\s+(\d+)/gi,
            /:(\d+)/gi
        ];

        for (const pattern of portPatterns) {
            let match;
            while ((match = pattern.exec(content)) !== null) {
                const port = parseInt(match[1]);
                if (port > 1000 && port < 65536) {
                    ports.push(port);
                }
            }
        }

        return [...new Set(ports)];
    }

    private async getPythonDependencies(): Promise<string[]> {
        const dependencies: string[] = [];
        
        try {
            const requirementsPath = path.join(this.workspacePath, 'requirements.txt');
            if (fs.existsSync(requirementsPath)) {
                const content = await fs.promises.readFile(requirementsPath, 'utf-8');
                const lines = content.split('\n');
                for (const line of lines) {
                    const dep = line.trim().split(/[>=<]/)[0];
                    if (dep && !dep.startsWith('#')) {
                        dependencies.push(dep);
                    }
                }
            }
        } catch (error) {
            console.warn('Failed to read requirements.txt:', error);
        }

        return dependencies;
    }

    private async getJavaScriptDependencies(): Promise<string[]> {
        const dependencies: string[] = [];
        
        try {
            const packagePath = path.join(this.workspacePath, 'package.json');
            if (fs.existsSync(packagePath)) {
                const content = await fs.promises.readFile(packagePath, 'utf-8');
                const packageJson = JSON.parse(content);
                
                const deps = {
                    ...packageJson.dependencies,
                    ...packageJson.devDependencies
                };
                
                dependencies.push(...Object.keys(deps));
            }
        } catch (error) {
            console.warn('Failed to read package.json:', error);
        }

        return dependencies;
    }

    private async findFiles(pattern: string): Promise<string[]> {
        try {
            const files = await vscode.workspace.findFiles(pattern, '**/node_modules/**');
            return files.map(file => file.fsPath);
        } catch (error) {
            console.warn(`Failed to find files with pattern ${pattern}:`, error);
            return [];
        }
    }

    private parseSimpleYAML(content: string): any {
        // Very basic YAML parsing - for complex YAML, we'd need a proper parser
        const lines = content.split('\n');
        const result: any = {};
        
        for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed && !trimmed.startsWith('#')) {
                const colonIndex = trimmed.indexOf(':');
                if (colonIndex !== -1) {
                    const key = trimmed.substring(0, colonIndex).trim();
                    const value = trimmed.substring(colonIndex + 1).trim();
                    result[key] = value.replace(/['"]/g, '');
                }
            }
        }
        
        return result;
    }

    public async isMCPWorkspace(): Promise<boolean> {
        const servers = await this.detectMCPServers();
        return servers.length > 0;
    }
}
