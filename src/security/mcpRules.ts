export interface MCPSecurityRule {
    id: string;
    name: string;
    description: string;
    category: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    patterns: RegExp[];
    filePatterns?: string[];
    languages: string[];
    mitigation: string;
    owaspLLMCategory?: string;
}

export interface MCPVulnerability {
    rule: MCPSecurityRule;
    line: number;
    column: number;
    text: string;
    filePath: string;
    suggestion: string;
    context?: string;
}

export const MCP_SECURITY_RULES: MCPSecurityRule[] = [
    // 1. Prompt Injection
    {
        id: 'mcp-prompt-injection-1',
        name: 'Direct Prompt Injection',
        description: 'Potential direct prompt injection vulnerability in MCP server',
        category: 'Prompt Injection',
        severity: 'critical',
        patterns: [
            /prompt\s*\+=?\s*user_input/gi,
            /system_prompt\s*\+=?\s*.*input/gi,
            /prompt\.format\([^)]*user[^)]*\)/gi,
            /f["'`][^"'`]*\{.*user.*\}[^"'`]*["'`]/gi,
            /template\s*\.\s*render\([^)]*user[^)]*\)/gi
        ],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Sanitize and validate user inputs before incorporating into prompts. Use parameterized prompt templates.',
        owaspLLMCategory: 'LLM01: Prompt Injection'
    },
    {
        id: 'mcp-prompt-injection-2',
        name: 'Unsafe Prompt Concatenation',
        description: 'Direct string concatenation in prompt construction',
        category: 'Prompt Injection',
        severity: 'high',
        patterns: [
            /prompt\s*\+\s*user/gi,
            /system_message\s*\+\s*.*input/gi,
            /["'`][^"'`]*["'`]\s*\+\s*user/gi,
            /concat\([^)]*user[^)]*prompt[^)]*\)/gi
        ],
        languages: ['python', 'javascript', 'typescript', 'java'],
        mitigation: 'Use structured prompt templates with proper input validation and sanitization'
    },

    // 2. Tool Poisoning
    {
        id: 'mcp-tool-poisoning-1',
        name: 'Dynamic Tool Loading',
        description: 'Dynamic tool loading without proper validation',
        category: 'Tool Poisoning',
        severity: 'critical',
        patterns: [
            /import\s+.*\s+from\s+user_input/gi,
            /require\([^)]*user[^)]*\)/gi,
            /exec\([^)]*tool[^)]*\)/gi,
            /eval\([^)]*tool[^)]*\)/gi,
            /importlib\.import_module\([^)]*user[^)]*\)/gi
        ],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Use a whitelist of approved tools and validate tool signatures before loading',
        owaspLLMCategory: 'LLM05: Supply Chain Vulnerabilities'
    },
    {
        id: 'mcp-tool-poisoning-2',
        name: 'Untrusted Tool Execution',
        description: 'Execution of tools from untrusted sources',
        category: 'Tool Poisoning',
        severity: 'high',
        patterns: [
            /subprocess\.call\([^)]*user[^)]*\)/gi,
            /os\.system\([^)]*tool[^)]*\)/gi,
            /child_process\.exec\([^)]*user[^)]*\)/gi,
            /shell_execute\([^)]*tool[^)]*\)/gi
        ],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Implement tool sandboxing and restrict execution permissions'
    },

    // 3. Dynamic Tool Changes
    {
        id: 'mcp-dynamic-tools-1',
        name: 'Runtime Tool Modification',
        description: 'Tools are modified at runtime without proper validation',
        category: 'Dynamic Tool Changes',
        severity: 'high',
        patterns: [
            /tools\[.*\]\s*=\s*.*user/gi,
            /setattr\(tool,.*user.*\)/gi,
            /tool\.__dict__\[.*\]\s*=/gi,
            /Object\.defineProperty\(tool,.*user.*\)/gi
        ],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Implement immutable tool definitions and validate any tool modifications'
    },
    {
        id: 'mcp-dynamic-tools-2',
        name: 'Hot Tool Swapping',
        description: 'Tools are replaced at runtime without security checks',
        category: 'Dynamic Tool Changes',
        severity: 'medium',
        patterns: [
            /reload_tool\([^)]*\)/gi,
            /hot_swap\([^)]*\)/gi,
            /replace_tool\([^)]*user[^)]*\)/gi,
            /tool_registry\.update\([^)]*\)/gi
        ],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Implement proper authentication and authorization for tool updates'
    },

    // 4. Misconfigured Authentication & Authorization
    {
        id: 'mcp-auth-1',
        name: 'Missing Authentication',
        description: 'MCP server endpoints without authentication',
        category: 'Authentication & Authorization',
        severity: 'critical',
        patterns: [
            /@app\.route\([^)]*\)\s*\n\s*def\s+\w+\([^)]*\):/gi,
            /app\.(get|post|put|delete)\([^)]*\)\s*=>\s*{/gi,
            /server\.register\([^)]*\)\s*{/gi,
            /mcp_server\.add_tool\([^)]*\)/gi
        ],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Implement proper authentication middleware for all MCP endpoints',
        owaspLLMCategory: 'LLM02: Insecure Output Handling'
    },
    {
        id: 'mcp-auth-2',
        name: 'Weak Token Validation',
        description: 'Weak or missing token validation in MCP server',
        category: 'Authentication & Authorization',
        severity: 'high',
        patterns: [
            /token\s*==\s*["'][^"']*["']/gi,
            /auth_token\s*in\s*request/gi,
            /if\s+token:/gi,
            /decode\([^)]*verify=False[^)]*\)/gi
        ],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Use strong JWT validation with proper signature verification'
    },

    // 5. Excessive Permissions
    {
        id: 'mcp-permissions-1',
        name: 'Overprivileged Tool Access',
        description: 'Tools granted excessive system permissions',
        category: 'Excessive Permissions',
        severity: 'high',
        patterns: [
            /os\.chmod\([^)]*0o777[^)]*\)/gi,
            /subprocess\.call\([^)]*shell=True[^)]*\)/gi,
            /exec\([^)]*sudo[^)]*\)/gi,
            /permissions\s*=\s*["'].*\*.*["']/gi
        ],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Apply principle of least privilege and use specific permission models',
        owaspLLMCategory: 'LLM06: Excessive Agency'
    },
    {
        id: 'mcp-permissions-2',
        name: 'Unrestricted File Access',
        description: 'Tools with unrestricted file system access',
        category: 'Excessive Permissions',
        severity: 'medium',
        patterns: [
            /open\([^)]*["']\.\./gi,
            /file_path\s*=\s*.*user/gi,
            /os\.walk\(["']\/["']\)/gi,
            /glob\.glob\(["']\*["']\)/gi
        ],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Implement file access sandboxing and path validation'
    },

    // 6. Indirect Prompt Injections
    {
        id: 'mcp-indirect-injection-1',
        name: 'External Data Injection',
        description: 'External data sources incorporated into prompts without sanitization',
        category: 'Indirect Prompt Injections',
        severity: 'high',
        patterns: [
            /requests\.get\([^)]*\)\.text/gi,
            /urllib\.request\.[^(]*\([^)]*\)/gi,
            /fetch\([^)]*\)\.then\([^)]*text[^)]*\)/gi,
            /file_content\s*=\s*open\([^)]*\)\.read\(\)/gi
        ],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Sanitize and validate all external data before using in prompts',
        owaspLLMCategory: 'LLM03: Training Data Poisoning'
    },
    {
        id: 'mcp-indirect-injection-2',
        name: 'User-Controlled File Processing',
        description: 'Processing user-controlled files without proper validation',
        category: 'Indirect Prompt Injections',
        severity: 'medium',
        patterns: [
            /process_file\([^)]*user[^)]*\)/gi,
            /parse_document\([^)]*input[^)]*\)/gi,
            /read_user_file\([^)]*\)/gi,
            /upload_handler\([^)]*\)/gi
        ],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Implement proper file validation and content sanitization'
    },

    // 7. Session Hijacking
    {
        id: 'mcp-session-1',
        name: 'Insecure Session Management',
        description: 'Insecure session handling in MCP server',
        category: 'Session Hijacking',
        severity: 'high',
        patterns: [
            /session_id\s*=\s*str\(random/gi,
            /session\[["']user["']\]\s*=\s*user_input/gi,
            /cookie\s*=\s*request\.cookies\.get\([^)]*\)/gi,
            /session\.permanent\s*=\s*False/gi
        ],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Use secure session management with proper token rotation and validation'
    },
    {
        id: 'mcp-session-2',
        name: 'Session Token Exposure',
        description: 'Session tokens exposed in logs or responses',
        category: 'Session Hijacking',
        severity: 'medium',
        patterns: [
            /print\([^)]*session[^)]*\)/gi,
            /console\.log\([^)]*token[^)]*\)/gi,
            /logger\.[^(]*\([^)]*session[^)]*\)/gi,
            /response\.json\([^)]*token[^)]*\)/gi
        ],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Avoid logging sensitive session information and sanitize responses'
    },

    // 8. Confused Deputy Problem
    {
        id: 'mcp-deputy-1',
        name: 'Privilege Escalation via Tool Chain',
        description: 'Tool chain allowing privilege escalation',
        category: 'Confused Deputy Problem',
        severity: 'high',
        patterns: [
            /execute_as_admin\([^)]*user[^)]*\)/gi,
            /sudo_execute\([^)]*tool[^)]*\)/gi,
            /elevate_privileges\([^)]*\)/gi,
            /run_with_elevated_access\([^)]*\)/gi
        ],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Implement proper privilege separation and validate tool chain permissions'
    },
    {
        id: 'mcp-deputy-2',
        name: 'Cross-Tool Authority Delegation',
        description: 'Tools delegating authority without proper validation',
        category: 'Confused Deputy Problem',
        severity: 'medium',
        patterns: [
            /delegate_to\([^)]*tool[^)]*\)/gi,
            /proxy_request\([^)]*user[^)]*\)/gi,
            /forward_authority\([^)]*\)/gi,
            /chain_execution\([^)]*\)/gi
        ],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Validate authority delegation and implement proper access controls'
    },

    // 9. Token Passthrough Vulnerabilities
    {
        id: 'mcp-token-passthrough-1',
        name: 'Unvalidated Token Passthrough',
        description: 'Authentication tokens passed through without validation',
        category: 'Token Passthrough Vulnerabilities',
        severity: 'critical',
        patterns: [
            /headers\[["']Authorization["']\]\s*=\s*request\.headers/gi,
            /forward_token\([^)]*\)/gi,
            /proxy_auth\([^)]*user[^)]*\)/gi,
            /passthrough_credentials\([^)]*\)/gi
        ],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Validate and sanitize all authentication tokens before forwarding'
    },
    {
        id: 'mcp-token-passthrough-2',
        name: 'Token Leakage in Logs',
        description: 'Authentication tokens logged or exposed',
        category: 'Token Passthrough Vulnerabilities',
        severity: 'high',
        patterns: [
            /log\([^)]*token[^)]*\)/gi,
            /print\([^)]*bearer[^)]*\)/gi,
            /console\.log\([^)]*authorization[^)]*\)/gi,
            /debug\([^)]*credential[^)]*\)/gi
        ],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Implement proper logging practices and avoid exposing sensitive tokens'
    },

    // 10. Supply Chain Vulnerabilities
    {
        id: 'mcp-supply-chain-1',
        name: 'Untrusted Package Dependencies',
        description: 'Use of packages from untrusted sources',
        category: 'Supply Chain Vulnerabilities',
        severity: 'medium',
        patterns: [
            /pip\s+install\s+[^-][^\s]*\s*$/gi,
            /npm\s+install\s+[^@][^\s]*$/gi,
            /import\s+[a-zA-Z_][a-zA-Z0-9_]*\s*$/gi,
            /require\(["'][^"'@][^"']*["']\)/gi
        ],
        filePatterns: ['requirements.txt', 'package.json', 'pyproject.toml'],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Use package managers with integrity checking and vulnerability scanning',
        owaspLLMCategory: 'LLM05: Supply Chain Vulnerabilities'
    },
    {
        id: 'mcp-supply-chain-2',
        name: 'Outdated Dependencies',
        description: 'Use of outdated packages with known vulnerabilities',
        category: 'Supply Chain Vulnerabilities',
        severity: 'medium',
        patterns: [
            /["'][^"']*["']\s*:\s*["']\^?[0-9]+\.[0-9]+\.[0-9]+["']/gi,
            /==[0-9]+\.[0-9]+\.[0-9]+/gi,
            /~[0-9]+\.[0-9]+\.[0-9]+/gi
        ],
        filePatterns: ['package.json', 'requirements.txt', 'Pipfile'],
        languages: ['python', 'javascript', 'typescript'],
        mitigation: 'Regularly update dependencies and use automated vulnerability scanning'
    }
];

export class MCPSecurityAnalyzer {
    private vulnerabilities: MCPVulnerability[] = [];

    public analyzeCode(content: string, filePath: string, language: string): MCPVulnerability[] {
        this.vulnerabilities = [];
        const lines = content.split('\n');

        // Check each rule against the content
        for (const rule of MCP_SECURITY_RULES) {
            if (rule.languages.includes(language) || rule.languages.includes('*')) {
                this.checkRule(rule, lines, filePath);
            }
        }

        return this.vulnerabilities;
    }

    private checkRule(rule: MCPSecurityRule, lines: string[], filePath: string): void {
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            
            for (const pattern of rule.patterns) {
                const match = pattern.exec(line);
                if (match) {
                    const vulnerability: MCPVulnerability = {
                        rule,
                        line: i + 1,
                        column: match.index || 0,
                        text: match[0],
                        filePath,
                        suggestion: this.generateSuggestion(rule),
                        context: this.getContext(lines, i)
                    };
                    
                    this.vulnerabilities.push(vulnerability);
                }
                
                // Reset regex state for global patterns
                pattern.lastIndex = 0;
            }
        }
    }

    private generateSuggestion(rule: MCPSecurityRule): string {
        const suggestions: { [key: string]: string } = {
            'Prompt Injection': 'Implement input validation and use parameterized prompt templates',
            'Tool Poisoning': 'Use tool whitelisting and signature verification',
            'Dynamic Tool Changes': 'Implement immutable tool definitions',
            'Authentication & Authorization': 'Add proper authentication middleware',
            'Excessive Permissions': 'Apply principle of least privilege',
            'Indirect Prompt Injections': 'Sanitize external data sources',
            'Session Hijacking': 'Use secure session management',
            'Confused Deputy Problem': 'Implement proper privilege separation',
            'Token Passthrough Vulnerabilities': 'Validate tokens before forwarding',
            'Supply Chain Vulnerabilities': 'Use trusted package sources and integrity checking'
        };

        return suggestions[rule.category] || rule.mitigation;
    }

    private getContext(lines: string[], lineIndex: number): string {
        const start = Math.max(0, lineIndex - 2);
        const end = Math.min(lines.length, lineIndex + 3);
        return lines.slice(start, end).join('\n');
    }

    public getVulnerabilityCount(): number {
        return this.vulnerabilities.length;
    }

    public getCriticalVulnerabilities(): MCPVulnerability[] {
        return this.vulnerabilities.filter(v => v.rule.severity === 'critical');
    }

    public getHighVulnerabilities(): MCPVulnerability[] {
        return this.vulnerabilities.filter(v => v.rule.severity === 'high');
    }

    public getVulnerabilitiesByCategory(): { [category: string]: MCPVulnerability[] } {
        const categorized: { [category: string]: MCPVulnerability[] } = {};
        
        for (const vulnerability of this.vulnerabilities) {
            const category = vulnerability.rule.category;
            if (!categorized[category]) {
                categorized[category] = [];
            }
            categorized[category].push(vulnerability);
        }
        
        return categorized;
    }
}
