export interface SecurityRule {
    id: string;
    name: string;
    description: string;
    owaspCategory: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    patterns: RegExp[];
    astPatterns?: string[];
    languages: string[];
    mitigation: string;
}

export interface SecurityVulnerability {
    rule: SecurityRule;
    line: number;
    column: number;
    text: string;
    filePath: string;
    suggestion: string;
}

export const OWASP_TOP_10_RULES: SecurityRule[] = [
    // A01:2021 - Broken Access Control
    {
        id: 'broken-access-control-1',
        name: 'Hardcoded Authorization',
        description: 'Hardcoded user roles or permissions found',
        owaspCategory: 'A01:2021 - Broken Access Control',
        severity: 'high',
        patterns: [
            /role\s*=\s*["']admin["']/gi,
            /isAdmin\s*=\s*true/gi,
            /permissions\s*=\s*\[.*["']admin["'].*\]/gi,
            /user\.role\s*===\s*["']admin["']/gi
        ],
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp'],
        mitigation: 'Use dynamic role-based access control (RBAC) instead of hardcoded values'
    },
    {
        id: 'broken-access-control-2',
        name: 'Missing Authorization Check',
        description: 'API endpoint without proper authorization checks',
        owaspCategory: 'A01:2021 - Broken Access Control',
        severity: 'critical',
        patterns: [
            /app\.(get|post|put|delete)\([^)]*\)\s*{[^}]*}/gi,
            /router\.(get|post|put|delete)\([^)]*\)\s*{[^}]*}/gi
        ],
        languages: ['javascript', 'typescript'],
        mitigation: 'Add authentication and authorization middleware to all sensitive endpoints'
    },

    // A02:2021 - Cryptographic Failures
    {
        id: 'crypto-failures-1',
        name: 'Weak Hash Algorithm',
        description: 'Use of weak or deprecated hash algorithms',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
        severity: 'high',
        patterns: [
            /md5\s*\(/gi,
            /sha1\s*\(/gi,
            /\.digest\(\s*["']md5["']\s*\)/gi,
            /hashlib\.md5\s*\(/gi,
            /hashlib\.sha1\s*\(/gi
        ],
        languages: ['javascript', 'typescript', 'python', 'java'],
        mitigation: 'Use SHA-256 or higher, or bcrypt for password hashing'
    },
    {
        id: 'crypto-failures-2',
        name: 'Hardcoded Secrets',
        description: 'Hardcoded passwords, API keys, or secrets found',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
        severity: 'critical',
        patterns: [
            /password\s*=\s*["'][^"'\s]{8,}["']/gi,
            /api[_-]?key\s*=\s*["'][^"'\s]{10,}["']/gi,
            /secret\s*=\s*["'][^"'\s]{8,}["']/gi,
            /token\s*=\s*["'][^"'\s]{20,}["']/gi,
            /access[_-]?key\s*=\s*["'][^"'\s]{10,}["']/gi
        ],
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp', 'php'],
        mitigation: 'Use environment variables or secure key management systems'
    },

    // A03:2021 - Injection
    {
        id: 'injection-sql-1',
        name: 'SQL Injection Risk',
        description: 'Potential SQL injection vulnerability detected',
        owaspCategory: 'A03:2021 - Injection',
        severity: 'critical',
        patterns: [
            /query\s*\(\s*["'`][^"'`]*\$\{.*\}[^"'`]*["'`]\s*\)/gi,
            /execute\s*\(\s*["'`][^"'`]*\+[^"'`]*["'`]\s*\)/gi,
            /SELECT\s+.*\s+FROM\s+.*WHERE\s+.*\+/gi,
            /INSERT\s+INTO\s+.*VALUES\s*\([^)]*\+[^)]*\)/gi
        ],
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp', 'php'],
        mitigation: 'Use parameterized queries or prepared statements'
    },
    {
        id: 'injection-cmd-1',
        name: 'Command Injection Risk',
        description: 'Potential command injection vulnerability detected',
        owaspCategory: 'A03:2021 - Injection',
        severity: 'critical',
        patterns: [
            /exec\s*\(\s*[^)]*\+[^)]*\)/gi,
            /system\s*\(\s*[^)]*\+[^)]*\)/gi,
            /shell_exec\s*\(\s*[^)]*\+[^)]*\)/gi,
            /Runtime\.getRuntime\(\)\.exec\s*\(\s*[^)]*\+[^)]*\)/gi
        ],
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp', 'php'],
        mitigation: 'Use parameterized commands and input validation'
    },

    // A04:2021 - Insecure Design
    {
        id: 'insecure-design-1',
        name: 'Missing Input Validation',
        description: 'User input processed without validation',
        owaspCategory: 'A04:2021 - Insecure Design',
        severity: 'medium',
        patterns: [
            /req\.body\.[a-zA-Z_][a-zA-Z0-9_]*(?!\s*\.\s*(trim|toLowerCase|toUpperCase)\s*\(\))/gi,
            /request\.form\[['""][^'""]+['""]]/gi,
            /input\(\)/gi
        ],
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp', 'php'],
        mitigation: 'Implement proper input validation and sanitization'
    },

    // A05:2021 - Security Misconfiguration
    {
        id: 'security-config-1',
        name: 'Debug Mode Enabled',
        description: 'Debug mode or development settings in production code',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        severity: 'medium',
        patterns: [
            /debug\s*=\s*true/gi,
            /DEBUG\s*=\s*True/gi,
            /app\.set\s*\(\s*["']env["']\s*,\s*["']development["']\s*\)/gi,
            /process\.env\.NODE_ENV\s*=\s*["']development["']/gi
        ],
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp'],
        mitigation: 'Disable debug mode and use environment-specific configurations'
    },

    // A06:2021 - Vulnerable and Outdated Components
    {
        id: 'vulnerable-components-1',
        name: 'Potentially Vulnerable Import',
        description: 'Import of potentially vulnerable or deprecated packages',
        owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
        severity: 'medium',
        patterns: [
            /import.*['"]lodash['"]/gi,
            /import.*['"]moment['"]/gi,
            /require\s*\(\s*['"]request['"]/gi,
            /from\s+['"]xml2js['"]/gi
        ],
        languages: ['javascript', 'typescript'],
        mitigation: 'Update to secure versions or use modern alternatives'
    },

    // A07:2021 - Identification and Authentication Failures
    {
        id: 'auth-failures-1',
        name: 'Weak Password Policy',
        description: 'Weak password validation or storage',
        owaspCategory: 'A07:2021 - Identification and Authentication Failures',
        severity: 'high',
        patterns: [
            /password\.length\s*<\s*[1-7]/gi,
            /len\(password\)\s*<\s*[1-7]/gi,
            /password\s*==\s*['""][^'""]{1,7}['""]*/gi
        ],
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp'],
        mitigation: 'Implement strong password policies and secure storage'
    },

    // A08:2021 - Software and Data Integrity Failures
    {
        id: 'integrity-failures-1',
        name: 'Unsafe Deserialization',
        description: 'Unsafe deserialization of untrusted data',
        owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
        severity: 'high',
        patterns: [
            /pickle\.loads\s*\(/gi,
            /JSON\.parse\s*\(\s*[^)]*req\./gi,
            /unserialize\s*\(/gi,
            /yaml\.load\s*\(\s*[^)]*\)/gi
        ],
        languages: ['javascript', 'typescript', 'python', 'php'],
        mitigation: 'Validate and sanitize data before deserialization'
    },

    // A09:2021 - Security Logging and Monitoring Failures
    {
        id: 'logging-monitoring-1',
        name: 'Missing Security Logging',
        description: 'Authentication or authorization operations without logging',
        owaspCategory: 'A09:2021 - Security Logging and Monitoring Failures',
        severity: 'low',
        patterns: [
            /login\s*\([^)]*\)\s*{[^}]*}(?!.*log)/gi,
            /authenticate\s*\([^)]*\)\s*{[^}]*}(?!.*log)/gi,
            /authorize\s*\([^)]*\)\s*{[^}]*}(?!.*log)/gi
        ],
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp'],
        mitigation: 'Add comprehensive security event logging'
    },

    // A10:2021 - Server-Side Request Forgery (SSRF)
    {
        id: 'ssrf-1',
        name: 'Server-Side Request Forgery Risk',
        description: 'Potential SSRF vulnerability with user-controlled URLs',
        owaspCategory: 'A10:2021 - Server-Side Request Forgery (SSRF)',
        severity: 'high',
        patterns: [
            /fetch\s*\(\s*req\.[a-zA-Z_][a-zA-Z0-9_]*/gi,
            /axios\.(get|post)\s*\(\s*req\.[a-zA-Z_][a-zA-Z0-9_]*/gi,
            /http\.(get|request)\s*\(\s*req\.[a-zA-Z_][a-zA-Z0-9_]*/gi,
            /urllib\.request\s*\(\s*[^)]*input/gi
        ],
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp'],
        mitigation: 'Validate and whitelist allowed URLs and domains'
    }
];

export class OwaspSecurityAnalyzer {
    private rules: SecurityRule[] = OWASP_TOP_10_RULES;

    constructor(enabledRules?: string[]) {
        if (enabledRules) {
            this.rules = OWASP_TOP_10_RULES.filter(rule => 
                enabledRules.some(enabled => rule.owaspCategory.toLowerCase().includes(enabled.toLowerCase()))
            );
        }
    }

    analyzeCode(code: string, filePath: string, language: string): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];
        const lines = code.split('\n');

        const applicableRules = this.rules.filter(rule => 
            rule.languages.includes(language.toLowerCase())
        );

        for (const rule of applicableRules) {
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                
                for (const pattern of rule.patterns) {
                    const matches = line.match(pattern);
                    if (matches) {
                        vulnerabilities.push({
                            rule,
                            line: i + 1,
                            column: line.indexOf(matches[0]) + 1,
                            text: matches[0],
                            filePath,
                            suggestion: this.generateSuggestion(rule, matches[0])
                        });
                    }
                }
            }
        }

        return vulnerabilities;
    }

    private generateSuggestion(rule: SecurityRule, matchedText: string): string {
        const suggestions: Record<string, string> = {
            'broken-access-control-1': `Replace hardcoded role with dynamic RBAC: const userRole = await getUserRole(userId);`,
            'crypto-failures-1': `Use bcrypt for passwords: const hash = await bcrypt.hash(password, 10);`,
            'crypto-failures-2': `Use environment variables: const apiKey = process.env.API_KEY;`,
            'injection-sql-1': `Use parameterized queries: db.query('SELECT * FROM users WHERE id = ?', [userId]);`,
            'injection-cmd-1': `Use child_process.execFile() with array arguments instead of string concatenation`,
            'insecure-design-1': `Add input validation: const sanitizedInput = validator.escape(req.body.input);`,
            'security-config-1': `Use NODE_ENV environment variable: if (process.env.NODE_ENV !== 'production')`,
            'auth-failures-1': `Implement strong password policy: minimum 8 characters, mixed case, numbers, symbols`,
            'integrity-failures-1': `Validate data before parsing: if (isValidJSON(data)) JSON.parse(data);`,
            'logging-monitoring-1': `Add security logging: logger.info('Authentication attempt', { userId, timestamp });`,
            'ssrf-1': `Validate URLs against whitelist: if (allowedDomains.includes(domain)) fetch(url);`
        };

        return suggestions[rule.id] || rule.mitigation;
    }

    calculateSecurityScore(vulnerabilities: SecurityVulnerability[]): { score: number; level: string } {
        let totalScore = 100;
        const severityWeights = { low: 2, medium: 5, high: 10, critical: 20 };

        for (const vuln of vulnerabilities) {
            totalScore -= severityWeights[vuln.rule.severity];
        }

        totalScore = Math.max(0, totalScore);

        let level = 'excellent';
        if (totalScore < 30) {level = 'critical';}
        else if (totalScore < 50) {level = 'poor';}
        else if (totalScore < 70) {level = 'fair';}
        else if (totalScore < 85) {level = 'good';}

        return { score: totalScore, level };
    }
}
