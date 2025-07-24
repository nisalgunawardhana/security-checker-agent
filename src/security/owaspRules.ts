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
    },

    // Modern Framework Security Rules - React
    {
        id: 'react-xss-1',
        name: 'React dangerouslySetInnerHTML XSS',
        description: 'Use of dangerouslySetInnerHTML with user input can lead to XSS',
        owaspCategory: 'A03:2021 - Injection',
        severity: 'critical',
        patterns: [
            /dangerouslySetInnerHTML\s*=\s*{{\s*__html:\s*[^}]*\+/gi,
            /dangerouslySetInnerHTML\s*=\s*{{\s*__html:\s*[^}]*\$\{/gi,
            /dangerouslySetInnerHTML\s*=\s*{{\s*__html:\s*props\./gi,
            /dangerouslySetInnerHTML\s*=\s*{{\s*__html:\s*state\./gi
        ],
        languages: ['javascript', 'typescript', 'jsx', 'tsx'],
        mitigation: 'Sanitize HTML content using DOMPurify or avoid dangerouslySetInnerHTML'
    },
    {
        id: 'react-xss-2',
        name: 'React href XSS Vulnerability',
        description: 'Dynamic href attributes can lead to javascript: protocol XSS',
        owaspCategory: 'A03:2021 - Injection',
        severity: 'high',
        patterns: [
            /href\s*=\s*{[^}]*\+/gi,
            /href\s*=\s*{[^}]*\$\{/gi,
            /href\s*=\s*{\s*props\./gi,
            /href\s*=\s*{\s*state\./gi
        ],
        languages: ['javascript', 'typescript', 'jsx', 'tsx'],
        mitigation: 'Validate URLs and use URL constructor to prevent javascript: protocol injection'
    },
    {
        id: 'react-state-1',
        name: 'React State Mutation',
        description: 'Direct state mutation detected, can lead to security issues',
        owaspCategory: 'A04:2021 - Insecure Design',
        severity: 'medium',
        patterns: [
            /this\.state\.[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*/gi,
            /state\.[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*/gi
        ],
        languages: ['javascript', 'typescript', 'jsx', 'tsx'],
        mitigation: 'Use setState() or state setters to ensure proper state management'
    },

    // Vue.js Security Rules
    {
        id: 'vue-xss-1',
        name: 'Vue.js v-html XSS Risk',
        description: 'Use of v-html directive with user input can lead to XSS',
        owaspCategory: 'A03:2021 - Injection',
        severity: 'critical',
        patterns: [
            /v-html\s*=\s*["'][^"']*\+/gi,
            /v-html\s*=\s*["'][^"']*\$\{/gi,
            /v-html\s*=\s*["'][^"']*props\./gi,
            /v-html\s*=\s*["'][^"']*data\./gi
        ],
        languages: ['javascript', 'typescript', 'vue'],
        mitigation: 'Sanitize HTML content or use v-text for plain text rendering'
    },
    {
        id: 'vue-injection-1',
        name: 'Vue.js Template Injection',
        description: 'Dynamic template compilation with user input',
        owaspCategory: 'A03:2021 - Injection',
        severity: 'high',
        patterns: [
            /Vue\.compile\s*\([^)]*\+/gi,
            /\$compile\s*\([^)]*\+/gi,
            /template:\s*[^,}]*\+/gi
        ],
        languages: ['javascript', 'typescript', 'vue'],
        mitigation: 'Avoid dynamic template compilation with user input'
    },

    // Angular Security Rules
    {
        id: 'angular-xss-1',
        name: 'Angular innerHTML XSS Risk',
        description: 'Use of innerHTML binding with user input can lead to XSS',
        owaspCategory: 'A03:2021 - Injection',
        severity: 'critical',
        patterns: [
            /\[innerHTML\]\s*=\s*[^>]*\+/gi,
            /\[innerHTML\]\s*=\s*[^>]*\$\{/gi,
            /\.innerHTML\s*=\s*[^;]*\+/gi
        ],
        languages: ['javascript', 'typescript'],
        mitigation: 'Use Angular DomSanitizer or avoid innerHTML binding'
    },
    {
        id: 'angular-trust-1',
        name: 'Angular Unsafe Trust Usage',
        description: 'Use of bypassSecurityTrust methods can introduce XSS',
        owaspCategory: 'A03:2021 - Injection',
        severity: 'high',
        patterns: [
            /bypassSecurityTrustHtml\s*\(/gi,
            /bypassSecurityTrustScript\s*\(/gi,
            /bypassSecurityTrustUrl\s*\(/gi,
            /bypassSecurityTrustResourceUrl\s*\(/gi
        ],
        languages: ['javascript', 'typescript'],
        mitigation: 'Carefully validate input before using bypass methods'
    },

    // API Security Rules
    {
        id: 'api-graphql-1',
        name: 'GraphQL Query Complexity',
        description: 'Potential GraphQL DoS through query complexity',
        owaspCategory: 'A04:2021 - Insecure Design',
        severity: 'medium',
        patterns: [
            /query\s*{[^}]*{[^}]*{[^}]*{/gi,
            /mutation\s*{[^}]*{[^}]*{[^}]*{/gi
        ],
        languages: ['javascript', 'typescript', 'python'],
        mitigation: 'Implement query complexity limits and depth limiting'
    },
    {
        id: 'api-graphql-2',
        name: 'GraphQL Injection Risk',
        description: 'Dynamic GraphQL query construction with user input',
        owaspCategory: 'A03:2021 - Injection',
        severity: 'critical',
        patterns: [
            /`query\s*{[^`]*\$\{[^}]*\}/gi,
            /`mutation\s*{[^`]*\$\{[^}]*\}/gi,
            /"query":\s*"[^"]*"\s*\+/gi
        ],
        languages: ['javascript', 'typescript', 'python'],
        mitigation: 'Use parameterized GraphQL queries and proper validation'
    },
    {
        id: 'api-cors-1',
        name: 'Insecure CORS Configuration',
        description: 'Overly permissive CORS configuration detected',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        severity: 'high',
        patterns: [
            /Access-Control-Allow-Origin:\s*\*/gi,
            /cors\(\s*{\s*origin:\s*true/gi,
            /\.cors\(\s*\)/gi,
            /"Access-Control-Allow-Origin":\s*"\*"/gi
        ],
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp'],
        mitigation: 'Configure CORS with specific origins and proper credentials handling'
    },
    {
        id: 'api-rate-limit-1',
        name: 'Missing Rate Limiting',
        description: 'API endpoint without rate limiting detected',
        owaspCategory: 'A04:2021 - Insecure Design',
        severity: 'medium',
        patterns: [
            /app\.(get|post|put|delete)\([^)]*\)(?![^{]*rateLimit)/gi,
            /router\.(get|post|put|delete)\([^)]*\)(?![^{]*rateLimit)/gi,
            /@RequestMapping(?![^{]*@RateLimited)/gi
        ],
        languages: ['javascript', 'typescript', 'java'],
        mitigation: 'Implement rate limiting to prevent abuse and DoS attacks'
    },

    // Cloud Security Rules
    {
        id: 'cloud-aws-s3-1',
        name: 'AWS S3 Public Read Access',
        description: 'S3 bucket configured with public read access',
        owaspCategory: 'A01:2021 - Broken Access Control',
        severity: 'critical',
        patterns: [
            /PublicRead\s*:\s*true/gi,
            /"Effect":\s*"Allow"[^}]*"Principal":\s*"\*"/gi,
            /s3:GetObject[^}]*"Principal":\s*"\*"/gi
        ],
        languages: ['json', 'yaml', 'javascript', 'typescript', 'python'],
        mitigation: 'Remove public access and implement proper bucket policies'
    },
    {
        id: 'cloud-aws-lambda-1',
        name: 'AWS Lambda Environment Variable Exposure',
        description: 'Sensitive data in Lambda environment variables',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
        severity: 'high',
        patterns: [
            /Environment:\s*{[^}]*password/gi,
            /Environment:\s*{[^}]*secret/gi,
            /Environment:\s*{[^}]*key/gi,
            /process\.env\.[A-Z_]*(?:PASSWORD|SECRET|KEY)/gi
        ],
        languages: ['yaml', 'javascript', 'typescript', 'python'],
        mitigation: 'Use AWS Secrets Manager or Parameter Store for sensitive data'
    },
    {
        id: 'cloud-docker-1',
        name: 'Docker Container Running as Root',
        description: 'Docker container running with root privileges',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        severity: 'high',
        patterns: [
            /USER\s+root/gi,
            /FROM[^#]*(?!.*USER\s+(?!root))/gi
        ],
        languages: ['dockerfile'],
        mitigation: 'Create and use a non-root user in Docker containers'
    },

    // Modern Crypto and JWT Security
    {
        id: 'jwt-weak-secret-1',
        name: 'JWT Weak Secret',
        description: 'JWT signed with weak or default secret',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
        severity: 'critical',
        patterns: [
            /jwt\.sign\([^,]*,\s*["']secret["']/gi,
            /jwt\.sign\([^,]*,\s*["']your-256-bit-secret["']/gi,
            /jwt\.sign\([^,]*,\s*["']key["']/gi,
            /JWT_SECRET\s*=\s*["'][^"']{1,15}["']/gi
        ],
        languages: ['javascript', 'typescript', 'python'],
        mitigation: 'Use strong, randomly generated secrets of at least 32 characters'
    },
    {
        id: 'jwt-no-verify-1',
        name: 'JWT Without Verification',
        description: 'JWT token used without proper verification',
        owaspCategory: 'A07:2021 - Identification and Authentication Failures',
        severity: 'critical',
        patterns: [
            /jwt\.decode\([^,)]*\)/gi,
            /JSON\.parse\(atob\([^)]*\.split\(/gi,
            /base64\.decode\([^)]*\.split\(/gi
        ],
        languages: ['javascript', 'typescript', 'python'],
        mitigation: 'Always verify JWT tokens using jwt.verify() with proper secret'
    },

    // NoSQL Injection
    {
        id: 'nosql-injection-1',
        name: 'NoSQL Injection Risk',
        description: 'Potential NoSQL injection in database query',
        owaspCategory: 'A03:2021 - Injection',
        severity: 'critical',
        patterns: [
            /db\.collection\([^)]*\)\.find\(\s*req\./gi,
            /Model\.find\(\s*req\./gi,
            /\$where:\s*[^,}]*\+/gi,
            /collection\.find\(\s*JSON\.parse\(/gi
        ],
        languages: ['javascript', 'typescript', 'python'],
        mitigation: 'Use parameterized queries and input validation for NoSQL databases'
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
            'ssrf-1': `Validate URLs against whitelist: if (allowedDomains.includes(domain)) fetch(url);`,
            // Modern Framework Suggestions
            'react-xss-1': `Use DOMPurify to sanitize HTML: dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(content)}}`,
            'react-xss-2': `Validate URLs: const safeUrl = new URL(userUrl).protocol === 'https:' ? userUrl : '#';`,
            'react-state-1': `Use setState: this.setState({property: newValue}) or useState setter: setProperty(newValue)`,
            'vue-xss-1': `Use v-text for plain text or sanitize HTML: v-html="$sanitize(content)"`,
            'vue-injection-1': `Avoid dynamic template compilation. Use predefined templates or proper escaping`,
            'angular-xss-1': `Use DomSanitizer: constructor(private sanitizer: DomSanitizer) {}`,
            'angular-trust-1': `Validate input thoroughly before bypassing Angular's security`,
            // API Security Suggestions
            'api-graphql-1': `Implement query complexity analysis: const depthLimit = require('graphql-depth-limit')(5);`,
            'api-graphql-2': `Use GraphQL variables: query($id: ID!) { user(id: $id) { name } }`,
            'api-cors-1': `Configure specific origins: cors({origin: ['https://trusted-domain.com']})`,
            'api-rate-limit-1': `Add rate limiting: const rateLimit = require('express-rate-limit');`,
            // Cloud Security Suggestions
            'cloud-aws-s3-1': `Remove public access and use signed URLs or CloudFront for controlled access`,
            'cloud-aws-lambda-1': `Use AWS Secrets Manager: const secret = await secretsManager.getSecretValue().promise();`,
            'cloud-docker-1': `Add non-root user: RUN adduser --disabled-password --gecos '' appuser && USER appuser`,
            // JWT Security Suggestions
            'jwt-weak-secret-1': `Use strong secret: const secret = crypto.randomBytes(64).toString('hex');`,
            'jwt-no-verify-1': `Always verify JWT: const decoded = jwt.verify(token, secret);`,
            // NoSQL Security Suggestions
            'nosql-injection-1': `Sanitize input: const query = {_id: mongoose.Types.ObjectId(req.params.id)};`
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
