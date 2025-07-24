import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { OwaspSecurityAnalyzer, SecurityVulnerability } from './owaspRules';

// Use dynamic imports for optional dependencies
let babelParser: any = null;
let babelTraverse: any = null;
let acorn: any = null;

async function loadBabelParser() {
    if (!babelParser) {
        try {
            const babel = await import('@babel/parser');
            babelParser = babel.parse;
        } catch (error) {
            console.warn('Babel parser not available, using fallback');
        }
    }
    return babelParser;
}

async function loadBabelTraverse() {
    if (!babelTraverse) {
        try {
            const traverse = await import('@babel/traverse');
            babelTraverse = traverse.default || traverse;
        } catch (error) {
            console.warn('Babel traverse not available');
        }
    }
    return babelTraverse;
}

async function loadAcorn() {
    if (!acorn) {
        try {
            acorn = await import('acorn');
        } catch (error) {
            console.warn('Acorn parser not available');
        }
    }
    return acorn;
}

export interface ParsedFile {
    filePath: string;
    language: string;
    ast?: any;
    content: string;
    vulnerabilities: SecurityVulnerability[];
}

export class MultiLanguageParser {
    private securityAnalyzer: OwaspSecurityAnalyzer;
    private supportedExtensions = new Map([
        ['.js', 'javascript'],
        ['.jsx', 'javascript'],
        ['.ts', 'typescript'],
        ['.tsx', 'typescript'],
        ['.vue', 'vue'],
        ['.py', 'python'],
        ['.java', 'java'],
        ['.cs', 'csharp'],
        ['.php', 'php'],
        ['.rb', 'ruby'],
        ['.go', 'go'],
        ['.cpp', 'cpp'],
        ['.c', 'c'],
        ['.dockerfile', 'dockerfile'],
        ['.json', 'json'],
        ['.yaml', 'yaml'],
        ['.yml', 'yaml'],
        ['.rs', 'rust'],
        ['.kt', 'kotlin'],
        ['.swift', 'swift']
    ]);

    constructor(enabledRules?: string[]) {
        this.securityAnalyzer = new OwaspSecurityAnalyzer(enabledRules);
    }

    async parseWorkspace(workspaceUri: vscode.Uri): Promise<ParsedFile[]> {
        const files = await this.findCodeFiles(workspaceUri);
        const parsedFiles: ParsedFile[] = [];

        for (const fileUri of files) {
            try {
                const parsedFile = await this.parseFile(fileUri);
                if (parsedFile) {
                    parsedFiles.push(parsedFile);
                }
            } catch (error) {
                console.error(`Error parsing file ${fileUri.fsPath}:`, error);
            }
        }

        return parsedFiles;
    }

    async parseFile(fileUri: vscode.Uri): Promise<ParsedFile | null> {
        const filePath = fileUri.fsPath;
        const extension = path.extname(filePath).toLowerCase();
        const language = this.supportedExtensions.get(extension);

        if (!language) {
            return null; // Unsupported file type
        }

        try {
            const content = fs.readFileSync(filePath, 'utf8');
            let ast: any = null;

            // Parse AST based on language
            if (language === 'javascript' || language === 'typescript') {
                ast = await this.parseJavaScriptTypeScript(content, language === 'typescript');
            } else if (language === 'python') {
                // For Python, we'll use regex patterns for now (could integrate Python AST parser)
                ast = null;
            }

            // Analyze for security vulnerabilities
            const vulnerabilities = this.securityAnalyzer.analyzeCode(content, filePath, language);

            return {
                filePath,
                language,
                ast,
                content,
                vulnerabilities
            };
        } catch (error) {
            console.error(`Error parsing file ${filePath}:`, error);
            return null;
        }
    }

    private async parseJavaScriptTypeScript(content: string, isTypeScript: boolean): Promise<any> {
        const parser = await loadBabelParser();
        if (parser) {
            try {
                return parser(content, {
                    sourceType: 'module',
                    allowImportExportEverywhere: true,
                    allowReturnOutsideFunction: true,
                    plugins: [
                        'jsx',
                        'typescript',
                        'decorators-legacy',
                        'classProperties',
                        'objectRestSpread',
                        'asyncGenerators',
                        'dynamicImport',
                        'nullishCoalescingOperator',
                        'optionalChaining'
                    ]
                });
            } catch (error) {
                console.warn('Babel parsing failed, trying Acorn fallback');
            }
        }

        // Fallback to Acorn parser
        const acornParser = await loadAcorn();
        if (acornParser) {
            try {
                return acornParser.parse(content, {
                    ecmaVersion: 'latest',
                    sourceType: 'module',
                    allowHashBang: true,
                    allowReturnOutsideFunction: true
                });
            } catch (acornError) {
                console.warn('Both Babel and Acorn parsers failed');
            }
        }
        
        return null;
    }

    private async findCodeFiles(workspaceUri: vscode.Uri): Promise<vscode.Uri[]> {
        const files: vscode.Uri[] = [];
        const excludePatterns = [
            '**/node_modules/**',
            '**/dist/**',
            '**/build/**',
            '**/coverage/**',
            '**/.git/**',
            '**/vendor/**',
            '**/target/**',
            '**/bin/**',
            '**/obj/**'
        ];

        const includePatterns = Array.from(this.supportedExtensions.keys()).map(ext => `**/*${ext}`);

        for (const pattern of includePatterns) {
            try {
                const foundFiles = await vscode.workspace.findFiles(
                    new vscode.RelativePattern(workspaceUri, pattern),
                    `{${excludePatterns.join(',')}}`
                );
                files.push(...foundFiles);
            } catch (error) {
                console.error(`Error finding files with pattern ${pattern}:`, error);
            }
        }

        return files;
    }

    async performAdvancedASTAnalysis(ast: any, language: string): Promise<SecurityVulnerability[]> {
        const vulnerabilities: SecurityVulnerability[] = [];

        if ((language === 'javascript' || language === 'typescript') && ast) {
            const traverse = await loadBabelTraverse();
            if (!traverse) {
                return vulnerabilities; // Skip AST analysis if traverse not available
            }

            try {
                // Track potentially tainted variables for data flow analysis
                const taintedVariables = new Set<string>();
                
                traverse(ast, {
                    // Detect sources of user input
                    VariableDeclarator: (path: any) => {
                        const init = path.node.init;
                        if (init && init.type === 'MemberExpression') {
                            // Track req.body, req.params, req.query as tainted
                            if (init.object && init.object.name === 'req' && 
                                (init.property.name === 'body' || init.property.name === 'params' || init.property.name === 'query')) {
                                if (path.node.id && path.node.id.name) {
                                    taintedVariables.add(path.node.id.name);
                                }
                            }
                        }
                    },

                    CallExpression: (path: any) => {
                        const callee = path.node.callee;
                        
                        // Check for dangerous function calls
                        if (callee.name === 'eval' || 
                           (callee.object && callee.object.name === 'window' && callee.property.name === 'eval')) {
                            vulnerabilities.push({
                                rule: {
                                    id: 'ast-eval-usage',
                                    name: 'Dangerous eval() Usage',
                                    description: 'Use of eval() function detected',
                                    owaspCategory: 'A03:2021 - Injection',
                                    severity: 'high',
                                    patterns: [],
                                    languages: ['javascript', 'typescript'],
                                    mitigation: 'Avoid using eval(). Use JSON.parse() for JSON or create specific parsing functions'
                                },
                                line: path.node.loc?.start?.line || 0,
                                column: path.node.loc?.start?.column || 0,
                                text: 'eval() call detected',
                                filePath: '',
                                suggestion: 'Replace eval() with safer alternatives like JSON.parse() or specific parsing functions'
                            });
                        }

                        // Check for React dangerouslySetInnerHTML with tainted data
                        if (callee.type === 'MemberExpression' && callee.property.name === 'createElement') {
                            const args = path.node.arguments;
                            if (args.length > 1 && args[1] && args[1].type === 'ObjectExpression') {
                                const dangerousProp = args[1].properties.find((prop: any) => 
                                    prop.key && prop.key.name === 'dangerouslySetInnerHTML');
                                if (dangerousProp && this.containsTaintedVariable(dangerousProp.value, taintedVariables)) {
                                    vulnerabilities.push({
                                        rule: {
                                            id: 'ast-react-xss-advanced',
                                            name: 'React XSS via Tainted Data',
                                            description: 'dangerouslySetInnerHTML used with potentially tainted user input',
                                            owaspCategory: 'A03:2021 - Injection',
                                            severity: 'critical',
                                            patterns: [],
                                            languages: ['javascript', 'typescript'],
                                            mitigation: 'Sanitize user input before using dangerouslySetInnerHTML'
                                        },
                                        line: path.node.loc?.start?.line || 0,
                                        column: path.node.loc?.start?.column || 0,
                                        text: 'dangerouslySetInnerHTML with user input',
                                        filePath: '',
                                        suggestion: 'Use DOMPurify.sanitize() before setting HTML content'
                                    });
                                }
                            }
                        }

                        // Check for SQL query construction with tainted variables
                        if (callee.object && (callee.property.name === 'query' || callee.property.name === 'execute')) {
                            const args = path.node.arguments;
                            if (args.length > 0 && this.containsTaintedVariable(args[0], taintedVariables)) {
                                vulnerabilities.push({
                                    rule: {
                                        id: 'ast-sql-injection-advanced',
                                        name: 'SQL Injection via Data Flow',
                                        description: 'Database query constructed with tainted user input',
                                        owaspCategory: 'A03:2021 - Injection',
                                        severity: 'critical',
                                        patterns: [],
                                        languages: ['javascript', 'typescript'],
                                        mitigation: 'Use parameterized queries to prevent SQL injection'
                                    },
                                    line: path.node.loc?.start?.line || 0,
                                    column: path.node.loc?.start?.column || 0,
                                    text: 'SQL query with user input',
                                    filePath: '',
                                    suggestion: 'Use db.query("SELECT * FROM users WHERE id = ?", [userId])'
                                });
                            }
                        }

                        // Check for innerHTML assignments with variables
                        if (callee.object && callee.property && 
                            callee.property.name === 'innerHTML' && 
                            path.node.arguments.some((arg: any) => arg.type === 'Identifier' || arg.type === 'BinaryExpression')) {
                            vulnerabilities.push({
                                rule: {
                                    id: 'ast-xss-innerhtml',
                                    name: 'XSS Risk with innerHTML',
                                    description: 'Potential XSS vulnerability with innerHTML and variables',
                                    owaspCategory: 'A03:2021 - Injection',
                                    severity: 'high',
                                    patterns: [],
                                    languages: ['javascript', 'typescript'],
                                    mitigation: 'Use textContent instead of innerHTML or sanitize input'
                                },
                                line: path.node.loc?.start?.line || 0,
                                column: path.node.loc?.start?.column || 0,
                                text: 'innerHTML with variable content',
                                filePath: '',
                                suggestion: 'Use element.textContent = value or sanitize HTML with DOMPurify'
                            });
                        }

                        // Check for JWT decode without verification
                        if (callee.object && callee.object.name === 'jwt' && callee.property.name === 'decode') {
                            vulnerabilities.push({
                                rule: {
                                    id: 'ast-jwt-no-verify',
                                    name: 'JWT Decoded Without Verification',
                                    description: 'JWT token decoded without proper verification',
                                    owaspCategory: 'A07:2021 - Identification and Authentication Failures',
                                    severity: 'critical',
                                    patterns: [],
                                    languages: ['javascript', 'typescript'],
                                    mitigation: 'Use jwt.verify() instead of jwt.decode() for security'
                                },
                                line: path.node.loc?.start?.line || 0,
                                column: path.node.loc?.start?.column || 0,
                                text: 'jwt.decode() detected',
                                filePath: '',
                                suggestion: 'Replace with jwt.verify(token, secret) to ensure token integrity'
                            });
                        }
                    },

                    AssignmentExpression: (path: any) => {
                        const left = path.node.left;
                        
                        // Check for document.cookie assignments
                        if (left.object && left.object.name === 'document' && 
                            left.property && left.property.name === 'cookie') {
                            vulnerabilities.push({
                                rule: {
                                    id: 'ast-insecure-cookie',
                                    name: 'Insecure Cookie Setting',
                                    description: 'Cookie set without security flags',
                                    owaspCategory: 'A02:2021 - Cryptographic Failures',
                                    severity: 'medium',
                                    patterns: [],
                                    languages: ['javascript', 'typescript'],
                                    mitigation: 'Add secure, httpOnly, and sameSite flags to cookies'
                                },
                                line: path.node.loc?.start?.line || 0,
                                column: path.node.loc?.start?.column || 0,
                                text: 'document.cookie assignment',
                                filePath: '',
                                suggestion: 'Set cookies with security flags: "name=value; Secure; HttpOnly; SameSite=Strict"'
                            });
                        }

                        // Check for React state mutations
                        if (left.object && left.object.type === 'MemberExpression' &&
                            left.object.object && left.object.object.type === 'ThisExpression' &&
                            left.object.property && left.object.property.name === 'state') {
                            vulnerabilities.push({
                                rule: {
                                    id: 'ast-react-state-mutation',
                                    name: 'Direct React State Mutation',
                                    description: 'Direct mutation of React state detected',
                                    owaspCategory: 'A04:2021 - Insecure Design',
                                    severity: 'medium',
                                    patterns: [],
                                    languages: ['javascript', 'typescript'],
                                    mitigation: 'Use setState() to update React state'
                                },
                                line: path.node.loc?.start?.line || 0,
                                column: path.node.loc?.start?.column || 0,
                                text: 'this.state.property = value',
                                filePath: '',
                                suggestion: 'Use this.setState({property: value}) instead'
                            });
                        }
                    },

                    // Check for template literals with user input
                    TemplateLiteral: (path: any) => {
                        const expressions = path.node.expressions;
                        for (const expr of expressions) {
                            if (this.containsTaintedVariable(expr, taintedVariables)) {
                                // Check if it's in a dangerous context (SQL, HTML, etc.)
                                const parent = path.parent;
                                if (this.isDangerousContext(parent)) {
                                    vulnerabilities.push({
                                        rule: {
                                            id: 'ast-template-injection',
                                            name: 'Template Injection Risk',
                                            description: 'Template literal with user input in dangerous context',
                                            owaspCategory: 'A03:2021 - Injection',
                                            severity: 'high',
                                            patterns: [],
                                            languages: ['javascript', 'typescript'],
                                            mitigation: 'Use parameterized queries or proper escaping'
                                        },
                                        line: path.node.loc?.start?.line || 0,
                                        column: path.node.loc?.start?.column || 0,
                                        text: 'Template literal with user input',
                                        filePath: '',
                                        suggestion: 'Use parameterized queries or escape user input'
                                    });
                                }
                            }
                        }
                    }
                });
            } catch (error) {
                console.error('Error in AST traversal:', error);
            }
        }

        return vulnerabilities;
    }

    // Helper method to check if a node contains tainted variables
    private containsTaintedVariable(node: any, taintedVariables: Set<string>): boolean {
        if (!node) {
            return false;
        }
        
        if (node.type === 'Identifier') {
            return taintedVariables.has(node.name);
        }
        
        if (node.type === 'MemberExpression') {
            return this.containsTaintedVariable(node.object, taintedVariables) ||
                   this.containsTaintedVariable(node.property, taintedVariables);
        }
        
        if (node.type === 'BinaryExpression') {
            return this.containsTaintedVariable(node.left, taintedVariables) ||
                   this.containsTaintedVariable(node.right, taintedVariables);
        }
        
        if (node.type === 'CallExpression') {
            return node.arguments.some((arg: any) => this.containsTaintedVariable(arg, taintedVariables));
        }
        
        return false;
    }

    // Helper method to check if we're in a dangerous context
    private isDangerousContext(parent: any): boolean {
        if (!parent) {
            return false;
        }
        
        // Check for SQL query context
        if (parent.type === 'CallExpression' && parent.callee) {
            const callee = parent.callee;
            if (callee.property && (callee.property.name === 'query' || callee.property.name === 'execute')) {
                return true;
            }
        }
        
        // Check for innerHTML context
        if (parent.type === 'AssignmentExpression' && parent.left) {
            const left = parent.left;
            if (left.property && left.property.name === 'innerHTML') {
                return true;
            }
        }
        
        return false;
    }
}
