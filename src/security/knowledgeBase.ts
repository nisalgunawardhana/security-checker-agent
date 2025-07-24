import * as vscode from 'vscode';

export interface SecurityKnowledge {
    id: string;
    title: string;
    category: string;
    description: string;
    examples: {
        vulnerable: string;
        secure: string;
    };
    references: string[];
    severity: 'low' | 'medium' | 'high' | 'critical';
    cweId?: string;
}

export const SECURITY_KNOWLEDGE_BASE: SecurityKnowledge[] = [
    {
        id: 'xss-prevention',
        title: 'Cross-Site Scripting (XSS) Prevention',
        category: 'A03:2021 - Injection',
        description: 'XSS occurs when untrusted data is included in web pages without proper validation or escaping, allowing attackers to execute malicious scripts.',
        examples: {
            vulnerable: `
// Vulnerable: Direct HTML insertion
element.innerHTML = userInput;
document.write(userInput);

// React - Dangerous HTML insertion
<div dangerouslySetInnerHTML={{__html: userInput}} />

// Vue.js - Unsafe HTML binding
<div v-html="userInput"></div>
            `,
            secure: `
// Secure: Use textContent for plain text
element.textContent = userInput;

// Secure: Sanitize HTML content
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);

// React - Safe rendering
<div>{userInput}</div> // Auto-escaped
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />

// Vue.js - Safe text binding
<div>{{ userInput }}</div> // Auto-escaped
            `
        },
        references: [
            'https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)',
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
        ],
        severity: 'high',
        cweId: 'CWE-79'
    },
    {
        id: 'sql-injection-prevention',
        title: 'SQL Injection Prevention',
        category: 'A03:2021 - Injection',
        description: 'SQL injection occurs when user input is directly concatenated into SQL queries, allowing attackers to manipulate database operations.',
        examples: {
            vulnerable: `
// Vulnerable: String concatenation
const query = "SELECT * FROM users WHERE id = " + userId;
const query2 = \`SELECT * FROM users WHERE name = '\${userName}'\`;

// Vulnerable: Dynamic query building
db.query("SELECT * FROM users WHERE id = " + req.params.id);
            `,
            secure: `
// Secure: Parameterized queries
const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId]);

// Secure: Named parameters
const query = "SELECT * FROM users WHERE name = :name";
db.query(query, { name: userName });

// Secure: ORM with safe methods
const user = await User.findById(userId);
const users = await User.findAll({ where: { name: userName } });
            `
        },
        references: [
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
        ],
        severity: 'critical',
        cweId: 'CWE-89'
    },
    {
        id: 'jwt-security',
        title: 'JSON Web Token (JWT) Security',
        category: 'A07:2021 - Identification and Authentication Failures',
        description: 'JWT tokens must be properly signed, verified, and configured to prevent token-based attacks.',
        examples: {
            vulnerable: `
// Vulnerable: Weak secret
const token = jwt.sign(payload, 'secret');

// Vulnerable: No verification
const decoded = jwt.decode(token);

// Vulnerable: No expiration
const token = jwt.sign(payload, secret);
            `,
            secure: `
// Secure: Strong secret
const secret = crypto.randomBytes(64).toString('hex');
const token = jwt.sign(payload, secret, {
    expiresIn: '1h',
    issuer: 'your-app',
    audience: 'your-users'
});

// Secure: Always verify
try {
    const decoded = jwt.verify(token, secret);
    // Token is valid
} catch (error) {
    // Token is invalid
    throw new Error('Invalid token');
}
            `
        },
        references: [
            'https://jwt.io/introduction/',
            'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html'
        ],
        severity: 'high',
        cweId: 'CWE-287'
    },
    {
        id: 'react-security',
        title: 'React Security Best Practices',
        category: 'Modern Framework Security',
        description: 'React applications have specific security considerations including XSS prevention, secure state management, and safe prop handling.',
        examples: {
            vulnerable: `
// Vulnerable: Direct HTML insertion
<div dangerouslySetInnerHTML={{__html: userInput}} />

// Vulnerable: Dynamic href
<a href={userUrl}>Link</a>

// Vulnerable: Direct state mutation
this.state.items = newItems;
            `,
            secure: `
// Secure: Auto-escaped content
<div>{userInput}</div>

// Secure: Sanitized HTML
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />

// Secure: URL validation
const safeUrl = isValidUrl(userUrl) ? userUrl : '#';
<a href={safeUrl} rel="noopener noreferrer">Link</a>

// Secure: Proper state updates
this.setState({ items: newItems });
// Or with hooks
setItems(newItems);
            `
        },
        references: [
            'https://react.dev/reference/react-dom/components/common#applying-css-styles',
            'https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html'
        ],
        severity: 'medium'
    },
    {
        id: 'api-security',
        title: 'API Security Best Practices',
        category: 'A04:2021 - Insecure Design',
        description: 'APIs require proper authentication, authorization, rate limiting, and input validation to prevent abuse.',
        examples: {
            vulnerable: `
// Vulnerable: No rate limiting
app.get('/api/data', (req, res) => {
    res.json(data);
});

// Vulnerable: Permissive CORS
app.use(cors({ origin: '*' }));

// Vulnerable: No input validation
app.post('/api/users', (req, res) => {
    const user = new User(req.body);
    user.save();
});
            `,
            secure: `
// Secure: Rate limiting
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP
});

app.get('/api/data', limiter, authenticateToken, (req, res) => {
    res.json(data);
});

// Secure: Specific CORS origins
app.use(cors({
    origin: ['https://trusted-domain.com'],
    credentials: true
}));

// Secure: Input validation
const { body, validationResult } = require('express-validator');

app.post('/api/users',
    body('email').isEmail(),
    body('name').trim().escape(),
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        // Process validated input
    }
);
            `
        },
        references: [
            'https://owasp.org/www-project-api-security/',
            'https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html'
        ],
        severity: 'high'
    },
    {
        id: 'cryptographic-security',
        title: 'Cryptographic Security',
        category: 'A02:2021 - Cryptographic Failures',
        description: 'Proper cryptographic practices include using strong algorithms, secure random generation, and proper key management.',
        examples: {
            vulnerable: `
// Vulnerable: Weak hash algorithms
const hash = crypto.createHash('md5').update(password).digest('hex');
const hash2 = crypto.createHash('sha1').update(data).digest('hex');

// Vulnerable: Hardcoded secrets
const API_KEY = 'sk-1234567890abcdef';

// Vulnerable: Weak random
const sessionId = Math.random().toString(36);
            `,
            secure: `
// Secure: Strong hash algorithms
const bcrypt = require('bcrypt');
const saltRounds = 12;
const hash = await bcrypt.hash(password, saltRounds);

// Secure: Environment variables
const API_KEY = process.env.API_KEY;

// Secure: Cryptographically secure random
const sessionId = crypto.randomBytes(32).toString('hex');

// Secure: Strong secrets
const jwtSecret = crypto.randomBytes(64).toString('hex');
            `
        },
        references: [
            'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
            'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'
        ],
        severity: 'high',
        cweId: 'CWE-327'
    },
    {
        id: 'nosql-injection',
        title: 'NoSQL Injection Prevention',
        category: 'A03:2021 - Injection',
        description: 'NoSQL databases are vulnerable to injection attacks when user input is directly used in queries without proper validation.',
        examples: {
            vulnerable: `
// Vulnerable: Direct user input in MongoDB query
const user = await User.find(req.body);

// Vulnerable: Dynamic query construction
const filter = { $where: \`this.name == '\${userName}'\` };
const users = await User.find(filter);

// Vulnerable: JSON parsing in queries
const query = JSON.parse(req.body.filter);
const results = await collection.find(query);
            `,
            secure: `
// Secure: Validate and sanitize input
const userId = mongoose.Types.ObjectId(req.params.id);
const user = await User.findById(userId);

// Secure: Use schema validation
const userSchema = {
    name: { type: String, required: true },
    email: { type: String, required: true, validate: validator.isEmail }
};

// Secure: Whitelist allowed fields
const allowedFields = ['name', 'email', 'age'];
const filter = {};
Object.keys(req.body).forEach(key => {
    if (allowedFields.includes(key)) {
        filter[key] = req.body[key];
    }
});
const users = await User.find(filter);
            `
        },
        references: [
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection',
            'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html'
        ],
        severity: 'critical',
        cweId: 'CWE-943'
    }
];

export class SecurityKnowledgeProvider {
    getKnowledgeById(id: string): SecurityKnowledge | undefined {
        return SECURITY_KNOWLEDGE_BASE.find(kb => kb.id === id);
    }

    getKnowledgeByCategory(category: string): SecurityKnowledge[] {
        return SECURITY_KNOWLEDGE_BASE.filter(kb => 
            kb.category.toLowerCase().includes(category.toLowerCase())
        );
    }

    searchKnowledge(query: string): SecurityKnowledge[] {
        const lowerQuery = query.toLowerCase();
        return SECURITY_KNOWLEDGE_BASE.filter(kb =>
            kb.title.toLowerCase().includes(lowerQuery) ||
            kb.description.toLowerCase().includes(lowerQuery) ||
            kb.category.toLowerCase().includes(lowerQuery)
        );
    }

    getAllKnowledge(): SecurityKnowledge[] {
        return SECURITY_KNOWLEDGE_BASE;
    }

    generateKnowledgeReport(vulnerabilityIds: string[]): string {
        const relevantKnowledge = vulnerabilityIds
            .map(id => this.getKnowledgeById(id))
            .filter(kb => kb !== undefined) as SecurityKnowledge[];

        if (relevantKnowledge.length === 0) {
            return 'No specific knowledge base entries found for detected vulnerabilities.';
        }

        let report = '# Security Knowledge Report\n\n';
        
        relevantKnowledge.forEach(kb => {
            report += `## ${kb.title}\n\n`;
            report += `**Category:** ${kb.category}\n`;
            report += `**Severity:** ${kb.severity}\n`;
            if (kb.cweId) {
                report += `**CWE ID:** ${kb.cweId}\n`;
            }
            report += `\n${kb.description}\n\n`;
            
            report += `### Vulnerable Code Example\n\`\`\`\n${kb.examples.vulnerable}\n\`\`\`\n\n`;
            report += `### Secure Code Example\n\`\`\`\n${kb.examples.secure}\n\`\`\`\n\n`;
            
            report += `### References\n`;
            kb.references.forEach(ref => {
                report += `- [${ref}](${ref})\n`;
            });
            report += '\n---\n\n';
        });

        return report;
    }
}
