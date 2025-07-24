// Security Checker Agent - Secure Code Examples
// This file demonstrates secure coding practices

// Note: This file shows security patterns and may reference external libraries
// that are not installed in this workspace. The patterns shown are for educational purposes.

// A02: Secure Cryptographic Practices
const API_KEY = process.env.API_KEY; // Environment variable
const JWT_SECRET = process.env.JWT_SECRET || generateSecureSecret(); // Strong secret

// Secure password hashing (example pattern)
async function hashPassword(password: string): Promise<string> {
    // In real code: const saltRounds = 12; return await bcrypt.hash(password, saltRounds);
    return `hashed_${password}_with_salt`; // Simplified for example
}

function generateSecureSecret(): string {
    // In real code: return crypto.randomBytes(64).toString('hex');
    return 'secure-randomly-generated-secret-key';
}

// A03: Injection Prevention
async function getUserById(userId: string): Promise<User> {
    // Parameterized query example
    const query = 'SELECT * FROM users WHERE id = ?';
    // In real code: return await db.query(query, [userId]);
    return { id: userId, name: 'user', role: 'user' }; // Simplified for example
}

// Safe command execution pattern
function executeCommand(userInput: string) {
    const allowedCommands = ['ls', 'pwd', 'date'];
    if (allowedCommands.includes(userInput)) {
        // In real code: return execFile(userInput, [], { timeout: 5000 });
        return `Executing safe command: ${userInput}`;
    }
    throw new Error('Command not allowed');
}

// XSS Prevention
function safeRender(content: string): string {
    // In real code: return DOMPurify.sanitize(content);
    return content.replace(/[<>&'"]/g, (char) => {
        const escapeMap: { [key: string]: string } = {
            '<': '&lt;',
            '>': '&gt;',
            '&': '&amp;',
            "'": '&#x27;',
            '"': '&quot;'
        };
        return escapeMap[char];
    });
}

// A01: Proper Access Control
interface User {
    id: string;
    role: string;
    name?: string;
}

async function getUserRole(userId: string): Promise<string> {
    const user = await getUserById(userId);
    return user?.role || 'guest';
}

// Authorization middleware pattern
async function requireAdmin(req: any, res: any, next: any) {
    const userRole = await getUserRole(req.user.id);
    if (userRole !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }
    next();
}

// React Security Best Practices
interface UserProfileProps {
    userData: {
        name: string;
        bio: string;
    };
}

// Example secure React component (JSX syntax shown as string templates)
function SecureUserProfile({ userData }: UserProfileProps) {
    // Secure approach: Use JSX auto-escaping
    // return <div><h1>{userData.name}</h1><p>{userData.bio}</p></div>;
    
    // Or sanitize if HTML is needed
    // return <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userData.bio)}} />;
    
    return userData.name; // Simplified for TypeScript compilation
}

// Secure URL handling
interface ProfileLinkProps {
    url: string;
}

const SecureProfileLink = ({ url }: ProfileLinkProps) => {
    const safeUrl = (() => {
        try {
            const urlObj = new URL(url);
            return ['http:', 'https:'].includes(urlObj.protocol) ? url : '#';
        } catch {
            return '#';
        }
    })();
    
    // return <a href={safeUrl} rel="noopener noreferrer">Profile</a>;
    return safeUrl; // Simplified for TypeScript compilation
};

// API Security Best Practices
const corsOptions = {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['https://trusted-domain.com'],
    credentials: true,
    optionsSuccessStatus: 200
};

// Input validation pattern
const validateUserInput = (input: string): boolean => {
    // Basic validation example
    const allowedPattern = /^[a-zA-Z0-9\s@.-]+$/;
    return allowedPattern.test(input) && input.length <= 100;
};

// JWT Security Best Practices
function createSecureToken(payload: any): string {
    // In real code: return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h', issuer: 'secure-app' });
    return `secure.jwt.token.for.${JSON.stringify(payload)}`;
}

function verifyToken(token: string): any {
    try {
        // In real code: return jwt.verify(token, JWT_SECRET);
        if (token.startsWith('secure.jwt.token.for.')) {
            return JSON.parse(token.replace('secure.jwt.token.for.', ''));
        }
        throw new Error('Invalid token format');
    } catch (error) {
        throw new Error('Invalid token');
    }
}

// NoSQL Security
async function findUserSecurely(criteria: any) {
    // Sanitize input pattern
    const sanitizedCriteria = {
        _id: validateObjectId(criteria.id) ? criteria.id : null
    };
    // In real code: return await User.findOne(sanitizedCriteria);
    return sanitizedCriteria._id ? { id: sanitizedCriteria._id } : null;
}

function validateObjectId(id: string): boolean {
    // Basic ObjectId validation pattern
    return /^[0-9a-fA-F]{24}$/.test(id);
}

// Secure Random Generation
function generateSecureSessionId(): string {
    // In real code: return crypto.randomBytes(32).toString('hex');
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < 64; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// Path Traversal Prevention
function secureFileAccess(filename: string): string {
    // Remove path traversal characters
    const sanitized = filename.replace(/[^a-zA-Z0-9.-]/g, '');
    const safePath = `./uploads/${sanitized}`;
    
    // Ensure the path is within uploads directory
    if (!safePath.startsWith('./uploads/')) {
        throw new Error('Invalid file path');
    }
    
    return safePath;
}

// Security Headers example configuration
const securityHeaders = {
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
};

// Secure Cookie Settings example
const secureCookieOptions = {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    sameSite: 'strict' as const
};

// GraphQL Security example
const graphqlSecurityConfig = {
    depthLimit: 5,
    costAnalysis: { maximumCost: 1000 },
    queryTimeout: 10000
};

// Cloud Security - S3 Example (policy structure)
const secureS3Policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::ACCOUNT-ID:user/specific-user"
            },
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::bucket-name/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-server-side-encryption": "AES256"
                }
            }
        }
    ]
};

// Logging Security Events
function logSecurityEvent(event: string, details: any) {
    const logEntry = {
        event,
        details,
        timestamp: new Date().toISOString(),
        ip: details.ip,
        userAgent: details.userAgent
    };
    
    // In real code: use proper logging library like winston
    console.log('Security Event:', JSON.stringify(logEntry));
}

export {
    hashPassword,
    getUserById,
    executeCommand,
    safeRender,
    requireAdmin,
    SecureUserProfile,
    SecureProfileLink,
    createSecureToken,
    verifyToken,
    findUserSecurely,
    generateSecureSessionId,
    secureFileAccess,
    logSecurityEvent,
    validateUserInput,
    validateObjectId
};