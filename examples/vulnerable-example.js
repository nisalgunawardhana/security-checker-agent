// Security Checker Agent - Vulnerable Code Examples
// This file demonstrates various security vulnerabilities that the extension can detect

// A02: Cryptographic Failures
const API_KEY = 'sk-1234567890abcdef'; // Hardcoded secret
const password = 'admin123'; // Weak password
const hash = require('crypto').createHash('md5').update(password).digest('hex'); // Weak hash

// A03: Injection Vulnerabilities
const userId = req.params.id;
const query = `SELECT * FROM users WHERE id = ${userId}`; // SQL injection
const command = `ls -la ${userInput}`; // Command injection
document.getElementById('content').innerHTML = userInput; // XSS

// A01: Broken Access Control
const user = { role: 'admin' }; // Hardcoded role
app.get('/admin', (req, res) => { // Missing auth check
    res.send('Admin panel');
});

// React Security Issues
function UserProfile({ userData }) {
    return (
        <div dangerouslySetInnerHTML={{__html: userData.bio}} /> // React XSS
    );
}

const ProfileLink = ({ url }) => (
    <a href={url}>Profile</a> // Potential XSS via href
);

// Vue.js Security Issues
const VueComponent = {
    template: `<div v-html="userContent"></div>`, // Vue XSS
    data() {
        return {
            userContent: this.$route.params.content // Unsafe content
        };
    }
};

// Angular Security Issues
@Component({
    template: `<div [innerHTML]="userHtml"></div>` // Angular XSS
})
class MyComponent {
    constructor(private sanitizer: DomSanitizer) {}
    
    dangerousMethod() {
        return this.sanitizer.bypassSecurityTrustHtml(userInput); // Unsafe trust
    }
}

// API Security Issues
const corsOptions = {
    origin: '*', // Insecure CORS
    credentials: true
};

app.get('/api/data', (req, res) => { // Missing rate limiting
    const query = `{ user(id: "${req.params.id}") { name email } }`; // GraphQL injection
    graphql(schema, query);
});

// JWT Security Issues
const token = jwt.sign(payload, 'secret'); // Weak JWT secret
const decoded = jwt.decode(token); // JWT without verification

// NoSQL Injection
const user = await User.find(req.body); // NoSQL injection
const result = db.collection('users').find({$where: `this.name == '${userName}'`}); // MongoDB injection

// Cloud Security Issues (if in config files)
const s3Policy = {
    "Effect": "Allow",
    "Principal": "*", // Public S3 access
    "Action": "s3:GetObject"
};

// Missing Security Headers
app.get('/', (req, res) => {
    res.send('Hello World'); // Missing security headers
});

// Insecure Random
const sessionId = Math.random().toString(36); // Weak random

// Path Traversal
const filePath = './uploads/' + req.params.filename; // Path traversal
fs.readFile(filePath, callback);

// Missing Input Validation
app.post('/user', (req, res) => {
    const user = new User(req.body); // No validation
    user.save();
});

// Prototype Pollution
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key]; // Prototype pollution
    }
}

// LDAP Injection
const filter = `(uid=${username})`; // LDAP injection
ldap.search('dc=example,dc=com', { filter }, callback);

// XML External Entity (XXE)
const xml = libxmljs.parseXml(userXmlInput); // Potential XXE

// Server-Side Template Injection
const template = `Hello ${userInput}`; // Template injection
eval(`\`${template}\``);