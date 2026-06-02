const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 12;
const SESSION_SECRET = process.env.SESSION_SECRET || require('crypto').randomBytes(32).toString('hex');

// In-memory store (resets on sleep, but fine for demo/CTF)
const db = {
    admin: null,      // { username, hash, createdAt }
    sessions: new Set() // track active session IDs
};

// === MIDDLEWARE ===
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"], // inline styles for demo
            imgSrc: ["'self'", "data:"],
        }
    },
    hsts: { maxAge: 31536000, includeSubDomains: true }
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
    name: 'admin_sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,        // set to true if using HTTPS (Render does this automatically)
        httpOnly: true,       // prevents XSS cookie theft
        maxAge: 15 * 60 * 1000, // 15 minutes
        sameSite: 'strict'
    }
}));

// === RATE LIMITING ===
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,                   // 5 attempts per IP
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    handler: (req, res) => {
        res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
    }
});

const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30
});

app.use('/api/', apiLimiter);

// === AUTH MIDDLEWARE ===
function requireAuth(req, res, next) {
    if (req.session && req.session.authenticated && db.sessions.has(req.sessionID)) {
        return next();
    }
    return res.status(401).json({ error: 'Unauthorized' });
}

function requireNoAuth(req, res, next) {
    if (req.session && req.session.authenticated) {
        return res.status(403).json({ error: 'Already logged in' });
    }
    next();
}

// === ROUTES ===

// Check if setup is needed
app.get('/api/status', (req, res) => {
    res.json({
        setupRequired: !db.admin,
        authenticated: !!(req.session && req.session.authenticated)
    });
});

// Setup (first-time only)
app.post('/api/setup', requireNoAuth, async (req, res) => {
    if (db.admin) {
        return res.status(403).json({ error: 'Admin already exists' });
    }

    const { username, password } = req.body;
    if (!username || !password || password.length < 8) {
        return res.status(400).json({ error: 'Username required, password min 8 chars' });
    }

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    db.admin = { username, hash, createdAt: Date.now() };

    req.session.authenticated = true;
    req.session.username = username;
    db.sessions.add(req.sessionID);

    res.json({ success: true, message: 'Admin created and logged in' });
});

// Login
app.post('/api/login', loginLimiter, async (req, res) => {
    if (!db.admin) {
        return res.status(400).json({ error: 'Setup required first' });
    }

    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    if (username !== db.admin.username) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    const valid = await bcrypt.compare(password, db.admin.hash);
    if (!valid) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    req.session.authenticated = true;
    req.session.username = username;
    db.sessions.add(req.sessionID);

    res.json({ success: true });
});

// Logout
app.post('/api/logout', (req, res) => {
    db.sessions.delete(req.sessionID);
    req.session.destroy(() => {
        res.json({ success: true });
    });
});

// Admin data (protected)
app.get('/api/admin/data', requireAuth, (req, res) => {
    res.json({
        username: req.session.username,
        serverTime: new Date().toISOString(),
        sessionId: req.sessionID.slice(0, 8) + '...',
        security: {
            hashing: 'bcrypt (12 rounds)',
            sessions: 'Server-side + HttpOnly cookies',
            rateLimit: '5 attempts / 15 min per IP',
            transport: 'Helmet security headers'
        },
        flag: 'GROK_FAILED_TO_BYPASS_SERVER_AUTH'
    });
});

// Serve SPA
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`🔒 Secure Admin Panel running on port ${PORT}`);
    console.log(`Setup required: ${!db.admin}`);
});
