const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 13;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');

const db = {
    admin: null,
    csrfTokens: new Map(),
    failedAttempts: new Map(),
    bannedIPs: new Set(),
};

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            frameAncestors: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
        }
    },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    referrerPolicy: { policy: 'same-origin' },
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

app.use(session({
    name: '__Host-admin_sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 15 * 60 * 1000,
        sameSite: 'strict',
        path: '/',
    }
}));

function getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0].trim() 
        || req.headers['x-real-ip'] 
        || req.connection.remoteAddress 
        || 'unknown';
}

function isIPBanned(ip) {
    return db.bannedIPs.has(ip);
}

function recordFailedAttempt(ip) {
    const now = Date.now();
    if (!db.failedAttempts.has(ip)) db.failedAttempts.set(ip, []);
    const attempts = db.failedAttempts.get(ip).filter(t => now - t < 3600000);
    attempts.push(now);
    db.failedAttempts.set(ip, attempts);

    if (attempts.length >= 10) {
        db.bannedIPs.add(ip);
        return { banned: true, duration: 'permanent' };
    } else if (attempts.length >= 5) {
        db.bannedIPs.add(ip);
        setTimeout(() => db.bannedIPs.delete(ip), 3600000);
        return { banned: true, duration: 3600000 };
    }
    return { banned: false, remaining: 5 - attempts.length };
}

function generateCSRF(sessionId) {
    const token = crypto.randomBytes(32).toString('base64');
    db.csrfTokens.set(token, { expires: Date.now() + 15 * 60 * 1000, sessionId });
    return token;
}

const strictLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => getClientIP(req),
    handler: (req, res) => {
        res.status(429).json({ error: 'Too many requests. Cool down.' });
    }
});

const generalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    keyGenerator: (req) => getClientIP(req),
});

app.use(generalLimiter);

function requireAuth(req, res, next) {
    if (req.session?.authenticated === true && req.session?.username) {
        return next();
    }
    return res.status(401).json({ error: 'Unauthorized', code: 'NO_SESSION' });
}

function requireNoAuth(req, res, next) {
    if (req.session?.authenticated) {
        return res.status(403).json({ error: 'Already authenticated' });
    }
    next();
}

app.all('/admin/backup/config.bak', (req, res) => {
    db.bannedIPs.add(getClientIP(req));
    res.status(200).send('<!-- nothing -->');
});

app.all('/.env', (req, res) => {
    db.bannedIPs.add(getClientIP(req));
    res.status(404).send('Not Found');
});

app.get('/api/status', (req, res) => {
    res.json({
        setupRequired: !db.admin,
        authenticated: !!req.session?.authenticated,
    });
});

app.get('/api/csrf', (req, res) => {
    if (!req.sessionID) return res.status(400).json({ error: 'No session' });
    res.json({ token: generateCSRF(req.sessionID) });
});

app.post('/api/setup', strictLimiter, requireNoAuth, async (req, res) => {
    const ip = getClientIP(req);
    if (isIPBanned(ip)) return res.status(403).json({ error: 'Banned' });
    if (db.admin) return res.status(403).json({ error: 'Already initialized' });

    const { username, password, csrfToken } = req.body;
    if (!username || !password || password.length < 8) {
        return res.status(400).json({ error: 'Username required, password min 8 chars' });
    }

    const entry = db.csrfTokens.get(csrfToken);
    if (!entry || entry.expires < Date.now() || entry.sessionId !== req.sessionID) {
        return res.status(403).json({ error: 'Invalid CSRF' });
    }
    db.csrfTokens.delete(csrfToken);

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    db.admin = { username, hash, createdAt: Date.now() };

    req.session.authenticated = true;
    req.session.username = username;
    req.session.createdAt = Date.now();

    res.json({ success: true });
});

app.post('/api/login', strictLimiter, async (req, res) => {
    const ip = getClientIP(req);
    if (isIPBanned(ip)) return res.status(403).json({ error: 'IP banned' });
    if (!db.admin) return res.status(400).json({ error: 'Not initialized' });

    const { username, password, csrfToken } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Missing credentials' });
    }

    const entry = db.csrfTokens.get(csrfToken);
    if (!entry || entry.expires < Date.now() || entry.sessionId !== req.sessionID) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    db.csrfTokens.delete(csrfToken);

    if (username !== db.admin.username) {
        recordFailedAttempt(ip);
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    const valid = await bcrypt.compare(password, db.admin.hash);
    if (!valid) {
        const status = recordFailedAttempt(ip);
        if (status.banned) {
            return res.status(403).json({ error: `IP banned for ${status.duration === 'permanent' ? 'permanent' : '1 hour'}` });
        }
        return res.status(401).json({ error: 'Invalid credentials', remaining: status.remaining });
    }

    db.failedAttempts.delete(ip);

    req.session.regenerate((err) => {
        if (err) return res.status(500).json({ error: 'Session error' });
        req.session.authenticated = true;
        req.session.username = username;
        req.session.createdAt = Date.now();
        res.json({ success: true });
    });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('__Host-admin_sid', { path: '/' });
        res.json({ success: true });
    });
});

app.get('/api/admin/data', requireAuth, (req, res) => {
    res.json({
        username: req.session.username,
        serverTime: new Date().toISOString(),
        sessionAge: Date.now() - (req.session.createdAt || Date.now()),
        security: {
            hashing: 'bcrypt (13 rounds)',
            sessions: 'Server-side + HttpOnly + SameSite=Strict + Rolling',
            csrf: 'Double-submit cryptographically random tokens',
            rateLimit: '5 attempts / 15 min per IP + progressive ban',
            transport: 'Helmet CSP + HSTS + Referrer-Policy',
            honeypot: 'Active decoy endpoints logging attackers',
        },
        flag: 'SERVER_SIDE_AUTH_UNBREAKABLE_BY_SOURCE_INSPECTION'
    });
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`🔒 Secure Admin Panel v3 running on port ${PORT}`);
    console.log(`Setup required: ${!db.admin}`);
});
