
// SECURE WEB PROJECT
require('dotenv').config();
const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const path = require('path');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csurf = require('csurf');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');


// CONFIGURAÇÕES
const app = express();
const PORT = process.env.PORT || 3000;
const uploadDir = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');
const SALT_ROUNDS = 12;


// DATABASE CONNECTION
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// UTILITY FUNCTIONS
// Impede Log injection, pois valida os logs do sistema, e remove caracteres de controle (newlines, tabs, etc)
function sanitizeForLog(s) {
    if (s == null) return s;
    return String(s).replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
}

function sanitizeForDisplay(s) {
    if (s == null) return '';
    // Remove tags HTML e caracteres perigosos
    return String(s)
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

// Essa função impede PATH traversal pois só permite upload de arquivos que o usuário possui
function safeJoin(base, filename) {
    const resolvedBase = path.resolve(base);
    const resolvedPath = path.resolve(path.join(resolvedBase, filename));
    if (!resolvedPath.startsWith(resolvedBase)) throw new Error('Invalid path');
    return resolvedPath;
}

async function audit(userId, eventType, metadata, ip) {
    try {
        const safeMeta = metadata ? JSON.stringify(metadata) : null;
        await pool.query(
            'INSERT INTO audit_logs (user_id, event_type, event_metadata, ip_addr) VALUES ($1,$2,$3,$4)',
            [userId || null, eventType, safeMeta, ip || null]
        );
    } catch (e) {
        console.error('Audit log error:', e.message);
    }
}


// AUTH FUNCTIONS
async function registerUser({ username, password }) {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    await pool.query(
        'INSERT INTO users (username, password_hash) VALUES ($1,$2)',
        [username, hash]
    );
}

async function findUserByUsername(username) {
    const r = await pool.query(
        'SELECT id, username, password_hash, locked_until FROM users WHERE username = $1',
        [username] // Parâmetros separados impedem SQL Injection
    );
    return r.rows[0];
}


// MIDDLEWARES
// EJS Config
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');

// Security & Body Parsers
app.use(helmet());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use((req, res, next) => {
    res.charset = 'utf-8';
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    next();
});

// Session Config
app.use(session({
    store: new pgSession({
        pool,
        tableName: 'session',
        createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET || 'dev_secret_change_this',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
    }
}));

// CSRF Protection
const csrfProtection = csurf();

// Rate Limit (login)
// Impede força bruta no login
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Muitas tentativas de login. Tente novamente mais tarde.',
});

// File Upload Config
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
    destination: uploadDir,
    filename: (req, file, cb) => {
        const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
        const ext = path.extname(originalName);
        cb(null, uuidv4() + ext);
    },
});

const upload = multer({ 
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
    fileFilter: (req, file, cb) => {
        file.originalname = Buffer.from(file.originalname, 'latin1').toString('utf8');
        cb(null, true);
    }
});

// Global Request Audit
app.use(async (req, res, next) => {
    try {
        await audit(
            req.session.userId || null,
            'request',
            { path: req.path, method: req.method },
            req.ip
        );
    } catch (e) { /* ignora */ }
    next();
});

// Auth Guard Middleware
function requireAuth(req, res, next) {
    if (!req.session.userId) return res.redirect('/login');
    next();
}


// ROUTES


// Home → Redirect to Login
app.get('/', (req, res) => res.redirect('/login'));

// --- REGISTER ---
app.get('/register', csrfProtection, (req, res) => {
    res.render('register', { csrfToken: req.csrfToken(), error: null });
});

app.post('/register', csrfProtection, async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).render('register', {
            csrfToken: req.csrfToken(),
            error: 'Usuário e senha obrigatórios'
        });
    }

    // Validação básica
    if (username.length < 3) {
        return res.status(400).render('register', {
            csrfToken: req.csrfToken(),
            error: 'Usuário deve ter no mínimo 3 caracteres'
        });
    }

    if (password.length < 6) {
        return res.status(400).render('register', {
            csrfToken: req.csrfToken(),
            error: 'Senha deve ter no mínimo 6 caracteres'
        });
    }

    try {
        await registerUser({ username, password });
        await audit(null, 'user_registered', { username: sanitizeForLog(username) }, req.ip);
        res.redirect('/login');
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).render('register', {
            csrfToken: req.csrfToken(),
            error: 'Erro no registro. Usuário já existe ou erro no servidor.'
        });
    }
});

// --- LOGIN ---
app.get('/login', csrfProtection, (req, res) => {
    res.render('login', { csrfToken: req.csrfToken(), error: null });
});

app.post('/login', loginLimiter, csrfProtection, async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await findUserByUsername(username);

        if (!user) {
            await audit(null, 'login_failed', { username: sanitizeForLog(username), reason: 'user_not_found' }, req.ip);
            return res.status(401).render('login', {
                csrfToken: req.csrfToken(),
                error: 'Credenciais inválidas'
            });
        }

        const ok = await bcrypt.compare(password, user.password_hash);

        if (!ok) {
            await audit(user.id, 'login_failed', { username: sanitizeForLog(username), reason: 'wrong_password' }, req.ip);
            return res.status(401).render('login', {
                csrfToken: req.csrfToken(),
                error: 'Credenciais inválidas'
            });
        }

        req.session.userId = user.id;
        req.session.username = user.username;
        await audit(user.id, 'login_success', null, req.ip);
        res.redirect('/dashboard');
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).render('login', {
            csrfToken: req.csrfToken(),
            error: 'Erro no login.'
        });
    }
});

// --- DASHBOARD ---
app.get('/dashboard', requireAuth, csrfProtection, async (req, res) => {
    try {
        // Buscar logs do usuário
        const logsResult = await pool.query(
            'SELECT id, event_type, event_metadata, ip_addr, created_at FROM audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50',
            [req.session.userId]
        );

        // Buscar arquivos do usuário
        const filesResult = await pool.query(
            'SELECT id, stored_filename, original_name, description, created_at FROM resources WHERE user_id = $1 ORDER BY created_at DESC',
            [req.session.userId]
        );

        res.render('dashboard', {
            logs: logsResult.rows,
            files: filesResult.rows,
            username: req.session.username,
            csrfToken: req.csrfToken()
        });
    } catch (e) {
        console.error('Dashboard error:', e);
        res.status(500).send('Erro ao buscar dados');
    }
});

// --- FILE UPLOAD ---
app.post('/upload', requireAuth, upload.single('file'), csrfProtection, async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).send('Nenhum arquivo enviado');
        }

        const description = req.body.description || '';

        // Sanitizar descrição para prevenir XSS
        const safeDescription = sanitizeForDisplay(description);

        await pool.query(
            'INSERT INTO resources (user_id, stored_filename, original_name, description) VALUES ($1,$2,$3,$4)',
            [req.session.userId, req.file.filename, req.file.originalname, safeDescription]
        );

        await audit(
            req.session.userId,
            'file_upload',
            { filename: sanitizeForLog(req.file.originalname), size: req.file.size },
            req.ip
        );

        res.redirect('/dashboard');
    } catch (e) {
        console.error('Upload error:', e);
        res.status(500).send('Erro no upload');
    }
});

// --- FILE DOWNLOAD ---
app.get('/files/:id', requireAuth, async (req, res) => {
    try {
        const fileId = parseInt(req.params.id, 10);

        if (isNaN(fileId)) {
            return res.status(400).send('ID inválido');
        }

        const r = await pool.query(
            'SELECT stored_filename, original_name FROM resources WHERE id = $1 AND user_id = $2',
            [fileId, req.session.userId]
        );

        if (!r.rowCount) {
            await audit(req.session.userId, 'file_access_denied', { id: fileId }, req.ip);
            return res.status(404).send('Arquivo não encontrado');
        }

        const stored = r.rows[0].stored_filename;
        const filepath = safeJoin(uploadDir, stored);

        await audit(req.session.userId, 'file_download', { id: fileId }, req.ip);
        res.download(filepath, r.rows[0].original_name || stored);
    } catch (e) {
        console.error('Download error:', e);
        res.status(500).send('Erro ao servir arquivo');
    }
});

// --- SEARCH (NOVO - permite testar SQL Injection) ---
app.get('/search', requireAuth, csrfProtection, async (req, res) => {
    try {
        const query = req.query.q || '';
        let results = [];

        if (query.trim()) {
            // Busca segura usando LIKE com parâmetros
            results = await pool.query(
                'SELECT id, original_name, description, created_at FROM resources WHERE user_id = $1 AND (original_name ILIKE $2 OR description ILIKE $2) ORDER BY created_at DESC',
                [req.session.userId, `%${query}%`]
            );

            await audit(req.session.userId, 'search', { query: sanitizeForLog(query) }, req.ip);
        }

        res.render('search', {
            query: sanitizeForDisplay(query),
            results: results.rows || [],
            csrfToken: req.csrfToken()
        });
    } catch (e) {
        console.error('Search error:', e);
        res.status(500).send('Erro na busca');
    }
});

// --- LOGOUT ---
app.post('/logout', requireAuth, csrfProtection, async (req, res) => {
    const uid = req.session.userId;
    req.session.destroy(async err => {
        if (err) return res.status(500).send('Erro ao encerrar sessão');
        await audit(uid, 'logout', null, req.ip);
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

// ERROR HANDLERS
app.use((err, req, res, next) => {
    if (err && err.code === 'EBADCSRFTOKEN') {
        return res.status(403).send('Formulário inválido (CSRF detectado).');
    }
    next(err);
});

// START SERVER
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
});
