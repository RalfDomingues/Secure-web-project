// app.js
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

const pool = require('./db'); // db.js
const { registerUser, findUserByUsername } = require('./auth'); // auth.js
const { sanitizeForLog, safeJoin } = require('./utils'); // utils.js

const app = express();
const PORT = process.env.PORT || 3000;
const uploadDir = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');

// ===== EJS CONFIG =====
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');

// ===== SECURITY MIDDLEWARES =====
app.use(helmet());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ===== SESSION CONFIG =====
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

// ===== CSRF PROTECTION =====
// aplicaremos CSRF por rota específica
const csrfProtection = csurf();

// ===== RATE LIMIT (login) =====
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Muitas tentativas de login. Tente novamente mais tarde.',
});

// ===== FILE UPLOAD CONFIG =====
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
    destination: uploadDir,
    filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// ===== AUDIT LOG FUNCTION =====
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

// ===== GLOBAL REQUEST AUDIT =====
app.use(async (req, res, next) => {
    try {
        await audit(req.session.userId || null, 'request', { path: req.path, method: req.method }, req.ip);
    } catch (e) { /* ignora */ }
    next();
});

// ===== ROUTES =====
app.get('/', (req, res) => res.redirect('/login'));

// --- REGISTER ---
app.get('/register', csrfProtection, (req, res) => {
    res.render('register', { csrfToken: req.csrfToken(), error: null });
});

app.post('/register', csrfProtection, async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !password) {
        return res.status(400).render('register', { csrfToken: req.csrfToken(), error: 'Usuário e senha obrigatórios' });
    }
    try {
        await registerUser({ username, email, password });
        await audit(null, 'user_registered', { username }, req.ip);
        res.redirect('/login');
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).render('register', { csrfToken: req.csrfToken(), error: 'Erro no registro. Verifique o console.' });
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
            await audit(null, 'login_failed', { username }, req.ip);
            return res.status(401).render('login', { csrfToken: req.csrfToken(), error: 'Credenciais inválidas' });
        }

        const bcrypt = require('bcrypt');
        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) {
            await audit(user.id, 'login_failed', { username }, req.ip);
            return res.status(401).render('login', { csrfToken: req.csrfToken(), error: 'Credenciais inválidas' });
        }

        req.session.userId = user.id;
        await audit(user.id, 'login_success', null, req.ip);
        res.redirect('/dashboard');
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).render('login', { csrfToken: req.csrfToken(), error: 'Erro no login.' });
    }
});

// --- AUTH GUARD ---
function requireAuth(req, res, next) {
    if (!req.session.userId) return res.redirect('/login');
    next();
}

// --- DASHBOARD ---
app.get('/dashboard', requireAuth, csrfProtection, async (req, res) => {
    try {
        const r = await pool.query(
            'SELECT id, event_type, event_metadata, ip_addr, created_at FROM audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50',
            [req.session.userId]
        );
        res.render('dashboard', { logs: r.rows, csrfToken: req.csrfToken() });
    } catch (e) {
        console.error('Dashboard error:', e);
        res.status(500).send('Erro ao buscar logs');
    }
});

// --- FILE UPLOAD ---
// aqui aplicamos multer primeiro, depois CSRF
app.post('/upload', requireAuth, upload.single('file'), csrfProtection, async (req, res) => {
    try {
        await pool.query(
            'INSERT INTO resources (user_id, stored_filename, original_name) VALUES ($1,$2,$3)',
            [req.session.userId, req.file.filename, req.file.originalname]
        );
        await audit(req.session.userId, 'file_upload', { filename: req.file.originalname }, req.ip);
        res.redirect('/dashboard');
    } catch (e) {
        console.error('Upload error:', e);
        res.status(500).send('Erro no upload');
    }
});

// --- FILE DOWNLOAD ---
app.get('/files/:id', requireAuth, async (req, res) => {
    try {
        const r = await pool.query(
            'SELECT stored_filename, original_name FROM resources WHERE id = $1 AND user_id = $2',
            [req.params.id, req.session.userId]
        );
        if (!r.rowCount) return res.status(404).send('Arquivo não encontrado');

        const stored = r.rows[0].stored_filename;
        const filepath = safeJoin(uploadDir, stored);
        await audit(req.session.userId, 'file_download', { id: req.params.id }, req.ip);
        res.download(filepath, r.rows[0].original_name || stored);
    } catch (e) {
        console.error('Download error:', e);
        res.status(500).send('Erro ao servir arquivo');
    }
});

// --- LOGOUT ---
app.post('/logout', requireAuth, async (req, res) => {
    const uid = req.session.userId;
    req.session.destroy(async err => {
        if (err) return res.status(500).send('Erro ao encerrar sessão');
        await audit(uid, 'logout', null, req.ip);
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

// ===== CSRF ERROR HANDLER =====
app.use((err, req, res, next) => {
    if (err && err.code === 'EBADCSRFTOKEN') {
        return res.status(403).send('Formulário inválido (CSRF detectado).');
    }
    next(err);
});

// ===== START SERVER =====
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
