// app.js
require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csurf = require('csurf');
const multer = require('multer');
const uuid = require('uuid').v4;
const pool = require('./db'); // seu db.js
const { registerUser, findUserByUsername } = require('./auth'); // auth.js que vou fornecer
const { sanitizeForLog, safeJoin } = require('./utils'); // utils.js que vou fornecer
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const uploadDir = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');

// view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// middlewares
app.use(helmet());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// session store in Postgres
app.use(session({
    store: new pgSession({ pool }),
    secret: process.env.SESSION_SECRET || 'dev_secret_change_this',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
}));

// CSRF - after session
app.use(csurf());

// simple rate limiter for auth routes
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Muitas tentativas. Tente novamente mais tarde.'
});

// ensure upload directory exists
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// multer storage with uuid names
const storage = multer.diskStorage({
    destination: uploadDir,
    filename: (req, file, cb) => cb(null, uuid() + path.extname(file.originalname))
});
const upload = multer({ storage });

// small audit logger - writes a row to audit_logs
async function audit(userId, eventType, metadata, ip) {
    try {
        await pool.query(
            'INSERT INTO audit_logs (user_id, event_type, event_metadata, ip_addr) VALUES ($1,$2,$3,$4)',
            [userId || null, eventType, metadata ? JSON.stringify(metadata) : null, ip || null]
        );
    } catch (e) {
        console.error('Audit log error', e);
    }
}

// middleware to log requests (non-sensitive)
app.use(async (req, res, next) => {
    try {
        const meta = { path: req.path, method: req.method };
        await audit(req.session.userId || null, 'request', meta, req.ip);
    } catch (e) { /* ignore */ }
    next();
});

// ROUTES
app.get('/', (req, res) => res.redirect('/login'));

// register page
app.get('/register', (req, res) => {
    res.render('register', { csrfToken: req.csrfToken(), error: null });
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    // minimal server-side validation
    if (!username || !password) {
        return res.status(400).render('register', { csrfToken: req.csrfToken(), error: 'Usuário e senha obrigatórios' });
    }
    try {
        await registerUser({ username, email, password });
        await audit(null, 'user_registered', { username }, req.ip);
        res.redirect('/login');
    } catch (err) {
        console.error(err);
        res.status(500).render('register', { csrfToken: req.csrfToken(), error: 'Erro no registro (ver console)' });
    }
});

// login
app.get('/login', (req, res) => {
    res.render('login', { csrfToken: req.csrfToken(), error: null });
});

app.post('/login', loginLimiter, async (req, res) => {
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
        // success
        req.session.userId = user.id;
        await audit(user.id, 'login_success', null, req.ip);
        res.redirect('/dashboard');
    } catch (err) {
        console.error(err);
        res.status(500).render('login', { csrfToken: req.csrfToken(), error: 'Erro no login' });
    }
});

// require auth
function requireAuth(req, res, next) {
    if (!req.session.userId) return res.redirect('/login');
    next();
}

// dashboard - shows recent audit logs
app.get('/dashboard', requireAuth, async (req, res) => {
    try {
        const r = await pool.query('SELECT id, event_type, event_metadata, ip_addr, created_at FROM audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50', [req.session.userId]);
        res.render('dashboard', { logs: r.rows, csrfToken: req.csrfToken() });
    } catch (e) {
        console.error(e);
        res.status(500).send('Erro ao buscar logs');
    }
});

// upload endpoint
app.post('/upload', requireAuth, upload.single('file'), async (req, res) => {
    try {
        await pool.query('INSERT INTO resources (user_id, stored_filename, original_name) VALUES ($1,$2,$3)', [req.session.userId, req.file.filename, req.file.originalname]);
        await audit(req.session.userId, 'file_upload', { filename: req.file.originalname }, req.ip);
        res.redirect('/dashboard');
    } catch (e) {
        console.error(e);
        res.status(500).send('Erro no upload');
    }
});

// serve file by id (safe path)
app.get('/files/:id', requireAuth, async (req, res) => {
    try {
        const r = await pool.query('SELECT stored_filename, original_name FROM resources WHERE id = $1 AND user_id = $2', [req.params.id, req.session.userId]);
        if (!r.rowCount) return res.status(404).send('Arquivo não encontrado');
        const stored = r.rows[0].stored_filename;
        const filepath = safeJoin(uploadDir, stored);
        await audit(req.session.userId, 'file_download', { id: req.params.id }, req.ip);
        res.download(filepath, r.rows[0].original_name || stored);
    } catch (e) {
        console.error(e);
        res.status(500).send('Erro ao servir arquivo');
    }
});

// logout
app.post('/logout', requireAuth, (req, res) => {
    const uid = req.session.userId;
    req.session.destroy(err => {
        if (err) return res.status(500).send('Erro ao encerrar sessão');
        audit(uid, 'logout', null, null);
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

// error handler for CSRF token errors
app.use((err, req, res, next) => {
    if (err && err.code === 'EBADCSRFTOKEN') {
        return res.status(403).send('Formulário inválido (CSRF).');
    }
    next(err);
});

// start
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
