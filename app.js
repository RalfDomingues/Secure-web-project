// SECURE WEB PROJECT - TLS + File Encryption
require('dotenv').config();
const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const path = require('path');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const helmet = require('helmet'); // Protege por headers HTTP seguros
const rateLimit = require('express-rate-limit'); // Mitigação de brute-force por IP
const csurf = require('csurf'); // Proteção CSRF
const multer = require('multer'); // Uploads (com validações)
const { v4: uuidv4 } = require('uuid'); // Para nomes de arquivo únicos
const fs = require('fs');
const bcrypt = require('bcrypt'); // Hash de senhas
const { Pool } = require('pg');
const crypto = require('crypto');
const https = require('https');
const http = require('http');

// ------------------------------------------------------------------
// CONFIGURAÇÕES
// ------------------------------------------------------------------
const app = express();
const PORT = process.env.PORT || 3000; // HTTPS port
const INSECURE_PORT = process.env.INSECURE_PORT || 3001; // Porta de redirecionamento
const uploadDir = process.env.UPLOAD_DIR || 'D:\\secure-web-project\\uploads';
const novosUsuariosRoot = "D:\\secure-web-project\\novos usuários";
const SALT_ROUNDS = 12;

// Chave de criptografia: espera uma chave de 32 bytes codificada em Base64 na variável de ambiente FILE_ENC_KEY
// ex. export FILE_ENC_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")
const FILE_ENC_KEY_B64 = process.env.FILE_ENC_KEY;
if (!FILE_ENC_KEY_B64) {
    console.error('FATAL: FILE_ENC_KEY environment variable not set (base64 32 bytes).');

}
let FILE_ENC_KEY = null;
try {
    if (FILE_ENC_KEY_B64) FILE_ENC_KEY = Buffer.from(FILE_ENC_KEY_B64, 'base64');
    if (FILE_ENC_KEY && FILE_ENC_KEY.length !== 32) {
        console.error('FATAL: FILE_ENC_KEY must decode to 32 bytes (AES-256).');
        FILE_ENC_KEY = null;
    }
} catch (e) {
    FILE_ENC_KEY = null;
}

// TLS cert/key paths (PEM files)
const TLS_KEY_PATH = process.env.TLS_KEY_PATH || path.join(__dirname, 'certs', 'key.pem');
const TLS_CERT_PATH = process.env.TLS_CERT_PATH || path.join(__dirname, 'certs', 'cert.pem');

// DATABASE CONNECTION
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// ------------------------------------------------------------------
// Utility functions (segurança/neutralização)
// ------------------------------------------------------------------

// Impede Log injection: remove caracteres de controle (newlines, tabs, etc)
// Útil quando colocamos conteúdo de usuário em logs ou em audit logs.
// Sem isso um atacante poderia injetar linhas falsas no log.
function sanitizeForLog(s) {
    if (s == null) return s;
    return String(s).replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
}

// Essa função valida dados passados nela para não ter Cross site scripting
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

// Esta função evita PATH TRAVERSAL: resolve caminhos e garante que o caminho pedido esteja dentro do base.
// Use sempre ao servir arquivos a partir de um diretório controlado.
function safeJoin(base, filename) {
    const resolvedBase = path.resolve(base);
    const resolvedPath = path.resolve(path.join(resolvedBase, filename));
    if (!resolvedPath.startsWith(resolvedBase)) throw new Error('Invalid path');
    return resolvedPath;
}

// Garante existência de diretório com permissões restritas (700)
// No Windows, mode pode ser ignorado, mas mantemos para compatibilidade.
function mkdirSecureSync(dirPath) {
    if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
    } else {
        try { fs.chmodSync(dirPath, 0o700); } catch (e) { }
    }
}

// ------------------------------------------------------------------
// Auxiliares de criptografia (AES-256-GCM)
// Formato do arquivo no disco: [12 bytes IV][texto cifrado][16 bytes authTag]
// Isso evita alterações no esquema do banco de dados e mantém os metadados de criptografia dentro do arquivo.
// ------------------------------------------------------------------
function encryptBufferToFile(buf, destPath) {
    if (!FILE_ENC_KEY) throw new Error('Encryption key not configured (FILE_ENC_KEY)');
    const iv = crypto.randomBytes(12); // recomendado para GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', FILE_ENC_KEY, iv);
    const ciphertext = Buffer.concat([cipher.update(buf), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const out = Buffer.concat([iv, ciphertext, authTag]);

    fs.writeFileSync(destPath, out, { mode: 0o600 });
}

function decryptFileToBuffer(srcPath) {
    if (!FILE_ENC_KEY) throw new Error('Encryption key not configured (FILE_ENC_KEY)');
    const data = fs.readFileSync(srcPath);
    if (data.length < 12 + 16) throw new Error('Invalid encrypted file');
    const iv = data.slice(0, 12);
    const authTag = data.slice(data.length - 16);
    const ciphertext = data.slice(12, data.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', FILE_ENC_KEY, iv);
    decipher.setAuthTag(authTag);
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plain;
}


function getWindowsUserHomeIfExists(username) {
    // Força uso de drive do sistema: process.env.SystemDrive normalmente 'C:'
    const systemDrive = process.env.SystemDrive || 'C:';
    const candidate = path.join(systemDrive + path.sep, 'Users', username);
    if (fs.existsSync(candidate)) return path.resolve(candidate);
    return null;
}

// Detecta se há symlink (ou junction) em qualquer componente do caminho.
// Isso ajuda a mitigar escapes via links simbólicos.
function hasSymlinkInPathSync(targetPath, stopAt) {
    const parsed = path.parse(targetPath);
    let cur = parsed.root;
    const parts = targetPath.slice(parsed.root.length).split(path.sep).filter(Boolean);

    for (const part of parts) {
        cur = path.join(cur, part);
        try {
            const st = fs.lstatSync(cur);
            if (st.isSymbolicLink()) return true;

        } catch (e) { }
        if (stopAt) {
            try { if (fs.realpathSync(cur) === stopAt) break; } catch (e) { }
        }
    }
    return false;
}

// Garante que resolvedPath esteja dentro de allowedRoot
function isPathInside(allowedRoot, resolvedPath) {
    const realAllowed = path.resolve(allowedRoot);
    const realResolved = path.resolve(resolvedPath);
    const prefix = realAllowed.endsWith(path.sep) ? realAllowed : realAllowed + path.sep;
    return realResolved === realAllowed || realResolved.startsWith(prefix);
}

// Função principal: valida o caminho físico informado pelo cliente (servidor Windows)
// - Se existir C:\Users\<webUsername>\ => allowedRoot = esse diretório (usuário existe no SO).
// - Caso contrário => cria e usa: <projectRoot>\novos usuarios\<webUsername>\  (sandbox).
// - Verifica realpath, presença de symlinks, e certifica que o caminho final está dentro do allowedRoot.
function validateClientPhysicalPath(webUsername, clientPath) {
    if (typeof clientPath !== 'string' || clientPath.trim() === '') {
        throw new Error('Caminho inválido');
    }

    // 1) Determina allowedRoot 
    let allowedRoot = getWindowsUserHomeIfExists(webUsername);

    if (!allowedRoot) {
        // cria pasta no projeto para esse usuário (isolada)
        mkdirSecureSync(novosUsuariosRoot);
        allowedRoot = path.join(novosUsuariosRoot, webUsername);
        mkdirSecureSync(allowedRoot);
    }

    // 2) Normalize candidate.
    // Se o cliente forneceu caminho absoluto (ex: C:\Users\Ralf\Downloads\file.pdf),
    // aceitamos considerar esse caminho, mas só se ele estiver dentro do allowedRoot.
    // Se o cliente forneceu caminho relativo, consideramos relativo ao allowedRoot.
    let candidate = path.isAbsolute(clientPath)
        ? path.normalize(clientPath)
        : path.join(allowedRoot, clientPath);

    // 3) Tenta resolver realpath. Se não existir ainda
    let realCandidate;
    try {
        realCandidate = fs.realpathSync(candidate);
    } catch (e) {
        realCandidate = path.resolve(candidate);
    }

    // 4) Rejeita se houver symlink em qualquer componente do caminho (entre allowedRoot e target inclusive).
    let realAllowed;
    try { realAllowed = fs.realpathSync(allowedRoot); } catch (e) { realAllowed = path.resolve(allowedRoot); }

    if (hasSymlinkInPathSync(realCandidate, realAllowed)) {
        throw new Error('Caminho inválido: presença de link simbólico detectada');
    }

    // 5) Garante que o caminho final esteja dentro do allowedRoot
    if (!isPathInside(realAllowed, realCandidate)) {
        throw new Error('Acesso negado: caminho fora da raiz do usuário');
    }

    return realCandidate;
}

// ------------------------------------------------------------------
// Função que grava logs de auditoria na base.
// Note que event_metadata deve ser serializado/validado para evitar injeção e problemas com estrutura.
// ------------------------------------------------------------------
async function audit(userId, eventType, metadata, ip) {
    try {
        const safeMeta = metadata ? JSON.stringify(metadata) : null;
        await pool.query('INSERT INTO audit_logs (user_id, event_type, event_metadata, ip_addr) VALUES ($1,$2,$3,$4)', [userId || null, eventType, safeMeta, ip || null]);
    } catch (e) { console.error('Audit log error:', e.message); }
}

// ------------------------------------------------------------------
// AUTH FUNCTIONS
// ------------------------------------------------------------------

// Registra usuário com hash de senha seguro (bcrypt).
// HASH de senha mitiga o risco caso a base seja comprometida.
async function registerUser({ username, password }) {

    // Verifica se o nome de usuário já existe
    const existing = await pool.query('SELECT 1 FROM users WHERE username = $1', [username]);
    if (existing.rowCount > 0) { const error = new Error('Usuário já existe'); error.code = 'USER_EXISTS'; throw error; }
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await pool.query('INSERT INTO users (username, password_hash) VALUES ($1,$2) RETURNING id', [username, hash]);
    const userId = result.rows[0].id;

    //Cria diretório pessoal se não houver usuário local
    const existingHome = getWindowsUserHomeIfExists(username);
    if (!existingHome) { const userSandbox = path.join(novosUsuariosRoot, username); mkdirSecureSync(novosUsuariosRoot); mkdirSecureSync(userSandbox); }
    return userId;
}

// Proteção contra SQL Injection
// Todas as consultas ao banco utilizam parâmetros ($1, $2, ...), 
// evitando concatenação direta de strings fornecidas pelo usuário.
// Isso impede que um atacante injete comandos SQL maliciosos.
//
async function findUserByUsername(username) {
    const r = await pool.query('SELECT id, username, password_hash, locked_until FROM users WHERE username = $1', [username]);
    return r.rows[0];
}

// ------------------------------------------------------------------
// MIDDLEWARES / CONFIGS GLOBAIS
// ------------------------------------------------------------------

// EJS Config
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');

// Security & Body Parsers
app.use(helmet()); // Adiciona headers de segurança (X-Frame, X-XSS-Protection, etc.)
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use((req, res, next) => {
    // Garantir charset para evitar problemas com interpretações estranhas de input
    res.charset = 'utf-8';
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    next();
});

// Session
app.use(session({
    store: new pgSession({ pool, tableName: 'session', createTableIfMissing: true }),
    secret: process.env.SESSION_SECRET || 'dev_secret_change_this',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true, // impede acesso ao cookie via JavaScript (mitiga XSS -> roubo de cookie)
        secure: process.env.NODE_ENV === 'production', // cookie apenas via HTTPS em produção
        sameSite: 'lax', // ajuda contra CSRF em muitos casos
    }
}));

// CSRF Protection
const csrfProtection = csurf(); // middleware usado nas rotas que recebem formulários

// Rate Limit (login) - impede força bruta por IP
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Muitas tentativas de login. Tente novamente mais tarde.',
});

// File Upload Config
if (!fs.existsSync(uploadDir)) mkdirSecureSync(uploadDir);

// ------------------------------------------------------------------
// Configuração de storage dinâmica por usuário
// ------------------------------------------------------------------
const memStorage = multer.memoryStorage();
const upload = multer({
    storage: memStorage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => { file.originalname = Buffer.from(file.originalname, 'latin1').toString('utf8'); cb(null, true); }
});

// Auth guard
function requireAuth(req, res, next) { if (!req.session.userId) return res.redirect('/login'); next(); }

// ------------------------------------------------------------------
// ROUTES (kept structure, but upload & download now encrypt/decrypt)
// ------------------------------------------------------------------

// Home → Redirect to Login
app.get('/', (req, res) => res.redirect('/login'));

// --- REGISTER ---
// CSRF token aplicado na view (ver register view)
app.get('/register', csrfProtection, (req, res) => {
    res.render('register', { csrfToken: req.csrfToken(), error: null });
});

app.post('/register', csrfProtection, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).render('register', { csrfToken: req.csrfToken(), error: 'Usuário e senha obrigatórios' });
    if (username.length < 3) return res.status(400).render('register', { csrfToken: req.csrfToken(), error: 'Usuário deve ter no mínimo 3 caracteres' });
    if (password.length < 6) return res.status(400).render('register', { csrfToken: req.csrfToken(), error: 'Senha deve ter no mínimo 6 caracteres' });
    try {
        const existing = await pool.query('SELECT 1 FROM users WHERE username = $1', [username]);
        if (existing.rowCount > 0) return res.status(400).render('register', { csrfToken: req.csrfToken(), error: 'Usuário já existe. Escolha outro nome de usuário.' });
        const userId = await registerUser({ username, password });
        await audit(userId, 'user_registered', { username: sanitizeForLog(username) }, req.ip);
        res.redirect('/login');
    } catch (err) { console.error('Register error:', err); res.status(500).render('register', { csrfToken: req.csrfToken(), error: 'Erro no registro. Usuário já existe ou erro no servidor.' }); }
});
app.get('/login', csrfProtection, (req, res) => { res.render('login', { csrfToken: req.csrfToken(), error: null }); });
app.post('/login', loginLimiter, csrfProtection, async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await findUserByUsername(username);
        if (!user) { await audit(null, 'login_failed', { username: sanitizeForLog(username), reason: 'user_not_found' }, req.ip); return res.status(401).render('login', { csrfToken: req.csrfToken(), error: 'Credenciais inválidas' }); }
        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) { await audit(user.id, 'login_failed', { username: sanitizeForLog(username), reason: 'wrong_password' }, req.ip); return res.status(401).render('login', { csrfToken: req.csrfToken(), error: 'Credenciais inválidas' }); }
        req.session.userId = user.id; req.session.username = user.username;
        await audit(user.id, 'login_success', { username: sanitizeForLog(user.username) }, req.ip);
        writeLog(req.session.username, 'login_success', { ip: req.ip });
        res.redirect('/dashboard');
    } catch (err) { console.error('Login error:', err); res.status(500).render('login', { csrfToken: req.csrfToken(), error: 'Erro no login.' }); }
});

app.get('/dashboard', requireAuth, csrfProtection, async (req, res) => {
    try {
        const logsResult = await pool.query('SELECT id, event_type, event_metadata, ip_addr, created_at FROM audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50', [req.session.userId]);
        const filesResult = await pool.query('SELECT id, stored_filename, original_name, description, created_at FROM resources WHERE user_id = $1 ORDER BY created_at DESC', [req.session.userId]);
        res.render('dashboard', { logs: logsResult.rows, files: filesResult.rows, username: req.session.username, csrfToken: req.csrfToken() });
    } catch (e) { console.error('Dashboard error:', e); res.status(500).send('Erro ao buscar dados'); }
});

// --- FILE UPLOAD --- now encrypts before saving to D:\secure-web-project\uploads\<userId>\<uuid>.enc
app.post('/upload', requireAuth, upload.single('file'), csrfProtection, async (req, res) => {
    try {
        if (!req.file) return res.status(400).send('Nenhum arquivo enviado');
        if (!FILE_ENC_KEY) return res.status(500).send('Chave de criptografia não configurada no servidor.');

        const description = req.body.description || '';
        const userUploadDir = path.join(uploadDir, String(req.session.userId));
        mkdirSecureSync(uploadDir);
        mkdirSecureSync(userUploadDir);

        const originalName = Buffer.from(req.file.originalname || 'file', 'utf8').toString();
        const ext = path.extname(originalName) || '';
        const storedName = `${uuidv4()}${ext}.enc`; // mark encrypted files with .enc
        //const storedName = `${uuidv4()}.enc`; // caso queira remover a extensão original do arquivo

        const dest = path.join(userUploadDir, storedName);

        // Encrypt buffer and write atomically
        encryptBufferToFile(req.file.buffer, dest);

        const fileSize = req.file.size;
        await pool.query('INSERT INTO resources (user_id, stored_filename, original_name, description, size) VALUES ($1,$2,$3,$4,$5)', [req.session.userId, storedName, originalName, description || null, fileSize]);

        await audit(req.session.userId, 'file_upload', { filename: sanitizeForLog(originalName), size: fileSize }, req.ip);
        writeLog(req.session.username, 'file_upload', { file: originalName, size: fileSize });
        res.redirect('/dashboard');
    } catch (e) { console.error('Upload error:', e); res.status(500).send('Erro no upload: ' + (e.message || '')); }
});

// --- FILE DOWNLOAD (GET) --- decrypts file and serves buffer
app.get('/files/:id', requireAuth, async (req, res) => {
    try {
        const fileId = parseInt(req.params.id, 10);
        if (isNaN(fileId)) return res.status(400).send('ID inválido');
        const r = await pool.query('SELECT stored_filename, original_name FROM resources WHERE id = $1 AND user_id = $2', [fileId, req.session.userId]);
        if (!r.rowCount) return res.status(404).send('Arquivo não encontrado');
        const stored = r.rows[0].stored_filename;
        const filepath = safeJoin(path.join(uploadDir, String(req.session.userId)), stored);
        await audit(req.session.userId, 'file_download', { id: fileId }, req.ip);

        // Decrypt into memory (files limited to 5MB in upload)
        const plain = decryptFileToBuffer(filepath);
        res.setHeader('Content-Disposition', `attachment; filename="${r.rows[0].original_name || stored.replace('.enc', '')}"`);
        res.setHeader('Content-Type', 'application/octet-stream');
        res.send(plain);

        writeLog(req.session.username, 'file_download', { file: r.rows[0].original_name || stored, size: plain.length });
    } catch (e) { console.error('Download error:', e); res.status(500).send('Erro ao servir arquivo: ' + (e.message || '')); }
});

// --- DOWNLOAD SEGURO (POST + CSRF) ---
app.post('/files/download', requireAuth, csrfProtection, async (req, res) => {
    try {
        const fileId = parseInt(req.body.id, 10);
        if (isNaN(fileId)) return res.status(400).send('ID inválido');
        const r = await pool.query('SELECT stored_filename, original_name FROM resources WHERE id = $1 AND user_id = $2', [fileId, req.session.userId]);
        if (!r.rowCount) return res.status(404).send('Arquivo não encontrado');
        const filepath = safeJoin(path.join(uploadDir, String(req.session.userId)), r.rows[0].stored_filename);
        await audit(req.session.userId, 'file_download', { id: fileId }, req.ip);

        const plain = decryptFileToBuffer(filepath);
        writeLog(req.session.username, 'file_download', { file: r.rows[0].original_name || r.rows[0].stored_filename, size: plain.length });
        res.setHeader('Content-Disposition', `attachment; filename="${r.rows[0].original_name}"`);
        res.setHeader('Content-Type', 'application/octet-stream');
        res.send(plain);
    } catch (err) { console.error('Download error:', err); res.status(500).send('Erro ao servir arquivo: ' + (err.message || '')); }
});

// Rota para "abrir" (visualizar/baixar inline) um arquivo no filesystem do servidor,
// com validação rígida (apenas dentro de C:\Users\<username>\ ou dentro de novos usuarios\<username>\)

app.post('/import-by-path', requireAuth, csrfProtection, async (req, res) => {
    try {
        const clientPath = req.body.clientPath; const webUser = req.session.username; const description = req.body.description || '';
        const validated = validateClientPhysicalPath(webUser, clientPath);
        const stat = fs.statSync(validated); if (!stat.isFile()) return res.status(400).send('Caminho não é arquivo');

        const userUploadDir = path.join(uploadDir, String(req.session.userId)); mkdirSecureSync(uploadDir); mkdirSecureSync(userUploadDir);
        const ext = path.extname(validated) || ''; const storedName = `${uuidv4()}${ext}.enc`; const dest = path.join(userUploadDir, storedName);

        const buf = fs.readFileSync(validated);
        encryptBufferToFile(buf, dest);

        const fileSize = stat.size;
        await pool.query('INSERT INTO resources (user_id, stored_filename, original_name, description, size) VALUES ($1,$2,$3,$4,$5)', [req.session.userId, storedName, path.basename(validated), description || null, fileSize]);
        await audit(req.session.userId, 'import_by_path', { basename: path.basename(validated) }, req.ip);
        return res.redirect('/dashboard');
    } catch (err) { console.error('Erro import-by-path', err); res.status(400).send('Erro ao importar arquivo: ' + (err.message || '')); }
});

// open-by-path left unchanged (serves server filesystem files as-is)
app.post('/open-by-path', requireAuth, csrfProtection, async (req, res) => {
    try {
        const clientPath = req.body.clientPath; const webUser = req.session.username; const validated = validateClientPhysicalPath(webUser, clientPath);
        const stat = fs.statSync(validated); if (!stat.isFile()) return res.status(400).send('Caminho não é arquivo');
        await audit(req.session.userId, 'open_by_path', { basename: path.basename(validated) }, req.ip);
        res.setHeader('Content-Disposition', `inline; filename="${path.basename(validated)}"`);
        res.setHeader('Content-Type', 'application/octet-stream');
        const stream = fs.createReadStream(validated);
        stream.pipe(res);
    } catch (err) { console.warn('Tentativa de acesso inválido:', err.message); return res.status(400).send('Caminho inválido ou acesso negado'); }
});

// search, logout, error handlers, logs (kept as before)
app.get('/search', requireAuth, csrfProtection, async (req, res) => {
    try {
        const query = req.query.q || ''; let results = [];
        if (query.trim()) {
            results = await pool.query('SELECT id, original_name, description, created_at FROM resources WHERE user_id = $1 AND (original_name ILIKE $2 OR description ILIKE $2) ORDER BY created_at DESC', [req.session.userId, `%${query}%`]);
            await audit(req.session.userId, 'search', { query: sanitizeForLog(query) }, req.ip);
        }
        res.render('search', { query: sanitizeForDisplay(query), results: results.rows || [], csrfToken: req.csrfToken() });
    } catch (e) { console.error('Search error:', e); res.status(500).send('Erro na busca'); }
});
app.post('/logout', requireAuth, csrfProtection, async (req, res) => {
    const uid = req.session.userId; const uname = req.session.username;
    req.session.destroy(async err => { if (err) return res.status(500).send('Erro ao encerrar sessão'); await audit(uid, 'logout', { username: sanitizeForLog(uname) }, req.ip); res.clearCookie('connect.sid'); res.redirect('/login'); });
});
app.use((err, req, res, next) => { if (err && err.code === 'EBADCSRFTOKEN') { return res.status(403).send('Formulário inválido (CSRF detectado).'); } next(err); });

// Logging system (kept intact)
const LOGS_DIR = path.join(__dirname, 'logs'); mkdirSecureSync(LOGS_DIR);
const BLACKLIST_FILE = path.join(LOGS_DIR, 'blacklist.json'); const FLOOD_THRESHOLD = 30; const floodTracker = {};
function ensureBlacklist() { if (!fs.existsSync(BLACKLIST_FILE)) { fs.writeFileSync(BLACKLIST_FILE, JSON.stringify([]), { mode: 0o600 }); } }
function getBlacklist() { ensureBlacklist(); try { return JSON.parse(fs.readFileSync(BLACKLIST_FILE, 'utf8')); } catch { return []; } }
function addToBlacklist(username) { ensureBlacklist(); const list = getBlacklist(); if (!list.includes(username)) { list.push(username); fs.writeFileSync(BLACKLIST_FILE, JSON.stringify(list, null, 2)); } }
function isBlacklisted(username) { const list = getBlacklist(); return list.includes(username); }
function formatDate(d = new Date()) { const dd = String(d.getDate()).padStart(2, '0'); const mm = String(d.getMonth() + 1).padStart(2, '0'); const yyyy = d.getFullYear(); return `${dd}-${mm}-${yyyy}`; }
function cleanupOldLogs() { const files = fs.readdirSync(LOGS_DIR).filter(f => f.startsWith('log-') && f.endsWith('.txt')); const now = Date.now(); for (const file of files) { const match = file.match(/log-(\d{2})-(\d{2})-(\d{4})\.txt/); if (!match) continue; const [_, dd, mm, yyyy] = match; const fileDate = new Date(`${yyyy}-${mm}-${dd}T00:00:00`); const diffDays = (now - fileDate.getTime()) / (1000 * 60 * 60 * 24); if (diffDays > 7) { try { fs.unlinkSync(path.join(LOGS_DIR, file)); console.log(`[LOG CLEANUP] Removido: ${file}`); } catch (e) { console.warn(`[LOG CLEANUP] Falha ao remover ${file}:`, e.message); } } } }
function writeLog(username, eventType, details = {}) {
    try {
        mkdirSecureSync(LOGS_DIR); cleanupOldLogs(); const today = formatDate(); const baseFilename = isBlacklisted(username) ? `auditoria-${today}.txt` : `log-${today}.txt`; const logPath = path.join(LOGS_DIR, baseFilename); if (!fs.existsSync(logPath)) { fs.writeFileSync(logPath, '', { mode: 0o600 }); }
        if (username) {
            const now = Date.now(); if (!floodTracker[username]) floodTracker[username] = []; floodTracker[username].push(now); floodTracker[username] = floodTracker[username].filter(ts => now - ts < 60000);
            if (floodTracker[username].length > FLOOD_THRESHOLD && !isBlacklisted(username)) { console.warn(`[SECURITY] ${username} gerou muitos logs rapidamente — marcando como suspeito.`); addToBlacklist(username); const auditFile = path.join(LOGS_DIR, `auditoria-${today}.txt`); const auditMsg = `[${new Date().toISOString()}] USUÁRIO SUSPEITO: ${username} excedeu ${FLOOD_THRESHOLD} logs/min\n`; fs.appendFileSync(auditFile, auditMsg, { encoding: 'utf8' }); }
        }
        const entry = `[${new Date().toISOString()}] USER=${username || 'anon'} EVENT=${eventType} DETAILS=${JSON.stringify(details)}\n`;
        fs.appendFileSync(logPath, entry, { encoding: 'utf8' });
    } catch (err) { console.error('[LOG ERROR]', err); }
}

// ------------------------------------------------------------------
// START HTTPS and HTTP (redirect to HTTPS)
// ------------------------------------------------------------------
function startServers() {
    // Read cert/key
    let tlsOptions = null;
    try {
        const key = fs.readFileSync(TLS_KEY_PATH);
        const cert = fs.readFileSync(TLS_CERT_PATH);
        tlsOptions = { key, cert };
    } catch (e) {
        console.error('TLS cert/key not found or unreadable. Expected at:', TLS_KEY_PATH, TLS_CERT_PATH);
        console.error('You can generate self-signed certs for testing. See README for commands.');
    }

    if (!tlsOptions) {
        // Start ONLY HTTP with a warning (useful for development), but assignment requires HTTPS.
        http.createServer(app).listen(PORT, () => {
            console.warn(`⚠️  HTTPS not configured. Server running insecurely on http://localhost:${PORT} - for assignment you MUST configure TLS.`);
        });
        return;
    }

    // HTTPS server
    https.createServer(tlsOptions, app).listen(PORT, () => {
        console.log(`✅ HTTPS Server running on https://localhost:${PORT}`);
    });

    // HTTP redirect server
    const redirectApp = express();
    redirectApp.use((req, res) => {
        const host = req.headers.host ? req.headers.host.split(':')[0] : 'localhost';
        let redirectTo = `https://${host}:${PORT}${req.url}`;
        res.redirect(301, redirectTo);
    });
    http.createServer(redirectApp).listen(INSECURE_PORT, () => {
        console.log(`➡️  HTTP redirect server running on http://localhost:${INSECURE_PORT} -> https://localhost:${PORT}`);
    });
}

startServers();

// Note: keep exporting app for tests if needed
module.exports = app;
