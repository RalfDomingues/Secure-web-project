// auth.js
const bcrypt = require('bcrypt');
const pool = require('./db');
const SALT_ROUNDS = 12;

async function registerUser({ username, email, password }) {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    await pool.query('INSERT INTO users (username, email, password_hash) VALUES ($1,$2,$3)', [username, email || null, hash]);
}

async function findUserByUsername(username) {
    const r = await pool.query('SELECT id, username, password_hash, locked_until FROM users WHERE username = $1', [username]);
    return r.rows[0];
}

module.exports = { registerUser, findUserByUsername };
