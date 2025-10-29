// testdb.js
const { Pool } = require('pg');
require('dotenv').config();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

(async () => {
  try {
    const r = await pool.query('SELECT NOW()');
    console.log('Conexão OK:', r.rows[0]);
  } catch (err) {
    console.error('Erro ao conectar:', err);
  } finally {
    pool.end();
  }
})();
