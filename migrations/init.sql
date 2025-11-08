-- migrations/init.sql

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'user',
  locked_until TIMESTAMP NULL,
  created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  event_type TEXT NOT NULL,
  event_metadata JSONB,
  ip_addr TEXT,
  created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS resources (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  stored_filename TEXT NOT NULL,
  original_name TEXT,
  description TEXT,
  created_at TIMESTAMP DEFAULT now(),
  size BIGINT
);

-- cria tabela usada pelo connect-pg-simple (resolução de erro session)
CREATE TABLE IF NOT EXISTS "session" (
  "sid" varchar NOT NULL COLLATE "default",
  "sess" json NOT NULL,
  "expire" timestamp(6) NOT NULL
)
WITH (OIDS=FALSE);

ALTER TABLE "session" ADD CONSTRAINT "session_pkey" PRIMARY KEY ("sid");

CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");

-- Índice para melhorar performance de consultas por usuário
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- Índice para melhorar performance
CREATE INDEX IF NOT EXISTS idx_resources_user_id ON resources(user_id);


-- libera uso de tabelas para funcionamento da página
GRANT USAGE, SELECT ON SEQUENCE audit_logs_id_seq TO secureweb_user;
GRANT UPDATE ON SEQUENCE audit_logs_id_seq TO secureweb_user;
GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO secureweb_user;
GRANT UPDATE ON SEQUENCE users_id_seq TO secureweb_user;
GRANT INSERT, SELECT, UPDATE ON resources TO secureweb_user;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE resources_id_seq TO secureweb_user;


