// utils.js
const path = require('path');

function sanitizeForLog(s) {
  if (s == null) return s;
  return String(s).replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
}

function safeJoin(base, filename) {
  const resolvedBase = path.resolve(base);
  const resolvedPath = path.resolve(path.join(resolvedBase, filename));
  if (!resolvedPath.startsWith(resolvedBase)) throw new Error('Invalid path');
  return resolvedPath;
}

module.exports = { sanitizeForLog, safeJoin };
