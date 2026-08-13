import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export function sha256Buffer(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function sha256File(file) {
  return sha256Buffer(fs.readFileSync(file));
}

export function ensurePrivateDir(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  return directory;
}

export function writePrivateFile(file, content, { exclusive = false } = {}) {
  ensurePrivateDir(path.dirname(file));
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(5).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(temporary, content, { mode: 0o600, flag: 'wx' });
    fs.chmodSync(temporary, 0o600);
    if (exclusive && fs.existsSync(file)) throw new Error(`Refusing to overwrite existing file: ${file}`);
    fs.renameSync(temporary, file);
    fs.chmodSync(file, 0o600);
  } finally {
    try { fs.unlinkSync(temporary); } catch {}
  }
}

export function writeJson(file, value, options) {
  writePrivateFile(file, `${JSON.stringify(value, null, 2)}\n`, options);
}

export function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
  return value;
}

export function stableJson(value) {
  return `${JSON.stringify(stableValue(value), null, 2)}\n`;
}

export function walkRegularFiles(root) {
  const output = [];
  function visit(directory, prefix = '') {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absolute = path.join(directory, entry.name);
      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink()) throw new Error(`Symbolic links are forbidden: ${relative}`);
      if (stat.isDirectory()) visit(absolute, relative);
      else if (stat.isFile()) output.push(relative);
      else throw new Error(`Unsupported filesystem entry: ${relative}`);
    }
  }
  visit(root);
  return output;
}
