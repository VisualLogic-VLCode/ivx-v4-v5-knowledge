#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ensurePrivateDir, writePrivateFile } from '../lib/fs.mjs';

const scriptFile = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(scriptFile), '..');

export function generateReleaseKey({ privateKeyFile, publicKeyFile } = {}) {
  const privateFile = path.resolve(privateKeyFile || path.join(os.homedir(), '.ivx-v4-v5-maintainer', 'keys', 'knowledge-release-private-key.pem'));
  const publicFile = path.resolve(publicKeyFile || path.join(repoRoot, 'keys', 'knowledge-release-public-key.pem'));
  if (fs.existsSync(privateFile) || fs.existsSync(publicFile)) throw new Error('Refusing to overwrite an existing Knowledge release key');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  ensurePrivateDir(path.dirname(privateFile));
  writePrivateFile(privateFile, privateKey.export({ type: 'pkcs8', format: 'pem' }), { exclusive: true });
  fs.mkdirSync(path.dirname(publicFile), { recursive: true });
  fs.writeFileSync(publicFile, publicKey.export({ type: 'spki', format: 'pem' }), { flag: 'wx', mode: 0o644 });
  return {
    privateKeyFile: privateFile,
    publicKeyFile: publicFile,
    publicKeyFingerprintSha256: crypto.createHash('sha256').update(fs.readFileSync(publicFile)).digest('hex'),
  };
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === scriptFile;
if (invokedDirectly) {
  try {
    process.stdout.write(`${JSON.stringify(generateReleaseKey(), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ ok: false, message: error.message }, null, 2)}\n`);
    process.exitCode = 1;
  }
}
