#!/usr/bin/env node

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateRuntime } from '../lib/runtime-contracts.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'runtime');
const result = validateRuntime(root);
process.stdout.write(`${JSON.stringify({ ok: true, version: result.manifest.version, contentSha256: result.manifest.contentSha256, cardCount: result.cards.length }, null, 2)}\n`);
