import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { syncFromSource } from '../scripts/sync-from-source.mjs';
import { sha256File, walkRegularFiles } from '../lib/fs.mjs';

function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`${command} failed: ${result.stderr || result.stdout}`);
  return result.stdout.trim();
}

function write(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

function initSource(root) {
  const source = path.join(root, 'vx-json-evolution-claude');
  fs.mkdirSync(source);
  write(path.join(source, 'scripts', 'build_book.py'), 'print("fixture build ok")\n');
  write(path.join(source, 'scripts', 'book_lint.py'), 'print("fixture lint ok")\n');
  write(path.join(source, 'docs', 'book-dist', 'spec-4x.md'), '# V4\n\nnid: 987654321012345678 uses `$refs.I_bfixture12345678901[3]`.\n');
  write(path.join(source, 'docs', 'book-dist', 'spec-5x.md'), '# V5\n\nThe target is a non-executable JSON knowledge package.\n');
  write(path.join(source, 'docs', 'book-dist', 'conversion.md'), '# Conversion\n\n## Rule\n\nCVT-FC-001: nid 987654321012345678 and `cfixture98765432109` → preserve an AST invariant. 已确证。\n');
  run('git', ['init', '-b', 'main'], source);
  run('git', ['config', 'user.name', 'Knowledge Test'], source);
  run('git', ['config', 'user.email', 'knowledge@example.test'], source);
  run('git', ['add', '.'], source);
  run('git', ['commit', '-m', 'fixture source'], source);
  return source;
}

function initTarget(root) {
  const target = path.join(root, 'target');
  fs.mkdirSync(path.join(target, 'config'), { recursive: true });
  fs.copyFileSync(new URL('../config/public-export-allowlist.json', import.meta.url), path.join(target, 'config', 'public-export-allowlist.json'));
  return target;
}

function digestTree(root) {
  return walkRegularFiles(root).map((relative) => `${relative}:${sha256File(path.join(root, relative))}`).join('\n');
}

test('published compatibility metadata admits Agent protocol 9 without changing knowledge content', () => {
  const manifest = JSON.parse(fs.readFileSync(new URL('../runtime/manifest.json', import.meta.url), 'utf8'));
  const allowlist = JSON.parse(fs.readFileSync(new URL('../config/public-export-allowlist.json', import.meta.url), 'utf8'));
  assert.deepEqual(manifest.compatibility.agentProtocol, { min: 4, max: 9 });
  assert.deepEqual(allowlist.compatibility.agentProtocol, manifest.compatibility.agentProtocol);
  assert.equal(manifest.contentSha256, '43ef6f4a14eb17e1d831176ee498fece9ae6a5e00132531e5d3dda53d83502b5');
});

test('sync exports a deterministic deidentified commit snapshot and ignores dirty source data', () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ivx-knowledge-sync-test-'));
  try {
    const source = initSource(temporary);
    const target = initTarget(temporary);
    write(path.join(source, 'AGENTS.md'), 'access_token=must-never-be-exported\n');
    const first = syncFromSource({ source, version: '0.1.0', targetRoot: target });
    assert.equal(first.dirtySourceIgnored, true);
    assert.deepEqual(first.notices, ['DIRTY_SOURCE_IGNORED']);
    assert.equal(first.cardCount, 1);
    assert.equal(first.privacy.findings.length, 0);
    const exported = walkRegularFiles(path.join(target, 'runtime')).map((relative) => fs.readFileSync(path.join(target, 'runtime', relative), 'utf8')).join('\n');
    assert.doesNotMatch(exported, /987654321012345678|bfixture12345678901|cfixture98765432109|must-never-be-exported/);
    assert.match(exported, /<case-0001>|<object-id-/);
    const before = digestTree(path.join(target, 'runtime'));
    const second = syncFromSource({ source, version: '0.1.0', targetRoot: target });
    assert.equal(digestTree(path.join(target, 'runtime')), before);
    assert.equal(second.semanticDiff.suggestion, 'NONE');
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});

test('privacy failure preserves the prior runtime and cleans failed candidates', () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ivx-knowledge-privacy-test-'));
  try {
    const source = initSource(temporary);
    const target = initTarget(temporary);
    syncFromSource({ source, version: '0.1.0', targetRoot: target });
    const before = digestTree(path.join(target, 'runtime'));
    fs.appendFileSync(path.join(source, 'docs', 'book-dist', 'conversion.md'), '\nCVT-FC-002: private path /Users/test-maintainer/private.json → reject.\n');
    run('git', ['add', 'docs/book-dist/conversion.md'], source);
    run('git', ['commit', '-m', 'unsafe source'], source);
    assert.throws(() => syncFromSource({ source, version: '0.2.0', targetRoot: target }), /Privacy scan blocked/);
    assert.equal(digestTree(path.join(target, 'runtime')), before);
    assert.equal(fs.readdirSync(target).some((name) => name.startsWith('.runtime-candidate-')), false);
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});
