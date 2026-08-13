import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { verifySignedEnvelope } from '../lib/release-envelope.mjs';
import { prepareRelease } from '../scripts/prepare-release.mjs';
import { publishRelease, validateRepositoryReleaseHardening } from '../scripts/publish-release.mjs';

function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`${command} failed: ${result.stderr || result.stdout}`);
  return result.stdout.trim();
}

const protectedRulesets = [
  {
    target: 'branch', enforcement: 'active',
    conditions: { ref_name: { include: ['refs/heads/main', 'refs/heads/release-channel'], exclude: [] } },
    rules: [{ type: 'deletion' }, { type: 'non_fast_forward' }], bypass_actors: [],
  },
  {
    target: 'tag', enforcement: 'active',
    conditions: { ref_name: { include: ['refs/tags/v*'], exclude: [] } },
    rules: [{ type: 'deletion' }, { type: 'non_fast_forward' }], bypass_actors: [],
  },
];

test('publication requires immutable Releases and protected branch/tag history', () => {
  assert.doesNotThrow(() => validateRepositoryReleaseHardening({ immutableReleases: { enabled: true }, rulesets: protectedRulesets }));
  assert.throws(() => validateRepositoryReleaseHardening({ immutableReleases: { enabled: false }, rulesets: protectedRulesets }), /immutable Releases/);
  assert.throws(() => validateRepositoryReleaseHardening({ immutableReleases: { enabled: true }, rulesets: protectedRulesets.map((value) => ({ ...value, bypass_actors: [{ id: 1 }] })) }), /without bypass actors/);
});

test('release preparation packages only signed non-executable runtime data from a pushed clean commit', async () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ivx-knowledge-release-test-'));
  try {
    const packageDir = path.join(temporary, 'knowledge');
    const origin = path.join(temporary, 'origin.git');
    const releaseVersion = JSON.parse(fs.readFileSync(new URL('../runtime/manifest.json', import.meta.url), 'utf8')).version;
    const output = path.join(packageDir, 'release-out', `knowledge-${releaseVersion}`);
    fs.mkdirSync(packageDir);
    fs.writeFileSync(path.join(packageDir, 'package.json'), JSON.stringify({ name: '@test/maintainer', version: releaseVersion, type: 'module', private: true }));
    fs.cpSync(new URL('../runtime', import.meta.url), path.join(packageDir, 'runtime'), { recursive: true });
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const privateKeyFile = path.join(temporary, 'private.pem');
    const publicKeyFile = path.join(packageDir, 'keys', 'knowledge-release-public-key.pem');
    fs.mkdirSync(path.dirname(publicKeyFile), { recursive: true });
    fs.writeFileSync(privateKeyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(publicKeyFile, publicKey.export({ type: 'spki', format: 'pem' }));
    run('git', ['init', '--bare', origin], temporary);
    run('git', ['init', '-b', 'main'], packageDir);
    run('git', ['config', 'user.name', 'Knowledge Test'], packageDir);
    run('git', ['config', 'user.email', 'knowledge@example.test'], packageDir);
    run('git', ['add', '.'], packageDir);
    run('git', ['commit', '-m', 'release fixture'], packageDir);
    run('git', ['remote', 'add', 'origin', origin], packageDir);
    run('git', ['push', '-u', 'origin', 'main'], packageDir);
    const prepared = prepareRelease({ packageDir, output, repo: 'test-owner/knowledge', privateKey: privateKeyFile, publicKey: publicKeyFile });
    assert.equal(prepared.runtime.cardCount, 84);
    assert.equal(fs.existsSync(prepared.artifact.file), true);
    const envelope = JSON.parse(fs.readFileSync(prepared.manifest.file, 'utf8'));
    const payload = verifySignedEnvelope(envelope, fs.readFileSync(publicKeyFile, 'utf8'));
    assert.equal(payload.latest, releaseVersion);
    assert.equal(payload.versions[releaseVersion].capabilities.automaticRepair, false);
    const listing = run('tar', ['-tzf', prepared.artifact.file], packageDir);
    assert.match(listing, /package\/rules\.jsonl/);
    assert.doesNotMatch(listing, /scripts\/|private|raw|candidate-out/);
    await assert.rejects(publishRelease({ plan: prepared.planFile }), /requires --confirm PUBLISH_STABLE_KNOWLEDGE/);
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});
