#!/usr/bin/env node

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { verifySignedEnvelope } from '../lib/release-envelope.mjs';
import { sha256File } from '../lib/fs.mjs';

const scriptFile = fileURLToPath(import.meta.url);

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) throw new Error(`Unexpected argument: ${token}`);
    const key = token.slice(2);
    const next = argv[index + 1];
    if (next !== undefined && !next.startsWith('--')) {
      options[key] = next;
      index += 1;
    } else options[key] = true;
  }
  return options;
}

function run(command, args, { cwd, input, allowFailure = false } = {}) {
  const result = spawnSync(command, args, { cwd, input, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  if (result.status !== 0 && !allowFailure) throw new Error(`${command} ${args.join(' ')} failed: ${(result.stderr || result.stdout).trim()}`);
  return result;
}

function ghJson(args, options = {}) {
  const result = run('gh', args, options);
  return result.stdout.trim() ? JSON.parse(result.stdout) : null;
}

function apiJson(method, endpoint, body) {
  return ghJson(['api', '--method', method, endpoint, '--input', '-'], { input: JSON.stringify(body) });
}

function assertFileHash(file, expected, label) {
  if (!fs.existsSync(file) || fs.lstatSync(file).isSymbolicLink()) throw new Error(`${label} is missing or unsafe: ${file}`);
  if (sha256File(file) !== expected) throw new Error(`${label} SHA-256 changed after preparation`);
}

function rulesetProtects(ruleset, target, requiredRefs) {
  if (ruleset?.enforcement !== 'active' || ruleset.target !== target) return false;
  const includes = new Set(ruleset.conditions?.ref_name?.include || []);
  const rules = new Set((ruleset.rules || []).map((rule) => rule.type));
  return requiredRefs.every((ref) => includes.has(ref)) && rules.has('deletion') && rules.has('non_fast_forward') && (ruleset.bypass_actors || []).length === 0;
}

export function validateRepositoryReleaseHardening({ immutableReleases, rulesets }) {
  if (immutableReleases?.enabled !== true) throw new Error('GitHub immutable Releases must be enabled before publication');
  if (!rulesets.some((ruleset) => rulesetProtects(ruleset, 'branch', ['refs/heads/main', 'refs/heads/release-channel']))) {
    throw new Error('Active branch rules must protect main and release-channel from deletion and non-fast-forward updates without bypass actors');
  }
  if (!rulesets.some((ruleset) => rulesetProtects(ruleset, 'tag', ['refs/tags/v*']))) {
    throw new Error('Active tag rules must protect v* from deletion and non-fast-forward updates without bypass actors');
  }
}

function assertHardening(repo) {
  const immutableReleases = ghJson(['api', `repos/${repo}/immutable-releases`]);
  const summaries = ghJson(['api', `repos/${repo}/rulesets`]) || [];
  const rulesets = summaries.map((entry) => ghJson(['api', `repos/${repo}/rulesets/${entry.id}`]));
  validateRepositoryReleaseHardening({ immutableReleases, rulesets });
}

function createChannelBranch(repo, branch, channelPath, bytes, message) {
  const blob = apiJson('POST', `repos/${repo}/git/blobs`, { content: bytes.toString('base64'), encoding: 'base64' });
  const tree = apiJson('POST', `repos/${repo}/git/trees`, { tree: [{ path: channelPath, mode: '100644', type: 'blob', sha: blob.sha }] });
  const commit = apiJson('POST', `repos/${repo}/git/commits`, { message, tree: tree.sha, parents: [] });
  apiJson('POST', `repos/${repo}/git/refs`, { ref: `refs/heads/${branch}`, sha: commit.sha });
  return commit.sha;
}

function updateChannelBranch(repo, branch, channelPath, bytes, message) {
  const existing = run('gh', ['api', `repos/${repo}/contents/${channelPath}?ref=${encodeURIComponent(branch)}`], { allowFailure: true });
  const body = { message, content: bytes.toString('base64'), branch };
  if (existing.status === 0) body.sha = JSON.parse(existing.stdout).sha;
  return apiJson('PUT', `repos/${repo}/contents/${channelPath}`, body).commit.sha;
}

function assertRemoteAssets(plan) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ivx-knowledge-assets-'));
  try {
    for (const asset of [plan.artifact, plan.manifest]) {
      run('gh', ['release', 'download', plan.tag, '--repo', plan.repo, '--dir', temporary, '--pattern', asset.name, '--clobber']);
      if (sha256File(path.join(temporary, asset.name)) !== asset.sha256) throw new Error(`Remote Release asset differs from prepared bytes: ${asset.name}`);
    }
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

function assertRemoteChannel(plan) {
  const result = ghJson(['api', `repos/${plan.repo}/contents/${plan.manifest.channelPath}?ref=${encodeURIComponent(plan.manifest.channelBranch)}`]);
  const remote = Buffer.from(String(result.content || '').replace(/\s/g, ''), 'base64');
  const local = fs.readFileSync(plan.manifest.file);
  if (!remote.equals(local)) throw new Error('Remote stable channel differs from signed manifest bytes');
}

export async function publishRelease(options = {}) {
  if (!options.plan) throw new Error('--plan is required');
  const plan = JSON.parse(fs.readFileSync(path.resolve(options.plan), 'utf8'));
  if (options.confirm !== plan.publish?.requiredConfirmation) throw new Error(`Publication requires --confirm ${plan.publish?.requiredConfirmation || 'PUBLISH_STABLE_KNOWLEDGE'}`);
  if (plan.kind !== 'knowledge') throw new Error('Release plan is not a Knowledge publication');
  assertFileHash(plan.artifact.file, plan.artifact.sha256, 'Artifact');
  assertFileHash(plan.payload.file, plan.payload.sha256, 'Payload');
  assertFileHash(plan.manifest.file, plan.manifest.sha256, 'Signed manifest');
  assertFileHash(plan.publicKey.file, plan.publicKey.sha256, 'Public key');
  const payload = verifySignedEnvelope(JSON.parse(fs.readFileSync(plan.manifest.file, 'utf8')), fs.readFileSync(plan.publicKey.file, 'utf8'));
  if (payload.latest !== plan.version || payload.versions[plan.version]?.artifact?.sha256 !== plan.artifact.sha256) throw new Error('Signed manifest does not match the release plan');
  const packageDir = path.resolve(plan.source.packageDir);
  if (run('git', ['status', '--porcelain'], { cwd: packageDir }).stdout.trim()) throw new Error('Knowledge repository must be clean before publication');
  const head = run('git', ['rev-parse', 'HEAD'], { cwd: packageDir }).stdout.trim();
  if (head !== plan.source.commit) throw new Error('Source commit differs from the prepared release plan');
  const remote = run('git', ['ls-remote', 'origin', 'refs/heads/main'], { cwd: packageDir }).stdout.trim().split(/\s+/)[0];
  if (remote !== head) throw new Error('Knowledge HEAD is no longer the origin/main commit');
  const repository = ghJson(['repo', 'view', plan.repo, '--json', 'visibility,url']);
  if (repository.visibility !== 'PUBLIC') throw new Error(`GitHub repository must be public before publication: ${plan.repo}`);
  run('gh', ['api', `repos/${plan.repo}/commits/${head}`]);
  assertHardening(plan.repo);
  if (run('gh', ['release', 'view', plan.tag, '--repo', plan.repo], { allowFailure: true }).status === 0) throw new Error(`GitHub Release already exists: ${plan.repo} ${plan.tag}`);
  run('gh', ['release', 'create', plan.tag, plan.artifact.file, plan.manifest.file, '--repo', plan.repo, '--target', head, '--title', plan.title, '--notes', `Signed Knowledge Runtime ${plan.version}.`, '--draft']);
  const draft = ghJson(['release', 'view', plan.tag, '--repo', plan.repo, '--json', 'isDraft,assets']);
  const names = new Set((draft.assets || []).map((asset) => asset.name));
  if (!draft.isDraft || !names.has(plan.artifact.name) || !names.has(plan.manifest.name)) throw new Error('Draft Release verification failed; it was left unpublished for review');
  assertRemoteAssets(plan);
  run('gh', ['release', 'edit', plan.tag, '--repo', plan.repo, '--draft=false', '--latest']);
  assertRemoteAssets(plan);
  const branch = plan.manifest.channelBranch;
  const ref = run('gh', ['api', `repos/${plan.repo}/git/ref/heads/${branch}`], { allowFailure: true });
  const bytes = fs.readFileSync(plan.manifest.file);
  const message = `release: promote knowledge ${plan.version}`;
  const channelCommit = ref.status === 0
    ? updateChannelBranch(plan.repo, branch, plan.manifest.channelPath, bytes, message)
    : createChannelBranch(plan.repo, branch, plan.manifest.channelPath, bytes, message);
  assertRemoteChannel(plan);
  return { published: true, repo: plan.repo, tag: plan.tag, releaseUrl: `https://github.com/${plan.repo}/releases/tag/${plan.tag}`, channel: { branch, path: plan.manifest.channelPath, commit: channelCommit } };
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === scriptFile;
if (invokedDirectly) {
  try {
    process.stdout.write(`${JSON.stringify(await publishRelease(parseArguments(process.argv.slice(2))), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ ok: false, message: error.message }, null, 2)}\n`);
    process.exitCode = 1;
  }
}
