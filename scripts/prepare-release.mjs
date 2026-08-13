#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { validateRuntime } from '../lib/runtime-contracts.mjs';
import { createSignedEnvelope, verifySignedEnvelope } from '../lib/release-envelope.mjs';
import { ensurePrivateDir, sha256File, walkRegularFiles, writeJson } from '../lib/fs.mjs';

const scriptFile = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(scriptFile), '..');
const REPO = 'VisualLogic-VLCode/ivx-v4-v5-knowledge';

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

function run(command, args, { cwd, allowFailure = false } = {}) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  if (result.status !== 0 && !allowFailure) throw new Error(`${command} ${args.join(' ')} failed: ${(result.stderr || result.stdout).trim()}`);
  return result;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function assertPrivateKey(file) {
  if (!fs.existsSync(file)) throw new Error(`Knowledge release private key is missing: ${file}`);
  const stat = fs.lstatSync(file);
  if (stat.isSymbolicLink() || !stat.isFile()) throw new Error('Knowledge release private key must be a regular non-symlink file');
  if (process.platform !== 'win32') {
    if ((stat.mode & 0o077) !== 0) throw new Error('Knowledge release private key must have mode 0600');
    if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) throw new Error('Knowledge release private key must be owned by the current user');
  }
}

function assertPublicKeyMatches(privateKeyPem, publicKeyPem) {
  const derived = crypto.createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' });
  const configured = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'pem' });
  if (!Buffer.from(derived).equals(Buffer.from(configured))) throw new Error('Committed Knowledge public key does not match the release private key');
}

function assertPublishedCommit(packageDir) {
  const status = run('git', ['status', '--porcelain'], { cwd: packageDir }).stdout.trim();
  if (status) throw new Error('Knowledge repository must be clean before release preparation');
  const commit = run('git', ['rev-parse', 'HEAD'], { cwd: packageDir }).stdout.trim();
  const remote = run('git', ['ls-remote', 'origin', 'refs/heads/main'], { cwd: packageDir }).stdout.trim().split(/\s+/)[0];
  if (!remote || remote !== commit) throw new Error('Knowledge HEAD must already be pushed to origin/main');
  return commit;
}

function stagePackage(packageDir, version, temporary) {
  const runtimeRoot = path.join(packageDir, 'runtime');
  const verified = validateRuntime(runtimeRoot);
  if (verified.manifest.version !== version) throw new Error('Runtime manifest version does not match package.json');
  const stage = path.join(temporary, 'package');
  fs.mkdirSync(stage, { recursive: true, mode: 0o700 });
  for (const relative of walkRegularFiles(runtimeRoot)) {
    const source = path.join(runtimeRoot, relative);
    const target = path.join(stage, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    fs.copyFileSync(source, target, fs.constants.COPYFILE_EXCL);
  }
  const runtimePackage = {
    name: '@visuallogic-vlcode/ivx-v4-v5-knowledge',
    version,
    description: 'Signed non-executable iVX V4-to-V5 Knowledge Runtime.',
    license: 'UNLICENSED',
    private: false,
    files: ['manifest.json', 'rules.jsonl', 'provenance.json', 'books', 'index', 'vocab'],
  };
  writeJson(path.join(stage, 'package.json'), runtimePackage);
  validateRuntime(stage);
  return { stage, verified };
}

function previousPayload(options, publicKeyPem) {
  if (!options['previous-manifest']) return null;
  const envelope = readJson(path.resolve(options['previous-manifest']));
  return verifySignedEnvelope(envelope, publicKeyPem);
}

export function prepareRelease(options = {}) {
  const packageDir = path.resolve(options.packageDir || repoRoot);
  const packageJson = readJson(path.join(packageDir, 'package.json'));
  const version = String(options.version || packageJson.version);
  if (version !== String(packageJson.version)) throw new Error(`Requested version ${version} does not match package.json ${packageJson.version}`);
  const repo = options.repo || REPO;
  const tag = options.tag || `v${version}`;
  const privateKeyFile = path.resolve(options.privateKey || options['private-key'] || path.join(os.homedir(), '.ivx-v4-v5-maintainer', 'keys', 'knowledge-release-private-key.pem'));
  const publicKeyFile = path.resolve(options.publicKey || options['public-key'] || path.join(packageDir, 'keys', 'knowledge-release-public-key.pem'));
  assertPrivateKey(privateKeyFile);
  if (!fs.existsSync(publicKeyFile) || fs.lstatSync(publicKeyFile).isSymbolicLink()) throw new Error('Committed Knowledge public key is missing or unsafe');
  const privateKeyPem = fs.readFileSync(privateKeyFile, 'utf8');
  const publicKeyPem = fs.readFileSync(publicKeyFile, 'utf8');
  assertPublicKeyMatches(privateKeyPem, publicKeyPem);
  const commit = assertPublishedCommit(packageDir);
  const outputDir = path.resolve(options.output || path.join(packageDir, 'release-out', `knowledge-${version}`));
  if (fs.existsSync(outputDir)) throw new Error(`Refusing to overwrite existing release output: ${outputDir}`);
  ensurePrivateDir(outputDir);
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ivx-knowledge-release-'));
  try {
    const { stage, verified } = stagePackage(packageDir, version, temporary);
    const packed = run(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['pack', '--json', '--pack-destination', temporary], { cwd: stage });
    const packedInfo = JSON.parse(packed.stdout)[0];
    const generated = path.join(temporary, packedInfo.filename);
    const assetName = `ivx-v4-v5-knowledge-${version}.tgz`;
    const artifactFile = path.join(outputDir, assetName);
    fs.copyFileSync(generated, artifactFile, fs.constants.COPYFILE_EXCL);
    fs.chmodSync(artifactFile, 0o600);
    const artifactSha256 = sha256File(artifactFile);
    const prior = previousPayload(options, publicKeyPem);
    if (prior?.kind !== undefined && prior.kind !== 'knowledge') throw new Error('Previous signed manifest is not a Knowledge channel');
    if (prior?.versions?.[version]) throw new Error(`Knowledge version ${version} is already present in the signed channel`);
    const manifest = verified.manifest;
    const payload = {
      schemaVersion: 1,
      kind: 'knowledge',
      channel: 'stable',
      latest: version,
      minimumSupported: options['minimum-supported'] || prior?.minimumSupported || version,
      revoked: options.revoked ? String(options.revoked).split(',').map((value) => value.trim()).filter(Boolean) : prior?.revoked || [],
      versions: {
        ...(prior?.versions || {}),
        [version]: {
          packageName: '@visuallogic-vlcode/ivx-v4-v5-knowledge',
          artifact: {
            url: `https://github.com/${repo}/releases/download/${tag}/${assetName}`,
            sha256: artifactSha256,
          },
          knowledgeSchemaVersion: manifest.knowledgeSchemaVersion,
          contentSha256: manifest.contentSha256,
          compatibleWorkflow: manifest.compatibility.workflow,
          compatibleConverter: manifest.compatibility.converter,
          compatibleAgentProtocol: manifest.compatibility.agentProtocol,
          capabilities: { diagnosis: true, staticValidation: true, automaticRepair: false },
        },
      },
    };
    const payloadFile = path.join(outputDir, 'knowledge-stable.payload.json');
    const envelopeFile = path.join(outputDir, 'knowledge-stable.json');
    writeJson(payloadFile, payload);
    writeJson(envelopeFile, createSignedEnvelope(payload, privateKeyPem));
    verifySignedEnvelope(readJson(envelopeFile), publicKeyPem);
    const plan = {
      schemaVersion: 1,
      kind: 'knowledge',
      version,
      repo,
      tag,
      title: `Knowledge Runtime ${version}`,
      source: { packageDir, commit, branch: 'main' },
      artifact: { file: artifactFile, name: assetName, sha256: artifactSha256, url: payload.versions[version].artifact.url },
      payload: { file: payloadFile, sha256: sha256File(payloadFile) },
      manifest: { file: envelopeFile, name: 'knowledge-stable.json', sha256: sha256File(envelopeFile), channelBranch: 'release-channel', channelPath: 'knowledge-stable.json' },
      publicKey: { file: publicKeyFile, sha256: sha256File(publicKeyFile) },
      runtime: { contentSha256: manifest.contentSha256, cardCount: verified.cards.length },
      publish: { draftFirst: true, verifyRemoteAssets: true, promoteChannelLast: true, requiredConfirmation: 'PUBLISH_STABLE_KNOWLEDGE' },
    };
    const planFile = path.join(outputDir, 'github-release-plan.json');
    writeJson(planFile, plan);
    return { ...plan, planFile };
  } catch (error) {
    fs.rmSync(outputDir, { recursive: true, force: true });
    throw error;
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === scriptFile;
if (invokedDirectly) {
  try {
    process.stdout.write(`${JSON.stringify(prepareRelease(parseArguments(process.argv.slice(2))), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ ok: false, message: error.message }, null, 2)}\n`);
    process.exitCode = 1;
  }
}
