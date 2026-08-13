#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { computeContentSha256, validateCard, validateRuntime } from '../lib/runtime-contracts.mjs';
import { ensurePrivateDir, sha256Buffer, sha256File, stableJson, walkRegularFiles, writePrivateFile, writeJson } from '../lib/fs.mjs';

const scriptFile = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(scriptFile), '..');
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const RULE_ID = /\bCVT-[A-Z]+-\d{3}\b/g;
const OBJECT_ID = /(?<![A-Za-z0-9])[bc](?=[a-z0-9]{0,23}\d)[a-z0-9]{18,24}(?![A-Za-z0-9])/gi;
const OBJECT_ID_FINDING = /(?<![A-Za-z0-9])[bc](?=[a-z0-9]{0,23}\d)[a-z0-9]{18,24}(?![A-Za-z0-9])/i;
const CASE_ID = /\b(?:nid|案例)\s*[:=：]?\s*(\d+)\b/gi;
const SCAN_ID = /\b(run_id|pattern|snippet)\s*[:=]\s*(\d+)\b/gi;
const PUBLIC_BOOK_ROOTS = new Set(['books', 'index', 'vocab']);

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (!value.startsWith('--')) throw new Error(`Unexpected argument: ${value}`);
    const key = value.slice(2);
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

function assertSource(source, config) {
  const resolved = fs.realpathSync(path.resolve(source));
  const root = run('git', ['rev-parse', '--show-toplevel'], { cwd: resolved }).stdout.trim();
  if (fs.realpathSync(root) !== resolved) throw new Error('--source must name the maintenance repository root');
  if (path.basename(resolved) !== config.sourceIdentity) throw new Error(`Unexpected maintenance source identity: ${path.basename(resolved)}`);
  return resolved;
}

function snapshotCommit(source, sourceRef, config, temporary) {
  const commit = run('git', ['rev-parse', '--verify', `${sourceRef}^{commit}`], { cwd: source }).stdout.trim();
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error('Source reference did not resolve to a full commit');
  const archive = path.join(temporary, 'source.tar');
  const snapshot = ensurePrivateDir(path.join(temporary, 'snapshot'));
  run('git', ['archive', '--format=tar', '--output', archive, commit], { cwd: source });
  run('tar', ['-xf', archive, '-C', snapshot]);
  for (const relative of config.requiredSourceFiles) {
    const target = path.join(snapshot, relative);
    if (!fs.existsSync(target) || fs.lstatSync(target).isSymbolicLink() || !fs.lstatSync(target).isFile()) throw new Error(`Required committed source file is missing or unsafe: ${relative}`);
  }
  return { commit, snapshot };
}

function sourceDirty(source) {
  return Boolean(run('git', ['status', '--porcelain'], { cwd: source }).stdout.trim());
}

function buildAndLint(snapshot) {
  const build = run('python3', ['scripts/build_book.py'], { cwd: snapshot });
  const lint = run('python3', ['scripts/book_lint.py'], { cwd: snapshot });
  return {
    buildSummary: build.stdout.trim().split(/\r?\n/).slice(-10),
    lintSummary: lint.stdout.trim().split(/\r?\n/).slice(-10),
  };
}

function mapping(values, prefix) {
  return new Map([...new Set(values)].sort().map((value, index) => [value.toLowerCase(), `<${prefix}-${String(index + 1).padStart(4, '0')}>`]));
}

function deidentifier(texts) {
  const objectIds = [];
  const caseIds = [];
  for (const text of texts) {
    objectIds.push(...(text.match(OBJECT_ID) || []));
    for (const match of text.matchAll(CASE_ID)) caseIds.push(match[1]);
  }
  const objectMap = mapping(objectIds, 'object-id');
  const caseMap = mapping(caseIds, 'case');
  return {
    apply(input) {
      let value = input.replace(OBJECT_ID, (match) => objectMap.get(match.toLowerCase()));
      value = value.replace(CASE_ID, (match, digits) => match.replace(digits, caseMap.get(digits.toLowerCase())));
      value = value.replace(SCAN_ID, (_match, label) => `${label}=<redacted-id>`);
      value = value.replace(/\[([^\]]+)\]\((?:\.\.\/)?notes\/[^)]+\)/g, '$1 (maintainer evidence omitted)');
      value = value.replace(/\[([^\]]+)\]\(\.\.\/(?:spec-4x|spec-5x|conversion-4x-to-5x)\/README\.md\)/g, '$1');
      return value;
    },
    counts: { caseIds: caseMap.size, objectIds: objectMap.size },
  };
}

function privacyFindings(relative, text) {
  const findings = [];
  const patterns = [
    ['ABSOLUTE_MAINTAINER_PATH', /(?:\/Users\/|\/home\/|[A-Za-z]:\\Users\\)/],
    ['PRIVATE_KEY', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
    ['BEARER_CREDENTIAL', /\bBearer\s+[A-Za-z0-9._~+\/-]{12,}/i],
    ['SECRET_ASSIGNMENT', /\b(?:access[_-]?token|refresh[_-]?token|authorization|cookie|password|passwd|secret|api[_-]?key|private[_-]?key)\b\s*[:=]\s*[^\s,;]{4,}/i],
    ['JWT', /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/],
    ['PRIVATE_NETWORK', /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/],
    ['NON_EXAMPLE_EMAIL', /\b[A-Z0-9._%+-]+@(?!example\.(?:com|cn|test)\b)[A-Z0-9.-]+\.[A-Z]{2,}\b/i],
    ['CASE_ID', /\b(?:nid|案例)\s*[:=：]?\s*\d+\b/i],
    ['SCAN_ID', /\b(?:run_id|pattern|snippet)\s*[:=]\s*\d+\b/i],
    ['OBJECT_ID', OBJECT_ID_FINDING],
  ];
  for (const [code, pattern] of patterns) if (pattern.test(text)) findings.push({ code, file: relative });
  return findings;
}

function plainMarkdown(value) {
  return value
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/[`*_>#|]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function nearestHeading(lines, index) {
  for (let cursor = index; cursor >= 0; cursor -= 1) {
    const match = /^(#{1,6})\s+(.+)$/.exec(lines[cursor]);
    if (match) return plainMarkdown(match[2]).slice(0, 256);
  }
  return 'V4 to V5 conversion rule';
}

function contextFor(lines, index) {
  let start = index;
  let end = index;
  while (start > 0 && lines[start - 1].trim() && !/^#{1,6}\s/.test(lines[start - 1])) start -= 1;
  while (end + 1 < lines.length && lines[end + 1].trim() && !/^#{1,6}\s/.test(lines[end + 1])) end += 1;
  return plainMarkdown(lines.slice(start, end + 1).join(' ')).slice(0, 3000);
}

function unique(values, limit = 100) {
  return [...new Set(values.filter(Boolean))].sort().slice(0, limit);
}

function extractJsonPaths(context) {
  const values = [];
  for (const match of context.matchAll(/`([^`]{1,160})`/g)) {
    const token = match[1];
    if (/^(?:\$?stage|server|case|props|binds|events|action)(?:\.[A-Za-z0-9_$@*-]+)+$/.test(token)) {
      values.push(`/${token.replace(/^\$/, '').replaceAll('.', '/')}`);
    }
  }
  return unique(values, 30);
}

function matchTerms(ruleId, context) {
  const domain = ruleId.split('-')[1];
  const nodeTypes = unique([...context.matchAll(/\b(?:data|obj|server|ih5)-[A-Za-z0-9_-]+\b/g)].map((match) => match[0]), 30);
  const astOps = unique([
    ...[...context.matchAll(/\bop\s*[:=]\s*['"]([A-Za-z0-9_$!=<>%+-]+)['"]/g)].map((match) => `op:${match[1]}`),
    ...[...context.matchAll(/\b(?:sysutil|sysop)\s+([A-Za-z0-9_$-]+)/g)].map((match) => match[0].replace(/\s+/, ':')),
  ], 30);
  const componentMethods = unique([
    ...[...context.matchAll(/\b(?:name|meth|val)\s*[:=]\s*['"]([A-Za-z_$][A-Za-z0-9_$-]{1,80})['"]/g)].map((match) => match[1]),
  ], 30);
  const diagnostics = unique([ruleId, ...[...context.matchAll(/\bKI-\d{1,3}\b/g)].map((match) => match[0])], 30);
  const runtimeErrors = unique([...context.matchAll(/\b(?:ParseError|ReferenceError|TypeError|SyntaxError|RangeError)\b/g)].map((match) => match[0]), 20);
  const mismatch = { TOP: 'top-level-shape', PROP: 'style-or-asset', VAL: 'value-shape', FC: 'formula-ast', EV: 'event-behavior' }[domain] || 'conversion-behavior';
  return {
    jsonPaths: extractJsonPaths(context),
    nodeTypes,
    astOps,
    componentMethods,
    diagnosticCodes: diagnostics,
    runtimeErrors,
    behaviorMismatches: [mismatch],
  };
}

function extractCards(conversionText) {
  const lines = conversionText.split(/\r?\n/);
  const occurrences = new Map();
  lines.forEach((line, index) => {
    for (const ruleId of line.match(RULE_ID) || []) {
      if (!occurrences.has(ruleId)) occurrences.set(ruleId, []);
      occurrences.get(ruleId).push(index);
    }
  });
  return [...occurrences.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([ruleId, indexes]) => {
    const index = indexes[0];
    const context = contextFor(lines, index);
    const evidenceText = indexes.map((line) => lines[line]).join(' ');
    const uncertain = /待(?:语料|回验|确证)|未证|疑似|边界|不可转换/.test(evidenceText + context);
    const confirmed = /已确证|实测|源码提取|在野实证/.test(evidenceText + context) && !uncertain;
    const status = confirmed ? 'CONFIRMED' : uncertain ? 'PENDING_RUNTIME' : 'ADVISORY_ONLY';
    const arrow = context.indexOf('→');
    const sourcePattern = arrow > 0
      ? context.slice(0, arrow).slice(-1800)
      : `Apply ${ruleId} when the V4 input matches the documented condition: ${context.slice(0, 1600)}`;
    const targetInvariant = arrow > 0
      ? context.slice(arrow + 1, arrow + 1801)
      : `The V5 result must preserve the documented ${ruleId} invariant: ${context.slice(0, 1600)}`;
    const exceptions = /警示|例外|禁止|边界|未证|不可/.test(context) ? [context.slice(0, 1800)] : [];
    return validateCard({
      schemaVersion: 1,
      ruleId,
      version: 1,
      topic: nearestHeading(lines, index),
      status,
      match: matchTerms(ruleId, context),
      sourcePattern,
      targetInvariant,
      exceptions,
      evidence: {
        level: confirmed ? 'HIGH' : status === 'PENDING_RUNTIME' ? 'LOW' : 'MEDIUM',
        types: confirmed ? ['PUBLIC_BOOK', 'REVIEWED_EVIDENCE'] : ['PUBLIC_BOOK'],
        provenanceIds: [`public:${ruleId}`],
      },
      permissions: {
        diagnosis: true,
        staticValidation: status === 'CONFIRMED',
        automaticRepair: false,
        humanConfirmationRequired: true,
      },
    });
  });
}

function semanticCard(card) {
  return {
    ruleId: card.ruleId,
    status: card.status,
    match: card.match,
    sourcePattern: card.sourcePattern,
    targetInvariant: card.targetInvariant,
    exceptions: card.exceptions,
    evidence: card.evidence,
    permissions: card.permissions,
  };
}

function readPreviousCards(runtimeRoot) {
  try {
    return validateRuntime(runtimeRoot).cards;
  } catch {
    return [];
  }
}

function semanticDiff(previousCards, nextCards, previousBookDigest, nextBookDigest) {
  const previous = new Map(previousCards.map((card) => [card.ruleId, card]));
  const next = new Map(nextCards.map((card) => [card.ruleId, card]));
  const added = [...next.keys()].filter((id) => !previous.has(id)).sort();
  const removed = [...previous.keys()].filter((id) => !next.has(id)).sort();
  const changed = [...next.keys()].filter((id) => previous.has(id) && JSON.stringify(semanticCard(previous.get(id))) !== JSON.stringify(semanticCard(next.get(id)))).sort();
  const statusChanged = changed.filter((id) => previous.get(id).status !== next.get(id).status);
  const suggestion = !previousCards.length || added.length || removed.length || changed.length
    ? 'MINOR'
    : previousBookDigest !== nextBookDigest ? 'PATCH' : 'NONE';
  return { added, removed, changed, statusChanged, suggestion };
}

function publicFileHashes(root) {
  return walkRegularFiles(root)
    .filter((relative) => relative !== 'manifest.json')
    .map((relative) => ({ path: relative, sha256: sha256File(path.join(root, relative)) }));
}

function createCandidate({ snapshot, config, version, sourceCommit, previousCards, previousBookDigest, targetRoot }) {
  const candidate = fs.mkdtempSync(path.join(targetRoot, '.runtime-candidate-'));
  try {
    const sourceBooks = config.publicBooks.map((entry) => fs.readFileSync(path.join(snapshot, entry.source), 'utf8'));
    const scrubber = deidentifier(sourceBooks);
    for (const [index, entry] of config.publicBooks.entries()) {
      const target = path.join(candidate, entry.target);
      writePrivateFile(target, scrubber.apply(sourceBooks[index]));
    }
    const conversionEntry = config.publicBooks.find((entry) => entry.source === config.ruleSource);
    if (!conversionEntry) throw new Error('ruleSource must be present in publicBooks');
    const conversionText = fs.readFileSync(path.join(candidate, conversionEntry.target), 'utf8');
    const cards = extractCards(conversionText);
    if (!cards.length) throw new Error('No stable CVT rule IDs were extracted');
    writePrivateFile(path.join(candidate, 'rules.jsonl'), `${cards.map((card) => JSON.stringify(card)).join('\n')}\n`);
    writePrivateFile(path.join(candidate, 'index', 'rules.json'), stableJson({
      schemaVersion: 1,
      rules: cards.map((card) => ({ ruleId: card.ruleId, topic: card.topic, status: card.status, match: card.match })),
    }));
    const domains = Object.fromEntries([...new Set(cards.map((card) => card.ruleId.split('-')[1]))].sort().map((domain) => [domain, cards.filter((card) => card.ruleId.split('-')[1] === domain).length]));
    writePrivateFile(path.join(candidate, 'vocab', 'rule-domains.json'), stableJson({ schemaVersion: 1, domains }));
    const provenance = {
      schemaVersion: 1,
      source: { identity: config.sourceIdentity, commit: sourceCommit, inputMode: 'GIT_COMMIT_ARCHIVE' },
      generator: { name: 'ivx-v4-v5-knowledge-sync', version: '1.0.0', allowlistVersion: config.allowlistVersion, privacyScannerVersion: config.privacyScannerVersion },
      deidentification: { policyVersion: '1.0.0', replacements: scrubber.counts },
      rules: Object.fromEntries(cards.map((card) => [card.ruleId, { publicBook: 'books/conversion.md', provenanceIds: card.evidence.provenanceIds }])),
    };
    writePrivateFile(path.join(candidate, 'provenance.json'), stableJson(provenance));
    const findings = [];
    for (const relative of walkRegularFiles(candidate)) {
      if (!PUBLIC_BOOK_ROOTS.has(relative.split('/')[0]) && !['rules.jsonl', 'provenance.json'].includes(relative)) throw new Error(`Generated file is outside the public runtime layout: ${relative}`);
      findings.push(...privacyFindings(relative, fs.readFileSync(path.join(candidate, relative), 'utf8')));
    }
    if (findings.length) throw new Error(`Privacy scan blocked the candidate: ${JSON.stringify(findings.slice(0, 20))}`);
    const files = publicFileHashes(candidate);
    const manifest = {
      schemaVersion: 1,
      kind: 'ivx-v4-v5-knowledge-runtime',
      version,
      knowledgeSchemaVersion: 1,
      contentSha256: computeContentSha256(files),
      compatibility: config.compatibility,
      files,
    };
    writeJson(path.join(candidate, 'manifest.json'), manifest);
    const verified = validateRuntime(candidate);
    const nextBookDigest = sha256Buffer(Buffer.from(config.publicBooks.map((entry) => sha256File(path.join(candidate, entry.target))).join('\n'), 'utf8'));
    return {
      candidate,
      verified,
      privacy: { scannerVersion: config.privacyScannerVersion, findings: [] },
      deidentification: scrubber.counts,
      semanticDiff: semanticDiff(previousCards, cards, previousBookDigest, nextBookDigest),
      bookDigest: nextBookDigest,
    };
  } catch (error) {
    fs.rmSync(candidate, { recursive: true, force: true });
    throw error;
  }
}

function replaceRuntime(candidate, targetRoot) {
  const runtime = path.join(targetRoot, 'runtime');
  const backup = path.join(targetRoot, `.runtime-backup-${crypto.randomBytes(6).toString('hex')}`);
  let movedOld = false;
  try {
    if (fs.existsSync(runtime)) {
      fs.renameSync(runtime, backup);
      movedOld = true;
    }
    fs.renameSync(candidate, runtime);
    if (movedOld) fs.rmSync(backup, { recursive: true, force: true });
  } catch (error) {
    if (!fs.existsSync(runtime) && movedOld && fs.existsSync(backup)) fs.renameSync(backup, runtime);
    throw error;
  }
}

function writeSyncReport(report, targetRoot) {
  const root = path.join(targetRoot, 'candidate-out', 'latest');
  fs.rmSync(root, { recursive: true, force: true });
  ensurePrivateDir(root);
  writeJson(path.join(root, 'sync-report.json'), report);
  const lines = [
    '# Knowledge sync report', '',
    `- Status: ${report.status}`,
    `- Source commit: ${report.sourceCommit}`,
    `- Dirty source ignored: ${report.dirtySourceIgnored}`,
    `- Runtime version: ${report.version}`,
    `- Content SHA-256: ${report.contentSha256}`,
    `- Cards: ${report.cardCount}`,
    `- Deidentified case IDs: ${report.deidentification.caseIds}`,
    `- Deidentified object IDs: ${report.deidentification.objectIds}`,
    `- Added rules: ${report.semanticDiff.added.length}`,
    `- Changed rules: ${report.semanticDiff.changed.length}`,
    `- Removed rules: ${report.semanticDiff.removed.length}`,
    `- SemVer suggestion: ${report.semanticDiff.suggestion}`,
    `- Privacy findings: ${report.privacy.findings.length}`,
    '',
  ];
  writePrivateFile(path.join(root, 'sync-report.md'), lines.join('\n'));
}

function cleanupStaleCandidates(targetRoot) {
  for (const entry of fs.readdirSync(targetRoot, { withFileTypes: true })) {
    if (entry.isDirectory() && entry.name.startsWith('.runtime-candidate-')) {
      fs.rmSync(path.join(targetRoot, entry.name), { recursive: true, force: true });
    }
  }
}

export function syncFromSource(options = {}) {
  if (!options.source) throw new Error('--source is required');
  const version = String(options.version || '');
  if (!SEMVER.test(version)) throw new Error('--version must be SemVer');
  const targetRoot = path.resolve(options.targetRoot || repoRoot);
  cleanupStaleCandidates(targetRoot);
  const config = readJson(path.join(targetRoot, 'config', 'public-export-allowlist.json'));
  const source = assertSource(options.source, config);
  const dirty = sourceDirty(source);
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ivx-knowledge-sync-'));
  const runtimeRoot = path.join(targetRoot, 'runtime');
  const previousCards = readPreviousCards(runtimeRoot);
  const previousBookDigest = fs.existsSync(runtimeRoot)
    ? sha256Buffer(Buffer.from(config.publicBooks.filter((entry) => fs.existsSync(path.join(runtimeRoot, entry.target))).map((entry) => sha256File(path.join(runtimeRoot, entry.target))).join('\n'), 'utf8'))
    : sha256Buffer(Buffer.alloc(0));
  let candidate = null;
  try {
    const snapshot = snapshotCommit(source, options['source-ref'] || 'HEAD', config, temporary);
    const checks = buildAndLint(snapshot.snapshot);
    const built = createCandidate({
      snapshot: snapshot.snapshot,
      config,
      version,
      sourceCommit: snapshot.commit,
      previousCards,
      previousBookDigest,
      targetRoot,
    });
    candidate = built.candidate;
    replaceRuntime(candidate, targetRoot);
    candidate = null;
    const report = {
      schemaVersion: 1,
      status: 'CANDIDATE_READY',
      sourceIdentity: config.sourceIdentity,
      sourceCommit: snapshot.commit,
      dirtySourceIgnored: dirty,
      notices: dirty ? ['DIRTY_SOURCE_IGNORED'] : [],
      version,
      contentSha256: built.verified.manifest.contentSha256,
      cardCount: built.verified.cards.length,
      compatibility: built.verified.manifest.compatibility,
      checks,
      deidentification: built.deidentification,
      privacy: built.privacy,
      semanticDiff: built.semanticDiff,
    };
    writeSyncReport(report, targetRoot);
    return report;
  } finally {
    if (candidate && fs.existsSync(candidate)) fs.rmSync(candidate, { recursive: true, force: true });
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === scriptFile;
if (invokedDirectly) {
  try {
    process.stdout.write(`${JSON.stringify(syncFromSource(parseArguments(process.argv.slice(2))), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ ok: false, message: error.message }, null, 2)}\n`);
    process.exitCode = 1;
  }
}
