import fs from 'node:fs';
import path from 'node:path';
import { sha256Buffer, sha256File, walkRegularFiles } from './fs.mjs';

export const QUERY_FIELDS = Object.freeze(['jsonPaths', 'nodeTypes', 'astOps', 'componentMethods', 'diagnosticCodes', 'runtimeErrors', 'behaviorMismatches']);
const CARD_STATUSES = new Set(['CONFIRMED', 'PENDING_RUNTIME', 'ADVISORY_ONLY', 'EXECUTABLE_REPAIR']);
const HASH = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const SECRET_KEY = /^(?:token|accesstoken|refreshtoken|bearertoken|cookie|authorization|password|secret|clientsecret|secretkey|privatekey|certificatepassword|apikey|accesskey)$/i;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function object(value, label) {
  assert(value && typeof value === 'object' && !Array.isArray(value), `${label} must be an object`);
  return value;
}

function exactKeys(value, required, allowed, label) {
  object(value, label);
  for (const key of required) assert(Object.hasOwn(value, key), `${label}.${key} is required`);
  for (const key of Object.keys(value)) assert(allowed.includes(key), `${label}.${key} is not allowed`);
}

function string(value, label, max = 4096) {
  assert(typeof value === 'string' && value.trim() && value.length <= max, `${label} must be a non-empty bounded string`);
  return value;
}

function strings(value, label, maxItems = 100, maxLength = 1024) {
  assert(Array.isArray(value) && value.length <= maxItems, `${label} must be a bounded array`);
  value.forEach((entry, index) => string(entry, `${label}[${index}]`, maxLength));
  assert(new Set(value).size === value.length, `${label} contains duplicates`);
  return value;
}

function noSecretKeys(value, location = '$', seen = new Set()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return;
  seen.add(value);
  if (Array.isArray(value)) return value.forEach((entry, index) => noSecretKeys(entry, `${location}[${index}]`, seen));
  for (const [key, child] of Object.entries(value)) {
    assert(!SECRET_KEY.test(key.replace(/[^A-Za-z0-9]/g, '')), `${location}.${key} is a forbidden secret-bearing field`);
    noSecretKeys(child, `${location}.${key}`, seen);
  }
}

export function computeContentSha256(files) {
  return sha256Buffer(Buffer.from([...files].map((entry) => `${entry.path}\0${entry.sha256}\n`).sort().join(''), 'utf8'));
}

export function validateCard(card) {
  const keys = ['schemaVersion', 'ruleId', 'version', 'topic', 'status', 'match', 'sourcePattern', 'targetInvariant', 'exceptions', 'evidence', 'permissions'];
  exactKeys(card, keys, keys, 'card');
  assert(card.schemaVersion === 1 && ID.test(card.ruleId), 'Card identity is invalid');
  assert(Number.isSafeInteger(card.version) && card.version >= 1, 'Card version is invalid');
  string(card.topic, 'card.topic', 256);
  assert(CARD_STATUSES.has(card.status), 'Card status is invalid');
  exactKeys(card.match, QUERY_FIELDS, QUERY_FIELDS, 'card.match');
  for (const field of QUERY_FIELDS) strings(card.match[field], `card.match.${field}`, 100, 512);
  string(card.sourcePattern, 'card.sourcePattern');
  string(card.targetInvariant, 'card.targetInvariant');
  strings(card.exceptions, 'card.exceptions', 100, 2048);
  exactKeys(card.evidence, ['level', 'types', 'provenanceIds'], ['level', 'types', 'provenanceIds'], 'card.evidence');
  assert(['HIGH', 'MEDIUM', 'LOW'].includes(card.evidence.level), 'Evidence level is invalid');
  strings(card.evidence.types, 'card.evidence.types', 20, 128);
  strings(card.evidence.provenanceIds, 'card.evidence.provenanceIds', 100, 128);
  const permissionKeys = ['diagnosis', 'staticValidation', 'automaticRepair', 'humanConfirmationRequired'];
  exactKeys(card.permissions, permissionKeys, permissionKeys, 'card.permissions');
  permissionKeys.forEach((key) => assert(typeof card.permissions[key] === 'boolean', `Permission ${key} must be boolean`));
  if (card.permissions.automaticRepair) assert(card.status === 'EXECUTABLE_REPAIR' && card.permissions.humanConfirmationRequired, 'Executable repair cards must be explicitly confirmed');
  noSecretKeys(card);
  return card;
}

export function validateManifest(manifest) {
  const keys = ['schemaVersion', 'kind', 'version', 'knowledgeSchemaVersion', 'contentSha256', 'compatibility', 'files'];
  exactKeys(manifest, keys, keys, 'manifest');
  assert(manifest.schemaVersion === 1 && manifest.kind === 'ivx-v4-v5-knowledge-runtime', 'Manifest identity is invalid');
  assert(SEMVER.test(manifest.version) && manifest.knowledgeSchemaVersion === 1 && HASH.test(manifest.contentSha256), 'Manifest version or digest is invalid');
  exactKeys(manifest.compatibility, ['workflow', 'converter', 'agentProtocol'], ['workflow', 'converter', 'agentProtocol'], 'manifest.compatibility');
  string(manifest.compatibility.workflow, 'manifest.compatibility.workflow', 128);
  string(manifest.compatibility.converter, 'manifest.compatibility.converter', 128);
  exactKeys(manifest.compatibility.agentProtocol, ['min', 'max'], ['min', 'max'], 'manifest.compatibility.agentProtocol');
  assert(Number.isSafeInteger(manifest.compatibility.agentProtocol.min) && manifest.compatibility.agentProtocol.min >= 1, 'Agent protocol minimum is invalid');
  assert(Number.isSafeInteger(manifest.compatibility.agentProtocol.max) && manifest.compatibility.agentProtocol.max >= manifest.compatibility.agentProtocol.min, 'Agent protocol maximum is invalid');
  assert(Array.isArray(manifest.files) && manifest.files.length > 0 && manifest.files.length <= 10000, 'Manifest file list is invalid');
  const seen = new Set();
  for (const entry of manifest.files) {
    exactKeys(entry, ['path', 'sha256'], ['path', 'sha256'], 'manifest.files[]');
    assert(typeof entry.path === 'string' && !path.isAbsolute(entry.path) && !entry.path.includes('\\') && !entry.path.split('/').includes('..'), 'Manifest file path is unsafe');
    assert(!seen.has(entry.path) && HASH.test(entry.sha256), 'Manifest file entry is duplicate or invalid');
    seen.add(entry.path);
  }
  assert(seen.has('rules.jsonl') && seen.has('provenance.json'), 'Manifest must include rules.jsonl and provenance.json');
  assert(computeContentSha256(manifest.files) === manifest.contentSha256, 'Manifest contentSha256 is invalid');
  noSecretKeys(manifest);
  return manifest;
}

export function validateRuntime(root) {
  const packageFile = path.join(root, 'package.json');
  if (fs.existsSync(packageFile)) {
    const packageJson = JSON.parse(fs.readFileSync(packageFile, 'utf8'));
    for (const forbidden of ['scripts', 'bin', 'main', 'exports', 'dependencies', 'optionalDependencies', 'peerDependencies']) assert(!Object.hasOwn(packageJson, forbidden), `Runtime package must not declare ${forbidden}`);
  }
  const manifest = validateManifest(JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8')));
  const actual = walkRegularFiles(root).filter((value) => !['manifest.json', 'package.json', '.ivx-runtime.json'].includes(value));
  const declared = manifest.files.map((entry) => entry.path).sort();
  assert(JSON.stringify(actual) === JSON.stringify(declared), 'Runtime files differ from manifest');
  for (const entry of manifest.files) {
    assert(entry.path === 'rules.jsonl' || entry.path === 'provenance.json' || ['books/', 'index/', 'vocab/'].some((prefix) => entry.path.startsWith(prefix)), `Runtime path is outside public layout: ${entry.path}`);
    assert(sha256File(path.join(root, entry.path)) === entry.sha256, `Runtime file hash mismatch: ${entry.path}`);
  }
  const lines = fs.readFileSync(path.join(root, 'rules.jsonl'), 'utf8').split(/\r?\n/).filter(Boolean);
  assert(lines.length > 0 && lines.length <= 50000, 'rules.jsonl card count is invalid');
  const ids = new Set();
  const cards = lines.map((line) => {
    assert(Buffer.byteLength(line) <= 64 * 1024, 'Knowledge Card line exceeds 64 KiB');
    const card = validateCard(JSON.parse(line));
    assert(!ids.has(card.ruleId), `Duplicate ruleId: ${card.ruleId}`);
    ids.add(card.ruleId);
    return card;
  });
  object(JSON.parse(fs.readFileSync(path.join(root, 'provenance.json'), 'utf8')), 'provenance');
  return { manifest, cards };
}
