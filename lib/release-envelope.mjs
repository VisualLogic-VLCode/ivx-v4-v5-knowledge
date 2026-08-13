import crypto from 'node:crypto';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

export function validateReleasePayload(payload) {
  assert(payload?.schemaVersion === 1 && payload.kind === 'knowledge' && payload.channel === 'stable', 'Release payload identity is invalid');
  assert(typeof payload.latest === 'string' && payload.versions?.[payload.latest], 'Release latest descriptor is missing');
  assert(payload.minimumSupported === null || typeof payload.minimumSupported === 'string', 'minimumSupported is invalid');
  assert(Array.isArray(payload.revoked) && new Set(payload.revoked).size === payload.revoked.length, 'revoked is invalid');
  for (const [version, descriptor] of Object.entries(payload.versions)) {
    assert(descriptor && typeof descriptor === 'object' && !Array.isArray(descriptor), `Descriptor ${version} is invalid`);
    assert(typeof descriptor.packageName === 'string' && descriptor.packageName, `Descriptor ${version} packageName is required`);
    assert(/^https:\/\//.test(descriptor.artifact?.url || '') && /^[0-9a-f]{64}$/.test(descriptor.artifact?.sha256 || ''), `Descriptor ${version} artifact is invalid`);
    assert(descriptor.knowledgeSchemaVersion === 1 && /^[0-9a-f]{64}$/.test(descriptor.contentSha256 || ''), `Descriptor ${version} Knowledge metadata is invalid`);
    assert(typeof descriptor.compatibleWorkflow === 'string' && typeof descriptor.compatibleConverter === 'string', `Descriptor ${version} compatibility is invalid`);
    assert(Number.isSafeInteger(descriptor.compatibleAgentProtocol?.min) && Number.isSafeInteger(descriptor.compatibleAgentProtocol?.max) && descriptor.compatibleAgentProtocol.max >= descriptor.compatibleAgentProtocol.min, `Descriptor ${version} Agent protocol is invalid`);
  }
  return payload;
}

export function createSignedEnvelope(payload, privateKeyPem) {
  const payloadBytes = Buffer.from(JSON.stringify(validateReleasePayload(payload)), 'utf8');
  return {
    schemaVersion: 1,
    payload: payloadBytes.toString('base64'),
    signature: { algorithm: 'ed25519', value: crypto.sign(null, payloadBytes, privateKeyPem).toString('base64') },
  };
}

export function verifySignedEnvelope(envelope, publicKeyPem) {
  assert(envelope?.schemaVersion === 1 && envelope.signature?.algorithm === 'ed25519', 'Release envelope identity is invalid');
  const payloadBytes = Buffer.from(envelope.payload, 'base64');
  const signature = Buffer.from(envelope.signature.value, 'base64');
  assert(crypto.verify(null, payloadBytes, publicKeyPem, signature), 'Release signature is invalid');
  return validateReleasePayload(JSON.parse(payloadBytes.toString('utf8')));
}
