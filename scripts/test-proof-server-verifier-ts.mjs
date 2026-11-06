#!/usr/bin/env node
/** Run all six real TypeScript verifier phases and generate a proof. */
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

const { values } = parseArgs({ options: {
  'verifier-module': { type: 'string' },
  'application-id': { type: 'string' },
  'api-host': { type: 'string' },
  'attestation-host': { type: 'string' },
  'warden-url': { type: 'string', default: 'https://warden.wastedp.io' },
  'pointer-address': { type: 'string' },
  'indexer-url': { type: 'string', default: 'https://midnight-preprod.blockfrost.io/api/v0' },
  payload: { type: 'string' },
  output: { type: 'string' },
} });

let session;
const projectId = process.env.BLOCKFROST_PROJECT_ID;
const redact = text => projectId ? text.split(projectId).join('[redacted]') : text;
const log = value => console.log(redact(JSON.stringify(value)));

try {
  for (const name of ['verifier-module', 'application-id', 'api-host', 'attestation-host', 'pointer-address']) {
    assert.ok(values[name], `Missing --${name}`);
  }
  assert.match(values['application-id'], /^[a-fA-F0-9]{64}$/, 'Invalid application ID');
  assert.match(values['pointer-address'], /^[a-fA-F0-9]{64}$/, 'Invalid pointer address');

  const {
    AMD_ROOT_CERTIFICATES, AkxChannelBinder, AkxEvidenceProvider,
    AttestationVerifier, RealLedgerClient, RealLocalVerifier, RealWardenClient,
  } = await import(pathToFileURL(resolve(values['verifier-module'])).href);

  const config = {
    attestationHost: values['attestation-host'],
    proofServerApiUrl: `https://${values['api-host']}`,
    akxServerUrl: `https://${values['attestation-host']}/tee_attestation`,
    wardenUrl: values['warden-url'], applicationId: values['application-id'],
    pointerContractAddress: values['pointer-address'], indexerUrl: values['indexer-url'],
    amdRootCertificates: [...AMD_ROOT_CERTIFICATES],
    // The real Warden client uses normal platform HTTPS certificate validation.
    wardenTlsCertificate: '',
  };

  const indexerOrigin = new URL(config.indexerUrl).origin;
  const isBlockfrost = indexerOrigin === 'https://midnight-preprod.blockfrost.io';
  if (isBlockfrost) {
    assert.ok(projectId, 'Set BLOCKFROST_PROJECT_ID privately for the preprod Blockfrost indexer');
  }
  const indexerFetch = (url, init = {}) => {
    assert.equal(new URL(url).origin, indexerOrigin, 'Indexer request changed origin');
    const headers = new Headers(init.headers);
    if (isBlockfrost) headers.set('project_id', projectId);
    return fetch(url, { ...init, headers, redirect: 'error', signal: AbortSignal.timeout(60_000) });
  };

  const verifier = new AttestationVerifier({
    evidenceProvider: AkxEvidenceProvider.fromConfig(config),
    ledgerClient: RealLedgerClient.fromConfig(config, { fetchImpl: indexerFetch }),
    localVerifier: new RealLocalVerifier(),
    wardenClient: RealWardenClient.fromConfig(config),
    channelBinder: AkxChannelBinder.fromConfig(config),
  }, config);

  session = await verifier.establishVerifiedSession(event => {
    log(event.status === 'check'
      ? { phase: event.phase, check: event.check.id, status: event.check.status, detail: event.check.detail }
      : { phase: event.phase, status: event.status, detail: event.detail, error: event.error?.message });
  });
  assert.ok(session.report.localVerification.ok);
  assert.ok(session.report.localVerification.checks.every(c => c.status === 'passed' && !c.mocked));
  assert.ok(session.report.wardenVerdict.verified);

  const payloadPath = values.payload
    ? resolve(values.payload)
    : fileURLToPath(new URL('../docs/proof-server-prove-fixture/zswap-prove-payload.bin', import.meta.url));
  const payload = await readFile(payloadPath);
  const started = performance.now();
  const response = await session.prove({ body: new Uint8Array(payload), headers: { 'content-type': 'application/octet-stream' } });
  assert.equal(response.status, 200);
  const prefix = Buffer.from('midnight:proof-versioned:');
  assert.ok(Buffer.from(response.body).subarray(0, prefix.length).equals(prefix), 'Invalid proof response prefix');
  assert.ok(response.body.length > 1000, 'Proof response is too short');

  const summary = {
    checkedAt: new Date().toISOString(), attestationHost: config.attestationHost,
    applicationId: config.applicationId, registrationId: session.report.expected.record.registrationId,
    ledger: session.report.expected.ledger, mocked: false,
    localChecks: session.report.localVerification.checks, wardenVerdict: session.report.wardenVerdict,
    prove: { status: response.status, bytes: response.body.length, elapsedMs: Math.round(performance.now() - started) },
  };
  if (values.output) {
    await writeFile(values.output, redact(JSON.stringify(summary, null, 2)) + '\n', { mode: 0o600 });
  }
  log({ result: 'PASS', ...summary });
} catch (error) {
  log({ result: 'FAIL', phase: error.phase, message: error.message });
  process.exitCode = 1;
} finally {
  await session?.close();
}
