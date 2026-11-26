// Lab fixture: use independently implemented RFC 9578 issuance to exercise our verifier.
// The in-process issuer deliberately has no payment, identity, or traffic integration.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { connect, createServer } from 'node:tls';
import { TokenChallenge, publicVerif } from '@cloudflare/privacypass-ts';

const { BlindRSAMode, Client, Issuer, getPublicKeyBytes } = publicVerif;
const epoch = 1;
const issuerName = 'issuer.vpn.test';
const poolName = 'pool.vpn.test';
const roles = ['entry', 'exit'];
const pairsPerBatch = 4;
const mode = BlindRSAMode.PSS;
const servers = JSON.parse(readFileSync(0, 'utf8'));
const { privateKey, publicKey } = await Issuer.generateKey(mode, {
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
});
const keyBytes = await getPublicKeyBytes(publicKey);
const issuer = new Issuer(mode, issuerName, privateKey, publicKey);

function challenge(role) {
    const epochBytes = Buffer.alloc(4);
    epochBytes.writeUInt32BE(epoch);
    const context = createHash('sha256').update('cpvpn/shared-epoch/v1\0').update(epochBytes).digest();
    return new TokenChallenge(2, issuerName, context, [`${role}.${poolName}`]);
}

const code = randomBytes(32).toString('hex');
const availableCodes = new Set([code]);
async function issueSponsoredBatch(sponsorCode, blindedRequests) {
    assert.equal(blindedRequests.length, pairsPerBatch * roles.length);
    if (!availableCodes.delete(sponsorCode)) throw new Error('sponsor code unavailable');
    return Promise.all(blindedRequests.map(request => issuer.issue(request)));
}

const clients = Array.from({ length: pairsPerBatch * roles.length }, () => new Client(mode));
const requests = await Promise.all(clients.map((client, index) =>
    client.createTokenRequest(challenge(roles[index % roles.length]), keyBytes)
));
const responses = await issueSponsoredBatch(code, requests);
await assert.rejects(() => issueSponsoredBatch(code, requests), /sponsor code unavailable/);
const tokens = await Promise.all(clients.map(async (client, index) =>
    Buffer.from((await client.finalize(responses[index])).serialize()).toString('hex')
));
const pairs = Array.from({ length: pairsPerBatch }, (_, index) => tokens.slice(2 * index, 2 * index + 2));

async function exporterPair(role) {
    const label = 'EXPORTER-CYPHERPUNK-SHARED-ADMISSION-v1';
    const context = Buffer.from(role);
    const { cert, key } = servers[role];
    const server = createServer({ cert, key, minVersion: 'TLSv1.3' });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const inbound = once(server, 'secureConnection');
    const client = connect({
        host: '127.0.0.1', port: server.address().port, ca: cert,
        servername: `${role}.vpn.test`, minVersion: 'TLSv1.3',
    });
    try {
        const [, [peer]] = await Promise.all([once(client, 'secureConnect'), inbound]);
        const clientExporter = client.exportKeyingMaterial(32, label, context);
        const serverExporter = peer.exportKeyingMaterial(32, label, context);
        return [clientExporter.toString('hex'), serverExporter.toString('hex')];
    } finally {
        client.destroy();
        server.close();
    }
}

const channels = await Promise.all(pairs.map(() => Promise.all(roles.map(exporterPair))));
process.stdout.write(JSON.stringify({
    issuerName, poolName, epoch, issuerSpki: Buffer.from(keyBytes).toString('hex'), pairs, channels,
}));
