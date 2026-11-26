// Standalone RFC 9578 blind-RSA helper for the testnet checkout pilot.
// Uses @cloudflare/privacypass-ts so blind request, signing, and unblinding match the lab issuer.
import { createHash, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { TokenChallenge, publicVerif } from '@cloudflare/privacypass-ts';

const { BLIND_RSA, BlindRSAMode, Client, Issuer, TokenRequest, TokenResponse, getPublicKeyBytes } = publicVerif;
const mode = BlindRSAMode.PSS;
const roles = ['entry', 'exit'];
const pairsPerBatch = 4;

const subtle = webcrypto.subtle;

function makeChallenge(issuerName, poolName, role, epoch) {
    const epochBytes = Buffer.alloc(4);
    epochBytes.writeUInt32BE(epoch);
    const context = createHash('sha256').update('cpvpn/shared-epoch/v1\0').update(epochBytes).digest();
    return new TokenChallenge(2, issuerName, context, [`${role}.${poolName}`]);
}

async function exportKeyPair(privateKey, publicKey) {
    const priv = Buffer.from(await subtle.exportKey('pkcs8', privateKey)).toString('base64');
    const pub = Buffer.from(await subtle.exportKey('spki', publicKey)).toString('base64');
    const spkiBytes = Buffer.from(await getPublicKeyBytes(publicKey)).toString('hex');
    return { privateKeyPkcs8: priv, publicKeySpki: pub, issuerSpki: spkiBytes };
}

async function importPrivate(pkcs8B64) {
    return subtle.importKey(
        'pkcs8',
        Buffer.from(pkcs8B64, 'base64'),
        { name: 'RSA-PSS', hash: 'SHA-384' },
        true,
        ['sign'],
    );
}

async function importPublic(spkiB64) {
    return subtle.importKey(
        'spki',
        Buffer.from(spkiB64, 'base64'),
        { name: 'RSA-PSS', hash: 'SHA-384' },
        true,
        ['verify'],
    );
}

if (process.argv[2] === 'client-checkout') {
    const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
    const iter = rl[Symbol.asyncIterator]();
    const first = await iter.next();
    const input = JSON.parse(first.value);
    const spki = Buffer.from(input.issuerSpki, 'hex');
    const clients = Array.from({ length: pairsPerBatch * roles.length }, () => new Client(mode));
    const requests = [];
    for (let i = 0; i < clients.length; i++) {
        const ch = makeChallenge(input.issuerName, input.poolName, roles[i % roles.length], input.epoch);
        const req = await clients[i].createTokenRequest(ch, spki);
        requests.push(Buffer.from(req.serialize()).toString('hex'));
    }
    process.stdout.write(JSON.stringify({ requests }) + '\n');
    const second = await iter.next();
    const reply = JSON.parse(second.value);
    const tokens = [];
    for (let i = 0; i < clients.length; i++) {
        const resp = TokenResponse.deserialize(Buffer.from(reply.responses[i], 'hex'));
        const token = await clients[i].finalize(resp);
        tokens.push(Buffer.from(token.serialize()).toString('hex'));
    }
    const pairs = Array.from({ length: pairsPerBatch }, (_, idx) => tokens.slice(2 * idx, 2 * idx + 2));
    process.stdout.write(JSON.stringify({ pairs }) + '\n');
    rl.close();
} else {
    const input = JSON.parse(readFileSync(0, 'utf8'));
    if (input.op === 'keygen') {
        const { privateKey, publicKey } = await Issuer.generateKey(mode, {
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
        });
        process.stdout.write(JSON.stringify(await exportKeyPair(privateKey, publicKey)));
    } else if (input.op === 'blind-sign') {
        const privateKey = await importPrivate(input.privateKeyPkcs8);
        const publicKey = await importPublic(input.publicKeySpki);
        const issuer = new Issuer(mode, input.issuerName, privateKey, publicKey);
        const responses = [];
        for (const hexReq of input.requests) {
            const req = TokenRequest.deserialize(BLIND_RSA, Buffer.from(hexReq, 'hex'));
            const resp = await issuer.issue(req);
            responses.push(Buffer.from(resp.serialize()).toString('hex'));
        }
        process.stdout.write(JSON.stringify({ responses }));
    } else {
        throw new Error(`unknown op: ${input.op}`);
    }
}
