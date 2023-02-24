// Fix for https://stackoverflow.com/questions/68468203/why-am-i-getting-textencoder-is-not-defined-in-jest
import { TextEncoder, TextDecoder } from 'util'
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder as any;

import { createSigner, issue } from '../src/index';
import { OutputType } from '../src/credentials.types';
import { createPrivateKey } from './util/util';
import { verifyCredential, W3CCredential } from '@tonomy/did-jwt-vc';
import { decodeJWT } from '@tonomy/did-jwt';
import { JWTDecoded } from '@tonomy/did-jwt/lib/JWT';
import { Issuer, JWT } from '@tonomy/did-jwt-vc/lib/types';
import { createMockVerify } from './util/mockResolver';
import { PrivateKey } from '@greymass/eosio';
import AntelopeDID from '@tonomy/antelope-did';
import { tonomyDid, tonomyVcPayload } from './util/vc';
import fetch from 'cross-fetch';

describe('Issue and verify credential', () => {
    const now = new Date();
    const chain = "telos";
    const account = "university";
    const permission = "permission0"

    const vc: W3CCredential = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        id: "https://example.com/id/1234324",
        type: ['VerifiableCredential'],
        issuer: {
            id: `did:antelope:${chain}:${account}`,
        },
        issuanceDate: now.toISOString(),
        credentialSubject: {
            degree: {
                type: 'BachelorDegree',
                name: 'Baccalauréat en musiques numériques'
            }
        }
    }

    it('Issues a credential with a single signature', async () => {

        const privateKey = createPrivateKey()
        const issuer = {
            did: `did:antelope:${chain}:${account}#${permission}`,
            signer: createSigner(privateKey)
        }

        const vcJwt = await issue(vc, {
            issuer,
            outputType: OutputType.JWT
        }) as JWT;
        const jwt: JWTDecoded = decodeJWT(vcJwt);

        // check if the JWT object complies to the W3C standard https://www.w3.org/TR/vc-data-model/#jwt-encoding
        expect(jwt.header.alg).toBeTruthy();
        if (jwt.header.type) {
            expect(jwt.header.type).toEqual("JWT");
        }
        expect(jwt.payload.nbf).toBeTruthy();
        expect(jwt.payload.nbf).toBe(Math.floor(new Date(vc.issuanceDate).getTime() / 1000));
        expect(jwt.payload.iss).toBeTruthy();
        expect(jwt.payload.iss).toEqual(issuer.did);
        if (vc.credentialSubject.id) {
            expect(jwt.payload.sub).toBeTruthy();
            expect(jwt.payload.sub).toEqual(vc.credentialSubject.id);
        }
        expect(jwt.signature).toBeTruthy();
    })

    it('Verifies an issued credential with a single signature', async () => {
        const privateKey = createPrivateKey()
        const issuer: Issuer = {
            did: `did:antelope:${chain}:${account}#${permission}`,
            signer: createSigner(privateKey),
            alg: 'ES256K-R',
        }

        const vcJwt = await issue(vc, {
            issuer
        }) as JWT;

        const verify = createMockVerify({
            threshold: 1,
            keys: [{
                key: privateKey.toPublic().toString(),
                weight: 1
            }],
            accounts: []
        })
        const verified = await verify(vcJwt);
        expect(verified).toBeTruthy();
    })

    it('Issues a credential with a three signatures', async () => {
        const privateKey1 = createPrivateKey()
        const issuer1 = {
            did: `did:antelope:${chain}:${account}#${permission}`,
            signer: createSigner(privateKey1)
        }
        const privateKey2 = createPrivateKey()
        const issuer2 = {
            did: `did:antelope:${chain}:${account}#${permission}`,
            signer: createSigner(privateKey2)
        }
        const privateKey3 = createPrivateKey()
        const issuer3 = {
            did: `did:antelope:${chain}:${account}#${permission}`,
            signer: createSigner(privateKey3)
        }

        const vcJwt = await issue(vc, {
            issuer: [issuer1, issuer2, issuer3],
            outputType: OutputType.JWT
        }) as JWT;

        const jwt: JWTDecoded = decodeJWT(vcJwt);

        // check if the JWT object complies to the W3C standard https://www.w3.org/TR/vc-data-model/#jwt-encoding
        expect(jwt.header.alg).toBeTruthy();
        if (jwt.header.cty) {
            expect(jwt.header.cty).toEqual("JWT");
        }

        expect(jwt.payload.nbf).toBeTruthy();
        expect(jwt.payload.nbf).toBe(Math.floor(new Date(vc.issuanceDate).getTime() / 1000));
        expect(jwt.payload.iss).toBeTruthy();
        expect(jwt.payload.iss).toEqual(issuer1.did);
        if (vc.credentialSubject.id) {
            expect(jwt.payload.sub).toBeTruthy();
            expect(jwt.payload.sub).toEqual(vc.credentialSubject.id);
        }
        expect(jwt.signature).toBeTruthy();

    })

    it("test against jungle testnet",async ()=>{

        const privateKey = PrivateKey.from("5KgcG8uRpoKWWbjsuJhyp9H6tAiy8yGVhuztMCSjXXj4oN1JPJB")

        const antelopeDID = new AntelopeDID({ fetch, chain: 'https://jungle4.cryptolions.io' });
    const resolver = { resolve: antelopeDID.resolve.bind(antelopeDID) };

    const issuer: Issuer = {
        did: tonomyDid + "#active",
        signer: createSigner(privateKey),
        alg: 'ES256K-R',
    }
    const resolved= await resolver.resolve(issuer.did)
    console
    .log("resolved",JSON.stringify(resolved))
    const vc = await issue(tonomyVcPayload as any,{
        issuer,
        outputType: OutputType.JWT
    })
    

    const result = await verifyCredential(vc,{
        resolve: resolver.resolve
    })


    expect(result).toBeTruthy()
    })
})