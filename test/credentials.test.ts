// Fix for https://stackoverflow.com/questions/68468203/why-am-i-getting-textencoder-is-not-defined-in-jest
import { TextEncoder, TextDecoder } from 'util'
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder as any;

import { createSigner, issue } from '../src/credentials';
import { OutputType } from '../src/credentials.types';
import { createPrivateKey } from './util/util';
import { W3CCredential } from 'did-jwt-vc';
import { decodeJWT } from 'did-jwt';
import { JWTDecoded } from 'did-jwt/lib/JWT';
import { JWT } from 'did-jwt-vc/lib/types';

describe('Issue and verify credential', () => {
    const now = new Date();
    const chain = "telos";
    const account = "university";
    const permission = "active"

    const vc: W3CCredential = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        id: "https://example.com/id/1234324",
        type: ['ConditionalProof2022'],
        issuer: {
            id: `did:eosio:${chain}:${account}`,
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
            did: `did:eosio:${chain}:${account}#${permission}`,
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

    it('Issues a credential with a three signatures', async () => {
        const privateKey1 = createPrivateKey()
        const issuer1 = {
            did: `did:eosio:${chain}:${account}#${permission}`,
            signer: createSigner(privateKey1)
        }
        const privateKey2 = createPrivateKey()
        const issuer2 = {
            did: `did:eosio:${chain}:${account}#${permission}`,
            signer: createSigner(privateKey2)
        }
        const privateKey3 = createPrivateKey()
        const issuer3 = {
            did: `did:eosio:${chain}:${account}#${permission}`,
            signer: createSigner(privateKey3)
        }

        const vcJwt = await issue(vc, {
            issuer: [issuer1, issuer2, issuer3],
            outputType: OutputType.JWT
        }) as JWT;
        console.log("jwt", vcJwt);
        const jwt: JWTDecoded = decodeJWT(vcJwt);

        // check if the JWT object complies to the W3C standard https://www.w3.org/TR/vc-data-model/#jwt-encoding
        expect(jwt.header.alg).toBeTruthy();
        if (jwt.header.type) {
            expect(jwt.header.type).toEqual("JWT");
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
})