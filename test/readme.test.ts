// Fix for https://stackoverflow.com/questions/68468203/why-am-i-getting-textencoder-is-not-defined-in-jest
import { TextEncoder, TextDecoder } from 'util'
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder as any;

import { createSigner, issue } from '../src/index';
import { PrivateKey } from "@greymass/eosio";
import { createMockVerify } from './util/mockResolver';

describe('Issue and verify credential', () => {
    const privateKey = PrivateKey.from("PVT_K1_2bfGi9rYsXQSXXTvJbDAPhHLQUojjaNLomdm3cEJ1XTzMqUt3V");

    it('Issues a credential with a single signature', async () => {
        const vc = {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            id: "https://example.com/id/1234324",
            type: ['VerifiableCredential'],
            issuer: {
                id: `did:antelope:telos:university`,
            },
            issuanceDate: (new Date()).toISOString(),
            credentialSubject: {
                degree: {
                    type: 'BachelorDegree',
                    name: 'Bachelor of Music'
                }
            }
        }

        const issuer = {
            did: "did:antelope:telos:university#active",
            signer: createSigner(privateKey),
            alg: 'ES256K-R'
        }

        const vcJwt = await issue(vc, {
            issuer
        });
        const verify = createMockVerify({
            threshold: 1,
            keys: [{
                key: privateKey.toPublic().toString(),
                weight: 1
            }],
            accounts: []
        })

        const isVerified = await verify(vcJwt);

        expect(typeof vcJwt).toBe("string");
        expect(isVerified).toBeTruthy();
    })

})