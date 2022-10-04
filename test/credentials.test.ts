// Fix for https://stackoverflow.com/questions/68468203/why-am-i-getting-textencoder-is-not-defined-in-jest
import { TextEncoder, TextDecoder } from 'util'
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder as any;

import { createSigner, issue } from '../src/credentials';
import { OutputType } from '../src/credentials.types';
import { createPrivateKey } from './util/util';
import { W3CCredential } from 'did-jwt-vc';
import { decodeJWT } from 'did-jwt';
import { JWT } from 'did-jwt-vc/lib/types';

describe('Issue and verify credential', () => {

    it('Issues a credential with a single signature', async () => {
        const now = new Date();
        const chain = "telos";
        const account = "university";
        const permission = "active"

        const vc: W3CCredential = {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            id: "https://example.com/id/1234324",
            type: ['VerifiableCredential'],
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

        const privateKey = createPrivateKey()
        const issuer = {
            did: `did:eosio:${chain}:${account}#${permission}`,
            signer: createSigner(privateKey)
        }

        const vcJwt = await issue(vc, {
            issuer,
            outputType: OutputType.JWT
        }) as JWT;

        console.log(decodeJWT(vcJwt));
    })

    it('Issues a credential with a three signatures', async () => {
        const now = new Date();
        const chain = "telos";
        const account = "university";
        const permission = "active"

        const vc: W3CCredential = {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            id: "https://example.com/id/1234324",
            type: ['VerifiableCredential'],
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

        const jwt = decodeJWT(vcJwt);
        console.log("decodeJWT", JSON.stringify(jwt, null, 2))
    })
})