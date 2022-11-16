// Fix for https://stackoverflow.com/questions/68468203/why-am-i-getting-textencoder-is-not-defined-in-jest
import { TextEncoder, TextDecoder } from 'util';
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder as any;

import { PrivateKey } from '@greymass/eosio';
import { decodeJWT } from 'did-jwt';
import {
  Issuer,
  JwtCredentialPayload,
  createVerifiableCredentialJwt,
  verifyCredential,
} from 'did-jwt-vc';
import { createSigner } from '../src/credentials';
import AntelopeDID, {
  createDIDDocument,
  antelopeChainRegistry,
  checkDID,
} from 'antelope-did';
import fetch from 'node-fetch';
import { parse } from 'did-resolver';

describe('Issue and verify credential', () => {
  /**
   * Public Key: EOS6Q8zrGD6dceAiRx1FxruYYCZaoAr4cintr5mpibHQC6ToxUreA
   * Private key: 5JAJ7BfYKdRnrSQCsdcBqrCcBVQQSuQ77fuRAJ5fcbQ3UDhuLLZ
   *
   *
   * Public Key: EOS7EEmiZSRfqMmVse9bycExAAZ1ixUioPavkGTbotiGLryhACufQ
   * Private key: 5JcKy5rAp4rTnE9za1CNm5xBG4DnJ2T29cYpz87kRVRdQqv1K8x
   *
   * Public Key: EOS7y23bQGv367BFcv4eKrFdq6BTZsTh4gbDziNdRiffv1tq6DnaP
   * Private key: 5JibpxxNpkqdejc38KD9xZF3fKHtTUonKCAYiZbwNPsgoKbw6FQ
   */
  const publicKeys = [
    'EOS6Q8zrGD6dceAiRx1FxruYYCZaoAr4cintr5mpibHQC6ToxUreA',
    'EOS7EEmiZSRfqMmVse9bycExAAZ1ixUioPavkGTbotiGLryhACufQ',
    'EOS7y23bQGv367BFcv4eKrFdq6BTZsTh4gbDziNdRiffv1tq6DnaP',
  ];
  const privatekeys = [
    '5JAJ7BfYKdRnrSQCsdcBqrCcBVQQSuQ77fuRAJ5fcbQ3UDhuLLZ',
    '5JcKy5rAp4rTnE9za1CNm5xBG4DnJ2T29cYpz87kRVRdQqv1K8x',
    '5JibpxxNpkqdejc38KD9xZF3fKHtTUonKCAYiZbwNPsgoKbw6FQ',
  ];
  const Resolver = {
    resolve: async (did: string) => {
      const parsed = parse(did);
      if (!parsed) throw new Error('could not parse did');
      const methodId = checkDID(parsed, antelopeChainRegistry);
      if (!methodId) throw new Error('invalid did');
      
      const account = {
        permissions: [{
          perm_name: "active",
          parent: "owner",
          required_auth: {
            threshold: 2,
            keys: publicKeys.map(key => {
              return { key, weight: 1 };
            }),
            accounts: []
          }
        }]
      }
      const didDoc = createDIDDocument(methodId, parsed.did, account);
      console.log('didDoc', JSON.stringify(didDoc, null, 2))
      
      return {
        didResolutionMetadata: {},
        didDocument: didDoc,
        didDocumentMetadata: {},
      };
    },
  };

  it('Issues a simple Antelope credential signed by one key', async () => {
    const did = 'did:antelope:eos:testnet:jungle:reball1block';

    const keyIssuer1: Issuer = {
      did: did + '#active',
      signer: createSigner(
        PrivateKey.from('5KSKD681YRwQjwDkr8TLkUUU5adHy1CWGuLiow1DR5ToZF5oiUQ')
      ),
      alg: 'ES256K-R',
    };

    const vcPayload: JwtCredentialPayload = {
      sub: did,
      nbf: 1562950282,
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['ConditionalProof2022'],
        credentialSubject: {
          degree: {
            type: 'BachelorDegree',
            name: 'Baccalauréat en musiques numériques',
          },
        },
      },
    };

    const vcJwt = await createVerifiableCredentialJwt(vcPayload, keyIssuer1);
    const decodedJwt = decodeJWT(vcJwt);
    const antelopeDID = new AntelopeDID({ fetch });
    const resolver = { resolve: antelopeDID.resolve.bind(antelopeDID) };

    await expect(verifyCredential(vcJwt, resolver)).resolves.toBeTruthy();
    await expect(decodedJwt).toBeDefined();
  });

  it('Issues and verify a simple Antelope credential with 2 of 3 signature check', async () => {
    const did = 'did:antelope:eos:testnet:jungle:reball1block';

    const keyIssuer1: Issuer = {
      did: did + '#active',
      signer: createSigner(PrivateKey.from(privatekeys[0])),
      alg: 'ES256K-R',
    };
    const keyIssuer2: Issuer = {
      did: did + '#active',
      signer: createSigner(PrivateKey.from(privatekeys[1])),
      alg: 'ES256K-R',
    };

    const vcPayload: JwtCredentialPayload = {
      sub: did,
      nbf: 1562950282,
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['ConditionalProof2022'],
        credentialSubject: {
          degree: {
            type: 'BachelorDegree',
            name: 'Baccalauréat en musiques numériques',
          },
        },
      },
    };

    const vcJwtWith2Signatures = await createVerifiableCredentialJwt(
      vcPayload,
      [keyIssuer1, keyIssuer2]
    );
    expect(typeof vcJwtWith2Signatures === 'string').toBeTruthy()

    const verifiedVc = await verifyCredential(vcJwtWith2Signatures, Resolver);
    expect(verifiedVc.verified).toBeTruthy();
  });
});
