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
import {
  createDIDDocument,
  antelopeChainRegistry,
  checkDID,
} from 'antelope-did';
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
  const privateKeys = [
    '5JAJ7BfYKdRnrSQCsdcBqrCcBVQQSuQ77fuRAJ5fcbQ3UDhuLLZ',
    '5JcKy5rAp4rTnE9za1CNm5xBG4DnJ2T29cYpz87kRVRdQqv1K8x',
    '5JibpxxNpkqdejc38KD9xZF3fKHtTUonKCAYiZbwNPsgoKbw6FQ',
  ];

  type AntelopePermission = {
    threshold: number;
    keys: {
      key: string;
      weight: number;
    }[]
    accounts: {
      permission: {
        permission: string;
        actor: string;
      }
      weight: number
    }[]
  }
  function createResolver(required_auth: AntelopePermission) {
    return {
      resolve: async (did: string) => {
        const parsed = parse(did);
        if (!parsed) throw new Error('could not parse did');
        const methodId = checkDID(parsed, antelopeChainRegistry);
        if (!methodId) throw new Error('invalid did');
        
        const account = {
          permissions: [{
            perm_name: "active",
            parent: "owner",
            required_auth
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
    }
  }

  it('Issues and verifies an Antelope credential signed by one key', async () => {
    const did = 'did:antelope:eos:testnet:jungle:reball1block';

    const keyIssuer1: Issuer = {
      did: did + '#active',
      signer: createSigner(
        PrivateKey.from(privateKeys[0])
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
    await expect(decodedJwt).toBeDefined();

    const resolver = createResolver({
      threshold: 1,
      keys: [{
        key: publicKeys[0],
        weight: 1
      }],
      accounts: []
    })
    const verifiedCredential = await verifyCredential(vcJwt, resolver);

    await expect(verifiedCredential.verified).toBeTruthy();
  });

  it('Issues and verify a simple Antelope credential with 2 of 3 signature check', async () => {
    const did = 'did:antelope:eos:testnet:jungle:reball1block';

    const keyIssuer1: Issuer = {
      did: did + '#active',
      signer: createSigner(PrivateKey.from(privateKeys[0])),
      alg: 'ES256K-R',
    };
    const keyIssuer2: Issuer = {
      did: did + '#active',
      signer: createSigner(PrivateKey.from(privateKeys[1])),
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

    const resolver = createResolver({
      threshold: 2,
      keys: publicKeys.map((key) => { return { key, weight: 1}}),
      accounts: []
    })
    
    const verifiedVc = await verifyCredential(vcJwtWith2Signatures, resolver);
    expect(verifiedVc.verified).toBeTruthy();
  });
});
