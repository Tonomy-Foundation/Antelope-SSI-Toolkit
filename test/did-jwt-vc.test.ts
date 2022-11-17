// Fix for https://stackoverflow.com/questions/68468203/why-am-i-getting-textencoder-is-not-defined-in-jest
import { TextEncoder, TextDecoder } from 'util';
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder as any;

import { PrivateKey } from '@greymass/eosio';
import { decodeJWT } from 'did-jwt';
import {
  Issuer,
  createVerifiableCredentialJwt,
  verifyCredential,
} from 'did-jwt-vc';
import { createSigner } from '../src/credentials';
import { createResolver } from './util/mockResolver'
import { publicKeys, privateKeys } from './util/keys';
import { did, vcPayload } from './util/vc';

describe('Issue and verify credential', () => {

  it('Issues and verifies an Antelope credential signed by one key', async () => {
    const keyIssuer1: Issuer = {
      did: did + '#active',
      signer: createSigner(
        PrivateKey.from(privateKeys[0])
      ),
      alg: 'ES256K-R',
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

  it('Issues and verify a credential with a delegated signature check', async () => {
    const keyIssuer1: Issuer = {
      did: did + '#active',
      signer: createSigner(PrivateKey.from(privateKeys[0])),
      alg: 'ES256K-R',
    };

    const vcJwtWith2Signatures = await createVerifiableCredentialJwt(
      vcPayload,
      [keyIssuer1]
    );
    expect(typeof vcJwtWith2Signatures === 'string').toBeTruthy()

    const resolver = createResolver([{
      threshold: 1,
      keys: [],
      accounts: [{
        permission: {
          permission: 'active-1',
          actor: 'reball1block',
        },
        weight: 1
      }]
    }, {
      threshold: 1,
      keys: [{
        key: publicKeys[0],
        weight: 1
      }],
      accounts: []
    }])
    console.log('check')
    console.log(JSON.stringify(((await resolver.resolve('did:antelope:eos:testnet:jungle:reball1block')) as any).didDocument.verificationMethod[0], null, 2));
    
    // const verifiedVc = await verifyCredential(vcJwtWith2Signatures, resolver);
    // expect(verifiedVc.verified).toBeTruthy();
  });
});
