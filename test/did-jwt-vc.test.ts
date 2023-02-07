// Fix for https://stackoverflow.com/questions/68468203/why-am-i-getting-textencoder-is-not-defined-in-jest
import { TextEncoder, TextDecoder } from 'util';
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder as any;

import { PrivateKey } from '@greymass/eosio';
import { decodeJWT, JWT_ERROR } from '@tonomy/did-jwt';
import {
  Issuer,
  createVerifiableCredentialJwt,
  verifyCredential,
} from '@tonomy/did-jwt-vc';
import { createSigner } from '../src/credentials';
import { createResolver } from './util/mockResolver'
import { publicKeys, privateKeys } from './util/keys';
import { did, vcPayload } from './util/vc';

describe('Issue and verify credential', () => {

  // const h = '####################################\n'
  it('1. Issues and verifies an Antelope credential signed by one key', async () => {
    // console.log(`${h}${h}${h}\nTest 1\n\n${h}${h}${h}`)
    const keyIssuer1: Issuer = {
      did: did + '#permission0',
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

  it('2. Issues and fails to verify an Antelope credential signed by the wrong key', async () => {
    // console.log(`${h}${h}${h}\nTest 2\n\n${h}${h}${h}`)
    const keyIssuer1: Issuer = {
      did: did + '#permission0',
      signer: createSigner(
        PrivateKey.from(privateKeys[1])
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

    await expect(() => verifyCredential(vcJwt, resolver)).rejects.toThrowError(JWT_ERROR.INVALID_SIGNATURE)
  });

  it('2a. Issues and fails to verify when the issuer DID URL does not match the authenticator', async () => {
    // TODO
    // console.log(`${h}${h}${h}\nTest 2a\n\n${h}${h}${h}`)
    // const keyIssuer1: Issuer = {
    //   did: did + '#active0',
    //   signer: createSigner(
    //     PrivateKey.from(privateKeys[0])
    //   ),
    //   alg: 'ES256K-R',
    // };

    // const vcJwt = await createVerifiableCredentialJwt(vcPayload, keyIssuer1);
    // const decodedJwt = decodeJWT(vcJwt);
    // await expect(decodedJwt.payload.vc).toEqual(vcPayload.vc);

    // const resolver = createResolver({
    //   threshold: 1,
    //   keys: [{
    //     key: publicKeys[0],
    //     weight: 1
    //   }],
    //   accounts: []
    // })
  });

  it('3. Issues and verify a simple Antelope credential with 2 of 3 signature check', async () => {
    // console.log(`${h}${h}${h}\nTest 3\n\n${h}${h}${h}`)
    const keyIssuer1: Issuer = {
      did: did + '#permission0',
      signer: createSigner(PrivateKey.from(privateKeys[0])),
      alg: 'ES256K-R',
    };
    const keyIssuer2: Issuer = {
      did: did + '#permission0',
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
      keys: [publicKeys[0], publicKeys[1], publicKeys[2]].map((key) => { return { key, weight: 1}}),
      accounts: []
    })
    
    const verifiedVc = await verifyCredential(vcJwtWith2Signatures, resolver);
    expect(verifiedVc.verified).toBeTruthy();
  });

  it('4. Issues and fails to verify a simple Antelope credential with 2 of 3 signature check with only 1 signature', async () => {
    // console.log(`${h}${h}${h}\nTest 4\n\n${h}${h}${h}`)
    const keyIssuer1: Issuer = {
      did: did + '#permission0',
      signer: createSigner(PrivateKey.from(privateKeys[0])),
      alg: 'ES256K-R',
    };

    const vcJwtWith2Signatures = await createVerifiableCredentialJwt(
      vcPayload,
      [keyIssuer1]
    );
    expect(typeof vcJwtWith2Signatures === 'string').toBeTruthy()

    const resolver = createResolver({
      threshold: 2,
      keys: [publicKeys[0], publicKeys[1], publicKeys[2]].map((key) => { return { key, weight: 1}}),
      accounts: []
    })

    await expect(() => verifyCredential(vcJwtWith2Signatures, resolver)).rejects.toThrowError(JWT_ERROR.INVALID_SIGNATURE)
  });

  it('5. Issues and verify a credential with a delegated signature check', async () => {
    // console.log(`${h}${h}${h}\nTest 5\n\n${h}${h}${h}`)
    const keyIssuer1: Issuer = {
      did: did + '#permission0',
      signer: createSigner(PrivateKey.from(privateKeys[0])),
      alg: 'ES256K-R',
    };

    const vcJwtWithDelegatedSignature = await createVerifiableCredentialJwt(
      vcPayload,
      [keyIssuer1]
    );
    expect(typeof vcJwtWithDelegatedSignature === 'string').toBeTruthy()

    const resolver = createResolver([{
      threshold: 1,
      keys: [],
      accounts: [{
        permission: {
          permission: 'permission1',
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
    
    const verifiedVc = await verifyCredential(vcJwtWithDelegatedSignature, resolver);
    expect(verifiedVc.verified).toBeTruthy();
  });

  it('6. Issues and fails to verify a credential with the wrong delegated signature check', async () => {
    // console.log(`${h}${h}${h}\nTest 6\n\n${h}${h}${h}`)
    const keyIssuer1: Issuer = {
      did: did + '#permission0',
      signer: createSigner(PrivateKey.from(privateKeys[1])),
      alg: 'ES256K-R',
    };

    const vcJwtWithDelegatedSignature = await createVerifiableCredentialJwt(
      vcPayload,
      [keyIssuer1]
    );
    expect(typeof vcJwtWithDelegatedSignature === 'string').toBeTruthy()

    const resolver = createResolver([{
      threshold: 1,
      keys: [],
      accounts: [{
        permission: {
          permission: 'permission1',
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

    await expect(() => verifyCredential(vcJwtWithDelegatedSignature, resolver)).rejects.toThrowError(JWT_ERROR.INVALID_SIGNATURE)
  });

  it('7. Issues and verify a credential with a 3 threshold and 2 keys and 2 delegated signature check', async () => {
    // console.log(`${h}${h}${h}\nTest 7\n\n${h}${h}${h}`)
    const keyIssuer1: Issuer = {
      did: did + '#permission0',
      signer: createSigner(PrivateKey.from(privateKeys[0])),
      alg: 'ES256K-R',
    };
    const keyIssuer2: Issuer = {
      did: did + '#permission0',
      signer: createSigner(PrivateKey.from(privateKeys[1])),
      alg: 'ES256K-R',
    };
    const keyIssuer3: Issuer = {
      did: did + '#permission0',
      signer: createSigner(PrivateKey.from(privateKeys[2])),
      alg: 'ES256K-R',
    };

    const vcJwtWithDelegatedSignature = await createVerifiableCredentialJwt(
      vcPayload,
      [keyIssuer1, keyIssuer2, keyIssuer3]
    );
    expect(typeof vcJwtWithDelegatedSignature === 'string').toBeTruthy()

    const resolver = createResolver([{
      threshold: 3,
      keys: [{
        key: publicKeys[0],
        weight: 1
      }, {
        key: publicKeys[1],
        weight: 1
      }],
      accounts: [{
        permission: {
          permission: 'permission1',
          actor: 'reball1block',
        },
        weight: 1
      }, {
        permission: {
          permission: 'permission2',
          actor: 'reball1block',
        },
        weight: 1
      }]
    }, {
      threshold: 1,
      keys: [{
        key: publicKeys[2],
        weight: 1
      }],
      accounts: []
    }, {
      threshold: 1,
      keys: [{
        key: publicKeys[3],
        weight: 1
      }],
      accounts: []
    }])
    
    const verifiedVc = await verifyCredential(vcJwtWithDelegatedSignature, resolver);
    expect(verifiedVc.verified).toBeTruthy();
  });

  it('8. Issues and fails to verify a credential with a 3 threshold and 2 keys and 2 delegated signature check, with incorrect key', async () => {
    // console.log(`${h}${h}${h}\nTest 8\n\n${h}${h}${h}`)
    const keyIssuer1: Issuer = {
      did: did + '#permission0',
      signer: createSigner(PrivateKey.from(privateKeys[4])),
      alg: 'ES256K-R',
    };
    const keyIssuer2: Issuer = {
      did: did + '#permission0',
      signer: createSigner(PrivateKey.from(privateKeys[1])),
      alg: 'ES256K-R',
    };
    const keyIssuer3: Issuer = {
      did: did + '#permission0',
      signer: createSigner(PrivateKey.from(privateKeys[2])),
      alg: 'ES256K-R',
    };

    const vcJwtWithDelegatedSignature = await createVerifiableCredentialJwt(
      vcPayload,
      [keyIssuer1, keyIssuer2, keyIssuer3]
    );
    expect(typeof vcJwtWithDelegatedSignature === 'string').toBeTruthy()

    const resolver = createResolver([{
      threshold: 3,
      keys: [{
        key: publicKeys[0],
        weight: 1
      }, {
        key: publicKeys[1],
        weight: 1
      }],
      accounts: [{
        permission: {
          permission: 'permission1',
          actor: 'reball1block',
        },
        weight: 1
      }, {
        permission: {
          permission: 'permission2',
          actor: 'reball1block',
        },
        weight: 1
      }]
    }, {
      threshold: 1,
      keys: [{
        key: publicKeys[2],
        weight: 1
      }],
      accounts: []
    }, {
      threshold: 1,
      keys: [{
        key: publicKeys[3],
        weight: 1
      }],
      accounts: []
    }])

    await expect(() => verifyCredential(vcJwtWithDelegatedSignature, resolver)).rejects.toThrowError(JWT_ERROR.INVALID_SIGNATURE)
  });

  it('9. Issues and fails to verify a credential with a 3 threshold and 2 keys and 2 delegated signature check, with incorrect delegation', async () => {
    // console.log(`${h}${h}${h}\nTest 9\n\n${h}${h}${h}`)
    const keyIssuer1: Issuer = {
      did: did + '#permission0',
      signer: createSigner(PrivateKey.from(privateKeys[0])),
      alg: 'ES256K-R',
    };
    const keyIssuer2: Issuer = {
      did: did + '#permission0',
      signer: createSigner(PrivateKey.from(privateKeys[1])),
      alg: 'ES256K-R',
    };
    const keyIssuer3: Issuer = {
      did: did + '#permission0',
      signer: createSigner(PrivateKey.from(privateKeys[4])),
      alg: 'ES256K-R',
    };

    const vcJwtWithDelegatedSignature = await createVerifiableCredentialJwt(
      vcPayload,
      [keyIssuer1, keyIssuer2, keyIssuer3]
    );
    expect(typeof vcJwtWithDelegatedSignature === 'string').toBeTruthy()
    // console.log(vcJwtWithDelegatedSignature)
    const resolver = createResolver([{
      threshold: 3,
      keys: [{
        key: publicKeys[0],
        weight: 1
      }, {
        key: publicKeys[1],
        weight: 1
      }],
      accounts: [{
        permission: {
          permission: 'permission1',
          actor: 'reball1block',
        },
        weight: 1
      }, {
        permission: {
          permission: 'permission2',
          actor: 'reball1block',
        },
        weight: 1
      }]
    }, {
      threshold: 1,
      keys: [{
        key: publicKeys[2],
        weight: 1
      }],
      accounts: []
    }, {
      threshold: 1,
      keys: [{
        key: publicKeys[3],
        weight: 1
      }],
      accounts: []
    }])

    await expect(() => verifyCredential(vcJwtWithDelegatedSignature, resolver)).rejects.toThrowError(JWT_ERROR.INVALID_SIGNATURE)
  });

});
