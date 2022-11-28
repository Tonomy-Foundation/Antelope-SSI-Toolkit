// Fix for https://stackoverflow.com/questions/68468203/why-am-i-getting-textencoder-is-not-defined-in-jest
import { TextEncoder, TextDecoder } from 'util';
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder as any;

import { PrivateKey } from '@greymass/eosio';
import { createJWT, decodeJWT, JWTHeader, JWTOptions, JWTPayload, JWT_ERROR, Signer } from 'did-jwt';
import {
  Issuer,
  createVerifiableCredentialJwt,
  verifyCredential,
} from 'did-jwt-vc';
import { createSigner } from '../src/credentials';
import { createResolver } from './util/mockResolver'
import { publicKeys, privateKeys } from './util/keys';
import { did, vcPayload } from './util/vc';

// @ts-ignore
async function mockCreateMultisignatureJWT(
  payload: Partial<JWTPayload>,
  { expiresIn, canonicalize }: Partial<JWTOptions>,
  issuers: { issuer: string; signer: Signer; alg: string }[]
): Promise<string> {
  if (issuers.length === 0) throw new Error('invalid_argument: must provide one or more issuers')

  let payloadResult: Partial<JWTPayload> = payload

  let jwt = ''
  for (let i = 0; i < issuers.length; i++) {
    const issuer = issuers[i]

    const header: Partial<JWTHeader> = {
      typ: 'JWT',
      alg: issuer.alg,
    }

    // Create nested JWT
    // See Point 5 of https://www.rfc-editor.org/rfc/rfc7519#section-7.1
    // After the first JWT is created (the first JWS), the next JWT is created by inputting the previous JWT as the payload
    if (i !== 0) {
      header.cty = 'JWT'
    }

    jwt = await createJWT(payloadResult, { ...issuer, canonicalize, expiresIn }, header)

    // Mock the 2nd signature is tampered with here
    if (i === 1) {
      const [header, payload] = jwt.split('.')
      const tamperedSignature = '7F5jTioKhny2fifxCI6ZAWl3XrFZ9bMhP9WYlOfkU-wNxO1jfQuyl9zZyQXqo7FfIgYi7CYoAU_mUsRAuGb4cQA'
      jwt = `${header}.${payload}.${tamperedSignature}`
    }

    payloadResult = { jwt }
  }
  return jwt
}

jest.mock('did-jwt', () => ({
  // @ts-ignore
  ...jest.requireActual('did-jwt'),
  createMultisignatureJWT: jest.fn(mockCreateMultisignatureJWT),
}));

describe('Issue and verify credential', () => {

  const h = '####################################\n'
  it('7a. Issues a credential with 2 valid signature and 1 tampered signature, which correctly decodes but fails validation', async () => {
    console.log(`${h}${h}${h}\nTest 7a\n\n${h}${h}${h}`)
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

    const vcJwtWithDelegatedSignatureDecoded = decodeJWT(vcJwtWithDelegatedSignature, true);
    expect(vcJwtWithDelegatedSignatureDecoded.payload.vc).toEqual(vcPayload.vc);

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
