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
import AntelopeDID from 'antelope-did';
import fetch from 'node-fetch';

describe('Issue and verify credential', () => {
  it('Issues a simple Antelope credential signed by one key', async () => {
    const did = 'did:eosio:eos:testnet:jungle:reball1block';

    const keyIssuer1: Issuer = {
      did: did + '#active-0',
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
    // console.log(
    //   JSON.stringify(
    //     await resolver.resolve(did, { accept: 'application/did+ld+json' })
    //   )
    // );

    expect(verifyCredential(vcJwt, resolver)).resolves.toBeTruthy();
    expect(decodedJwt).toBeDefined();
  });

  it('Issues a simple Antelope credential signed by multiple keys', async () => {
    const did = 'did:eosio:eos:jungle:tonomytester';

    const keyIssuer1: Issuer = {
      did: did + '#key-1',
      signer: createSigner(
        PrivateKey.from('5KH76LoG9PhgjQqXCExJP5bHxShk5K6A7QHj723k2AdX5NYUHt7')
      ),
      alg: 'ES256K',
    };
    const keyIssuer2: Issuer = {
      did: did + '#key-1',
      signer: createSigner(
        PrivateKey.from('5HrTzxFoNA4MweauhgkWmrUZFc5kAZ8hGbgmqbT3z8gnd35EYy8')
      ),
      alg: 'ES256K',
    };
    // const keyIssuer3: Issuer = {
    //   did: did + "#key-1",
    //   signer: createSigner(PrivateKey.from("5JnSPB4mn9b52GVXMjnNxKp8x4bEGk6nsoVhwCPbEA3WoWnmEvf")),
    //   alg: "ES256K"
    // }

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
    const vcJwtWith1Signatures = await createVerifiableCredentialJwt(
      vcPayload,
      keyIssuer1
    );

    const vcJwtWith2Signatures = await createVerifiableCredentialJwt(
      vcPayload,
      [keyIssuer1, keyIssuer2]
    );

    expect(vcJwtWith2Signatures).toBeTruthy();
    expect(vcJwtWith1Signatures).toBeTruthy();

    // const vcJwtWith3Signatures = await addSignatureToJwt(vcJwtWith2Signatures, keyIssuer3);
    // console.log("3 signatures", vcJwtWith3Signatures);
  });
});
