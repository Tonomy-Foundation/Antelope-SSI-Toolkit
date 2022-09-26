// Fix for https://stackoverflow.com/questions/68468203/why-am-i-getting-textencoder-is-not-defined-in-jest
import { TextEncoder, TextDecoder } from 'util'
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder as any;

import { EthrDID } from 'ethr-did'
// import EosioDID from 'eosio-did'
import { PrivateKey } from '@greymass/eosio';
import { decodeJWT } from 'did-jwt'
import { Issuer } from 'did-jwt-vc'
import { JwtCredentialPayload, createVerifiableCredentialJwt, addSignatureToJwt } from 'did-jwt-vc'

function createSigner(privateKey: PrivateKey) {
  return async (data: string | Uint8Array) => {
    console.log(data.length);
    if (typeof data === 'string') {
      // TODO is this base64 or base52/58???
      // convert from base64 to hex
      const buffer = Buffer.from(data, 'base64');
      data = buffer.toString('hex');
    }

    const signature = await privateKey.signMessage(data);
    return signature.toString();
    // TODO signature in incorrect format still with prefix and base58 encoding
  }
}

describe('Issue and verify credential', () => {

  it('Issues an Ethereum credential, testing backwards compatibility', async () => {

    const issuer = new EthrDID({
      identifier: '0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
      privateKey: 'd8b595680851765f38ea5405129244ba3cbad84467d190859f4c8b20c1ff6c75'
    }) as Issuer

    const vcPayload: JwtCredentialPayload = {
      sub: 'did:ethr:0x435df3eda57154cf8cf7926079881f2912f54db4',
      nbf: 1562950282,
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        credentialSubject: {
          degree: {
            type: 'BachelorDegree',
            name: 'Baccalauréat en musiques numériques'
          }
        }
      }
    }

    const vcJwt = await createVerifiableCredentialJwt(vcPayload, issuer)
    expect(vcJwt).toBe("eyJhbGciOiJFUzI1NkstUiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRlZ3JlZSI6eyJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUiLCJuYW1lIjoiQmFjY2FsYXVyw6lhdCBlbiBtdXNpcXVlcyBudW3DqXJpcXVlcyJ9fX0sInN1YiI6ImRpZDpldGhyOjB4NDM1ZGYzZWRhNTcxNTRjZjhjZjc5MjYwNzk4ODFmMjkxMmY1NGRiNCIsIm5iZiI6MTU2Mjk1MDI4MiwiaXNzIjoiZGlkOmV0aHI6MHhGMTIzMkY4NDBmM2FEN2QyM0ZjRGFBODRkNkM2NmRhYzI0RUZiMTk4In0.BO15QQyc7pQKTxGy7OTp-ZUIsNBkNFkBnVJmFTcsltc3vSP10qVT57IiURDSb6onaioS7Bd499K8yp83OYx4gwA");
  })

  it('Issues a simple Antelope credential signed by one key', async () => {
    const did = "did:eosio:jungle:tonomytester";

    const keyIssuer1: Issuer = {
      did: did + "#key-1",
      signer: createSigner(PrivateKey.from("5KH76LoG9PhgjQqXCExJP5bHxShk5K6A7QHj723k2AdX5NYUHt7")),
      alg: "ES256K"
    }

    const vcPayload: JwtCredentialPayload = {
      sub: did,
      nbf: 1562950282,
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        credentialSubject: {
          degree: {
            type: 'BachelorDegree',
            name: 'Baccalauréat en musiques numériques'
          }
        }
      }
    }

    const vcJwt = await createVerifiableCredentialJwt(vcPayload, keyIssuer);
    const decodedJwt = decodeJWT(vcJwt);
    console.log(decodedJwt);
  })

  it('Issues a simple Antelope credential signed by one key', async () => {

    const did = "did:eosio:jungle:tonomytester";

    const keyIssuer1: Issuer = {
      did: did + "#key-1",
      signer: createSigner(PrivateKey.from("5KH76LoG9PhgjQqXCExJP5bHxShk5K6A7QHj723k2AdX5NYUHt7")),
      alg: "ES256K"
    }
    const keyIssuer2: Issuer = {
      did: did + "#key-1",
      signer: createSigner(PrivateKey.from("5KH76LoG9PhgjQqXCExJP5bHxShk5K6A7QHj723k2AdX5NYUHt7")),
      alg: "ES256K"
    }
    const keyIssuer3: Issuer = {
      did: did + "#key-1",
      signer: createSigner(PrivateKey.from("5KH76LoG9PhgjQqXCExJP5bHxShk5K6A7QHj723k2AdX5NYUHt7")),
      alg: "ES256K"
    }

    const vcPayload: JwtCredentialPayload = {
      sub: did,
      nbf: 1562950282,
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        credentialSubject: {
          degree: {
            type: 'BachelorDegree',
            name: 'Baccalauréat en musiques numériques'
          }
        }
      }
    }
    const vcJwtWith1Signatures = await createVerifiableCredentialJwt(vcPayload, keyIssuer1);

    const vcJwtWith2Signatures = await createVerifiableCredentialJwt(vcPayload, [keyIssuer1, keyIssuer2]);

    const vcJwtWith3Signatures = await addSignatureToJwt(vcJwtWith2Signatures, keyIssuer3);

    const decodedJwt = decodeJWT(vcJwt);
    console.log(decodedJwt);
  })
})