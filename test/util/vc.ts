import { JwtCredentialPayload } from "did-jwt-vc";

export const did = 'did:antelope:eos:testnet:jungle:reball1block';

export const vcPayload: JwtCredentialPayload = {
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