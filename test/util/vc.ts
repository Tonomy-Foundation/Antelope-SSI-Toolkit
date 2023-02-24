import { JwtCredentialPayload } from "@tonomy/did-jwt-vc";

export const did = 'did:antelope:eos:testnet:jungle:reball1block';

export const vcPayload: JwtCredentialPayload = {
  sub: did,
  nbf: 1562950282,
  vc: {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    credentialSubject: {
      degree: {
        type: 'BachelorDegree',
        name: 'Baccalauréat en musiques numériques',
      },
    },
  },
};

export const tonomyDid = 'did:antelope:eos:testnet:jungle:tonomytest12';
export const tonomyVcPayload: JwtCredentialPayload = {
  sub: tonomyDid,
  nbf: 1562950282,
  vc: {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    credentialSubject: {
      degree: {
        type: 'BachelorDegree',
        name: 'Baccalauréat en musiques numériques',
      },
    },
  },
};

