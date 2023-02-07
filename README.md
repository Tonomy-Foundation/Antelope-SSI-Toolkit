# Antelope Self-sovereign identity (SSI) Toolkit

A toolkit allowing Antelope (formerly EOSIO) accounts to use SSI components:

- Verifiable Credentials
- DIDComm (planned)

## Install

```bash
npm i @tonomy/antelope-ssi-toolkit
```

## Usage

### Create a and verify a credential

```typescript
import { createSigner, issue, verify } from '@tonomy/antelope-ssi-toolkit';
import { PrivateKey } from "@greymass/eosio";

const vc = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    id: "https://example.com/id/1234324",
    type: ['VerifiableCredential'],
    issuer: {
        id: `did:antelope:telos:university`,
    },
    issuanceDate: (new Date()).toISOString(),
    credentialSubject: {
        degree: {
            type: 'BachelorDegree',
            name: 'Bachelor of Music'
        }
    }
}

const issuer = {
    did: "did:antelope:telos:university#active",
    signer: createSigner(PrivateKey.from("PVT_K1_2bfGi9rYsXQSXXTvJbDAPhHLQUojjaNLomdm3cEJ1XTzMqUt3V")),
    alg: 'ES256K-R'
}

const vcJwt = await issue(vc, {
    issuer
});

const isVerified = await verify(vcJwt);
```

## Development

TSDX scaffolds your new library inside `/src`.

To run TSDX, use:

```bash
npm start # or yarn start
```

This builds to `/dist` and runs the project in watch mode so any edits you save inside `src` causes a rebuild to `/dist`.

To do a one-off build, use `npm run build` or `yarn build`.

To run tests, use `npm test` or `yarn test`.

## Publish

```bash
npm run build
npm publish
```
