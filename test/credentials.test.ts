// Fix for https://stackoverflow.com/questions/68468203/why-am-i-getting-textencoder-is-not-defined-in-jest
import { TextEncoder, TextDecoder } from 'util'
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder as any;

import { Name } from '@greymass/eosio';
import { createSigner, issue } from '../src/credentials';
import { CredentialUnsigned, OutputType } from '../src/credentials.types';
import { createPrivateKey } from './util/util';

describe('Issue and verify credential', () => {

    it('Issues a credential with a single signature', async () => {
        const now = new Date();

        const vc: CredentialUnsigned = {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            id: "https://example.com/id/1234324",
            type: ['VerifiableCredential'],
            issuer: "did:eosio:telos:university1",
            issuanceDate: now,
            credentialSubject: {
                degree: {
                    type: 'BachelorDegree',
                    name: 'Baccalauréat en musiques numériques'
                }
            }
        }

        const privateKey = createPrivateKey()

        console.log(privateKey.toString());
        const vcJwt = await issue(vc, {
            account: Name.from("university1"),
            permission: Name.from("active"),
            signer: { signer: createSigner(privateKey), publicKey: privateKey.toPublic() },
            outputType: OutputType.JWT
        }, { chainId: "telos" });

        expect(vcJwt).toBe("eyJhbGciOiJFUzI1NkstUiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRlZ3JlZSI6eyJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUiLCJuYW1lIjoiQmFjY2FsYXVyw6lhdCBlbiBtdXNpcXVlcyBudW3DqXJpcXVlcyJ9fX0sInN1YiI6ImRpZDpldGhyOjB4NDM1ZGYzZWRhNTcxNTRjZjhjZjc5MjYwNzk4ODFmMjkxMmY1NGRiNCIsIm5iZiI6MTU2Mjk1MDI4MiwiaXNzIjoiZGlkOmV0aHI6MHhGMTIzMkY4NDBmM2FEN2QyM0ZjRGFBODRkNkM2NmRhYzI0RUZiMTk4In0.BO15QQyc7pQKTxGy7OTp-ZUIsNBkNFkBnVJmFTcsltc3vSP10qVT57IiURDSb6onaioS7Bd499K8yp83OYx4gwA");
    })
})