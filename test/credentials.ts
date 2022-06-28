import Credentials, { CredentialUnsigned } from '../src/credentials';

describe('Issue and verify credential', () => {
  it('Issues a credential', async () => {

    const myId = "did:eosio:telos:mytelosaccount";
    const universityId = "did:eosio:telos:exampleuniversity";
    const universityVerificationMethod = "did:eosio:telos:exampleuniversity#active";

    const credential: CredentialUnsigned = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      id: myId,
      type: ["VerifiableCredential", "AlumniCredential"],
      issuer: universityId,
      issuanceDate: new Date("2010-01-01T19:23:24Z"),
      credentialSubject: {
        id: myId,
        alumniOf: "Example University"
      }
    };

    const credentials = new Credentials();
    const signedCredential = await credentials.issue(universityVerificationMethod, credential);
    console.log(signedCredential);

    const verifiedCreedential = await credentials.verify(signedCredential);
    console.log(verifiedCreedential);

    expect(signedCredential).toBeDefined();
  });
});
