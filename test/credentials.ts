import Credentials, { CredentialUnsigned } from '../src/credentials';

const jungleAccount1Key1 = '5Jr3KwQ2yB7sDhrZtGf4VcnwhfawWizibHBxc3kk6nXz9ZashS4';
const jungleAccount2Key1 = '5HugTPie8ajGCiWR5L82SkYjx8zQ79eawwTReMwHQgHZJuB1nKP';

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
    expect(signedCredential.proof).toBeDefined();
    expect(signedCredential.proof.jws).toBeDefined();

    const verifiedCreedential = await credentials.verify(signedCredential);
    expect(verifiedCreedential).toBeTruthy();
  });
});
