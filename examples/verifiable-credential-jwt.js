const vcPayload = {
      sub: 'did:example:123',
      vc: {
          ...
          type: ['VerifiableCredential'],
          credentialSubject: {
            "id": "did:example:456",
            "alumniOf": {...}
      }
}

const vcJwt = await createVerifiableCredentialJwt(vcPayload, issuer)
console.log(vcJwt)
// eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQi...0CQmqB14NnN5XxD0d_glLRs1Myc_LBJjnuNwE




