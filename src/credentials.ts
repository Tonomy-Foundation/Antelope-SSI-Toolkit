import { CredentialOptions, OutputType } from './credentials.types';
import { createVerifiableCredentialJwt, verifyCredential, W3CCredential } from '@tonomy/did-jwt-vc';
import { getResolver } from '@tonomy/antelope-did-resolver';
import { PrivateKey, KeyType } from '@greymass/eosio';
import { ES256KSigner, ES256Signer, Signer } from '@tonomy/did-jwt'
import { JWT } from '@tonomy/did-jwt-vc/lib/types';
import { Resolver } from '@tonomy/did-resolver'

/* Creates a signer from a private key that can be used to sign a JWT
 *
 * @param privateKey the private key to use to sign the JWT
 * @returns a signer (function) that can be used to sign a JWT
 */
export function createSigner(privateKey: PrivateKey): Signer {
    if (privateKey.type === KeyType.K1) {
        return ES256KSigner(privateKey.data.array, true);
    }
    if (privateKey.type === KeyType.R1 || privateKey.type === KeyType.WA) {
        return ES256Signer(privateKey.data.array);
    }
    throw new Error('Unsupported key type');
}

/**
 * Issues a verifiable credential
 * 
 * @param credential the verifiable credential to issue
 * @param credentialOptions  the options to issue the credential with 
 * @returns the issued jwt credential signed by one or more issuers
 */
export async function issue(credential: W3CCredential, credentialOptions: CredentialOptions): Promise<JWT> {
    if (credentialOptions.outputType && credentialOptions.outputType !== OutputType.JWT) {
        throw new Error('Only JWT output type is supported for now');
    }

    // TODO return the full W3C version as well?
    return await createVerifiableCredentialJwt(credential, credentialOptions.issuer, { canonicalize: true });
}

/**
 * Verifies a credential signed by a did:antelope or did:eosio issuer
 * For a more complete verification result, use the verifyCredential function from @tonomy/did-jwt-vc
 * 
 * @param credential the signed jwt verifiable credential to verify
 * @param credentialOptions  the options to verify the credential with 
 * 
 * @returns true if the signature matches the issuer
 */
export async function verify(verifiableCredential: JWT, options?: CredentialOptions): Promise<boolean> {
    const resolver = new Resolver(getResolver());
    return !! await verifyCredential(verifiableCredential, resolver, options);
}
