import { CredentialOptions, OutputType } from './credentials.types';
import { createVerifiableCredentialJwt, verifyCredential, W3CCredential } from 'did-jwt-vc';
import { PrivateKey, KeyType, PublicKey } from '@greymass/eosio';
import { ES256KSigner, ES256Signer } from 'did-jwt'
import { JWT } from 'did-jwt-vc/lib/types';

export function createSigner(privateKey: PrivateKey) {
    if (privateKey.type === KeyType.K1) {
        return ES256KSigner(privateKey.data.array, true);
    }
    if (privateKey.type === KeyType.R1 || privateKey.type === KeyType.WA) {
        return ES256Signer(privateKey.data.array);
    }
    throw new Error('Unsupported key type');
}

export function keyToJwsAlgo(publicKey: PublicKey): string {
    if (publicKey.type === KeyType.K1) {
        return 'ES256K';
    }
    if (publicKey.type === KeyType.R1) {
        return 'ES256R';
    }
    throw new Error('Unsupported key type');
}

/**
 * Issues a verifiable credential
 * @param credential the verfiable credential to issue
 * @param credentialOptions  the options to issue the credential with 
 * @returns the issued credential signed by one or more issuers
 */
export async function issue(credential: W3CCredential, credentialOptions: CredentialOptions): Promise<JWT> {
    if (credentialOptions.outputType && credentialOptions.outputType !== OutputType.JWT) {
        throw new Error('Only JWT output type is supported for now');
    }

    // TODO return the full version as well?
    return await createVerifiableCredentialJwt(credential, credentialOptions.issuer, { canonicalize: true });
}

// TODO asynchroneously add signatures to the credential
// export async function addSignature(credential: VerifiableCredential, credentialOptions: CredentialOptions, options?: EosioOptions): Promise<CredentialSigned> {
//     throw Error("Not implemented");
// }

export async function verify(verifiableCredential: JWT, options?: CredentialOptions): Promise<boolean> {
    // return false
    return !! await verifyCredential(verifiableCredential, {} as any, options);
}
