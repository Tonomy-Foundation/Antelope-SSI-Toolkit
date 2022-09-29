import { CredentialOptions, OutputType } from './credentials.types';
import { createVerifiableCredentialJwt, VerifiableCredential, W3CCredential } from 'did-jwt-vc';
import { PrivateKey, KeyType, PublicKey } from '@greymass/eosio';
import { ES256KSigner, ES256Signer } from 'did-jwt'

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

export async function issue(credential: W3CCredential, credentialOptions: CredentialOptions): Promise<VerifiableCredential> {
    if (credentialOptions.outputType !== OutputType.JWT) {
        throw new Error('Only JWT output type is supported for now');
    }

    if (!Array.isArray(credentialOptions.issuer)) {
        return await createVerifiableCredentialJwt(credential, credentialOptions.issuer);
    } else {
        throw Error("Not implemented");
        // TODO
    }
}

// export async function addSignature(credential: CredentialSigned, credentialOptions: CredentialOptions, options?: EosioOptions): Promise<CredentialSigned> {
//     throw Error("Not implemented");
// }

// export async function verify(credential: CredentialSigned, options?: EosioOptions): Promise<boolean> {
//     throw Error("Not implemented");
// }
