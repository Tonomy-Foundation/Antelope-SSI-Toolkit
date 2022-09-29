import { CredentialUnsigned, CredentialSigned, CredentialOptions, JWT, OutputType } from './credentials.types';
import { EosioOptions } from 'eosio-did';
import { createVerifiableCredentialJwt, Issuer, JwtCredentialPayload } from 'did-jwt-vc';
import { PrivateKey, KeyType, PublicKey } from '@greymass/eosio';
import { ES256KSigner, ES256Signer, Signer } from 'did-jwt'

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

export async function issue(credential: CredentialUnsigned, credentialOptions: CredentialOptions, options?: EosioOptions): Promise<CredentialSigned | JWT> {
    if (credentialOptions.outputType !== OutputType.JWT) {
        throw new Error('Only JWT output type is supported for now');
    }

    let did = "did:eosio:";
    if (options && options.chainId) {
        did += options.chainId;
    } else {
        throw Error("No chainId provided");
    }
    did += credentialOptions.account.toString();
    did += "#" + credentialOptions.permission.toString();

    const vcPayload: JwtCredentialPayload = {
        jti: credential.id,
        vc: credential
    }

    if (!Array.isArray(credentialOptions.signer)) {
        const issuer: Issuer = {
            did: did + "-key-1",
            signer: credentialOptions.signer.signer as Signer,
            alg: keyToJwsAlgo(credentialOptions.signer.publicKey)
        }
        return await createVerifiableCredentialJwt(vcPayload, issuer);
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
