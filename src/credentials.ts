import { ICredentials, CredentialUnsigned, CredentialSigned, Proof, JwsProof, Signer } from './credentials.types';
import { EosioOptions } from 'eosio-did';
import { createVerifiableCredentialJwt, Issuer, JwtCredentialPayload } from 'did-jwt-vc';
import { Name, PrivateKey, KeyType, PublicKey } from '@greymass/eosio';
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

export function keyToAlgo(publicKey: PublicKey): string {
    if (publicKey.type === KeyType.K1) {
        return 'ES256K';
    }
    if (publicKey.type === KeyType.R1 || publicKey.type === KeyType.WA) {
        return 'ES256R';
    }
    throw new Error('Unsupported key type');
}


class Credentials implements ICredentials {
    _options: EosioOptions;
    constructor(options: EosioOptions) {
        this._options = options;
    }

    get options(): EosioOptions {
        return this._options;
    }

    set options(options: EosioOptions) {
        this._options = options;
    }

    async issue(credential: CredentialUnsigned, account: Name, permission: Name, signer: Signer | Signer[], options?: EosioOptions): Promise<CredentialSigned> {
        let did = "did:eosio:";
        if (options && options.chainId) {
            did += options.chainId;
        } else if (this._options && this._options.chainId) {
            did += this._options.chainId;
        } else {
            throw Error("No chainId provided");
        }
        did += account.toString();
        did += "#" + permission.toString();

        const vcPayload: JwtCredentialPayload = {
            jti: credential.id,
            vc: credential,
            sub: credential.credentialSubject
        }

        if (!Array.isArray(signer)) {
            const issuer = {
                did: did + "-key-1",
                signer,
                alg: keyToAlgo(signer.publicKey)
            }
            return await createVerifiableCredentialJwt(vcPayload, issuer);
        } else {
            // TODO
        }
    }


    async addSignature(credential: CredentialSigned, signer: Signer, options?: EosioOptions): Promise<CredentialSigned> {
        throw Error("Not implemented");
    }

    async verify(credential: CredentialSigned, options?: EosioOptions): Promise<boolean> {
        throw Error("Not implemented");
    }
}