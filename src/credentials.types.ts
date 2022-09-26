import { Name, PrivateKey, PublicKey } from '@greymass/eosio';
import { EosioOptions } from 'eosio-did';
import { Signer as JWTSigner } from 'did-jwt';

type url = string;
type did = url;
type didurl = string;

interface CredentialUnsigned {
    "@context": url[];
    id: did;
    type: string[];
    issuer?: url;
    issuanceDate?: Date;
    credentialSubject: url;
    evidence?: object;
    termsOfUse?: object;
}

interface Proof {
    type: string;
    created: Date;
    proofPurpose?: string;
    verificationMethod: didurl;
}

interface JwsProof extends Proof {
    jws: string;
}

interface CredentialSigned extends CredentialUnsigned {
    proof: Proof
}

type Signer = {
    signer: JWTSigner,
    publicKey: PublicKey
}

export default interface ICredentials {
    _options: EosioOptions;
    constructor(options: EosioOptions): null;
    get options(): EosioOptions;
    set options(options: EosioOptions);

    issue(credential: CredentialUnsigned, signer: Signer | Signer[], options?: EosioOptions): Promise<CredentialSigned>;
    addSignature(credential: CredentialSigned, signer: Signer, options?: EosioOptions): Promise<CredentialSigned>;

    verify(credential: CredentialSigned, options?: EosioOptions): Promise<boolean>;
}

export { ICredentials, CredentialUnsigned, CredentialSigned, Proof, JwsProof, Signer };