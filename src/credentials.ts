import { EosioOptions, Authority } from 'eosio-did';

type url = string;
type did = url;

interface CredentialUnsigned {
    "@context": url[];
    id: did;
    type: string[];
    issuer: url;
    issuanceDate: Date;
    credentialSubject: object;
}

interface Proof {
    type: string;
    created: Date;
    proofPurpose: string;
    verificationMethod: url;
}

interface JwsProof extends Proof {
    jws: string;
}

interface CredentialSigned extends CredentialUnsigned {
    proof: Proof
}

export default interface Credentials {
    _options: EosioOptions;
    constructor(options: EosioOptions): null;
    get options(): EosioOptions;
    set options(options: EosioOptions);

    issue(id: did, verificationMethod: string, options?: EosioOptions): Promise<CredentialSigned>;
    verify(did: string, options?: EosioOptions): Promise<boolean>;
}

export { CredentialUnsigned, CredentialSigned, Proof, JwsProof };