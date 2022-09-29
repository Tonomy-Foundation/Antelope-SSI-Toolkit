import { Name, PrivateKey, PublicKey } from '@greymass/eosio';
import { Signer as JWTSigner } from 'did-jwt';

type url = string;
type did = url;
type didurl = string;
type JWT = string;

interface CredentialUnsigned {
    "@context": url[];
    id: did;
    type: string[];
    issuer?: url;
    issuanceDate?: Date;
    credentialSubject: object;
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
    privateKey?: PrivateKey;
    signer?: JWTSigner,
    publicKey: PublicKey
}

enum OutputType {
    JWT = "JWT",
    JSONLD = "JSONLD"
}

namespace OutputType {
    /* 
     * Returns the index of the enum value
     * 
     * @param value The value to get the index of
     */
    export function indexFor(value: OutputType): number {
        return Object.keys(OutputType).indexOf(value);
    }

    /* 
     * Creates an OutputType from a string or index of the level
     * 
     * @param value The string or index
     */
    export function from(value: number | string): OutputType {
        let index: number
        if (typeof value !== 'number') {
            index = OutputType.indexFor(value as OutputType)
        } else {
            index = value
        }
        return Object.values(OutputType)[index] as OutputType;
    }
}

type CredentialOptions = {
    account: Name;
    permission: Name;
    signer: Signer | Signer[];
    outputType: OutputType;
}

export { CredentialUnsigned, CredentialSigned, Proof, JwsProof, Signer, JWT, OutputType, CredentialOptions };