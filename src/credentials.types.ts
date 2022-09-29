import { Issuer } from 'did-jwt-vc';

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
    account: string;
    permission: string;
    issuer: Issuer | Issuer[];
    outputType: OutputType;
}

export { OutputType, CredentialOptions };