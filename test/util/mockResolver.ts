import {
  createDIDDocument,
  antelopeChainRegistry,
  checkDID,
} from '@tonomy/antelope-did';
import { parse, DIDDocument } from '@tonomy/did-resolver';

type AntelopePermission = {
    threshold: number;
    keys: {
        key: string;
        weight: number;
    }[]
    accounts: {
        permission: {
        permission: string;
        actor: string;
        }
        weight: number
    }[]
}

export function createResolver(required_auth: AntelopePermission | AntelopePermission []) {
    return {
        resolve: async (did: string) => {
            const parsed = parse(did);
            if (!parsed) throw new Error('could not parse did');
            const methodId = checkDID(parsed, antelopeChainRegistry);
            if (!methodId) throw new Error('invalid did');
            
            let didDoc: DIDDocument;
            
            let auth: AntelopePermission[]
            if (!Array.isArray(required_auth)) {
                auth = [required_auth]
            } else {
                auth = required_auth
            }
            const mockAccountResponse = {
                    permissions: auth.map((permission, index) => {
                        return {
                        perm_name: "permission" + index,
                        parent: "owner",
                        required_auth: permission
                    }
                })
            }
            didDoc = createDIDDocument(methodId, parsed.did, mockAccountResponse);
            
            return {
                didResolutionMetadata: {},
                didDocument: didDoc,
                didDocumentMetadata: {},
            };
        },
    }
}