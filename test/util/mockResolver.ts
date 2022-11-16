import {
  createDIDDocument,
  antelopeChainRegistry,
  checkDID,
} from 'antelope-did';
import { parse, DIDDocument } from 'did-resolver';

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

export function createResolver(required_auth: AntelopePermission, required_auth2?: AntelopePermission) {
    return {
        resolve: async (did: string) => {
            const parsed = parse(did);
            if (!parsed) throw new Error('could not parse did');
            const methodId = checkDID(parsed, antelopeChainRegistry);
            if (!methodId) throw new Error('invalid did');
            
            let didDoc: DIDDocument;
            console.log('parsed', parsed);
            if (parsed.id === 'jackacc' && required_auth2) {
                const account = {
                    permissions: [{
                    perm_name: "active",
                    parent: "owner",
                    required_auth
                    }]
                }
                didDoc = createDIDDocument(methodId, parsed.did, account);    
            } else {
                const account = {
                    permissions: [{
                    perm_name: "active",
                    parent: "owner",
                    required_auth
                    }]
                }
                didDoc = createDIDDocument(methodId, parsed.did, account);    
            }
            console.log('didDoc', JSON.stringify(didDoc, null, 2))
            
            return {
                didResolutionMetadata: {},
                didDocument: didDoc,
                didDocumentMetadata: {},
            };
        },
    }
}