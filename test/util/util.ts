import { Bytes, KeyType, PrivateKey } from "@greymass/eosio";
import crypto from 'crypto';

export function createPrivateKey(): PrivateKey {
    return new PrivateKey(KeyType.K1, Bytes.from(crypto.randomBytes(32)));
}
