import {encryptFn as nativeEncrypt} from './impl/encrypt/native.js';
import {encryptFn as polyEncrypt} from './impl/encrypt/poly.js';
import {digestFn as nativeDigest} from './impl/digest/native.js';
import {digestFn as polyDigest} from './impl/digest/poly.js';
import {getNativeCrypto} from "./utils/crypto.js";

/**
 * @type {function(data: string, publicKey: (string|pkObj), algorithm: Object): Promise<ArrayBuffer>}
 */
export const encrypt = getNativeCrypto() ? nativeEncrypt : polyEncrypt;
/**
 * @type {function(data: string, algorithm: string=): Promise<string>}
 */
export const digest = getNativeCrypto() ? nativeDigest : polyDigest;
