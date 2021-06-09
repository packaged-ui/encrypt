import {encryptFn as nativeEncrypt} from './impl/encrypt/native.js';
import {encryptFn as polyEncrypt} from './impl/encrypt/poly.js';
import {digestFn as nativeDigest} from './impl/digest/native.js';
import {digestFn as polyDigest} from './impl/digest/poly.js';
import {getNativeCrypto} from "./utils/crypto";

export const encrypt = getNativeCrypto() ? nativeEncrypt : polyEncrypt;
export const digest = getNativeCrypto() ? nativeDigest : polyDigest;
