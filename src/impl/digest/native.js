import {getNativeCrypto} from "../../utils/crypto.js";
import {arrayBufferToHex, promisify, stringToArrayBuffer} from "../../utils/utils.js";

/**
 * @param {string} data
 * @param {string} algorithm
 * @return {Promise<string>}
 */
export function digestFn(data, algorithm = 'SHA-512')
{
  return promisify(getNativeCrypto().subtle.digest(algorithm, stringToArrayBuffer(data)))
    .then(arrayBufferToHex);
}
