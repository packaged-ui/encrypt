import {getNativeCrypto} from "../../utils/crypto";
import {arrayBufferToHex, promisify, stringToArrayBuffer} from "../../utils/utils";

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
