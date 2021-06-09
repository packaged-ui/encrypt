/**
 * Convert array buffer to Hex String
 *
 * @param {ArrayBuffer} buffer
 * @return {String}
 */
export function arrayBufferToHex(buffer)
{
  return Array.from(new Uint8Array(buffer)).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert a hex string into a ByteArray
 * @param {String} hex
 * @return {ArrayBuffer}
 */
export function hexToArrayBuffer(hex)
{
  return Uint8Array.from(hex.match(/.{2}/g).map((hex) => parseInt(hex, 16))).buffer;
}

/**
 * Convert string to byte array
 *
 * @param {String} str
 * @return {ArrayBuffer}
 */
export function stringToArrayBuffer(str)
{
  return Uint8Array.from(Array.from(str).map(chr => chr.codePointAt(0))).buffer;
}

/**
 * Convert ByteArray to string
 *
 * @param {Uint8Array} ba
 * @return {String}
 */
export function byteArrayToString(ba)
{
  return Array.from(ba).map(b => String.fromCharCode(b)).join('')
}

const _b64uTable = {'=': '', '+': '-', '/': '_'};
const _b64Search = new RegExp('[' + Object.keys(_b64uTable) + ']', 'g');

/**
 * Convert Base64 string to URL-safe Base64 string (Base64urlUInt)
 * Required by JWA Key Data for RSA https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1
 *
 * @param {String} string
 * @return {String}
 */
export function b64tob64u(string)
{
  return string.replace(_b64Search, c => _b64uTable[c]);
}

export function promisify(p)
{
  if(p instanceof Promise)
  {
    return p;
  }
  if(p.hasOwnProperty('oncomplete'))
  {
    return new Promise(
      resolve =>
      {
        p.oncomplete = function (e)
        {
          resolve(e.target.result);
        }
      });
  }
  return p;
}
