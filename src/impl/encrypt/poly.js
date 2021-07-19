import {arrayBufferToHex, stringToArrayBuffer} from "../../utils/utils.js";
import pki from 'node-forge/lib/pki.js';
import md from 'node-forge/lib/md.all.js';
import jsbn from 'node-forge/lib/jsbn.js';

/**
 * @param {string|pkObj} publicKey
 * @param {string} data
 * @param {object} algorithm
 * @return {Promise<ArrayBuffer>}
 */
export function encryptFn(data, publicKey, algorithm)
{
  return new Promise(
    (resolve, reject) =>
    {
      if(!publicKey)
      {
        reject();
      }
      let key;
      if(publicKey.n && publicKey.e)
      {
        key = pki.setRsaPublicKey(_b64toBI(publicKey.n), _b64toBI(publicKey.e));
      }
      else
      {
        try
        {
          key = pki.publicKeyFromPem(publicKey);
        }
        catch(e)
        {
          if(/^Could not convert public key from PEM/.test(e.message))
          {
            reject('private keys not supported');
          }
          else
          {
            reject(e);
          }
          return;
        }
      }

      //{name: "RSA-OAEP", hash: "SHA-512"}
      const mda = md.algorithms[algorithm.hash.replace('-', '').toLowerCase()];
      const encrypted = key.encrypt(data, algorithm.name, {md: mda.create()});
      resolve(stringToArrayBuffer(encrypted));
    });
}

function _b64toBI(data)
{
  return new jsbn.BigInteger(arrayBufferToHex(stringToArrayBuffer(atob(data))), 16);
}
