import {b64tob64u, stringToArrayBuffer} from "../utils/utils";

const cryptoObj = window.crypto || window.webkitCrypto || window.mozCrypto || window.msCrypto;

export function hasNative()
{
  return !!cryptoObj;
}

/**
 * @param {string|pkObj} publicKey
 * @param {string} data
 * @param {object} algorithm
 * @return {Promise<ArrayBuffer>}
 */
export function encryptFn(data, publicKey, algorithm)
{
  if(!hasNative())
  {
    throw new Error('no native implementation');
  }

  return new Promise(
    (resolve, reject) =>
    {
      if(!publicKey)
      {
        reject('no public key');
      }

      try
      {
        // import key
        let importPromise;
        if(publicKey.n && publicKey.e)
        {
          importPromise = _promisify(cryptoObj.subtle.importKey(
            "jwk",
            {"kty": "RSA", "n": b64tob64u(publicKey.n), "e": b64tob64u(publicKey.e)},
            algorithm,
            true,
            ["encrypt"]
          ));
        }
        else
        {
          // strip header and footer
          if(/^-----BEGIN PRIVATE/.test(publicKey))
          {
            reject('private keys not supported');
            return;
          }
          const stripped = atob(publicKey.replace(/^-----(BEGIN|END).+$/mg, '').trim());
          importPromise = _promisify(cryptoObj.subtle.importKey(
            'spki',
            stringToArrayBuffer(stripped),
            algorithm,
            false,
            ['encrypt']
          ));
        }

        importPromise.then(
          (importedKey) =>
          {
            // encrypt using imported key
            _promisify(cryptoObj.subtle.encrypt(algorithm, importedKey, stringToArrayBuffer(data)))
              .then(resolve)
              .catch(reject)
          }).catch(reject);
      }
      catch(err)
      {
        reject(err)
      }
    });
}

function _promisify(p)
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
