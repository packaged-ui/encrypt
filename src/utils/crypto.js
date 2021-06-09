const cryptoObj = window.crypto || window.webkitCrypto || window.mozCrypto || window.msCrypto || undefined;

export function getNativeCrypto()
{
  return cryptoObj;
}
