import {encryptFn as poly} from "../src/impl/poly";
import {encryptFn as native, hasNative} from "../src/impl/native";
import {encrypt} from "../src";
import chai from "chai/chai";
import chaiAsPromised from 'chai-as-promised';

import {byteArrayToString, hexToArrayBuffer} from "../src/utils/utils";
import pki from "node-forge/lib/pki";
import sha512 from 'node-forge/lib/sha512';

chai.use(chaiAsPromised);

const privKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDZQlLpUOy95NTS
fE8eamKQvMil8G+1LWInL0X3GnFlrQuRpCXF0Fe8+f1xHUDiU/qIsuCOsaUrrBA0
81q+JIHFLCp/buDvsUmS4nyhegJfSvA2ZPRzkqzRx/KL6w5rEkcj3f21VYBqjVDZ
u1mGW2WGQIQ5mkK177PDzl13YI3xYagEikXobLdqkbgdwuRjjoWjur8ifMBYWr8g
SqAaX7MT+Xabgw7V/lAQu5eX9QjQ+WbcDc95ZlLPFsG05NMLXO2MzEskx+fRKkAR
7+AOo/70rmDZmTM9CvgKD7ayiZ31x9WOhxMoAo6b9NO5bsLOrgKL1h/zQsU1ViVz
Y4VE03zLAgMBAAECggEAAuJUg3BllCfDg3/O9RJoeI9pAnrsoLUXhnmkLiGVu8nO
S4KoVbXsVD/lU2kWAWsn+kSVoo9NKAVCudE5NSj66AksD0EDj2sFFQQYr3QVL/qo
sbApZpdd3/MNjznxmQ5HD3zU72FRMRjrJ9jK2XPBJ0UX/EPF+vBRrJnCt+D6QWgK
MtSU/MQiaSrJZ2A1rkY3tLVmBb0c/AQKfnVjmJ7ENACXniiiJjxnYC+SgSuNgsfr
SlNRUv3Tj0UDl7adPdVzMRa3xT9rN5BcrAcZZYhaJtLC8huWUE0rfnBDE/2Vq3us
uVKl76dZo6qV1/CkE0xzwfubX95Sdj2Vk+byAx3/sQKBgQD7LPj/c+MV1mO567Mu
oRzcXhw+VqC0AaF8uSXsAmDrjp+5REkU7yM1DQ+fPNoMyprGVuq5Y7eprvS0i7On
wIpzJehby10C2a/MKGWYqAZoSMvkKBTZwTSbbjVIbjPgyq6R9b0hyvqrX2ljJg4r
OnuedGIKBbva8xzCotwbPSTuLQKBgQDdbpVyyPPN7BpnfYD7D5FyRLSmtu19lpGt
89Smji2eGWuBrkBb7SqrBlXYW61Sb+FBHDRBiwt7fPK3nREb2/rIg8D11T4H/OYU
dav+PX59m7nyujARuARTTtSwGvHK+nIRR8KCoq87NpfxTcqEw7XnyfUoU22DGsfb
m/9+m/tp1wKBgACj2bKU8gQxOqnTnu5EfNVW7A2AnQI4atfthNo4G1UeVOvc7668
+UL+WIbYWdnkfkZ5HDoCtgoZpwf6vydzRycJ9rCdMQx7z4XeqHueGf4UCWj4bS0s
39xxiHM5zKoK+iznCmdWpBLhuFwHUcvsZzo9I67Q2uyw5+bbEWKEYl61AoGBAI8v
FMB2pQCBLcnB5Ad0V662MsKjAwr0tBrx0o4o3eKfuV7P2JoY0EBrBlOzZG4sHlJF
9Jx1VuVxNFn63LdRFedXGw1b6JKtu/F67c6m4QZEDoegUbkDbviXvvxpT/Ta4au+
5U4n+Hunn7TPgqc7DoNlmnuLBwOB675cL2glYPtdAoGAOJWN5OVD+xrxIeOXRFlW
ZU+XIyiye473Wue7WyjRrHWvWvHgWVqOkPvDxEYWPn/qQ/K2ybUfp5AIjEoE2V1o
yX4q+jljBra8A3F9uxLF4xJM+ecyFs6QS49p5vUuH9o71idAorPWkey3puM1eVF1
wB546Vx1hVe50iMOxQiF/Zs=
-----END PRIVATE KEY-----`;
const pubKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2UJS6VDsveTU0nxPHmpi
kLzIpfBvtS1iJy9F9xpxZa0LkaQlxdBXvPn9cR1A4lP6iLLgjrGlK6wQNPNaviSB
xSwqf27g77FJkuJ8oXoCX0rwNmT0c5Ks0cfyi+sOaxJHI939tVWAao1Q2btZhltl
hkCEOZpCte+zw85dd2CN8WGoBIpF6Gy3apG4HcLkY46Fo7q/InzAWFq/IEqgGl+z
E/l2m4MO1f5QELuXl/UI0Plm3A3PeWZSzxbBtOTTC1ztjMxLJMfn0SpAEe/gDqP+
9K5g2ZkzPQr4Cg+2somd9cfVjocTKAKOm/TTuW7Czq4Ci9Yf80LFNVYlc2OFRNN8
ywIDAQAB
-----END PUBLIC KEY-----`;
const modulusHex = 'D94252E950ECBDE4D4D27C4F1E6A6290BCC8A5F06FB52D62272F45F71A7165AD0B91A425C5D057BCF9FD711D40E253FA88B2E08EB1A52BAC1034F35ABE2481C52C2A7F6EE0EFB14992E27CA17A025F4AF03664F47392ACD1C7F28BEB0E6B124723DDFDB555806A8D50D9BB59865B65864084399A42B5EFB3C3CE5D77608DF161A8048A45E86CB76A91B81DC2E4638E85A3BABF227CC0585ABF204AA01A5FB313F9769B830ED5FE5010BB9797F508D0F966DC0DCF796652CF16C1B4E4D30B5CED8CCC4B24C7E7D12A4011EFE00EA3FEF4AE60D999333D0AF80A0FB6B2899DF5C7D58E871328028E9BF4D3B96EC2CEAE028BD61FF342C535562573638544D37CCB';
const modulusB64 = btoa(byteArrayToString(new Uint8Array(hexToArrayBuffer(modulusHex))));
const exponentB64 = btoa(byteArrayToString(new Uint8Array(hexToArrayBuffer('010001'))));

const key = {n: modulusB64, e: exponentB64};

const decryptKey = pki.privateKeyFromPem(privKey);
const encryptKey = pki.setRsaPublicKey(decryptKey.n, decryptKey.e);
chai.assert.equal(decryptKey.decrypt(encryptKey.encrypt('test')), 'test');

describe('helper', function ()
{
  it('match', function ()
  {
    chai.assert.isFunction(encrypt);
    if(window.crypto)
    {
      chai.assert.equal(encrypt, native);
    }
    else
    {
      chai.assert.equal(encrypt, poly);
    }
  });
});

describe('polyfill', function ()
{
  it('poly priv', function ()
  {
    return chai.assert.isRejected(
      poly('test', privKey, {
        name: "RSA-OAEP", hash: "SHA-512",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
      }),
      'private keys not supported'
    )
  });

  it('poly pubkey', function ()
  {
    return chai.assert.becomes(
      poly('test', pubKey, {name: "RSA-OAEP", hash: "SHA-512"})
        .then(enc => decryptKey.decrypt(byteArrayToString(new Uint8Array(enc)), 'RSA-OAEP', {md: sha512.create()})),
      'test'
    );
  });

  it('poly modulus', function ()
  {
    return chai.assert.becomes(
      poly('test', key, {name: "RSA-OAEP", hash: "SHA-512"})
        .then(enc => decryptKey.decrypt(byteArrayToString(new Uint8Array(enc)), 'RSA-OAEP', {md: sha512.create()})),
      'test'
    );
  });
});

describe('native', function ()
{
  before(function () {hasNative() || this.skip()});

  it('native priv', function ()
  {
    return chai.assert.isRejected(
      native('test', privKey, {
        name: "RSA-OAEP", hash: "SHA-512",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
      }),
      'private keys not supported'
    )
  });

  it('native pubkey', function ()
  {
    return chai.assert.becomes(
      native('test', pubKey, {name: "RSA-OAEP", hash: "SHA-512"})
        .then(enc => decryptKey.decrypt(byteArrayToString(new Uint8Array(enc)), 'RSA-OAEP', {md: sha512.create()})),
      'test'
    );
  });

  it('native modulus', function ()
  {
    return chai.assert.becomes(
      native('test', key, {name: "RSA-OAEP", hash: "SHA-512"})
        .then(enc => decryptKey.decrypt(byteArrayToString(new Uint8Array(enc)), 'RSA-OAEP', {md: sha512.create()})),
      'test'
    );
  });
});
