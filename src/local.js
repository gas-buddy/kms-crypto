import crypto from 'crypto';
import ohash from 'object-hash';
import { getLogger } from './logger';

const asymmetricVersion = Buffer.from([1]);
const ciphers = {};

function removeLocal(name) {
  return name.substring('local:'.length);
}

// Use a closure to provide a modicum of protection
function Cipher(key) {
  return {
    encrypt(context, plaintext) {
      const hash = ohash({
        context,
        plain: plaintext.toString('base64'),
      }, {
        algorithm: 'sha256',
        encoding: 'buffer',
      });
      const textAndHash = Buffer.concat([hash, plaintext]);
      const cipherText = crypto.publicEncrypt(key, textAndHash);
      return Buffer.concat([asymmetricVersion, cipherText]);
    },
    decrypt(context, cipherBuf) {
      if (cipherBuf.length < 33 || cipherBuf[0] !== asymmetricVersion[0]) {
        return null;
      }
      try {
        const textAndHash = crypto.privateDecrypt(key, cipherBuf.slice(1));
        const plainText = textAndHash.slice(32);
        const hash = ohash({
          context,
          plain: plainText.toString('base64'),
        }, {
          algorithm: 'sha256',
          encoding: 'buffer',
        });
        if (textAndHash.slice(0, 32).compare(hash) !== 0) {
          return null;
        }
        return plainText;
      } catch (err) {
        getLogger().error('Decryption failed', err);
        return null;
      }
    },
  };
}

export function configure(config) {
  for (const [name, key] of Object.entries(config)) {
    ciphers[name] = new Cipher(key);
  }
}

export async function decrypt(context, ciphered) {
  const keyNameLen = ciphered.readUInt16BE(0);
  const keyName = ciphered.slice(2, 2 + keyNameLen).toString();
  const plain = ciphers[keyName].decrypt(context, ciphered.slice(2 + keyNameLen));
  return plain;
}

export async function encrypt(keyArn, context, plaintext) {
  const plainBuffer = Buffer.from(plaintext);
  const szBuf = Buffer.alloc(2);
  const arnInfo = Buffer.from(keyArn.substring('local:'.length));
  szBuf.writeUInt16BE(arnInfo.byteLength);
  return Buffer.concat([
    szBuf,
    arnInfo,
    ciphers[removeLocal(keyArn)].encrypt(context, plainBuffer),
  ]);
}

export async function generateDataKey(keyUri, context) {
  const random = crypto.randomBytes(32);
  const cipher = await encrypt(keyUri, context, random);
  return [random, cipher];
}
