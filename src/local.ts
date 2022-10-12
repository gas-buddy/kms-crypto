import crypto from 'crypto';
import ohash from 'object-hash';

import type { KmsCryptoProvider, KmsOperationContext, KmsProviderConfig } from './types';

const asymmetricVersion = Buffer.from([1]);

// Use a closure to provide a modicum of protection
function getCipher(key: string) {
  return {
    encrypt(context: KmsOperationContext, plaintext: string | Buffer) {
      const hash = ohash(
        {
          context,
          plain: plaintext.toString('base64'),
        },
        {
          algorithm: 'sha256',
          encoding: 'buffer',
        },
      );
      const textAndHash = Buffer.concat([Buffer.from(hash), Buffer.from(plaintext)]);
      const cipherText = crypto.publicEncrypt(key, textAndHash);
      return Buffer.concat([asymmetricVersion, cipherText]);
    },
    decrypt(context: KmsOperationContext, cipherBuf: Buffer) {
      if (cipherBuf.length < 33 || cipherBuf[0] !== asymmetricVersion[0]) {
        return null;
      }

      const textAndHash = crypto.privateDecrypt(key, cipherBuf.subarray(1));
      const plainText = textAndHash.subarray(32);
      const hash = ohash(
        {
          context,
          plain: plainText.toString('base64'),
        },
        {
          algorithm: 'sha256',
          encoding: 'buffer',
        },
      );
      if (textAndHash.subarray(0, 32).compare(Buffer.from(hash)) !== 0) {
        return null;
      }
      return plainText;
    },
  };
}

function removeLocal(name: string) {
  return name.substring('local:'.length);
}

export async function createLocalProvider(config: Required<KmsProviderConfig>['local']): Promise<KmsCryptoProvider> {
  const ciphers: Record<string, ReturnType<typeof getCipher>> = {};
  Object.entries(config).forEach(([key, value]) => {
    ciphers[key] = getCipher(value);
  });

  const closure: KmsCryptoProvider = {
    async decrypt(context: KmsOperationContext, ciphered: Buffer) {
      const keyNameLen = ciphered.readUInt16BE(0);
      const keyName = ciphered.subarray(2, 2 + keyNameLen).toString();
      const plain = ciphers[keyName].decrypt(context, ciphered.subarray(2 + keyNameLen));
      return plain || undefined;
    },
    async encrypt(keyArn: string, context: Record<string, any>, plaintext: string | Buffer) {
      const plainBuffer = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext);
      const szBuf = Buffer.alloc(2);
      const arnInfo = Buffer.from(keyArn.substring('local:'.length));
      szBuf.writeUInt16BE(arnInfo.byteLength);
      return Buffer.concat([
        szBuf,
        arnInfo,
        ciphers[removeLocal(keyArn)].encrypt(context, plainBuffer),
      ]);
    },
    async generateDataKey(keyArn: string, context: KmsOperationContext) {
      const random = crypto.randomBytes(32);
      const cipher = await closure.encrypt(keyArn, context, random);
      return {
        Plaintext: random,
        CiphertextBlob: cipher,
      };
    },
  };
  return closure;
}
