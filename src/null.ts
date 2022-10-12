import ohash from 'object-hash';
import crypto from 'crypto';
import type { KmsCryptoProvider } from './types';

export function nullProvider(): KmsCryptoProvider {
  const closure: KmsCryptoProvider = {
    async decrypt(context, cipher) {
      const plainBuf = JSON.parse(cipher.toString());
      const hash = ohash(context);
      if (hash !== plainBuf.hash) {
        return undefined;
      }
      return Buffer.from(plainBuf.plain, 'base64');
    },
    async encrypt(key, context, plain) {
      const blob = JSON.stringify({
        hash: ohash(context),
        plain: Buffer.from(plain).toString('base64'),
      });
      return Buffer.from(blob);
    },
    async generateDataKey(keyArn, context) {
      const random = crypto.randomBytes(32);
      const cipher = await closure.encrypt(keyArn, context, random);
      return { Plaintext: random, CiphertextBlob: cipher };
    },
  };
  return closure;
}
