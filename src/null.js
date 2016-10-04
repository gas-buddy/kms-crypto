import ohash from 'object-hash';
import winston from 'winston';
import crypto from 'crypto';

export async function decrypt(context, cipher) {
  const plainBuf = JSON.parse(cipher.toString());
  const hash = ohash(context);
  if (hash !== plainBuf.hash) {
    winston.warn('Context mismatch', context);
    return null;
  }
  return Buffer.from(plainBuf.plain, 'base64');
}

export async function encrypt(keyUri, context, plain) {
  const blob = JSON.stringify({
    hash: ohash(context),
    plain: Buffer.from(plain).toString('base64'),
  });
  return Buffer.from(blob).toString('base64');
}

export async function generateDataKey(keyUri, context) {
  const random = crypto.randomBytes(32);
  const cipher = await encrypt(keyUri, context, random);
  return [random, cipher];
}
