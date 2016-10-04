import assert from 'assert';

export async function decrypt(context, cipher) {
  const plainBuf = JSON.parse(Buffer.from(cipher, 'base64'));
  try {
    assert.deepEqual(plainBuf.context, context);
  } catch (error) {
    return null;
  }
  return Buffer.from(plainBuf.plain, 'base64');
}

export async function encrypt(keyUri, context, plain) {
  const blob = JSON.stringify({
    context,
    plain: Buffer.from(plain).toString('base64'),
  });
  return Buffer.from(blob).toString('base64');
}
