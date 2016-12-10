import tap from 'tap';
import * as kms from '../src/index';

tap.test('Should work with null encryption', async (t) => {
  const encBlob = await kms.encrypt('null:nothing', 'foobar', 'testing123');
  const decBlob = await kms.decrypt('foobar', encBlob);
  t.strictEquals(decBlob.toString(), 'testing123', 'Should get original text');
  t.strictEquals(await kms.decrypt('notfoobar', encBlob), null, 'context mismatch fail');
});

tap.test('Should work with a callback', (t) => {
  kms.encrypt('null:nothing', 'foobar', 'testing123', (err, blob) => {
    kms.decryptText('foobar', blob, (err2, dec) => {
      t.strictEquals(dec, 'testing123', 'callback text should match');
      t.end();
    });
  });
});

tap.test('Should generate a key', async (t) => {
  const { Plain, Ciphered } = await kms.generateDataKey('null:nothing', 'foobar');
  const decBlob = await kms.decrypt('foobar', Ciphered);
  t.ok(decBlob, 'Key should decrypt');
  t.strictEquals(decBlob.toString('base64'), Plain.toString('base64'), 'Keys should match');
});

tap.test('Should work with text', async (t) => {
  const encBlob = await kms.encrypt('null:nothing', 'foobar', 'testing123');
  const decBlob = await kms.decryptText('foobar', encBlob);
  t.strictEquals(decBlob, 'testing123', 'Should get original text');
});

tap.test('Context functions should work', async (t) => {
  const dec = kms.decryptorInContext('foobar');
  const dec2 = kms.textDecryptorInContext('foobar');
  const encBlob = await kms.encrypt('null:nothing', 'foobar', 'testing123');
  t.strictEquals((await dec(encBlob)).toString(), 'testing123', 'should get original');
  t.strictEquals((await dec2(encBlob)), 'testing123', 'should get original');
});

