import tap from 'tap';
import * as kms from '../src/index';

tap.test('Should work with null encryption', async (t) => {
  const encBlob = await kms.encrypt('null:nothing', 'foobar', 'testing123');
  const decBlob = await kms.decrypt('foobar', encBlob);
  t.strictEquals(decBlob.toString(), 'testing123', 'Should get original text');
  t.end();
});

tap.test('Should generate a key', async (t) => {
  const { Plain, Ciphered } = await kms.generateDataKey('null:nothing', 'foobar');
  const decBlob = await kms.decrypt('foobar', Ciphered);
  t.ok(decBlob, 'Key should decrypt');
  t.strictEquals(decBlob.toString('base64'), Plain.toString('base64'), 'Keys should match');
  t.end();
});
