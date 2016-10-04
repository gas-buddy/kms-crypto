import fs from 'fs';
import path from 'path';
import tap from 'tap';
import * as kms from '../src/index';

tap.test('Should work with local encryption', async (t) => {
  const key = fs.readFileSync(path.join(__dirname, 'dev_app_key.pem'), 'utf8');
  await kms.configure({
    local: {
      purple: key,
    },
  });
  const encBlob = await kms.encrypt('local:purple', 'foobar', 'testing123');
  const decBlob = await kms.decrypt('foobar', encBlob);
  t.strictEquals(decBlob.toString(), 'testing123', 'Should get original text');
  t.end();
});

tap.test('Should generate a key', async (t) => {
  const { Plain, Ciphered } = await kms.generateDataKey('local:purple', 'foobar');
  const decBlob = await kms.decrypt('foobar', Ciphered);
  t.ok(decBlob, 'Key should decrypt');
  t.strictEquals(decBlob.toString('base64'), Plain.toString('base64'), 'Keys should match');
  t.end();
});
