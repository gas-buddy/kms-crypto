import fs from 'fs';
import path from 'path';
import { createLocalProvider } from '../src/local';

test('Local encryption', async () => {
  const key = fs.readFileSync(path.join(__dirname, 'dev_app_key.pem'), 'utf8');
  const cipher = await createLocalProvider({ purple: key });

  const encBlob = await cipher.encrypt('local:purple', { service: 'foobar' }, Buffer.from('testing123'));
  let decBlob = await cipher.decrypt({ service: 'foobar' }, encBlob);
  expect(decBlob).toBeTruthy();
  expect(decBlob?.toString()).toEqual('testing123'); // Should get original text

  const { Plaintext, CiphertextBlob } = await cipher.generateDataKey('local:purple', { service: 'foobar' });
  decBlob = await cipher.decrypt({ service: 'foobar' }, CiphertextBlob);
  expect(decBlob).toBeTruthy(); // Key should decrypt
  expect(decBlob?.toString('base64')).toEqual(Plaintext.toString('base64')); // Keys should match
});
