import fs from 'fs';
import path from 'path';
import { createKmsCryptoProvider } from '../src/index';

test('high level provider', async () => {
  const foobar = { service: 'foobar' };
  const key = fs.readFileSync(path.join(__dirname, 'dev_app_key.pem'), 'utf8');
  const provider = await createKmsCryptoProvider({ aws: { region: 'local' }, local: { purple: key } });

  let encBlob = await provider.encrypt('local:purple', { service: 'foobar' }, Buffer.from('testing123'));
  expect(encBlob).toBeTruthy();
  expect(encBlob).toMatch(/^loc:/);
  let decBlob = await provider.decrypt(foobar, encBlob!);
  expect(decBlob).toBeTruthy();
  expect(decBlob?.toString()).toEqual('testing123'); // Should get original text

  encBlob = await provider.encrypt('null:nothing', foobar, 'testing123');
  expect(encBlob).toBeTruthy();
  expect(encBlob).toMatch(/^nil:/);
  decBlob = await provider.decrypt(foobar, encBlob!);
  expect(decBlob).toBeTruthy();
  expect(decBlob!.toString()).toEqual('testing123'); // Should get original text
  const fail = await provider.decrypt({ service: 'barbaz' }, encBlob!);
  expect(fail).toEqual(undefined); // context mismatch fail

  const { Plaintext, CiphertextBlob } = await provider.generateDataKey('null:nothing', foobar);
  decBlob = await provider.decrypt(foobar, CiphertextBlob);
  expect(decBlob).toBeTruthy(); // Key should decrypt
  expect(decBlob?.toString('base64')).toEqual(Plaintext.toString('base64')); // Keys should match

  encBlob = await provider.encrypt('null:nothing', foobar, 'testing123');
  let strBlob = await provider.decryptText(foobar, encBlob);
  expect(strBlob).toEqual('testing123'); // Should get original text

  const dec = provider.decryptorInContext(foobar, true);
  const dec2 = provider.textDecryptorInContext(foobar, true);
  encBlob = await provider.encrypt('null:nothing', foobar, 'testing123');
  decBlob = await dec(encBlob);
  expect(decBlob?.toString()).toEqual('testing123'); // should get original
  strBlob = await dec2(encBlob);
  expect(strBlob).toEqual('testing123'); // should get original
  decBlob = await dec('FAKE TEXT');
  expect(decBlob?.toString()).toEqual('FAKE TEXT'); // failure should return original
  strBlob = await dec2('FAKE TEXT');
  expect(strBlob).toEqual('FAKE TEXT'); // failure should return original
});
