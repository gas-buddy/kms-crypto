import { KMSClient, DecryptCommand, EncryptCommand } from '@aws-sdk/client-kms';
import { mockClient } from 'aws-sdk-client-mock';
import { createAwsProvider } from '../src/aws';

import 'aws-sdk-client-mock-jest';

describe('KMS encryption', () => {
  const oldFetch = global.fetch;

  afterEach(() => {
    global.fetch = oldFetch;
  });

  test('Region discovery', async () => {
    let fetchCalled = false;
    global.fetch = jest.fn(() => {
      fetchCalled = true;
      return Promise.resolve({
        text: () => Promise.resolve('{"region":"foobar"}'),
      });
    }) as any;

    const k = await createAwsProvider(true);
    expect(fetchCalled).toBeTruthy();
    expect(k.region).toEqual('foobar');
  });

  test('Should take a region argument', async () => {
    const k = await createAwsProvider({ region: 'mars' });
    expect(k.region).toEqual('mars');
  });

  test('Should encrypt a value with KMS', async () => {
    const mockKMS = mockClient(KMSClient);
    mockKMS.on(EncryptCommand, { KeyId: 'arn:KEY_ARN' }).resolvesOnce({
      CiphertextBlob: Buffer.from('hello world'),
    });
    const cipher = await createAwsProvider({ region: 'local' });
    const encBlob = await cipher.encrypt(
      'arn:KEY_ARN',
      { service: 'foobar' },
      Buffer.from('testing123'),
    );
    expect(encBlob).toBeTruthy();
    expect(encBlob?.toString('base64')).toEqual(Buffer.from('hello world').toString('base64')); // Should match mock text
    expect(mockKMS).toHaveReceivedCommandTimes(EncryptCommand, 1);
  });

  test('Should decrypt a value with KMS', async () => {
    const mockKMS = mockClient(KMSClient);
    mockKMS
      .on(DecryptCommand, {
        CiphertextBlob: Buffer.from('hello world'),
        EncryptionContext: { service: 'megaserv' },
      })
      .resolvesOnce({
        Plaintext: Buffer.from('hello world'),
      });

    const cipher = await createAwsProvider({ region: 'local' });
    const cipherBlob = Buffer.from('hello world');
    const plain = await cipher.decrypt({ service: 'megaserv' }, cipherBlob);
    expect(plain).toBeTruthy();
    expect(plain?.toString()).toEqual('hello world'); // Should match mock text
    expect(mockKMS).toHaveReceivedCommandTimes(DecryptCommand, 1);
  });
});
