import tap from 'tap';
import nock from 'nock';
import AWS from 'aws-sdk';
import * as kms from '../src/index';

const originalRegion = AWS.config.region || process.env.AWS_REGION;
const originalKms = AWS.KMS;

tap.test('Should call the AWS metadata service without a region', async (t) => {
  const oldEnv = process.env.AWS_REGION || AWS.config.region;
  delete process.env.AWS_REGION;
  const expectation = nock('http://169.254.169.254')
    .get('/latest/dynamic/instance-identity/document')
    .reply(200, '{"region":"foobar"}');
  await kms.configure({ aws: null });
  t.ok(expectation.isDone(), 'Expect to call API');
  t.strictEquals(AWS.config.region, 'foobar', 'Expect region to be foobar');
  t.end();
  process.env.AWS_REGION = oldEnv;
  AWS.config.update({ region: originalRegion });
});

tap.test('Should take an AWS region explicitly', (t) => {
  kms.configure({
    aws: {
      region: 'mars',
    },
  });
  t.strictEquals(AWS.config.region, 'mars', 'Expect explicit region setting to work');
  t.end();
  AWS.config.update({ region: originalRegion });
});

tap.test('Should encrypt a token with AWS', async (t) => {
  t.plan(7);
  const encrypt = (options) => {
    t.strictEquals(options.KeyId, 'arn:KEY_ARN', 'KeyId should match');
    return {
      promise: async () => {
        t.ok(true, 'Should call promise()');
        return {
          CiphertextBlob: Buffer.from('hello world'),
        };
      },
    };
  };
  AWS.KMS = () => ({ encrypt });
  const cipher = await kms.encrypt('arn:KEY_ARN', 'megaserv', 'plaintextValue');
  t.strictEquals(cipher, `aws:${Buffer.from('hello world').toString('base64')}`,
    'Should match mock text');
  await new Promise((accept) => {
    kms.encrypt('arn:KEY_ARN', { foo: true, bar: false }, 'plaintextValue', (error, cbCipher) => {
      t.notOk(error, 'Should not error');
      t.strictEquals(cbCipher,
        `aws:${Buffer.from('hello world').toString('base64')}`,
        'Should match mock text');
      accept();
    });
  });
  t.end();
});

tap.test('Should decrypt a token from AWS', async (t) => {
  t.plan(9);
  const decrypt = (options) => {
    t.strictEquals(options.CiphertextBlob.toString(), 'hello world', 'Ciphertext should match');
    t.deepEquals(options.EncryptionContext, { service: 'megaserv' }, 'Context should match');
    return {
      promise: async () => {
        t.ok(true, 'Should call promise()');
        return {
          Plaintext: Buffer.from('hello world'),
        };
      },
    };
  };
  AWS.KMS = () => ({ decrypt });
  const cipherBlob = Buffer.from('hello world');
  const plain = await kms.decrypt('megaserv', `aws:${cipherBlob.toString('base64')}`);
  t.strictEquals(plain.toString(), 'hello world', 'Should match mock text');
  await new Promise((accept) => {
    kms.decrypt('megaserv', `aws:${cipherBlob.toString('base64')}`, (error, cbPlain) => {
      t.notOk(error, 'Should not error');
      t.strictEquals(cbPlain.toString(), 'hello world', 'Should match mock text');
      accept();
    });
  });
  t.end();
});

tap.test('Should generate a key', async (t) => {
  t.plan(7);
  const generateDataKey = (options) => {
    t.deepEquals(options.EncryptionContext, { service: 'foobar' }, 'Context should match');
    return {
      promise: async () => {
        t.ok(true, 'Should call promise()');
        return {
          Plaintext: Buffer.from('Bb6NvG5yrN0+xPp8/OgBqPoexmIHRiKK/WKZA9BCDM4=', 'base64'),
          CiphertextBlob: Buffer.from('aabbccdd', 'hex'),
        };
      },
    };
  };
  const decrypt = (options) => {
    t.strictEquals(options.CiphertextBlob.toString('hex'), 'aabbccdd', 'cipher text should match');
    t.deepEquals(options.EncryptionContext, { service: 'foobar' }, 'Context should match');
    return {
      promise: async () => {
        t.ok(true, 'Should call promise()');
        return {
          Plaintext: Buffer.from('Bb6NvG5yrN0+xPp8/OgBqPoexmIHRiKK/WKZA9BCDM4=', 'base64'),
        };
      },
    };
  };
  AWS.KMS = () => ({ decrypt, generateDataKey });

  const { Plain, Ciphered } = await kms.generateDataKey('arn:aws:kms:us-east-1:896521799855:key/df5d2613-33c4-4cdc-b0ed-d41f69d78779', 'foobar');
  const decBlob = await kms.decrypt('foobar', Ciphered);
  t.ok(decBlob, 'Key should decrypt');
  t.strictEquals(decBlob.toString('base64'), Plain.toString('base64'), 'Keys should match');
  t.end();
});

tap.test('Restore KMS', (t) => {
  AWS.KMS = originalKms;
  t.end();
});
