import tap from 'tap';
import nock from 'nock';
import AWS from 'aws-sdk';
import { configure, decrypt as kmsDecrypt, encrypt as kmsEncrypt } from '../src/index';

tap.test('Should call the AWS metadata service without a region', async (t) => {
  const oldEnv = process.env.AWS_REGION;
  delete process.env.AWS_REGION;
  const expectation = nock('http://169.254.169.254')
    .get('/latest/dynamic/instance-identity/document')
    .reply(200, {
      region: 'foobar',
    });
  await configure({ aws: null });
  t.ok(expectation.isDone(), 'Expect to call API');
  t.strictEquals(AWS.config.region, 'foobar', 'Expect region to be foobar');
  t.end();
  process.env.AWS_REGION = oldEnv;
});

tap.test('Should take an AWS region explicitly', (t) => {
  configure({
    aws: {
      region: 'mars',
    },
  });
  t.strictEquals(AWS.config.region, 'mars', 'Expect explicit region setting to work');
  t.end();
});

tap.test('Should encrypt a token with AWS', async (t) => {
  t.plan(7);
  const oldKms = AWS.KMS;
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
  const cipher = await kmsEncrypt('arn:KEY_ARN', 'megaserv', 'plaintextValue');
  t.strictEquals(cipher, `aws:${Buffer.from('hello world').toString('base64')}`,
    'Should match mock text');
  await new Promise((accept) => {
    kmsEncrypt('arn:KEY_ARN', { foo: true, bar: false }, 'plaintextValue', (error, cbCipher) => {
      t.notOk(error, 'Should not error');
      t.strictEquals(cbCipher,
        `aws:${Buffer.from('hello world').toString('base64')}`,
        'Should match mock text');
      accept();
    });
  });
  t.end();
  AWS.KMS = oldKms;
});

tap.test('Should decrypt a token from AWS', async (t) => {
  t.plan(9);
  const oldKms = AWS.KMS;
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
  const plain = await kmsDecrypt('megaserv', `aws:${cipherBlob.toString('base64')}`);
  t.strictEquals(plain.toString(), 'hello world', 'Should match mock text');
  await new Promise((accept) => {
    kmsDecrypt('megaserv', `aws:${cipherBlob.toString('base64')}`, (error, cbPlain) => {
      t.notOk(error, 'Should not error');
      t.strictEquals(cbPlain.toString(), 'hello world', 'Should match mock text');
      accept();
    });
  });
  t.end();
  AWS.KMS = oldKms;
});

tap.test('Should work with null encryption', async (t) => {
  const encBlob = await kmsEncrypt('null:nothing', 'foobar', 'testing123');
  console.error(encBlob);
  const decBlob = await kmsDecrypt('foobar', encBlob);
  console.error(decBlob);
  t.strictEquals(decBlob.toString(), 'testing123', 'Should get original text');
  t.end();
});
