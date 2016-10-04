import AWS from 'aws-sdk';
import request from 'superagent';

const identityUrl = 'http://169.254.169.254/latest/dynamic/instance-identity/document';

let regionPromise = null;

async function reallyGetRegion() {
  const response = await request
    .get(identityUrl)
    .set('Accept', 'application/json');
  regionPromise = null;
  AWS.config.update({
    region: response.body.region,
  });
}

function getRegion() {
  // KMS shortstop handler needs a region. See if the env has it
  if (process.env.AWS_REGION) {
    AWS.config.update({
      region: process.env.AWS_REGION,
    });
    return null;
  }
  if (regionPromise) {
    return regionPromise;
  }
  regionPromise = reallyGetRegion();
  return regionPromise;
}

/**
 * AWS configures itself mostly, but for KMS
 * you need a region. You can pass it as a
 * property on manualConfig, or we will look
 * for process.env.AWS_REGION.
 */
export function configure(manualConfig) {
  if (manualConfig) {
    AWS.config.update(manualConfig);
    return undefined;
  }
  // No args passed, do auto configuration.
  return getRegion();
}

export async function decrypt(context, cipheredKey) {
  if (!AWS.config.region) {
    await configure();
  }

  const kms = new AWS.KMS();
  const { Plaintext } = await kms.decrypt({
    CiphertextBlob: cipheredKey,
    EncryptionContext: context,
  }).promise();

  return Plaintext;
}

export async function encrypt(keyArn, context, plaintext) {
  if (!AWS.config.region) {
    await configure();
  }

  const kms = new AWS.KMS();
  const { CiphertextBlob } = await kms.encrypt({
    KeyId: keyArn,
    Plaintext: plaintext,
    EncryptionContext: context,
  }).promise();

  return CiphertextBlob;
}

export async function generateDataKey(keyArn, context) {
  if (!AWS.config.region) {
    await configure();
  }

  const kms = new AWS.KMS();
  const { CiphertextBlob, Plaintext } = await kms.generateDataKey({
    KeyId: keyArn,
    KeySpec: 'AES_256',
    EncryptionContext: context,
  }).promise();
  return [Plaintext, CiphertextBlob];
}
