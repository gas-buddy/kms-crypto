import AWS from 'aws-sdk';
import region from './region';

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
  return region();
}

export async function decrypt(context, cipheredKey) {
  if (!AWS.config.region) {
    await configure();
  }

  const kms = new AWS.KMS();
  const { Plaintext } = await kms.decrypt({
    CiphertextBlob: new Buffer(cipheredKey, 'base64'),
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
