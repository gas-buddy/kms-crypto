import AWS from 'aws-sdk';
import winston from 'winston';
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
    return;
  }
}

/**
 * Takes a callback or will return a promise if a
 * callback is not passed.
 */
export async function decrypt(contextPlusCipherText, callback) {
  if (!AWS.config.region) {
    await region();
  }

  const [, contextKey, cipheredKey] = contextPlusCipherText.match(/^(.*):([A-Za-z0-9+/=]+)$/);

  if (!contextKey || !cipheredKey) {
    winston.error('Improperly formatted AWS cipher text (should be context:ciphertext)', {
      text: contextPlusCipherText,
    });
    throw new Error(`Improperly formatted AWS cipher text: ${contextPlusCipherText}`);
  }

  let encContext = { service: contextKey };
  if (contextKey.startsWith('{')) {
    encContext = JSON.parse(encContext);
  }
  try {
    const kms = new AWS.KMS();
    const decPromise = kms.decrypt({
      CiphertextBlob: new Buffer(cipheredKey, 'base64'),
      EncryptionContext: encContext,
    }).promise();

    if (callback) {
      decPromise.then(({ Plaintext }) => callback(null, Plaintext), callback);
      return undefined;
    }
    return (await decPromise).Plaintext;
  } catch (error) {
    if (callback) {
      callback(error);
      return undefined;
    }
    throw error;
  }
}

export async function decryptText(blob, callback) {
  if (callback) {
    decrypt(blob, (error, buffer) => {
      const str = buffer ? buffer.toString('utf8') : buffer;
      callback(error, str);
    });
    return undefined;
  }
  const raw = await decrypt(blob);
  return raw.toString('utf8');
}

function format(contextOrService, blob) {
  if (typeof contextOrService === 'string') {
    return `${contextOrService}:${blob.toString('base64')}`;
  }
  const json = JSON.stringify(contextOrService);
  return `${json.replace('"', '\\"')}:${blob.toString('base64')}`;
}

export async function encrypt(keyArn, contextOrService, plaintext, callback) {
  try {
    if (!AWS.config.region) {
      await region();
    }

    let context = contextOrService;
    if (typeof contextOrService === 'string') {
      context = { service: contextOrService };
    }
    const kms = new AWS.KMS();
    const encPromise = kms.encrypt({
      KeyId: keyArn,
      Plaintext: plaintext,
      EncryptionContext: context,
    }).promise();

    if (callback) {
      encPromise
        // eslint-disable-next-line max-len
        .then(({ CiphertextBlob }) => callback(null, format(contextOrService, CiphertextBlob)), callback);
      return undefined;
    }
    return format(contextOrService, (await encPromise).CiphertextBlob);
  } catch (error) {
    if (callback) {
      callback(error);
      return undefined;
    }
    throw error;
  }
}
