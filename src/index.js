import * as aws from './aws';
import * as nulls from './null';
import * as local from './local';
import { getLogger } from './logger';

export { setLogger } from './logger';

export function configure(manualConfig) {
  const promises = [];
  if (manualConfig && {}.hasOwnProperty.call(manualConfig, 'aws')) {
    getLogger().info('Configuring AWS Key Management Service');
    const maybePromise = aws.configure(manualConfig.aws);
    if (maybePromise) {
      promises.push(maybePromise);
    }
  }
  if (manualConfig && {}.hasOwnProperty.call(manualConfig, 'local')) {
    getLogger().info('Configuring Local Key Management Service');
    const maybePromise = local.configure(manualConfig.local);
    if (maybePromise) {
      promises.push(maybePromise);
    }
  }
  return promises ? Promise.all(promises) : undefined;
}

/**
 * Takes a callback or will return a promise if a
 * callback is not passed.
 */
export async function decrypt(contextOrService, cipherText, callback) {
  const [, kms, ciphered] =
    cipherText.toString().match(/^([a-z]{3}):([A-Za-z0-9+/=]+)$/) || [];

  let context = contextOrService;
  if (typeof contextOrService === 'string') {
    context = { service: contextOrService };
  }

  if (!kms || !ciphered) {
    getLogger().error('Improperly formatted AWS cipher text (should be kms:ciphertext)', {
      text: cipherText,
    });
    const error = new Error('Improperly formatted AWS cipher text');
    if (callback) {
      callback(error);
      return undefined;
    }
    throw error;
  }

  const cipherBuffer = Buffer.from(ciphered, 'base64');

  let decPromise;
  try {
    if (kms === 'aws') {
      decPromise = aws.decrypt(context, cipherBuffer);
    } else if (kms === 'nil') {
      decPromise = nulls.decrypt(context, cipherBuffer);
    } else if (kms === 'loc') {
      decPromise = local.decrypt(context, cipherBuffer);
    }

    if (decPromise) {
      if (callback) {
        decPromise.then(Plaintext => callback(null, Plaintext), callback);
        return undefined;
      }
      return (await decPromise);
    }
  } catch (error) {
    if (callback) {
      callback(error);
      return undefined;
    }
    throw error;
  }

  const error = new Error(`Unknown key management service: ${kms}`);
  if (callback) {
    return callback(error);
  }
  throw error;
}

export async function decryptText(contextOrService, blob, callback) {
  if (callback) {
    decrypt(contextOrService, blob, (error, buffer) => {
      const str = buffer ? buffer.toString('utf8') : buffer;
      callback(error, str);
    });
    return undefined;
  }
  const raw = await decrypt(contextOrService, blob);
  return raw.toString('utf8');
}

export async function encrypt(keyArn, contextOrService, plaintext, callback) {
  let encPromise;
  let kmsName;

  let context = contextOrService;
  if (typeof contextOrService === 'string') {
    context = { service: contextOrService };
  }

  try {
    if (keyArn.startsWith('arn:')) {
      kmsName = 'aws';
      encPromise = aws.encrypt(keyArn, context, plaintext);
    } else if (keyArn.startsWith('null:')) {
      kmsName = 'nil';
      encPromise = nulls.encrypt(keyArn, context, plaintext);
    } else if (keyArn.startsWith('local:')) {
      kmsName = 'loc';
      encPromise = local.encrypt(keyArn, context, plaintext);
    }

    if (encPromise) {
      if (callback) {
        encPromise
          // eslint-disable-next-line max-len
          .then(blob =>
            callback(null, `${kmsName}:${blob.toString('base64')}`),
          callback);
        return undefined;
      }
      const blob = await encPromise;
      return `${kmsName}:${blob.toString('base64')}`;
    }
  } catch (error) {
    if (callback) {
      callback(error);
      return undefined;
    }
    throw error;
  }

  const error = new Error(`Could not find KMS for ${keyArn}`);
  if (callback) {
    return callback(error);
  }
  throw error;
}

export async function generateDataKey(keyArn, contextOrService, callback) {
  let kmsName;
  let keyPromise;

  let context = contextOrService;
  if (typeof contextOrService === 'string') {
    context = { service: contextOrService };
  }

  if (keyArn.startsWith('arn:')) {
    kmsName = 'aws';
    keyPromise = aws.generateDataKey(keyArn, context);
  } else if (keyArn.startsWith('null:')) {
    kmsName = 'nil';
    keyPromise = nulls.generateDataKey(keyArn, context);
  } else if (keyArn.startsWith('local:')) {
    kmsName = 'loc';
    keyPromise = local.generateDataKey(keyArn, context);
  }

  if (keyPromise) {
    if (callback) {
      keyPromise
        // eslint-disable-next-line max-len
        .then(parts =>
          callback(null, {
            Plain: parts[0],
            Ciphered: `${kmsName}:${parts[1].toString('base64')}`,
          }),
        callback);
      return undefined;
    }
    const parts = await keyPromise;
    return {
      Plain: parts[0],
      Ciphered: `${kmsName}:${parts[1].toString('base64')}`,
    };
  }

  const error = new Error(`Could not find KMS for ${keyArn}`);
  if (callback) {
    return callback(error);
  }
  throw error;
}

export function decryptorInContext(contextOrService, returnOriginalOnFailure) {
  return (async (cipher, callback) => {
    const cbIntercept = callback ? ((error, result) => {
      if (returnOriginalOnFailure && error) {
        callback(null, cipher);
      } else if (error) {
        callback(error, result);
      } else {
        callback(null, result);
      }
    }) : null;
    try {
      return await decrypt(contextOrService, cipher, cbIntercept);
    } catch (error) {
      if (returnOriginalOnFailure) {
        return cipher;
      }
      throw error;
    }
  });
}

export function textDecryptorInContext(contextOrService, returnOriginalOnFailure) {
  return (async (cipher, callback) => {
    const cbIntercept = callback ? ((error, result) => {
      if (returnOriginalOnFailure && error) {
        callback(null, cipher);
      } else if (error) {
        callback(error, result);
      } else {
        callback(null, result);
      }
    }) : null;

    try {
      return await decryptText(contextOrService, cipher, cbIntercept);
    } catch (error) {
      if (returnOriginalOnFailure) {
        return cipher;
      }
      throw error;
    }
  });
}

export class ConfiguredKms {
  constructor(context, config) {
    this.config = config;
    this.logger = context.logger;
  }

  async start() {
    await configure(this.config, this.logger);
    return module.exports;
  }
}
