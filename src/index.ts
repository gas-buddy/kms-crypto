import assert from 'assert';
import { createAwsProvider } from './aws';
import { createLocalProvider } from './local';
import { nullProvider } from './null';
import { KmsVariant, KmsCryptoProvider, KmsOperationContext, KmsProviderConfig } from './types';

export async function createKmsCryptoProvider(config: KmsProviderConfig) {
  const [aws, local] = await Promise.all([
    config.aws ? createAwsProvider(config.aws) : undefined,
    config.local ? createLocalProvider(config.local) : undefined,
  ]);
  const nullP = nullProvider();

  const closure = {
    async decrypt(
      context: KmsOperationContext,
      cipherText: string,
    ) {
      const [, kmsSpec, ciphered] =
        cipherText.toString().match(/^([a-z]{3}):([A-Za-z0-9+/=]+)$/) || [];
      if (!kmsSpec && !ciphered) {
        throw new Error('Improperly formatted cipher text (should be kms:ciphertext)');
      }

      const cipherBuffer = Buffer.from(ciphered, 'base64');

      if (kmsSpec === KmsVariant.AWS) {
        assert(aws, 'KMS provider not configured');
        return aws.decrypt(context, cipherBuffer);
      }
      if (kmsSpec === KmsVariant.LOCAL) {
        assert(local, 'Local provider not configured');
        return local.decrypt(context, cipherBuffer);
      }
      if (kmsSpec === KmsVariant.NULL) {
        return nullP.decrypt(context, cipherBuffer);
      }
      throw new Error(`Unknown KMS provider ${kmsSpec}`);
    },
    async encrypt(
      keyArn: string,
      context: KmsOperationContext,
      plaintext: string | Buffer,
    ) {
      if (keyArn.startsWith('aws:')) {
        assert(aws, 'KMS provider not configured');
        const cipherText = await aws.encrypt(keyArn, context, Buffer.from(plaintext));
        return `aws:${cipherText.toString('base64')}`;
      }
      if (keyArn.startsWith('local:')) {
        assert(local, 'Local provider not configured');
        const cipherText = await local.encrypt(keyArn, context, Buffer.from(plaintext));
        return `loc:${cipherText.toString('base64')}`;
      }
      if (keyArn.startsWith('null:')) {
        const cipherText = await nullP.encrypt(keyArn, context, Buffer.from(plaintext));
        return `nil:${cipherText.toString('base64')}`;
      }
      throw new Error(`Unknown KMS provider ${keyArn.split(':')[0]}`);
    },
    async generateDataKey(
      keyArn: string,
      context: KmsOperationContext,
    ) {
      let datakey: Awaited<ReturnType<KmsCryptoProvider['generateDataKey']> | undefined>;
      let provider: KmsVariant;

      if (keyArn.startsWith('aws:')) {
        assert(aws, 'KMS provider not configured');
        provider = KmsVariant.AWS;
        datakey = await aws.generateDataKey(keyArn, context);
      }
      if (keyArn.startsWith('local:')) {
        assert(local, 'Local provider not configured');
        provider = KmsVariant.LOCAL;
        datakey = await local.generateDataKey(keyArn, context);
      }
      if (keyArn.startsWith('null:')) {
        provider = KmsVariant.NULL;
        datakey = await nullP.generateDataKey(keyArn, context);
      }
      if (datakey) {
        return {
          Plaintext: datakey.Plaintext,
          CiphertextBlob: `${provider!}:${datakey.CiphertextBlob.toString('base64')}`,
        };
      }
      throw new Error(`Unknown KMS provider ${keyArn.split(':')[0]}`);
    },
    async decryptText(
      context: KmsOperationContext,
      cipherText: string,
    ) {
      const buffer = await closure.decrypt(context, cipherText);
      return buffer?.toString('utf8');
    },
    decryptorInContext(
      context: KmsOperationContext,
      returnOriginalOnFailure: boolean,
    ) {
      return async (cipher: string) => {
        try {
          return await closure.decrypt(context, cipher);
        } catch (error) {
          if (returnOriginalOnFailure) {
            return Buffer.from(cipher);
          }
          throw error;
        }
      };
    },
    textDecryptorInContext(
      context: KmsOperationContext,
      returnOriginalOnFailure: boolean,
    ) {
      return async (cipher: string) => {
        try {
          const buffer = await closure.decrypt(context, cipher);
          return buffer?.toString('utf8');
        } catch (error) {
          if (returnOriginalOnFailure) {
            return cipher;
          }
          throw error;
        }
      };
    },
  } as const;
  return closure;
}
