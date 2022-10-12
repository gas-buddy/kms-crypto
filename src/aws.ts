import {
  DecryptCommand,
  EncryptCommand,
  GenerateDataKeyCommand,
  KMSClient,
} from '@aws-sdk/client-kms';
import type { KmsProviderConfig, KmsOperationContext, KmsCryptoProvider } from './types';

const identityUrl = 'http://169.254.169.254/latest/dynamic/instance-identity/document';

async function getRegion(config: KmsProviderConfig['aws']) {
  const forcedRegion = typeof config === 'object' ? config.region : process.env.AWS_REGION;
  // Otherwise assume we are already setup with AWS SDK
  if (forcedRegion || config !== true) {
    return forcedRegion;
  }

  try {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 2500);

    const response = await fetch(identityUrl, { method: 'get', signal: controller.signal });
    clearTimeout(id);
    const body = await response.text();
    const { region } = JSON.parse(body);
    return region || undefined;
  } catch (error) {
    throw new Error('Unable to fetch instance identity document for KMS configuration');
  }
}

export async function createAwsProvider(
  config: KmsProviderConfig['aws'],
): Promise<KmsCryptoProvider & { region?: string }> {
  const region = await getRegion(config);
  return {
    region,
    async decrypt(context: KmsOperationContext, cipheredKey: Buffer) {
      const awsKms = new KMSClient({ region });
      const { Plaintext } = await awsKms.send(
        new DecryptCommand({ CiphertextBlob: cipheredKey, EncryptionContext: context }),
      );

      return Plaintext ? Buffer.from(Plaintext) : undefined;
    },
    async encrypt(keyArn: string, context: KmsOperationContext, plaintext: Buffer) {
      const awsKms = new KMSClient({ region });
      const { CiphertextBlob } = await awsKms.send(
        new EncryptCommand({
          KeyId: keyArn,
          EncryptionContext: context,
          Plaintext: plaintext,
        }),
      );
      if (!CiphertextBlob) {
        throw new Error('Unable to encrypt data with KMS');
      }
      return Buffer.from(CiphertextBlob);
    },
    async generateDataKey(keyArn: string, context: KmsOperationContext) {
      const awsKms = new KMSClient({ region });
      const { CiphertextBlob, Plaintext } = await awsKms.send(
        new GenerateDataKeyCommand({
          KeyId: keyArn,
          EncryptionContext: context,
          KeySpec: 'AES_256',
        }),
      );

      if (!Plaintext || !CiphertextBlob) {
        throw new Error('Unable to generate data key with KMS');
      }

      return {
        Plaintext: Buffer.from(Plaintext),
        CiphertextBlob: Buffer.from(CiphertextBlob),
      };
    },
  };
}
