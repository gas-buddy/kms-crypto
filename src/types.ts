import type { BaseLogger } from 'pino';

export enum KmsVariant {
  AWS = 'aws',
  LOCAL = 'loc',
  NULL = 'nil',
}

export interface KmsProviderConfig {
  aws?: boolean | { region: string };
  local?: Record<string, string>;
}

export interface CryptoContext {
  logger: BaseLogger;
}

export type KmsOperationContext = Record<string, any>;

export interface KmsDataKey {
  Plaintext: Buffer;
  CiphertextBlob: Buffer;
}

export interface KmsCryptoProvider {
  encrypt(keyArn: string, context: KmsOperationContext, plaintext: Buffer): Promise<Buffer>;
  decrypt(context: KmsOperationContext, cipherBuf: Buffer): Promise<Buffer | undefined>;
  generateDataKey(keyArn: string, context: KmsOperationContext): Promise<KmsDataKey>;
}
