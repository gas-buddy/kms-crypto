kms-crypto
==========

![main CI](https://github.com/gas-buddy/kms-crypto/actions/workflows/nodejs.yml/badge.svg)

[![npm version](https://badge.fury.io/js/@gasbuddy%2Fkms-crypto.svg)](https://badge.fury.io/js/@gasbuddy%2Fkms-crypto)

The kms-crypto module creates a generic interface for Key Management Services which allows reasonably flexible usage between true cloud providers (currently only AWS) and local encryption (mostly for development).

The key resource name is used to differentiate between the service providers, and the service provider is embedded in encrypted values (e.g. ciphertext). PLEASE NOTE - the examples use `null:whatever` but DO NOT USE THAT IN PRODUCTION CODE. Your key should start with `kms:` and you should get that key ARN from the ops team.

```
import assert from 'assert';
import { createKmsCryptoProvider } from '@gasbuddy/kms-crypto';

(async () => {
  const kms = createKmsCryptoProvider({});
  const encBlob = kms.encrypt('null:whatever', 'somethingunique', 'testing123');
  const decBlob = kms.decrypt('somethingunique', encBlob);
  assert.equals(decBlob.toString(), 'testing123');
})();
```