kms-crypto
==========

[![wercker status](https://app.wercker.com/status/eae07123030a63629d8e637448964ec4/m/master "wercker status")](https://app.wercker.com/project/byKey/eae07123030a63629d8e637448964ec4)

The kms-crypto module creates a generic interface for Key Management Services which allows reasonably flexible usage
between true cloud providers (currently only AWS) and local encryption (mostly for development).

The key resource name is used to differentiate between the service providers, and the service provider is embedded in
encrypted values (e.g. ciphertext). PLEASE NOTE - the examples use `null:whatever` but DO NOT USE THAT IN PRODUCTION CODE. Your key should start with `kms:` and you should get that key ARN from the ops team.

The module supports promises and callbacks.

```
var assert = require('assert');
var kms = require('kms-crypto');

kms.encrypt('null:whatever', 'somethingunique', 'testing123')
  .then(function (encBlob) {
    return kms.decrypt('somethingunique', encBlob);
  })
  .then(function (decBlob) {
    assert.equals(decBlob.toString(), 'testing123');
  });
```

Or, with callbacks (ewww):

```
var assert = require('assert');
var kms = require('kms-crypto');

kms.encrypt('null:whatever', 'somethingunique', 'testing123', function (error, encBlob) {
  kms.decrypt('somethingunique', encBlob, function (decError, decBlob) {
    assert.equal(decBlob.toString(), 'testing123');
  });
});
```

Or with ES 2016:

```
import assert from 'assert';
import * as kms from 'kms-crypto';

async function run() {
  const encBlob = await kms.encrypt('null:whatever', 'somethingunique', 'testing123');
  const decBlob = await kms.decrypt('somethingunique', encBlob);
  assert.equal(decBlob.toString(), 'testing123');
}

run();
```

### Encrypting secrets with the CLI

When secret key is needed, the following steps can be used to encode one using the CLI tool provided by this project.  The following steps outline how to do it.

Clone the repo
run `npm install`
run `npm run build`
run
```
node build/kms-encrypt.js \
  --service token-serv \
  --base64 \
  '<KMS ARN>' \
  $(echo -n '<SOOOOOOOOOOOPER_SECRET_PLAINTEXT>' | base64)
```

KMS ARN: this is the ARN of the KMS object to use, ex. `arn:aws:kms:us-east-1:267230788984:key/f09db2c3-ab61-499e-9b28-0515ed805008`
SOOOOOOOOOOOPER_SECRET_PLAINTEXT: a 32 char string to encrypt.  Probably randomly generated with something like 1Password.

The output will include 2 stings.  The raw encrypted value, and the raw value base64 encoded.  For use with kubernetes secretes, you will want the base64 encoded one.
