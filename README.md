kms-crypto
==========

[![Greenkeeper badge](https://badges.greenkeeper.io/gas-buddy/kms-crypto.svg)](https://greenkeeper.io/)

[![wercker status](https://app.wercker.com/status/eae07123030a63629d8e637448964ec4/m/master "wercker status")](https://app.wercker.com/project/byKey/eae07123030a63629d8e637448964ec4)

The kms-crypto module creates a generic interface for Key Management Services which allows reasonably flexible usage
between true cloud providers (currently only AWS) and local encryption (mostly for development).

The key resource name is used to differentiate between the service providers, and the service provider is embedded in
encrypted values (e.g. ciphertext).

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