#!/usr/bin/env node
/* eslint-disable no-console */
import fs from 'fs';
import assert from 'assert';
import minimist from 'minimist';
import { createKmsCryptoProvider } from '../index';

const argv = minimist(process.argv.slice(2), {
  string: '_',
});

function usage() {
  console.error('Usage:');
  console.error(
    '\tkms-encrypt [--context <json>] [--service <name>] [--base64 | --file] [--local-key <filepath>] <key id> <plaintext>',
  );
  console.error('\nYou must provide either a service or context argument\n');
  console.error(argv);
  process.exit(-1);
}

function getProviderConfig() {
  if (argv._[0].startsWith('aws:')) {
    return { aws: true };
  }
  if (argv._[0].startsWith('local:')) {
    return {
      local: { [argv._[0].substring('local:'.length)]: fs.readFileSync(argv['local-key'], 'utf8') },
    };
  }
  return {};
}

async function run() {
  let context;
  if (argv.service) {
    context = { service: argv.service };
  } else {
    context = JSON.parse(argv.context);
  }
  const kms = await createKmsCryptoProvider(getProviderConfig());

  let input: Buffer;
  if (argv.base64) {
    input = Buffer.from(argv._[1], 'base64');
  } else if (argv.file) {
    input = fs.readFileSync(argv._[1], 'binary') as unknown as Buffer;
  } else {
    input = Buffer.from(argv._[1]);
  }
  const blob = await kms.encrypt(argv._[0], context, input);
  console.log(`Raw:\n${blob}\n`);
  console.log(`Base64:\n${Buffer.from(blob, 'ascii').toString('base64')}\n`);
  const original = await kms.decrypt(context, blob);
  assert(original?.equals(input), 'Decrypted value does not match original');
}

if (argv._.length < 1 || (!argv.service && !argv.context)) {
  usage();
}

run().catch((error) => {
  console.error('Failed to encrypt', error);
});
