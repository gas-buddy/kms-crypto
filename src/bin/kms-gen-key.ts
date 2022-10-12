#!/usr/bin/env node
/* eslint-disable no-console */
import fs from 'fs';
import minimist from 'minimist';
import { createKmsCryptoProvider } from '../index';

const argv = minimist(process.argv.slice(2));

function usage() {
  console.error('Usage:');
  console.error('\tkms-gen-key [--context <json>] [--service <name>] [--local-key <filepath>] <key id>');
  console.error('\nYou must provide either a service or context argument\n');
  console.error(argv);
  process.exit(-1);
}

function getProviderConfig() {
  if (argv._[0].startsWith('aws:')) {
    return { aws: true };
  }
  if (argv._[0].startsWith('local:')) {
    return { local: { [argv._[0].substring('local:'.length)]: fs.readFileSync(argv['local-key'], 'utf8') } };
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
  const { CiphertextBlob } = await kms.generateDataKey(argv._[0], context);
  console.log(CiphertextBlob);
}

if (argv._.length < 1 || (!argv.service && !argv.context)) {
  usage();
}

run().catch((error) => {
  console.error('Failed to generate data key', error);
});
