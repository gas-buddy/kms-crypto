#!/usr/bin/env node
/* eslint-disable no-console */
import minimist from 'minimist';
import * as kms from './index';

function usage(argv) {
  console.error('Usage:');
  console.error('\tkms-encrypt [--context <json>] [--service <name>] [--base64] <key id> <plaintext>');
  console.error('\nYou must provide either a service or context argument\n');
  console.error(argv);
  process.exit(-1);
}

async function run(argv) {
  let context;
  if (argv.service) {
    context = { service: argv.service };
  } else {
    context = JSON.parse(argv.context);
  }
  const input = argv.base64 ? Buffer.from(argv._[1], 'base64') : argv._[1];
  const blob = await kms.encrypt(argv._[0], context, input);
  console.log('Raw:', blob);
  console.log('Base64:', Buffer.from(blob, 'ascii').toString('base64'));
}

const argv = minimist(process.argv.slice(2), { boolean: ['base64']});

if (argv._.length < 2 || (!argv.service && !argv.context)) {
  usage(argv);
}

run(argv)
  .catch((error) => {
    console.error('Failed to encrypt', error);
  });
