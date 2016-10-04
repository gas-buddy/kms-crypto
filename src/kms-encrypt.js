#!/usr/bin/env node
/* eslint-disable no-console */
import minimist from 'minimist';
import * as kms from './index';

function usage(argv) {
  console.error('Usage:');
  console.error('\tkms-encrypt [--context <json>] [--service <name>] <key id> <plaintext>');
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
  const blob = await kms.encrypt(argv._[0], context, argv._[1]);
  console.log(blob);
}

const argv = minimist(process.argv.slice(2));

if (argv._.length < 2 || (!argv.service && !argv.context)) {
  usage(argv);
}

run(argv)
  .catch((error) => {
    console.error('Failed to encrypt', error);
  });
