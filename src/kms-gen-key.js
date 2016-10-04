#!/usr/bin/env node
/* eslint-disable no-console */
import minimist from 'minimist';
import * as kms from './index';

function usage(argv) {
  console.error('Usage:');
  console.error('\tkms-gen-key [--context <json>] [--service <name>] <key id>');
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
  const { Ciphered } = await kms.generateDataKey(argv._[0], context);
  console.log(Ciphered);
}

const argv = minimist(process.argv.slice(2));

if (argv._.length < 1 || (!argv.service && !argv.context)) {
  usage(argv);
}

run(argv)
  .catch((error) => {
    console.error('Failed to encrypt', error);
  });
