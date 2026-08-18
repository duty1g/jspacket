#!/usr/bin/env node
/**
 * samedit - In-place edits a local user's password in a SAM hive file.
 *
 * Simple implementation for replacing a local user's password through editing
 * of a copy of the SAM and SYSTEM hives. It only allows replacing an existing
 * password for an existing user.
 *
 * Original impacket author:
 *   Otavio Brito (@Iorpim)
 *   (largely based on secretsdump / winregistry by @agsolino)
 *
 * TypeScript port for jspacket.
 */

import { parseArgs } from 'node:util';
import {
  init as initLogger,
  info,
  error as logError,
  debug as logDebug,
  critical,
  LocalOperations,
  SAMHashes,
  normalizeArgs,
  BANNER,
  initProxy,
} from '@impacket/examples';
import { ntowfV1 } from '@impacket/ntlm';


function printHelp(): void {
  console.log(`usage: samedit [-h] [-password PASSWORD] [-hashes HASHES] [-system SYSTEM]
               [-bootkey BOOTKEY] [-debug] [-ts]
               user sam

In-place edits a local user's password in a SAM hive file

positional arguments:
  user                Name of the user account to replace the password
  sam                 SAM hive file to edit

options:
  -h, --help          show this help message and exit
  -password PASSWORD  New password to be set
  -hashes HASHES      Replace NTLM hash directly (LM hash is optional)
  -system SYSTEM      SYSTEM hive file containing the bootkey for password encryption
  -bootkey BOOTKEY    Bootkey used to encrypt and decrypt SAM passwords
  -debug              Turn DEBUG output ON
  -ts                 Adds timestamp to every logging output`);
}

/** binascii.unhexlify equivalent that validates the input is pure hex. */
function fromHex(value: string): Buffer {
  if (value.length % 2 !== 0 || /[^0-9a-fA-F]/.test(value)) {
    throw new Error(`Non-hexadecimal digit found in '${value}'`);
  }
  return Buffer.from(value, 'hex');
}

function main(): void {
  console.log(BANNER + '\n');

  const argv = normalizeArgs(process.argv.slice(2));

  // impacket prints help when fewer than 4 argv items are supplied
  // (program + user + sam + at least one option). argv here excludes program.
  if (argv.length < 3) {
    printHelp();
    process.exit(1);
  }

  let values;
  let positionals;
  try {
    ({ values, positionals } = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        help: { type: 'boolean', short: 'h', default: false },
        password: { type: 'string' },
        hashes: { type: 'string' },
        system: { type: 'string' },
        bootkey: { type: 'string' },
        debug: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        proxy: { type: 'string' },
      },
    }));
  } catch (e) {
    logError((e as Error).message);
    printHelp();
    process.exit(1);
    return;
  }

  if (values.help) {
    printHelp();
    process.exit(0);
  }

  initProxy(values.proxy as string | undefined);

  if (positionals.length < 2) {
    printHelp();
    process.exit(1);
  }

  const user = positionals[0]!;
  const sam = positionals[1]!;

  initLogger({ ts: values.ts as boolean, debug: values.debug as boolean });

  const system = values.system as string | undefined;
  const bootkeyOpt = values.bootkey as string | undefined;
  const passwordOpt = values.password as string | undefined;
  const hashesOpt = values.hashes as string | undefined;

  if (system === undefined && bootkeyOpt === undefined) {
    critical('A SYSTEM hive or bootkey value is required for password changing');
    process.exit(1);
  }

  if (system !== undefined && bootkeyOpt !== undefined) {
    critical('Only a SYSTEM hive or bootkey value can be supplied');
    process.exit(1);
  }

  if (passwordOpt === undefined && hashesOpt === undefined) {
    critical('A password or hash argument is required');
    process.exit(1);
  }

  if (passwordOpt !== undefined && hashesOpt !== undefined) {
    critical('Only a password or hash argument can be supplied');
    process.exit(1);
  }

  let bootkey: Buffer;
  if (bootkeyOpt !== undefined) {
    bootkey = fromHex(bootkeyOpt);
  } else {
    const localOperations = new LocalOperations(system!);
    bootkey = localOperations.getBootKey();
  }

  const hive = new SAMHashes(sam, bootkey, false);

  let LMHash: Buffer = Buffer.alloc(0);
  let NTHash: Buffer = Buffer.alloc(0);

  if (hashesOpt !== undefined) {
    if (!hashesOpt.includes(':')) {
      LMHash = Buffer.alloc(0);
      NTHash = fromHex(hashesOpt);
    } else {
      const parts = hashesOpt.split(':');
      LMHash = fromHex(parts[0]!);
      NTHash = fromHex(parts[1]!);
    }
  }

  if (passwordOpt !== undefined) {
    LMHash = Buffer.alloc(0);
    NTHash = ntowfV1(passwordOpt);
  }

  try {
    hive.edit(user, NTHash, LMHash);
  } catch (e) {
    if (values.debug) {
      logDebug((e as Error).stack ?? String(e));
    }
    logError((e as Error).message);
  }

  hive.finish();
}

main();
