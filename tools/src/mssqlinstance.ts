#!/usr/bin/env node
/**
 * [MC-SQLR] example. Retrieves the instances names from the target host.
 *
 * Original impacket author: Alberto Solino (@agsolino)
 * TypeScript port for jspacket.
 *
 * Reference for: Structure
 */

import { parseArgs } from 'node:util';
import { init as initLogger, initProxy, info, normalizeArgs,
  BANNER,
} from '@impacket/examples';
import { MSSQL } from '@impacket/tds';

function printUsage(): void {
  console.log(`Asks the remote host for its running MSSQL Instances.

usage: mssqlinstance [-h] [-timeout TIMEOUT] [-debug] [-ts] host

positional arguments:
  host              target host

options:
  -h, --help        show this help message and exit
  -timeout TIMEOUT  timeout to wait for an answer
  -debug            Turn DEBUG output ON
  -ts               Adds timestamp to every logging output`);
}

async function main(): Promise<void> {
  console.log(BANNER + '\n');

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: normalizeArgs(process.argv.slice(2)),
      options: {
        timeout: { type: 'string', default: '5' },
        debug: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
      allowPositionals: true,
      strict: true,
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    printUsage();
    process.exit(1);
  }

  if (values.help || positionals.length === 0) {
    printUsage();
    process.exit(positionals.length === 0 ? 1 : 0);
  }

  // Init the example's logger theme
  initLogger({ ts: values.ts, debug: values.debug });
  initProxy(values.proxy);

  const host = positionals[0]!;
  const timeout = parseInt(values.timeout!, 10);

  const msSql = new MSSQL(host);
  const instances = await msSql.getInstances(timeout);

  if (instances.length === 0) {
    console.log('No MSSQL Instances found');
  } else {
    instances.forEach((instance, i) => {
      info(`Instance ${i}`);
      for (const key of Object.keys(instance)) {
        console.log(`${key}:${instance[key]}`);
      }
    });
  }

  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
