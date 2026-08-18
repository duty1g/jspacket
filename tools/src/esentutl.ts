#!/usr/bin/env node
/**
 * Impacket - Collection of TypeScript classes for working with network protocols.
 *
 * Copyright Fortra, LLC and its affiliated companies
 *
 * All rights reserved.
 *
 * This software is provided under a slightly modified version
 * of the Apache Software License. See the accompanying LICENSE file
 * for more information.
 *
 * Description:
 *   ESE utility. Allows dumping catalog, pages and tables.
 *
 * Author:
 *   Alberto Solino (@agsolino)
 *   TypeScript port
 *
 * Reference for:
 *   Extensive Storage Engine (ese)
 */

import { parseArgs } from 'node:util';
import {
  init as initLogger,
  error,
  debug,
  getLevel,
  LogLevel,
  normalizeArgs,
  BANNER,
  initProxy,
} from '@impacket/examples';
import {
  ESENT_DB,
  ESENT_PAGE,
  type RecordValue,
} from '@impacket/ese';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function printBanner(): void {
  console.log(BANNER + '\n');
}

/**
 * Mimic Python's `%r` (repr) formatting for a single record value so the
 * exported rows look like the original impacket output.
 */
function reprValue(value: RecordValue): string {
  if (value === null) return 'None';
  if (Buffer.isBuffer(value)) {
    let out = "b'";
    for (const b of value) {
      if (b === 0x5c) out += '\\\\';
      else if (b === 0x27) out += "\\'";
      else if (b === 0x0a) out += '\\n';
      else if (b === 0x0d) out += '\\r';
      else if (b === 0x09) out += '\\t';
      else if (b >= 0x20 && b < 0x7f) out += String.fromCharCode(b);
      else out += '\\x' + b.toString(16).padStart(2, '0');
    }
    return out + "'";
  }
  if (typeof value === 'string') {
    // repr of a str
    return "'" + value.replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'";
  }
  if (typeof value === 'bigint') return value.toString();
  return String(value);
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

function dumpPage(ese: ESENT_DB, pageNum: number): void {
  const data = ese.getPage(pageNum) as ESENT_PAGE;
  data.dump();
}

function exportTable(ese: ESENT_DB, tableName: string): void {
  const cursor = ese.openTable(tableName);
  if (cursor === null) {
    error(`Can"t get a cursor for table: ${tableName}`);
    return;
  }

  let i = 1;
  console.log(`Table: ${tableName}`);
  for (;;) {
    let record: Map<string, RecordValue> | null;
    try {
      record = ese.getNextRow(cursor);
    } catch (e) {
      debug(`Exception: ${e instanceof Error ? e.stack ?? e.message : String(e)}`);
      error('Error while calling getNextRow(), trying the next one');
      continue;
    }

    if (record === null) break;

    console.log(`*** ${i}`);
    for (const [j, value] of record) {
      if (value !== null) {
        console.log(`${j.padEnd(30)}: ${reprValue(value)}`);
      }
    }
    i += 1;
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printUsage(): void {
  console.log(`Extensive Storage Engine utility. Allows dumping catalog, pages and tables.

usage: esentutl [-h] [-debug] [-ts] [-page PAGE]
                databaseFile {dump,info,export} ...

positional arguments:
  databaseFile          ESE to open
  {dump,info,export}    actions
    dump                dumps an specific page (-page PAGE required)
    info                dumps the catalog info for the DB
    export              dumps a table (-table TABLE required)

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output
  -page PAGE            page to open
  -table TABLE          table to dump (export action)
`);
}

async function main(): Promise<void> {
  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: normalizeArgs(process.argv.slice(2)),
      allowPositionals: true,
      options: {
        debug: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        page: { type: 'string' },
        table: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
        proxy: { type: 'string' },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    printUsage();
    process.exit(1);
  }

  printBanner();

  if (values.help || positionals.length === 0) {
    printUsage();
    process.exit(1);
  }

  initProxy(values.proxy);

  // positionals: databaseFile [action]
  const databaseFile = positionals[0]!;
  const action = positionals[1];

  // Init the example's logger theme
  initLogger({ ts: values.ts, debug: values.debug });

  const ese = new ESENT_DB(databaseFile);

  try {
    const act = (action ?? '').toUpperCase();
    if (act === 'INFO') {
      ese.printCatalog();
    } else if (act === 'DUMP') {
      if (values.page === undefined) {
        throw new Error('the following arguments are required: -page');
      }
      dumpPage(ese, parseInt(values.page, 10));
    } else if (act === 'EXPORT') {
      if (values.table === undefined) {
        throw new Error('the following arguments are required: -table');
      }
      exportTable(ese, values.table);
    } else {
      throw new Error(`Unknown action ${action} `);
    }
  } catch (e) {
    if (getLevel() === LogLevel.DEBUG) {
      console.error(e instanceof Error ? e.stack : String(e));
    }
    console.log(e instanceof Error ? e.message : String(e));
  }
  ese.close();
}

main()
  .then(() => process.exit(1))
  .catch((e) => {
    console.log(e instanceof Error ? e.message : String(e));
    process.exit(1);
  });
