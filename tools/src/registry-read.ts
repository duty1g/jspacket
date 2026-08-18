#!/usr/bin/env node
/**
 * jspacket - registry-read
 *
 * A Windows Registry Reader.
 * Reads data from registry hives (binary `regf` hives or `.reg` exports).
 *
 * TypeScript port of impacket's examples/registry-read.py.
 *
 * Original author: Alberto Solino (@agsolino) - Fortra, LLC
 * TypeScript port.
 *
 * Reference for: winregistry.py
 */

import { parseArgs } from 'node:util';
import { Buffer } from 'node:buffer';
import { init as initLogger, normalizeArgs,
  BANNER, initProxy,
} from '@impacket/examples';
import {
  getRegistryParser,
  REG_BINARY,
  type Registry,
} from '@impacket/winregistry';
import { hexdump } from '@impacket/structure';

// ─── ntpath helpers ──────────────────────────────────────────────────────────

function ntDirname(p: string): string {
  const i = p.lastIndexOf('\\');
  return i < 0 ? '' : p.substring(0, i);
}

function ntBasename(p: string): string {
  const i = p.lastIndexOf('\\');
  return i < 0 ? p : p.substring(i + 1);
}

// ─── Actions (mirrors registry-read.py) ──────────────────────────────────────

/**
 * Computes the syskey (boot key) from a SYSTEM hive.
 * Faithful port of registry-read.py's bootKey(); not wired to any sub-command
 * in the original tool, kept here for parity/reuse.
 */
function bootKey(reg: Registry): void {
  const baseClass = 'ControlSet001\\Control\\Lsa\\';
  const keys = ['JD', 'Skew1', 'GBG', 'Data'];
  let tmpKey = Buffer.alloc(0);

  for (const key of keys) {
    const cls = reg.getClass(baseClass + key);
    if (cls === null) return;
    // Class data is UTF-16LE text; first 8 hex chars → 4 bytes.
    const hex = cls.toString('utf16le').slice(0, 8);
    tmpKey = Buffer.concat([tmpKey, Buffer.from(hex, 'hex')]);
  }

  const transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];
  const syskey = Buffer.alloc(tmpKey.length);
  for (let i = 0; i < tmpKey.length; i++) {
    syskey[i] = tmpKey[transforms[i]!]!;
  }

  console.log(syskey.toString('hex'));
}

function getClass(reg: Registry, className: string): void {
  const regKey = ntDirname(className);
  const regClass = ntBasename(className);

  const value = reg.getClass(className);
  if (value === null || value === undefined) return;

  console.log(`[${regKey}]`);
  process.stdout.write(`Value for Class ${regClass}: \n `);
  console.log(hexdump(value, '   '));
}

function getValue(reg: Registry, keyValue: string): void {
  const regKey = ntDirname(keyValue);
  const regValue = ntBasename(keyValue);

  const value = reg.getValue(keyValue);

  console.log(`[${regKey}]\n`);

  if (value === null || value === undefined) return;

  process.stdout.write(`Value for ${regValue}:\n     `);
  reg.printValue(value[0], value[1]);
}

function enumValues(reg: Registry, searchKey: string): void {
  const key = reg.findKey(searchKey);
  if (key === null || key === undefined) return;

  console.log(`[${searchKey}]\n`);

  const values = reg.enumValues(key);
  if (values === null) return;
  console.log(values.map((v) => v.toString('utf-8')));

  for (const value of values) {
    const name = value.toString('utf-8');
    process.stdout.write(`  ${name.padEnd(30)}:  `);
    const data = reg.getValue(searchKey, name);
    if (data === null) {
      console.log('');
      continue;
    }
    // Special case for binary strings so they look better formatted.
    if (data[0] === REG_BINARY) {
      console.log('');
      reg.printValue(data[0], data[1]);
      console.log('');
    } else {
      reg.printValue(data[0], data[1]);
    }
  }
}

function enumKey(
  reg: Registry,
  searchKey: string,
  isRecursive: boolean,
  indent = '  ',
): void {
  const parentKey = reg.findKey(searchKey);
  if (parentKey === null || parentKey === undefined) return;

  const keys = reg.enumKey(parentKey);

  for (const key of keys) {
    console.log(`${indent}${key}`);
    if (isRecursive) {
      if (searchKey === '\\') {
        enumKey(reg, `\\${key}`, isRecursive, indent + '  ');
      } else {
        enumKey(reg, `${searchKey}\\${key}`, isRecursive, indent + '  ');
      }
    }
  }
}

function walk(reg: Registry, keyName: string): void {
  reg.walk(keyName);
}

// ─── CLI ─────────────────────────────────────────────────────────────────────


function printUsage(): void {
  console.log(`Reads data from registry hives.

usage: registry-read [-h] [-debug] [-ts] hive
                     {enum_key,enum_values,get_value,get_class,walk} ...

positional arguments:
  hive                  registry hive to open
  {enum_key,enum_values,get_value,get_class,walk}
                        actions
    enum_key            enumerates the subkeys of the specified open registry key
                        (-name KEY [-recursive])
    enum_values         enumerates the values for the specified open registry key
                        (-name KEY)
    get_value           retrieves the data for the specified registry value
                        (-name VALUE)
    get_class           retrieves the data for the specified registry class
                        (-name CLASSNAME)
    walk                walks the registry from the name node down (-name NODE)

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output`);
}

async function main(): Promise<void> {
  console.log(BANNER);

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: normalizeArgs(process.argv.slice(2)),
      options: {
        debug: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        name: { type: 'string' },
        recursive: { type: 'boolean', default: false },
        help: { type: 'boolean', short: 'h', default: false },
        proxy: { type: 'string' },
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

  initProxy(values.proxy);

  // Init the logger theme.
  initLogger({ ts: values.ts, debug: values.debug });

  const hive = positionals[0]!;
  const action = (positionals[1] ?? '').toUpperCase();

  const reg = getRegistryParser(hive);

  try {
    switch (action) {
      case 'ENUM_KEY': {
        const name = values.name!;
        console.log(`[${name}]`);
        enumKey(reg, name, values.recursive ?? false);
        break;
      }
      case 'ENUM_VALUES':
        enumValues(reg, values.name!);
        break;
      case 'GET_VALUE':
        getValue(reg, values.name!);
        break;
      case 'GET_CLASS':
        getClass(reg, values.name!);
        break;
      case 'WALK':
        walk(reg, values.name!);
        break;
      default:
        printUsage();
        reg.close();
        process.exit(1);
    }
  } finally {
    reg.close();
  }
}

// Reference the parity-only helper so it is retained.
void bootKey;

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
