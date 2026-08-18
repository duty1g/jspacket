#!/usr/bin/env node
/**
 * jspacket - mqtt_check
 *
 * TypeScript port of impacket's examples/mqtt_check.py.
 *
 * Simple MQTT login check. Can be adapted into a brute-forcer.
 *
 * Original impacket author: Alberto Solino (@agsolino)
 * TypeScript port for jspacket.
 */

import { parseArgs } from 'node:util';
import {
  parseTarget,
  init as initLogger,
  initProxy,
  info,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';
import {
  MQTTConnection,
  CONNECT_ACK_ERROR_MSGS,
} from '@impacket/mqtt';


async function main(): Promise<void> {
  console.log(BANNER);

  const argv = normalizeArgs(process.argv.slice(2));
  let opt: any;
  let positionals: string[];
  try {
    ({ values: opt, positionals } = parseArgs({
      args: argv,
      options: {
        'client-id': { type: 'string' },
        ssl: { type: 'boolean', default: false },
        port: { type: 'string', default: '1883' },
        debug: { type: 'boolean', short: 'd', default: false },
        ts: { type: 'boolean', default: false },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
      allowPositionals: true,
      strict: false,
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    process.exit(1);
  }

  if (opt.help || positionals.length === 0) {
    console.log(`
usage: mqtt_check [[domain/]username[:password]@]<targetName> [options]

MQTT login check

positional arguments:
  target                [[domain/]username[:password]@]<targetName>

options:
  -client-id ID         Client ID used when authenticating (default random)
  -ssl                  Turn SSL on
  -port PORT            Port to connect to (default 1883)
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output
  -h, -help             Show this help message and exit
`);
    process.exit(0);
  }

  initLogger({ ts: opt.ts as boolean, debug: opt.debug as boolean });
  initProxy(opt.proxy as string);

  const [domain, username, password, address] = parseTarget(positionals[0]!);

  const mqtt = new MQTTConnection(address, parseInt(opt.port as string, 10), opt.ssl as boolean);
  await mqtt.connectSocket();

  const clientId = (opt['client-id'] as string) ?? ' ';
  const user = username || null;
  const pwd = password || null;

  await mqtt.connect(clientId, user, pwd);

  info(CONNECT_ACK_ERROR_MSGS[0]!);
}

main().catch((err) => {
  console.error(`[-] ${err.message ?? err}`);
  process.exit(1);
});
