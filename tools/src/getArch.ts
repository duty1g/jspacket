#!/usr/bin/env node
/**
 * getArch - Gets the target system's OS architecture version.
 *
 * This script connects against a target (or list of targets) machine/s and
 * gathers the OS architecture type installed by binding the RPC Endpoint Mapper
 * with the NDR64 transfer syntax. If the target accepts NDR64 it is 64-bit,
 * otherwise it is 32-bit. This trick is documented by Microsoft here:
 *   https://msdn.microsoft.com/en-us/library/cc243948.aspx#Appendix_A_53
 * and doesn't require any authentication at all.
 *
 * Have in mind this trick will *not* work if the target system is running
 * Samba. Don't know what happens with macOS.
 *
 * Original impacket author: beto (@agsolino)
 * TypeScript port for jspacket.
 *
 * Reference for: RPCRT, NDR
 */

import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { init as initLogger, initProxy, info, error, normalizeArgs,
  BANNER,
} from '@impacket/examples';
import { DCERPCTransportFactory, MSRPC_UUID_PORTMAP, DCERPCException } from '@impacket/dcerpc';

// NDR64 transfer syntax — probing for it reveals a 64-bit target.
const NDR64Syntax: [string, string] = ['71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'];

interface Options {
  target?: string;
  targets?: string;
  timeout: string;
}

class TARGETARCH {
  private machinesList: string[] = [];
  private options: Options;

  constructor(options: Options) {
    this.options = options;
  }

  async run(): Promise<void> {
    if (this.options.targets != null) {
      const contents = readFileSync(this.options.targets, 'utf-8');
      for (const line of contents.split('\n')) {
        // Python: line.strip(' \r\n')
        const stripped = line.replace(/^[ \r\n]+|[ \r\n]+$/g, '');
        this.machinesList.push(stripped);
      }
    } else if (this.options.target != null) {
      this.machinesList.push(this.options.target);
    }

    info(`Gathering OS architecture for ${this.machinesList.length} machines`);
    info(`Socket connect timeout set to ${this.options.timeout} secs`);

    for (const machine of this.machinesList) {
      try {
        const stringBinding = `ncacn_ip_tcp:${machine}[135]`;
        const transport = DCERPCTransportFactory(stringBinding);
        transport.setConnectTimeout(parseInt(this.options.timeout, 10));
        const dce = transport.getDceRpc();
        await dce.connect();

        let bindOk = false;
        try {
          await dce.bind(MSRPC_UUID_PORTMAP, 0, 0, NDR64Syntax);
          bindOk = true;
        } catch (e) {
          if (e instanceof DCERPCException) {
            if (String(e.message).indexOf('syntaxes_not_supported') >= 0) {
              console.log(`${machine} is 32-bit`);
            } else {
              error(String(e.message));
            }
          } else {
            throw e;
          }
        }

        // Python's try/else: a successful bind (no exception) means 64-bit.
        if (bindOk) {
          console.log(`${machine} is 64-bit`);
        }

        await dce.disconnect();
      } catch (e) {
        error(`${machine}: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  }
}

function printBanner(): void {
  console.log(BANNER + '\n');
}

function printHelp(): void {
  console.log(`Gets the target system's OS architecture version

usage: getArch [-h] [-target TARGET] [-targets TARGETS] [-timeout TIMEOUT]
               [-debug] [-ts]

options:
  -h, --help        show this help message and exit
  -target TARGET    <targetName or address>
  -targets TARGETS  input file with targets system to query Arch from (one per line).
  -timeout TIMEOUT  socket timeout out when connecting to the target (default 2 sec)
  -debug            Turn DEBUG output ON
  -ts               Adds timestamp to every logging output`);
}

async function main(): Promise<void> {
  const rawArgs = process.argv.slice(2);

  let values: any;
  try {
    ({ values } = parseArgs({
      args: normalizeArgs(rawArgs),
      options: {
        target: { type: 'string' },
        targets: { type: 'string' },
        timeout: { type: 'string', default: '2' },
        debug: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
      allowPositionals: false,
      strict: true,
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    printHelp();
    process.exit(1);
  }

  if (values.help || rawArgs.length === 0) {
    printHelp();
    process.exit(rawArgs.length === 0 ? 1 : 0);
  }

  printBanner();

  initProxy(values.proxy);
  // Init the example's logger theme
  initLogger({ ts: values.ts, debug: values.debug });

  if (values.target == null && values.targets == null) {
    error('You have to specify a target!');
    process.exit(1);
  }

  try {
    const getArch = new TARGETARCH({
      target: values.target,
      targets: values.targets,
      timeout: values.timeout!,
    });
    await getArch.run();
  } catch (e) {
    error(e instanceof Error ? e.message : String(e));
  }

  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
