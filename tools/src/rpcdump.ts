#!/usr/bin/env node
// Impacket-JS - DCE/RPC endpoint mapper dumper
//
// TypeScript port of impacket-rpcdump.
// Dumps RPC endpoints via the EPM (Endpoint Mapper).
//
// Reference: DCE/RPC

import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline';
import { parseTarget, init as initLogger, initProxy, info, critical, debug, normalizeArgs,
  BANNER,
} from '@impacket/examples';
import {
  DCERPCTransportFactory,
  heptLookup,
  EPMRPCInterface,
  EPMPipeName,
  EPMHostName,
  EPMHostAddr,
  EPMPortAddr,
  FLOOR_TCPPORT_IDENTIFIER,
  FLOOR_UDPPORT_IDENTIFIER,
  FLOOR_LRPC_IDENTIFIER,
  FLOOR_NBNP_IDENTIFIER,
  FLOOR_MSNB_IDENTIFIER,
  FLOOR_HTTP_IDENTIFIER,
  KNOWN_UUIDS,
  KNOWN_PROTOCOLS as KNOWN_UUID_PROTOCOLS,
  type EpmEntry,
} from '@impacket/dcerpc';
import {
  RPC_PROXY_INVALID_RPC_PORT_ERR,
  RPC_PROXY_CONN_A1_0X6BA_ERR,
  RPC_PROXY_CONN_A1_404_ERR,
  RPC_PROXY_RPC_OUT_DATA_404_ERR,
} from '@impacket/dcerpc';
import { AUTH_NTLM } from '@impacket/http';
import { binToString, uuidtupToBin, stringToUuidtup } from '@impacket/uuid';

// ---------------------------------------------------------------------------
// Helper: resolve friendly Provider (EXE/DLL) and Protocol names from a
// "UUID vMaj.Min" string, mirroring Python impacket's rpcdump.
// ---------------------------------------------------------------------------

function lookupProvider(tmpUUID: string): string {
  const tup = stringToUuidtup(tmpUUID);
  if (!tup) return 'N/A';
  const bin = uuidtupToBin(tup);
  if (!bin) return 'N/A';
  // Python keys on the first 18 bytes (16-byte GUID + 2-byte major version).
  const key = bin.subarray(0, 18).toString('hex');
  return KNOWN_UUIDS[key] ?? 'N/A';
}

function lookupProtocol(tmpUUID: string): string {
  // Python keys on the first 36 chars (the UUID string, no version).
  const key = tmpUUID.slice(0, 36).toUpperCase();
  return KNOWN_UUID_PROTOCOLS[key] ?? 'N/A';
}

// ---------------------------------------------------------------------------
// Known protocol bindings
// ---------------------------------------------------------------------------

const KNOWN_PROTOCOLS: Record<number, { bindstr: string }> = {
  135: { bindstr: 'ncacn_ip_tcp:%s[135]' },
  139: { bindstr: 'ncacn_np:%s[\\pipe\\epmapper]' },
  443: { bindstr: 'ncacn_http:[593,RpcProxy=%s:443]' },
  445: { bindstr: 'ncacn_np:%s[\\pipe\\epmapper]' },
  593: { bindstr: 'ncacn_http:%s' },
};

// ---------------------------------------------------------------------------
// Helper: build a printable string binding from tower floors
// ---------------------------------------------------------------------------

function getFloorData(floor: any): Buffer {
  return floor.getData ? floor.getData() : floor;
}

function printStringBinding(floors: any[]): string {
  // Floor 0 = RPC interface, Floor 1 = data representation,
  // Floor 2 = protocol identifier, Floor 3 = transport/pipe, Floor 4 = host
  const parts: string[] = [];

  if (floors.length >= 4) {
    const floor3Data = getFloorData(floors[3]!);
    const portIdent = floor3Data.length >= 3 ? floor3Data[2] : undefined;

    if (portIdent === FLOOR_TCPPORT_IDENTIFIER || portIdent === FLOOR_HTTP_IDENTIFIER) {
      try {
        const portAddr = new EPMPortAddr(floor3Data);
        const proto = portIdent === FLOOR_HTTP_IDENTIFIER ? 'ncacn_http' : 'ncacn_ip_tcp';
        parts.push(`${proto}:`);
        if (floors.length >= 5) {
          const floor4 = floors[4]!;
          const floor4Data = getFloorData(floor4);
          try {
            const hostAddr = new EPMHostAddr(floor4Data);
            const ipBuf = hostAddr.get('Ip4addr') as Buffer;
            parts.push(`${ipBuf[0]}.${ipBuf[1]}.${ipBuf[2]}.${ipBuf[3]}`);
          } catch {
            // skip
          }
        }
        parts.push(`[${portAddr.get('IpPort')}]`);
      } catch {
        parts.push('ncacn_ip_tcp:???');
      }
    } else if (portIdent === FLOOR_NBNP_IDENTIFIER) {
      try {
        const pipeName = new EPMPipeName(floor3Data);
        const pipeStr = (pipeName.get('PipeName') as Buffer).toString('utf-8').replace(/\0$/, '');
        parts.push('ncacn_np:');
        if (floors.length >= 5) {
          const floor4 = floors[4]!;
          const floor4Data = getFloorData(floor4);
          try {
            const hostName = new EPMHostName(floor4Data);
            const hostStr = (hostName.get('HostName') as Buffer).toString('utf-8').replace(/\0$/, '');
            parts.push(hostStr);
          } catch {
            // skip
          }
        }
        parts.push(`[${pipeStr}]`);
      } catch {
        parts.push('ncacn_np:???');
      }
    } else if (portIdent === FLOOR_LRPC_IDENTIFIER) {
      // Local RPC — RHS is a null-terminated endpoint name (same wire layout as a pipe name).
      try {
        const lrpc = new EPMPipeName(floor3Data);
        const lrpcStr = (lrpc.get('PipeName') as Buffer).toString('utf-8').replace(/\0$/, '');
        return `ncalrpc:[${lrpcStr}]`;
      } catch {
        return 'ncalrpc:???';
      }
    } else if (portIdent === FLOOR_UDPPORT_IDENTIFIER) {
      try {
        const portAddr = new EPMPortAddr(floor3Data);
        parts.push('ncadg_ip_udp:');
        if (floors.length >= 5) {
          const floor4Data = getFloorData(floors[4]!);
          try {
            const hostAddr = new EPMHostAddr(floor4Data);
            const ipBuf = hostAddr.get('Ip4addr') as Buffer;
            parts.push(`${ipBuf[0]}.${ipBuf[1]}.${ipBuf[2]}.${ipBuf[3]}`);
          } catch {
            // skip
          }
        }
        parts.push(`[${portAddr.get('IpPort')}]`);
      } catch {
        parts.push('ncadg_ip_udp:???');
      }
    } else {
      parts.push(`unknown_proto_0x${(portIdent ?? 0).toString(16)}:[0]`);
    }
  }

  return parts.join('');
}

// ---------------------------------------------------------------------------
// RPCDump
// ---------------------------------------------------------------------------

class RPCDump {
  private username: string;
  private password: string;
  private domain: string;
  private lmhash: string;
  private nthash: string;
  private port: number;

  constructor(opts: {
    username?: string;
    password?: string;
    domain?: string;
    hashes?: string | null;
    port?: number;
  }) {
    this.username = opts.username ?? '';
    this.password = opts.password ?? '';
    this.domain = opts.domain ?? '';
    this.lmhash = '';
    this.nthash = '';
    this.port = opts.port ?? 135;
    if (opts.hashes) {
      const parts = opts.hashes.split(':');
      this.lmhash = parts[0] ?? '';
      this.nthash = parts[1] ?? '';
    }
  }

  async dump(remoteName: string, remoteHost: string): Promise<void> {
    info(`Retrieving endpoint list from ${remoteName}`);

    const proto = KNOWN_PROTOCOLS[this.port];
    if (!proto) {
      throw new Error(`Unsupported port: ${this.port}`);
    }

    const stringBinding = proto.bindstr.replace('%s', remoteName);
    debug(`StringBinding ${stringBinding}`);
    const rpctransport = DCERPCTransportFactory(stringBinding);

    if (this.port === 139 || this.port === 445) {
      rpctransport.setCredentials(
        this.username,
        this.password,
        this.domain,
        this.lmhash,
        this.nthash,
      );
      rpctransport.setRemoteHost(remoteHost);
      rpctransport.setDport(this.port);
    } else if (this.port === 443) {
      rpctransport.setCredentials(
        this.username,
        this.password,
        this.domain,
        this.lmhash,
        this.nthash,
      );
      if ('setAuthType' in rpctransport) {
        (rpctransport as any).setAuthType(AUTH_NTLM);
      }
    }
    // Ports 135 and 593 don't need authentication

    let entries: EpmEntry[] = [];
    try {
      entries = await this.fetchList(rpctransport);
    } catch (e) {
      const errorText = `Protocol failed: ${e}`;
      critical(errorText);

      if (
        errorText.includes(RPC_PROXY_INVALID_RPC_PORT_ERR) ||
        errorText.includes(RPC_PROXY_RPC_OUT_DATA_404_ERR) ||
        errorText.includes(RPC_PROXY_CONN_A1_404_ERR) ||
        errorText.includes(RPC_PROXY_CONN_A1_0X6BA_ERR)
      ) {
        critical(
          'This usually means the target does not allow to connect to its epmapper using RpcProxy.',
        );
        return;
      }
    }

    // Group results by UUID
    const endpoints: Record<
      string,
      { Bindings: string[]; EXE: string; annotation: string; Protocol: string }
    > = {};

    for (const entry of entries) {
      const tower = entry.tower;
      const floors = tower.floors;
      const binding = printStringBinding(floors);

      // Get the interface UUID from floor 0
      let tmpUUID = '';
      if (floors.length > 0) {
        const floor0 = floors[0]!;
        const floor0Data = floor0.getData();
        try {
          const iface = new EPMRPCInterface(floor0Data);
          const ifaceUuidBuf = iface.get('InterfaceUUID') as Buffer;
          const majorVersion = iface.get('MajorVersion') as number;
          const minorVersion = (iface.get('MinorVersion') as number | undefined) ?? 0;
          tmpUUID = `${binToString(ifaceUuidBuf)} v${majorVersion}.${minorVersion}`;
        } catch {
          tmpUUID = 'Unknown';
        }
      }

      if (!endpoints[tmpUUID]) {
        endpoints[tmpUUID] = {
          Bindings: [],
          EXE: tmpUUID === 'Unknown' ? 'N/A' : lookupProvider(tmpUUID),
          annotation: '',
          Protocol: tmpUUID === 'Unknown' ? 'N/A' : lookupProtocol(tmpUUID),
        };
      }

      endpoints[tmpUUID]!.annotation = entry.annotation.replace(/\0$/, '');
      endpoints[tmpUUID]!.Bindings.push(binding);
    }

    // Display results
    for (const [endpoint, data] of Object.entries(endpoints)) {
      console.log(`Protocol: ${data.Protocol} `);
      console.log(`Provider: ${data.EXE} `);
      console.log(`UUID    : ${endpoint} ${data.annotation}`);
      console.log('Bindings: ');
      for (const binding of data.Bindings) {
        console.log(`          ${binding}`);
      }
      console.log('');
    }

    if (entries.length > 0) {
      if (entries.length === 1) {
        info('Received one endpoint.');
      } else {
        info(`Received ${entries.length} endpoints.`);
      }
    } else {
      info('No endpoints found.');
    }
  }

  private async fetchList(rpctransport: ReturnType<typeof DCERPCTransportFactory>): Promise<EpmEntry[]> {
    const dce = rpctransport.getDceRpc();
    await dce.connect();

    const resp = await heptLookup('', undefined, undefined, undefined, undefined, dce);

    await dce.disconnect();
    return resp;
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printUsage(): void {
  console.log(`Dumps the remote RPC enpoints information via epmapper.

usage: rpcdump [-h] [-debug] [-ts] [-target-ip ip address]
               [-port {135,139,443,445,593}] [-hashes LMHASH:NTHASH]
               target

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output

connection:
  -target-ip ip address
                        IP Address of the target machine. If ommited it will
                        use whatever was specified as target
  -port {135,139,443,445,593}
                        Destination port to connect to RPC Endpoint Mapper

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH`);
}

async function main(): Promise<void> {
  console.log(BANNER + '\n');

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: normalizeArgs(process.argv.slice(2)),
      options: {
        debug: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        'target-ip': { type: 'string' },
        port: { type: 'string', default: '135' },
        hashes: { type: 'string' },
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

  initLogger({ ts: values.ts, debug: values.debug });
  initProxy(values.proxy);

  const target = positionals[0]!;
  const [domain, username, password, remoteName] = parseTarget(target);

  let resolvedPassword = password;
  if (resolvedPassword === '' && username !== '' && !values.hashes) {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    resolvedPassword = await new Promise<string>((resolve) => {
      rl.question('Password: ', (answer) => {
        rl.close();
        resolve(answer);
      });
    });
  }

  const targetIp = values['target-ip'] ?? remoteName;

  const dumper = new RPCDump({
    username,
    password: resolvedPassword,
    domain: domain || '',
    hashes: values.hashes ?? null,
    port: parseInt(values.port!, 10),
  });

  await dumper.dump(remoteName, targetIp);
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
