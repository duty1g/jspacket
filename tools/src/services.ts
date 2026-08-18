#!/usr/bin/env node
/**
 * jspacket - Windows Service manipulation script.
 *
 * [MS-SCMR] services common functions for manipulating services via DCE/RPC.
 *
 * Original impacket author: Alberto Solino (@agsolino)
 * TypeScript port for jspacket.
 */

import { Buffer } from 'node:buffer';
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import {
  parseTarget,
  init as initLogger,
  initProxy,
  info,
  error as logError,
  debug,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';
import {
  DCERPCTransportFactory,
  MSRPC_UUID_SCMR,
  NULL,
  hROpenSCManagerW,
  hROpenServiceW,
  hRStartServiceW,
  hRControlService,
  hRDeleteService,
  hRQueryServiceConfigW,
  hRQueryServiceStatus,
  hREnumServicesStatusW,
  hRCreateServiceW,
  hRChangeServiceConfigW,
  hRCloseServiceHandle,
  SERVICE_CONTROL_STOP,
  SERVICE_NO_CHANGE,
  SERVICE_ERROR_IGNORE,
  SERVICE_CONTINUE_PENDING,
  SERVICE_PAUSE_PENDING,
  SERVICE_PAUSED,
  SERVICE_RUNNING,
  SERVICE_START_PENDING,
  SERVICE_STOP_PENDING,
  SERVICE_STOPPED,
  type SMBTransport,
  type ScRpcHandle,
} from '@impacket/dcerpc';
import { encryptSecret } from '@impacket/crypto';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Mirrors impacket's `value[:-1]` — strips exactly one trailing char (the
// terminating null) from the NDR-decoded string.
function stripLast(value: unknown): string {
  if (typeof value !== 'string') return '';
  return value.slice(0, -1);
}

function stateToString(state: number): string {
  switch (state) {
    case SERVICE_CONTINUE_PENDING:
      return 'CONTINUE PENDING';
    case SERVICE_PAUSE_PENDING:
      return 'PAUSE PENDING';
    case SERVICE_PAUSED:
      return 'PAUSED';
    case SERVICE_RUNNING:
      return 'RUNNING';
    case SERVICE_START_PENDING:
      return 'START PENDING';
    case SERVICE_STOP_PENDING:
      return 'STOP PENDING';
    case SERVICE_STOPPED:
      return 'STOPPED';
    default:
      return 'UNKNOWN';
  }
}

// Read a NUL-terminated UTF-16LE string from a buffer at the given offset.
function readWideStringZ(buf: Buffer, offset: number): string {
  let end = offset;
  while (end + 1 < buf.length) {
    if (buf[end] === 0 && buf[end + 1] === 0) break;
    end += 2;
  }
  return buf.subarray(offset, end).toString('utf-16le');
}

// ---------------------------------------------------------------------------
// SVCCTL
// ---------------------------------------------------------------------------

interface SvcOptions {
  action: string;
  name?: string;
  display?: string;
  path?: string;
  service_type?: string;
  start_type?: string;
  start_name?: string;
  password?: string;
  hashes?: string | null;
  aesKey?: string | null;
  k?: boolean;
  dc_ip?: string | null;
}

class SVCCTL {
  private username: string;
  private password: string;
  private domain: string;
  private port: number;
  private action: string;
  private options: SvcOptions;
  private lmhash = '';
  private nthash = '';
  private aesKey: string | null;
  private doKerberos: boolean;
  private kdcHost: string | null;

  constructor(
    username: string,
    password: string,
    domain: string,
    options: SvcOptions,
    port = 445,
  ) {
    this.username = username;
    this.password = password;
    this.domain = domain;
    this.options = options;
    this.port = port;
    this.action = options.action.toUpperCase();
    this.aesKey = options.aesKey ?? null;
    this.doKerberos = options.k ?? false;
    this.kdcHost = options.dc_ip ?? null;

    if (options.hashes) {
      const parts = options.hashes.split(':');
      this.lmhash = parts[0] ?? '';
      this.nthash = parts[1] ?? '';
    }
  }

  async run(remoteName: string, remoteHost: string): Promise<void> {
    const stringbinding = `ncacn_np:${remoteName}[\\pipe\\svcctl]`;
    debug(`StringBinding ${stringbinding}`);
    const rpctransport = DCERPCTransportFactory(stringbinding) as SMBTransport;
    rpctransport.setDport(this.port);
    rpctransport.setRemoteHost(remoteHost);
    if ('setCredentials' in rpctransport) {
      rpctransport.setCredentials(
        this.username,
        this.password,
        this.domain,
        this.lmhash,
        this.nthash,
        this.aesKey,
      );
    }
    rpctransport.setKerberos(this.doKerberos, this.kdcHost);
    await this.doStuff(rpctransport);
  }

  private async doStuff(rpctransport: SMBTransport): Promise<void> {
    const dce = rpctransport.getDceRpc();
    await dce.connect();
    await dce.bind(MSRPC_UUID_SCMR);
    const rpc = dce;

    const ans = await hROpenSCManagerW(rpc);
    const scManagerHandle = ans.get('lpScHandle') as ScRpcHandle;

    let serviceHandle: ScRpcHandle | undefined;
    if (this.action !== 'LIST' && this.action !== 'CREATE') {
      const resp = await hROpenServiceW(rpc, scManagerHandle, this.options.name + '\x00');
      serviceHandle = resp.get('lpServiceHandle') as ScRpcHandle;
    }

    if (this.action === 'START') {
      info(`Starting service ${this.options.name}`);
      await hRStartServiceW(rpc, serviceHandle!);
      await hRCloseServiceHandle(rpc, serviceHandle!);
    } else if (this.action === 'STOP') {
      info(`Stopping service ${this.options.name}`);
      await hRControlService(rpc, serviceHandle!, SERVICE_CONTROL_STOP);
      await hRCloseServiceHandle(rpc, serviceHandle!);
    } else if (this.action === 'DELETE') {
      info(`Deleting service ${this.options.name}`);
      await hRDeleteService(rpc, serviceHandle!);
      await hRCloseServiceHandle(rpc, serviceHandle!);
    } else if (this.action === 'CONFIG') {
      info(`Querying service config for ${this.options.name}`);
      const resp = await hRQueryServiceConfigW(rpc, serviceHandle!);
      const cfg = resp.get('lpServiceConfig') as {
        get(k: string): unknown;
      };
      const serviceType = cfg.get('dwServiceType') as number;
      let typeLine = `TYPE              : ${String(serviceType).padStart(2)} - `;
      if (serviceType & 0x1) typeLine += 'SERVICE_KERNEL_DRIVER  ';
      if (serviceType & 0x2) typeLine += 'SERVICE_FILE_SYSTEM_DRIVER  ';
      if (serviceType & 0x10) typeLine += 'SERVICE_WIN32_OWN_PROCESS  ';
      if (serviceType & 0x20) typeLine += 'SERVICE_WIN32_SHARE_PROCESS  ';
      if (serviceType & 0x100) typeLine += 'SERVICE_INTERACTIVE_PROCESS  ';
      console.log(typeLine);

      const startType = cfg.get('dwStartType') as number;
      let startLine = `START_TYPE        : ${String(startType).padStart(2)} - `;
      switch (startType) {
        case 0x0:
          startLine += 'BOOT START';
          break;
        case 0x1:
          startLine += 'SYSTEM START';
          break;
        case 0x2:
          startLine += 'AUTO START';
          break;
        case 0x3:
          startLine += 'DEMAND START';
          break;
        case 0x4:
          startLine += 'DISABLED';
          break;
        default:
          startLine += 'UNKNOWN';
      }
      console.log(startLine);

      const errorControl = cfg.get('dwErrorControl') as number;
      let errLine = `ERROR_CONTROL     : ${String(errorControl).padStart(2)} - `;
      switch (errorControl) {
        case 0x0:
          errLine += 'IGNORE';
          break;
        case 0x1:
          errLine += 'NORMAL';
          break;
        case 0x2:
          errLine += 'SEVERE';
          break;
        case 0x3:
          errLine += 'CRITICAL';
          break;
        default:
          errLine += 'UNKNOWN';
      }
      console.log(errLine);

      console.log(`BINARY_PATH_NAME  : ${stripLast(cfg.get('lpBinaryPathName'))}`);
      console.log(`LOAD_ORDER_GROUP  : ${stripLast(cfg.get('lpLoadOrderGroup'))}`);
      console.log(`TAG               : ${cfg.get('dwTagId') as number}`);
      console.log(`DISPLAY_NAME      : ${stripLast(cfg.get('lpDisplayName'))}`);
      console.log(`DEPENDENCIES      : ${stripLast(cfg.get('lpDependencies'))}`);
      console.log(`SERVICE_START_NAME: ${stripLast(cfg.get('lpServiceStartName'))}`);
    } else if (this.action === 'STATUS') {
      console.log(`Querying status for ${this.options.name}`);
      const resp = await hRQueryServiceStatus(rpc, serviceHandle!);
      const status = resp.get('lpServiceStatus') as { get(k: string): unknown };
      const state = status.get('dwCurrentState') as number;
      console.log(`${(this.options.name ?? '').padStart(30)} -  ${stateToString(state)}`);
    } else if (this.action === 'LIST') {
      info('Listing services available on target');
      const resp = await hREnumServicesStatusW(rpc, scManagerHandle);
      const count = resp.get('lpServicesReturned') as number;

      // The returned lpBuffer is a raw copy of the remote SCM memory. impacket
      // parses it with a conformant array (consuming a 4-byte header) and then
      // resolves each record's name/display-name via their referent pointers,
      // which point into that same buffer (offset = ReferentID - 4).
      const rawArr = resp.get('lpBuffer') as number[];
      const data = Buffer.from(rawArr.map(v => v & 0xff));
      const RECORD_SIZE = 36; // 2 pointers (4) + SERVICE_STATUS (7 * 4)

      for (let i = 0; i < count; i++) {
        const base = i * RECORD_SIZE;
        const svcNamePtr = data.readUInt32LE(base + 0);
        const dispNamePtr = data.readUInt32LE(base + 4);
        const state = data.readUInt32LE(base + 12); // dwCurrentState
        const serviceName = readWideStringZ(data, svcNamePtr);
        const displayName = readWideStringZ(data, dispNamePtr);
        console.log(
          `${serviceName.padStart(30)} - ${displayName.padStart(70)} -  ${stateToString(state)}`,
        );
      }
      console.log(`Total Services: ${count}`);
    } else if (this.action === 'CREATE') {
      info(`Creating service ${this.options.name}`);
      await hRCreateServiceW(
        rpc,
        scManagerHandle,
        this.options.name + '\x00',
        this.options.display + '\x00',
        undefined,
        undefined,
        undefined,
        undefined,
        this.options.path + '\x00',
      );
    } else if (this.action === 'CHANGE') {
      info(`Changing service config for ${this.options.name}`);
      const startType =
        this.options.start_type != null ? parseInt(this.options.start_type, 10) : SERVICE_NO_CHANGE;
      const serviceType =
        this.options.service_type != null
          ? parseInt(this.options.service_type, 10)
          : SERVICE_NO_CHANGE;

      const display = this.options.display != null ? this.options.display + '\x00' : NULL;
      const path = this.options.path != null ? this.options.path + '\x00' : NULL;
      const startName = this.options.start_name != null ? this.options.start_name + '\x00' : NULL;

      let password: Buffer | typeof NULL = NULL;
      if (this.options.password != null) {
        const smb = rpctransport.getSmbConnection();
        if (!smb) {
          throw new Error('No SMB connection available to derive the session key');
        }
        const key = smb.getSessionKey();
        const pwdBuf = Buffer.from(this.options.password + '\x00', 'utf-16le');
        password = encryptSecret(key, pwdBuf);
      }

      await hRChangeServiceConfigW(
        rpc,
        serviceHandle!,
        serviceType,
        startType,
        SERVICE_ERROR_IGNORE,
        path,
        NULL,
        NULL,
        NULL,
        0,
        startName,
        password as unknown as typeof NULL,
        0,
        display,
      );
      await hRCloseServiceHandle(rpc, serviceHandle!);
    } else {
      logError(`Unknown action ${this.action}`);
    }

    await hRCloseServiceHandle(rpc, scManagerHandle);
    await dce.disconnect();
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printUsage(): void {
  console.log(`Windows Service manipulation script.

usage: services [-h] [-debug] [-ts] [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                [-aesKey hex key] [-dc-ip ip address] [-target-ip ip address]
                [-port [{139,445}]]
                target
                {start,stop,delete,status,config,list,create,change} ...

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

actions:
  start   -name <service>                          starts the service
  stop    -name <service>                          stops the service
  delete  -name <service>                          deletes the service
  status  -name <service>                          returns service status
  config  -name <service>                          returns service configuration
  list                                             list available services
  create  -name <s> -display <d> -path <p>         create a service
  change  -name <s> [-display] [-path]             change a service configuration
          [-service_type] [-start_type]
          [-start_name] [-password]

authentication:
  -hashes LMHASH:NTHASH  NTLM hashes, format is LMHASH:NTHASH
  -no-pass               don't ask for password (useful for -k)
  -k                     Use Kerberos authentication. Grabs credentials from
                         ccache file (KRB5CCNAME) based on target parameters
  -aesKey hex key        AES key to use for Kerberos Authentication (128 or 256 bits)

connection:
  -dc-ip ip address      IP Address of the domain controller
  -target-ip ip address  IP Address of the target machine
  -port {139,445}        Destination port to connect to SMB Server`);
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
        // action arguments
        name: { type: 'string' },
        display: { type: 'string' },
        path: { type: 'string' },
        service_type: { type: 'string' },
        start_type: { type: 'string' },
        start_name: { type: 'string' },
        password: { type: 'string' },
        // authentication
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        // connection
        'dc-ip': { type: 'string' },
        'target-ip': { type: 'string' },
        port: { type: 'string', default: '445' },
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

  initProxy(values.proxy);
  initLogger({ ts: values.ts, debug: values.debug });

  const target = positionals[0]!;
  const action = positionals[1];
  if (!action) {
    printUsage();
    process.exit(1);
  }

  const [domainRaw, username, password, remoteName] = parseTarget(target);
  const domain = domainRaw || '';

  const targetIp = values['target-ip'] ?? remoteName;

  let doKerberos = values.k ?? false;
  if (values.aesKey) {
    doKerberos = true;
  }

  let resolvedPassword = password;
  if (
    resolvedPassword === '' &&
    username !== '' &&
    !values.hashes &&
    !values['no-pass'] &&
    !values.aesKey
  ) {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    resolvedPassword = await new Promise<string>((resolve) => {
      rl.question('Password: ', (answer) => {
        rl.close();
        resolve(answer);
      });
    });
  }

  const options: SvcOptions = {
    action,
    name: values.name,
    display: values.display,
    path: values.path,
    service_type: values.service_type,
    start_type: values.start_type,
    start_name: values.start_name,
    password: values.password,
    hashes: values.hashes ?? null,
    aesKey: values.aesKey ?? null,
    k: doKerberos,
    dc_ip: values['dc-ip'] ?? null,
  };

  const services = new SVCCTL(
    username,
    resolvedPassword,
    domain,
    options,
    parseInt(values.port!, 10),
  );

  try {
    await services.run(remoteName, targetIp);
  } catch (e) {
    logError(String(e instanceof Error ? e.message : e));
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
