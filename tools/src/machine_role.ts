#!/usr/bin/env node
/**
 * jspacket - machine_role
 *
 * TypeScript port of impacket's examples/machine_role.py.
 *
 * Through MS-DSSP, this script retrieves a host's role along with its primary
 * domain details.
 *
 * Original impacket author: Simon Decosse (@simondotsh)
 * TypeScript port for jspacket.
 */

import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline';
import {
  parseTarget,
  init as initLogger,
  initProxy,
  critical,
  debug,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';
import {
  DCERPCTransportFactory,
  MSRPC_UUID_DSSP,
  DSROLE_MACHINE_ROLE,
  DSROLE_PRIMARY_DOMAIN_INFO_LEVEL,
  hDsRolerGetPrimaryDomainInformation,
} from '@impacket/dcerpc';
import { binToString } from '@impacket/uuid';

// ---------------------------------------------------------------------------
// MachineRole
// ---------------------------------------------------------------------------

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dssp/09f0677f-52e5-454d-9a65-0e8d8ba6fdeb
const MACHINE_ROLES: Record<number, string> = {
  [DSROLE_MACHINE_ROLE.enumValues.DsRole_RoleStandaloneWorkstation!]:
    'Standalone Workstation',
  [DSROLE_MACHINE_ROLE.enumValues.DsRole_RoleMemberWorkstation!]:
    'Domain-joined Workstation',
  [DSROLE_MACHINE_ROLE.enumValues.DsRole_RoleStandaloneServer!]:
    'Standalone Server',
  [DSROLE_MACHINE_ROLE.enumValues.DsRole_RoleMemberServer!]:
    'Domain-joined Server',
  [DSROLE_MACHINE_ROLE.enumValues.DsRole_RoleBackupDomainController!]:
    'Backup Domain Controller',
  [DSROLE_MACHINE_ROLE.enumValues.DsRole_RolePrimaryDomainController!]:
    'Primary Domain Controller',
};

class MachineRole {
  private username: string;
  private password: string;
  private domain: string;
  private lmhash: string;
  private nthash: string;
  private aesKey: string | null;
  private doKerberos: boolean;
  private kdcHost: string | null;
  private port: number;

  constructor(opts: {
    username?: string;
    password?: string;
    domain?: string;
    hashes?: string | null;
    aesKey?: string | null;
    doKerberos?: boolean;
    kdcHost?: string | null;
    port?: number;
  }) {
    this.username = opts.username ?? '';
    this.password = opts.password ?? '';
    this.domain = opts.domain ?? '';
    this.lmhash = '';
    this.nthash = '';
    this.aesKey = opts.aesKey ?? null;
    this.doKerberos = opts.doKerberos ?? false;
    this.kdcHost = opts.kdcHost ?? null;
    this.port = opts.port ?? 445;
    if (opts.hashes) {
      const parts = opts.hashes.split(':');
      this.lmhash = parts[0] ?? '';
      this.nthash = parts[1] ?? '';
    }
  }

  async printInfo(remoteName: string, remoteHost: string): Promise<void> {
    let dce: ReturnType<ReturnType<typeof DCERPCTransportFactory>['getDceRpc']>;
    try {
      dce = await this.authenticate(remoteName, remoteHost);
    } catch (e) {
      this.logAndExit(String(e));
      return;
    }

    let output: Record<string, unknown>;
    try {
      output = await this.fetch(dce);
    } catch (e) {
      this.logAndExit(String(e));
      return;
    }

    for (const [key, value] of Object.entries(output)) {
      console.log(`${key}: ${value}`);
    }

    await dce.disconnect();
  }

  private async authenticate(
    remoteName: string,
    remoteHost: string,
  ): Promise<ReturnType<ReturnType<typeof DCERPCTransportFactory>['getDceRpc']>> {
    const dce = this.getTransport(remoteName, remoteHost);

    await dce.connect();
    await dce.bind(MSRPC_UUID_DSSP!);

    return dce;
  }

  private getTransport(
    remoteName: string,
    remoteHost: string,
  ): ReturnType<ReturnType<typeof DCERPCTransportFactory>['getDceRpc']> {
    const stringBinding = `ncacn_np:${remoteName}[\\pipe\\lsarpc]`;
    debug(`StringBinding ${stringBinding}`);
    const rpctransport = DCERPCTransportFactory(stringBinding);
    rpctransport.setDport(this.port);
    rpctransport.setRemoteHost(remoteHost);

    if ('setCredentials' in rpctransport) {
      // This method exists only for selected protocol sequences.
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

    return rpctransport.getDceRpc();
  }

  private async fetch(
    dce: ReturnType<ReturnType<typeof DCERPCTransportFactory>['getDceRpc']>,
  ): Promise<Record<string, unknown>> {
    const output: Record<string, unknown> = {};

    const domainInfo = await hDsRolerGetPrimaryDomainInformation(
      dce,
      DSROLE_PRIMARY_DOMAIN_INFO_LEVEL.DsRolePrimaryDomainInfoBasic,
    );

    const info = (domainInfo.get('DomainInfo') as any).get(
      'DomainInfoBasic',
    ) as any;

    const machineRole = info.get('MachineRole') as number;
    output['Machine Role'] =
      MACHINE_ROLES[machineRole] ?? `Unknown (${machineRole})`;
    output['NetBIOS Domain Name'] = info.get('DomainNameFlat');
    output['Domain Name'] = info.get('DomainNameDns');
    output['Forest Name'] = info.get('DomainForestName');
    output['Domain GUID'] = binToString(info.get('DomainGuid') as Buffer);

    return output;
  }

  private logAndExit(errorText: string): void {
    critical(`Error while enumerating host: ${errorText}`);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printUsage(): void {
  console.log(`Retrieve a host's role along with its primary domain details.

usage: machine_role [-h] [-ts] [-debug] [-dc-ip ip address]
                    [-target-ip ip address] [-port [destination port]]
                    [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                    target

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

connection:
  -dc-ip ip address     IP Address of the domain controller. If ommited it use
                        the domain part (FQDN) specified in the target
                        parameter
  -target-ip ip address
                        IP Address of the target machine. If ommited it will
                        use whatever was specified as target. This is useful
                        when target is the NetBIOS name and you cannot resolve
                        it
  -port [destination port]
                        Destination port to connect to SMB Server

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters. If
                        valid credentials cannot be found, it will use the ones
                        specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)`);
}

async function main(): Promise<void> {
  console.log(BANNER + '\n');

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: normalizeArgs(process.argv.slice(2)),
      options: {
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        'dc-ip': { type: 'string' },
        'target-ip': { type: 'string' },
        port: { type: 'string', default: '445' },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
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

  const resolvedDomain = domain || '';
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

  const machineRole = new MachineRole({
    username,
    password: resolvedPassword,
    domain: resolvedDomain,
    hashes: values.hashes ?? null,
    aesKey: values.aesKey ?? null,
    doKerberos,
    kdcHost: values['dc-ip'] ?? null,
    port: parseInt(values.port!, 10),
  });

  await machineRole.printInfo(remoteName, targetIp);
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
