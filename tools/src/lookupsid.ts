#!/usr/bin/env node
// Impacket-JS - DCE/RPC lookup SID brute forcer
//
// TypeScript port of impacket-lookupsid.
// Enumerates SIDs via LSAT DCE/RPC.
//
// Reference: DCE/RPC [MS-LSAT]

import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline';
import { parseTarget, init as initLogger, initProxy, info, critical, debug, normalizeArgs,
  BANNER,
} from '@impacket/examples';
import {
  DCERPCTransportFactory,
  DCERPCException,
  MSRPC_UUID_LSAT,
  POLICY_LOOKUP_NAMES,
  hLsarOpenPolicy2,
  hLsarQueryInformationPolicy2,
  hLsarLookupSids,
  LsapLookupLevel,
  POLICY_INFORMATION_CLASS,
  SID_NAME_USE,
  MAXIMUM_ALLOWED,
} from '@impacket/dcerpc';

// ---------------------------------------------------------------------------
// Known protocol bindings
// ---------------------------------------------------------------------------

const KNOWN_PROTOCOLS: Record<number, { bindstr: string; setHost: boolean }> = {
  139: { bindstr: 'ncacn_np:%s[\\pipe\\lsarpc]', setHost: true },
  445: { bindstr: 'ncacn_np:%s[\\pipe\\lsarpc]', setHost: true },
};

// ---------------------------------------------------------------------------
// LSALookupSid
// ---------------------------------------------------------------------------

class LSALookupSid {
  private username: string;
  private password: string;
  private port: number;
  private maxRid: number;
  private domain: string;
  private lmhash: string;
  private nthash: string;
  private domainSids: boolean;
  private doKerberos: boolean;

  constructor(opts: {
    username?: string;
    password?: string;
    domain?: string;
    port?: number;
    hashes?: string | null;
    domainSids?: boolean;
    useKerberos?: boolean;
    maxRid?: number;
  }) {
    this.username = opts.username ?? '';
    this.password = opts.password ?? '';
    this.domain = opts.domain ?? '';
    this.port = opts.port ?? 445;
    this.maxRid = opts.maxRid ?? 4000;
    this.domainSids = opts.domainSids ?? false;
    this.doKerberos = opts.useKerberos ?? false;
    this.lmhash = '';
    this.nthash = '';
    if (opts.hashes) {
      const parts = opts.hashes.split(':');
      this.lmhash = parts[0] ?? '';
      this.nthash = parts[1] ?? '';
    }
  }

  async dump(remoteName: string, remoteHost: string): Promise<void> {
    info(`Brute forcing SIDs at ${remoteName}`);

    const proto = KNOWN_PROTOCOLS[this.port];
    if (!proto) {
      throw new Error(`Unsupported port: ${this.port}`);
    }

    const stringBinding = proto.bindstr.replace('%s', remoteName);
    info(`StringBinding ${stringBinding}`);
    const rpctransport = DCERPCTransportFactory(stringBinding);
    rpctransport.setDport(this.port);
    rpctransport.setKerberos(this.doKerberos);

    if (proto.setHost) {
      rpctransport.setRemoteHost(remoteHost);
    }

    if ('setCredentials' in rpctransport) {
      rpctransport.setCredentials(
        this.username,
        this.password,
        this.domain,
        this.lmhash,
        this.nthash,
      );
    }

    try {
      await this.bruteForce(rpctransport, this.maxRid);
    } catch (e) {
      critical(String(e));
      throw e;
    }
  }

  private async bruteForce(rpctransport: ReturnType<typeof DCERPCTransportFactory>, maxRid: number): Promise<void> {
    const dce = rpctransport.getDceRpc();
    await dce.connect();
    await dce.bind(MSRPC_UUID_LSAT);

    const resp = await hLsarOpenPolicy2(dce as any, MAXIMUM_ALLOWED | POLICY_LOOKUP_NAMES);
    const policyHandle = resp.get('PolicyHandle');

    let domainSid: string;
    if (this.domainSids) {
      const resp2 = await hLsarQueryInformationPolicy2(
        dce as any,
        policyHandle,
        POLICY_INFORMATION_CLASS.enumValues.PolicyPrimaryDomainInformation!,
      );
      domainSid = resp2.get('PolicyInformation').get('PolicyPrimaryDomainInfo').get('Sid').formatCanonical();
    } else {
      const resp2 = await hLsarQueryInformationPolicy2(
        dce as any,
        policyHandle,
        POLICY_INFORMATION_CLASS.enumValues.PolicyAccountDomainInformation!,
      );
      domainSid = resp2.get('PolicyInformation').get('PolicyAccountDomainInfo').get('DomainSid').formatCanonical();
    }

    info(`Domain SID is: ${domainSid}`);

    let soFar = 0;
    const SIMULTANEOUS = 1000;

    for (let j = 0; j <= Math.floor(maxRid / SIMULTANEOUS); j++) {
      let sidsToCheck: number;
      if (Math.floor((maxRid - soFar) / SIMULTANEOUS) === 0) {
        sidsToCheck = (maxRid - soFar) % SIMULTANEOUS;
      } else {
        sidsToCheck = SIMULTANEOUS;
      }

      if (sidsToCheck === 0) break;

      const sids: string[] = [];
      for (let i = soFar; i < soFar + sidsToCheck; i++) {
        sids.push(`${domainSid}-${i}`);
      }

      let lookupResp: any;
      try {
        lookupResp = await hLsarLookupSids(
          dce as any,
          policyHandle,
          sids,
          LsapLookupLevel.enumValues.LsapLookupWksta,
        );
      } catch (e) {
        if (e instanceof DCERPCException) {
          if ((e as any).error_code === 0xC0000073) {
            soFar += SIMULTANEOUS;
            continue;
          } else if ((e as any).error_code === 0x107) {
            lookupResp = (e as any).packet;
          } else {
            throw e;
          }
        } else {
          throw e;
        }
      }

      const translatedNames = lookupResp.get('TranslatedNames');
      const names = translatedNames.get('Names');
      const referencedDomains = lookupResp.get('ReferencedDomains');
      const domains = referencedDomains.get('Domains');
      const nameCount = Array.isArray(names) ? names.length : 0;
      for (let n = 0; n < nameCount; n++) {
        const item = names[n]!;
        const use = typeof item.get === 'function' ? item.get('Use') : item['Use'];
        if (use !== SID_NAME_USE.enumValues.SidTypeUnknown) {
          const domainIndex = typeof item.get === 'function' ? item.get('DomainIndex') : item['DomainIndex'];
          const domEntry = domains[domainIndex];
          const domainName = domEntry && typeof domEntry.get === 'function' ? domEntry.get('Name') : domEntry?.['Name'];
          const itemName = typeof item.get === 'function' ? item.get('Name') : item['Name'];
          const sidTypeName = SID_NAME_USE.enumItems[use as number] ?? 'Unknown';
          console.log(`${soFar + n}: ${domainName}\\${itemName} (${sidTypeName})`);
        }
      }
      soFar += SIMULTANEOUS;
    }

    await dce.disconnect();
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printUsage(): void {
  console.log(`usage: lookupsid [-h] [-ts] [-debug] [-target-ip ip address]
                 [-port {139,445}] [-domain-sids]
                 [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                 target [maxRid]

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>
  maxRid                max Rid to check (default 4000)

options:
  -h, --help            show this help message and exit
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

connection:
  -target-ip ip address
                        IP Address of the target machine. If omitted it will
                        use whatever was specified as target
  -port {139,445}       Destination port to connect to SMB Server
  -domain-sids          Enumerate Domain SIDs (will likely forward requests to
                        the DC)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful when proxying through
                        smbrelayx)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters`);
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
        port: { type: 'string', default: '445' },
        'domain-sids': { type: 'boolean', default: false },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
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
  const maxRid = positionals[1] ? parseInt(positionals[1], 10) : 4000;
  const [domain, username, password, remoteName] = parseTarget(target);

  let resolvedPassword = password;
  if (
    resolvedPassword === '' &&
    username !== '' &&
    !values.hashes &&
    !values['no-pass']
  ) {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    resolvedPassword = await new Promise<string>((resolve) => {
      rl.question('Password: ', (answer) => {
        rl.close();
        resolve(answer);
      });
    });
  }

  const targetIp = values['target-ip'] ?? remoteName;

  const lookup = new LSALookupSid({
    username,
    password: resolvedPassword,
    domain: domain || '',
    port: parseInt(values.port!, 10),
    hashes: values.hashes ?? null,
    domainSids: values['domain-sids'],
    useKerberos: values.k,
    maxRid,
  });

  try {
    await lookup.dump(remoteName, targetIp);
  } catch {
    // Error already logged
  }
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
