#!/usr/bin/env node
// Impacket-JS - DCE/RPC SAMR dumper
//
// TypeScript port of impacket-samrdump.
// Dumps SAM database info via SAMR DCE/RPC.
//
// Reference: DCE/RPC for SAMR

import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline';
import { parseTarget, init as initLogger, initProxy, info, critical, debug, normalizeArgs,
  BANNER,
} from '@impacket/examples';
import {
  DCERPCTransportFactory,
  DCERPCException,
  MSRPC_UUID_SAMR,
  MAXIMUM_ALLOWED,
  hSamrConnect,
  hSamrEnumerateDomainsInSamServer,
  hSamrLookupDomainInSamServer,
  hSamrOpenDomain,
  hSamrEnumerateUsersInDomain,
  hSamrOpenUser,
  hSamrQueryInformationUser2,
  hSamrCloseHandle,
  USER_INFORMATION_CLASS,
  USER_DONT_EXPIRE_PASSWORD,
  USER_ACCOUNT_DISABLED,
} from '@impacket/dcerpc';
import { STATUS_MORE_ENTRIES } from '@impacket/nt-errors';

// ---------------------------------------------------------------------------
// ListUsersException
// ---------------------------------------------------------------------------

class ListUsersException extends Error {}

// ---------------------------------------------------------------------------
// SAMRDump
// ---------------------------------------------------------------------------

class SAMRDump {
  private username: string;
  private password: string;
  private domain: string;
  private lmhash: string;
  private nthash: string;
  private aesKey: string | null;
  private doKerberos: boolean;
  private kdcHost: string | null;
  private port: number;
  private csvOutput: boolean;

  constructor(opts: {
    username?: string;
    password?: string;
    domain?: string;
    hashes?: string | null;
    aesKey?: string | null;
    doKerberos?: boolean;
    kdcHost?: string | null;
    port?: number;
    csvOutput?: boolean;
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
    this.csvOutput = opts.csvOutput ?? false;
    if (opts.hashes) {
      const parts = opts.hashes.split(':');
      this.lmhash = parts[0] ?? '';
      this.nthash = parts[1] ?? '';
    }
  }

  static getUnixTime(t: number): number {
    t -= 116444736000000000;
    t /= 10000000;
    return t;
  }

  async dump(remoteName: string, remoteHost: string): Promise<void> {
    info(`Retrieving endpoint list from ${remoteName}`);

    const stringBinding = `ncacn_np:${remoteName}[\\pipe\\samr]`;
    debug(`StringBinding ${stringBinding}`);
    const rpctransport = DCERPCTransportFactory(stringBinding);
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

    let entries: [string, number, any][] = [];
    try {
      entries = await this.fetchList(rpctransport);
    } catch (e) {
      critical(String(e));
    }

    // Display results
    if (this.csvOutput) {
      console.log(
        '#Name,RID,FullName,PrimaryGroupId,BadPasswordCount,LogonCount,' +
          'PasswordLastSet,PasswordDoesNotExpire,AccountIsDisabled,AdminComment,UserComment,ScriptPath',
      );
    }

    for (const [username, uid, user] of entries) {
      const pwdLastSetObj = user.get('PasswordLastSet') as any;
      const pwdLastSetRaw =
        ((pwdLastSetObj.get('HighPart') as number) * 0x100000000) +
        (pwdLastSetObj.get('LowPart') as number);
      let pwdLastSet: string;
      if (pwdLastSetRaw === 0) {
        pwdLastSet = '<never>';
      } else {
        pwdLastSet = new Date(SAMRDump.getUnixTime(pwdLastSetRaw) * 1000).toISOString().replace('T', ' ').slice(0, 19);
      }

      const uac = user.get('UserAccountControl') as number;
      const dontExpire = uac & USER_DONT_EXPIRE_PASSWORD ? 'True' : 'False';
      const accountDisabled = uac & USER_ACCOUNT_DISABLED ? 'True' : 'False';

      if (this.csvOutput) {
        console.log(
          `${username},${uid},${user.get('FullName')},${user.get('PrimaryGroupId')},` +
            `${user.get('BadPasswordCount')},${user.get('LogonCount')},${pwdLastSet},` +
            `${dontExpire},${accountDisabled},` +
            `${String(user.get('AdminComment')).replace(/,/g, '.')},` +
            `${String(user.get('UserComment')).replace(/,/g, '.')},` +
            `${user.get('ScriptPath')}`,
        );
      } else {
        const base = `${username} (${uid})`;
        console.log(`${base}/FullName: ${user.get('FullName')}`);
        console.log(`${base}/AdminComment: ${user.get('AdminComment')}`);
        console.log(`${base}/UserComment: ${user.get('UserComment')}`);
        console.log(`${base}/PrimaryGroupId: ${user.get('PrimaryGroupId')}`);
        console.log(`${base}/BadPasswordCount: ${user.get('BadPasswordCount')}`);
        console.log(`${base}/LogonCount: ${user.get('LogonCount')}`);
        console.log(`${base}/PasswordLastSet: ${pwdLastSet}`);
        console.log(`${base}/PasswordDoesNotExpire: ${dontExpire}`);
        console.log(`${base}/AccountIsDisabled: ${accountDisabled}`);
        console.log(`${base}/ScriptPath: ${user.get('ScriptPath')}`);
      }
    }

    if (entries.length > 0) {
      if (entries.length === 1) {
        info('Received one entry.');
      } else {
        info(`Received ${entries.length} entries.`);
      }
    } else {
      info('No entries received.');
    }
  }

  private async fetchList(rpctransport: ReturnType<typeof DCERPCTransportFactory>): Promise<[string, number, any][]> {
    const dce = rpctransport.getDceRpc();
    const entries: [string, number, any][] = [];

    await dce.connect();
    await dce.bind(MSRPC_UUID_SAMR);

    try {
      const resp = await hSamrConnect(dce);
      const serverHandle = resp.get('ServerHandle') as any;

      const domainsResp = await hSamrEnumerateDomainsInSamServer(dce, serverHandle);
      const domainsBuffer = domainsResp.get('Buffer') as any;
      const domains = domainsBuffer.get('Buffer') as any[];

      console.log('Found domain(s):');
      for (const domain of domains) {
        console.log(` . ${domain.get('Name')}`);
      }

      const firstDomainName = domains[0]!.get('Name');
      info(`Looking up users in domain ${firstDomainName}`);

      const lookupResp = await hSamrLookupDomainInSamServer(dce, serverHandle, firstDomainName);

      const openResp = await hSamrOpenDomain(dce, serverHandle, MAXIMUM_ALLOWED, lookupResp.get('DomainId') as any);
      const domainHandle = openResp.get('DomainHandle') as any;

      let status = STATUS_MORE_ENTRIES;
      let enumerationContext = 0;

      while (status === STATUS_MORE_ENTRIES) {
        let usersResp: any;
        try {
          usersResp = await hSamrEnumerateUsersInDomain(dce, domainHandle, 0, enumerationContext);
        } catch (e) {
          if (e instanceof DCERPCException) {
            if ((e as any).error_code !== STATUS_MORE_ENTRIES) {
              throw e;
            }
            usersResp = e.getPacket() as any;
          } else {
            throw e;
          }
        }

        const usersBuffer = usersResp.get('Buffer') as any;
        const users = usersBuffer.get('Buffer') as any[];
        for (const user of users) {
          const rid = user.get('RelativeId') as number;
          const name = user.get('Name') as string;
          const r = await hSamrOpenUser(dce, domainHandle, MAXIMUM_ALLOWED, rid);
          console.log(`Found user: ${name}, uid = ${rid}`);
          const userInfo = await hSamrQueryInformationUser2(
            dce,
            r.get('UserHandle') as any,
            USER_INFORMATION_CLASS.enumValues.UserAllInformation!,
          );
          const userInfoBuffer = userInfo.get('Buffer') as any;
          entries.push([name, rid, userInfoBuffer.get('All')]);
          await hSamrCloseHandle(dce, r.get('UserHandle') as any);
        }

        enumerationContext = usersResp.get('EnumerationContext') as number;
        status = usersResp.get('ErrorCode') as number;
      }
    } catch (e) {
      if (e instanceof ListUsersException) {
        critical(`Error listing users: ${e}`);
      } else {
        throw e;
      }
    }

    await dce.disconnect();
    return entries;
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printUsage(): void {
  console.log(`This script downloads the list of users for the target system.

usage: samrdump [-h] [-csv] [-ts] [-debug]
                [-dc-ip ip address] [-target-ip ip address]
                [-port {139,445}] [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                [-aesKey hex key]
                target

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -csv                  Turn CSV output
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

connection:
  -dc-ip ip address     IP Address of the domain controller. If ommited it use
                        the domain part (FQDN) specified in the target
                        parameter
  -target-ip ip address
                        IP Address of the target machine. If ommited it will
                        use whatever was specified as target
  -port {139,445}       Destination port to connect to SMB Server

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters
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
        csv: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
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

  const dumper = new SAMRDump({
    username,
    password: resolvedPassword,
    domain: domain || '',
    hashes: values.hashes ?? null,
    aesKey: values.aesKey ?? null,
    doKerberos,
    kdcHost: values['dc-ip'] ?? null,
    port: parseInt(values.port!, 10),
    csvOutput: values.csv,
  });

  await dumper.dump(remoteName, targetIp);
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
