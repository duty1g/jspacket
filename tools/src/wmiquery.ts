#!/usr/bin/env node
/**
 * [MS-WMI] example. It allows to issue WQL queries and get description of the
 * objects.
 *
 *   e.g.: select name from win32_account
 *   e.g.: describe win32_process
 *
 * Original impacket author:
 *   Alberto Solino (@agsolino)
 *
 * TypeScript port for jspacket.
 *
 * Reference for: DCOM / WMI
 */

import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import {
  parseTarget,
  init as initLogger,
  initProxy,
  error,
  critical,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';
import {
  DCOMConnection,
  COMVERSION,
  INTERFACE,
  IWbemLevel1Login,
  type IWbemServices,
  type IEnumWbemClassObject,
  CLSID_WbemLevel1Login,
  IID_IWbemLevel1Login,
  NULL,
  DCERPCException,
  RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
  RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
} from '@impacket/dcerpc';

// WBEM_S_FALSE (0x1) is returned by IEnumWbemClassObject::Next when the
// enumeration is exhausted. impacket detects the end of the result set by the
// S_FALSE status; the jspacket DCE/RPC layer surfaces it as a session error
// carrying error code 0x1.
const WBEM_S_FALSE = 0x1;

// --------------------------------------------------------------------------
// WMIQUERY shell
// --------------------------------------------------------------------------

class WMIQUERY {
  private iWbemServices: IWbemServices;

  constructor(iWbemServices: IWbemServices) {
    this.iWbemServices = iWbemServices;
  }

  private printHelp(): void {
    console.log(`
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 describe {class}           - describes class
 ! {cmd}                    - executes a local shell cmd
 `);
  }

  private async doShell(s: string): Promise<void> {
    const { execSync } = await import('node:child_process');
    try {
      process.stdout.write(execSync(s, { encoding: 'utf-8' }));
    } catch (e) {
      error(String(e));
    }
  }

  private async doDescribe(sClassRaw: string): Promise<void> {
    let sClass = sClassRaw.replace(/\n/g, '');
    if (sClass.endsWith(';')) {
      sClass = sClass.slice(0, -1);
    }
    try {
      const [iObject] = await this.iWbemServices.GetObject(sClass);
      iObject.printInformation();
      await iObject.RemRelease();
    } catch (e) {
      error(String(e));
    }
  }

  private doLcd(s: string): void {
    if (s === '') {
      console.log(process.cwd());
    } else {
      try {
        process.chdir(s);
      } catch (e) {
        error(String(e));
      }
    }
  }

  private async printReply(iEnum: IEnumWbemClassObject): Promise<void> {
    let printHeader = true;
    for (;;) {
      let pEnum;
      try {
        const objects = await iEnum.Next(0xffffffff, 1);
        pEnum = objects[0];
        if (pEnum === undefined) {
          break;
        }
      } catch (e) {
        if (e instanceof DCERPCException && e.getErrorCode() === WBEM_S_FALSE) {
          break;
        }
        if (String(e).includes('S_FALSE')) {
          break;
        }
        throw e;
      }

      const record = pEnum.getProperties();
      const keys = Object.keys(record);

      if (printHeader) {
        let header = '| ';
        for (const col of keys) {
          header += `${col} | `;
        }
        console.log(header);
        printHeader = false;
      }

      let row = '| ';
      for (const key of keys) {
        const value = record[key]!.value;
        if (Array.isArray(value)) {
          for (const item of value) {
            row += `${item} `;
          }
          row += ' | ';
        } else {
          row += `${value} | `;
        }
      }
      console.log(row);
    }
    await iEnum.RemRelease();
  }

  private async doDefault(lineRaw: string): Promise<void> {
    let line = lineRaw.replace(/\n/g, '');
    if (line.endsWith(';')) {
      line = line.slice(0, -1);
    }
    try {
      const iEnumWbemClassObject = await this.iWbemServices.ExecQuery(line.trim());
      await this.printReply(iEnumWbemClassObject);
      await iEnumWbemClassObject.RemRelease();
    } catch (e) {
      error(String(e));
    }
  }

  /**
   * Dispatch a single command line, mirroring cmd.Cmd.onecmd.
   * Returns true when the shell should terminate.
   */
  async onecmd(lineRaw: string): Promise<boolean> {
    const line = lineRaw.replace(/\n/g, '');
    const trimmed = line.trim();

    if (trimmed === '') {
      // emptyline() -> pass
      return false;
    }

    if (trimmed === 'exit') {
      return true;
    }

    if (trimmed === 'help') {
      this.printHelp();
      return false;
    }

    if (trimmed.startsWith('!')) {
      await this.doShell(line.slice(line.indexOf('!') + 1));
      return false;
    }

    if (trimmed === 'lcd' || trimmed.startsWith('lcd ')) {
      this.doLcd(trimmed.slice(3).trim());
      return false;
    }

    if (trimmed === 'describe' || trimmed.startsWith('describe ')) {
      await this.doDescribe(trimmed.slice('describe'.length).trim());
      return false;
    }

    await this.doDefault(line);
    return false;
  }

  async cmdloop(): Promise<void> {
    console.log('[!] Press help for extra shell commands');
    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
      prompt: 'WQL> ',
    });
    rl.prompt();

    for await (const line of rl) {
      let stop = false;
      try {
        stop = await this.onecmd(line);
      } catch (e) {
        error(String(e));
      }
      if (stop) {
        rl.close();
        break;
      }
      rl.prompt();
    }
  }
}

// --------------------------------------------------------------------------
// CLI
// --------------------------------------------------------------------------

function printUsage(): void {
  console.log(`Executes WQL queries and gets object descriptions using Windows Management
Instrumentation.

usage: wmiquery [-h] [-namespace NAMESPACE] [-file FILE] [-debug] [-ts]
                [-com-version MAJOR_VERSION:MINOR_VERSION]
                [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                [-dc-ip ip address]
                [-rpc-auth-level [{integrity,privacy,default}]]
                target

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -namespace NAMESPACE  namespace name (default //./root/cimv2)
  -file FILE            input file with commands to execute in the WQL shell
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output
  -com-version MAJOR_VERSION:MINOR_VERSION
                        DCOM version, format is MAJOR_VERSION:MINOR_VERSION
                        e.g. 5.7

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters. If
                        valid credentials cannot be found, it will use the ones
                        specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)
  -dc-ip ip address     IP Address of the domain controller. If ommited it use
                        the domain part (FQDN) specified in the target parameter
  -rpc-auth-level [{integrity,privacy,default}]
                        default, integrity (RPC_C_AUTHN_LEVEL_PKT_INTEGRITY) or
                        privacy (RPC_C_AUTHN_LEVEL_PKT_PRIVACY). For example CIM
                        path "root/MSCluster" would require privacy level by
                        default)`);
}

async function main(): Promise<void> {
  console.log(BANNER + '\n');

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: normalizeArgs(process.argv.slice(2)),
      allowPositionals: true,
      options: {
        namespace: { type: 'string', default: '//./root/cimv2' },
        file: { type: 'string' },
        debug: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        'com-version': { type: 'string' },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        'dc-ip': { type: 'string' },
        'rpc-auth-level': { type: 'string', default: 'default' },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
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

  // Parse COM version (dot separated, e.g. 5.7)
  if (values['com-version'] != null) {
    const parts = values['com-version'].split('.');
    const major = parseInt(parts[0]!, 10);
    const minor = parseInt(parts[1]!, 10);
    if (parts.length !== 2 || isNaN(major) || isNaN(minor)) {
      error('Wrong COMVERSION format, use dot separated integers e.g. "5.7"');
      process.exit(1);
    }
    COMVERSION.setDefaultVersion(major, minor);
  }

  let [domain, username, password, address] = parseTarget(positionals[0]!);
  if (domain == null) {
    domain = '';
  }

  let doKerberos = values.k ?? false;
  if (values.aesKey != null) {
    doKerberos = true;
  }

  let lmhash = '';
  let nthash = '';
  if (values.hashes != null) {
    const parts = values.hashes.split(':');
    lmhash = parts[0] ?? '';
    nthash = parts[1] ?? '';
  }

  if (
    password === '' &&
    username !== '' &&
    values.hashes == null &&
    !values['no-pass'] &&
    values.aesKey == null
  ) {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    password = await new Promise<string>((resolve) => {
      rl.question('Password:', (answer) => {
        rl.close();
        resolve(answer);
      });
    });
  }

  const rpcAuthLevel = values['rpc-auth-level'] ?? 'default';

  let dcom: DCOMConnection | null = null;
  try {
    dcom = new DCOMConnection(
      address,
      username,
      password,
      domain,
      lmhash,
      nthash,
      values.aesKey ?? '',
      undefined,
      undefined,
      undefined,
      true,
      doKerberos,
      values['dc-ip'] ?? null,
    );
    await dcom.initConnection();

    const iInterface = await dcom.CoCreateInstanceEx(
      CLSID_WbemLevel1Login,
      IID_IWbemLevel1Login,
    );
    const iWbemLevel1Login = new IWbemLevel1Login(iInterface as unknown as INTERFACE);
    const iWbemServices = await iWbemLevel1Login.NTLMLogin(values.namespace!, '', NULL);

    if (rpcAuthLevel === 'privacy') {
      iWbemServices.getDceRpc().setAuthLevel(RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
    } else if (rpcAuthLevel === 'integrity') {
      iWbemServices.getDceRpc().setAuthLevel(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY);
    }

    await iWbemLevel1Login.RemRelease();

    const shell = new WMIQUERY(iWbemServices);
    const inlineQuery = positionals[1];
    if (inlineQuery != null) {
      await shell.onecmd(inlineQuery);
    } else if (values.file == null) {
      await shell.cmdloop();
    } else {
      const contents = readFileSync(values.file, 'utf-8');
      for (const line of contents.split('\n')) {
        process.stdout.write(`WQL> ${line} `);
        console.log();
        await shell.onecmd(line);
      }
    }

    await iWbemServices.RemRelease();
    dcom.disconnect();
  } catch (e) {
    critical(String(e));
    try {
      dcom?.disconnect();
    } catch {
      /* best-effort */
    }
  }

  process.exit(0);
}

main().catch((e) => {
  critical(String(e));
  process.exit(1);
});
