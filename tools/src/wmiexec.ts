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
//   A semi-interactive shell used through WMI. It does not require to install
//   any service/agent at the target server. Runs as Administrator. Highly stealthy.
//
// Author:
//   beto (@agsolino)
//   Ported to TypeScript
//
// Reference for:
//   DCOM and WMI.
//

import { Buffer } from 'node:buffer';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import {
  parseTarget,
  init as initLogger,
  initProxy,
  info,
  error,
  debug,
  warning,
  critical,
  normalizeArgs,
  loadKeytabKeys,
  BANNER,
} from '@impacket/examples';
import { SMBConnection } from '@impacket/smb-connection';
import {
  DCOMConnection,
  COMVERSION,
  INTERFACE,
  IWbemLevel1Login,
  type IWbemServices,
  type IWbemClassObject,
  CLSID_WbemLevel1Login,
  IID_IWbemLevel1Login,
  NULL,
  DCERPCException,
} from '@impacket/dcerpc';

// --------------------------------------------------------------------------
// Utility
// --------------------------------------------------------------------------

function randomLetters(n: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  let result = '';
  for (let i = 0; i < n; i++) {
    result += chars[Math.floor(Math.random() * chars.length)]!;
  }
  return result;
}

const OUTPUT_FILENAME = `__${Date.now()}_${randomLetters(5)}`;

// --------------------------------------------------------------------------
// WMIEXEC class
// --------------------------------------------------------------------------

class WMIEXEC {
  private command: string;
  private username: string;
  private password: string;
  private domain: string;
  private lmhash: string;
  private nthash: string;
  private aesKey: string;
  private doKerberos: boolean;
  private kdcHost: string;
  private share: string;
  private noOutput: boolean;
  private codec: string;
  private shellType: string;
  private comVersion: [number, number] | null;
  private port: number;

  private shell = '';
  private pwd = 'C:\\';
  private targetAddr = '';
  private smbConnection: SMBConnection | null = null;
  private win32Process: IWbemClassObject | null = null;
  private dcom: DCOMConnection | null = null;
  private iWbemServices: IWbemServices | null = null;
  private outputBuffer = '';

  constructor(
    command: string,
    username: string,
    password: string,
    domain: string,
    hashes: string,
    aesKey: string,
    share: string,
    noOutput: boolean,
    doKerberos: boolean,
    kdcHost: string,
    shellType: string,
    codec: string,
    comVersion: [number, number] | null,
    port: number,
  ) {
    this.command = command;
    this.username = username;
    this.password = password;
    this.domain = domain;
    this.lmhash = '';
    this.nthash = '';
    if (hashes) {
      const parts = hashes.split(':');
      this.lmhash = parts[0] ?? '';
      this.nthash = parts[1] ?? '';
    }
    this.aesKey = aesKey;
    this.doKerberos = doKerberos;
    this.kdcHost = kdcHost;
    this.share = share;
    this.noOutput = noOutput;
    this.codec = codec;
    this.shellType = shellType;
    this.comVersion = comVersion;
    this.port = port;

    if (shellType === 'powershell') {
      this.shell = 'powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc ';
    } else {
      this.shell = 'cmd.exe /Q /c ';
    }
  }

  async run(addr: string, silentCommand: boolean): Promise<void> {
    if (this.comVersion !== null) {
      COMVERSION.setDefaultVersion(this.comVersion[0], this.comVersion[1]);
    }

    this.targetAddr = addr;

    try {
      await this.initWmi(addr);
    } catch (e: any) {
      critical(`Error initializing WMI: ${e}`);
      if (e?.stack) critical(e.stack);
      if (this.dcom) this.dcom.disconnect();
      process.exit(1);
    }

    if (!this.noOutput) {
      try {
        await this.connectSmbForOutput(addr);
        const dialect = this.smbConnection!.getDialect();
        if (typeof dialect === 'string') {
          info('SMBv1 dialect used');
        } else if (dialect === 0x0202) {
          info('SMBv2.0 dialect used');
        } else if (dialect === 0x0210) {
          info('SMBv2.1 dialect used');
        } else {
          info('SMBv3.0 dialect used');
        }
      } catch (e) {
        warning(`Could not connect SMB for output retrieval: ${e}`);
        warning('Switching to no-output mode');
        this.noOutput = true;
      }
    }

    try {
      if (this.command !== '') {
        await this.execHandler(this.command, silentCommand);
      } else {
        await this.cmdloop();
      }
    } finally {
      if (this.dcom) {
        try { this.dcom.disconnect(); } catch { /* best-effort */ }
      }
    }
  }

  private async initWmi(addr: string): Promise<void> {
    this.dcom = new DCOMConnection(
      addr,
      this.username,
      this.password,
      this.domain,
      this.lmhash,
      this.nthash,
      this.aesKey,
      undefined, undefined, undefined,
      true,
      this.doKerberos,
      this.kdcHost || null,
    );
    await this.dcom.initConnection();

    const iInterface = await this.dcom.CoCreateInstanceEx(
      CLSID_WbemLevel1Login,
      IID_IWbemLevel1Login,
    );
    const iWbemLevel1Login = new IWbemLevel1Login(
      iInterface as unknown as INTERFACE,
    );
    this.iWbemServices = await iWbemLevel1Login.NTLMLogin(
      '//./root/cimv2', '', NULL,
    );
    const [win32Process] = await this.iWbemServices.GetObject('Win32_Process');
    this.win32Process = win32Process;
    debug('WMI session established');
  }

  private async reconnect(): Promise<void> {
    info('Session expired, reconnecting...');
    if (this.dcom) {
      try { this.dcom.disconnect(); } catch { /* ignore */ }
    }
    await this.initWmi(this.targetAddr);
    if (!this.noOutput) {
      await this.connectSmbForOutput(this.targetAddr);
    }
    info('Reconnected successfully');
  }

  private async connectSmbForOutput(addr: string): Promise<void> {
    this.targetAddr = addr;
    this.smbConnection = new SMBConnection(addr, addr, {
      sessPort: this.port,
    });
    await this.smbConnection.negotiateSession();

    if (this.doKerberos) {
      await this.smbConnection.kerberosLogin(
        this.username, this.password, this.domain,
        this.lmhash, this.nthash, this.aesKey,
        this.kdcHost || null,
      );
    } else {
      await this.smbConnection.login(
        this.username, this.password, this.domain,
        this.lmhash, this.nthash,
      );
    }
    this.smbConnection.setTimeout(100000);
  }

  async execHandler(data: string, silentCommand = false): Promise<void> {
    if (silentCommand) {
      await this.executeRemote(data);
      return;
    }

    await this.executeRemote(data);

    if (!this.noOutput && this.outputBuffer.length > 0) {
      try {
        process.stdout.write(this.outputBuffer);
      } catch {
        error(
          'Decoding error detected, consider running chcp.com at the target,\n' +
          'map the result with https://docs.python.org/3/library/codecs.html#standard-encodings\n' +
          'and then execute wmiexec again with --codec and the corresponding codec',
        );
      }
      this.outputBuffer = '';
    }
  }

  private async executeRemote(data: string): Promise<void> {
    if (!this.iWbemServices || !this.win32Process) {
      throw new Error('WMI session not initialized');
    }

    this.outputBuffer = '';

    // Delete stale output file from previous command to prevent reading old data
    if (!this.noOutput && this.smbConnection) {
      try {
        await this.smbConnection.deleteFile(this.share, OUTPUT_FILENAME);
      } catch {
        // File may not exist or delete may fail — getOutput handles retries
      }
    }

    // ADMIN$ maps to %SystemRoot% (typically C:\Windows)
    const outputPath = `\\\\127.0.0.1\\${this.share}\\${OUTPUT_FILENAME}`;

    // Build the full command line
    let command: string;
    if (this.shellType === 'powershell') {
      const psCmd = '$ProgressPreference="SilentlyContinue";' + data;
      const encoded = Buffer.from(psCmd, 'utf16le').toString('base64');
      command = this.shell + encoded;
    } else {
      command = this.shell + data;
    }

    if (!this.noOutput) {
      command += ` 1> ${outputPath} 2>&1`;
    }

    debug(`Executing remote: ${command}`);

    // Invoke Win32_Process.Create(CommandLine, CurrentDirectory, null).
    // The IWbemClassObject for Win32_Process has a dynamically-created
    // Create() method that delegates to IWbemServices.ExecMethod().
    try {
      const createFn = (this.win32Process as unknown as Record<string, unknown>)[
        'Create'
      ] as ((...args: unknown[]) => Promise<IWbemClassObject | null>) | undefined;

      if (typeof createFn === 'function') {
        const result = await createFn.call(
          this.win32Process, command, this.pwd, null,
        );
        if (result) {
          const rv = (result as unknown as Record<string, unknown>)['ReturnValue'] as number | undefined;
          if (rv !== undefined && rv !== 0) {
            error(`Win32_Process.Create returned ${rv}`);
          }
        }
      } else {
        error('Win32_Process.Create dynamic method not found on class object');
      }
    } catch (e: any) {
      const errStr = String(e);
      if (errStr.includes('Session') || errStr.includes('Broken') ||
          errStr.includes('ECONNRESET') || errStr.includes('EPIPE') ||
          errStr.includes('0x778') || errStr.includes('timed out')) {
        throw e;
      }
      debug(`Process creation error: ${e}`);
    }

    if (!this.noOutput) {
      await this.getOutput();
    }
  }

  private async getOutput(): Promise<void> {
    if (!this.smbConnection) return;

    const FILE_READ_DATA = 0x00000001;
    const FILE_SHARE_RWD = 0x00000001 | 0x00000002 | 0x00000004;

    for (let attempt = 0; attempt < 30; attempt++) {
      try {
        const tid = await this.smbConnection.connectTree(this.share);
        try {
          const fid = await this.smbConnection.openFile(
            tid, OUTPUT_FILENAME, FILE_READ_DATA, FILE_SHARE_RWD,
          );
          const data = await this.smbConnection.readFile(tid, fid, 0, null, false);
          await this.smbConnection.closeFile(tid, fid);
          try {
            this.outputBuffer = data.toString(this.codec as BufferEncoding);
          } catch {
            this.outputBuffer = data.toString('utf-8');
          }
          try {
            await this.smbConnection.deleteFile(this.share, OUTPUT_FILENAME);
          } catch {
            debug('Could not delete output file from share');
          }
          await this.smbConnection.disconnectTree(tid);
          return;
        } catch (e: any) {
          try { await this.smbConnection.disconnectTree(tid); } catch { /* ignore */ }
          const errStr = String(e);
          if (errStr.includes('0xc0000043') || errStr.includes('SHARING_VIOLATION')) {
            await new Promise((r) => setTimeout(r, 1000));
            continue;
          }
          throw e;
        }
      } catch (e: any) {
        const errStr = String(e);
        if (errStr.includes('0xc0000043') || errStr.includes('SHARING_VIOLATION') ||
            errStr.includes('0xc0000034') || errStr.includes('OBJECT_NAME_NOT_FOUND')) {
          await new Promise((r) => setTimeout(r, 1500));
          continue;
        }
        if (errStr.includes('Broken') || errStr.includes('ECONNRESET') || errStr.includes('EPIPE')) {
          debug('Connection broken, trying to reconnect');
          try { await this.connectSmbForOutput(this.targetAddr); } catch { /* ignore */ }
          continue;
        }
        debug(`getOutput error: ${e}`);
        return;
      }
    }
  }

  // -----------------------------------------------------------------------
  // Interactive shell
  // -----------------------------------------------------------------------

  private async cmdloop(): Promise<void> {
    console.log('[!] Launching semi-interactive shell - Careful what you execute');
    console.log('[!] Press help for extra shell commands');

    // Determine the initial working directory from the target
    await this.executeRemote('cd');
    if (this.outputBuffer.length > 0) {
      this.pwd = this.outputBuffer.replace(/\r?\n/g, '').trim();
      this.outputBuffer = '';
    }

    const getPrompt = (): string =>
      this.shellType === 'powershell' ? `PS ${this.pwd}> ` : `${this.pwd}>`;

    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
      prompt: getPrompt(),
    });
    rl.prompt();

    let isClosed = false;
    rl.on('close', () => { isClosed = true; });

    for await (const line of rl) {
      const trimmed = line.trim();

      if (trimmed === '') { rl.prompt(); continue; }

      if (trimmed === 'exit' || trimmed === 'quit') {
        rl.close();
        break;
      }

      if (trimmed === 'help') {
        console.log(
          '\n lcd {path}                 - changes the current local directory to {path}\n' +
          ' exit                       - terminates the server process (and this session)\n' +
          ` lput {src_file, dst_path}  - uploads a local file to dst_path RELATIVE to ${this.share}\n` +
          ` lget {file}                - downloads pathname RELATIVE to ${this.share} to the current local dir\n` +
          ' ! {cmd}                    - executes a local shell cmd\n',
        );
        rl.prompt();
        continue;
      }

      // lcd -- change local directory
      if (trimmed.startsWith('lcd ') || trimmed === 'lcd') {
        const dir = trimmed.slice(4).trim();
        if (dir === '') { console.log(process.cwd()); }
        else { try { process.chdir(dir); } catch (e) { error(`lcd: ${e}`); } }
        rl.prompt();
        continue;
      }

      // lget -- download file from remote share
      if (trimmed.startsWith('lget ')) {
        await this.doLget(trimmed.slice(5).trim());
        rl.prompt();
        continue;
      }

      // lput -- upload file to remote share
      if (trimmed.startsWith('lput ')) {
        const args = trimmed.slice(5).trim().split(/[,\s]+/);
        await this.doLput(args[0] ?? '', args[1] ?? path.basename(args[0] ?? ''));
        rl.prompt();
        continue;
      }

      // ! -- local shell command
      if (trimmed.startsWith('!')) {
        const { execSync } = await import('node:child_process');
        try {
          process.stdout.write(execSync(trimmed.slice(1), { encoding: 'utf-8' }));
        } catch (e) { error(String(e)); }
        rl.prompt();
        continue;
      }

      try {
        // cd -- track working directory locally
        if (/^cd(\s|$)/i.test(trimmed)) {
          await this.doCd(trimmed.slice(2).trim());
          rl.setPrompt(getPrompt());
          rl.prompt();
          continue;
        }

        // Drive change (e.g. "D:") — match Python's default() handler
        if (trimmed.length === 2 && trimmed[1] === ':') {
          await this.executeRemote(trimmed);
          const stripped = this.outputBuffer.replace(/\r?\n/g, '').trim();
          if (stripped.length > 0) {
            process.stdout.write(this.outputBuffer);
            this.outputBuffer = '';
          } else {
            this.pwd = trimmed;
            await this.executeRemote('cd');
            const newPwd = this.outputBuffer.replace(/\r?\n/g, '').trim();
            if (newPwd) this.pwd = newPwd;
            this.outputBuffer = '';
          }
          rl.setPrompt(getPrompt());
          rl.prompt();
          continue;
        }

        // Regular command
        await this.execHandler(trimmed);
      } catch (e: any) {
        const errStr = String(e);
        if (errStr.includes('Session') || errStr.includes('Broken') ||
            errStr.includes('ECONNRESET') || errStr.includes('EPIPE') ||
            errStr.includes('0x778') || errStr.includes('timed out')) {
          try {
            await this.reconnect();
            // Retry the command after reconnection
            if (/^cd(\s|$)/i.test(trimmed)) {
              await this.doCd(trimmed.slice(2).trim());
              rl.setPrompt(getPrompt());
            } else {
              await this.execHandler(trimmed);
            }
          } catch (retryErr) {
            error(`Reconnection failed: ${retryErr}`);
          }
        } else {
          error(String(e));
        }
      }

      if (isClosed) break;
      rl.prompt();
    }
  }

  private async doCd(target: string): Promise<void> {
    if (target === '') {
      await this.executeRemote('cd');
      if (this.outputBuffer.length > 0) {
        const newPwd = this.outputBuffer.replace(/\r?\n/g, '').trim();
        if (newPwd) this.pwd = newPwd;
        process.stdout.write(this.outputBuffer);
        this.outputBuffer = '';
      }
      return;
    }

    // Match Python: run cd <target>, check for error output
    await this.executeRemote(`cd ${target}`);
    const stripped = this.outputBuffer.replace(/\r?\n/g, '').trim();
    if (stripped.length > 0) {
      // cd produced output → error message
      process.stdout.write(this.outputBuffer);
      this.outputBuffer = '';
    } else {
      // cd succeeded (no output) — verify actual cwd
      this.pwd = path.win32.resolve(this.pwd, target);
      await this.executeRemote('cd');
      const newPwd = this.outputBuffer.replace(/\r?\n/g, '').trim();
      if (newPwd) this.pwd = newPwd;
      this.outputBuffer = '';
    }
  }

  private async doLget(remotePath: string): Promise<void> {
    if (!remotePath) { error('Usage: lget <remote_path>'); return; }
    if (!this.smbConnection) { error('No SMB connection for file transfer'); return; }

    try {
      const tid = await this.smbConnection.connectTree(this.share);
      try {
        const fid = await this.smbConnection.openFile(tid, remotePath);
        const data = await this.smbConnection.readFile(tid, fid, 0, null, true);
        await this.smbConnection.closeFile(tid, fid);
        const localName = path.basename(remotePath);
        writeFileSync(localName, data);
        info(`Downloaded ${remotePath} -> ${path.resolve(localName)}`);
      } finally {
        try { await this.smbConnection.disconnectTree(tid); } catch { /* ignore */ }
      }
    } catch (e) { error(`lget failed: ${e}`); }
  }

  private async doLput(srcFile: string, dstPath: string): Promise<void> {
    if (!srcFile) { error('Usage: lput <src_file>[, <dst_path>]'); return; }
    if (!this.smbConnection) { error('No SMB connection for file transfer'); return; }
    if (!existsSync(srcFile)) { error(`Local file not found: ${srcFile}`); return; }

    try {
      const fileData = readFileSync(srcFile);
      const tid = await this.smbConnection.connectTree(this.share);
      try {
        const fid = await this.smbConnection.openFile(tid, dstPath);
        await this.smbConnection.writeFile(tid, fid, fileData);
        await this.smbConnection.closeFile(tid, fid);
        info(`Uploaded ${srcFile} -> ${dstPath}`);
      } finally {
        try { await this.smbConnection.disconnectTree(tid); } catch { /* ignore */ }
      }
    } catch (e) { error(`lput failed: ${e}`); }
  }
}

// --------------------------------------------------------------------------
// CLI
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
        share: { type: 'string', default: 'ADMIN$' },
        nooutput: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        silentcommand: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        codec: { type: 'string', default: 'utf-8' },
        'shell-type': { type: 'string', default: 'cmd' },
        'com-version': { type: 'string' },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        'dc-ip': { type: 'string' },
        'target-ip': { type: 'string' },
        A: { type: 'string' },
        keytab: { type: 'string' },
        port: { type: 'string', default: '445' },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    process.exit(1);
  }

  if (values.help || positionals.length === 0) {
    console.log(`Executes a semi-interactive shell using Windows Management Instrumentation.

usage: wmiexec [-h] [-share SHARE] [-nooutput] [-ts] [-silentcommand] [-debug]
               [-codec CODEC] [-shell-type {cmd,powershell}]
               [-com-version MAJOR_VERSION:MINOR_VERSION]
               [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
               [-dc-ip ip address] [-target-ip ip address] [-A authfile]
               [-keytab KEYTAB]
               target [command ...]

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>
  command               command to execute at the target. If empty it will
                        launch a semi-interactive shell

options:
  -h, --help            show this help message and exit
  -share SHARE          share where the output will be grabbed from (default
                        ADMIN$)
  -nooutput             whether or not to print the output (no SMB connection
                        created)
  -ts                   Adds timestamp to every logging output
  -silentcommand        does not execute cmd.exe to run given command (no
                        output)
  -debug                Turn DEBUG output ON
  -codec CODEC          Sets encoding used (codec) from the target's output
                        (default "utf-8")
  -shell-type {cmd,powershell}
                        choose a command processor for the semi-interactive
                        shell
  -com-version MAJOR_VERSION:MINOR_VERSION
                        DCOM version, format is MAJOR_VERSION:MINOR_VERSION
                        e.g. 5.7

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters.
                        If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)
  -dc-ip ip address     IP Address of the domain controller. If ommited it use
                        the domain part (FQDN) specified in the target
                        parameter
  -target-ip ip address
                        IP Address of the target machine. If ommited it will
                        use whatever was specified as target
  -A authfile           smbclient/mount.cifs-style authentication file. See
                        smbclient man page's -A option
  -keytab KEYTAB        Read keys for SPN from keytab file
`);
    process.exit(positionals.length === 0 ? 1 : 0);
  }

  initProxy(values.proxy);
  initLogger({ ts: values.ts, debug: values.debug });

  const target = positionals[0]!;
  let [domain, username, password, remoteName] = parseTarget(target);
  const targetIp = values['target-ip'] ?? remoteName;

  // Handle auth file (-A)
  if (values.A) {
    try {
      const authData = readFileSync(values.A, 'utf-8');
      for (const line of authData.split('\n')) {
        const t = line.trim();
        if (t.startsWith('username=')) username = t.slice(9);
        else if (t.startsWith('password=')) password = t.slice(9);
        else if (t.startsWith('domain=')) domain = t.slice(7);
      }
    } catch (e) {
      critical(`Error reading auth file ${values.A}: ${e}`);
      process.exit(1);
    }
  }

  if (
    password === '' &&
    username !== '' &&
    !values.hashes &&
    !values['no-pass'] &&
    !values.aesKey &&
    !values.k
  ) {
    critical(
      'Password required. Use --hashes, --no-pass, -k, or provide password in the target string.',
    );
    process.exit(1);
  }

  let doKerberos = values.k ?? false;

  // Handle keytab
  let aesKey = values.aesKey ?? '';
  if (values.keytab) {
    const keys = loadKeytabKeys(values.keytab);
    if (keys.aesKey) aesKey = keys.aesKey;
    if (keys.nthash && !values.hashes) values.hashes = `:${keys.nthash}`;
    doKerberos = true;
  }
  if (aesKey) doKerberos = true;

  // Parse COM version
  let comVersion: [number, number] | null = null;
  if (values['com-version']) {
    const vParts = values['com-version'].split(':');
    if (vParts.length !== 2) {
      critical('Invalid --com-version format. Expected major:minor, e.g. 5:7');
      process.exit(1);
    }
    const major = parseInt(vParts[0]!, 10);
    const minor = parseInt(vParts[1]!, 10);
    if (isNaN(major) || isNaN(minor)) {
      critical('Invalid --com-version values. Expected integers, e.g. 5:7');
      process.exit(1);
    }
    comVersion = [major, minor];
  }

  const shellType = values['shell-type'] ?? 'cmd';
  if (shellType !== 'cmd' && shellType !== 'powershell') {
    critical('--shell-type must be "cmd" or "powershell"');
    process.exit(1);
  }

  const command = positionals.slice(1).join(' ');
  const silentCommand = values.silentcommand ?? false;

  const executer = new WMIEXEC(
    command,
    username,
    password,
    domain || '',
    values.hashes ?? '',
    aesKey,
    values.share ?? 'ADMIN$',
    values.nooutput ?? false,
    doKerberos,
    values['dc-ip'] ?? '',
    shellType,
    values.codec ?? 'utf-8',
    comVersion,
    parseInt(values.port ?? '445', 10),
  );

  try {
    await executer.run(targetIp, silentCommand);
  } catch (e) {
    if (e instanceof DCERPCException) {
      critical(`DCE/RPC error: ${e}`);
    } else {
      critical(String(e));
    }
  }
  process.exit(0);
}

main().catch((e) => {
  critical(String(e));
  process.exit(1);
});
