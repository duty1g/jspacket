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
//   A similar approach to psexec but using DCOM.
//   Uses DCOM objects (MMC20.Application, ShellWindows, ShellBrowserWindow)
//   to execute commands on a remote target. Output is redirected to a temp file
//   on an SMB share, then read back.
//
// Author:
//   beto (@agsolino)
//   Ported to TypeScript
//
// Reference for:
//   DCOM, IDispatch, SMB.

import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
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
  IID_IDispatch,
  IDispatch,
  DISPPARAMS,
  DISPATCH_METHOD,
  DISPATCH_PROPERTYGET,
  VARENUM,
  wireVARIANTStr,
  VARIANT,
  FLAGGED_WORD_BLOB,
  INTERFACE,
  NULL,
  type NDRCALL,
} from '@impacket/dcerpc';
import { stringToBin } from '@impacket/uuid';

// CLSIDs for the three DCOM execution objects
const CLSID_MMC20 = stringToBin('49B2791A-B1AE-4C90-9B8E-E860BA07F889');
const CLSID_ShellWindows = stringToBin('9BA05972-F6A8-11CF-A442-00A0C90A8F39');
const CLSID_ShellBrowserWindow = stringToBin('C08AFD90-F2A1-11D1-8455-00A0C91F3880');

function randomLetters(n: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  let result = '';
  for (let i = 0; i < n; i++) {
    result += chars[Math.floor(Math.random() * chars.length)]!;
  }
  return result;
}

const OUTPUT_FILENAME = '__' + randomLetters(8);

// --------------------------------------------------------------------------
// IDispatch helpers
// --------------------------------------------------------------------------

/** Concatenate abData buffers from an IDispatch response. */
function joinAbData(abData: Buffer[]): Buffer {
  return Buffer.concat(abData.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from([x as unknown as number]))));
}

/** Follow an IDispatch property (PROPERTYGET) and return a new IDispatch on the result. */
async function getDispatchProperty(disp: IDispatch, name: string): Promise<IDispatch> {
  const ids = await disp.GetIDsOfNames([name]);
  const resp = await disp.Invoke(ids[0]!, 0x409, DISPATCH_PROPERTYGET, buildEmptyDispParams(), 0, [], []);
  const result = resp.get('pVarResult') as NDRCALL;
  const vu = result.get('_varUnion') as NDRCALL;
  const pdispVal = vu.get('pdispVal') as NDRCALL;
  const abData = pdispVal.get('abData') as Buffer[];
  return new IDispatch(
    new INTERFACE({
      cinstance: disp.getCinstance(),
      objRef: joinAbData(abData),
      ipidRemUnknown: disp.getIpidRemUnknown(),
      target: disp.getTarget(),
    }),
  );
}

/** Call an IDispatch method by name with the given DISPPARAMS. */
async function invokeMethod(disp: IDispatch, name: string, params: DISPPARAMS): Promise<void> {
  const ids = await disp.GetIDsOfNames([name]);
  await disp.Invoke(ids[0]!, 0x409, DISPATCH_METHOD, params, 0, [], []);
}

function buildEmptyDispParams(): DISPPARAMS {
  const dp = new DISPPARAMS();
  dp.set('cArgs', 0);
  dp.set('cNamedArgs', 0);
  dp.set('rgdispidNamedArgs', NULL);
  return dp;
}

function makeStringVariant(str: string): VARIANT {
  const v = new VARIANT();
  const wvs = v.fields['Data'] as wireVARIANTStr;
  wvs.set('clSize', 0x10);
  wvs.set('vt', VARENUM.VT_BSTR);
  const vu = wvs.fields['_varUnion'] as NDRCALL;
  vu.set('tag', VARENUM.VT_BSTR);
  const bstr = vu.fields['bstrVal'] as NDRCALL;
  const blob = bstr.fields['Data'] as FLAGGED_WORD_BLOB;
  const val = str + '\x00';
  const cp: number[] = [];
  for (let j = 0; j < val.length; j++) cp.push(val.charCodeAt(j));
  blob.set('cBytes', cp.length * 2);
  blob.set('clSize', cp.length);
  blob.set('asData', cp);
  return v;
}

function buildStringDispParams(args: string[]): DISPPARAMS {
  const dp = new DISPPARAMS();
  dp.set('cArgs', args.length);
  dp.set('cNamedArgs', 0);
  dp.set('rgdispidNamedArgs', NULL);
  const pArr = dp.fields['rgvarg'] as NDRCALL;
  const arr = pArr.fields['Data'] as NDRCALL;
  const data = arr.fields['Data'] as unknown[];
  for (let i = args.length - 1; i >= 0; i--) {
    data.push(makeStringVariant(args[i]!));
  }
  return dp;
}

function buildIntDispParams(value: number): DISPPARAMS {
  const dp = new DISPPARAMS();
  dp.set('cArgs', 1);
  dp.set('cNamedArgs', 0);
  dp.set('rgdispidNamedArgs', NULL);
  const v = new VARIANT();
  const wvs = v.fields['Data'] as wireVARIANTStr;
  wvs.set('clSize', 0x10);
  wvs.set('vt', VARENUM.VT_I4);
  const vu = wvs.fields['_varUnion'] as NDRCALL;
  vu.set('tag', VARENUM.VT_I4);
  vu.set('lVal', value);
  const pArr = dp.fields['rgvarg'] as NDRCALL;
  const arr = pArr.fields['Data'] as NDRCALL;
  (arr.fields['Data'] as unknown[]).push(v);
  return dp;
}

// --------------------------------------------------------------------------
// Shared executor interface + factory
// --------------------------------------------------------------------------

interface ExecutorCredentials {
  target: string;
  username: string;
  password: string;
  domain: string;
  lmhash: string;
  nthash: string;
  aesKey: string;
  doKerberos: boolean;
  kdcHost: string | null;
}

interface Executor {
  connect(): Promise<void>;
  execute(command: string, output: boolean): Promise<void>;
  disconnect(): void;
}

function makeDcom(creds: ExecutorCredentials): DCOMConnection {
  return new DCOMConnection(
    creds.target, creds.username, creds.password, creds.domain,
    creds.lmhash, creds.nthash, creds.aesKey,
    null, null, undefined, true, creds.doKerberos, creds.kdcHost,
  );
}

/** Shared ShellExecute logic used by ShellWindows and ShellBrowserWindow. */
async function callShellExecute(iApp: IDispatch, command: string): Promise<void> {
  const parts = command.split(' ');
  const params = buildStringDispParams([parts[0]!, parts.slice(1).join(' '), '', 'open', '0']);
  await invokeMethod(iApp, 'ShellExecute', params);
}

// --------------------------------------------------------------------------
// Executor implementations
// --------------------------------------------------------------------------

class MMC20Executor implements Executor {
  private dcom: DCOMConnection;
  private iView: IDispatch | null = null;
  constructor(private creds: ExecutorCredentials) {
    this.dcom = makeDcom(creds);
  }
  async connect(): Promise<void> {
    await this.dcom.initConnection();
    const iInterface = await this.dcom.CoCreateInstanceEx(CLSID_MMC20, IID_IDispatch);
    const iDispatch = new IDispatch(iInterface as unknown as INTERFACE);
    const iDoc = await getDispatchProperty(iDispatch, 'Document');
    this.iView = await getDispatchProperty(iDoc, 'ActiveView');
  }
  async execute(command: string, _output: boolean): Promise<void> {
    const parts = command.split(' ');
    const params = buildStringDispParams([parts[0]!, '/', parts.slice(1).join(' '), '7']);
    await invokeMethod(this.iView!, 'ExecuteShellCommand', params);
  }
  disconnect(): void { try { this.dcom.disconnect(); } catch { /* ignore */ } }
}

class ShellWindowsExecutor implements Executor {
  private dcom: DCOMConnection;
  private iApp: IDispatch | null = null;
  constructor(private creds: ExecutorCredentials) {
    this.dcom = makeDcom(creds);
  }
  async connect(): Promise<void> {
    await this.dcom.initConnection();
    const iInterface = await this.dcom.CoCreateInstanceEx(CLSID_ShellWindows, IID_IDispatch);
    const iDispatch = new IDispatch(iInterface as unknown as INTERFACE);
    const itemIds = await iDispatch.GetIDsOfNames(['Item']);
    const itemResp = await iDispatch.Invoke(itemIds[0]!, 0x409, DISPATCH_METHOD, buildIntDispParams(0), 0, [], []);
    const ir = itemResp.get('pVarResult') as NDRCALL;
    const vu = ir.get('_varUnion') as NDRCALL;
    const pd = vu.get('pdispVal') as NDRCALL;
    const iItem = new IDispatch(
      new INTERFACE({
        cinstance: iDispatch.getCinstance(),
        objRef: joinAbData(pd.get('abData') as Buffer[]),
        ipidRemUnknown: iDispatch.getIpidRemUnknown(),
        target: iDispatch.getTarget(),
      }),
    );
    const iDoc = await getDispatchProperty(iItem, 'Document');
    this.iApp = await getDispatchProperty(iDoc, 'Application');
  }
  async execute(command: string, _output: boolean): Promise<void> {
    await callShellExecute(this.iApp!, command);
  }
  disconnect(): void { try { this.dcom.disconnect(); } catch { /* ignore */ } }
}

class ShellBrowserWindowExecutor implements Executor {
  private dcom: DCOMConnection;
  private iApp: IDispatch | null = null;
  constructor(private creds: ExecutorCredentials) {
    this.dcom = makeDcom(creds);
  }
  async connect(): Promise<void> {
    await this.dcom.initConnection();
    const iInterface = await this.dcom.CoCreateInstanceEx(CLSID_ShellBrowserWindow, IID_IDispatch);
    const iDispatch = new IDispatch(iInterface as unknown as INTERFACE);
    const iDoc = await getDispatchProperty(iDispatch, 'Document');
    this.iApp = await getDispatchProperty(iDoc, 'Application');
  }
  async execute(command: string, _output: boolean): Promise<void> {
    await callShellExecute(this.iApp!, command);
  }
  disconnect(): void { try { this.dcom.disconnect(); } catch { /* ignore */ } }
}

function createExecutor(object: string, creds: ExecutorCredentials): Executor {
  if (object === 'ShellWindows') return new ShellWindowsExecutor(creds);
  if (object === 'ShellBrowserWindow') return new ShellBrowserWindowExecutor(creds);
  return new MMC20Executor(creds);
}

// --------------------------------------------------------------------------
// DCOMEXEC main class
// --------------------------------------------------------------------------

interface DCOMEXECOptions {
  username: string;
  password: string;
  domain: string;
  hashes?: string;
  aesKey?: string;
  doKerberos: boolean;
  kdcHost?: string;
  share: string;
  noOutput: boolean;
  codec: string;
  dcomObject: string;
  shellType: string;
  silentCommand: boolean;
}

class DCOMEXEC {
  private shell: string;
  private share: string;
  private pwd = 'C:\\';
  private noOutput: boolean;
  private codec: string;
  private dcomObject: string;
  private silentCommand: boolean;
  private creds: ExecutorCredentials;
  private smbConnection: SMBConnection | null = null;
  private executor: Executor | null = null;

  constructor(opts: DCOMEXECOptions) {
    this.share = opts.share;
    this.noOutput = opts.noOutput;
    this.codec = opts.codec;
    this.dcomObject = opts.dcomObject;
    this.silentCommand = opts.silentCommand;
    let lmhash = '', nthash = '';
    if (opts.hashes) {
      const p = opts.hashes.split(':');
      lmhash = p[0] ?? '';
      nthash = p[1] ?? '';
    }
    this.creds = {
      target: '',
      username: opts.username,
      password: opts.password,
      domain: opts.domain,
      lmhash, nthash,
      aesKey: opts.aesKey ?? '',
      doKerberos: opts.doKerberos,
      kdcHost: opts.kdcHost ?? null,
    };
    this.shell = opts.shellType === 'powershell'
      ? 'powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc '
      : 'cmd.exe /Q /c ';
  }

  async run(addr: string, singleCommand?: string): Promise<void> {
    this.creds.target = addr;

    // SMB connection for reading output
    if (!this.noOutput) {
      const smb = new SMBConnection(addr, addr, { sessPort: 445 });
      await smb.negotiateSession();
      if (this.creds.doKerberos) {
        await smb.kerberosLogin(
          this.creds.username, this.creds.password, this.creds.domain,
          this.creds.lmhash, this.creds.nthash, this.creds.aesKey,
          this.creds.kdcHost ?? undefined,
        );
      } else {
        await smb.login(
          this.creds.username, this.creds.password, this.creds.domain,
          this.creds.lmhash, this.creds.nthash,
        );
      }
      this.smbConnection = smb;
    }

    // Try DCOM objects — user-specified first, then fall through others
    const allObjects = ['MMC20', 'ShellWindows', 'ShellBrowserWindow'];
    const tryOrder = [this.dcomObject, ...allObjects.filter(o => o !== this.dcomObject)];
    let connected = false;
    for (const obj of tryOrder) {
      const exec = createExecutor(obj, this.creds);
      try {
        await exec.connect();
        this.executor = exec;
        this.dcomObject = obj;
        connected = true;
        info(`Using DCOM object: ${obj}`);
        break;
      } catch (e) {
        exec.disconnect();
        debug(`${obj} failed: ${String(e)}`);
      }
    }
    if (!connected) {
      critical('All DCOM objects failed. Target may not allow remote DCOM activation.');
      this.cleanup();
      return;
    }

    if (singleCommand) {
      const output = await this.executeRemote(singleCommand);
      if (output) process.stdout.write(output);
      this.cleanup();
      return;
    }

    // Interactive mode
    const cdResult = await this.executeRemote('cd');
    if (cdResult) this.pwd = cdResult.trim();
    info(`Found writable share ${this.share}`);
    console.log('[!] Launching semi-interactive shell - Careful what you execute');
    await this.cmdloop();
  }

  private async getOutput(): Promise<string> {
    if (this.noOutput || !this.smbConnection) return '';
    let out = '';
    try {
      const tid = await this.smbConnection.connectTree(this.share);
      try {
        const fid = await this.smbConnection.openFile(tid, OUTPUT_FILENAME);
        const data = await this.smbConnection.readFile(tid, fid, 0, null, false);
        out = data.toString(this.codec as BufferEncoding);
        await this.smbConnection.closeFile(tid, fid);
      } catch {
        await new Promise((r) => setTimeout(r, 1500));
        try {
          const fid = await this.smbConnection.openFile(tid, OUTPUT_FILENAME);
          const data = await this.smbConnection.readFile(tid, fid, 0, null, false);
          out = data.toString(this.codec as BufferEncoding);
          await this.smbConnection.closeFile(tid, fid);
        } catch { /* still no output */ }
      } finally {
        try { await this.smbConnection.deleteFile(this.share, OUTPUT_FILENAME); } catch { /* ignore */ }
        await this.smbConnection.disconnectTree(tid);
      }
    } catch (e) { debug(`getOutput error: ${String(e)}`); }
    return out;
  }

  async executeRemote(data: string): Promise<string> {
    if (!this.executor) return '';

    let command: string;
    const redir = ` > \\\\127.0.0.1\\${this.share}\\${OUTPUT_FILENAME} 2>&1`;
    if (this.noOutput) {
      command = this.silentCommand ? data : this.shell + data;
    } else {
      command = this.silentCommand ? data + redir : this.shell + data + redir;
    }

    debug(`Executing command: ${command}`);
    try {
      await this.executor.execute(command, !this.noOutput);
    } catch (e) {
      error(`Error executing command: ${String(e)}`);
      return '';
    }
    if (this.noOutput) return '';
    await new Promise((r) => setTimeout(r, 1500));
    return this.getOutput();
  }

  private updatePrompt(rl: ReturnType<typeof createInterface>): void {
    rl.setPrompt(`${this.pwd}> `);
  }

  private async cmdloop(): Promise<void> {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    let closed = false;
    rl.on('close', () => { closed = true; });
    this.updatePrompt(rl);
    rl.prompt();

    const prompt = () => { if (!closed) rl.prompt(); };

    for await (const line of rl) {
      const t = line.trim();
      if (t === 'exit' || t === 'quit') break;
      if (t === '') { prompt(); continue; }

      if (t === 'help') {
        console.log(
          '\n lcd {path}                 - changes the current local directory to {path}\n' +
          ' exit                       - terminates the server process (and this session)\n' +
          ' lput {src_file, dst_path}  - uploads a local file to the dst_path (relative to share)\n' +
          ' lget {file}                - downloads pathname (relative to share) to local dir\n' +
          ' ! {cmd}                    - executes a local shell cmd\n',
        );
        prompt(); continue;
      }

      if (t.startsWith('lcd ')) {
        try { process.chdir(t.slice(4).trim() || '.'); } catch (e) { error(`lcd: ${String(e)}`); }
        prompt(); continue;
      }

      if (t.startsWith('!')) {
        const { execSync } = await import('node:child_process');
        try { process.stdout.write(execSync(t.slice(1), { encoding: 'utf-8' })); } catch (e) { error(String(e)); }
        prompt(); continue;
      }

      if (t.startsWith('lput ')) {
        await this.handleLput(t.slice(5).trim());
        prompt(); continue;
      }

      if (t.startsWith('lget ')) {
        await this.handleLget(t.slice(5).trim());
        prompt(); continue;
      }

      if (t.toLowerCase().startsWith('cd ') || t.toLowerCase() === 'cd') {
        const cdCmd = t.length > 3 ? `cd /d ${t.slice(3).trim()} & cd` : 'cd';
        const out = await this.executeRemote(cdCmd);
        if (out) {
          this.pwd = out.trim();
          this.updatePrompt(rl);
        }
        prompt(); continue;
      }

      // Regular command — prepend cd to cwd so commands run in correct directory
      try {
        const fullCmd = this.pwd !== 'C:\\' ? `cd /d ${this.pwd} & ${t}` : t;
        const out = await this.executeRemote(fullCmd);
        if (out) process.stdout.write(out);
      } catch (e) { error(String(e)); }

      prompt();
    }

    this.cleanup();
  }

  private async handleLput(argStr: string): Promise<void> {
    if (!this.smbConnection) { error('No SMB connection (--nooutput mode)'); return; }
    const parts = argStr.split(',').map((s) => s.trim());
    const src = parts[0]!;
    try {
      const { readFileSync } = await import('node:fs');
      const { basename } = await import('node:path');
      const name = parts[1] || basename(src);
      const tid = await this.smbConnection.connectTree(this.share);
      const fid = await this.smbConnection.openFile(tid, name, 0x02 | 0x04, undefined, 0x40, undefined, 0x80);
      await this.smbConnection.writeFile(tid, fid, readFileSync(src));
      await this.smbConnection.closeFile(tid, fid);
      await this.smbConnection.disconnectTree(tid);
      info(`Uploaded ${src} to \\\\${this.share}\\${name}`);
    } catch (e) { error(`lput: ${String(e)}`); }
  }

  private async handleLget(remotePath: string): Promise<void> {
    if (!this.smbConnection) { error('No SMB connection (--nooutput mode)'); return; }
    try {
      const { writeFileSync } = await import('node:fs');
      const { basename } = await import('node:path');
      const tid = await this.smbConnection.connectTree(this.share);
      const fid = await this.smbConnection.openFile(tid, remotePath);
      const data = await this.smbConnection.readFile(tid, fid, 0, null, false);
      await this.smbConnection.closeFile(tid, fid);
      await this.smbConnection.disconnectTree(tid);
      const local = basename(remotePath);
      writeFileSync(local, data);
      info(`Downloaded ${remotePath} to ${local}`);
    } catch (e) { error(`lget: ${String(e)}`); }
  }

  private cleanup(): void {
    if (this.executor) this.executor.disconnect();
    if (this.smbConnection) {
      try { void this.smbConnection.deleteFile(this.share, OUTPUT_FILENAME).catch(() => {}); } catch { /* ignore */ }
    }
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
        debug: { type: 'boolean', default: false },
        codec: { type: 'string', default: 'utf-8' },
        object: { type: 'string', default: 'MMC20' },
        'shell-type': { type: 'string', default: 'cmd' },
        'com-version': { type: 'string' },
        silentcommand: { type: 'boolean', default: false },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        'dc-ip': { type: 'string' },
        'target-ip': { type: 'string' },
        A: { type: 'string' },
        keytab: { type: 'string' },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    process.exit(1);
  }

  if (values.help || positionals.length === 0) {
    console.log(`Executes a semi-interactive shell using the ShellBrowserWindow DCOM object.

usage: dcomexec [-h] [-share SHARE] [-nooutput] [-ts] [-debug] [-codec CODEC]
                [-object {ShellWindows,ShellBrowserWindow,MMC20}]
                [-shell-type {cmd,powershell}]
                [-com-version MAJOR_VERSION:MINOR_VERSION] [-silentcommand]
                [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                [-dc-ip ip address] [-A authfile] [-keytab KEYTAB]
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
  -debug                Turn DEBUG output ON
  -codec CODEC          Sets encoding used (codec) from the target's output
  -object {ShellWindows,ShellBrowserWindow,MMC20}
                        DCOM object to use for shell command execution
                        (default MMC20)
  -shell-type {cmd,powershell}
                        choose a command processor for the semi-interactive
                        shell
  -com-version MAJOR_VERSION:MINOR_VERSION
                        DCOM version, format is MAJOR_VERSION:MINOR_VERSION
                        (e.g. 5.7)
  -silentcommand        does not execute cmd.exe to run given command (no
                        output)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -A authfile           smbclient/mount.cifs-style authentication file
  -keytab KEYTAB        Read keys for SPN from keytab file
`);
    process.exit(positionals.length === 0 ? 1 : 0);
  }

  initProxy(values.proxy);
  initLogger({ ts: values.ts, debug: values.debug });

  if (values['com-version']) {
    const cp = values['com-version'].split(':');
    const major = parseInt(cp[0]!, 10);
    const minor = parseInt(cp[1] ?? '0', 10);
    if (!isNaN(major)) COMVERSION.setDefaultVersion(major, isNaN(minor) ? undefined : minor);
  }

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
        else if (t.startsWith('hashes=')) values.hashes = t.slice(7);
      }
    } catch (e) {
      critical(`Error reading auth file ${values.A}: ${e}`);
      process.exit(1);
    }
  }

  if (password === '' && username !== '' && !values.hashes && !values['no-pass'] && !values.aesKey && !values.k) {
    critical('Password required. Use --hashes, --no-pass, -k, or provide password in the target string.');
    process.exit(1);
  }

  const validObjects = ['ShellWindows', 'ShellBrowserWindow', 'MMC20'];
  const dcomObject = values.object ?? 'MMC20';
  if (!validObjects.includes(dcomObject)) {
    critical(`Invalid DCOM object: ${dcomObject}. Must be one of: ${validObjects.join(', ')}`);
    process.exit(1);
  }

  let aesKey = values.aesKey ?? '';
  if (values.keytab) {
    const keys = loadKeytabKeys(values.keytab);
    if (keys.aesKey) aesKey = keys.aesKey;
    if (keys.nthash && !values.hashes) values.hashes = `:${keys.nthash}`;
  }
  const doKerberos = values.k || !!aesKey;
  const commandParts = positionals.slice(1);
  const singleCommand = commandParts.length > 0 ? commandParts.join(' ') : undefined;

  const executer = new DCOMEXEC({
    username,
    password,
    domain: domain || '',
    hashes: values.hashes,
    aesKey: aesKey || undefined,
    doKerberos,
    kdcHost: values['dc-ip'],
    share: values.share ?? 'ADMIN$',
    noOutput: values.nooutput ?? false,
    codec: values.codec ?? 'utf-8',
    dcomObject,
    shellType: values['shell-type'] ?? 'cmd',
    silentCommand: values.silentcommand ?? false,
  });

  try {
    await executer.run(targetIp, singleCommand);
  } catch (e) {
    if (String(e).includes('rpc_s_access_denied')) {
      error('Access denied. The user does not have permissions to use DCOM on the target.');
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
