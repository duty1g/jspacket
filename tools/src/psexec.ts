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
//   PSEXEC like functionality example using RemComSvc
//   (https://github.com/kavika13/RemCom)
//
// Author:
//   beto (@agsolino)
//   Ported to TypeScript
//
// Reference for:
//   DCE/RPC and SMB.
//

import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import {
  parseTarget,
  init as initLogger,
  initProxy,
  info,
  error,
  critical,
  debug,
  ServiceInstall,
  normalizeArgs,
  loadKeytabKeys,
  BANNER,
} from '@impacket/examples';
import { SMBConnection } from '@impacket/smb-connection';
import {
  DCERPCTransportFactory,
  type SMBTransport,
  type DCERPC_v5,
} from '@impacket/dcerpc';

// --------------------------------------------------------------------------
// RemCom protocol structures
// --------------------------------------------------------------------------

const REMCOM_COMMAND_LEN = 4096;
const REMCOM_WORKINGDIR_LEN = 260;
const REMCOM_MACHINE_LEN = 260;

const REMCOMSVC_EXE = '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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAeEAAA4CMAAB4QAADIGAAA7CMAAMgYAAAXGQAADCQAABcZAAA1GQAAGCQAADUZAACgGQAAICQAAKAZAADyGQAAMCQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAwAAAAAoAigAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

function buildRemComMessage(opts: {
  command: string;
  workingDir?: string;
  priority?: number;
  processId?: number;
  machine?: string;
  noWait?: number;
}): Buffer {
  const buf = Buffer.alloc(REMCOM_COMMAND_LEN + REMCOM_WORKINGDIR_LEN + 4 + 4 + REMCOM_MACHINE_LEN + 4);
  let offset = 0;

  // Command (4096 bytes, null-padded)
  buf.write(opts.command, offset, 'utf-8');
  offset += REMCOM_COMMAND_LEN;

  // WorkingDir (260 bytes, null-padded)
  if (opts.workingDir) {
    buf.write(opts.workingDir, offset, 'utf-8');
  }
  offset += REMCOM_WORKINGDIR_LEN;

  // Priority (uint32 LE)
  buf.writeUInt32LE(opts.priority ?? 0x20, offset);
  offset += 4;

  // ProcessID (uint32 LE)
  buf.writeUInt32LE(opts.processId ?? 1, offset);
  offset += 4;

  // Machine (260 bytes, null-padded)
  const machine = opts.machine ?? '';
  buf.write(machine, offset, 'utf-8');
  offset += REMCOM_MACHINE_LEN;

  // NoWait (uint32 LE)
  buf.writeUInt32LE(opts.noWait ?? 0, offset);

  return buf;
}

function parseRemComResponse(data: Buffer): { errorCode: number; returnCode: number } {
  return {
    errorCode: data.readUInt32LE(0),
    returnCode: data.readUInt32LE(4),
  };
}


function randomLetters(n: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  let result = '';
  for (let i = 0; i < n; i++) {
    result += chars[Math.floor(Math.random() * chars.length)]!;
  }
  return result;
}

// --------------------------------------------------------------------------
// Pipe management
// --------------------------------------------------------------------------

const FILE_WRITE_DATA = 0x00000002;
const FILE_APPEND_DATA = 0x00000004;
const FILE_READ_DATA = 0x00000001;

async function openPipe(
  conn: SMBConnection,
  tid: number,
  pipeName: string,
  accessMask: number,
): Promise<number | Buffer> {
  let pipeReady = false;
  let tries = 50;
  while (!pipeReady && tries > 0) {
    try {
      await conn.waitNamedPipe(tid, pipeName);
      pipeReady = true;
    } catch {
      tries--;
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  if (tries === 0) {
    throw new Error('Pipe not ready, aborting');
  }
  return conn.openFile(tid, pipeName, accessMask, undefined, 0x40, undefined, 0x80);
}

async function connectPipe(
  transport: SMBTransport,
  pipeName: string,
  permissions: number,
  port: number,
  codec: string,
): Promise<{ server: SMBConnection; tid: number; fid: number | Buffer }> {
  const credentials = transport.getCredentials();
  const [user, passwd, domain, lm, nt] = credentials;
  const remoteHost = transport.getSmbConnection()!.getRemoteHost();
  const remoteName = transport.getSmbConnection()!.getRemoteName();
  const dialect = transport.getSmbConnection()!.getDialect();

  const server = new SMBConnection(remoteName, remoteHost, {
    sessPort: port,
    preferredDialect: dialect as number,
  });
  await server.negotiateSession();

  if (transport.getKerberos()) {
    await server.kerberosLogin(
      user ?? '', passwd ?? '', domain, lm, nt,
      credentials[5] as string,
      transport.getKdcHost() ?? undefined,
      credentials[6] as null,
      credentials[7] as null,
    );
  } else {
    await server.login(user ?? '', passwd ?? '', domain, lm, nt);
  }

  const tid = await server.connectTree('IPC$');
  let pipeReady = false;
  let tries = 25;
  while (!pipeReady && tries > 0) {
    try {
      await server.waitNamedPipe(tid, pipeName);
      pipeReady = true;
    } catch {
      tries--;
      debug(`Data pipe ${pipeName} not ready, retrying (${tries} left)...`);
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  if (!pipeReady) {
    throw new Error(`Data pipe ${pipeName} not ready after retries`);
  }
  const fid = await server.openFile(tid, pipeName, permissions, undefined, 0x40, undefined, 0x80);
  server.setTimeout(1000000);

  return { server, tid, fid };
}

// --------------------------------------------------------------------------
// Remote stdout pipe reader
// --------------------------------------------------------------------------

async function runStdoutPipe(
  transport: SMBTransport,
  pipeName: string,
  port: number,
  codec: string,
): Promise<void> {
  const { server, tid, fid } = await connectPipe(transport, pipeName, FILE_READ_DATA, port, codec);

  let outputBuffer = Buffer.alloc(0);
  const promptRegex = /^([a-zA-Z]:[\\\/])((([a-zA-Z0-9 \-\.]*)[\\\/]?)+(([a-zA-Z0-9 \-\.]+))?)?>$/;

  while (true) {
    let data: Buffer;
    try {
      data = await server.readFile(tid, fid, 0, 1024);
    } catch {
      break;
    }

    if (data.length === 0) continue;

    outputBuffer = Buffer.concat([outputBuffer, data]);

    const bufStr = outputBuffer.toString(codec as BufferEncoding);
    const endsWithPrompt = promptRegex.test(bufStr);

    let toPrint = '';
    if (endsWithPrompt) {
      toPrint = bufStr + ' ';
      outputBuffer = Buffer.alloc(0);
    } else if (bufStr.includes('\n')) {
      const lines = bufStr.split('\n');
      toPrint = lines.slice(0, -1).join('\n') + '\n';
      const remainder = lines[lines.length - 1]!;
      if (promptRegex.test(remainder)) {
        toPrint += remainder + ' ';
        outputBuffer = Buffer.alloc(0);
      } else {
        outputBuffer = Buffer.from(remainder, codec as BufferEncoding);
      }
    }

    if (toPrint.length > 0) {
      process.stdout.write(toPrint);
    }
  }

  if (outputBuffer.length > 0) {
    const remaining = outputBuffer.toString(codec as BufferEncoding);
    process.stdout.write(remaining + '\n');
  }
}

// --------------------------------------------------------------------------
// Remote stderr pipe reader
// --------------------------------------------------------------------------

async function runStderrPipe(
  transport: SMBTransport,
  pipeName: string,
  port: number,
  codec: string,
): Promise<void> {
  const { server, tid, fid } = await connectPipe(transport, pipeName, FILE_READ_DATA, port, codec);

  let outputBuffer = Buffer.alloc(0);

  while (true) {
    let data: Buffer;
    try {
      data = await server.readFile(tid, fid, 0, 1024);
    } catch {
      break;
    }

    if (data.length === 0) continue;

    outputBuffer = Buffer.concat([outputBuffer, data]);
    const bufStr = outputBuffer.toString(codec as BufferEncoding);

    if (bufStr.includes('\n')) {
      const lines = bufStr.split('\n');
      const toPrint = lines.slice(0, -1).join('\n') + '\n';
      outputBuffer = Buffer.from(lines[lines.length - 1]!, codec as BufferEncoding);
      process.stderr.write(toPrint);
    }
  }
}

// --------------------------------------------------------------------------
// Remote stdin pipe (interactive shell)
// --------------------------------------------------------------------------

async function runStdinPipe(
  transport: SMBTransport,
  pipeName: string,
  port: number,
  codec: string,
  share: string,
): Promise<void> {
  const { server, tid, fid } = await connectPipe(
    transport,
    pipeName,
    FILE_WRITE_DATA | FILE_APPEND_DATA,
    port,
    codec,
  );

  const { createInterface } = await import('node:readline');
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: false });

  console.log('[!] Press help for extra shell commands');

  rl.on('line', async (line: string) => {
    try {
      const trimmed = line.trim();
      if (trimmed === 'help') {
        console.log(`
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 lput {src_file, dst_path}   - uploads a local file to the dst_path RELATIVE to the connected share (${share})
 lget {file}                 - downloads pathname RELATIVE to the connected share (${share}) to the current local dir
 ! {cmd}                    - executes a local shell cmd
`);
        await server.writeFile(tid, fid, Buffer.from('\r\n', codec as BufferEncoding));
        return;
      }

      if (trimmed === 'exit') {
        await server.writeFile(tid, fid, Buffer.from('exit\r\n', codec as BufferEncoding));
        rl.close();
        process.exit(0);
        return;
      }

      if (trimmed.startsWith('lcd ')) {
        const dir = trimmed.slice(4).trim();
        if (dir === '') {
          console.log(process.cwd());
        } else {
          try { process.chdir(dir); } catch (e) { console.log(String(e)); }
        }
        await server.writeFile(tid, fid, Buffer.from('\r\n', codec as BufferEncoding));
        return;
      }

      await server.writeFile(tid, fid, Buffer.from(line + '\r\n', codec as BufferEncoding));
    } catch (e) {
      error(`Error writing to pipe: ${e}`);
    }
  });

  await new Promise<void>((resolve) => {
    rl.on('close', resolve);
  });
}

// --------------------------------------------------------------------------
// PSEXEC class
// --------------------------------------------------------------------------

interface PSEXECOptions {
  command: string;
  path?: string;
  exeFile?: string;
  copyFile?: string;
  port?: number;
  username?: string;
  password?: string;
  domain?: string;
  hashes?: string;
  aesKey?: string;
  doKerberos?: boolean;
  kdcHost?: string;
  serviceName?: string;
  remoteBinaryName?: string;
  codec?: string;
}

class PSEXEC {
  private username: string;
  private password: string;
  private port: number;
  private command: string;
  private workingPath?: string;
  private domain: string;
  private lmhash: string;
  private nthash: string;
  private aesKey?: string;
  private exeFile?: string;
  private copyFile?: string;
  private doKerberos: boolean;
  private kdcHost?: string;
  private serviceName?: string;
  private remoteBinaryName?: string;
  private codec: string;

  constructor(opts: PSEXECOptions) {
    this.username = opts.username ?? '';
    this.password = opts.password ?? '';
    this.port = opts.port ?? 445;
    this.command = opts.command;
    this.workingPath = opts.path;
    this.domain = opts.domain ?? '';
    this.lmhash = '';
    this.nthash = '';
    this.aesKey = opts.aesKey;
    this.exeFile = opts.exeFile;
    this.copyFile = opts.copyFile;
    this.doKerberos = opts.doKerberos ?? false;
    this.kdcHost = opts.kdcHost;
    this.serviceName = opts.serviceName;
    this.remoteBinaryName = opts.remoteBinaryName;
    this.codec = opts.codec ?? 'utf-8';
    if (opts.hashes) {
      const parts = opts.hashes.split(':');
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
    rpctransport.setCredentials(
      this.username, this.password, this.domain,
      this.lmhash, this.nthash, this.aesKey ?? null,
    );
    rpctransport.setKerberos(this.doKerberos, this.kdcHost ?? null);

    await this.doStuff(rpctransport);
  }

  private async doStuff(rpctransport: SMBTransport): Promise<void> {
    const dce = rpctransport.getDceRpc();
    try {
      await dce.connect();
    } catch (e) {
      critical(String(e));
      process.exit(1);
    }

    let unInstalled = false;
    let installService!: ServiceInstall;

    try {
      const s = rpctransport.getSmbConnection()!;
      s.setTimeout(100000);

      // Prepare the service binary
      let exeData: Buffer;
      if (this.exeFile) {
        try {
          exeData = readFileSync(this.exeFile);
        } catch (e) {
          critical(String(e));
          process.exit(1);
        }
      } else {
        exeData = Buffer.from(REMCOMSVC_EXE, 'base64');
      }

      installService = new ServiceInstall(
        s,
        exeData!,
        this.serviceName,
        this.remoteBinaryName,
      );

      const installed = await installService.install();
      if (!installed) return;

      // Check if we need to copy a file for execution
      if (this.copyFile) {
        await installService.copyFile(
          this.copyFile,
          installService.getShare(),
          path.basename(this.copyFile),
        );
        this.command = path.basename(this.copyFile) + ' ' + this.command;
      }

      // Use a dedicated SMB connection for the comm pipe to avoid
      // interference from stale DCE/RPC responses on the shared connection
      const remoteHost = rpctransport.getSmbConnection()!.getRemoteHost();
      const remoteName = rpctransport.getSmbConnection()!.getRemoteName();
      const dialect = rpctransport.getSmbConnection()!.getDialect();
      const [cUser, cPasswd, cDomain, cLm, cNt] = rpctransport.getCredentials();

      const commConn = new SMBConnection(remoteName, remoteHost, {
        sessPort: this.port,
        preferredDialect: dialect as number,
      });
      await commConn.negotiateSession();
      if (rpctransport.getKerberos()) {
        await commConn.kerberosLogin(
          cUser ?? '', cPasswd ?? '', cDomain, cLm, cNt,
          rpctransport.getCredentials()[5] as string,
          rpctransport.getKdcHost() ?? undefined,
          rpctransport.getCredentials()[6] as null,
          rpctransport.getCredentials()[7] as null,
        );
      } else {
        await commConn.login(cUser ?? '', cPasswd ?? '', cDomain, cLm, cNt);
      }
      commConn.setTimeout(100000);

      const tid = await commConn.connectTree('IPC$');
      const svcName = installService.serviceName;
      const fidMain = await openPipe(commConn, tid, `\\${svcName}`, 0x12019f);

      const machine = randomLetters(4);
      const pid = process.pid;

      const packet = buildRemComMessage({
        command: this.command,
        workingDir: this.workingPath,
        machine,
        processId: pid,
      });

      debug(`Writing RemCom message (${packet.length} bytes) to comm pipe`);
      await commConn.writeNamedPipe(tid, fidMain, packet);
      debug(`Message written, launching data pipe connections`);

      // Launch pipe readers/writers concurrently
      const stdinPipeName = `\\${svcName}_in${machine}${pid}`;
      const stdoutPipeName = `\\${svcName}_out${machine}${pid}`;
      const stderrPipeName = `\\${svcName}_err${machine}${pid}`;

      const stdinPromise = runStdinPipe(rpctransport, stdinPipeName, this.port, this.codec, installService.getShare()).catch(() => {});
      const stdoutPromise = runStdoutPipe(rpctransport, stdoutPipeName, this.port, this.codec).catch(() => {});
      const stderrPromise = runStderrPipe(rpctransport, stderrPipeName, this.port, this.codec).catch(() => {});

      // Read exit code from comm pipe (blocks until process finishes)
      let exitCode = 0;
      try {
        const ans = await commConn.readNamedPipe(tid, fidMain, 8);
        if (ans.length > 0) {
          const retCode = parseRemComResponse(ans);
          info(`Process ${this.command} finished with ErrorCode: ${retCode.errorCode}, ReturnCode: ${retCode.returnCode}`);
          exitCode = retCode.errorCode || retCode.returnCode;
        }
      } catch {
        // Comm pipe read failed — wait for stdout/stderr to finish instead
        await Promise.race([
          Promise.all([stdoutPromise, stderrPromise]),
          new Promise((r) => setTimeout(r, 10000)),
        ]);
      }

      await Promise.race([
        Promise.all([stdoutPromise, stderrPromise]),
        new Promise((r) => setTimeout(r, 10000)),
      ]);

      await installService.uninstall();
      if (this.copyFile) {
        await s.deleteFile(installService.getShare(), path.basename(this.copyFile));
      }
      unInstalled = true;

      process.exit(exitCode);
    } catch (e) {
      if (e instanceof Error && e.message.includes('process.exit')) throw e;
      debug(String(e));
      if (!unInstalled && installService) {
        try {
          await installService.uninstall();
        } catch { /* ignore */ }
        if (this.copyFile) {
          try {
            await rpctransport.getSmbConnection()!.deleteFile(
              installService.getShare(),
              path.basename(this.copyFile),
            );
          } catch { /* ignore */ }
        }
      }
      process.exit(1);
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
        c: { type: 'string', short: 'c' },
        path: { type: 'string' },
        file: { type: 'string' },
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        codec: { type: 'string' },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        keytab: { type: 'string' },
        'dc-ip': { type: 'string' },
        'target-ip': { type: 'string' },
        port: { type: 'string', default: '445' },
        'service-name': { type: 'string', default: '' },
        'remote-binary-name': { type: 'string' },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    process.exit(1);
  }

  if (values.help || positionals.length === 0) {
    console.log(`PSEXEC like functionality example using RemComSvc.

usage: psexec [-h] [-c pathname] [-path PATH] [-file FILE] [-ts] [-debug]
              [-codec CODEC] [-hashes LMHASH:NTHASH] [-no-pass] [-k]
              [-aesKey hex key] [-keytab KEYTAB]
              [-dc-ip ip address] [-target-ip ip address]
              [-port {139,445}] [-service-name service_name]
              [-remote-binary-name remote_binary_name]
              target [command ...]

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>
  command               command (or arguments if -c is used) to execute at the
                        target (w/o path) - (default:cmd.exe)

options:
  -h, --help            show this help message and exit
  -c pathname           copy the filename for later execution, arguments are
                        passed in the command option
  -path PATH            path of the command to execute
  -file FILE            alternative RemCom binary (be sure it doesn't require
                        CRT)
  -ts                   adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -codec CODEC          Sets encoding used (codec) from the target's output

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)
  -keytab KEYTAB        Read keys for SPN from keytab file

connection:
  -dc-ip ip address     IP Address of the domain controller. If omitted it
                        will use the domain part (FQDN) specified in the
                        target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will
                        use whatever was specified as target
  -port {139,445}       Destination port to connect to SMB Server
  -service-name service_name
                        The name of the service used to trigger the payload
  -remote-binary-name remote_binary_name
                        This will be the name of the executable uploaded on
                        the target
`);
    process.exit(positionals.length === 0 ? 1 : 0);
  }

  initLogger({ ts: values.ts, debug: values.debug });
  initProxy(values.proxy);

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
    // In a real implementation, we'd prompt for a password here
    critical('Password required. Use --hashes, --no-pass, or provide password in the target string.');
    process.exit(1);
  }

  const commandParts = positionals.slice(1);
  const command = commandParts.length > 0 ? commandParts.join(' ') : 'cmd.exe /q';

  let aesKey = values.aesKey ?? '';
  if (values.keytab) {
    const keys = loadKeytabKeys(values.keytab);
    if (keys.aesKey) aesKey = keys.aesKey;
    if (keys.nthash && !values.hashes) values.hashes = `:${keys.nthash}`;
  }
  const doKerberos = values.k || !!aesKey;

  const executer = new PSEXEC({
    command,
    path: values.path,
    exeFile: values.file,
    copyFile: values.c,
    port: parseInt(values.port ?? '445', 10),
    username,
    password,
    domain: domain || '',
    hashes: values.hashes,
    aesKey: aesKey || undefined,
    doKerberos,
    kdcHost: values['dc-ip'],
    serviceName: values['service-name'],
    remoteBinaryName: values['remote-binary-name'],
    codec,
  });

  await executer.run(remoteName, targetIp);
}

main().catch((e) => {
  critical(String(e));
  process.exit(1);
});
