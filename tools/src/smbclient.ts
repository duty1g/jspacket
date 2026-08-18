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
//   A generic SMB client that will let you list shares and files,
//   rename, upload, download, and delete files, and create and
//   delete directories — all using either username/password or
//   hashes for authentication. It's an interactive, mini FTP-like
//   client for SMB shares.
//
// Author:
//   beto (@agsolino)
//   Ported to TypeScript
//
// Reference for:
//   SMB Connection

import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import {
  createWriteStream,
  existsSync,
  readFileSync,
} from 'node:fs';
import path from 'node:path';
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
  BANNER,
} from '@impacket/examples';
import { SMBConnection } from '@impacket/smb-connection';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ATTR_DIRECTORY = 0x0010;

const COMMAND_HELP: Record<string, string> = {
  help:    'display this help message',
  shares:  'list available shares',
  use:     'connect to a specific share (e.g. use C$)',
  cd:      'change remote current directory (e.g. cd Windows)',
  lcd:     'change local current directory (e.g. lcd /tmp)',
  pwd:     'print current remote directory',
  ls:      'list remote directory contents (e.g. ls *.txt)',
  cat:     'display remote file contents',
  get:     'download a remote file (e.g. get file.txt)',
  mget:    'download files matching a mask (e.g. mget *.exe)',
  put:     'upload a local file (e.g. put local.txt remote.txt)',
  mkdir:   'create a remote directory',
  rmdir:   'remove a remote directory',
  rm:      'delete a remote file (e.g. rm file.txt)',
  rename:  'rename a remote file (e.g. rename old.txt new.txt)',
  info:    'display information about a remote file',
  close:   'close the current share connection',
  exit:    'terminate the client',
  quit:    'terminate the client',
  '!':     'execute a local shell command (e.g. ! ls -la)',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function humanSize(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 * 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  return `${(size / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatDate(d: Date): string {
  const pad = (n: number): string => String(n).padStart(2, '0');
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}`
  );
}

function ntPath(...parts: string[]): string {
  return parts
    .join('\\')
    .replace(/\//g, '\\')
    .replace(/\\{2,}/g, '\\')
    .replace(/^\\/, '');
}

function fileAttrString(attr: number): string {
  let s = '';
  s += attr & 0x0001 ? 'r' : '-'; // readonly
  s += attr & 0x0002 ? 'h' : '-'; // hidden
  s += attr & 0x0004 ? 's' : '-'; // system
  s += attr & ATTR_DIRECTORY ? 'd' : '-'; // directory
  s += attr & 0x0020 ? 'a' : '-'; // archive
  return s;
}

// ---------------------------------------------------------------------------
// MiniImpacketShell
// ---------------------------------------------------------------------------

interface SharedFileEntry {
  name: string;
  shortname: string;
  filesize: number;
  attrib: number;
  mtime: Date;
  ctime: Date;
  atime: Date;
}

class MiniImpacketShell {
  private smbClient: SMBConnection;
  private pwd = '\\';
  private share: string | null = null;
  private loggedIn = true;
  private completionCache: Record<string, string[]> = {};
  private tidMap: Map<string, number> = new Map();
  private prompt = '# ';

  constructor(smbClient: SMBConnection) {
    this.smbClient = smbClient;
  }

  // -----------------------------------------------------------------------
  // Prompt
  // -----------------------------------------------------------------------

  private updatePrompt(): void {
    if (this.share) {
      this.prompt = `# ${this.share}${this.pwd}> `;
    } else {
      this.prompt = '# ';
    }
  }

  // -----------------------------------------------------------------------
  // Internal share / tree helpers
  // -----------------------------------------------------------------------

  private async ensureShare(verb: string): Promise<boolean> {
    if (!this.share) {
      error(`No share selected. Use "use <share>" before "${verb}".`);
      return false;
    }
    return true;
  }

  private async getTid(share: string): Promise<number> {
    const cached = this.tidMap.get(share);
    if (cached !== undefined) return cached;
    const tid = await this.smbClient.connectTree(share);
    this.tidMap.set(share, tid);
    return tid;
  }

  // -----------------------------------------------------------------------
  // Commands
  // -----------------------------------------------------------------------

  async do_help(): Promise<void> {
    console.log('\nAvailable commands:');
    const maxLen = Math.max(...Object.keys(COMMAND_HELP).map((k) => k.length));
    for (const [cmd, desc] of Object.entries(COMMAND_HELP)) {
      console.log(`  ${cmd.padEnd(maxLen + 2)}${desc}`);
    }
    console.log();
  }

  async do_shares(): Promise<void> {
    try {
      const shares = await this.smbClient.listShares();
      console.log();
      console.log('  Share           Type    Comment');
      console.log('  -----           ----    -------');
      for (const s of shares) {
        const entry = s as any;
        const nameRaw = (typeof entry.get === 'function' ? entry.get('shi1_netname') : entry.fields?.['shi1_netname']) as string | undefined;
        const typeRaw = (typeof entry.get === 'function' ? entry.get('shi1_type') : entry.fields?.['shi1_type']) as number | undefined;
        const remarkRaw = (typeof entry.get === 'function' ? entry.get('shi1_remark') : entry.fields?.['shi1_remark']) as string | undefined;

        const name = (nameRaw ?? '').replace(/\x00/g, '');
        const remark = (remarkRaw ?? '').replace(/\x00/g, '');
        const typeNum = typeRaw ?? 0;

        let typeStr: string;
        switch (typeNum & 0x0fffffff) {
          case 0:
            typeStr = 'DISK';
            break;
          case 1:
            typeStr = 'PRINT';
            break;
          case 2:
            typeStr = 'DEV';
            break;
          case 3:
            typeStr = 'IPC';
            break;
          default:
            typeStr = `0x${typeNum.toString(16)}`;
        }

        console.log(`  ${name.padEnd(16)}${typeStr.padEnd(8)}${remark}`);
      }
      console.log();
    } catch (e) {
      error(`Failed to list shares: ${e}`);
    }
  }

  async do_use(share: string): Promise<void> {
    if (!share) {
      error('Usage: use <share>');
      return;
    }
    try {
      const tid = await this.smbClient.connectTree(share);
      this.tidMap.set(share, tid);
      this.share = share;
      this.pwd = '\\';
      this.completionCache = {};
      this.updatePrompt();
      info(`Connected to ${share}`);
    } catch (e) {
      error(`Failed to connect to share "${share}": ${e}`);
    }
  }

  async do_cd(pathArg: string): Promise<void> {
    if (!(await this.ensureShare('cd'))) return;
    if (!pathArg) {
      this.pwd = '\\';
      this.updatePrompt();
      return;
    }

    let newPath: string;
    if (pathArg === '..') {
      const parts = this.pwd.split('\\').filter(Boolean);
      parts.pop();
      newPath = parts.length > 0 ? '\\' + parts.join('\\') : '\\';
    } else if (pathArg.startsWith('\\') || pathArg.startsWith('/')) {
      newPath = pathArg.replace(/\//g, '\\');
    } else {
      newPath = ntPath(this.pwd, pathArg);
      if (!newPath.startsWith('\\')) newPath = '\\' + newPath;
    }

    // Verify the directory exists by listing it
    try {
      const searchPath = ntPath(newPath, '*');
      await this.smbClient.listPath(this.share!, searchPath);
      this.pwd = newPath;
      this.updatePrompt();
    } catch {
      error(`Directory "${pathArg}" not found or not accessible.`);
    }
  }

  async do_lcd(pathArg: string): Promise<void> {
    if (!pathArg) {
      console.log(process.cwd());
      return;
    }
    try {
      process.chdir(pathArg);
      info(`Local directory changed to ${process.cwd()}`);
    } catch (e) {
      error(`Failed to change local directory: ${e}`);
    }
  }

  async do_pwd(): Promise<void> {
    if (this.share) {
      console.log(`Current remote directory: ${this.share}${this.pwd}`);
    } else {
      console.log('No share selected.');
    }
  }

  async do_ls(wildcard?: string): Promise<void> {
    if (!(await this.ensureShare('ls'))) return;
    const mask = wildcard || '*';
    const searchPath = ntPath(this.pwd, mask);
    try {
      const files = await this.smbClient.listPath(this.share!, searchPath);
      const entries = files as SharedFileEntry[];

      let totalSize = 0;
      let fileCount = 0;
      let dirCount = 0;

      console.log();
      for (const f of entries) {
        const isDir = (f.attrib & ATTR_DIRECTORY) !== 0;
        const sizeStr = isDir ? '<DIR>'.padStart(12) : String(f.filesize).padStart(12);
        const date = formatDate(f.mtime);
        const attrs = fileAttrString(f.attrib);

        console.log(`  ${date}  ${attrs}  ${sizeStr}  ${f.name}`);

        if (isDir) {
          dirCount++;
        } else {
          fileCount++;
          totalSize += f.filesize;
        }
      }
      console.log();
      console.log(`  ${fileCount} file(s)  ${humanSize(totalSize)}`);
      console.log(`  ${dirCount} dir(s)`);
      console.log();
    } catch (e) {
      error(`Failed to list path: ${e}`);
    }
  }

  async do_cat(filename: string): Promise<void> {
    if (!(await this.ensureShare('cat'))) return;
    if (!filename) {
      error('Usage: cat <filename>');
      return;
    }

    const remotePath = ntPath(this.pwd, filename);
    try {
      const tid = await this.getTid(this.share!);
      const fid = await this.smbClient.openFile(
        tid,
        remotePath,
        0x00000001, // FILE_READ_DATA
        0x00000001, // FILE_SHARE_READ
      );

      let offset = 0;
      const chunkSize = 4096;
      let keepReading = true;

      while (keepReading) {
        const data = await this.smbClient.readFile(tid, fid, offset, chunkSize, true);
        if (data.length === 0) {
          keepReading = false;
        } else {
          process.stdout.write(data);
          offset += data.length;
          if (data.length < chunkSize) keepReading = false;
        }
      }

      // Ensure newline at end of output
      process.stdout.write('\n');
      await this.smbClient.closeFile(tid, fid);
    } catch (e) {
      error(`Failed to read file "${filename}": ${e}`);
    }
  }

  async do_get(filename: string): Promise<void> {
    if (!(await this.ensureShare('get'))) return;
    if (!filename) {
      error('Usage: get <filename>');
      return;
    }

    const remotePath = ntPath(this.pwd, filename);
    const localName = path.basename(filename.replace(/\\/g, '/'));

    try {
      const tid = await this.getTid(this.share!);
      const fid = await this.smbClient.openFile(
        tid,
        remotePath,
        0x00000001, // FILE_READ_DATA
        0x00000001, // FILE_SHARE_READ
      );

      const ws = createWriteStream(localName);
      let offset = 0;
      const chunkSize = 65536;
      let totalBytes = 0;
      let keepReading = true;

      while (keepReading) {
        const data = await this.smbClient.readFile(tid, fid, offset, chunkSize, true);
        if (data.length === 0) {
          keepReading = false;
        } else {
          ws.write(data);
          offset += data.length;
          totalBytes += data.length;
          if (data.length < chunkSize) keepReading = false;
        }
      }

      await new Promise<void>((resolve, reject) => {
        ws.end(() => resolve());
        ws.on('error', reject);
      });

      await this.smbClient.closeFile(tid, fid);
      info(`Downloaded "${filename}" -> "${localName}" (${humanSize(totalBytes)})`);
    } catch (e) {
      error(`Failed to download "${filename}": ${e}`);
    }
  }

  async do_mget(mask: string): Promise<void> {
    if (!(await this.ensureShare('mget'))) return;
    if (!mask) {
      error('Usage: mget <mask> (e.g. mget *.txt)');
      return;
    }

    const searchPath = ntPath(this.pwd, mask);
    try {
      const files = await this.smbClient.listPath(this.share!, searchPath);
      const entries = files as SharedFileEntry[];
      let count = 0;

      for (const f of entries) {
        // Skip directories and pseudo-entries
        if (f.attrib & ATTR_DIRECTORY) continue;
        if (f.name === '.' || f.name === '..') continue;

        info(`Downloading ${f.name}...`);
        try {
          await this.do_get(f.name);
          count++;
        } catch (e) {
          error(`Failed to download ${f.name}: ${e}`);
        }
      }
      info(`Downloaded ${count} file(s).`);
    } catch (e) {
      error(`Failed to list files for mget: ${e}`);
    }
  }

  async do_put(localPath: string, remotePath?: string): Promise<void> {
    if (!(await this.ensureShare('put'))) return;
    if (!localPath) {
      error('Usage: put <local_file> [remote_file]');
      return;
    }

    if (!existsSync(localPath)) {
      error(`Local file "${localPath}" does not exist.`);
      return;
    }

    const remoteFile = remotePath || path.basename(localPath);
    const fullRemotePath = ntPath(this.pwd, remoteFile);

    try {
      const tid = await this.getTid(this.share!);
      const fid = await this.smbClient.createFile(tid, fullRemotePath);

      const fileData = readFileSync(localPath);
      const chunkSize = 65536;
      let offset = 0;

      while (offset < fileData.length) {
        const chunk = fileData.subarray(offset, offset + chunkSize);
        await this.smbClient.writeFile(tid, fid, chunk, offset);
        offset += chunk.length;
      }

      await this.smbClient.closeFile(tid, fid);
      info(`Uploaded "${localPath}" -> "${remoteFile}" (${humanSize(fileData.length)})`);
    } catch (e) {
      error(`Failed to upload "${localPath}": ${e}`);
    }
  }

  async do_mkdir(dirname: string): Promise<void> {
    if (!(await this.ensureShare('mkdir'))) return;
    if (!dirname) {
      error('Usage: mkdir <directory>');
      return;
    }

    const dirPath = ntPath(this.pwd, dirname);
    try {
      await this.smbClient.createDirectory(this.share!, dirPath);
      info(`Directory "${dirname}" created.`);
    } catch (e) {
      error(`Failed to create directory "${dirname}": ${e}`);
    }
  }

  async do_rmdir(dirname: string): Promise<void> {
    if (!(await this.ensureShare('rmdir'))) return;
    if (!dirname) {
      error('Usage: rmdir <directory>');
      return;
    }

    const dirPath = ntPath(this.pwd, dirname);
    try {
      await this.smbClient.deleteDirectory(this.share!, dirPath);
      info(`Directory "${dirname}" removed.`);
    } catch (e) {
      error(`Failed to remove directory "${dirname}": ${e}`);
    }
  }

  async do_rm(filename: string): Promise<void> {
    if (!(await this.ensureShare('rm'))) return;
    if (!filename) {
      error('Usage: rm <filename>');
      return;
    }

    const filePath = ntPath(this.pwd, filename);
    try {
      await this.smbClient.deleteFile(this.share!, filePath);
      info(`File "${filename}" deleted.`);
    } catch (e) {
      error(`Failed to delete "${filename}": ${e}`);
    }
  }

  async do_rename(oldName: string, newName: string): Promise<void> {
    if (!(await this.ensureShare('rename'))) return;
    if (!oldName || !newName) {
      error('Usage: rename <old_name> <new_name>');
      return;
    }

    const oldPath = ntPath(this.pwd, oldName);
    const newPath = ntPath(this.pwd, newName);
    try {
      await this.smbClient.rename(this.share!, oldPath, newPath);
      info(`Renamed "${oldName}" -> "${newName}".`);
    } catch (e) {
      error(`Failed to rename: ${e}`);
    }
  }

  async do_info(filename: string): Promise<void> {
    if (!(await this.ensureShare('info'))) return;
    if (!filename) {
      error('Usage: info <filename>');
      return;
    }

    // List the parent directory with the filename as the search pattern
    // to get the file's attributes
    const searchPath = ntPath(this.pwd, filename);
    try {
      const files = await this.smbClient.listPath(this.share!, searchPath);
      const entries = files as SharedFileEntry[];
      if (entries.length === 0) {
        error(`File "${filename}" not found.`);
        return;
      }

      // Find the actual file (not . or ..)
      let target = entries[0]!;
      for (const f of entries) {
        if (f.name !== '.' && f.name !== '..') {
          target = f;
          break;
        }
      }

      const isDir = (target.attrib & ATTR_DIRECTORY) !== 0;

      console.log();
      console.log(`  File:          ${target.name}`);
      console.log(`  Type:          ${isDir ? 'Directory' : 'File'}`);
      console.log(`  Attributes:    ${fileAttrString(target.attrib)} (0x${target.attrib.toString(16).padStart(4, '0')})`);
      if (!isDir) {
        console.log(`  Size:          ${target.filesize} bytes (${humanSize(target.filesize)})`);
      }
      console.log(`  Created:       ${formatDate(target.ctime)}`);
      console.log(`  Last modified: ${formatDate(target.mtime)}`);
      console.log(`  Last accessed: ${formatDate(target.atime)}`);
      console.log();
    } catch (e) {
      error(`Failed to get info for "${filename}": ${e}`);
    }
  }

  async do_close(): Promise<void> {
    if (!this.share) {
      error('No share is currently connected.');
      return;
    }

    try {
      const tid = this.tidMap.get(this.share);
      if (tid !== undefined) {
        await this.smbClient.disconnectTree(tid);
        this.tidMap.delete(this.share);
      }
    } catch {
      // Ignore errors during disconnect
    }

    info(`Disconnected from ${this.share}`);
    this.share = null;
    this.pwd = '\\';
    this.completionCache = {};
    this.updatePrompt();
  }

  async do_exit(): Promise<void> {
    // Disconnect all trees
    for (const [share, tid] of this.tidMap) {
      try {
        await this.smbClient.disconnectTree(tid);
      } catch {
        // Ignore errors during cleanup
      }
    }
    this.tidMap.clear();

    try {
      await this.smbClient.close();
    } catch {
      // Ignore
    }
  }

  // -----------------------------------------------------------------------
  // Tab completion
  // -----------------------------------------------------------------------

  private async completeRemotePath(partial: string): Promise<string[]> {
    if (!this.share) return [];

    // Determine the directory to search and the prefix to match
    let dirPart: string;
    let filePart: string;
    const lastSep = Math.max(partial.lastIndexOf('\\'), partial.lastIndexOf('/'));
    if (lastSep >= 0) {
      dirPart = partial.slice(0, lastSep);
      filePart = partial.slice(lastSep + 1);
    } else {
      dirPart = '';
      filePart = partial;
    }

    const searchDir = dirPart ? ntPath(this.pwd, dirPart) : this.pwd;
    const cacheKey = `${this.share}:${searchDir}`;

    let names = this.completionCache[cacheKey];
    if (!names) {
      try {
        const files = await this.smbClient.listPath(
          this.share,
          ntPath(searchDir, '*'),
        );
        names = (files as SharedFileEntry[])
          .filter((f) => f.name !== '.' && f.name !== '..')
          .map((f) => f.name);
        this.completionCache[cacheKey] = names;
      } catch {
        return [];
      }
    }

    const lowerPart = filePart.toLowerCase();
    return names
      .filter((n) => n.toLowerCase().startsWith(lowerPart))
      .map((n) => (dirPart ? `${dirPart}\\${n}` : n));
  }

  // -----------------------------------------------------------------------
  // Command dispatch
  // -----------------------------------------------------------------------

  private async dispatch(line: string): Promise<boolean> {
    const trimmed = line.trim();
    if (!trimmed) return true;

    // Local shell command
    if (trimmed.startsWith('!')) {
      const shellCmd = trimmed.slice(1).trim();
      if (!shellCmd) return true;
      const { execSync } = await import('node:child_process');
      try {
        const result = execSync(shellCmd, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
        process.stdout.write(result);
      } catch (e: unknown) {
        const err = e as { stderr?: string; message?: string };
        error(err.stderr || err.message || String(e));
      }
      return true;
    }

    // Parse command and arguments
    const parts = trimmed.split(/\s+/);
    const cmd = parts[0]!.toLowerCase();
    const args = parts.slice(1);

    switch (cmd) {
      case 'help':
      case '?':
        await this.do_help();
        break;

      case 'shares':
        await this.do_shares();
        break;

      case 'use':
        await this.do_use(args.join(' '));
        break;

      case 'cd':
        await this.do_cd(args.join(' '));
        break;

      case 'lcd':
        await this.do_lcd(args.join(' '));
        break;

      case 'pwd':
        await this.do_pwd();
        break;

      case 'ls':
      case 'dir':
        await this.do_ls(args.join(' ') || undefined);
        break;

      case 'cat':
      case 'type':
        await this.do_cat(args.join(' '));
        break;

      case 'get':
        await this.do_get(args.join(' '));
        break;

      case 'mget':
        await this.do_mget(args.join(' '));
        break;

      case 'put':
        await this.do_put(args[0] ?? '', args[1]);
        break;

      case 'mkdir':
        await this.do_mkdir(args.join(' '));
        break;

      case 'rmdir':
        await this.do_rmdir(args.join(' '));
        break;

      case 'rm':
      case 'del':
        await this.do_rm(args.join(' '));
        break;

      case 'rename':
      case 'ren':
      case 'mv':
        await this.do_rename(args[0] ?? '', args[1] ?? '');
        break;

      case 'info':
        await this.do_info(args.join(' '));
        break;

      case 'close':
        await this.do_close();
        break;

      case 'exit':
      case 'quit':
      case 'q':
        await this.do_exit();
        return false;

      default:
        error(`Unknown command: "${cmd}". Type "help" for available commands.`);
        break;
    }

    return true;
  }

  // -----------------------------------------------------------------------
  // Shell loop
  // -----------------------------------------------------------------------

  async cmdloop(inputCommands?: string[]): Promise<void> {
    console.log('Type help for list of commands');
    this.updatePrompt();

    // If we have pre-loaded commands (from -file), execute them in order
    if (inputCommands && inputCommands.length > 0) {
      for (const line of inputCommands) {
        console.log(`${this.prompt}${line}`);
        const shouldContinue = await this.dispatch(line);
        if (!shouldContinue) return;
      }
      return;
    }

    // Interactive mode
    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
      prompt: this.prompt,
      completer: (line: string, callback: (err: Error | null, result: [string[], string]) => void) => {
        // Tab completion: complete the last argument as a remote path
        const parts = line.split(/\s+/);
        if (parts.length <= 1) {
          // Complete command name
          const cmds = Object.keys(COMMAND_HELP);
          const partial = (parts[0] ?? '').toLowerCase();
          const hits = cmds.filter((c) => c.startsWith(partial));
          callback(null, [hits.length > 0 ? hits : cmds, partial]);
          return;
        }

        // Complete remote filename for file-related commands
        const fileCommands = ['cd', 'cat', 'type', 'get', 'put', 'rm', 'del', 'info', 'mkdir', 'rmdir', 'rename', 'ren', 'mv', 'mget', 'ls', 'dir'];
        const cmdName = parts[0]!.toLowerCase();
        if (fileCommands.includes(cmdName)) {
          const partial = parts[parts.length - 1] ?? '';
          this.completeRemotePath(partial)
            .then((completions) => {
              callback(null, [completions, partial]);
            })
            .catch(() => {
              callback(null, [[], partial]);
            });
          return;
        }

        // Complete share name for "use"
        if (cmdName === 'use') {
          callback(null, [[], parts[parts.length - 1] ?? '']);
          return;
        }

        callback(null, [[], '']);
      },
    });

    rl.prompt();

    let isClosed = false;
    rl.on('close', () => {
      isClosed = true;
    });

    for await (const line of rl) {
      try {
        const shouldContinue = await this.dispatch(line);
        if (!shouldContinue) {
          rl.close();
          break;
        }
      } catch (e) {
        error(`Error: ${e}`);
      }

      if (isClosed) break;
      this.updatePrompt();
      rl.setPrompt(this.prompt);
      rl.prompt();
    }
  }
}

// ---------------------------------------------------------------------------
// CLI argument parsing and main
// ---------------------------------------------------------------------------

function printBanner(): void {
  console.log(BANNER + '\n');
}

function printUsage(): void {
  console.log(`SMB client implementation.

usage: smbclient [-h] [-inputfile INPUTFILE] [-outputfile OUTPUTFILE]
                 [-debug] [-ts] [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                 [-aesKey hex key] [-dc-ip ip address]
                 [-target-ip ip address]
                 [-port {139,445}]
                 target

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -inputfile INPUTFILE  input file with commands to execute in the mini shell
  -outputfile OUTPUTFILE
                        Output file to log smbclient actions in
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)

connection:
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address
                        IP Address of the target machine. If omitted it will
                        use whatever was specified as target
  -port {139,445}       Destination port to connect to SMB Server
`);
}

async function main(): Promise<void> {
  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: normalizeArgs(process.argv.slice(2)),
      allowPositionals: true,
      options: {
        inputfile: { type: 'string' },
        outputfile: { type: 'string' },
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
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    printUsage();
    process.exit(1);
  }

  printBanner();

  if (values.help || positionals.length === 0) {
    printUsage();
    process.exit(positionals.length === 0 ? 1 : 0);
  }

  initProxy(values.proxy);
  initLogger({ ts: values.ts, debug: values.debug });

  // Tee stdout to output file when -outputfile is specified
  if (values.outputfile) {
    const logStream = createWriteStream(values.outputfile, { flags: 'a' });
    const origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = function (
      chunk: string | Uint8Array,
      encodingOrCb?: BufferEncoding | ((err?: Error | null) => void),
      cb?: (err?: Error | null) => void,
    ): boolean {
      logStream.write(chunk);
      return origWrite(chunk, encodingOrCb as BufferEncoding, cb);
    } as typeof process.stdout.write;
  }

  const target = positionals[0]!;
  const [domain, username, password, remoteName] = parseTarget(target);

  const targetIp = values['target-ip'] ?? remoteName;
  const port = parseInt(values.port ?? '445', 10);
  const doKerberos = values.k || !!values.aesKey;

  let lmhash = '';
  let nthash = '';
  if (values.hashes) {
    const parts = values.hashes.split(':');
    lmhash = parts[0] ?? '';
    nthash = parts[1] ?? '';
  }

  // Prompt for password if needed
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

  // Read command file if provided
  let inputCommands: string[] | undefined;
  if (values.inputfile) {
    try {
      const content = readFileSync(values.inputfile, 'utf-8');
      inputCommands = content
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l.length > 0 && !l.startsWith('#'));
    } catch (e) {
      critical(`Failed to read command file "${values.inputfile}": ${e}`);
      process.exit(1);
    }
  }

  // Connect to the target
  info(`Connecting to ${targetIp}:${port}...`);
  const smbClient = new SMBConnection(remoteName, targetIp, {
    sessPort: port,
  });

  try {
    await smbClient.negotiateSession();
  } catch (e) {
    critical(`Failed to negotiate session: ${e}`);
    process.exit(1);
  }

  // Authenticate
  try {
    if (doKerberos) {
      await smbClient.kerberosLogin(
        username,
        resolvedPassword,
        domain || '',
        lmhash,
        nthash,
        values.aesKey ?? '',
        values['dc-ip'] ?? null,
      );
    } else {
      await smbClient.login(
        username,
        resolvedPassword,
        domain || '',
        lmhash,
        nthash,
      );
    }
  } catch (e) {
    critical(`Authentication failed: ${e}`);
    process.exit(1);
  }

  const serverName = smbClient.getServerName();
  const serverDomain = smbClient.getServerDomain();
  const serverOS = smbClient.getServerOS();

  debug(`Server name: ${serverName}`);
  debug(`Server domain: ${serverDomain}`);
  debug(`Server OS: ${serverOS}`);
  info(`Authenticated as ${domain ? domain + '\\' : ''}${username}`);

  // Run the interactive shell
  const shell = new MiniImpacketShell(smbClient);

  try {
    await shell.cmdloop(inputCommands);
  } catch (e) {
    if (String(e).includes('EPIPE') || String(e).includes('ECONNRESET')) {
      warning('Connection lost.');
    } else {
      error(`Shell error: ${e}`);
    }
  }

  process.exit(0);
}

main().catch((e) => {
  critical(String(e));
  process.exit(1);
});
