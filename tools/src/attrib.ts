#!/usr/bin/env node
/**
 * jspacket - attrib
 *
 * TypeScript port of impacket's examples/attrib.py.
 *
 * Query and modify remote file / directory attributes via SMB.
 *
 * Original impacket author: Raz Kissos (@covertivy)
 * TypeScript port for jspacket.
 */

import { parseArgs } from 'node:util';
import * as path from 'node:path';
import { createInterface } from 'node:readline';
import {
  parseTarget,
  init as initLogger,
  debug,
  normalizeArgs,
  initProxy,
  BANNER,
} from '@impacket/examples';
import { SMBConnection } from '@impacket/smb-connection';
import { SMB2_FILE_BASIC_INFO, FILE_BASIC_INFORMATION } from '@impacket/smb3';
import {
  SMB_DIALECT,
  FILE_READ_ATTRIBUTES,
  FILE_WRITE_ATTRIBUTES,
  FILE_SHARE_READ,
  FILE_SHARE_WRITE,
  FILE_SHARE_DELETE,
  SMB_QUERY_FILE_BASIC_INFO,
  SMB_SET_FILE_BASIC_INFO,
  SMBQueryFileBasicInfo,
  SMBSetFileBasicInfo,
} from '@impacket/smb';


// [MS-FSCC] 2.6 File Attributes
const FILE_ATTRIBUTE_READONLY              = 0x00000001;
const FILE_ATTRIBUTE_HIDDEN                = 0x00000002;
const FILE_ATTRIBUTE_SYSTEM                = 0x00000004;
const FILE_ATTRIBUTE_VOLUME                = 0x00000008;
const FILE_ATTRIBUTE_DIRECTORY             = 0x00000010;
const FILE_ATTRIBUTE_ARCHIVE               = 0x00000020;
const FILE_ATTRIBUTE_NORMAL                = 0x00000080;
const FILE_ATTRIBUTE_TEMPORARY             = 0x00000100;
const FILE_ATTRIBUTE_COMPRESSED            = 0x00000800;
const FILE_ATTRIBUTE_OFFLINE               = 0x00001000;
const FILE_ATTRIBUTE_ENCRYPTED             = 0x00004000;
const FILE_ATTRIBUTE_PINNED                = 0x00080000;
const FILE_ATTRIBUTE_UNPINNED              = 0x00100000;

interface FileAttribs {
  readonly: boolean;
  hidden: boolean;
  system: boolean;
  volume: boolean;
  directory: boolean;
  archive: boolean;
  normal: boolean;
  temporary: boolean;
  compressed: boolean;
  offline: boolean;
  encrypted: boolean;
  pinned: boolean;
  unpinned: boolean;
}

function unpackAttribs(data: number): FileAttribs {
  return {
    readonly:   !!(data & FILE_ATTRIBUTE_READONLY),
    hidden:     !!(data & FILE_ATTRIBUTE_HIDDEN),
    system:     !!(data & FILE_ATTRIBUTE_SYSTEM),
    volume:     !!(data & FILE_ATTRIBUTE_VOLUME),
    directory:  !!(data & FILE_ATTRIBUTE_DIRECTORY),
    archive:    !!(data & FILE_ATTRIBUTE_ARCHIVE),
    normal:     !!(data & FILE_ATTRIBUTE_NORMAL),
    temporary:  !!(data & FILE_ATTRIBUTE_TEMPORARY),
    compressed: !!(data & FILE_ATTRIBUTE_COMPRESSED),
    offline:    !!(data & FILE_ATTRIBUTE_OFFLINE),
    encrypted:  !!(data & FILE_ATTRIBUTE_ENCRYPTED),
    pinned:     !!(data & FILE_ATTRIBUTE_PINNED),
    unpinned:   !!(data & FILE_ATTRIBUTE_UNPINNED),
  };
}

function packAttribs(a: FileAttribs): number {
  return (
    (a.readonly   ? FILE_ATTRIBUTE_READONLY   : 0) |
    (a.hidden     ? FILE_ATTRIBUTE_HIDDEN     : 0) |
    (a.system     ? FILE_ATTRIBUTE_SYSTEM     : 0) |
    (a.volume     ? FILE_ATTRIBUTE_VOLUME     : 0) |
    (a.directory  ? FILE_ATTRIBUTE_DIRECTORY  : 0) |
    (a.archive    ? FILE_ATTRIBUTE_ARCHIVE    : 0) |
    (a.normal     ? FILE_ATTRIBUTE_NORMAL     : 0) |
    (a.temporary  ? FILE_ATTRIBUTE_TEMPORARY  : 0) |
    (a.compressed ? FILE_ATTRIBUTE_COMPRESSED : 0) |
    (a.offline    ? FILE_ATTRIBUTE_OFFLINE    : 0) |
    (a.encrypted  ? FILE_ATTRIBUTE_ENCRYPTED  : 0) |
    (a.pinned     ? FILE_ATTRIBUTE_PINNED     : 0) |
    (a.unpinned   ? FILE_ATTRIBUTE_UNPINNED   : 0)
  );
}

function reprAttribs(a: FileAttribs): string {
  return (
    (a.readonly   ? 'R' : '-') +
    (a.hidden     ? 'H' : '-') +
    (a.system     ? 'S' : '-') +
    (a.volume     ? 'V' : '-') +
    (a.directory  ? 'D' : '-') +
    (a.archive    ? 'A' : '-') +
    (a.normal     ? 'N' : '-') +
    (a.temporary  ? 'T' : '-') +
    (a.compressed ? 'C' : '-') +
    (a.offline    ? 'O' : '-') +
    (a.encrypted  ? 'E' : '-') +
    (a.pinned     ? 'P' : '-') +
    (a.unpinned   ? 'U' : '-')
  );
}

async function attribQuery(conn: SMBConnection, tid: number, fid: number | Buffer): Promise<FileAttribs> {
  if (conn.getDialect() === SMB_DIALECT) {
    const raw = await conn.queryInfo(tid, fid, SMB_QUERY_FILE_BASIC_INFO) as Buffer;
    const info = new SMBQueryFileBasicInfo(raw);
    return unpackAttribs(info.get('ExtFileAttributes') as number);
  }
  const raw = await conn.queryInfo(tid, fid, SMB2_FILE_BASIC_INFO) as Buffer;
  const info = new FILE_BASIC_INFORMATION(raw);
  return unpackAttribs(info.get('FileAttributes') as number);
}

async function attribSet(conn: SMBConnection, tid: number, fid: number | Buffer, attribs: FileAttribs): Promise<void> {
  const packed = packAttribs(attribs);
  debug(`Setting file / directory attributes = ${packed}`);

  if (conn.getDialect() === SMB_DIALECT) {
    const info = new SMBSetFileBasicInfo();
    info.set('CreationTime', 0);
    info.set('LastAccessTime', 0);
    info.set('LastWriteTime', 0);
    info.set('ChangeTime', 0);
    info.set('ExtFileAttributes', packed);
    await conn.setInfo(tid, fid, SMB_SET_FILE_BASIC_INFO, info.getData());
  } else {
    const info = new FILE_BASIC_INFORMATION();
    info.set('CreationTime', BigInt(0));
    info.set('LastAccessTime', BigInt(0));
    info.set('LastWriteTime', BigInt(0));
    info.set('ChangeTime', BigInt(0));
    info.set('FileAttributes', packed);
    await conn.setInfo(tid, fid, SMB2_FILE_BASIC_INFO, info.getData());
  }
}

async function main(): Promise<void> {
  console.log(BANNER);

  const argv = normalizeArgs(process.argv.slice(2));
  let opt: any;
  let positionals: string[];
  try {
    ({ values: opt, positionals } = parseArgs({
      args: argv,
      options: {
        debug: { type: 'boolean', short: 'd', default: false },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        port: { type: 'string', short: 'p', default: '445' },
        'dc-ip': { type: 'string' },
        'target-ip': { type: 'string' },
        timeout: { type: 'string', short: 't', default: '60' },
        // set subcommand flags
        readonly: { type: 'boolean', short: 'r', default: false },
        hidden: { type: 'boolean', short: 'H', default: false },
        system: { type: 'boolean', short: 's', default: false },
        archive: { type: 'boolean', short: 'a', default: false },
        normal: { type: 'boolean', short: 'n', default: false },
        temporary: { type: 'boolean', default: false },
        compressed: { type: 'boolean', short: 'c', default: false },
        offline: { type: 'boolean', short: 'o', default: false },
        encrypted: { type: 'boolean', short: 'e', default: false },
        pinned: { type: 'boolean', default: false },
        unpinned: { type: 'boolean', short: 'u', default: false },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
      allowPositionals: true,
      strict: false,
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    process.exit(1);
  }

  if (opt.help || positionals.length < 3) {
    console.log(`
usage: attrib [[domain/]username[:password]@]<target> <share> <path> <query|set> [options]

File Attribute Modification Utility

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>
  share                 Share name
  path                  File path within the share
  action                query or set

query options:
  (none — just displays current attributes)

set options:
  -r, -readonly         Set read-only
  -H, -hidden           Set hidden
  -s, -system           Set system
  -a, -archive          Set archive
  -n, -normal           Set normal (clears others)
  -temporary            Set temporary
  -c, -compressed       Set compressed
  -o, -offline          Set offline
  -e, -encrypted        Set encrypted
  -pinned               Set pinned
  -u, -unpinned         Set unpinned

authentication:
  -hashes LMHASH:NTHASH
  -no-pass              Don't ask for password
  -k                    Use Kerberos authentication
  -aesKey HEX           AES key for Kerberos

connection:
  -p, -port PORT        Destination port (default 445)
  -dc-ip IP             Domain controller IP
  -target-ip IP         Target IP
  -t, -timeout SEC      Connection timeout (default 60)
  -debug                Turn DEBUG output ON
  -h, -help             Show this help message and exit
`);
    process.exit(0);
  }

  initLogger({ ts: false, debug: opt.debug as boolean });
  initProxy(opt.proxy);

  const [domain, username, parsedPw, address] = parseTarget(positionals[0]!);
  const share = positionals[1]!;
  const filePath = positionals[2]!.replace(/\//g, '\\');
  const action = (positionals[3] ?? 'query').toLowerCase();

  const targetIp = (opt['target-ip'] as string) ?? address;
  let password = parsedPw;

  if (!password && username && !opt.hashes && !opt['no-pass'] && !opt.aesKey) {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    password = await new Promise<string>((resolve) => {
      rl.question('Password:', (ans) => { rl.close(); resolve(ans); });
    });
  }

  let lmhash = '', nthash = '';
  if (opt.hashes) {
    [lmhash, nthash] = (opt.hashes as string).split(':') as [string, string];
  }

  const doKerberos = !!(opt.k || opt.aesKey);

  const conn = new SMBConnection(address, targetIp, {
    sessPort: parseInt(opt.port as string, 10),
    timeout: parseInt(opt.timeout as string, 10),
  });
  await conn.negotiateSession();

  if (doKerberos) {
    await conn.kerberosLogin(
      username, password, domain ?? '', lmhash, nthash,
      (opt.aesKey as string) ?? null,
      (opt['dc-ip'] as string) ?? null,
      null, null, false,
    );
  } else {
    await conn.login(username, password, domain ?? '', lmhash, nthash);
  }

  const tid = await conn.connectTree(share);
  const desiredAccess = action === 'set' ? FILE_WRITE_ATTRIBUTES : FILE_READ_ATTRIBUTES;

  const fid = await conn.openFile(
    tid,
    filePath,
    desiredAccess,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    0,
  );

  try {
    if (action === 'query') {
      const attrs = await attribQuery(conn, tid, fid);
      console.log(reprAttribs(attrs), share, filePath);
    } else if (action === 'set') {
      const attrs: FileAttribs = {
        readonly:   !!opt.readonly,
        hidden:     !!opt.hidden,
        system:     !!opt.system,
        volume:     false,
        directory:  false,
        archive:    !!opt.archive,
        normal:     !!opt.normal,
        temporary:  !!opt.temporary,
        compressed: !!opt.compressed,
        offline:    !!opt.offline,
        encrypted:  !!opt.encrypted,
        pinned:     !!opt.pinned,
        unpinned:   !!opt.unpinned,
      };
      await attribSet(conn, tid, fid, attrs);
      console.log(reprAttribs(attrs), share, filePath);
    } else {
      console.error(`[-] Invalid action '${action}'. Use 'query' or 'set'.`);
      process.exit(1);
    }
  } finally {
    await conn.closeFile(tid, fid);
    await conn.disconnectTree(tid);
    conn.close();
  }
}

main().catch((err) => {
  console.error(`[-] ${err.message ?? err}`);
  process.exit(1);
});
