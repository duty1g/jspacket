#!/usr/bin/env node
/**
 * jspacket - filetime
 *
 * Query & modify file / directory timestamps utilizing pure SMB.
 * Mimics the syntax & logic of the linux `touch` and `stat` binaries.
 *
 * Python implementation by Raz Kissos (@covertivy). TypeScript port.
 */

import { Buffer } from 'node:buffer';
import { createInterface } from 'node:readline';

import {
  parseTarget,
  init as initLogger,
  initProxy,
  info,
  error as logError,
  debug as logDebug,
  getLevel,
  LogLevel,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';

import { SMBConnection } from '@impacket/smb-connection';
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
  FTtoPOSIX,
} from '@impacket/smb';
import { SMB2_FILE_BASIC_INFO, FILE_BASIC_INFORMATION } from '@impacket/smb3';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SMB_SESSION_PORT = 445;
const FILETIME_READ_ACTION = 'stat';
const FILETIME_WRITE_ACTION = 'touch';
const VALID_FILETIME_ACTIONS = [FILETIME_READ_ACTION, FILETIME_WRITE_ACTION];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Convert a (possibly fractional) POSIX timestamp (seconds) to a Windows
 * FILETIME. Mirrors impacket's `POSIXtoFT`: t * 1e7 + 116444736000000000,
 * truncated to an integer. Implemented locally so fractional seconds don't
 * blow up BigInt() (the lib helper only accepts integer seconds).
 */
function posixToFT(seconds: number): bigint {
  return BigInt(Math.trunc(seconds * 10000000)) + 116444736000000000n;
}

/** Local-time ISO-8601 (no timezone suffix), matching Python's datetime.isoformat(). */
function ftToISO(ft: bigint): string {
  const posix = FTtoPOSIX(ft); // seconds
  const d = new Date(posix * 1000);
  const pad = (n: number): string => String(n).padStart(2, '0');
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
    `T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  );
}

/** ntpath.normpath-ish: normalise slashes and collapse separators. */
function ntNormpath(p: string): string {
  let s = p.replace(/\//g, '\\').replace(/\\{2,}/g, '\\');
  if (s.length > 1 && s.endsWith('\\')) s = s.slice(0, -1);
  return s;
}

interface FileTimes {
  creationTime: bigint | null;
  lastAccessTime: bigint | null;
  lastWriteTime: bigint | null;
  changeTime: bigint | null;
}

function prettyRepr(ft: FileTimes): string {
  const fmt = (v: bigint | null): string => (v === null ? 'N/A' : ftToISO(v));
  return (
    `\nCreationTime: ${fmt(ft.creationTime)}` +
    `\nLastAccessTime: ${fmt(ft.lastAccessTime)}` +
    `\nLastWriteTime: ${fmt(ft.lastWriteTime)}` +
    `\nChangeTime: ${fmt(ft.changeTime)}\n`
  );
}

// ---------------------------------------------------------------------------
// SMB query / set operations
// ---------------------------------------------------------------------------

async function filetimeQuery(
  connection: SMBConnection,
  tid: number,
  fid: number | Buffer,
): Promise<FileTimes> {
  let ft: FileTimes;
  if (connection.getDialect() === SMB_DIALECT) {
    const raw = (await connection.queryInfo(tid, fid, SMB_QUERY_FILE_BASIC_INFO)) as Buffer;
    const basic = new SMBQueryFileBasicInfo(raw);
    ft = {
      creationTime: basic.get('CreationTime') as bigint,
      lastAccessTime: basic.get('LastAccessTime') as bigint,
      lastWriteTime: basic.get('LastWriteTime') as bigint,
      changeTime: basic.get('LastChangeTime') as bigint,
    };
  } else {
    const raw = (await connection.queryInfo(tid, fid, SMB2_FILE_BASIC_INFO)) as Buffer;
    const basic = new FILE_BASIC_INFORMATION(raw);
    ft = {
      creationTime: basic.get('CreationTime') as bigint,
      lastAccessTime: basic.get('LastAccessTime') as bigint,
      lastWriteTime: basic.get('LastWriteTime') as bigint,
      changeTime: basic.get('ChangeTime') as bigint,
    };
  }
  logDebug(`Got file / directory filetimes = ${JSON.stringify(ft, (_k, v) => (typeof v === 'bigint' ? v.toString() : v))}`);
  return ft;
}

async function filetimeSet(
  connection: SMBConnection,
  tid: number,
  fid: number | Buffer,
  ft: FileTimes,
): Promise<void> {
  let infoData: SMBSetFileBasicInfo | FILE_BASIC_INFORMATION;
  let fileInfoClass: number;
  if (connection.getDialect() === SMB_DIALECT) {
    infoData = new SMBSetFileBasicInfo();
    infoData.set('ExtFileAttributes', 0);
    fileInfoClass = SMB_SET_FILE_BASIC_INFO;
  } else {
    infoData = new FILE_BASIC_INFORMATION();
    infoData.set('FileAttributes', 0);
    fileInfoClass = SMB2_FILE_BASIC_INFO;
  }

  infoData.set('CreationTime', ft.creationTime ?? 0n);
  infoData.set('LastAccessTime', ft.lastAccessTime ?? 0n);
  infoData.set('LastWriteTime', ft.lastWriteTime ?? 0n);
  infoData.set('ChangeTime', ft.changeTime ?? 0n);

  logDebug('Setting file / directory filetimes');
  await connection.setInfo(tid, fid, fileInfoClass, infoData.getData());
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

interface Options {
  target: string;
  share: string;
  path: string;
  action: string | null;
  debug: boolean;
  hashes: string | null;
  noPass: boolean;
  k: boolean;
  aesKey: string | null;
  port: number;
  dcIp: string | null;
  targetIp: string | null;
  timeout: number;
  proxy: string | null;
  // touch options
  create: boolean;
  access: boolean;
  write: boolean;
  modify: boolean;
  reference: [string, string] | null;
  timestamp: string | null;
  validate: boolean;
}

function printBanner(): void {
  console.log(BANNER + '\n');
}

function usage(): void {
  console.log(`File / Directory Timestamp Querying & Modification Utility implementation.

usage: filetime [-h] [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                [-aesKey hex key] [-p port] [-dc-ip ip] [-target-ip ip]
                [-t timeout]
                target share path {stat,touch} ...

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>
  share                 The share in which the file / directory resides
  path                  The path of the file / directory to query or modify
  {stat,touch}          Action to perform

stat:                   Show current file / directory timestamps

touch:                  Modify file / directory timestamps
  -c, --create          Change the "CreationTime"
  -a, --access          Change the "LastAccessTime"
  -w, --write           Change the "LastWriteTime"
  -m, --modify          Change the "ChangeTime"
  -r, --reference <share> <path>
                        File / directory to copy the timestamps of
  -t, --timestamp STAMP Timestamp to set (ISO format: YYYY-MM-DDTHH:MM:SS)
  -v, --validate        Query the file after touching to verify the changes

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON

authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication (KRB5CCNAME ccache)
  -aesKey hex key       AES key for Kerberos Authentication (128 or 256 bits)

connection:
  -p, --port port       Destination port to connect to the SMB Server
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -t, --timeout seconds Set connection timeout (seconds)
`);
}

/**
 * Manual argument parser. impacket uses argparse subparsers, which resolve the
 * -t collision (top-level --timeout vs touch --timestamp) by context: before
 * the `touch` subcommand -t means timeout, after it -t means timestamp. -r
 * (--reference) consumes two following values. node:util parseArgs can model
 * neither, so we tokenise by hand while preserving those exact semantics.
 */
function parseOptions(argv: string[]): Options | null {
  const opts: Options = {
    target: '',
    share: '',
    path: '',
    action: null,
    debug: false,
    hashes: null,
    noPass: false,
    k: false,
    aesKey: null,
    port: SMB_SESSION_PORT,
    dcIp: null,
    targetIp: null,
    timeout: 60,
    proxy: null,
    create: false,
    access: false,
    write: false,
    modify: false,
    reference: null,
    timestamp: null,
    validate: false,
  };

  const positionals: string[] = [];
  let sawTouch = false;

  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i]!;
    const next = (): string => {
      const v = argv[++i];
      if (v === undefined) {
        logError(`Option ${tok} requires a value`);
        process.exit(1);
      }
      return v;
    };

    switch (tok) {
      case '-h':
      case '--help':
        usage();
        process.exit(0);
        break;
      case '-debug':
      case '--debug':
        opts.debug = true;
        break;
      case '-hashes':
      case '--hashes':
        opts.hashes = next();
        break;
      case '-no-pass':
      case '--no-pass':
        opts.noPass = true;
        break;
      case '-k':
        opts.k = true;
        break;
      case '-aesKey':
      case '--aesKey':
        opts.aesKey = next();
        break;
      case '-p':
      case '--port':
        opts.port = parseInt(next(), 10);
        break;
      case '-dc-ip':
      case '--dc-ip':
        opts.dcIp = next();
        break;
      case '-target-ip':
      case '--target-ip':
        opts.targetIp = next();
        break;
      case '-proxy':
      case '--proxy':
        opts.proxy = next();
        break;
      // touch flags
      case '-c':
      case '--create':
        opts.create = true;
        break;
      case '-a':
      case '--access':
        opts.access = true;
        break;
      case '-w':
      case '--write':
        opts.write = true;
        break;
      case '-m':
      case '--modify':
        opts.modify = true;
        break;
      case '-v':
      case '--validate':
        opts.validate = true;
        break;
      case '-r':
      case '--reference':
        opts.reference = [next(), next()];
        break;
      case '-t':
        // Context-sensitive: --timeout before `touch`, --timestamp after.
        if (sawTouch) opts.timestamp = next();
        else opts.timeout = parseInt(next(), 10);
        break;
      case '--timeout':
        opts.timeout = parseInt(next(), 10);
        break;
      case '--timestamp':
        opts.timestamp = next();
        break;
      default:
        if (tok.startsWith('-')) {
          logError(`Unknown option: ${tok}`);
          process.exit(1);
        }
        positionals.push(tok);
        if (tok === FILETIME_WRITE_ACTION) sawTouch = true;
        break;
    }
  }

  if (positionals.length < 3) {
    usage();
    return null;
  }

  opts.target = positionals[0]!;
  opts.share = positionals[1]!;
  opts.path = positionals[2]!;
  opts.action = positionals[3] ?? null;
  return opts;
}

async function promptPassword(): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise<string>((resolve) => {
    rl.question('Password:', (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

async function main(): Promise<void> {
  const argv = normalizeArgs(process.argv.slice(2));

  initLogger({});
  printBanner();

  if (argv.length === 0) {
    usage();
    process.exit(1);
  }

  const options = parseOptions(argv);
  if (options === null) process.exit(1);

  initLogger({ debug: options.debug });
  initProxy(options.proxy ?? undefined);

  if (options.action === null || !VALID_FILETIME_ACTIONS.includes(options.action)) {
    logError(`Invalid action '${options.action}'`);
    process.exit(1);
  }

  const [domainRaw, username, passwordRaw, address] = parseTarget(options.target);
  const domain = domainRaw ?? '';
  let password = passwordRaw;
  if (options.targetIp === null) options.targetIp = address;

  if (
    password === '' &&
    username !== '' &&
    options.hashes === null &&
    !options.noPass &&
    options.aesKey === null
  ) {
    password = await promptPassword();
  }

  if (options.aesKey !== null) options.k = true;

  let lmhash = '';
  let nthash = '';
  if (options.hashes !== null) {
    const parts = options.hashes.split(':');
    lmhash = parts[0] ?? '';
    nthash = parts[1] ?? '';
  }

  const share = options.share;
  const path = ntNormpath(options.path);

  // Validate touch method (reference XOR timestamp) up-front.
  let refShare: string | null = null;
  let refPath: string | null = null;
  let touchTimestampSeconds: number | null = null;
  if (options.action === FILETIME_WRITE_ACTION) {
    const hasRef = options.reference !== null;
    const hasStamp = options.timestamp !== null;
    if ((hasRef && hasStamp) || (!hasRef && !hasStamp)) {
      logError('Error! Must select one touch method! Either by reference or by timestamp!');
      process.exit(1);
    }
    if (options.reference !== null) {
      refShare = options.reference[0];
      refPath = ntNormpath(options.reference[1]);
    } else if (options.timestamp !== null) {
      const parsed = new Date(options.timestamp.replace('_', 'T'));
      if (Number.isNaN(parsed.getTime())) {
        logError('Error parsing timestamp, make sure it is valid ISO format!');
        process.exit(1);
      }
      touchTimestampSeconds = parsed.getTime() / 1000;
    }
  }

  const shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

  const connection = new SMBConnection(address, options.targetIp ?? address, {
    sessPort: options.port,
    timeout: options.timeout,
  });

  try {
    await connection.negotiateSession();

    if (options.k) {
      await connection.kerberosLogin(
        username,
        password,
        domain,
        lmhash,
        nthash,
        options.aesKey ?? '',
        options.dcIp ?? null,
      );
    } else {
      await connection.login(username, password, domain, lmhash, nthash);
    }

    // Resolve the timestamps we intend to write (touch only).
    let newFiletimes: FileTimes | null = null;
    if (options.action === FILETIME_WRITE_ACTION) {
      if (refShare !== null && refPath !== null) {
        const refTid = await connection.connectTree(refShare);
        let refFid: number | Buffer | null = null;
        try {
          refFid = await connection.openFile(
            refTid,
            refPath,
            FILE_READ_ATTRIBUTES,
            shareMode,
            0, // creationOption: open both files and directories
          );
          logDebug(`Querying Reference FileTimes from '${refPath}' on share '${refShare}'!`);
          newFiletimes = await filetimeQuery(connection, refTid, refFid);
        } finally {
          if (refFid !== null) await connection.closeFile(refTid, refFid);
          await connection.disconnectTree(refTid);
        }
      } else if (touchTimestampSeconds !== null) {
        logDebug(`Got TimeStamp: '${options.timestamp}'!`);
        const ft = posixToFT(touchTimestampSeconds);
        newFiletimes = {
          creationTime: ft,
          lastAccessTime: ft,
          lastWriteTime: ft,
          changeTime: ft,
        };
      }

      // Keep only the desired filetime changes.
      if (newFiletimes !== null) {
        if (!options.create) newFiletimes.creationTime = null;
        if (!options.access) newFiletimes.lastAccessTime = null;
        if (!options.write) newFiletimes.lastWriteTime = null;
        if (!options.modify) newFiletimes.changeTime = null;
      }
    }

    const tid = await connection.connectTree(share);
    let fid: number | Buffer | null = null;
    try {
      let desiredAccess: number;
      if (options.action === FILETIME_READ_ACTION) {
        desiredAccess = FILE_READ_ATTRIBUTES;
      } else {
        desiredAccess = FILE_WRITE_ATTRIBUTES;
        if (options.validate) desiredAccess |= FILE_READ_ATTRIBUTES;
      }

      fid = await connection.openFile(
        tid,
        path,
        desiredAccess,
        shareMode,
        0, // creationOption: open both files and directories
      );

      if (options.action === FILETIME_READ_ACTION) {
        info(`Queried FileTimes for '${path}' on share '${share}'!`);
        console.log(prettyRepr(await filetimeQuery(connection, tid, fid)));
      } else if (options.action === FILETIME_WRITE_ACTION && newFiletimes !== null) {
        info(`Changing FileTimes for '${path}' on share '${share}'!`);
        console.log(prettyRepr(newFiletimes));
        await filetimeSet(connection, tid, fid, newFiletimes);
        if (options.validate) {
          info(`Validating Updated FileTimes for '${path}' on share '${share}'!`);
          console.log(prettyRepr(await filetimeQuery(connection, tid, fid)));
        }
      }
    } finally {
      if (fid !== null) await connection.closeFile(tid, fid);
      await connection.disconnectTree(tid);
      await connection.close();
    }
  } catch (e) {
    if (getLevel() === LogLevel.DEBUG) console.error(e);
    logError(String(e));
  }
}

main();
