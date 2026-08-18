import * as net from 'node:net';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

import { Structure, type PackValue } from '@impacket/structure';
import * as smb from '@impacket/smb';
import * as smb2 from '@impacket/smb3';
import * as ntlm from '@impacket/ntlm';
import * as spnego from '@impacket/spnego';
import * as uuid from '@impacket/uuid';
import * as nmb from '@impacket/nmb';
import {
  STATUS_SUCCESS, STATUS_LOGON_FAILURE, STATUS_ACCESS_DENIED,
  STATUS_NO_SUCH_FILE, STATUS_OBJECT_NAME_COLLISION,
  STATUS_FILE_IS_A_DIRECTORY, STATUS_NOT_IMPLEMENTED,
  STATUS_INVALID_HANDLE, STATUS_MORE_PROCESSING_REQUIRED,
  STATUS_OBJECT_PATH_NOT_FOUND, STATUS_DIRECTORY_NOT_EMPTY,
  STATUS_NOT_SUPPORTED, STATUS_INVALID_DEVICE_REQUEST,
  STATUS_FS_DRIVER_REQUIRED, STATUS_INVALID_INFO_CLASS,
  STATUS_OBJECT_PATH_SYNTAX_BAD, STATUS_CANCELLED,
  STATUS_INVALID_PARAMETER, STATUS_FILE_CLOSED,
  STATUS_OBJECT_NAME_NOT_FOUND, STATUS_NO_MORE_FILES,
  STATUS_NETWORK_NAME_DELETED,
} from '@impacket/nt-errors';

const STATUS_SMB_BAD_UID = 0x005B0002;
const STATUS_SMB_BAD_TID = 0x00050002;
const VOID_FILE_DESCRIPTOR = -1;
const PIPE_FILE_DESCRIPTOR = -2;

type CommandHandler = (...args: any[]) => any;
type TransHandler = (connId: string, smbServer: SMBSERVER, recvPacket: any, parameters: Buffer, data: Buffer, maxDataCount: number) => [Buffer, Buffer, Buffer, number];
type IoctlHandler = (connId: string, smbServer: SMBSERVER, ioctlRequest: any) => [any, number];

interface BuiltinPipeHandler {
  processData(input: Buffer): void;
  getResponse(): Buffer;
}

interface OpenedFile {
  FileHandle: number;
  FileName: string;
  DeleteOnClose: boolean;
  Socket?: net.Socket;
  PipeHandler?: BuiltinPipeHandler;
  Open?: {
    EnumerationLocation: number;
    EnumerationSearchPattern: string;
  };
}

interface ShareInfo {
  [key: string]: string;
  shareName: string;
}

interface ConnectionData {
  PacketNum: number;
  ClientIP: string;
  ClientPort: number;
  Uid: number;
  ConnectedShares: Record<number, ShareInfo>;
  OpenedFiles: Record<string, OpenedFile>;
  SIDs: Record<number, any[]>;
  LastRequest: Record<string, any>;
  SignatureEnabled: boolean;
  SigningChallengeResponse: Buffer;
  SigningSessionKey: Buffer;
  SignSequenceNumber: number;
  Authenticated: boolean;
  Pid?: number;
  Capabilities?: number;
  NEGOTIATE_MESSAGE?: any;
  CHALLENGE_MESSAGE?: any;
  AUTHENTICATE_MESSAGE?: any;
  _dialects_data?: any;
  _dialects_parameters?: any;
  EncryptionKey?: Buffer;
}

class ConfigParser {
  private _sections = new Map<string, Map<string, string>>();

  sections(): string[] {
    return [...this._sections.keys()];
  }

  hasSection(name: string): boolean {
    return this._sections.has(name);
  }

  addSection(name: string): void {
    if (!this._sections.has(name)) {
      this._sections.set(name, new Map());
    }
  }

  removeSection(name: string): boolean {
    return this._sections.delete(name);
  }

  get(section: string, key: string): string | undefined {
    return this._sections.get(section)?.get(key);
  }

  set(section: string, key: string, value: string): void {
    const sec = this._sections.get(section);
    if (sec) sec.set(key, value);
  }

  items(section: string): [string, string][] {
    const sec = this._sections.get(section);
    if (!sec) return [];
    return [...sec.entries()];
  }

  hasOption(section: string, key: string): boolean {
    return this._sections.get(section)?.has(key) ?? false;
  }

  getboolean(section: string, key: string): boolean {
    const v = this.get(section, key)?.toLowerCase();
    return v === 'true' || v === 'yes' || v === '1';
  }

  read(filePath: string): void {
    const content = fs.readFileSync(filePath, 'utf-8');
    let currentSection = '';
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;
      const sectionMatch = trimmed.match(/^\[(.+)\]$/);
      if (sectionMatch) {
        currentSection = sectionMatch[1]!;
        this.addSection(currentSection);
      } else if (currentSection) {
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx > 0) {
          const key = trimmed.substring(0, eqIdx).trim();
          const value = trimmed.substring(eqIdx + 1).trim();
          this.set(currentSection, key, value);
        }
      }
    }
  }
}

function getFileTime(t: number): bigint {
  return smb.POSIXtoFT(t);
}

function getUnixTime(t: bigint): number {
  return smb.FTtoPOSIX(t);
}

function getSMBDate(t: number): Buffer {
  const d = new Date(t * 1000);
  const val = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  const buf = Buffer.alloc(2);
  buf.writeUInt16LE(val);
  return buf;
}

function getSMBTime(t: number): Buffer {
  const d = new Date(t * 1000);
  const val = (d.getHours() << 11) | (d.getMinutes() << 5) | Math.floor(d.getSeconds() / 2);
  const buf = Buffer.alloc(2);
  buf.writeUInt16LE(val);
  return buf;
}

function computeNTLMv2(
  identity: string,
  lmhash: Buffer,
  nthash: Buffer,
  serverChallenge: Buffer,
  authenticateMessage: any,
  ntlmChallenge: any,
  type1: any,
): [number, Buffer] {
  const domainName = (authenticateMessage.get('domain_name') as Buffer).toString('utf16le');
  const responseKeyNT = ntlm.ntowfV2(identity, '', domainName, nthash);
  const responseKeyLM = ntlm.lmowfV2(identity, '', domainName, lmhash);

  const ntlmBuf = authenticateMessage.get('ntlm') as Buffer;
  const ntProofStr = ntlmBuf.subarray(0, 16);
  const temp = ntlmBuf.subarray(16);
  const ntProofStr2 = ntlm.hmacMd5(responseKeyNT, Buffer.concat([serverChallenge, temp]));
  const lmChallengeResponse = authenticateMessage.get('lanman') as Buffer;
  const sessionBaseKey = ntlm.hmacMd5(responseKeyNT, ntProofStr);

  let responseFlags = type1.get('flags') as number;
  const challengeFlags = ntlmChallenge.get('flags') as number;

  if (!(challengeFlags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)) {
    responseFlags &= 0xffffffff ^ ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
  }
  if (!(challengeFlags & ntlm.NTLMSSP_NEGOTIATE_128)) {
    responseFlags &= 0xffffffff ^ ntlm.NTLMSSP_NEGOTIATE_128;
  }
  if (!(challengeFlags & ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH)) {
    responseFlags &= 0xffffffff ^ ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH;
  }
  if (!(challengeFlags & ntlm.NTLMSSP_NEGOTIATE_SEAL)) {
    responseFlags &= 0xffffffff ^ ntlm.NTLMSSP_NEGOTIATE_SEAL;
  }
  if (!(challengeFlags & ntlm.NTLMSSP_NEGOTIATE_SIGN)) {
    responseFlags &= 0xffffffff ^ ntlm.NTLMSSP_NEGOTIATE_SIGN;
  }
  if (!(challengeFlags & ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN)) {
    responseFlags &= 0xffffffff ^ ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
  }

  const challenge = ntlmChallenge.get('challenge') as Buffer;
  const keyExchangeKey = ntlm.kxKey(
    challengeFlags, sessionBaseKey, lmChallengeResponse,
    challenge, '', lmhash, nthash, true,
  );

  let exportedSessionKey: Buffer;
  if (challengeFlags & ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH) {
    exportedSessionKey = authenticateMessage.get('session_key') as Buffer;
    exportedSessionKey = ntlm.generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey);
  } else {
    exportedSessionKey = keyExchangeKey;
  }

  if (ntProofStr.equals(ntProofStr2)) {
    return [STATUS_SUCCESS, exportedSessionKey];
  }
  return [STATUS_LOGON_FAILURE, exportedSessionKey];
}

function outputToJohnFormat(
  challenge: Buffer,
  username: Buffer,
  domain: Buffer,
  lmresponse: Buffer,
  ntresponse: Buffer,
): { hash_string: string; hash_version: string } | null {
  try {
    if (ntresponse.length > 24) {
      return {
        hash_string: `${username.toString('utf16le')}::${domain.toString('utf16le')}:${challenge.toString('hex')}:${ntresponse.toString('hex').substring(0, 32)}:${ntresponse.toString('hex').substring(32)}`,
        hash_version: 'ntlmv2',
      };
    }
    return {
      hash_string: `${username.toString('utf16le')}::${domain.toString('utf16le')}:${lmresponse.toString('hex')}:${ntresponse.toString('hex')}:${challenge.toString('hex')}`,
      hash_version: 'ntlm',
    };
  } catch {
    return null;
  }
}

function writeJohnOutputToFile(hashString: string, hashVersion: string, fileName: string): void {
  const parsed = path.parse(fileName);
  const suffix = hashVersion === 'ntlmv2' ? '_ntlmv2' : '_ntlm';
  const outputFilename = path.join(parsed.dir, parsed.name + suffix + parsed.ext);
  fs.appendFileSync(outputFilename, hashString + '\n');
}

function decodeSMBString(flags: number, text: Buffer): string {
  if (flags & smb.FLAGS2_UNICODE) {
    return text.toString('utf16le');
  }
  return text.toString('ascii');
}

function encodeSMBString(flags: number, text: string): Buffer {
  if (flags & smb.FLAGS2_UNICODE) {
    return Buffer.from(text, 'utf16le');
  }
  return Buffer.from(text, 'ascii');
}

function getShares(connId: string, smbServer: SMBSERVER): Record<string, Record<string, string>> {
  const config = smbServer.getServerConfig();
  const sections = config.sections().filter(s => s !== 'global');
  const shares: Record<string, Record<string, string>> = {};
  for (const s of sections) {
    shares[s] = Object.fromEntries(config.items(s));
  }
  return shares;
}

function searchShare(connId: string, share: string, smbServer: SMBSERVER): Record<string, string> | null {
  const config = smbServer.getServerConfig();
  if (config.hasSection(share)) {
    return Object.fromEntries(config.items(share));
  }
  return null;
}

function normalizePath(fileName: string, basePath?: string): string {
  let normalized = path.normalize(fileName.replace(/\\/g, '/'));
  if (normalized.length > 0 && (normalized[0] === '/' || normalized[0] === '\\')) {
    if (basePath === undefined || basePath !== '') {
      normalized = normalized.substring(1);
    }
  }
  return normalized;
}

function isInFileJail(basePath: string, fileName: string): boolean {
  const pathName = path.join(basePath, fileName);
  const shareRealPath = fs.realpathSync(basePath);
  try {
    const realPathName = fs.realpathSync(pathName);
    return realPathName.startsWith(shareRealPath);
  } catch {
    const parentDir = path.dirname(pathName);
    try {
      const realParent = fs.realpathSync(parentDir);
      return realParent.startsWith(shareRealPath);
    } catch {
      return false;
    }
  }
}

function openFile(
  basePath: string, fileName: string, accessMode: number,
  fileAttributes: number, openMode: number,
): [number, number, string, number] {
  fileName = normalizePath(fileName);
  const pathName = path.join(basePath, fileName);
  let errorCode = 0;
  let mode = 0;

  if (!isInFileJail(basePath, fileName)) {
    console.error('Path not in current working directory');
    return [0, 0, pathName, STATUS_OBJECT_PATH_SYNTAX_BAD];
  }

  if (openMode & 0x10) {
    mode = fs.constants.O_CREAT;
  } else {
    if (!fs.existsSync(pathName)) {
      return [0, 0, pathName, STATUS_NO_SUCH_FILE];
    }
  }

  try {
    if (fs.existsSync(pathName) && fs.statSync(pathName).isDirectory() && !(fileAttributes & smb.ATTR_DIRECTORY)) {
      return [0, 0, pathName, STATUS_FILE_IS_A_DIRECTORY];
    }
  } catch { /* ignore */ }

  if ((accessMode & 0x7) === 1) {
    mode |= fs.constants.O_WRONLY;
  } else if ((accessMode & 0x7) === 2) {
    mode |= fs.constants.O_RDWR;
  } else {
    mode = fs.constants.O_RDONLY;
  }

  let fid: number;
  try {
    fid = fs.openSync(pathName, mode);
  } catch (e) {
    console.error(`openFile: ${pathName},${mode}`, e);
    fid = 0;
    errorCode = STATUS_ACCESS_DENIED;
  }

  return [fid, mode, pathName, errorCode];
}

function queryFsInformation(
  basePath: string, filename: string,
  level?: number, pktFlags: number = smb.FLAGS2_UNICODE,
): Buffer | [number, number, number] | null {
  const encoding: BufferEncoding = (pktFlags & smb.FLAGS2_UNICODE) ? 'utf16le' : 'ascii';

  const fileName = normalizePath(filename);
  const pathName = path.join(basePath, fileName);
  const stat = fs.statSync(pathName);

  if (level === undefined) {
    const fileSize = stat.size;
    const lastWriteTime = Math.floor(stat.mtimeMs / 1000);
    let attribs = 0;
    if (stat.isDirectory()) attribs |= smb.ATTR_DIRECTORY;
    if (stat.isFile()) attribs |= smb.ATTR_NORMAL;
    return [fileSize, lastWriteTime, attribs];
  }

  if (level === smb.SMB_QUERY_FS_ATTRIBUTE_INFO || level === smb2.SMB2_FILESYSTEM_ATTRIBUTE_INFO) {
    const data = new smb.SMBQueryFsAttributeInfo();
    data.set('FileSystemAttributes', smb.FILE_CASE_SENSITIVE_SEARCH | smb.FILE_CASE_PRESERVED_NAMES);
    data.set('MaxFilenNameLengthInBytes', 255);
    data.set('LengthOfFileSystemName', Buffer.byteLength('XTFS', 'utf16le'));
    data.set('FileSystemName', Buffer.from('XTFS', 'utf16le'));
    return data.getData();
  }

  if (level === smb.SMB_INFO_VOLUME) {
    const data = new smb.SMBQueryFsInfoVolume();
    data.set('VolumeLabel', Buffer.from('SHARE', encoding));
    return data.getData();
  }

  if (level === smb.SMB_QUERY_FS_VOLUME_INFO || level === smb2.SMB2_FILESYSTEM_VOLUME_INFO) {
    const data = new smb.SMBQueryFsVolumeInfo();
    data.set('VolumeLabel', '');
    data.set('VolumeCreationTime', smb.POSIXtoFT(Math.floor(stat.ctimeMs / 1000)));
    return data.getData();
  }

  if (level === smb.SMB_QUERY_FS_SIZE_INFO) {
    const data = new smb.SMBQueryFsSizeInfo();
    return data.getData();
  }

  if (level === smb.SMB_QUERY_FS_DEVICE_INFO || level === smb2.SMB2_FILESYSTEM_DEVICE_INFO) {
    const data = new smb.SMBQueryFsDeviceInfo();
    data.set('DeviceType', smb.FILE_DEVICE_DISK);
    return data.getData();
  }

  if (level === smb.FILE_FS_FULL_SIZE_INFORMATION || level === smb2.SMB2_FILESYSTEM_FULL_SIZE_INFO) {
    const data = new smb.SMBFileFsFullSizeInformation();
    return data.getData();
  }

  if (level === smb.FILE_FS_SIZE_INFORMATION || level === smb2.SMB2_FILESYSTEM_SIZE_INFO) {
    const data = new smb.FileFsSizeInformation();
    return data.getData();
  }

  return null;
}

function fnmatch(name: string, pattern: string): boolean {
  const regex = new RegExp(
    '^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*')
      .replace(/\?/g, '.') + '$', 'i',
  );
  return regex.test(name);
}

function findFirst2(
  basePath: string, fileName: string, level: number,
  searchAttributes: number, pktFlags: number = smb.FLAGS2_UNICODE,
  isSMB2: boolean = false,
): [any[], number, number] {
  const encoding: BufferEncoding = (pktFlags & smb.FLAGS2_UNICODE) ? 'utf16le' : 'ascii';

  fileName = normalizePath(fileName);
  const pathName = path.join(basePath, fileName);

  if (!isInFileJail(basePath, fileName)) {
    console.error('Path not in current working directory');
    return [[], 0, STATUS_OBJECT_PATH_SYNTAX_BAD];
  }

  const files: string[] = [];
  let pattern = '';
  let dirName = '';

  if (!pathName.includes('*') && !pathName.includes('?')) {
    pattern = '';
  } else {
    pattern = path.basename(pathName);
    dirName = path.dirname(pathName);
  }

  if (pattern === '*') {
    files.push(path.join(dirName, '.'));
    files.push(path.join(dirName, '..'));
  }

  if (pattern !== '') {
    if (!fs.existsSync(dirName)) {
      return [[], 0, STATUS_OBJECT_NAME_NOT_FOUND];
    }
    for (const file of fs.readdirSync(dirName)) {
      if (fnmatch(file.toLowerCase(), pattern.toLowerCase())) {
        const entry = path.join(dirName, file);
        try {
          if (fs.statSync(entry).isDirectory()) {
            if (searchAttributes & smb.ATTR_DIRECTORY) {
              files.push(entry);
            }
          } else {
            files.push(entry);
          }
        } catch {
          files.push(entry);
        }
      }
    }
  } else {
    if (fs.existsSync(pathName)) {
      files.push(pathName);
    }
  }

  const searchResult: any[] = [];
  const searchCount = files.length;
  const errorCode = STATUS_SUCCESS;

  for (const i of files) {
    let item: Structure;
    if (level === smb.SMB_FIND_FILE_BOTH_DIRECTORY_INFO || level === smb2.SMB2_FILE_BOTH_DIRECTORY_INFO) {
      item = new smb.SMBFindFileBothDirectoryInfo();
    } else if (level === smb.SMB_FIND_FILE_DIRECTORY_INFO || level === smb2.SMB2_FILE_DIRECTORY_INFO) {
      item = new smb.SMBFindFileDirectoryInfo();
    } else if (level === smb.SMB_FIND_FILE_FULL_DIRECTORY_INFO || level === smb2.SMB2_FULL_DIRECTORY_INFO) {
      item = new smb.SMBFindFileFullDirectoryInfo();
    } else if ((level as number) === smb.SMB_FIND_INFO_STANDARD) {
      item = new smb.SMBFindInfoStandard();
    } else if (level === smb.SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO || level === smb2.SMB2_FILE_ID_FULL_DIRECTORY_INFO) {
      item = new smb.SMBFindFileIdFullDirectoryInfo();
    } else if (level === smb.SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO || level === smb2.SMB2_FILE_ID_BOTH_DIRECTORY_INFO) {
      item = new smb.SMBFindFileIdBothDirectoryInfo();
    } else if (level === smb.SMB_FIND_FILE_NAMES_INFO || level === smb2.SMB2_FILE_NAMES_INFO) {
      item = new smb.SMBFindFileNamesInfo();
    } else {
      console.error(`Wrong level ${level}!`);
      return [searchResult, searchCount, STATUS_NOT_SUPPORTED];
    }

    let stat: fs.Stats;
    try {
      stat = fs.statSync(i);
    } catch {
      stat = fs.lstatSync(i);
    }

    const size = stat.size;
    const atime = Math.floor(stat.atimeMs / 1000);
    const mtime = Math.floor(stat.mtimeMs / 1000);
    const ctime = Math.floor(stat.ctimeMs / 1000);

    if (stat.isDirectory()) {
      item.set('ExtFileAttributes', smb.ATTR_DIRECTORY);
    } else {
      item.set('ExtFileAttributes', smb.ATTR_NORMAL | smb.ATTR_ARCHIVE);
    }

    item.set('FileName', Buffer.from(path.basename(i), encoding));

    if (level === smb.SMB_FIND_FILE_BOTH_DIRECTORY_INFO || level === smb2.SMB2_FILE_BOTH_DIRECTORY_INFO ||
        level === smb.SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO || level === smb2.SMB2_FILE_ID_BOTH_DIRECTORY_INFO) {
      item.set('EaSize', 0);
      item.set('EndOfFile', size);
      item.set('AllocationSize', size);
      item.set('CreationTime', smb.POSIXtoFT(ctime));
      item.set('LastAccessTime', smb.POSIXtoFT(atime));
      item.set('LastWriteTime', smb.POSIXtoFT(mtime));
      item.set('LastChangeTime', smb.POSIXtoFT(mtime));
      item.set('ShortName', Buffer.alloc(24));
      item.set('FileName', Buffer.from(path.basename(i), encoding));
      const padLen = (8 - (item.length % 8)) % 8;
      item.set('NextEntryOffset', item.length + padLen);
    } else if (level === smb.SMB_FIND_FILE_DIRECTORY_INFO || level === smb2.SMB2_FILE_DIRECTORY_INFO) {
      item.set('EndOfFile', size);
      item.set('AllocationSize', size);
      item.set('CreationTime', smb.POSIXtoFT(ctime));
      item.set('LastAccessTime', smb.POSIXtoFT(atime));
      item.set('LastWriteTime', smb.POSIXtoFT(mtime));
      item.set('LastChangeTime', smb.POSIXtoFT(mtime));
      item.set('FileName', Buffer.from(path.basename(i), encoding));
      const padLen = (8 - (item.length % 8)) % 8;
      item.set('NextEntryOffset', item.length + padLen);
    } else if (level === smb.SMB_FIND_FILE_FULL_DIRECTORY_INFO || level === smb.SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO ||
               level === smb2.SMB2_FULL_DIRECTORY_INFO || level === smb2.SMB2_FILE_ID_FULL_DIRECTORY_INFO) {
      item.set('EaSize', 0);
      item.set('EndOfFile', size);
      item.set('AllocationSize', size);
      item.set('CreationTime', smb.POSIXtoFT(ctime));
      item.set('LastAccessTime', smb.POSIXtoFT(atime));
      item.set('LastWriteTime', smb.POSIXtoFT(mtime));
      item.set('LastChangeTime', smb.POSIXtoFT(mtime));
      const padLen = (8 - (item.length % 8)) % 8;
      item.set('NextEntryOffset', item.length + padLen);
    } else if ((level as number) === smb.SMB_FIND_INFO_STANDARD) {
      item.set('EaSize', size);
      item.set('CreationDate', getSMBDate(ctime));
      item.set('CreationTime', getSMBTime(ctime));
      item.set('LastAccessDate', getSMBDate(atime));
      item.set('LastAccessTime', getSMBTime(atime));
      item.set('LastWriteDate', getSMBDate(mtime));
      item.set('LastWriteTime', getSMBTime(mtime));
    } else if (level === smb.SMB_FIND_FILE_NAMES_INFO || level === smb2.SMB2_FILE_NAMES_INFO) {
      const padLen = (8 - (item.length % 8)) % 8;
      item.set('NextEntryOffset', item.length + padLen);
    }
    searchResult.push(item);
  }

  if (searchResult.length > 0) {
    searchResult[searchResult.length - 1]!.set('NextEntryOffset', 0);
  }

  return [searchResult, searchCount, errorCode];
}

function queryPathInformation(basePath: string, filename: string, level: number): [Buffer | null, number] {
  const fileName = normalizePath(filename);
  const pathName = path.join(basePath, fileName);

  if (!fs.existsSync(pathName)) {
    return [null, STATUS_OBJECT_NAME_NOT_FOUND];
  }

  const stat = fs.statSync(pathName);
  const atime = Math.floor(stat.atimeMs / 1000);
  const mtime = Math.floor(stat.mtimeMs / 1000);
  const ctime = Math.floor(stat.ctimeMs / 1000);
  const size = stat.size;

  let attribs = 0;
  if (stat.isDirectory()) attribs |= smb.ATTR_DIRECTORY;
  if (stat.isFile()) attribs |= smb.ATTR_NORMAL | smb.ATTR_ARCHIVE;

  if (level === smb.SMB_QUERY_FILE_BASIC_INFO || level === smb2.SMB2_FILE_BASIC_INFO) {
    const infoRecord = new smb.SMBQueryFileBasicInfo();
    infoRecord.set('CreationTime', smb.POSIXtoFT(ctime));
    infoRecord.set('LastAccessTime', smb.POSIXtoFT(atime));
    infoRecord.set('LastWriteTime', smb.POSIXtoFT(mtime));
    infoRecord.set('LastChangeTime', smb.POSIXtoFT(mtime));
    infoRecord.set('ExtFileAttributes', attribs);
    return [infoRecord.getData(), STATUS_SUCCESS];
  }

  if (level === smb.SMB_QUERY_FILE_STANDARD_INFO || level === smb2.SMB2_FILE_STANDARD_INFO) {
    const infoRecord = new smb.SMBQueryFileStandardInfo();
    infoRecord.set('AllocationSize', size);
    infoRecord.set('EndOfFile', size);
    infoRecord.set('NumberOfLinks', stat.nlink);
    infoRecord.set('DeletePending', 0);
    infoRecord.set('Directory', stat.isDirectory() ? 1 : 0);
    return [infoRecord.getData(), STATUS_SUCCESS];
  }

  if (level === smb.SMB_QUERY_FILE_ALL_INFO || level === smb2.SMB2_FILE_ALL_INFO) {
    const infoRecord = new smb.SMBQueryFileAllInfo();
    infoRecord.set('CreationTime', smb.POSIXtoFT(ctime));
    infoRecord.set('LastAccessTime', smb.POSIXtoFT(atime));
    infoRecord.set('LastWriteTime', smb.POSIXtoFT(mtime));
    infoRecord.set('LastChangeTime', smb.POSIXtoFT(mtime));
    infoRecord.set('ExtFileAttributes', attribs);
    infoRecord.set('AllocationSize', size);
    infoRecord.set('EndOfFile', size);
    infoRecord.set('NumberOfLinks', stat.nlink);
    infoRecord.set('DeletePending', 0);
    infoRecord.set('Directory', stat.isDirectory() ? 1 : 0);
    infoRecord.set('FileName', Buffer.from(path.basename(fileName), 'utf16le'));
    return [infoRecord.getData(), STATUS_SUCCESS];
  }

  if (level === smb2.SMB2_FILE_NETWORK_OPEN_INFO) {
    const infoRecord = new smb.SMBFileNetworkOpenInfo();
    infoRecord.set('CreationTime', smb.POSIXtoFT(ctime));
    infoRecord.set('LastAccessTime', smb.POSIXtoFT(atime));
    infoRecord.set('LastWriteTime', smb.POSIXtoFT(mtime));
    infoRecord.set('ChangeTime', smb.POSIXtoFT(mtime));
    infoRecord.set('AllocationSize', size);
    infoRecord.set('EndOfFile', size);
    infoRecord.set('FileAttributes', attribs);
    return [infoRecord.getData(), STATUS_SUCCESS];
  }

  if (level === smb.SMB_QUERY_FILE_EA_INFO || level === smb2.SMB2_FILE_EA_INFO) {
    const infoRecord = new smb.SMBQueryFileEaInfo();
    infoRecord.set('EaSize', 0);
    return [infoRecord.getData(), STATUS_SUCCESS];
  }

  if (level === smb.SMB_QUERY_FILE_STREAM_INFO || level === smb2.SMB2_FILE_STREAM_INFO) {
    const infoRecord = new smb.SMBFileStreamInformation();
    infoRecord.set('StreamName', Buffer.from('::$DATA', 'utf16le'));
    infoRecord.set('StreamSize', size);
    infoRecord.set('StreamAllocationSize', size);
    return [infoRecord.getData(), STATUS_SUCCESS];
  }

  if (level === smb2.SMB2_ATTRIBUTE_TAG_INFO) {
    const infoRecord = new smb2.FILE_ATTRIBUTE_TAG_INFORMATION();
    infoRecord.set('FileAttributes', attribs);
    infoRecord.set('ReparsePointTag', 0);
    return [infoRecord.getData(), STATUS_SUCCESS];
  }

  if (level === smb2.SMB2_FILE_INTERNAL_INFO) {
    const infoRecord = new smb2.FILE_INTERNAL_INFORMATION();
    infoRecord.set('IndexNumber', BigInt(stat.ino));
    return [infoRecord.getData(), STATUS_SUCCESS];
  }

  return [null, STATUS_INVALID_INFO_CLASS];
}

function queryFileInformation(basePath: string, filename: string, level: number): [Buffer | null, number] {
  return queryPathInformation(basePath, filename, level);
}

function queryDiskInformation(_basePath: string): [number, number] {
  return [65535, 65535];
}

class TRANSCommands {
  static lanMan(
    connId: string, smbServer: SMBSERVER, _recvPacket: any,
    _parameters: Buffer, data: Buffer, _maxDataCount: number,
  ): [Buffer, Buffer, Buffer, number] {
    const respSetup = Buffer.alloc(0);
    const respData = Buffer.alloc(0);
    const respParameters = Buffer.alloc(0);
    const errorCode = STATUS_NOT_IMPLEMENTED;
    return [respSetup, respParameters, respData, errorCode];
  }

  static transactNamedPipe(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
    parameters: Buffer, data: Buffer, _maxDataCount: number,
  ): [Buffer, Buffer, Buffer, number] {
    const connData = smbServer.getConnectionData(connId, false);
    const respSetup = Buffer.alloc(0);
    const respParameters = Buffer.alloc(0);
    let errorCode = STATUS_SUCCESS;

    const fid = parameters.readUInt16LE(0);
    const fidStr = fid.toString();

    if (!connData.OpenedFiles[fidStr]) {
      return [respSetup, respParameters, Buffer.alloc(0), STATUS_INVALID_HANDLE];
    }

    const fileHandle = connData.OpenedFiles[fidStr]!;
    let respData = Buffer.alloc(0);

    if (fileHandle.Socket) {
      try {
        fileHandle.Socket.write(data);
        respData = Buffer.alloc(65535);
        // For named pipes, we'd need async recv - simplified here
      } catch (e) {
        console.error('transactNamedPipe error:', e);
        errorCode = STATUS_ACCESS_DENIED;
      }
    }

    return [respSetup, respParameters, respData, errorCode];
  }
}

class TRANS2Commands {
  static setPathInformation(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
    parameters: Buffer, data: Buffer, _maxDataCount: number,
  ): [Buffer, Buffer, Buffer, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSetup = Buffer.alloc(0);
    const respParameters = new smb.SMBSetPathInformationResponse_Parameters();
    let errorCode = STATUS_SUCCESS;

    const setPathInfoParams = new smb.SMBSetPathInformation_Parameters();
    setPathInfoParams.fromString(parameters);
    const informationLevel = setPathInfoParams.get('InformationLevel') as number;

    if (informationLevel === smb.SMB_SET_FILE_BASIC_INFO) {
      const setInfo = new smb.SMBSetFileBasicInfo();
      setInfo.fromString(data);

      const pathStr = decodeSMBString(
        (recvPacket as Structure).get('Flags2') as number,
        setPathInfoParams.get('FileName') as Buffer,
      );

      const tid = (recvPacket as Structure).get('Tid') as number;
      const share = connData.ConnectedShares[tid];
      if (share) {
        const sharePath = share['path'] || '';
        const normalized = normalizePath(pathStr);
        const fullPath = path.join(sharePath, normalized);
        try {
          const atime = Number(smb.FTtoPOSIX(setInfo.get('LastAccessTime') as bigint));
          const mtime = Number(smb.FTtoPOSIX(setInfo.get('LastWriteTime') as bigint));
          if (atime > 0 && mtime > 0) {
            fs.utimesSync(fullPath, atime, mtime);
          }
        } catch {
          errorCode = STATUS_ACCESS_DENIED;
        }
      }
    }

    return [respSetup, respParameters.getData(), Buffer.alloc(0), errorCode];
  }

  static setFileInformation(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
    parameters: Buffer, data: Buffer, _maxDataCount: number,
  ): [Buffer, Buffer, Buffer, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSetup = Buffer.alloc(0);
    const respParameters = new smb.SMBSetFileInformationResponse_Parameters();
    let errorCode = STATUS_SUCCESS;

    const setFileInfoParams = new smb.SMBSetFileInformation_Parameters();
    setFileInfoParams.fromString(parameters);
    const informationLevel = setFileInfoParams.get('InformationLevel') as number;
    const fid = (setFileInfoParams.get('FID') as number).toString();

    if (!connData.OpenedFiles[fid]) {
      return [respSetup, respParameters.getData(), Buffer.alloc(0), STATUS_INVALID_HANDLE];
    }

    const fileEntry = connData.OpenedFiles[fid]!;

    if (informationLevel === smb.SMB_SET_FILE_DISPOSITION_INFO) {
      const setInfo = new smb.SMBSetFileDispositionInfo();
      setInfo.fromString(data);
      fileEntry.DeleteOnClose = (setInfo.get('DeletePending') as number) !== 0;
    } else if (informationLevel === smb.SMB_SET_FILE_BASIC_INFO) {
      const setInfo = new smb.SMBSetFileBasicInfo();
      setInfo.fromString(data);
      try {
        const atime = Number(smb.FTtoPOSIX(setInfo.get('LastAccessTime') as bigint));
        const mtime = Number(smb.FTtoPOSIX(setInfo.get('LastWriteTime') as bigint));
        if (atime > 0 && mtime > 0) {
          fs.utimesSync(fileEntry.FileName, atime, mtime);
        }
      } catch {
        errorCode = STATUS_ACCESS_DENIED;
      }
    } else if (informationLevel === smb.SMB_SET_FILE_END_OF_FILE_INFO) {
      const setInfo = new smb.SMBSetFileEndOfFileInfo();
      setInfo.fromString(data);
      const eof = setInfo.get('EndOfFile') as number;
      try {
        fs.ftruncateSync(fileEntry.FileHandle, eof);
      } catch {
        errorCode = STATUS_ACCESS_DENIED;
      }
    }

    smbServer.setConnectionData(connId, connData);
    return [respSetup, respParameters.getData(), Buffer.alloc(0), errorCode];
  }

  static queryFileInformation(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
    parameters: Buffer, data: Buffer, _maxDataCount: number,
  ): [Buffer, Buffer, Buffer, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSetup = Buffer.alloc(0);
    const respParameters = new smb.SMBQueryFileInformationResponse_Parameters();

    const queryFileInfoParams = new smb.SMBQueryFileInformation_Parameters();
    queryFileInfoParams.fromString(parameters);
    const fid = (queryFileInfoParams.get('FID') as number).toString();
    const informationLevel = queryFileInfoParams.get('InformationLevel') as number;

    if (!connData.OpenedFiles[fid]) {
      return [respSetup, respParameters.getData(), Buffer.alloc(0), STATUS_INVALID_HANDLE];
    }

    const fileEntry = connData.OpenedFiles[fid]!;
    const [infoRecord, errorCode] = queryFileInformation(
      path.dirname(fileEntry.FileName),
      path.basename(fileEntry.FileName),
      informationLevel,
    );

    if (infoRecord) {
      return [respSetup, respParameters.getData(), infoRecord, errorCode];
    }
    return [respSetup, respParameters.getData(), Buffer.alloc(0), errorCode];
  }

  static queryPathInformation(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
    parameters: Buffer, data: Buffer, _maxDataCount: number,
  ): [Buffer, Buffer, Buffer, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSetup = Buffer.alloc(0);
    const respParameters = new smb.SMBQueryPathInformationResponse_Parameters();

    const queryPathInfoParams = new smb.SMBQueryPathInformation_Parameters();
    queryPathInfoParams.fromString(parameters);
    const informationLevel = queryPathInfoParams.get('InformationLevel') as number;

    const pathStr = decodeSMBString(
      (recvPacket as Structure).get('Flags2') as number,
      queryPathInfoParams.get('FileName') as Buffer,
    );

    const tid = (recvPacket as Structure).get('Tid') as number;
    const share = connData.ConnectedShares[tid];
    if (!share) {
      return [respSetup, respParameters.getData(), Buffer.alloc(0), STATUS_SMB_BAD_TID];
    }

    const sharePath = share['path'] || '';
    const [infoRecord, errorCode] = queryPathInformation(sharePath, pathStr, informationLevel);

    if (infoRecord) {
      return [respSetup, respParameters.getData(), infoRecord, errorCode];
    }
    return [respSetup, respParameters.getData(), Buffer.alloc(0), errorCode];
  }

  static queryFsInformation(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
    parameters: Buffer, _data: Buffer, _maxDataCount: number,
  ): [Buffer, Buffer, Buffer, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSetup = Buffer.alloc(0);

    const informationLevel = parameters.readUInt16LE(0);
    const tid = (recvPacket as Structure).get('Tid') as number;
    const share = connData.ConnectedShares[tid];
    if (!share) {
      return [respSetup, Buffer.alloc(0), Buffer.alloc(0), STATUS_SMB_BAD_TID];
    }

    const sharePath = share['path'] || '.';
    const flags2 = (recvPacket as Structure).get('Flags2') as number;
    const result = queryFsInformation(sharePath, '', informationLevel, flags2);

    if (result && Buffer.isBuffer(result)) {
      return [respSetup, Buffer.alloc(0), result, STATUS_SUCCESS];
    }
    return [respSetup, Buffer.alloc(0), Buffer.alloc(0), STATUS_NOT_SUPPORTED];
  }

  static findFirst2(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
    parameters: Buffer, _data: Buffer, maxDataCount: number,
  ): [Buffer, Buffer, Buffer, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSetup = Buffer.alloc(0);
    const respParameters = new smb.SMBFindFirst2Response_Parameters();
    const flags2 = (recvPacket as Structure).get('Flags2') as number;

    const findFirst2Params = new smb.SMBFindFirst2_Parameters();
    findFirst2Params.fromString(parameters);
    const searchAttributes = findFirst2Params.get('SearchAttributes') as number;
    const informationLevel = findFirst2Params.get('InformationLevel') as number;

    const pathStr = decodeSMBString(flags2, findFirst2Params.get('FileName') as Buffer);
    const tid = (recvPacket as Structure).get('Tid') as number;
    const share = connData.ConnectedShares[tid];
    if (!share) {
      return [respSetup, respParameters.getData(), Buffer.alloc(0), STATUS_SMB_BAD_TID];
    }

    const sharePath = share['path'] || '.';
    const [searchResult, _searchCount, errorCode] = findFirst2(
      sharePath, pathStr, informationLevel, searchAttributes, flags2,
    );

    if (errorCode !== STATUS_SUCCESS) {
      return [respSetup, respParameters.getData(), Buffer.alloc(0), errorCode];
    }

    let respData = Buffer.alloc(0);
    let count = 0;
    for (const item of searchResult) {
      const itemData = (item as Structure).getData();
      const padLen = (8 - (itemData.length % 8)) % 8;
      const padded = Buffer.concat([itemData, Buffer.alloc(padLen)]);
      if (respData.length + padded.length > maxDataCount) break;
      respData = Buffer.concat([respData, padded]);
      count++;
    }

    const sid = Math.floor(Math.random() * 0xffff);
    connData.SIDs[sid] = searchResult.slice(count);

    respParameters.set('SID', sid);
    respParameters.set('SearchCount', count);
    respParameters.set('EndOfSearch', count >= searchResult.length ? 1 : 0);
    respParameters.set('LastNameOffset', 0);

    smbServer.setConnectionData(connId, connData);
    return [respSetup, respParameters.getData(), respData, STATUS_SUCCESS];
  }

  static findNext2(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
    parameters: Buffer, _data: Buffer, maxDataCount: number,
  ): [Buffer, Buffer, Buffer, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSetup = Buffer.alloc(0);
    const respParameters = new smb.SMBFindNext2Response_Parameters();

    const findNext2Params = new smb.SMBFindNext2_Parameters();
    findNext2Params.fromString(parameters);
    const sid = findNext2Params.get('SID') as number;

    if (!connData.SIDs[sid]) {
      return [respSetup, respParameters.getData(), Buffer.alloc(0), STATUS_INVALID_HANDLE];
    }

    const remaining = connData.SIDs[sid]!;
    let respData = Buffer.alloc(0);
    let count = 0;

    for (const item of remaining) {
      const itemData = (item as Structure).getData();
      const padLen = (8 - (itemData.length % 8)) % 8;
      const padded = Buffer.concat([itemData, Buffer.alloc(padLen)]);
      if (respData.length + padded.length > maxDataCount) break;
      respData = Buffer.concat([respData, padded]);
      count++;
    }

    connData.SIDs[sid] = remaining.slice(count);

    respParameters.set('SearchCount', count);
    respParameters.set('EndOfSearch', count >= remaining.length ? 1 : 0);
    respParameters.set('LastNameOffset', 0);

    smbServer.setConnectionData(connId, connData);
    return [respSetup, respParameters.getData(), respData, STATUS_SUCCESS];
  }
}

class SMBCommands {
  static smbTransaction(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any,
    recvPacket: any, transCommands: Record<string | number, TransHandler>,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_TRANSACTION;
    const transParameters = new smb.SMBTransaction_Parameters();
    transParameters.fromString((SMBCommand_ as Structure).get('Parameters') as Buffer);
    const transData = new smb.SMBTransaction_Data();
    transData.fromString((SMBCommand_ as Structure).get('Data') as Buffer);

    const setup = transParameters.get('Setup') as Buffer;
    const name = decodeSMBString(
      (recvPacket as Structure).get('Flags2') as number,
      transData.get('Name') as Buffer,
    );

    const paramOffset = (transParameters.get('ParameterOffset') as number) - 63;
    const paramCount = transParameters.get('ParameterCount') as number;
    const dataOffset = (transParameters.get('DataOffset') as number) - 63;
    const dataCount = transParameters.get('DataCount') as number;
    const maxDataCount = transParameters.get('MaxDataCount') as number;

    const rawData = (SMBCommand_ as Structure).get('Data') as Buffer;
    const paramBytes = rawData.subarray(paramOffset, paramOffset + paramCount);
    const dataBytes = rawData.subarray(dataOffset, dataOffset + dataCount);

    let handler: TransHandler | undefined;
    if (name && transCommands[name]) {
      handler = transCommands[name];
    } else if (setup.length >= 2) {
      const setupCode = setup.readUInt16LE(0);
      handler = transCommands[setupCode];
    }

    if (!handler) {
      return [[], null, STATUS_NOT_IMPLEMENTED];
    }

    const [respSetup, respParams, respData, errorCode] = handler(
      connId, smbServer, recvPacket, paramBytes, dataBytes, maxDataCount,
    );

    const transResponse = new smb.SMBTransactionResponse_Parameters();
    transResponse.set('TotalParameterCount', respParams.length);
    transResponse.set('TotalDataCount', respData.length);
    transResponse.set('ParameterCount', respParams.length);
    transResponse.set('ParameterOffset', 56 + respSetup.length);
    transResponse.set('ParameterDisplacement', 0);
    transResponse.set('DataCount', respData.length);
    transResponse.set('DataOffset', 56 + respSetup.length + respParams.length);
    transResponse.set('DataDisplacement', 0);
    transResponse.set('SetupCount', Math.floor(respSetup.length / 2));
    transResponse.set('Setup', respSetup);

    respSMBCommand.set('Parameters', transResponse.getData());

    const transResponseData = new smb.SMBTransactionResponse_Data();
    transResponseData.set('Trans_Parameters', respParams);
    transResponseData.set('Trans_Data', respData);
    respSMBCommand.set('Data', transResponseData.getData());

    smbServer.setConnectionData(connId, connData);
    return [[respSMBCommand], null, errorCode];
  }

  static smbTransaction2(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any,
    recvPacket: any, transCommands: Record<number, TransHandler>,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_TRANSACTION2;
    const trans2Parameters = new smb.SMBTransaction2_Parameters();
    trans2Parameters.fromString((SMBCommand_ as Structure).get('Parameters') as Buffer);

    const setup = trans2Parameters.get('Setup') as Buffer;
    const subCommand = setup.readUInt16LE(0);

    const paramOffset = (trans2Parameters.get('ParameterOffset') as number) - 63;
    const paramCount = trans2Parameters.get('ParameterCount') as number;
    const dataOffset = (trans2Parameters.get('DataOffset') as number) - 63;
    const dataCount = trans2Parameters.get('DataCount') as number;
    const maxDataCount = trans2Parameters.get('MaxDataCount') as number;

    const rawData = (SMBCommand_ as Structure).get('Data') as Buffer;
    const paramBytes = rawData.subarray(Math.max(0, paramOffset), paramOffset + paramCount);
    const dataBytes = rawData.subarray(Math.max(0, dataOffset), dataOffset + dataCount);

    const handler = transCommands[subCommand];
    if (!handler) {
      return [[], null, STATUS_NOT_IMPLEMENTED];
    }

    const [respSetup, respParams, respData, errorCode] = handler(
      connId, smbServer, recvPacket, paramBytes, dataBytes, maxDataCount,
    );

    const trans2Response = new smb.SMBTransaction2Response_Parameters();
    trans2Response.set('TotalParameterCount', respParams.length);
    trans2Response.set('TotalDataCount', respData.length);
    trans2Response.set('ParameterCount', respParams.length);
    trans2Response.set('ParameterOffset', 56 + respSetup.length);
    trans2Response.set('ParameterDisplacement', 0);
    trans2Response.set('DataCount', respData.length);
    trans2Response.set('DataOffset', 56 + respSetup.length + respParams.length);
    trans2Response.set('DataDisplacement', 0);
    trans2Response.set('SetupCount', Math.floor(respSetup.length / 2));
    trans2Response.set('Setup', respSetup);

    respSMBCommand.set('Parameters', trans2Response.getData());

    const trans2ResponseData = new smb.SMBTransaction2Response_Data();
    trans2ResponseData.set('Trans_Parameters', respParams);
    trans2ResponseData.set('Trans_Data', respData);
    respSMBCommand.set('Data', trans2ResponseData.getData());

    smbServer.setConnectionData(connId, connData);
    return [[respSMBCommand], null, errorCode];
  }

  static smbNTTransact(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any,
    recvPacket: any, transCommands: Record<number, TransHandler>,
  ): [any[], any | null, number] {
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_NT_TRANSACT;

    const ntTransParams = new smb.SMBNTTransaction_Parameters();
    ntTransParams.fromString((SMBCommand_ as Structure).get('Parameters') as Buffer);
    const subCommand = ntTransParams.get('Function') as number;

    const handler = transCommands[subCommand];
    if (!handler) {
      return [[], null, STATUS_NOT_IMPLEMENTED];
    }

    const paramOffset = (ntTransParams.get('ParameterOffset') as number) - 73;
    const paramCount = ntTransParams.get('ParameterCount') as number;
    const dataOffset = (ntTransParams.get('DataOffset') as number) - 73;
    const dataCount = ntTransParams.get('DataCount') as number;
    const maxDataCount = ntTransParams.get('MaxDataCount') as number;

    const rawData = (SMBCommand_ as Structure).get('Data') as Buffer;
    const paramBytes = rawData.subarray(Math.max(0, paramOffset), paramOffset + paramCount);
    const dataBytes = rawData.subarray(Math.max(0, dataOffset), dataOffset + dataCount);

    const [respSetup, respParams, respData, errorCode] = handler(
      connId, smbServer, recvPacket, paramBytes, dataBytes, maxDataCount,
    );

    const ntTransResponse = new smb.SMBNTTransactionResponse_Parameters();
    ntTransResponse.set('TotalParameterCount', respParams.length);
    ntTransResponse.set('TotalDataCount', respData.length);
    ntTransResponse.set('ParameterCount', respParams.length);
    ntTransResponse.set('ParameterOffset', 68 + respSetup.length);
    ntTransResponse.set('ParameterDisplacement', 0);
    ntTransResponse.set('DataCount', respData.length);
    ntTransResponse.set('DataOffset', 68 + respSetup.length + respParams.length);
    ntTransResponse.set('DataDisplacement', 0);
    ntTransResponse.set('SetupCount', Math.floor(respSetup.length / 2));
    ntTransResponse.set('Setup', respSetup);

    respSMBCommand.set('Parameters', ntTransResponse.getData());

    const ntTransResponseData = new smb.SMBNTTransactionResponse_Data();
    ntTransResponseData.set('Trans_Parameters', respParams);
    ntTransResponseData.set('Trans_Data', respData);
    respSMBCommand.set('Data', ntTransResponseData.getData());

    return [[respSMBCommand], null, errorCode];
  }

  static smbComLockingAndX(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_LOCKING_ANDX;
    respSMBCommand.set('Parameters', Buffer.alloc(4));
    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComClose(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_CLOSE;
    respSMBCommand.set('Parameters', Buffer.alloc(0));

    const closeParams = new smb.SMBClose_Parameters();
    closeParams.fromString((SMBCommand_ as Structure).get('Parameters') as Buffer);
    const fid = (closeParams.get('FID') as number).toString();

    if (connData.OpenedFiles[fid]) {
      const fileEntry = connData.OpenedFiles[fid]!;
      const fh = fileEntry.FileHandle;

      if (fh === PIPE_FILE_DESCRIPTOR) {
        fileEntry.Socket?.destroy();
      } else if (fh !== VOID_FILE_DESCRIPTOR) {
        try { fs.closeSync(fh); } catch { /* ignore */ }
        if (fileEntry.DeleteOnClose) {
          try { fs.unlinkSync(fileEntry.FileName); } catch { /* ignore */ }
        }
      }
      delete connData.OpenedFiles[fid];
    }

    smbServer.setConnectionData(connId, connData);
    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComWrite(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_WRITE;

    const writeParams = new smb.SMBWrite_Parameters();
    writeParams.fromString((SMBCommand_ as Structure).get('Parameters') as Buffer);
    const fid = (writeParams.get('Fid') as number).toString();
    const offset = writeParams.get('Offset') as number;

    if (!connData.OpenedFiles[fid]) {
      return [[respSMBCommand], null, STATUS_INVALID_HANDLE];
    }

    const fileEntry = connData.OpenedFiles[fid]!;
    const writeData = new smb.SMBWrite_Data();
    writeData.fromString((SMBCommand_ as Structure).get('Data') as Buffer);
    const dataBytes = writeData.get('Data') as Buffer;

    let written = 0;
    if (fileEntry.FileHandle === PIPE_FILE_DESCRIPTOR && fileEntry.Socket) {
      fileEntry.Socket.write(dataBytes);
      written = dataBytes.length;
    } else if (fileEntry.FileHandle > 0) {
      written = fs.writeSync(fileEntry.FileHandle, dataBytes, 0, dataBytes.length, offset);
    }

    const respParams = new smb.SMBWriteResponse_Parameters();
    respParams.set('Count', written);
    respSMBCommand.set('Parameters', respParams.getData());

    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComFlush(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_FLUSH;
    respSMBCommand.set('Parameters', Buffer.alloc(0));

    const flushParams = new smb.SMBFlush_Parameters();
    flushParams.fromString((SMBCommand_ as Structure).get('Parameters') as Buffer);
    const fid = (flushParams.get('FID') as number).toString();

    if (connData.OpenedFiles[fid]) {
      const fh = connData.OpenedFiles[fid]!.FileHandle;
      if (fh > 0) {
        try { fs.fsyncSync(fh); } catch { /* ignore */ }
      }
    }

    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComCreateDirectory(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_CREATE_DIRECTORY;
    respSMBCommand.set('Parameters', Buffer.alloc(0));

    const createDirData = new smb.SMBCreateDirectory_Data();
    createDirData.fromString((SMBCommand_ as Structure).get('Data') as Buffer);

    const flags2 = (recvPacket as Structure).get('Flags2') as number;
    const dirName = decodeSMBString(flags2, createDirData.get('DirectoryName') as Buffer);

    const tid = (recvPacket as Structure).get('Tid') as number;
    const share = connData.ConnectedShares[tid];
    if (!share) return [[respSMBCommand], null, STATUS_SMB_BAD_TID];

    const sharePath = share['path'] || '';
    const normalized = normalizePath(dirName);
    const fullPath = path.join(sharePath, normalized);

    try {
      fs.mkdirSync(fullPath, { recursive: true });
    } catch {
      return [[respSMBCommand], null, STATUS_ACCESS_DENIED];
    }

    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComRename(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_RENAME;
    respSMBCommand.set('Parameters', Buffer.alloc(0));

    const renameData = new smb.SMBRename_Data();
    renameData.fromString((SMBCommand_ as Structure).get('Data') as Buffer);

    const flags2 = (recvPacket as Structure).get('Flags2') as number;
    const oldName = decodeSMBString(flags2, renameData.get('OldFileName') as Buffer);
    const newName = decodeSMBString(flags2, renameData.get('NewFileName') as Buffer);

    const tid = (recvPacket as Structure).get('Tid') as number;
    const share = connData.ConnectedShares[tid];
    if (!share) return [[respSMBCommand], null, STATUS_SMB_BAD_TID];

    const sharePath = share['path'] || '';
    const oldPath = path.join(sharePath, normalizePath(oldName));
    const newPath = path.join(sharePath, normalizePath(newName));

    try {
      fs.renameSync(oldPath, newPath);
    } catch {
      return [[respSMBCommand], null, STATUS_ACCESS_DENIED];
    }

    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComDelete(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_DELETE;
    respSMBCommand.set('Parameters', Buffer.alloc(0));

    const deleteData = new smb.SMBDelete_Data();
    deleteData.fromString((SMBCommand_ as Structure).get('Data') as Buffer);

    const flags2 = (recvPacket as Structure).get('Flags2') as number;
    const fileName = decodeSMBString(flags2, deleteData.get('FileName') as Buffer);

    const tid = (recvPacket as Structure).get('Tid') as number;
    const share = connData.ConnectedShares[tid];
    if (!share) return [[respSMBCommand], null, STATUS_SMB_BAD_TID];

    const sharePath = share['path'] || '';
    const fullPath = path.join(sharePath, normalizePath(fileName));

    try {
      fs.unlinkSync(fullPath);
    } catch {
      return [[respSMBCommand], null, STATUS_ACCESS_DENIED];
    }

    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComDeleteDirectory(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_DELETE_DIRECTORY;
    respSMBCommand.set('Parameters', Buffer.alloc(0));

    const deleteData = new smb.SMBDeleteDirectory_Data();
    deleteData.fromString((SMBCommand_ as Structure).get('Data') as Buffer);

    const flags2 = (recvPacket as Structure).get('Flags2') as number;
    const dirName = decodeSMBString(flags2, deleteData.get('DirectoryName') as Buffer);

    const tid = (recvPacket as Structure).get('Tid') as number;
    const share = connData.ConnectedShares[tid];
    if (!share) return [[respSMBCommand], null, STATUS_SMB_BAD_TID];

    const sharePath = share['path'] || '';
    const fullPath = path.join(sharePath, normalizePath(dirName));

    try {
      fs.rmdirSync(fullPath);
    } catch (e: any) {
      if (e?.code === 'ENOTEMPTY') {
        return [[respSMBCommand], null, STATUS_DIRECTORY_NOT_EMPTY];
      }
      return [[respSMBCommand], null, STATUS_ACCESS_DENIED];
    }

    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComWriteAndX(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_WRITE_ANDX;

    const writeParams = new smb.SMBWriteAndX_Parameters();
    writeParams.fromString((SMBCommand_ as Structure).get('Parameters') as Buffer);
    const fid = (writeParams.get('Fid') as number).toString();
    let offset = writeParams.get('Offset') as number;
    const highOffset = writeParams.get('HighOffset') as number;
    if (highOffset > 0) offset = (highOffset * 0x100000000) + offset;

    if (!connData.OpenedFiles[fid]) {
      return [[respSMBCommand], null, STATUS_INVALID_HANDLE];
    }

    const fileEntry = connData.OpenedFiles[fid]!;
    const writeData = new smb.SMBWriteAndX_Data();
    writeData.fromString((SMBCommand_ as Structure).get('Data') as Buffer);
    const dataBytes = writeData.get('Pad1') as Buffer;

    let written = 0;
    if (fileEntry.FileHandle === PIPE_FILE_DESCRIPTOR && fileEntry.Socket) {
      fileEntry.Socket.write(dataBytes);
      written = dataBytes.length;
    } else if (fileEntry.FileHandle > 0) {
      written = fs.writeSync(fileEntry.FileHandle, dataBytes, 0, dataBytes.length, offset);
    }

    const respParams = new smb.SMBWriteAndXResponse_Parameters();
    respParams.set('Count', written);
    respParams.set('Available', 0);
    respSMBCommand.set('Parameters', respParams.getData());

    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComRead(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_READ;

    const readParams = new smb.SMBRead_Parameters();
    readParams.fromString((SMBCommand_ as Structure).get('Parameters') as Buffer);
    const fid = (readParams.get('Fid') as number).toString();
    const count = readParams.get('Count') as number;
    const offset = readParams.get('Offset') as number;

    if (!connData.OpenedFiles[fid]) {
      return [[respSMBCommand], null, STATUS_INVALID_HANDLE];
    }

    const fileEntry = connData.OpenedFiles[fid]!;
    let data: Buffer;

    if (fileEntry.FileHandle === PIPE_FILE_DESCRIPTOR && fileEntry.Socket) {
      data = Buffer.alloc(0);
    } else if (fileEntry.FileHandle > 0) {
      data = Buffer.alloc(count);
      const bytesRead = fs.readSync(fileEntry.FileHandle, data, 0, count, offset);
      data = data.subarray(0, bytesRead);
    } else {
      data = Buffer.alloc(0);
    }

    const respParams = new smb.SMBReadResponse_Parameters();
    respParams.set('Count', data.length);
    respSMBCommand.set('Parameters', respParams.getData());

    const respData = new smb.SMBReadResponse_Data();
    respData.set('Data', data);
    respSMBCommand.set('Data', respData.getData());

    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComReadAndX(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_READ_ANDX;

    const readParams = new smb.SMBReadAndX_Parameters();
    readParams.fromString((SMBCommand_ as Structure).get('Parameters') as Buffer);
    const fid = (readParams.get('Fid') as number).toString();
    const count = readParams.get('MaxCount') as number;
    let offset = readParams.get('Offset') as number;
    if (readParams.has('HighOffset')) {
      const highOffset = readParams.get('HighOffset') as number;
      if (highOffset > 0) offset = (highOffset * 0x100000000) + offset;
    }

    if (!connData.OpenedFiles[fid]) {
      return [[respSMBCommand], null, STATUS_INVALID_HANDLE];
    }

    const fileEntry = connData.OpenedFiles[fid]!;
    let data: Buffer;

    if (fileEntry.FileHandle === PIPE_FILE_DESCRIPTOR && fileEntry.Socket) {
      data = Buffer.alloc(0);
    } else if (fileEntry.FileHandle > 0) {
      data = Buffer.alloc(count);
      const bytesRead = fs.readSync(fileEntry.FileHandle, data, 0, count, offset);
      data = data.subarray(0, bytesRead);
    } else {
      data = Buffer.alloc(0);
    }

    const respParams = new smb.SMBReadAndXResponse_Parameters();
    respParams.set('Remaining', 0xffff);
    respParams.set('DataCount', data.length);
    respParams.set('DataOffset', 0);
    respParams.set('DataCount_Hi', 0);
    respSMBCommand.set('Parameters', respParams.getData());
    respSMBCommand.set('Data', Buffer.concat([Buffer.alloc(1), data]));

    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbQueryInformation(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_QUERY_INFORMATION;

    const queryData = new smb.SMBQueryInformation_Data();
    queryData.fromString((SMBCommand_ as Structure).get('Data') as Buffer);
    const flags2 = (recvPacket as Structure).get('Flags2') as number;
    const pathStr = decodeSMBString(flags2, queryData.get('FileName') as Buffer);

    const tid = (recvPacket as Structure).get('Tid') as number;
    const share = connData.ConnectedShares[tid];
    if (!share) return [[respSMBCommand], null, STATUS_SMB_BAD_TID];

    const sharePath = share['path'] || '.';
    try {
      const result = queryFsInformation(sharePath, pathStr);
      if (Array.isArray(result)) {
        const [fileSize, lastWriteTime, fileAttributes] = result;
        const respParams = new smb.SMBQueryInformationResponse_Parameters();
        respParams.set('FileAttributes', fileAttributes);
        respParams.set('LastWriteTime', lastWriteTime);
        respParams.set('FileSize', fileSize);
        respSMBCommand.set('Parameters', respParams.getData());
        return [[respSMBCommand], null, STATUS_SUCCESS];
      }
    } catch {
      return [[respSMBCommand], null, STATUS_NO_SUCH_FILE];
    }

    return [[respSMBCommand], null, STATUS_NO_SUCH_FILE];
  }

  static smbQueryInformationDisk(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_QUERY_INFORMATION_DISK;

    const respParams = new smb.SMBQueryInformationDiskResponse_Parameters();
    respParams.set('TotalUnits', 65535);
    respParams.set('BlocksPerUnit', 1);
    respParams.set('BlockSize', 512);
    respParams.set('FreeUnits', 65535);
    respSMBCommand.set('Parameters', respParams.getData());

    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComEcho(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_ECHO;

    const echoData = new smb.SMBEcho_Data();
    echoData.fromString((SMBCommand_ as Structure).get('Data') as Buffer);

    const respParams = new smb.SMBEchoResponse_Parameters();
    respParams.set('SequenceNumber', 1);
    respSMBCommand.set('Parameters', respParams.getData());

    const respData = new smb.SMBEchoResponse_Data();
    respData.set('Data', echoData.get('Data') as Buffer);
    respSMBCommand.set('Data', respData.getData());

    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComTreeDisconnect(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_TREE_DISCONNECT;
    respSMBCommand.set('Parameters', Buffer.alloc(0));

    const tid = (recvPacket as Structure).get('Tid') as number;
    delete connData.ConnectedShares[tid];
    smbServer.setConnectionData(connId, connData);

    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComLogOffAndX(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_LOGOFF_ANDX;
    respSMBCommand.set('Parameters', Buffer.alloc(4));

    connData.Uid = 0;
    connData.Authenticated = false;
    smbServer.setConnectionData(connId, connData);

    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComQueryInformation2(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_QUERY_INFORMATION2;

    const queryParams = new smb.SMBQueryInformation2_Parameters();
    queryParams.fromString((SMBCommand_ as Structure).get('Parameters') as Buffer);
    const fid = (queryParams.get('Fid') as number).toString();

    if (!connData.OpenedFiles[fid]) {
      return [[respSMBCommand], null, STATUS_INVALID_HANDLE];
    }

    const fileEntry = connData.OpenedFiles[fid]!;
    const stat = fs.fstatSync(fileEntry.FileHandle > 0 ? fileEntry.FileHandle : 0);

    const respParams = new smb.SMBQueryInformation2Response_Parameters();
    respParams.set('CreateDate', getSMBDate(Math.floor(stat.ctimeMs / 1000)));
    respParams.set('CreateTime', getSMBTime(Math.floor(stat.ctimeMs / 1000)));
    respParams.set('LastAccessDate', getSMBDate(Math.floor(stat.atimeMs / 1000)));
    respParams.set('LastAccessTime', getSMBTime(Math.floor(stat.atimeMs / 1000)));
    respParams.set('LastWriteDate', getSMBDate(Math.floor(stat.mtimeMs / 1000)));
    respParams.set('LastWriteTime', getSMBTime(Math.floor(stat.mtimeMs / 1000)));
    respParams.set('FileDataSize', stat.size);
    respParams.set('FileAllocationSize', stat.size);
    respParams.set('FileAttributes', stat.isDirectory() ? smb.ATTR_DIRECTORY : smb.ATTR_NORMAL);
    respSMBCommand.set('Parameters', respParams.getData());

    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComNtCreateAndX(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_NT_CREATE_ANDX;

    const ntCreateParams = new smb.SMBNtCreateAndX_Parameters();
    ntCreateParams.fromString((SMBCommand_ as Structure).get('Parameters') as Buffer);
    const ntCreateData = new smb.SMBNtCreateAndX_Data();
    ntCreateData.fromString((SMBCommand_ as Structure).get('Data') as Buffer);

    const flags2 = (recvPacket as Structure).get('Flags2') as number;
    const tid = (recvPacket as Structure).get('Tid') as number;
    const share = connData.ConnectedShares[tid];
    if (!share) return [[respSMBCommand], null, STATUS_SMB_BAD_TID];

    const sharePath = share['path'] || '';
    const createDisposition = ntCreateParams.get('Disposition') as number;
    const createOptions = ntCreateParams.get('CreateOptions') as number;
    const desiredAccess = ntCreateParams.get('AccessMask') as number;

    let pathStr = decodeSMBString(flags2, ntCreateData.get('FileName') as Buffer);
    if (pathStr === '' || pathStr === '\\') pathStr = '';

    const registeredPipes = smbServer.getRegisteredNamedPipes();
    const pipeKey = Object.keys(registeredPipes).find(
      k => pathStr.replace(/\\/g, '/').toLowerCase().endsWith(k.replace(/\\/g, '/').toLowerCase()),
    );

    if (pipeKey) {
      const pipeAddr = registeredPipes[pipeKey]!;
      const sock = new net.Socket();
      try {
        sock.connect({ host: pipeAddr[0], port: pipeAddr[1] });
      } catch {
        return [[respSMBCommand], null, STATUS_OBJECT_NAME_NOT_FOUND];
      }

      const fid = Math.floor(Math.random() * 0xfffe) + 1;
      connData.OpenedFiles[fid.toString()] = {
        FileHandle: PIPE_FILE_DESCRIPTOR,
        FileName: pathStr,
        DeleteOnClose: false,
        Socket: sock,
      };

      const respParams = new smb.SMBNtCreateAndXResponse_Parameters();
      respParams.set('Fid', fid);
      respParams.set('CreateAction', smb.FILE_OPEN);
      respParams.set('CreationTime', smb.POSIXtoFT(Math.floor(Date.now() / 1000)));
      respParams.set('LastAccessTime', smb.POSIXtoFT(Math.floor(Date.now() / 1000)));
      respParams.set('LastWriteTime', smb.POSIXtoFT(Math.floor(Date.now() / 1000)));
      respParams.set('LastChangeTime', smb.POSIXtoFT(Math.floor(Date.now() / 1000)));
      respParams.set('FileAttributes', 0x80);
      respParams.set('AllocationSize', 4096);
      respParams.set('EndOfFile', 0);
      respParams.set('FileType', 2);
      respParams.set('IPCState', 0x05ff);
      respParams.set('IsDirectory', 0);
      respSMBCommand.set('Parameters', respParams.getData());
      smbServer.setConnectionData(connId, connData);
      return [[respSMBCommand], null, STATUS_SUCCESS];
    }

    const normalized = normalizePath(pathStr);
    const fullPath = path.join(sharePath, normalized);

    if (!isInFileJail(sharePath, normalized)) {
      return [[respSMBCommand], null, STATUS_OBJECT_PATH_SYNTAX_BAD];
    }

    let fh: number;
    let action: number;
    const exists = fs.existsSync(fullPath);
    const isDir = exists && fs.statSync(fullPath).isDirectory();

    if (createOptions & smb.FILE_DIRECTORY_FILE) {
      if (createDisposition === smb.FILE_CREATE) {
        if (exists) return [[respSMBCommand], null, STATUS_OBJECT_NAME_COLLISION];
        fs.mkdirSync(fullPath, { recursive: true });
        action = smb.FILE_CREATE;
      } else if (createDisposition === smb.FILE_OPEN_IF) {
        if (!exists) {
          fs.mkdirSync(fullPath, { recursive: true });
          action = smb.FILE_CREATE;
        } else {
          action = smb.FILE_OPEN;
        }
      } else {
        if (!exists) return [[respSMBCommand], null, STATUS_OBJECT_PATH_NOT_FOUND];
        action = smb.FILE_OPEN;
      }
      fh = VOID_FILE_DESCRIPTOR;
    } else {
      if (createDisposition === smb.FILE_SUPERSEDE) {
        if (exists) {
          try { fs.unlinkSync(fullPath); } catch { /* ignore */ }
        }
        fh = fs.openSync(fullPath, fs.constants.O_CREAT | fs.constants.O_RDWR);
        action = smb.FILE_SUPERSEDE;
      } else if (createDisposition === smb.FILE_OVERWRITE_IF) {
        fh = fs.openSync(fullPath, fs.constants.O_CREAT | fs.constants.O_RDWR | fs.constants.O_TRUNC);
        action = exists ? smb.FILE_OVERWRITE : smb.FILE_CREATE;
      } else if (createDisposition === smb.FILE_OVERWRITE) {
        if (!exists) return [[respSMBCommand], null, STATUS_NO_SUCH_FILE];
        fh = fs.openSync(fullPath, fs.constants.O_RDWR | fs.constants.O_TRUNC);
        action = smb.FILE_OVERWRITE;
      } else if (createDisposition === smb.FILE_OPEN_IF) {
        const flags = exists ? fs.constants.O_RDWR : fs.constants.O_CREAT | fs.constants.O_RDWR;
        fh = fs.openSync(fullPath, flags);
        action = exists ? smb.FILE_OPEN : smb.FILE_CREATE;
      } else if (createDisposition === smb.FILE_CREATE) {
        if (exists) return [[respSMBCommand], null, STATUS_OBJECT_NAME_COLLISION];
        fh = fs.openSync(fullPath, fs.constants.O_CREAT | fs.constants.O_RDWR);
        action = smb.FILE_CREATE;
      } else {
        if (!exists) return [[respSMBCommand], null, STATUS_NO_SUCH_FILE];
        if (isDir) {
          fh = VOID_FILE_DESCRIPTOR;
        } else {
          const flags = (desiredAccess & smb.FILE_WRITE_DATA) ? fs.constants.O_RDWR : fs.constants.O_RDONLY;
          fh = fs.openSync(fullPath, flags);
        }
        action = smb.FILE_OPEN;
      }
    }

    const fid = Math.floor(Math.random() * 0xfffe) + 1;
    const deleteOnClose = !!(createOptions & smb.FILE_DELETE_ON_CLOSE);

    connData.OpenedFiles[fid.toString()] = {
      FileHandle: fh,
      FileName: fullPath,
      DeleteOnClose: deleteOnClose,
    };

    let stat: fs.Stats;
    try {
      stat = fs.statSync(fullPath);
    } catch {
      stat = { size: 0, atimeMs: Date.now(), mtimeMs: Date.now(), ctimeMs: Date.now(), isDirectory: () => false } as any;
    }

    const respParams = new smb.SMBNtCreateAndXResponse_Parameters();
    respParams.set('Fid', fid);
    respParams.set('CreateAction', action);
    respParams.set('CreationTime', smb.POSIXtoFT(Math.floor(stat.ctimeMs / 1000)));
    respParams.set('LastAccessTime', smb.POSIXtoFT(Math.floor(stat.atimeMs / 1000)));
    respParams.set('LastWriteTime', smb.POSIXtoFT(Math.floor(stat.mtimeMs / 1000)));
    respParams.set('LastChangeTime', smb.POSIXtoFT(Math.floor(stat.mtimeMs / 1000)));
    respParams.set('FileAttributes', stat.isDirectory() ? smb.ATTR_DIRECTORY : smb.ATTR_NORMAL | smb.ATTR_ARCHIVE);
    respParams.set('AllocationSize', stat.size);
    respParams.set('EndOfFile', stat.size);
    respParams.set('FileType', 0);
    respParams.set('IPCState', 0);
    respParams.set('IsDirectory', stat.isDirectory() ? 1 : 0);
    respSMBCommand.set('Parameters', respParams.getData());

    smbServer.setConnectionData(connId, connData);
    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComOpenAndX(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_OPEN_ANDX;

    const openParams = new smb.SMBOpenAndX_Parameters();
    openParams.fromString((SMBCommand_ as Structure).get('Parameters') as Buffer);
    const openData = new smb.SMBOpenAndX_Data();
    openData.fromString((SMBCommand_ as Structure).get('Data') as Buffer);

    const flags2 = (recvPacket as Structure).get('Flags2') as number;
    const tid = (recvPacket as Structure).get('Tid') as number;
    const share = connData.ConnectedShares[tid];
    if (!share) return [[respSMBCommand], null, STATUS_SMB_BAD_TID];

    const sharePath = share['path'] || '';
    const pathStr = decodeSMBString(flags2, openData.get('FileName') as Buffer);
    const accessMode = openParams.get('AccessMode') as number;
    const fileAttributes = openParams.get('FileAttributes') as number;
    const openMode = openParams.get('OpenMode') as number;

    const [fid, mode, pathName, errorCode] = openFile(sharePath, pathStr, accessMode, fileAttributes, openMode);
    if (errorCode !== 0) {
      return [[respSMBCommand], null, errorCode];
    }

    connData.OpenedFiles[fid.toString()] = {
      FileHandle: fid,
      FileName: pathName,
      DeleteOnClose: false,
    };

    let stat: fs.Stats;
    try { stat = fs.statSync(pathName); } catch { stat = { size: 0 } as any; }

    const respParams = new smb.SMBOpenAndXResponse_Parameters();
    respParams.set('Fid', fid);
    respParams.set('FileAttributes', fileAttributes);
    respParams.set('LastWriteTime', Math.floor((stat.mtimeMs || Date.now()) / 1000));
    respParams.set('FileSize', stat.size || 0);
    respParams.set('GrantedAccess', accessMode);
    respParams.set('FileType', 0);
    respParams.set('IPCState', 0);
    respParams.set('Action', mode);
    respParams.set('ServerFid', 0);
    respSMBCommand.set('Parameters', respParams.getData());

    smbServer.setConnectionData(connId, connData);
    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComTreeConnectAndX(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const flags2 = (recvPacket as Structure).get('Flags2') as number;

    const treeConnectData = new smb.SMBTreeConnectAndX_Data();
    treeConnectData.fromString((SMBCommand_ as Structure).get('Data') as Buffer);

    let pathStr = decodeSMBString(flags2, treeConnectData.get('Path') as Buffer);
    if (pathStr.includes('\x00')) pathStr = pathStr.split('\x00')[0]!;

    const parts = pathStr.replace(/\\/g, '/').split('/');
    const shareName = parts[parts.length - 1] || '';

    const shareInfo = searchShare(connId, shareName, smbServer);
    if (!shareInfo) {
      console.warn(`SMBServer: share not found: ${shareName}`);
      return [[], null, STATUS_OBJECT_PATH_NOT_FOUND];
    }

    const tid = Math.floor(Math.random() * 0xfffe) + 1;
    connData.ConnectedShares[tid] = { ...shareInfo, shareName };

    const respPacket = new smb.NewSMBPacket();
    respPacket.set('Flags1', smb.FLAGS1_REPLY | smb.FLAGS1_PATHCASELESS);
    respPacket.set('Flags2', smb.FLAGS2_EXTENDED_SECURITY | smb.FLAGS2_NT_STATUS | smb.FLAGS2_LONG_NAMES | smb.FLAGS2_UNICODE);
    respPacket.set('Tid', tid);
    respPacket.set('Mid', (recvPacket as Structure).get('Mid') as number);
    respPacket.set('Uid', connData.Uid);
    respPacket.set('Pid', (recvPacket as Structure).get('Pid') as number);

    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_TREE_CONNECT_ANDX;

    const shareType = parseInt(shareInfo['share type'] || '0', 10);

    if (flags2 & smb.FLAGS2_EXTENDED_SECURITY) {
      const respParams = new smb.SMBTreeConnectAndXExtendedResponse_Parameters();
      respParams.set('OptionalSupport', smb.SMB_SHARE_IS_IN_DFS);
      respSMBCommand.set('Parameters', respParams.getData());
    } else {
      const respParams = new smb.SMBTreeConnectAndXResponse_Parameters();
      respParams.set('OptionalSupport', smb.SMB_SHARE_IS_IN_DFS);
      respSMBCommand.set('Parameters', respParams.getData());
    }

    const respData = new smb.SMBTreeConnectAndXResponse_Data();
    if (shareType === 3) {
      respData.set('Service', Buffer.from('IPC\x00', 'ascii'));
      respData.set('NativeFileSystem', Buffer.alloc(0));
    } else {
      respData.set('Service', Buffer.from('A:\x00', 'ascii'));
      respData.set('NativeFileSystem', encodeSMBString(flags2, 'NTFS'));
    }
    respSMBCommand.set('Data', respData.getData());

    respPacket.addCommand(respSMBCommand);

    if (connData.SignatureEnabled) {
      smbServer.signSMBv1(connData, respPacket, connData.SigningSessionKey, connData.SigningChallengeResponse);
    }

    smbServer.setConnectionData(connId, connData);
    return [[], respPacket, STATUS_SUCCESS];
  }

  static smbComSessionSetupAndX(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId, false);
    const flags2 = (recvPacket as Structure).get('Flags2') as number;

    if (flags2 & smb.FLAGS2_EXTENDED_SECURITY) {
      return SMBCommands.smbComSessionSetupAndXExtended(connId, smbServer, SMBCommand_, recvPacket);
    }

    return SMBCommands.smbComSessionSetupAndXBasic(connId, smbServer, SMBCommand_, recvPacket);
  }

  static smbComSessionSetupAndXBasic(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId, false);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_SESSION_SETUP;

    connData.Uid = 10;
    connData.Authenticated = true;

    const respParams = new smb.SMBSessionSetupAndXResponse_Parameters();
    respParams.set('Action', 0);
    respSMBCommand.set('Parameters', respParams.getData());

    const respData = new smb.SMBSessionSetupAndXResponse_Data();
    respData.set('NativeOS', encodeSMBString(smb.FLAGS2_UNICODE, smbServer.getServerOS()));
    respData.set('NativeLanMan', encodeSMBString(smb.FLAGS2_UNICODE, 'Samba'));
    respSMBCommand.set('Data', respData.getData());

    smbServer.setConnectionData(connId, connData);
    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static smbComSessionSetupAndXExtended(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId, false);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_SESSION_SETUP;

    const sessionSetupParams = new smb.SMBSessionSetupAndX_Extended_Parameters();
    sessionSetupParams.fromString((SMBCommand_ as Structure).get('Parameters') as Buffer);

    const sessionSetupData = new smb.SMBSessionSetupAndX_Extended_Data();
    sessionSetupData.fromString((SMBCommand_ as Structure).get('Data') as Buffer);

    const securityBlob = sessionSetupData.get('SecurityBlob') as Buffer;

    let rawNTLM = false;
    let ntlmData: Buffer;

    if (securityBlob[0] === spnego.ASN1_AID) {
      const negTokenInit = new spnego.SPNEGO_NegTokenInit();
      negTokenInit.fromString(securityBlob);
      ntlmData = negTokenInit.fields['MechToken'] as Buffer || Buffer.alloc(0);
    } else if (securityBlob[0] === spnego.ASN1_SUPPORTED_MECH) {
      const negTokenResp = new spnego.SPNEGO_NegTokenResp();
      negTokenResp.fromString(securityBlob);
      ntlmData = negTokenResp.fields['ResponseToken'] as Buffer || Buffer.alloc(0);
    } else {
      ntlmData = securityBlob;
      rawNTLM = true;
    }

    if (ntlmData.length < 12) {
      return [[respSMBCommand], null, STATUS_LOGON_FAILURE];
    }

    const messageType = ntlmData.readUInt32LE(8);

    if (messageType === ntlm.NTLMSSP_AUTH_NEGOTIATE) {
      const negotiateMessage = new ntlm.NTLMAuthNegotiate();
      negotiateMessage.fromString(ntlmData);
      connData.NEGOTIATE_MESSAGE = negotiateMessage;

      const challengeMessage = new ntlm.NTLMAuthChallenge();

      let challengeFlags = ntlm.NTLMSSP_NEGOTIATE_128 |
        ntlm.NTLMSSP_NEGOTIATE_56 |
        ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH |
        ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
        ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO |
        ntlm.NTLMSSP_NEGOTIATE_NTLM |
        ntlm.NTLMSSP_NEGOTIATE_SEAL |
        ntlm.NTLMSSP_NEGOTIATE_SIGN |
        ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
        ntlm.NTLMSSP_NEGOTIATE_UNICODE |
        ntlm.NTLMSSP_REQUEST_TARGET;

      const serverName = smbServer.getServerName();
      const serverDomain = smbServer.getServerDomain();
      const challenge = smbServer.getSMBChallenge();

      const avPairs = new ntlm.AV_PAIRS();
      avPairs.set(ntlm.NTLMSSP_AV_HOSTNAME, Buffer.from(serverName, 'utf16le'));
      avPairs.set(ntlm.NTLMSSP_AV_DOMAINNAME, Buffer.from(serverDomain, 'utf16le'));
      avPairs.set(ntlm.NTLMSSP_AV_DNS_HOSTNAME, Buffer.from(serverName, 'utf16le'));
      avPairs.set(ntlm.NTLMSSP_AV_DNS_DOMAINNAME, Buffer.from(serverDomain, 'utf16le'));
      const now = BigInt(Date.now()) * BigInt(10000) + BigInt(116444736000000000);
      const timeBuf = Buffer.alloc(8);
      timeBuf.writeBigUInt64LE(now);
      avPairs.set(ntlm.NTLMSSP_AV_TIME, timeBuf);
      avPairs.set(ntlm.NTLMSSP_AV_EOL, Buffer.alloc(0));

      challengeMessage.set('flags', challengeFlags);
      challengeMessage.set('challenge', challenge);
      challengeMessage.set('domain_name', Buffer.from(serverDomain, 'utf16le'));
      challengeMessage.set('TargetInfoFields', avPairs.getData());

      connData.CHALLENGE_MESSAGE = challengeMessage;

      let responseToken: Buffer;
      if (rawNTLM) {
        responseToken = challengeMessage.getData();
      } else {
        const negTokenResp = new spnego.SPNEGO_NegTokenResp();
        negTokenResp.fields['NegState'] = Buffer.from([0x01]);
        negTokenResp.fields['SupportedMech'] = spnego.TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']!;
        negTokenResp.fields['ResponseToken'] = challengeMessage.getData();
        responseToken = negTokenResp.getData();
      }

      const respParams = new smb.SMBSessionSetupAndX_Extended_Response_Parameters();
      respParams.set('Action', 0);
      respParams.set('SecurityBlobLength', responseToken.length);
      respSMBCommand.set('Parameters', respParams.getData());

      const respData = new smb.SMBSessionSetupAndX_Extended_Response_Data();
      respData.set('SecurityBlob', responseToken);
      respData.set('NativeOS', encodeSMBString(smb.FLAGS2_UNICODE, smbServer.getServerOS()));
      respData.set('NativeLanMan', encodeSMBString(smb.FLAGS2_UNICODE, 'Samba'));
      respSMBCommand.set('Data', respData.getData());

      smbServer.setConnectionData(connId, connData);
      return [[respSMBCommand], null, STATUS_MORE_PROCESSING_REQUIRED];
    }

    if (messageType === ntlm.NTLMSSP_AUTH_CHALLENGE_RESPONSE) {
      const authenticateMessage = new ntlm.NTLMAuthChallengeResponse();
      authenticateMessage.fromString(ntlmData);
      connData.AUTHENTICATE_MESSAGE = authenticateMessage;

      const credentials = smbServer.getCredentials();
      const challenge = smbServer.getSMBChallenge();

      let errorCode = STATUS_SUCCESS;
      let exportedSessionKey: Buffer = Buffer.alloc(16);

      const userName = authenticateMessage.getUserString();
      const userNameLower = userName.toLowerCase();

      if (Object.keys(credentials).length > 0) {
        const cred = credentials[userNameLower];
        if (cred) {
          [errorCode, exportedSessionKey] = computeNTLMv2(
            userName, cred.lmhash, cred.nthash,
            challenge, authenticateMessage,
            connData.CHALLENGE_MESSAGE, connData.NEGOTIATE_MESSAGE,
          );
        } else {
          errorCode = STATUS_LOGON_FAILURE;
        }
      }

      if (errorCode === STATUS_SUCCESS) {
        connData.Uid = 10;
        connData.Authenticated = true;
        connData.SigningSessionKey = exportedSessionKey;

        const authCallback = smbServer.getAuthCallback();
        if (authCallback) {
          authCallback(smbServer, connData);
        }

        if (smbServer.getDumpHashes()) {
          const ntResponse = authenticateMessage.get('ntlm') as Buffer;
          const lmResponse = authenticateMessage.get('lanman') as Buffer;
          const domain = authenticateMessage.get('domain_name') as Buffer;
          const user = authenticateMessage.get('user_name') as Buffer;
          const jtrData = outputToJohnFormat(challenge, user, domain, lmResponse, ntResponse);
          if (jtrData) {
            console.debug(`[*] ${jtrData.hash_string}`);
            const jtrPath = smbServer.getJTRdumpPath();
            if (jtrPath) {
              writeJohnOutputToFile(jtrData.hash_string, jtrData.hash_version, jtrPath);
            }
          }
        }
      }

      let responseToken: Buffer;
      if (rawNTLM) {
        responseToken = Buffer.alloc(0);
      } else {
        const negTokenResp = new spnego.SPNEGO_NegTokenResp();
        negTokenResp.fields['NegState'] = Buffer.from([errorCode === STATUS_SUCCESS ? 0x00 : 0x02]);
        responseToken = negTokenResp.getData();
      }

      const respParams = new smb.SMBSessionSetupAndX_Extended_Response_Parameters();
      respParams.set('Action', 0);
      respParams.set('SecurityBlobLength', responseToken.length);
      respSMBCommand.set('Parameters', respParams.getData());

      const respData = new smb.SMBSessionSetupAndX_Extended_Response_Data();
      respData.set('SecurityBlob', responseToken);
      respData.set('NativeOS', encodeSMBString(smb.FLAGS2_UNICODE, smbServer.getServerOS()));
      respData.set('NativeLanMan', encodeSMBString(smb.FLAGS2_UNICODE, 'Samba'));
      respSMBCommand.set('Data', respData.getData());

      smbServer.setConnectionData(connId, connData);
      return [[respSMBCommand], null, errorCode];
    }

    return [[respSMBCommand], null, STATUS_LOGON_FAILURE];
  }

  static smbComNegotiate(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId, false);
    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_NEGOTIATE;

    const smb2Support = smbServer.getSMB2Support();
    const flags2 = (recvPacket as Structure).get('Flags2') as number;

    if (smb2Support) {
      return SMB2Commands.smb2Negotiate(connId, smbServer, recvPacket, true);
    }

    const negotiateData = (SMBCommand_ as Structure).get('Data') as Buffer;
    let dialectIndex = 0;
    let dialects: string[] = [];

    let offset = 0;
    while (offset < negotiateData.length) {
      if (negotiateData[offset] === 0x02) {
        offset++;
        const end = negotiateData.indexOf(0x00, offset);
        if (end >= 0) {
          dialects.push(negotiateData.subarray(offset, end).toString('ascii'));
          offset = end + 1;
        } else {
          break;
        }
      } else {
        offset++;
      }
    }

    const ntlmDialectIdx = dialects.indexOf('NT LM 0.12');
    if (ntlmDialectIdx < 0) {
      return [[], null, STATUS_NOT_SUPPORTED];
    }
    dialectIndex = ntlmDialectIdx;

    const respParams = new smb.SMBNTLMDialect_Parameters();
    respParams.set('DialectIndex', dialectIndex);
    respParams.set('SecurityMode', smb.NEGOTIATE_USER_SECURITY | smb.NEGOTIATE_ENCRYPT_PASSWORDS);
    respParams.set('MaxMpxCount', 1);
    respParams.set('MaxNumberVcs', 1);
    respParams.set('MaxBufferSize', 64000);
    respParams.set('MaxRawSize', 65536);
    respParams.set('SessionKey', 0);
    respParams.set('LowDateTime', 0);
    respParams.set('HighDateTime', 0);
    respParams.set('ServerTimeZone', 0);
    respParams.set('ChallengeLength', 0);

    let capabilities = smb.CAP_UNICODE | smb.CAP_LARGE_FILES | smb.CAP_NT_SMBS |
      smb.CAP_STATUS32 | smb.CAP_LARGE_READX | smb.CAP_LARGE_WRITEX;

    const config = smbServer.getServerConfig();
    if (config.hasOption('global', 'rpc_apis') && config.getboolean('global', 'rpc_apis')) {
      capabilities |= smb.CAP_RPC_REMOTE_APIS;
    }

    capabilities |= smb.CAP_EXTENDED_SECURITY;
    respParams.set('Capabilities', capabilities);

    const respData = new smb.SMBNTLMDialect_Data_ExtSec();
    const serverGuid = crypto.randomBytes(16);
    respData.set('ServerGUID', serverGuid);

    const negTokenInit = new spnego.SPNEGO_NegTokenInit();
    negTokenInit.fields['MechTypes'] = Buffer.concat([
      spnego.TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']!,
    ]);
    respData.set('SecurityBlob', negTokenInit.getData());

    respSMBCommand.set('Parameters', respParams.getData());
    respSMBCommand.set('Data', respData.getData());

    connData._dialects_parameters = respParams;
    connData._dialects_data = respData;
    smbServer.setConnectionData(connId, connData);

    return [[respSMBCommand], null, STATUS_SUCCESS];
  }

  static default(
    connId: string, smbServer: SMBSERVER, SMBCommand_: any, recvPacket: any,
  ): [any[], any | null, number] {
    return [[], null, STATUS_NOT_IMPLEMENTED];
  }
}

class SMB2Commands {
  static smb2Negotiate(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
    isSMB1: boolean = false,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId, false);

    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Status', STATUS_SUCCESS);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('Command', smb2.SMB2_NEGOTIATE);
    respPacket.set('SessionID', 0);

    const respNeg = new smb2.SMB2Negotiate_Response();
    respNeg.set('SecurityMode', smb2.SMB2_NEGOTIATE_SIGNING_ENABLED);
    respNeg.set('DialectRevision', smb2.SMB2_DIALECT_002);
    respNeg.set('ServerGuid', crypto.randomBytes(16));
    respNeg.set('Capabilities', 0);
    respNeg.set('MaxTransactSize', 65536);
    respNeg.set('MaxReadSize', 65536);
    respNeg.set('MaxWriteSize', 65536);

    const now = BigInt(Date.now()) * BigInt(10000) + BigInt(116444736000000000);
    const timeBuf = Buffer.alloc(8);
    timeBuf.writeBigUInt64LE(now);
    respNeg.set('SystemTime', timeBuf);
    respNeg.set('ServerStartTime', Buffer.alloc(8));

    const negTokenInit = new spnego.SPNEGO_NegTokenInit();
    negTokenInit.fields['MechTypes'] = Buffer.concat([
      spnego.TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']!,
    ]);
    respNeg.set('Buffer', negTokenInit.getData());

    respPacket.set('Data', respNeg.getData());

    smbServer.setConnectionData(connId, connData);
    return [[], respPacket, STATUS_SUCCESS];
  }

  static smb2SessionSetup(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId, false);

    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', smb2.SMB2_SESSION_SETUP);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);

    const sessionSetup = new smb2.SMB2SessionSetup();
    sessionSetup.fromString((recvPacket as Structure).get('Data') as Buffer);

    const securityBlob = sessionSetup.get('Buffer') as Buffer;
    let rawNTLM = false;
    let ntlmData: Buffer;

    if (securityBlob.length > 0 && securityBlob[0] === spnego.ASN1_AID) {
      const negTokenInit = new spnego.SPNEGO_NegTokenInit();
      negTokenInit.fromString(securityBlob);
      ntlmData = negTokenInit.fields['MechToken'] as Buffer || Buffer.alloc(0);
    } else if (securityBlob.length > 0 && securityBlob[0] === spnego.ASN1_SUPPORTED_MECH) {
      const negTokenResp = new spnego.SPNEGO_NegTokenResp();
      negTokenResp.fromString(securityBlob);
      ntlmData = negTokenResp.fields['ResponseToken'] as Buffer || Buffer.alloc(0);
    } else {
      ntlmData = securityBlob;
      rawNTLM = true;
    }

    if (ntlmData.length < 12) {
      respPacket.set('Status', STATUS_LOGON_FAILURE);
      const respSetup = new smb2.SMB2SessionSetup_Response();
      respSetup.set('Buffer', Buffer.alloc(0));
      respPacket.set('Data', respSetup.getData());
      return [[], respPacket, STATUS_LOGON_FAILURE];
    }

    const messageType = ntlmData.readUInt32LE(8);

    if (messageType === ntlm.NTLMSSP_AUTH_NEGOTIATE) {
      const negotiateMessage = new ntlm.NTLMAuthNegotiate();
      negotiateMessage.fromString(ntlmData);
      connData.NEGOTIATE_MESSAGE = negotiateMessage;

      const challengeMessage = new ntlm.NTLMAuthChallenge();

      let challengeFlags = ntlm.NTLMSSP_NEGOTIATE_128 |
        ntlm.NTLMSSP_NEGOTIATE_56 |
        ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH |
        ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
        ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO |
        ntlm.NTLMSSP_NEGOTIATE_NTLM |
        ntlm.NTLMSSP_NEGOTIATE_SEAL |
        ntlm.NTLMSSP_NEGOTIATE_SIGN |
        ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
        ntlm.NTLMSSP_NEGOTIATE_UNICODE |
        ntlm.NTLMSSP_REQUEST_TARGET;

      if (smbServer.getDropSSP()) {
        challengeFlags = ntlm.NTLMSSP_DROP_SSP_STATIC;
      }

      const serverName = smbServer.getServerName();
      const serverDomain = smbServer.getServerDomain();
      const challenge = smbServer.getSMBChallenge();

      const avPairs = new ntlm.AV_PAIRS();
      avPairs.set(ntlm.NTLMSSP_AV_HOSTNAME, Buffer.from(serverName, 'utf16le'));
      avPairs.set(ntlm.NTLMSSP_AV_DOMAINNAME, Buffer.from(serverDomain, 'utf16le'));
      avPairs.set(ntlm.NTLMSSP_AV_DNS_HOSTNAME, Buffer.from(serverName, 'utf16le'));
      avPairs.set(ntlm.NTLMSSP_AV_DNS_DOMAINNAME, Buffer.from(serverDomain, 'utf16le'));
      const now2 = BigInt(Date.now()) * BigInt(10000) + BigInt(116444736000000000);
      const timeBuf = Buffer.alloc(8);
      timeBuf.writeBigUInt64LE(now2);
      avPairs.set(ntlm.NTLMSSP_AV_TIME, timeBuf);
      avPairs.set(ntlm.NTLMSSP_AV_EOL, Buffer.alloc(0));

      challengeMessage.set('flags', challengeFlags);
      challengeMessage.set('challenge', challenge);
      challengeMessage.set('domain_name', Buffer.from(serverDomain, 'utf16le'));
      challengeMessage.set('TargetInfoFields', avPairs.getData());

      connData.CHALLENGE_MESSAGE = challengeMessage;

      let responseToken: Buffer;
      if (rawNTLM) {
        responseToken = challengeMessage.getData();
      } else {
        const negTokenResp = new spnego.SPNEGO_NegTokenResp();
        negTokenResp.fields['NegState'] = Buffer.from([0x01]);
        negTokenResp.fields['SupportedMech'] = spnego.TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']!;
        negTokenResp.fields['ResponseToken'] = challengeMessage.getData();
        responseToken = negTokenResp.getData();
      }

      respPacket.set('Status', STATUS_MORE_PROCESSING_REQUIRED);
      const respSetup = new smb2.SMB2SessionSetup_Response();
      respSetup.set('SecurityBufferOffset', 64 + 8);
      respSetup.set('SecurityBufferLength', responseToken.length);
      respSetup.set('Buffer', responseToken);
      respPacket.set('Data', respSetup.getData());

      smbServer.setConnectionData(connId, connData);
      return [[], respPacket, STATUS_MORE_PROCESSING_REQUIRED];
    }

    if (messageType === ntlm.NTLMSSP_AUTH_CHALLENGE_RESPONSE) {
      const authenticateMessage = new ntlm.NTLMAuthChallengeResponse();
      authenticateMessage.fromString(ntlmData);
      connData.AUTHENTICATE_MESSAGE = authenticateMessage;

      const credentials = smbServer.getCredentials();
      const challenge = smbServer.getSMBChallenge();

      let errorCode = STATUS_SUCCESS;
      let exportedSessionKey: Buffer = Buffer.alloc(16);

      const userName = authenticateMessage.getUserString();
      const userNameLower = userName.toLowerCase();

      if (Object.keys(credentials).length > 0) {
        const cred = credentials[userNameLower];
        if (cred) {
          [errorCode, exportedSessionKey] = computeNTLMv2(
            userName, cred.lmhash, cred.nthash,
            challenge, authenticateMessage,
            connData.CHALLENGE_MESSAGE, connData.NEGOTIATE_MESSAGE,
          );
        } else {
          errorCode = STATUS_LOGON_FAILURE;
        }
      } else {
        if (!smbServer.getAnonymousLogon()) {
          errorCode = STATUS_LOGON_FAILURE;
        }
      }

      if (errorCode === STATUS_SUCCESS) {
        const uid = Math.floor(Math.random() * 0xffffffff) + 1;
        connData.Uid = uid;
        connData.Authenticated = true;
        connData.SignatureEnabled = true;
        connData.SigningSessionKey = exportedSessionKey;

        respPacket.set('SessionID', uid);

        const authCallback = smbServer.getAuthCallback();
        if (authCallback) {
          authCallback(smbServer, connData);
        }

        if (smbServer.getDumpHashes()) {
          const ntResponse = authenticateMessage.get('ntlm') as Buffer;
          const lmResponse = authenticateMessage.get('lanman') as Buffer;
          const domain = authenticateMessage.get('domain_name') as Buffer;
          const user = authenticateMessage.get('user_name') as Buffer;
          const jtrData = outputToJohnFormat(challenge, user, domain, lmResponse, ntResponse);
          if (jtrData) {
            console.debug(`[*] ${jtrData.hash_string}`);
            const jtrPath = smbServer.getJTRdumpPath();
            if (jtrPath) {
              writeJohnOutputToFile(jtrData.hash_string, jtrData.hash_version, jtrPath);
            }
          }
        }
      }

      let responseToken: Buffer;
      if (rawNTLM) {
        responseToken = Buffer.alloc(0);
      } else {
        const negTokenResp = new spnego.SPNEGO_NegTokenResp();
        negTokenResp.fields['NegState'] = Buffer.from([errorCode === STATUS_SUCCESS ? 0x00 : 0x02]);
        responseToken = negTokenResp.getData();
      }

      respPacket.set('Status', errorCode);
      const respSetup = new smb2.SMB2SessionSetup_Response();
      respSetup.set('SecurityBufferOffset', 64 + 8);
      respSetup.set('SecurityBufferLength', responseToken.length);
      respSetup.set('Buffer', responseToken);
      respPacket.set('Data', respSetup.getData());

      smbServer.setConnectionData(connId, connData);
      return [[], respPacket, errorCode];
    }

    respPacket.set('Status', STATUS_LOGON_FAILURE);
    const respSetup = new smb2.SMB2SessionSetup_Response();
    respSetup.set('Buffer', Buffer.alloc(0));
    respPacket.set('Data', respSetup.getData());
    return [[], respPacket, STATUS_LOGON_FAILURE];
  }

  static smb2TreeConnect(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);

    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', smb2.SMB2_TREE_CONNECT);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('SessionID', connData.Uid);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);

    const treeConnect = new smb2.SMB2TreeConnect();
    treeConnect.fromString((recvPacket as Structure).get('Data') as Buffer);

    const pathOffset = treeConnect.get('PathOffset') as number;
    const pathLength = treeConnect.get('PathLength') as number;
    const rawPacketData = (recvPacket as Structure).getData();
    const pathStr = rawPacketData.subarray(pathOffset, pathOffset + pathLength).toString('utf16le');

    const parts = pathStr.replace(/\\/g, '/').split('/');
    const shareName = parts[parts.length - 1] || '';

    const shareInfo = searchShare(connId, shareName, smbServer);
    if (!shareInfo) {
      respPacket.set('Status', STATUS_OBJECT_PATH_NOT_FOUND);
      const resp = new smb2.SMB2TreeConnect_Response();
      respPacket.set('Data', resp.getData());
      return [[], respPacket, STATUS_OBJECT_PATH_NOT_FOUND];
    }

    const tid = Math.floor(Math.random() * 0xfffe) + 1;
    connData.ConnectedShares[tid] = { ...shareInfo, shareName };
    respPacket.set('TreeID', tid);

    const resp = new smb2.SMB2TreeConnect_Response();
    const shareType = parseInt(shareInfo['share type'] || '0', 10);
    resp.set('ShareType', shareType === 3 ? smb2.SMB2_SHARE_TYPE_PIPE : smb2.SMB2_SHARE_TYPE_DISK);
    resp.set('ShareFlags', 0);
    resp.set('Capabilities', 0);
    resp.set('MaximalAccess', 0x000f01ff);

    respPacket.set('Data', resp.getData());

    if (connData.SignatureEnabled) {
      smbServer.signSMBv2(respPacket, connData.SigningSessionKey);
    }

    smbServer.setConnectionData(connId, connData);
    return [[], respPacket, STATUS_SUCCESS];
  }

  static smb2Create(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);

    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', smb2.SMB2_CREATE);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('SessionID', connData.Uid);
    respPacket.set('TreeID', (recvPacket as Structure).get('TreeID') as number);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);

    const createRequest = new smb2.SMB2Create();
    createRequest.fromString((recvPacket as Structure).get('Data') as Buffer);

    const nameOffset = createRequest.get('NameOffset') as number;
    const nameLength = createRequest.get('NameLength') as number;
    const rawPacketData = (recvPacket as Structure).getData();
    let pathStr = '';
    if (nameLength > 0) {
      pathStr = rawPacketData.subarray(nameOffset, nameOffset + nameLength).toString('utf16le');
    }

    const createDisposition = createRequest.get('CreateDisposition') as number;
    const createOptions = createRequest.get('CreateOptions') as number;
    const desiredAccess = createRequest.get('DesiredAccess') as number;
    const fileAttributes = createRequest.get('FileAttributes') as number;

    const tid = (recvPacket as Structure).get('TreeID') as number;
    const share = connData.ConnectedShares[tid];
    if (!share) {
      respPacket.set('Status', STATUS_SMB_BAD_TID);
      const errResp = new smb2.SMB2Error();
      respPacket.set('Data', errResp.getData());
      return [[], respPacket, STATUS_SMB_BAD_TID];
    }

    const sharePath = share['path'] || '';

    const pathNorm = pathStr.replace(/\\/g, '/').toLowerCase();
    const builtinHandlers = smbServer.getBuiltinPipeHandlers();
    const builtinKey = Object.keys(builtinHandlers).find(
      k => pathNorm.endsWith(k.replace(/\\/g, '/').toLowerCase()),
    );

    if (builtinKey) {
      const handler = builtinHandlers[builtinKey]!();
      const fileId = uuid.generate();
      const fidStr = fileId.toString('hex');
      connData.OpenedFiles[fidStr] = {
        FileHandle: PIPE_FILE_DESCRIPTOR,
        FileName: pathStr,
        DeleteOnClose: false,
        PipeHandler: handler,
      };

      const resp = new smb2.SMB2Create_Response();
      resp.set('OplockLevel', 0);
      resp.set('CreateAction', smb.FILE_OPEN);
      const nowFt = smb.POSIXtoFT(Math.floor(Date.now() / 1000));
      resp.set('CreationTime', nowFt);
      resp.set('LastAccessTime', nowFt);
      resp.set('LastWriteTime', nowFt);
      resp.set('ChangeTime', nowFt);
      resp.set('AllocationSize', 4096);
      resp.set('EndOfFile', 0);
      resp.set('FileAttributes', 0x80);
      resp.set('FileID', fileId);
      resp.set('Buffer', Buffer.alloc(0));

      respPacket.set('Data', resp.getData());
      connData.LastRequest['SMB2_CREATE'] = resp;
      smbServer.setConnectionData(connId, connData);
      return [[], respPacket, STATUS_SUCCESS];
    }

    const registeredPipes = smbServer.getRegisteredNamedPipes();
    const pipeKey = Object.keys(registeredPipes).find(
      k => pathNorm.endsWith(k.replace(/\\/g, '/').toLowerCase()),
    );

    if (pipeKey) {
      const pipeAddr = registeredPipes[pipeKey]!;
      const sock = new net.Socket();
      try {
        sock.connect({ host: pipeAddr[0], port: pipeAddr[1] });
      } catch {
        respPacket.set('Status', STATUS_OBJECT_NAME_NOT_FOUND);
        const errResp = new smb2.SMB2Error();
        respPacket.set('Data', errResp.getData());
        return [[], respPacket, STATUS_OBJECT_NAME_NOT_FOUND];
      }

      const fileId = uuid.generate();
      const fidStr = fileId.toString('hex');
      connData.OpenedFiles[fidStr] = {
        FileHandle: PIPE_FILE_DESCRIPTOR,
        FileName: pathStr,
        DeleteOnClose: false,
        Socket: sock,
      };

      const resp = new smb2.SMB2Create_Response();
      resp.set('OplockLevel', 0);
      resp.set('CreateAction', smb.FILE_OPEN);
      const nowFt = smb.POSIXtoFT(Math.floor(Date.now() / 1000));
      resp.set('CreationTime', nowFt);
      resp.set('LastAccessTime', nowFt);
      resp.set('LastWriteTime', nowFt);
      resp.set('ChangeTime', nowFt);
      resp.set('AllocationSize', 4096);
      resp.set('EndOfFile', 0);
      resp.set('FileAttributes', 0x80);
      resp.set('FileID', fileId);
      resp.set('Buffer', Buffer.alloc(0));

      respPacket.set('Data', resp.getData());
      connData.LastRequest['SMB2_CREATE'] = resp;
      smbServer.setConnectionData(connId, connData);
      return [[], respPacket, STATUS_SUCCESS];
    }

    if (pathStr === '' || pathStr === '\\') pathStr = '';
    const normalized = normalizePath(pathStr);
    const fullPath = sharePath ? path.join(sharePath, normalized) : normalized;

    if (sharePath && !isInFileJail(sharePath, normalized || '.')) {
      respPacket.set('Status', STATUS_OBJECT_PATH_SYNTAX_BAD);
      const errResp = new smb2.SMB2Error();
      respPacket.set('Data', errResp.getData());
      return [[], respPacket, STATUS_OBJECT_PATH_SYNTAX_BAD];
    }

    let fh: number;
    let action: number;
    const actualPath = fullPath || sharePath;
    const exists = fs.existsSync(actualPath);
    const isDir = exists && fs.statSync(actualPath).isDirectory();

    if (createOptions & smb.FILE_DIRECTORY_FILE) {
      if (createDisposition === smb.FILE_CREATE) {
        if (exists) {
          respPacket.set('Status', STATUS_OBJECT_NAME_COLLISION);
          const errResp = new smb2.SMB2Error();
          respPacket.set('Data', errResp.getData());
          return [[], respPacket, STATUS_OBJECT_NAME_COLLISION];
        }
        fs.mkdirSync(actualPath, { recursive: true });
        action = smb.FILE_CREATE;
      } else if (createDisposition === smb.FILE_OPEN_IF) {
        if (!exists) {
          fs.mkdirSync(actualPath, { recursive: true });
          action = smb.FILE_CREATE;
        } else {
          action = smb.FILE_OPEN;
        }
      } else {
        if (!exists) {
          respPacket.set('Status', STATUS_OBJECT_PATH_NOT_FOUND);
          const errResp = new smb2.SMB2Error();
          respPacket.set('Data', errResp.getData());
          return [[], respPacket, STATUS_OBJECT_PATH_NOT_FOUND];
        }
        action = smb.FILE_OPEN;
      }
      fh = VOID_FILE_DESCRIPTOR;
    } else {
      try {
        if (createDisposition === smb.FILE_SUPERSEDE) {
          if (exists) try { fs.unlinkSync(actualPath); } catch { /* ignore */ }
          fh = fs.openSync(actualPath, fs.constants.O_CREAT | fs.constants.O_RDWR);
          action = smb.FILE_SUPERSEDE;
        } else if (createDisposition === smb.FILE_OVERWRITE_IF) {
          fh = fs.openSync(actualPath, fs.constants.O_CREAT | fs.constants.O_RDWR | fs.constants.O_TRUNC);
          action = exists ? smb.FILE_OVERWRITE : smb.FILE_CREATE;
        } else if (createDisposition === smb.FILE_OVERWRITE) {
          if (!exists) {
            respPacket.set('Status', STATUS_NO_SUCH_FILE);
            const errResp = new smb2.SMB2Error();
            respPacket.set('Data', errResp.getData());
            return [[], respPacket, STATUS_NO_SUCH_FILE];
          }
          fh = fs.openSync(actualPath, fs.constants.O_RDWR | fs.constants.O_TRUNC);
          action = smb.FILE_OVERWRITE;
        } else if (createDisposition === smb.FILE_OPEN_IF) {
          const flags = exists ? fs.constants.O_RDWR : fs.constants.O_CREAT | fs.constants.O_RDWR;
          fh = fs.openSync(actualPath, flags);
          action = exists ? smb.FILE_OPEN : smb.FILE_CREATE;
        } else if (createDisposition === smb.FILE_CREATE) {
          if (exists) {
            respPacket.set('Status', STATUS_OBJECT_NAME_COLLISION);
            const errResp = new smb2.SMB2Error();
            respPacket.set('Data', errResp.getData());
            return [[], respPacket, STATUS_OBJECT_NAME_COLLISION];
          }
          fh = fs.openSync(actualPath, fs.constants.O_CREAT | fs.constants.O_RDWR);
          action = smb.FILE_CREATE;
        } else {
          if (!exists) {
            respPacket.set('Status', STATUS_NO_SUCH_FILE);
            const errResp = new smb2.SMB2Error();
            respPacket.set('Data', errResp.getData());
            return [[], respPacket, STATUS_NO_SUCH_FILE];
          }
          if (isDir) {
            fh = VOID_FILE_DESCRIPTOR;
          } else {
            const flags = (desiredAccess & smb.FILE_WRITE_DATA) ? fs.constants.O_RDWR : fs.constants.O_RDONLY;
            fh = fs.openSync(actualPath, flags);
          }
          action = smb.FILE_OPEN;
        }
      } catch {
        respPacket.set('Status', STATUS_ACCESS_DENIED);
        const errResp = new smb2.SMB2Error();
        respPacket.set('Data', errResp.getData());
        return [[], respPacket, STATUS_ACCESS_DENIED];
      }
    }

    const fileId = uuid.generate();
    const fidStr = fileId.toString('hex');
    const deleteOnClose = !!(createOptions & smb.FILE_DELETE_ON_CLOSE);

    connData.OpenedFiles[fidStr] = {
      FileHandle: fh,
      FileName: actualPath,
      DeleteOnClose: deleteOnClose,
      Open: {
        EnumerationLocation: 0,
        EnumerationSearchPattern: '',
      },
    };

    let stat: fs.Stats;
    try {
      stat = fs.statSync(actualPath);
    } catch {
      stat = { size: 0, atimeMs: Date.now(), mtimeMs: Date.now(), ctimeMs: Date.now(), isDirectory: () => false, isFile: () => true } as any;
    }

    const resp = new smb2.SMB2Create_Response();
    resp.set('OplockLevel', 0);
    resp.set('CreateAction', action);
    resp.set('CreationTime', smb.POSIXtoFT(Math.floor(stat.ctimeMs / 1000)));
    resp.set('LastAccessTime', smb.POSIXtoFT(Math.floor(stat.atimeMs / 1000)));
    resp.set('LastWriteTime', smb.POSIXtoFT(Math.floor(stat.mtimeMs / 1000)));
    resp.set('ChangeTime', smb.POSIXtoFT(Math.floor(stat.mtimeMs / 1000)));
    resp.set('AllocationSize', stat.size);
    resp.set('EndOfFile', stat.size);
    resp.set('FileAttributes', stat.isDirectory() ? smb.ATTR_DIRECTORY : smb.ATTR_NORMAL | smb.ATTR_ARCHIVE);
    resp.set('FileID', fileId);
    resp.set('Buffer', Buffer.alloc(0));

    respPacket.set('Data', resp.getData());
    connData.LastRequest['SMB2_CREATE'] = resp;
    smbServer.setConnectionData(connId, connData);
    return [[], respPacket, STATUS_SUCCESS];
  }

  static smb2Close(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);

    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', smb2.SMB2_CLOSE);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('SessionID', connData.Uid);
    respPacket.set('TreeID', (recvPacket as Structure).get('TreeID') as number);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);

    const closeRequest = new smb2.SMB2Close();
    closeRequest.fromString((recvPacket as Structure).get('Data') as Buffer);

    let fileId = (closeRequest.get('FileID') as Structure).getData();
    let fidStr = fileId.toString('hex');

    const allOnes = Buffer.alloc(16, 0xff);
    if (fileId.equals(allOnes) && connData.LastRequest['SMB2_CREATE']) {
      const lastCreate = connData.LastRequest['SMB2_CREATE'] as Structure;
      fileId = (lastCreate.get('FileID') as Structure).getData();
      fidStr = fileId.toString('hex');
    }

    if (!connData.OpenedFiles[fidStr]) {
      respPacket.set('Status', STATUS_FILE_CLOSED);
      const errResp = new smb2.SMB2Error();
      respPacket.set('Data', errResp.getData());
      return [[], respPacket, STATUS_FILE_CLOSED];
    }

    const fileEntry = connData.OpenedFiles[fidStr]!;
    const fh = fileEntry.FileHandle;

    if (fh === PIPE_FILE_DESCRIPTOR) {
      fileEntry.Socket?.destroy();
    } else if (fh !== VOID_FILE_DESCRIPTOR && fh > 0) {
      try { fs.closeSync(fh); } catch { /* ignore */ }
    }

    if (fileEntry.DeleteOnClose) {
      try {
        const stat = fs.statSync(fileEntry.FileName);
        if (stat.isDirectory()) {
          fs.rmSync(fileEntry.FileName, { recursive: true, force: true });
        } else {
          fs.unlinkSync(fileEntry.FileName);
        }
      } catch { /* ignore */ }
    }

    delete connData.OpenedFiles[fidStr];

    const resp = new smb2.SMB2Close_Response();
    respPacket.set('Data', resp.getData());

    smbServer.setConnectionData(connId, connData);
    return [[], respPacket, STATUS_SUCCESS];
  }

  static smb2QueryInfo(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);

    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', smb2.SMB2_QUERY_INFO);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('SessionID', connData.Uid);
    respPacket.set('TreeID', (recvPacket as Structure).get('TreeID') as number);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);

    const queryInfoRequest = new smb2.SMB2QueryInfo();
    queryInfoRequest.fromString((recvPacket as Structure).get('Data') as Buffer);

    const infoType = queryInfoRequest.get('InfoType') as number;
    const fileInfoClass = queryInfoRequest.get('FileInfoClass') as number;
    const fileId = (queryInfoRequest.get('FileID') as Structure).getData();
    const fidStr = fileId.toString('hex');

    if (!connData.OpenedFiles[fidStr]) {
      respPacket.set('Status', STATUS_FILE_CLOSED);
      const errResp = new smb2.SMB2Error();
      respPacket.set('Data', errResp.getData());
      return [[], respPacket, STATUS_FILE_CLOSED];
    }

    const fileEntry = connData.OpenedFiles[fidStr]!;

    if (infoType === smb2.SMB2_0_INFO_FILE) {
      const [infoData, errorCode] = queryPathInformation(
        path.dirname(fileEntry.FileName),
        path.basename(fileEntry.FileName),
        fileInfoClass,
      );

      if (infoData && errorCode === STATUS_SUCCESS) {
        const resp = new smb2.SMB2QueryInfo_Response();
        resp.set('OutputBufferOffset', 64 + 8);
        resp.set('OutputBufferLength', infoData.length);
        resp.set('Buffer', infoData);
        respPacket.set('Data', resp.getData());
        return [[], respPacket, STATUS_SUCCESS];
      }

      respPacket.set('Status', errorCode);
      const errResp = new smb2.SMB2Error();
      respPacket.set('Data', errResp.getData());
      return [[], respPacket, errorCode];
    }

    if (infoType === smb2.SMB2_0_INFO_FILESYSTEM) {
      const tid = (recvPacket as Structure).get('TreeID') as number;
      const share = connData.ConnectedShares[tid];
      const sharePath = share?.['path'] || '.';

      const result = queryFsInformation(sharePath, '', fileInfoClass);
      if (result && Buffer.isBuffer(result)) {
        const resp = new smb2.SMB2QueryInfo_Response();
        resp.set('OutputBufferOffset', 64 + 8);
        resp.set('OutputBufferLength', result.length);
        resp.set('Buffer', result);
        respPacket.set('Data', resp.getData());
        return [[], respPacket, STATUS_SUCCESS];
      }

      respPacket.set('Status', STATUS_NOT_SUPPORTED);
      const errResp = new smb2.SMB2Error();
      respPacket.set('Data', errResp.getData());
      return [[], respPacket, STATUS_NOT_SUPPORTED];
    }

    if (infoType === smb2.SMB2_0_INFO_SECURITY) {
      const resp = new smb2.SMB2QueryInfo_Response();
      const secInfo = new smb2.FileSecInformation();
      const secData = secInfo.getData();
      resp.set('OutputBufferOffset', 64 + 8);
      resp.set('OutputBufferLength', secData.length);
      resp.set('Buffer', secData);
      respPacket.set('Data', resp.getData());
      return [[], respPacket, STATUS_SUCCESS];
    }

    respPacket.set('Status', STATUS_NOT_SUPPORTED);
    const errResp = new smb2.SMB2Error();
    respPacket.set('Data', errResp.getData());
    return [[], respPacket, STATUS_NOT_SUPPORTED];
  }

  static smb2SetInfo(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);

    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', smb2.SMB2_SET_INFO);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('SessionID', connData.Uid);
    respPacket.set('TreeID', (recvPacket as Structure).get('TreeID') as number);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);

    const setInfoRequest = new smb2.SMB2SetInfo();
    setInfoRequest.fromString((recvPacket as Structure).get('Data') as Buffer);

    const fileInfoClass = setInfoRequest.get('FileInfoClass') as number;
    const fileId = (setInfoRequest.get('FileID') as Structure).getData();
    const fidStr = fileId.toString('hex');
    const inputBuffer = setInfoRequest.get('Buffer') as Buffer;

    if (!connData.OpenedFiles[fidStr]) {
      respPacket.set('Status', STATUS_FILE_CLOSED);
      const errResp = new smb2.SMB2Error();
      respPacket.set('Data', errResp.getData());
      return [[], respPacket, STATUS_FILE_CLOSED];
    }

    const fileEntry = connData.OpenedFiles[fidStr]!;
    let errorCode = STATUS_SUCCESS;

    if (fileInfoClass === smb2.SMB2_FILE_DISPOSITION_INFO) {
      fileEntry.DeleteOnClose = inputBuffer.length > 0 && inputBuffer[0] !== 0;
    } else if (fileInfoClass === smb2.SMB2_FILE_BASIC_INFO) {
      const setInfo = new smb.SMBSetFileBasicInfo();
      setInfo.fromString(inputBuffer);
      try {
        const atime = Number(smb.FTtoPOSIX(setInfo.get('LastAccessTime') as bigint));
        const mtime = Number(smb.FTtoPOSIX(setInfo.get('LastWriteTime') as bigint));
        if (atime > 0 && mtime > 0) {
          fs.utimesSync(fileEntry.FileName, atime, mtime);
        }
      } catch {
        errorCode = STATUS_ACCESS_DENIED;
      }
    } else if (fileInfoClass === smb2.SMB2_FILE_END_OF_FILE_INFO) {
      const eof = inputBuffer.readBigInt64LE(0);
      try {
        fs.ftruncateSync(fileEntry.FileHandle, Number(eof));
      } catch {
        errorCode = STATUS_ACCESS_DENIED;
      }
    } else if (fileInfoClass === smb2.SMB2_FILE_RENAME_INFO) {
      const renameInfo = new smb2.FILE_RENAME_INFORMATION_TYPE_2();
      renameInfo.fromString(inputBuffer);
      const newName = (renameInfo.get('FileName') as Buffer).toString('utf16le');
      const tid = (recvPacket as Structure).get('TreeID') as number;
      const share = connData.ConnectedShares[tid];
      if (share) {
        const sharePath = share['path'] || '';
        const newPath = path.join(sharePath, normalizePath(newName));
        try {
          fs.renameSync(fileEntry.FileName, newPath);
          fileEntry.FileName = newPath;
        } catch {
          errorCode = STATUS_ACCESS_DENIED;
        }
      }
    } else if (fileInfoClass === smb2.SMB2_FILE_ALLOCATION_INFO) {
      // no-op
    }

    respPacket.set('Status', errorCode);
    const resp = new smb2.SMB2SetInfo_Response();
    respPacket.set('Data', resp.getData());

    smbServer.setConnectionData(connId, connData);
    return [[], respPacket, errorCode];
  }

  static smb2Write(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);

    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', smb2.SMB2_WRITE);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('SessionID', connData.Uid);
    respPacket.set('TreeID', (recvPacket as Structure).get('TreeID') as number);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);

    const writeRequest = new smb2.SMB2Write();
    writeRequest.fromString((recvPacket as Structure).get('Data') as Buffer);

    const fileId = (writeRequest.get('FileID') as Structure).getData();
    const fidStr = fileId.toString('hex');
    const offset = writeRequest.get('Offset') as bigint;
    const dataBuffer = writeRequest.get('Buffer') as Buffer;

    if (!connData.OpenedFiles[fidStr]) {
      respPacket.set('Status', STATUS_FILE_CLOSED);
      const errResp = new smb2.SMB2Error();
      respPacket.set('Data', errResp.getData());
      return [[], respPacket, STATUS_FILE_CLOSED];
    }

    const fileEntry = connData.OpenedFiles[fidStr]!;
    let written = 0;

    if (fileEntry.FileHandle === PIPE_FILE_DESCRIPTOR && fileEntry.PipeHandler) {
      fileEntry.PipeHandler.processData(dataBuffer);
      written = dataBuffer.length;
    } else if (fileEntry.FileHandle === PIPE_FILE_DESCRIPTOR && fileEntry.Socket) {
      fileEntry.Socket.write(dataBuffer);
      written = dataBuffer.length;
    } else if (fileEntry.FileHandle > 0) {
      written = fs.writeSync(fileEntry.FileHandle, dataBuffer, 0, dataBuffer.length, Number(offset));
    }

    const resp = new smb2.SMB2Write_Response();
    resp.set('Count', written);
    respPacket.set('Data', resp.getData());

    return [[], respPacket, STATUS_SUCCESS];
  }

  static smb2Read(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);

    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', smb2.SMB2_READ);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('SessionID', connData.Uid);
    respPacket.set('TreeID', (recvPacket as Structure).get('TreeID') as number);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);

    const readRequest = new smb2.SMB2Read();
    readRequest.fromString((recvPacket as Structure).get('Data') as Buffer);

    const fileId = (readRequest.get('FileID') as Structure).getData();
    const fidStr = fileId.toString('hex');
    const readLength = readRequest.get('Length') as number;
    const offset = readRequest.get('Offset') as bigint;

    if (!connData.OpenedFiles[fidStr]) {
      respPacket.set('Status', STATUS_FILE_CLOSED);
      const errResp = new smb2.SMB2Error();
      respPacket.set('Data', errResp.getData());
      return [[], respPacket, STATUS_FILE_CLOSED];
    }

    const fileEntry = connData.OpenedFiles[fidStr]!;
    let data: Buffer;

    if (fileEntry.FileHandle === PIPE_FILE_DESCRIPTOR && fileEntry.PipeHandler) {
      data = fileEntry.PipeHandler.getResponse();
    } else if (fileEntry.FileHandle === PIPE_FILE_DESCRIPTOR && fileEntry.Socket) {
      data = Buffer.alloc(0);
    } else if (fileEntry.FileHandle > 0) {
      data = Buffer.alloc(readLength);
      const bytesRead = fs.readSync(fileEntry.FileHandle, data, 0, readLength, Number(offset));
      data = data.subarray(0, bytesRead);
    } else {
      data = Buffer.alloc(0);
    }

    const resp = new smb2.SMB2Read_Response();
    resp.set('DataOffset', 64 + 16);
    resp.set('DataLength', data.length);
    resp.set('DataRemaining', 0);
    resp.set('Buffer', data);
    respPacket.set('Data', resp.getData());

    return [[], respPacket, STATUS_SUCCESS];
  }

  static smb2Flush(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);

    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', smb2.SMB2_FLUSH);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('SessionID', connData.Uid);
    respPacket.set('TreeID', (recvPacket as Structure).get('TreeID') as number);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);

    const flushRequest = new smb2.SMB2Flush();
    flushRequest.fromString((recvPacket as Structure).get('Data') as Buffer);

    const fileId = (flushRequest.get('FileID') as Structure).getData();
    const fidStr = fileId.toString('hex');

    if (connData.OpenedFiles[fidStr]) {
      const fh = connData.OpenedFiles[fidStr]!.FileHandle;
      if (fh > 0) {
        try { fs.fsyncSync(fh); } catch { /* ignore */ }
      }
    }

    const resp = new smb2.SMB2Flush_Response();
    respPacket.set('Data', resp.getData());

    return [[], respPacket, STATUS_SUCCESS];
  }

  static smb2QueryDirectory(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);

    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', smb2.SMB2_QUERY_DIRECTORY);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('SessionID', connData.Uid);
    respPacket.set('TreeID', (recvPacket as Structure).get('TreeID') as number);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);

    const queryDirRequest = new smb2.SMB2QueryDirectory();
    queryDirRequest.fromString((recvPacket as Structure).get('Data') as Buffer);

    const infoClass = queryDirRequest.get('FileInformationClass') as number;
    const queryFlags = queryDirRequest.get('Flags') as number;
    const fileId = (queryDirRequest.get('FileID') as Structure).getData();
    const fidStr = fileId.toString('hex');
    const maxOutput = queryDirRequest.get('OutputBufferLength') as number;

    const nameOffset = queryDirRequest.get('FileNameOffset') as number;
    const nameLength = queryDirRequest.get('FileNameLength') as number;
    const rawPacketData = (recvPacket as Structure).getData();
    let searchPattern = '*';
    if (nameLength > 0) {
      searchPattern = rawPacketData.subarray(nameOffset, nameOffset + nameLength).toString('utf16le');
    }

    if (!connData.OpenedFiles[fidStr]) {
      respPacket.set('Status', STATUS_FILE_CLOSED);
      const errResp = new smb2.SMB2Error();
      respPacket.set('Data', errResp.getData());
      return [[], respPacket, STATUS_FILE_CLOSED];
    }

    const fileEntry = connData.OpenedFiles[fidStr]!;
    const open = fileEntry.Open!;

    if (queryFlags & smb2.SMB2_REOPEN || queryFlags & smb2.SMB2_RESTART_SCANS) {
      open.EnumerationLocation = 0;
      open.EnumerationSearchPattern = searchPattern;
    }

    if (open.EnumerationSearchPattern === '') {
      open.EnumerationSearchPattern = searchPattern;
    }

    const searchDir = path.dirname(fileEntry.FileName) || fileEntry.FileName;
    const searchBase = path.basename(fileEntry.FileName);
    const searchPat = searchBase
      ? path.join(searchBase, open.EnumerationSearchPattern)
      : open.EnumerationSearchPattern;
    const [searchResult, _searchCount, errorCode] = findFirst2(
      searchDir,
      searchPat,
      infoClass,
      smb.ATTR_DIRECTORY,
      smb.FLAGS2_UNICODE,
      true,
    );

    if (errorCode !== STATUS_SUCCESS) {
      respPacket.set('Status', errorCode);
      const errResp = new smb2.SMB2Error();
      respPacket.set('Data', errResp.getData());
      return [[], respPacket, errorCode];
    }

    const start = open.EnumerationLocation;
    const remaining = searchResult.slice(start);

    if (remaining.length === 0) {
      respPacket.set('Status', STATUS_NO_MORE_FILES);
      const errResp = new smb2.SMB2Error();
      respPacket.set('Data', errResp.getData());
      return [[], respPacket, STATUS_NO_MORE_FILES];
    }

    const paddedEntries: Buffer[] = [];
    let count = 0;

    for (const item of remaining) {
      const itemData = (item as Structure).getData();
      const padLen = (8 - (itemData.length % 8)) % 8;
      const padded = Buffer.concat([itemData, Buffer.alloc(padLen)]);
      const totalSoFar = paddedEntries.reduce((s, b) => s + b.length, 0);
      if (totalSoFar + padded.length > maxOutput) break;
      paddedEntries.push(padded);
      count++;
      if (queryFlags & smb2.SL_RETURN_SINGLE_ENTRY) break;
    }

    for (let i = 0; i < paddedEntries.length; i++) {
      const entry = paddedEntries[i]!;
      if (i < paddedEntries.length - 1) {
        entry.writeUInt32LE(entry.length, 0);
      } else {
        entry.writeUInt32LE(0, 0);
      }
    }

    const respData = Buffer.concat(paddedEntries);

    open.EnumerationLocation = start + count;

    const resp = new smb2.SMB2QueryDirectory_Response();
    resp.set('OutputBufferOffset', 64 + 8);
    resp.set('OutputBufferLength', respData.length);
    resp.set('Buffer', respData);
    respPacket.set('Data', resp.getData());

    smbServer.setConnectionData(connId, connData);
    return [[], respPacket, STATUS_SUCCESS];
  }

  static smb2ChangeNotify(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', smb2.SMB2_CHANGE_NOTIFY);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('Status', STATUS_NOT_SUPPORTED);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);
    const errResp = new smb2.SMB2Error();
    respPacket.set('Data', errResp.getData());
    return [[], respPacket, STATUS_NOT_SUPPORTED];
  }

  static smb2Echo(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', smb2.SMB2_ECHO);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);
    respPacket.set('Data', Buffer.alloc(0));
    return [[], respPacket, STATUS_SUCCESS];
  }

  static smb2TreeDisconnect(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);

    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', smb2.SMB2_TREE_DISCONNECT);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('SessionID', connData.Uid);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);

    const tid = (recvPacket as Structure).get('TreeID') as number;
    delete connData.ConnectedShares[tid];

    const resp = new smb2.SMB2TreeDisconnect_Response();
    respPacket.set('Data', resp.getData());

    smbServer.setConnectionData(connId, connData);
    return [[], respPacket, STATUS_SUCCESS];
  }

  static smb2Logoff(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);

    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', smb2.SMB2_LOGOFF);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('SessionID', connData.Uid);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);

    connData.Uid = 0;
    connData.Authenticated = false;

    const resp = new smb2.SMB2Logoff_Response();
    respPacket.set('Data', resp.getData());

    smbServer.setConnectionData(connId, connData);
    return [[], respPacket, STATUS_SUCCESS];
  }

  static smb2Ioctl(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const connData = smbServer.getConnectionData(connId);

    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', smb2.SMB2_IOCTL);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('SessionID', connData.Uid);
    respPacket.set('TreeID', (recvPacket as Structure).get('TreeID') as number);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);

    const ioctlRequest = new smb2.SMB2Ioctl();
    ioctlRequest.fromString((recvPacket as Structure).get('Data') as Buffer);

    const ctlCode = ioctlRequest.get('CtlCode') as number;
    const ioctls = smbServer.getIoctls();
    const handler = ioctls[ctlCode];

    if (handler) {
      const [resp, errorCode] = handler(connId, smbServer, ioctlRequest);
      if (resp) {
        respPacket.set('Data', (resp as Structure).getData());
      } else {
        respPacket.set('Status', errorCode);
        const errResp = new smb2.SMB2Error();
        respPacket.set('Data', errResp.getData());
      }
      return [[], respPacket, errorCode];
    }

    respPacket.set('Status', STATUS_NOT_SUPPORTED);
    const errResp = new smb2.SMB2Error();
    respPacket.set('Data', errResp.getData());
    return [[], respPacket, STATUS_NOT_SUPPORTED];
  }

  static smb2Lock(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', smb2.SMB2_LOCK);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);
    const resp = new smb2.SMB2Lock_Response();
    respPacket.set('Data', resp.getData());
    return [[], respPacket, STATUS_SUCCESS];
  }

  static smb2Cancel(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', smb2.SMB2_CANCEL);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('Status', STATUS_CANCELLED);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);
    respPacket.set('Data', Buffer.alloc(0));
    return [[], respPacket, STATUS_CANCELLED];
  }

  static default(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
  ): [any[], any | null, number] {
    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('Status', STATUS_NOT_SUPPORTED);
    respPacket.set('MessageID', (recvPacket as Structure).get('MessageID') as bigint);
    const errResp = new smb2.SMB2Error();
    respPacket.set('Data', errResp.getData());
    return [[], respPacket, STATUS_NOT_SUPPORTED];
  }
}

class Ioctls {
  static fsctlDfsGetReferrals(
    connId: string, smbServer: SMBSERVER, ioctlRequest: any,
  ): [any | null, number] {
    const errResp = new smb2.SMB2Error();
    return [errResp, STATUS_FS_DRIVER_REQUIRED];
  }

  static fsctlPipeTransceive(
    connId: string, smbServer: SMBSERVER, ioctlRequest: any,
  ): [any | null, number] {
    const connData = smbServer.getConnectionData(connId);
    const fileId = ((ioctlRequest as Structure).get('FileID') as Structure).getData();
    const fidStr = fileId.toString('hex');

    if (!connData.OpenedFiles[fidStr]) {
      return [null, STATUS_INVALID_HANDLE];
    }

    const fileEntry = connData.OpenedFiles[fidStr]!;
    if (fileEntry.FileHandle !== PIPE_FILE_DESCRIPTOR || (!fileEntry.Socket && !fileEntry.PipeHandler)) {
      return [null, STATUS_INVALID_DEVICE_REQUEST];
    }

    const inputData = (ioctlRequest as Structure).get('Buffer') as Buffer;

    if (fileEntry.PipeHandler) {
      fileEntry.PipeHandler.processData(inputData);
      const responseData = fileEntry.PipeHandler.getResponse();
      const resp = new smb2.SMB2Ioctl_Response();
      resp.set('CtlCode', (ioctlRequest as Structure).get('CtlCode'));
      resp.set('FileID', fileId);
      resp.set('OutputOffset', 64 + 48);
      resp.set('OutputCount', responseData.length);
      resp.set('Buffer', responseData);
      return [resp, STATUS_SUCCESS];
    }

    fileEntry.Socket!.write(inputData);

    const resp = new smb2.SMB2Ioctl_Response();
    resp.set('CtlCode', (ioctlRequest as Structure).get('CtlCode'));
    resp.set('FileID', fileId);
    resp.set('OutputOffset', 64 + 48);
    resp.set('OutputCount', 0);
    resp.set('Buffer', Buffer.alloc(0));
    return [resp, STATUS_SUCCESS];
  }

  static fsctlValidateNegotiateInfo(
    connId: string, smbServer: SMBSERVER, ioctlRequest: any,
  ): [any | null, number] {
    const resp = new smb2.SMB2Ioctl_Response();
    resp.set('CtlCode', (ioctlRequest as Structure).get('CtlCode'));
    resp.set('FileID', (ioctlRequest as Structure).get('FileID'));

    const validateResp = new smb2.VALIDATE_NEGOTIATE_INFO_RESPONSE();
    validateResp.set('Capabilities', 0);
    validateResp.set('Guid', Buffer.from('A'.repeat(16)));
    validateResp.set('SecurityMode', smb2.SMB2_NEGOTIATE_SIGNING_ENABLED);
    validateResp.set('Dialect', smb2.SMB2_DIALECT_002);

    const validateData = validateResp.getData();
    resp.set('OutputOffset', 64 + 48);
    resp.set('OutputCount', validateData.length);
    resp.set('Buffer', validateData);
    return [resp, STATUS_SUCCESS];
  }
}

class SrvsvcPipeHandler implements BuiltinPipeHandler {
  private _smbServer: SMBSERVER;
  private _responseQueue: Buffer[] = [];

  constructor(smbServer: SMBSERVER) {
    this._smbServer = smbServer;
  }

  processData(input: Buffer): void {
    if (input.length < 16) return;
    const ptype = input[2]!;
    if (ptype === 11) {
      this._responseQueue.push(this._handleBind(input));
    } else if (ptype === 0) {
      this._responseQueue.push(this._handleRequest(input));
    }
  }

  getResponse(): Buffer {
    return this._responseQueue.shift() ?? Buffer.alloc(0);
  }

  private _handleBind(data: Buffer): Buffer {
    const callId = data.readUInt32LE(12);
    const maxXmitFrag = data.readUInt16LE(16);
    const maxRecvFrag = data.readUInt16LE(18);
    const assocGroup = data.readUInt32LE(20);
    const numCtxItems = data[24]!;

    const secAddr = Buffer.from('\\PIPE\\srvsvc\0', 'ascii');
    const secAddrPad = (4 - ((2 + secAddr.length) % 4)) % 4;

    const NDR_SYNTAX = Buffer.from([
      0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
      0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
      0x02, 0x00, 0x00, 0x00,
    ]);

    const bodySize = 8 + 2 + secAddr.length + secAddrPad + 4 + numCtxItems * 24;
    const totalSize = 16 + bodySize;
    const resp = Buffer.alloc(totalSize);

    resp[0] = 5; resp[1] = 0; resp[2] = 12; resp[3] = 0x03;
    resp.writeUInt32LE(0x00000010, 4);
    resp.writeUInt16LE(totalSize, 8);
    resp.writeUInt16LE(0, 10);
    resp.writeUInt32LE(callId, 12);

    let off = 16;
    resp.writeUInt16LE(maxXmitFrag, off); off += 2;
    resp.writeUInt16LE(maxRecvFrag, off); off += 2;
    resp.writeUInt32LE(assocGroup || 0x53F0, off); off += 4;
    resp.writeUInt16LE(secAddr.length, off); off += 2;
    secAddr.copy(resp, off); off += secAddr.length;
    off += secAddrPad;

    resp[off] = numCtxItems; off += 4;
    for (let i = 0; i < numCtxItems; i++) {
      if (i === 0) {
        resp.writeUInt16LE(0, off); off += 2;
        resp.writeUInt16LE(0, off); off += 2;
        NDR_SYNTAX.copy(resp, off); off += 20;
      } else {
        resp.writeUInt16LE(2, off); off += 2;
        resp.writeUInt16LE(1, off); off += 2;
        off += 20;
      }
    }
    return resp;
  }

  private _handleRequest(data: Buffer): Buffer {
    const callId = data.readUInt32LE(12);
    const contextId = data.readUInt16LE(20);
    const opnum = data.readUInt16LE(22);

    let stubData: Buffer;
    if (opnum === 15) {
      stubData = this._buildShareEnumResponse();
    } else {
      stubData = Buffer.alloc(4);
      stubData.writeUInt32LE(0x00000057, 0);
    }

    const totalSize = 24 + stubData.length;
    const resp = Buffer.alloc(totalSize);
    resp[0] = 5; resp[1] = 0; resp[2] = 2; resp[3] = 0x03;
    resp.writeUInt32LE(0x00000010, 4);
    resp.writeUInt16LE(totalSize, 8);
    resp.writeUInt16LE(0, 10);
    resp.writeUInt32LE(callId, 12);
    resp.writeUInt32LE(stubData.length, 16);
    resp.writeUInt16LE(contextId, 20);
    resp[22] = 0; resp[23] = 0;
    stubData.copy(resp, 24);
    return resp;
  }

  private _buildShareEnumResponse(): Buffer {
    const config = this._smbServer.getServerConfig();
    const sections = config.sections().filter(s => s !== 'global');

    const shares: Array<{ name: string; type: number; remark: string }> = [];
    for (const section of sections) {
      shares.push({
        name: section,
        type: parseInt(config.get(section, 'share type') || '0', 10),
        remark: config.get(section, 'comment') || '',
      });
    }

    const u32 = (v: number): Buffer => {
      const b = Buffer.alloc(4);
      b.writeUInt32LE(v >>> 0, 0);
      return b;
    };

    const ndrString = (str: string): Buffer => {
      const utf16 = Buffer.from(str + '\0', 'utf16le');
      const charCount = utf16.length / 2;
      const parts = [u32(charCount), u32(0), u32(charCount), utf16];
      const pad = (4 - (utf16.length % 4)) % 4;
      if (pad > 0) parts.push(Buffer.alloc(pad));
      return Buffer.concat(parts);
    };

    const bufs: Buffer[] = [];
    const n = shares.length;
    let refId = 1;

    bufs.push(u32(1));
    bufs.push(u32(1));
    bufs.push(u32(refId++));

    bufs.push(u32(n));
    bufs.push(u32(n > 0 ? refId++ : 0));

    if (n > 0) {
      bufs.push(u32(n));
      for (const share of shares) {
        bufs.push(u32(refId++));
        bufs.push(u32(share.type));
        bufs.push(u32(refId++));
      }
      for (const share of shares) {
        bufs.push(ndrString(share.name));
        bufs.push(ndrString(share.remark));
      }
    }

    bufs.push(u32(n));
    bufs.push(u32(refId++));
    bufs.push(u32(0));
    bufs.push(u32(0));

    return Buffer.concat(bufs);
  }
}

export class SMBSERVER extends EventEmitter {
  private _server: net.Server;
  private _serverName: string = '';
  private _serverOS: string = '';
  private _serverDomain: string = '';
  private _challenge: Buffer = Buffer.alloc(8);
  private _serverConfig: ConfigParser;
  private _credentials: Record<string, { uid: number; lmhash: Buffer; nthash: Buffer }> = {};
  private _logFile: string = '';
  private _registeredNamedPipes: Record<string, [string, number]> = {};
  private _builtinPipeHandlers: Record<string, () => BuiltinPipeHandler> = {};
  private _jtrDumpPath: string = '';
  private _smb2Support: boolean = false;
  private _dropSSP: boolean = false;
  private _anonymousLogon: boolean = true;
  private _dumpHashes: boolean = false;
  private _authCallback: ((smbServer: SMBSERVER, connData: ConnectionData) => void) | null = null;
  private _activeConnections: Record<string, ConnectionData> = {};
  private _connectionCounter: number = 0;

  private _smbCommands: Record<number, CommandHandler>;
  private _smbTransCommands: Record<string | number, TransHandler>;
  private _smbTrans2Commands: Record<number, TransHandler>;
  private _smbNTTransCommands: Record<number, TransHandler>;
  private _smb2Commands: Record<number, CommandHandler>;
  private _smb2Ioctls: Record<number, IoctlHandler>;

  constructor(
    private _serverAddress: string = '0.0.0.0',
    private _listenPort: number = 445,
    configParser?: ConfigParser,
  ) {
    super();
    this._serverConfig = configParser || new ConfigParser();

    this._smbTransCommands = {
      '\\PIPE\\LANMAN': TRANSCommands.lanMan,
      [smb.TRANS_TRANSACT_NMPIPE]: TRANSCommands.transactNamedPipe,
    };

    this._smbTrans2Commands = {
      [smb.TRANS2_FIND_FIRST2]: TRANS2Commands.findFirst2,
      [smb.TRANS2_FIND_NEXT2]: TRANS2Commands.findNext2,
      [smb.TRANS2_QUERY_FS_INFORMATION]: TRANS2Commands.queryFsInformation,
      [smb.TRANS2_QUERY_PATH_INFORMATION]: TRANS2Commands.queryPathInformation,
      [smb.TRANS2_QUERY_FILE_INFORMATION]: TRANS2Commands.queryFileInformation,
      [smb.TRANS2_SET_FILE_INFORMATION]: TRANS2Commands.setFileInformation,
      [smb.TRANS2_SET_PATH_INFORMATION]: TRANS2Commands.setPathInformation,
    };

    this._smbNTTransCommands = {
      0xff: (_c, _s, _r, _p, _d, _m) => [Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0), STATUS_NOT_IMPLEMENTED],
    };

    this._smbCommands = {
      [smb.SMB_COMMAND_FLUSH]: SMBCommands.smbComFlush,
      [smb.SMB_COMMAND_CREATE_DIRECTORY]: SMBCommands.smbComCreateDirectory,
      [smb.SMB_COMMAND_DELETE_DIRECTORY]: SMBCommands.smbComDeleteDirectory,
      [smb.SMB_COMMAND_RENAME]: SMBCommands.smbComRename,
      [smb.SMB_COMMAND_DELETE]: SMBCommands.smbComDelete,
      [smb.SMB_COMMAND_NEGOTIATE]: SMBCommands.smbComNegotiate,
      [smb.SMB_COMMAND_SESSION_SETUP]: SMBCommands.smbComSessionSetupAndX,
      [smb.SMB_COMMAND_LOGOFF_ANDX]: SMBCommands.smbComLogOffAndX,
      [smb.SMB_COMMAND_TREE_CONNECT_ANDX]: SMBCommands.smbComTreeConnectAndX,
      [smb.SMB_COMMAND_TREE_DISCONNECT]: SMBCommands.smbComTreeDisconnect,
      [smb.SMB_COMMAND_ECHO]: SMBCommands.smbComEcho,
      [smb.SMB_COMMAND_QUERY_INFORMATION]: SMBCommands.smbQueryInformation,
      [smb.SMB_COMMAND_TRANSACTION2]: (connId: string, srv: SMBSERVER, cmd: any, pkt: any) =>
        SMBCommands.smbTransaction2(connId, srv, cmd, pkt, this._smbTrans2Commands),
      [smb.SMB_COMMAND_TRANSACTION]: (connId: string, srv: SMBSERVER, cmd: any, pkt: any) =>
        SMBCommands.smbTransaction(connId, srv, cmd, pkt, this._smbTransCommands),
      [smb.SMB_COMMAND_NT_TRANSACT]: (connId: string, srv: SMBSERVER, cmd: any, pkt: any) =>
        SMBCommands.smbNTTransact(connId, srv, cmd, pkt, this._smbNTTransCommands),
      [smb.SMB_COMMAND_QUERY_INFORMATION_DISK]: SMBCommands.smbQueryInformationDisk,
      [smb.SMB_COMMAND_OPEN_ANDX]: SMBCommands.smbComOpenAndX,
      [smb.SMB_COMMAND_QUERY_INFORMATION2]: SMBCommands.smbComQueryInformation2,
      [smb.SMB_COMMAND_READ_ANDX]: SMBCommands.smbComReadAndX,
      [smb.SMB_COMMAND_READ]: SMBCommands.smbComRead,
      [smb.SMB_COMMAND_WRITE_ANDX]: SMBCommands.smbComWriteAndX,
      [smb.SMB_COMMAND_WRITE]: SMBCommands.smbComWrite,
      [smb.SMB_COMMAND_CLOSE]: SMBCommands.smbComClose,
      [smb.SMB_COMMAND_LOCKING_ANDX]: SMBCommands.smbComLockingAndX,
      [smb.SMB_COMMAND_NT_CREATE_ANDX]: SMBCommands.smbComNtCreateAndX,
      0xff: SMBCommands.default,
    };

    this._smb2Ioctls = {
      [smb2.FSCTL_DFS_GET_REFERRALS]: Ioctls.fsctlDfsGetReferrals,
      [smb2.FSCTL_PIPE_TRANSCEIVE]: Ioctls.fsctlPipeTransceive,
      [smb2.FSCTL_VALIDATE_NEGOTIATE_INFO]: Ioctls.fsctlValidateNegotiateInfo,
    };

    this._smb2Commands = {
      [smb2.SMB2_NEGOTIATE]: SMB2Commands.smb2Negotiate,
      [smb2.SMB2_SESSION_SETUP]: SMB2Commands.smb2SessionSetup,
      [smb2.SMB2_LOGOFF]: SMB2Commands.smb2Logoff,
      [smb2.SMB2_TREE_CONNECT]: SMB2Commands.smb2TreeConnect,
      [smb2.SMB2_TREE_DISCONNECT]: SMB2Commands.smb2TreeDisconnect,
      [smb2.SMB2_CREATE]: SMB2Commands.smb2Create,
      [smb2.SMB2_CLOSE]: SMB2Commands.smb2Close,
      [smb2.SMB2_FLUSH]: SMB2Commands.smb2Flush,
      [smb2.SMB2_READ]: SMB2Commands.smb2Read,
      [smb2.SMB2_WRITE]: SMB2Commands.smb2Write,
      [smb2.SMB2_LOCK]: SMB2Commands.smb2Lock,
      [smb2.SMB2_IOCTL]: SMB2Commands.smb2Ioctl,
      [smb2.SMB2_CANCEL]: SMB2Commands.smb2Cancel,
      [smb2.SMB2_ECHO]: SMB2Commands.smb2Echo,
      [smb2.SMB2_QUERY_DIRECTORY]: SMB2Commands.smb2QueryDirectory,
      [smb2.SMB2_CHANGE_NOTIFY]: SMB2Commands.smb2ChangeNotify,
      [smb2.SMB2_QUERY_INFO]: SMB2Commands.smb2QueryInfo,
      [smb2.SMB2_SET_INFO]: SMB2Commands.smb2SetInfo,
      0xff: SMB2Commands.default,
    };

    this._server = net.createServer((socket) => this._handleConnection(socket));
  }

  getIoctls(): Record<number, IoctlHandler> {
    return this._smb2Ioctls;
  }

  getCredentials(): Record<string, { uid: number; lmhash: Buffer; nthash: Buffer }> {
    return this._credentials;
  }

  removeConnection(name: string): void {
    delete this._activeConnections[name];
  }

  addConnection(name: string, ip: string, port: number): void {
    this._activeConnections[name] = {
      PacketNum: 0,
      ClientIP: ip,
      ClientPort: port,
      Uid: 0,
      ConnectedShares: {},
      OpenedFiles: {},
      SIDs: {},
      LastRequest: {},
      SignatureEnabled: false,
      SigningChallengeResponse: Buffer.alloc(0),
      SigningSessionKey: Buffer.alloc(0),
      SignSequenceNumber: 0,
      Authenticated: false,
    };
  }

  getActiveConnections(): Record<string, ConnectionData> {
    return this._activeConnections;
  }

  setConnectionData(connId: string, data: ConnectionData): void {
    this._activeConnections[connId] = data;
  }

  getConnectionData(connId: string, checkStatus: boolean = true): ConnectionData {
    const conn = this._activeConnections[connId];
    if (!conn) throw new Error(`Connection ${connId} not found`);
    return conn;
  }

  getRegisteredNamedPipes(): Record<string, [string, number]> {
    return this._registeredNamedPipes;
  }

  registerNamedPipe(pipeName: string, address: [string, number]): void {
    this._registeredNamedPipes[pipeName] = address;
  }

  unregisterNamedPipe(pipeName: string): void {
    delete this._registeredNamedPipes[pipeName];
  }

  registerBuiltinPipe(pipeName: string, factory: () => BuiltinPipeHandler): void {
    this._builtinPipeHandlers[pipeName] = factory;
  }

  getBuiltinPipeHandlers(): Record<string, () => BuiltinPipeHandler> {
    return this._builtinPipeHandlers;
  }

  hookSmbCommand(smbCommand: number, callback: CommandHandler): CommandHandler | undefined {
    const original = this._smbCommands[smbCommand];
    this._smbCommands[smbCommand] = callback;
    return original;
  }

  unregisterSmbCommand(smbCommand: number): void {
    delete this._smbCommands[smbCommand];
  }

  hookSmb2Command(smb2Command: number, callback: CommandHandler): CommandHandler | undefined {
    const original = this._smb2Commands[smb2Command];
    this._smb2Commands[smb2Command] = callback;
    return original;
  }

  unregisterSmb2Command(smb2Command: number): void {
    delete this._smb2Commands[smb2Command];
  }

  hookTransaction(transCommand: string | number, callback: TransHandler): TransHandler | undefined {
    const original = this._smbTransCommands[transCommand];
    this._smbTransCommands[transCommand] = callback;
    return original as TransHandler | undefined;
  }

  unregisterTransaction(transCommand: string | number): void {
    delete this._smbTransCommands[transCommand];
  }

  hookTransaction2(transCommand: number, callback: TransHandler): TransHandler | undefined {
    const original = this._smbTrans2Commands[transCommand];
    this._smbTrans2Commands[transCommand] = callback;
    return original;
  }

  unregisterTransaction2(transCommand: number): void {
    delete this._smbTrans2Commands[transCommand];
  }

  hookNTTransaction(transCommand: number, callback: TransHandler): TransHandler | undefined {
    const original = this._smbNTTransCommands[transCommand];
    this._smbNTTransCommands[transCommand] = callback;
    return original;
  }

  unregisterNTTransaction(transCommand: number): void {
    delete this._smbNTTransCommands[transCommand];
  }

  log(msg: string, level: string = 'info'): void {
    if (level === 'error') console.error(msg);
    else if (level === 'warn') console.warn(msg);
    else if (level === 'debug') console.debug(msg);
    else console.log(msg);
  }

  getServerName(): string { return this._serverName; }
  getServerOS(): string { return this._serverOS; }
  getServerDomain(): string { return this._serverDomain; }
  getSMBChallenge(): Buffer { return this._challenge; }
  getServerConfig(): ConfigParser { return this._serverConfig; }
  setServerConfig(config: ConfigParser): void { this._serverConfig = config; }
  getJTRdumpPath(): string { return this._jtrDumpPath; }
  getDumpHashes(): boolean { return this._dumpHashes; }
  getSMB2Support(): boolean { return this._smb2Support; }
  getDropSSP(): boolean { return this._dropSSP; }
  getAnonymousLogon(): boolean { return this._anonymousLogon; }

  getAuthCallback(): ((smbServer: SMBSERVER, connData: ConnectionData) => void) | null {
    return this._authCallback;
  }

  setAuthCallback(callback: ((smbServer: SMBSERVER, connData: ConnectionData) => void) | null): void {
    this._authCallback = callback;
  }

  signSMBv1(connData: ConnectionData, packet: any, signingSessionKey: Buffer, signingChallengeResponse: Buffer): void {
    (packet as Structure).set('SecurityFeatures', Buffer.alloc(8));
    const packetData = (packet as Structure).getData();

    const toSign = Buffer.concat([
      signingSessionKey,
      signingChallengeResponse,
      packetData,
    ]);

    const signature = crypto.createHash('md5').update(toSign).digest().subarray(0, 8);
    (packet as Structure).set('SecurityFeatures', signature);

    connData.SignSequenceNumber += 2;
  }

  signSMBv2(packet: any, signingSessionKey: Buffer, _padLength: number = 0): void {
    const flags = (packet as Structure).get('Flags') as number;
    (packet as Structure).set('Flags', flags | smb2.SMB2_FLAGS_SIGNED);
    (packet as Structure).set('Signature', Buffer.alloc(16));

    const packetData = (packet as Structure).getData();
    const signature = crypto.createHmac('sha256', signingSessionKey)
      .update(packetData)
      .digest()
      .subarray(0, 16);

    (packet as Structure).set('Signature', signature);
  }

  processRequest(connId: string, data: Buffer): Buffer[] {
    const responses: Buffer[] = [];

    try {
      const packet = new smb.NewSMBPacket();
      packet.fromString(data);

      const connData = this._activeConnections[connId];
      if (!connData) return responses;

      const commands = [packet];
      const smbCommand = new smb.SMBCommand();
      smbCommand.fromString((packet.get('Data') as Buffer[])[0]!);

      const commandCode = packet.get('Command') as number;

      if (commandCode !== smb.SMB_COMMAND_NEGOTIATE &&
          commandCode !== smb.SMB_COMMAND_SESSION_SETUP &&
          connData.Authenticated === false) {
        return responses;
      }

      const handler = this._smbCommands[commandCode] || this._smbCommands[0xff];

      const [respCommands, respPacketOverride, errorCode] = handler(connId, this, smbCommand, packet);

      if (respPacketOverride) {
        const respData = (respPacketOverride as Structure).getData();
        responses.push(respData);
        return responses;
      }

      if (respCommands && respCommands.length > 0) {
        const respPacket = new smb.NewSMBPacket();
        respPacket.set('Flags1', smb.FLAGS1_REPLY | smb.FLAGS1_PATHCASELESS);
        respPacket.set('Flags2', smb.FLAGS2_EXTENDED_SECURITY | smb.FLAGS2_NT_STATUS | smb.FLAGS2_LONG_NAMES | smb.FLAGS2_UNICODE);
        respPacket.set('Tid', packet.get('Tid') as number);
        respPacket.set('Mid', packet.get('Mid') as number);
        respPacket.set('Uid', connData.Uid);
        respPacket.set('Pid', packet.get('Pid') as number);

        if (errorCode > 0) {
          respPacket.set('ErrorCode', errorCode >>> 16);
          respPacket.set('_reserved', 0);
          respPacket.set('ErrorClass', errorCode & 0xffff);
        }

        for (const cmd of respCommands) {
          respPacket.addCommand(cmd as smb.SMBCommand);
        }

        const updatedConn = this._activeConnections[connId];
        if (updatedConn?.SignatureEnabled) {
          this.signSMBv1(updatedConn, respPacket, updatedConn.SigningSessionKey, updatedConn.SigningChallengeResponse);
        }

        responses.push(respPacket.getData());
      }

      return responses;
    } catch (e1) {
      // Try SMB2 — log SMB1 error for debugging
      if (data.length >= 4 && data[0] === 0xff && data[1] === 0x53) {
        console.error('SMB1 handler error:', e1);
      }
    }

    try {
      const packet = new smb2.SMB2Packet();
      packet.fromString(data);

      const connData = this._activeConnections[connId];
      if (!connData) return responses;

      const commandCode = packet.get('Command') as number;

      if (commandCode !== smb2.SMB2_NEGOTIATE &&
          commandCode !== smb2.SMB2_SESSION_SETUP &&
          !connData.Authenticated) {
        return responses;
      }

      let offset = 0;
      const totalData = data;

      while (offset < totalData.length) {
        const currentData = totalData.subarray(offset);
        const currentPacket = new smb2.SMB2Packet();
        currentPacket.fromString(currentData);

        const cmd = currentPacket.get('Command') as number;
        const handler = this._smb2Commands[cmd] || this._smb2Commands[0xff];

        if (handler) {
          const [_respCmds, respPacket, errorCode] = handler(connId, this, currentPacket);

          if (respPacket) {
            const updatedConn = this._activeConnections[connId];
            if (updatedConn?.SignatureEnabled &&
                cmd !== smb2.SMB2_NEGOTIATE &&
                cmd !== smb2.SMB2_SESSION_SETUP) {
              this.signSMBv2(respPacket, updatedConn.SigningSessionKey);
            }
            responses.push((respPacket as Structure).getData());
          }
        }

        const nextCommand = currentPacket.get('NextCommand') as number;
        if (nextCommand > 0) {
          offset += nextCommand;
        } else {
          break;
        }
      }
    } catch (e) {
      if (!(data.length >= 4 && data[0] === 0xff && data[1] === 0x53)) {
        console.error('processRequest error:', e);
      }
    }

    return responses;
  }

  processConfigFile(configFile?: string): void {
    if (configFile) {
      this._serverConfig.read(configFile);
    }

    const config = this._serverConfig;

    if (config.hasOption('global', 'server_name')) {
      this._serverName = config.get('global', 'server_name') || '';
    }
    if (config.hasOption('global', 'server_os')) {
      this._serverOS = config.get('global', 'server_os') || '';
    }
    if (config.hasOption('global', 'server_domain')) {
      this._serverDomain = config.get('global', 'server_domain') || '';
    }
    if (config.hasOption('global', 'log_file')) {
      this._logFile = config.get('global', 'log_file') || '';
    }
    if (config.hasOption('global', 'challenge')) {
      const challengeHex = config.get('global', 'challenge') || '';
      if (challengeHex.length > 0) {
        this._challenge = Buffer.from(challengeHex, 'hex');
      }
    }
    if (config.hasOption('global', 'jtr_dump_path')) {
      this._jtrDumpPath = config.get('global', 'jtr_dump_path') || '';
    }
    if (config.hasOption('global', 'dump_hashes')) {
      this._dumpHashes = config.getboolean('global', 'dump_hashes');
    }
    if (config.hasOption('global', 'SMB2Support')) {
      this._smb2Support = config.getboolean('global', 'SMB2Support');
    }
    if (config.hasOption('global', 'DropSSP')) {
      this._dropSSP = config.getboolean('global', 'DropSSP');
    }
    if (config.hasOption('global', 'anonymous_logon')) {
      this._anonymousLogon = config.getboolean('global', 'anonymous_logon');
    }

    if (config.hasOption('global', 'credentials_file')) {
      const credFile = config.get('global', 'credentials_file') || '';
      if (credFile && fs.existsSync(credFile)) {
        const lines = fs.readFileSync(credFile, 'utf-8').split('\n');
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#')) continue;
          const parts = trimmed.split(':');
          if (parts.length >= 4) {
            this.addCredential(parts[0]!, parseInt(parts[1]!, 10), parts[2]!, parts[3]!);
          }
        }
      }
    }
  }

  addCredential(name: string, uid: number, lmhash: string | Buffer, nthash: string | Buffer): void {
    let lm: Buffer;
    let nt: Buffer;

    if (typeof lmhash === 'string') {
      lm = lmhash.length === 32 ? Buffer.from(lmhash, 'hex') : Buffer.from(lmhash);
    } else {
      lm = lmhash;
    }

    if (typeof nthash === 'string') {
      nt = nthash.length === 32 ? Buffer.from(nthash, 'hex') : Buffer.from(nthash);
    } else {
      nt = nthash;
    }

    this._credentials[name.toLowerCase()] = { uid, lmhash: lm, nthash: nt };
  }

  listen(port?: number, host?: string): void {
    const p = port ?? this._listenPort;
    const h = host ?? this._serverAddress;
    this._server.listen(p, h, () => {
      this.emit('listening', { port: p, host: h });
    });
  }

  serveForever(): void {
    this.listen();
  }

  close(): void {
    this._server.close();
    for (const connId of Object.keys(this._activeConnections)) {
      this.removeConnection(connId);
    }
  }

  serverClose(): void {
    this.close();
  }

  private _handleConnection(socket: net.Socket): void {
    const connId = `conn_${++this._connectionCounter}`;
    const address = socket.remoteAddress || '0.0.0.0';
    const port = socket.remotePort || 0;

    this.addConnection(connId, address, port);
    this.emit('connection', { connId, address, port });

    let buffer = Buffer.alloc(0);
    let firstPacket = true;

    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);

      while (buffer.length >= 4) {
        const type = buffer[0]!;
        const length = ((buffer[1]! & 0x01) << 16) | buffer.readUInt16BE(2);

        if (buffer.length < 4 + length) break;

        const payload = Buffer.from(buffer.subarray(4, 4 + length));
        buffer = buffer.subarray(4 + length);

        if (type === nmb.NETBIOS_SESSION_REQUEST) {
          const positiveResponse = Buffer.alloc(4);
          positiveResponse[0] = nmb.NETBIOS_SESSION_POSITIVE_RESPONSE;
          socket.write(positiveResponse);
        } else if (type === nmb.NETBIOS_SESSION_MESSAGE || type === 0) {
          try {
            const responses = this.processRequest(connId, payload);
            for (const resp of responses) {
              const header = Buffer.alloc(4);
              header[0] = 0x00;
              header[1] = (resp.length >> 16) & 0x01;
              header.writeUInt16BE(resp.length & 0xffff, 2);
              socket.write(Buffer.concat([header, resp]));
            }
          } catch (e) {
            console.error(`Error processing request from ${address}:${port}:`, e);
          }
        } else if (type === nmb.NETBIOS_SESSION_KEEP_ALIVE) {
          // ignore keep-alives
        }
      }
    });

    socket.on('error', (err) => {
      console.debug(`Connection error from ${address}:${port}: ${err.message}`);
    });

    socket.on('close', () => {
      this.removeConnection(connId);
    });

    socket.setTimeout(300000, () => {
      socket.destroy();
    });
  }
}

export class SimpleSMBServer extends EventEmitter {
  private _server: SMBSERVER;
  private _config: ConfigParser;

  constructor(
    listenAddress: string = '0.0.0.0',
    listenPort: number = 445,
    configFile: string = '',
  ) {
    super();

    this._config = new ConfigParser();

    if (!configFile) {
      const randomName = () => {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        let result = '';
        for (let i = 0; i < 8; i++) {
          result += chars[Math.floor(Math.random() * chars.length)];
        }
        return result;
      };

      this._config.addSection('global');
      this._config.set('global', 'server_name', randomName());
      this._config.set('global', 'server_os', 'UNIX');
      this._config.set('global', 'server_domain', 'WORKGROUP');
      this._config.set('global', 'log_file', 'None');
      this._config.set('global', 'credentials_file', '');
      this._config.set('global', 'SMB2Support', 'True');
      this._config.set('global', 'jtr_dump_path', '');
      this._config.set('global', 'dump_hashes', 'false');
      this._config.set('global', 'challenge', '4141414141414141');
      this._config.set('global', 'anonymous_logon', 'true');
      this._config.set('global', 'rpc_apis', 'yes');

      this._config.addSection('IPC$');
      this._config.set('IPC$', 'comment', '');
      this._config.set('IPC$', 'read only', 'yes');
      this._config.set('IPC$', 'share type', '3');
      this._config.set('IPC$', 'path', '');
    } else {
      this._config.read(configFile);
    }

    this._server = new SMBSERVER(listenAddress, listenPort, this._config);
    this._server.processConfigFile();

    if (this._config.get('global', 'rpc_apis') !== 'no') {
      this._server.registerBuiltinPipe('srvsvc', () => new SrvsvcPipeHandler(this._server));
    }
  }

  getServer(): SMBSERVER {
    return this._server;
  }

  start(): void {
    this._server.serveForever();
  }

  stop(): void {
    this._server.close();
  }

  registerNamedPipe(pipeName: string, address: [string, number]): void {
    this._server.registerNamedPipe(pipeName, address);
  }

  unregisterNamedPipe(pipeName: string): void {
    this._server.unregisterNamedPipe(pipeName);
  }

  getRegisteredNamedPipes(): Record<string, [string, number]> {
    return this._server.getRegisteredNamedPipes();
  }

  addShare(
    shareName: string, sharePath: string,
    shareComment: string = '', shareType: string = '0',
    readOnly: string = 'no',
  ): void {
    this._config.addSection(shareName);
    this._config.set(shareName, 'comment', shareComment);
    this._config.set(shareName, 'read only', readOnly);
    this._config.set(shareName, 'share type', shareType);
    this._config.set(shareName, 'path', sharePath);
    this._server.setServerConfig(this._config);
  }

  removeShare(shareName: string): void {
    this._config.removeSection(shareName);
    this._server.setServerConfig(this._config);
  }

  setSMBChallenge(challenge: string): void {
    this._config.set('global', 'challenge', challenge);
    this._server.processConfigFile();
  }

  setLogFile(logFile: string): void {
    this._config.set('global', 'log_file', logFile);
    this._server.processConfigFile();
  }

  setCredentialsFile(credFile: string): void {
    this._config.set('global', 'credentials_file', credFile);
    this._server.processConfigFile();
  }

  addCredential(name: string, uid: number, lmhash: string, nthash: string): void {
    this._server.addCredential(name, uid, lmhash, nthash);
  }

  setSMB2Support(value: boolean): void {
    this._config.set('global', 'SMB2Support', value ? 'True' : 'False');
    this._server.processConfigFile();
  }

  getAuthCallback(): ((smbServer: SMBSERVER, connData: ConnectionData) => void) | null {
    return this._server.getAuthCallback();
  }

  setAuthCallback(callback: ((smbServer: SMBSERVER, connData: ConnectionData) => void) | null): void {
    this._server.setAuthCallback(callback);
  }

  setDropSSP(value: boolean): void {
    this._config.set('global', 'DropSSP', value ? 'True' : 'False');
    this._server.processConfigFile();
  }
}

export {
  ConfigParser,
  SMBCommands,
  SMB2Commands,
  TRANS2Commands,
  TRANSCommands,
  Ioctls,
  computeNTLMv2,
  outputToJohnFormat,
  writeJohnOutputToFile,
  decodeSMBString,
  encodeSMBString,
  getFileTime,
  getUnixTime,
  getSMBDate,
  getSMBTime,
  getShares,
  searchShare,
  normalizePath,
  isInFileJail,
  openFile,
  queryFsInformation,
  findFirst2,
  queryPathInformation,
  queryFileInformation,
  queryDiskInformation,
  VOID_FILE_DESCRIPTOR,
  PIPE_FILE_DESCRIPTOR,
  STATUS_SMB_BAD_UID,
  STATUS_SMB_BAD_TID,
};

export type {
  ConnectionData,
  OpenedFile,
  ShareInfo,
  CommandHandler,
  TransHandler,
  IoctlHandler,
};
