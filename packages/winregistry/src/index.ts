/**
 * @impacket/winregistry - TypeScript port of impacket/winregistry.py
 *
 * Windows Registry Hive Parser.
 * Supports both binary hive files (SAM, SYSTEM, SECURITY) and .reg export format.
 *
 * Reference:
 *   https://bazaar.launchpad.net/~guadalinex-members/dumphive/trunk/view/head:/winreg.txt
 *   http://sentinelchicken.com/data/TheWindowsNTRegistryFileFormat.pdf
 */

import { Buffer } from 'node:buffer';
import * as fs from 'node:fs';
import { Structure, hexdump } from '@impacket/structure';
import type { FieldDescriptor } from '@impacket/structure';

// ─── Constants ───────────────────────────────────────────────────────────────

export const ROOT_KEY      = 0x2c;
export const REG_NONE      = 0x00;
export const REG_SZ        = 0x01;
export const REG_EXPAND_SZ = 0x02;
export const REG_BINARY    = 0x03;
export const REG_DWORD     = 0x04;
export const REG_MULTISZ   = 0x07;
export const REG_QWORD     = 0x0b;

// ─── NT-path helpers ─────────────────────────────────────────────────────────

function ntDirname(p: string): string {
  const i = p.lastIndexOf('\\');
  return i < 0 ? '' : p.substring(0, i);
}

function ntBasename(p: string): string {
  const i = p.lastIndexOf('\\');
  return i < 0 ? p : p.substring(i + 1);
}

// ─── File I/O abstraction ────────────────────────────────────────────────────

/** File-like interface for reading/writing registry hive data. */
export interface FileIO {
  read(n: number): Buffer;
  seek(offset: number, whence?: number): void;
  write(data: Buffer): number;
  close(): void;
  open?(): void;
}

/** Local file wrapper implementing FileIO with a tracked position. */
class LocalFileIO implements FileIO {
  private fd: number;
  private pos = 0;

  constructor(path: string, flags: fs.OpenMode = 'r+') {
    this.fd = fs.openSync(path, flags);
  }

  read(n: number): Buffer {
    if (n <= 0) return Buffer.alloc(0);
    const buf = Buffer.alloc(n);
    const bytesRead = fs.readSync(this.fd, buf, 0, n, this.pos);
    this.pos += bytesRead;
    return buf.subarray(0, bytesRead);
  }

  seek(offset: number, whence = 0): void {
    if (whence === 0) this.pos = offset;
    else if (whence === 1) this.pos += offset;
  }

  write(data: Buffer): number {
    const written = fs.writeSync(this.fd, data, 0, data.length, this.pos);
    this.pos += written;
    return written;
  }

  close(): void {
    try {
      fs.closeSync(this.fd);
    } catch {
      // already closed
    }
  }
}

// ─── Structure classes ───────────────────────────────────────────────────────

export class REG_REGF extends Structure {
  static structure: FieldDescriptor[] = [
    ['Magic',             '"regf'],
    ['Unknown',           '<L=0'],
    ['Unknown2',          '<L=0'],
    ['lastChange',        '<Q=0'],
    ['MajorVersion',      '<L=0'],
    ['MinorVersion',      '<L=0'],
    ['0',                 '<L=0'],
    ['11',                '<L=0'],
    ['OffsetFirstRecord', '<L=0'],
    ['DataSize',          '<L=0'],
    ['1111',              '<L=0'],
    ['Name',              '48s=""'],
    ['Remaining1',        '411s=b""'],
    ['CheckSum',          '<L=0xffffffff'],
    ['Remaining2',        '3585s=b""'],
  ];
}

export class REG_HBIN extends Structure {
  static structure: FieldDescriptor[] = [
    ['Magic',            '"hbin'],
    ['OffsetFirstHBin',  '<L=0'],
    ['OffsetNextHBin',   '<L=0'],
    ['BlockSize',        '<L=0'],
  ];
}

export class REG_HBINBLOCK extends Structure {
  static structure: FieldDescriptor[] = [
    ['DataBlockSize', '<l=0'],
    ['_Data',         '_-Data', 'self["DataBlockSize"]*(-1)-4'],
    ['Data',          ':'],
  ];
}

export class REG_NK extends Structure {
  static structure: FieldDescriptor[] = [
    ['Magic',           '"nk'],
    ['Type',            '<H=0'],
    ['lastChange',      '<Q=0'],
    ['Unknown',         '<L=0'],
    ['OffsetParent',    '<l=0'],
    ['NumSubKeys',      '<L=0'],
    ['Unknown2',        '<L=0'],
    ['OffsetSubKeyLf',  '<l=0'],
    ['Unknown3',        '<L=0'],
    ['NumValues',       '<L=0'],
    ['OffsetValueList', '<l=0'],
    ['OffsetSkRecord',  '<l=0'],
    ['OffsetClassName', '<l=0'],
    ['UnUsed',          '20s=b""'],
    ['NameLength',      '<H=0'],
    ['ClassNameLength', '<H=0'],
    ['_KeyName',        '_-KeyName', 'self["NameLength"]'],
    ['KeyName',         ':'],
  ];
}

export class REG_VK extends Structure {
  static structure: FieldDescriptor[] = [
    ['Magic',      '"vk'],
    ['NameLength', '<H=0'],
    ['DataLen',    '<l=0'],
    ['OffsetData', '<L=0'],
    ['ValueType',  '<L=0'],
    ['Flag',       '<H=0'],
    ['UnUsed',     '<H=0'],
    ['_Name',      '_-Name', 'self["NameLength"]'],
    ['Name',       ':'],
  ];
}

export class REG_LF extends Structure {
  static structure: FieldDescriptor[] = [
    ['Magic',       '"lf'],
    ['NumKeys',     '<H=0'],
    ['HashRecords', ':'],
  ];
}

export class REG_LH extends Structure {
  static structure: FieldDescriptor[] = [
    ['Magic',       '"lh'],
    ['NumKeys',     '<H=0'],
    ['HashRecords', ':'],
  ];
}

export class REG_RI extends Structure {
  static structure: FieldDescriptor[] = [
    ['Magic',       '"ri'],
    ['NumKeys',     '<H=0'],
    ['HashRecords', ':'],
  ];
}

export class REG_SK extends Structure {
  static structure: FieldDescriptor[] = [
    ['Magic',            '"sk'],
    ['UnUsed',           '<H=0'],
    ['OffsetPreviousSk', '<l=0'],
    ['OffsetNextSk',     '<l=0'],
    ['UsageCounter',     '<L=0'],
    ['SizeSk',           '<L=0'],
    ['Data',             ':'],
  ];
}

export class REG_HASH extends Structure {
  static structure: FieldDescriptor[] = [
    ['OffsetNk', '<L=0'],
    ['KeyName',  '4s=b""'],
  ];
}

/** Map magic bytes to their corresponding structure class. */
type StructClass = new (data?: Buffer | null, alignment?: number) => Structure;

const StructMappings: Record<string, StructClass> = {
  'nk': REG_NK,
  'vk': REG_VK,
  'lf': REG_LF,
  'lh': REG_LH,
  'ri': REG_RI,
  'sk': REG_SK,
};

// ─── Abstract Registry base ─────────────────────────────────────────────────

export abstract class Registry {
  fd?: FileIO;

  close(): void {
    if (this.fd) {
      this.fd.close();
      this.fd = undefined;
    }
  }

  abstract walk(parentKey: string): void;
  abstract findKey(key: string): Structure | string | null;
  abstract printValue(valueType: number, valueData: Buffer | number | string): void;
  abstract enumKey(parentKey: Structure | string): string[];
  abstract enumValues(key: Structure | string): Buffer[] | null;
  abstract getValue(
    keyValue: string,
    valueName?: string,
  ): [number, Buffer | number | string] | null;
  abstract getClass(className: string): Buffer | null;
}

// ─── SaveRegistryParser (binary hive files) ──────────────────────────────────

export class SaveRegistryParser extends Registry {
  private hive: string | FileIO;
  private regf: REG_REGF;
  indent = '';
  rootKey: REG_NK | null = null;

  constructor(hive: string | FileIO, isRemote = false) {
    super();
    this.hive = hive;
    if (isRemote) {
      this.fd = hive as FileIO;
      this.fd.open?.();
    } else {
      this.fd = new LocalFileIO(hive as string, 'r+');
    }
    const data = this.fd.read(4096);
    this.regf = new REG_REGF(data);
    this.indent = '';
    this.rootKey = this.findRootKey();

    if (this.rootKey === null) {
      console.error("Can't find root key!");
    } else if (
      (this.regf.get('MajorVersion') as number) !== 1 &&
      (this.regf.get('MinorVersion') as number) > 5
    ) {
      console.warn(
        `Unsupported version (${this.regf.get('MajorVersion')}.${this.regf.get('MinorVersion')}) - things might not work!`,
      );
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  private findRootKey(): REG_NK | null {
    this.fd!.seek(0, 0);
    let data = this.fd!.read(4096);
    while (data.length > 0) {
      try {
        const hbin = new REG_HBIN(data.subarray(0, 0x20));
        const extra = Math.max(0, (hbin.get('OffsetNextHBin') as number) - 4096);
        if (extra > 0) {
          data = Buffer.concat([data, this.fd!.read(extra)]);
        }
        const blockData = data.subarray(0x20);
        const blocks = this.processDataBlocks(blockData);
        for (const block of blocks) {
          if (block instanceof REG_NK) {
            if ((block.get('Type') as number) === ROOT_KEY) {
              return block;
            }
          }
        }
      } catch {
        // ignore parse errors, try next block
      }
      data = this.fd!.read(4096);
    }
    return null;
  }

  private getBlock(offset: number): Structure | null {
    this.fd!.seek(4096 + offset, 0);
    const sizeBytes = this.fd!.read(4);
    if (sizeBytes.length < 4) return null;
    const size = sizeBytes.readInt32LE(0);
    const remaining = size * -1 - 4;
    if (remaining <= 0) return null;
    const rest = this.fd!.read(remaining);
    const data = Buffer.concat([sizeBytes, rest]);
    if (data.length === 0) return null;

    const block = new REG_HBINBLOCK(data);
    const blockData = block.get('Data') as Buffer;
    if (blockData && blockData.length >= 2) {
      const magic = blockData.subarray(0, 2).toString('latin1');
      if (magic in StructMappings) {
        return new StructMappings[magic]!(blockData);
      }
      console.debug(`Unknown type 0x${blockData.subarray(0, 2).toString('hex')}`);
    }
    return block;
  }

  private getValueBlocks(offset: number, count: number): Structure[] {
    const valueList: number[] = [];
    const res: Structure[] = [];
    this.fd!.seek(4096 + offset, 0);
    for (let i = 0; i < count; i++) {
      const buf = this.fd!.read(4);
      if (buf.length < 4) break;
      valueList.push(buf.readInt32LE(0));
    }
    for (const valueOffset of valueList) {
      if (valueOffset > 0) {
        const block = this.getBlock(valueOffset);
        if (block) res.push(block);
      }
    }
    return res;
  }

  private getDataRaw(offset: number, count: number): Buffer {
    this.fd!.seek(4096 + offset, 0);
    return this.fd!.read(count).subarray(4);
  }

  private setDataRaw(offset: number, value: Buffer): number {
    this.fd!.seek(4096 + offset + 4, 0);
    return this.fd!.write(value);
  }

  private processDataBlocks(data: Buffer): Structure[] {
    const res: Structure[] = [];
    let remaining = data;
    while (remaining.length > 4) {
      const blockSize = remaining.readInt32LE(0);
      const block = new REG_HBINBLOCK();
      if (blockSize > 0) {
        // Free block: use positive-size formula
        const newStructure: FieldDescriptor[] = [
          ['DataBlockSize', '<l=0'],
          ['_Data', '_-Data', 'self["DataBlockSize"]-4'],
          ['Data', ':'],
        ];
        block.structure = newStructure;
      }
      block.fromString(remaining);
      const blockLen = block.length;

      const blockData = block.get('Data') as Buffer;
      if (blockData && blockData.length >= 2) {
        const magic = blockData.subarray(0, 2).toString('latin1');
        if (magic in StructMappings) {
          res.push(new StructMappings[magic]!(blockData));
        } else {
          res.push(block);
        }
      } else {
        res.push(block);
      }

      remaining = remaining.subarray(blockLen);
    }
    return res;
  }

  private getValueData(rec: Structure): Buffer | number | string {
    const dataLen = rec.get('DataLen') as number;
    if (dataLen === 0) return '';
    if (dataLen < 0) {
      // Value is stored inline in the OffsetData field
      return rec.get('OffsetData') as number;
    }
    return this.getDataRaw(rec.get('OffsetData') as number, dataLen + 4);
  }

  private setValueData(rec: Structure, value: Buffer): number {
    const dataLen = rec.get('DataLen') as number;
    if (value.length !== dataLen) {
      console.debug(
        `Invalid value length received by setValueData. Expected: ${dataLen} - Got: ${value.length}`,
      );
      throw new Error(
        'Setting key values with differing lengths is not implemented.',
      );
    }
    if (dataLen === 0) {
      console.debug('Received 0 length input for setValueData.');
      return 0;
    }
    return this.setDataRaw(rec.get('OffsetData') as number, value);
  }

  private getLhHash(key: string): number {
    let res = 0;
    for (const ch of key.toUpperCase()) {
      res = (res * 37 + ch.charCodeAt(0)) % 0x100000000;
    }
    return res;
  }

  private compareHash(
    magic: string,
    hashData: Buffer,
    key: string,
  ): number | null {
    if (magic === 'lf') {
      const hashRec = new REG_HASH(hashData);
      const keyName = hashRec.get('KeyName') as Buffer;
      // Strip trailing null bytes from the 4-byte key name field
      const nullIdx = keyName.indexOf(0);
      const stripped =
        nullIdx >= 0 ? keyName.subarray(0, nullIdx) : keyName;
      if (stripped.equals(Buffer.from(key.slice(0, 4), 'latin1'))) {
        return hashRec.get('OffsetNk') as number;
      }
    } else if (magic === 'lh') {
      const hashRec = new REG_HASH(hashData);
      const keyNameBuf = hashRec.get('KeyName') as Buffer;
      const hashVal = keyNameBuf.readUInt32LE(0);
      if (hashVal === this.getLhHash(key)) {
        return hashRec.get('OffsetNk') as number;
      }
    } else if (magic === 'ri') {
      // Special case: ri pointing directly to an NK
      const offset = hashData.readUInt32LE(0);
      const nk = this.getBlock(offset);
      if (nk && (nk.get('KeyName') as Buffer).toString('utf-8') === key) {
        return offset;
      }
    } else {
      console.error(`UNKNOWN Magic ${magic}`);
      throw new Error(`Unknown magic: ${magic}`);
    }
    return null;
  }

  private findSubKey(
    parentKey: Structure,
    subKey: string,
  ): Structure | null {
    const lf = this.getBlock(parentKey.get('OffsetSubKeyLf') as number);
    if (lf !== null) {
      let data = lf.get('HashRecords') as Buffer;
      const lfMagic = lf.get('Magic') as string;

      // ri records point to lf/lh sub-lists; collect their hash records
      if (lfMagic === 'ri') {
        let records = Buffer.alloc(0);
        const numKeys = lf.get('NumKeys') as number;
        for (let i = 0; i < numKeys; i++) {
          const offset = data.readUInt32LE(0);
          const l = this.getBlock(offset)!;
          const lHashRecs = l.get('HashRecords') as Buffer;
          const lNumKeys = l.get('NumKeys') as number;
          records = Buffer.concat([
            records,
            lHashRecs.subarray(0, lNumKeys * 8),
          ]);
          data = data.subarray(4);
        }
        data = records;
      }

      const numSubKeys = parentKey.get('NumSubKeys') as number;
      for (let record = 0; record < numSubKeys; record++) {
        const hashRec = data.subarray(0, 8);
        const res = this.compareHash(lfMagic, hashRec, subKey);
        if (res !== null) {
          // Hash matched; verify the full key name
          const nk = this.getBlock(res);
          if (
            nk &&
            (nk.get('KeyName') as Buffer).toString('utf-8') === subKey
          ) {
            return nk;
          }
        }
        data = data.subarray(8);
      }
    }
    return null;
  }

  private walkSubNodes(rec: Structure): void {
    const nkOrLf = this.getBlock(rec.get('OffsetNk') as number);
    let lf: Structure | null;

    if (nkOrLf instanceof REG_NK) {
      console.log(
        `${this.indent}${(nkOrLf.get('KeyName') as Buffer).toString('utf-8')}`,
      );
      this.indent += '  ';
      if ((nkOrLf.get('OffsetSubKeyLf') as number) < 0) {
        this.indent = this.indent.slice(0, -2);
        return;
      }
      lf = this.getBlock(nkOrLf.get('OffsetSubKeyLf') as number);
    } else {
      lf = nkOrLf;
    }

    if (!lf) return;
    let data = lf.get('HashRecords') as Buffer;
    const lfMagic = lf.get('Magic') as string;

    if (lfMagic === 'ri') {
      let records = Buffer.alloc(0);
      const numKeys = lf.get('NumKeys') as number;
      for (let i = 0; i < numKeys; i++) {
        const offset = data.readUInt32LE(0);
        const l = this.getBlock(offset)!;
        const lHashRecs = l.get('HashRecords') as Buffer;
        const lNumKeys = l.get('NumKeys') as number;
        records = Buffer.concat([
          records,
          lHashRecs.subarray(0, lNumKeys * 8),
        ]);
        data = data.subarray(4);
      }
      data = records;
    }

    const numKeys = lf.get('NumKeys') as number;
    for (let k = 0; k < numKeys; k++) {
      const hashRec = new REG_HASH(data.subarray(0, 8));
      this.walkSubNodes(hashRec);
      data = data.subarray(8);
    }

    if (nkOrLf instanceof REG_NK) {
      this.indent = this.indent.slice(0, -2);
    }
  }

  // ── Public API ───────────────────────────────────────────────────────────

  walk(parentKey: string): void {
    const key = this.findKey(parentKey);
    if (key === null || !(key instanceof Structure)) return;
    if ((key.get('OffsetSubKeyLf') as number) < 0) return;

    const lf = this.getBlock(key.get('OffsetSubKeyLf') as number);
    if (!lf) return;
    let data = lf.get('HashRecords') as Buffer;
    const numKeys = lf.get('NumKeys') as number;
    for (let record = 0; record < numKeys; record++) {
      const hashRec = new REG_HASH(data.subarray(0, 8));
      this.walkSubNodes(hashRec);
      data = data.subarray(8);
    }
  }

  findKey(key: string): Structure | null {
    // Strip leading '\' except when asking for root node only
    let k = key;
    if (k[0] === '\\' && k.length > 1) {
      k = k.substring(1);
    }

    let parentKey: Structure | null = this.rootKey;
    if (parentKey === null) return null;

    if (k.length > 0 && k[0] !== '\\') {
      for (const subKey of k.split('\\')) {
        const res = this.findSubKey(parentKey, subKey);
        if (res !== null) {
          parentKey = res;
        } else {
          return null;
        }
      }
    }
    return parentKey;
  }

  printValue(
    valueType: number,
    valueData: Buffer | number | string,
  ): void {
    if (
      [REG_SZ, REG_EXPAND_SZ, REG_MULTISZ].includes(valueType)
    ) {
      if (typeof valueData === 'number') {
        console.log('NULL');
      } else {
        console.log((valueData as Buffer).toString('utf16le'));
      }
    } else if (valueType === REG_BINARY) {
      console.log('');
      console.log(hexdump(valueData as Buffer, this.indent));
    } else if (valueType === REG_DWORD) {
      console.log(`${valueData}`);
    } else if (valueType === REG_QWORD) {
      console.log(
        `${(valueData as Buffer).readBigUInt64LE(0)}`,
      );
    } else if (valueType === REG_NONE) {
      try {
        if ((valueData as Buffer | string).length > 1) {
          console.log('');
          console.log(hexdump(valueData as Buffer, this.indent));
        } else {
          console.log(' NULL');
        }
      } catch {
        console.log(' NULL');
      }
    } else {
      console.log(`Unknown Type 0x${valueType.toString(16)}!`);
      console.log(hexdump(valueData as Buffer));
    }
  }

  enumKey(parentKey: Structure | string): string[] {
    const pk = parentKey as Structure;
    const res: string[] = [];
    const numSubKeys = pk.get('NumSubKeys') as number;
    if (numSubKeys > 0) {
      const lf = this.getBlock(pk.get('OffsetSubKeyLf') as number);
      if (!lf) return res;
      let data = lf.get('HashRecords') as Buffer;
      const lfMagic = lf.get('Magic') as string;

      if (lfMagic === 'ri') {
        let records = Buffer.alloc(0);
        const numKeys = lf.get('NumKeys') as number;
        for (let i = 0; i < numKeys; i++) {
          const offset = data.readUInt32LE(0);
          const l = this.getBlock(offset)!;
          const lHashRecs = l.get('HashRecords') as Buffer;
          const lNumKeys = l.get('NumKeys') as number;
          records = Buffer.concat([
            records,
            lHashRecs.subarray(0, lNumKeys * 8),
          ]);
          data = data.subarray(4);
        }
        data = records;
      }

      for (let i = 0; i < numSubKeys; i++) {
        const hashRec = new REG_HASH(data.subarray(0, 8));
        const nk = this.getBlock(hashRec.get('OffsetNk') as number);
        data = data.subarray(8);
        if (nk) {
          res.push((nk.get('KeyName') as Buffer).toString('utf-8'));
        }
      }
    }
    return res;
  }

  enumValues(key: Structure | string): Buffer[] {
    const k = key as Structure;
    const resp: Buffer[] = [];
    const numValues = k.get('NumValues') as number;
    if (numValues > 0) {
      const valueList = this.getValueBlocks(
        k.get('OffsetValueList') as number,
        numValues + 1,
      );
      for (const value of valueList) {
        if ((value.get('Flag') as number) > 0) {
          resp.push(value.get('Name') as Buffer);
        } else {
          resp.push(Buffer.from('default', 'latin1'));
        }
      }
    }
    return resp;
  }

  getValue(
    keyValue: string,
    valueName?: string,
  ): [number, Buffer | number | string] | null {
    let regKey: string;
    let regValue: string;
    if (valueName === undefined) {
      regKey = ntDirname(keyValue);
      regValue = ntBasename(keyValue);
    } else {
      regKey = keyValue;
      regValue = valueName;
    }

    const key = this.findKey(regKey);
    if (key === null) return null;

    const numValues = (key as Structure).get('NumValues') as number;
    if (numValues > 0) {
      const valueList = this.getValueBlocks(
        (key as Structure).get('OffsetValueList') as number,
        numValues + 1,
      );
      for (const value of valueList) {
        const valueBuf = value.get('Name') as Buffer;
        if (valueBuf.equals(Buffer.from(regValue, 'latin1'))) {
          return [
            value.get('ValueType') as number,
            this.getValueData(value),
          ];
        }
        if (
          regValue === 'default' &&
          (value.get('Flag') as number) <= 0
        ) {
          return [
            value.get('ValueType') as number,
            this.getValueData(value),
          ];
        }
      }
    }
    return null;
  }

  setValue(
    keyValue: string,
    valueData: Buffer,
  ): [number, number] | null {
    const regKey = ntDirname(keyValue);
    const regValue = ntBasename(keyValue);

    const key = this.findKey(regKey);
    if (key === null) return null;

    const numValues = (key as Structure).get('NumValues') as number;
    if (numValues > 0) {
      const valueList = this.getValueBlocks(
        (key as Structure).get('OffsetValueList') as number,
        numValues + 1,
      );
      for (const value of valueList) {
        const valueBuf = value.get('Name') as Buffer;
        if (valueBuf.equals(Buffer.from(regValue, 'latin1'))) {
          return [
            value.get('ValueType') as number,
            this.setValueData(value, valueData),
          ];
        }
        if (
          regValue === 'default' &&
          (value.get('Flag') as number) <= 0
        ) {
          return [
            value.get('ValueType') as number,
            this.setValueData(value, valueData),
          ];
        }
      }
    }
    return null;
  }

  getClass(className: string): Buffer | null {
    const key = this.findKey(className);
    if (key === null) return null;

    if (((key as Structure).get('OffsetClassName') as number) > 0) {
      const value = this.getBlock(
        (key as Structure).get('OffsetClassName') as number,
      );
      if (value) return value.get('Data') as Buffer;
    }
    return null;
  }
}

// ─── RegistryNode (tree node for export format) ──────────────────────────────

export class RegistryNode {
  keyName: string;
  nodeName: string;
  data: Record<string, [number, string]> | null;
  childKeys: Record<string, RegistryNode> = {};

  constructor(
    keyName: string,
    nodeName: string,
    data: Record<string, [number, string]> | null = null,
  ) {
    this.keyName = keyName;
    this.nodeName = nodeName;
    this.data = data;
  }

  addChildNode(childKey: Record<string, RegistryNode>): void {
    Object.assign(this.childKeys, childKey);
  }
}

// ─── ExportRegistryParser (.reg file format) ─────────────────────────────────

export class ExportRegistryParser extends Registry {
  indent = '';
  private hive: string;
  registryTree!: RegistryNode;

  constructor(hive: string) {
    super();
    this.hive = hive;
    // Read file as UTF-16LE (matching Python's open(hive, encoding='utf-16le'))
    const raw = fs.readFileSync(hive);
    let text: string;
    // Handle UTF-16LE BOM
    if (raw.length >= 2 && raw[0] === 0xff && raw[1] === 0xfe) {
      text = raw.subarray(2).toString('utf16le');
    } else {
      text = raw.toString('utf16le');
    }
    this.buildRegistryTree(text);
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  private parseType(valueType: string): number {
    if (valueType === 'hex(0)') return REG_NONE;
    if (valueType === 'hex(2)') return REG_EXPAND_SZ;
    if (valueType === 'hex') return REG_BINARY;
    if (valueType === 'dword') return REG_DWORD;
    if (valueType === 'hex(7)') return REG_MULTISZ;
    if (valueType === 'hex(b)') return REG_QWORD;
    return parseInt(
      valueType.replace('hex(', '0x').replace(')', ''),
      16,
    );
  }

  private keyToNodePath(key: string): string[] {
    return key
      .replace(`${this.registryTree.keyName}\\`, '')
      .replace(/^\\+|\\+$/g, '')
      .split('\\');
  }

  private findNode(nodePath: string[]): RegistryNode | null {
    let node = this.registryTree;
    try {
      if (nodePath.length === 1 && nodePath[0] === '') {
        return node;
      }
      for (const tempNode of nodePath) {
        const child = node.childKeys[tempNode];
        if (!child) return null;
        node = child;
      }
      return node;
    } catch {
      return null;
    }
  }

  private extractData(
    regkeyValues: string,
  ): Record<string, [number, string]> {
    if (!regkeyValues) {
      return { default: [REG_SZ, ''] };
    }

    const data: Record<string, [number, string]> = {};
    const patternRegsz = /^(?:"(.*)"|(@))="(.*)"$/;
    const patternOther = /^(?:"(.*)"|(@))=(.*):([\S\s]*)$/;
    const patternSplitValues = /^([\S\s]*?)$(?<!\\)/gm;

    let match: RegExpExecArray | null;
    while ((match = patternSplitValues.exec(regkeyValues)) !== null) {
      const value = match[1]!;
      if (!value) continue;

      const regszMatch = patternRegsz.exec(value);
      if (regszMatch) {
        const valueName = regszMatch[2] ? 'default' : regszMatch[1]!;
        data[valueName] = [REG_SZ, regszMatch[3]!];
      } else {
        const otherMatch = patternOther.exec(value);
        if (otherMatch) {
          const valueName = otherMatch[2]
            ? 'default'
            : otherMatch[1]!;
          const valueType = this.parseType(otherMatch[3]!);
          const valueData = otherMatch[4]!
            .replace(/\n$/, '')
            .replace(/^\n/, '')
            .replace(/,/g, '')
            .replace(/ /g, '')
            .replace(/\\\n/g, '');
          data[valueName] = [valueType, valueData];
        }
      }
    }
    return data;
  }

  private buildChildNode(
    keyName: string,
    regkeyValues: string,
  ): Record<string, RegistryNode> {
    const parts = keyName.split('\\');
    const nodeName = parts[parts.length - 1]!;
    const data = this.extractData(regkeyValues);
    return { [nodeName]: new RegistryNode(keyName, nodeName, data) };
  }

  private buildRegistryTree(fileContent: string): void {
    const pattern = /^\[(.*?)\]\n([\S\s]*?)?^\n/gm;
    let rootKey = true;
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(fileContent)) !== null) {
      const keyName = match[1]!;
      const regkeyValues = (match[2] ?? '').replace(/^\n+|\n+$/g, '');

      if (rootKey) {
        const data = this.extractData(regkeyValues);
        const parts = keyName.split('\\');
        const nodeName = parts[parts.length - 1]!;
        this.registryTree = new RegistryNode(keyName, nodeName, data);
        rootKey = false;
      } else {
        const parentPath = this.keyToNodePath(keyName).slice(0, -1);
        const node = this.buildChildNode(keyName, regkeyValues);
        const parentNode = this.findNode(parentPath);
        if (parentNode) {
          parentNode.addChildNode(node);
        }
      }
    }
  }

  private walkSubNodesExport(node: RegistryNode): void {
    console.log(`${this.indent}${node.nodeName}`);
    this.indent += '  ';
    if (Object.keys(node.childKeys).length === 0) {
      this.indent = this.indent.slice(0, -2);
      return;
    }

    for (const subNode of Object.values(node.childKeys)) {
      this.walkSubNodesExport(subNode);
    }
    this.indent = this.indent.slice(0, -2);
  }

  // ── Public API ───────────────────────────────────────────────────────────

  walk(parentKey: string): void {
    const path = this.keyToNodePath(parentKey);
    const node = this.findNode(path);
    if (!node) return;

    for (const subNode of Object.values(node.childKeys)) {
      this.walkSubNodesExport(subNode);
    }
  }

  printValue(
    valueType: number,
    valueData: Buffer | number | string,
  ): void {
    if ([REG_SZ, REG_EXPAND_SZ, REG_MULTISZ].includes(valueType)) {
      const buf = valueData as Buffer;
      if (
        !buf ||
        buf.length === 0 ||
        (buf.length === 2 && buf[0] === 0 && buf[1] === 0)
      ) {
        console.log('NULL');
      } else {
        console.log(buf.toString('utf16le'));
      }
    } else if (valueType === REG_BINARY) {
      console.log('');
      console.log(hexdump(valueData as Buffer, this.indent));
    } else if (valueType === REG_DWORD) {
      const buf = valueData as Buffer;
      if (!buf || buf.length === 0) {
        console.log(0);
      } else {
        // Match Python int.from_bytes (big-endian by default)
        let val = 0;
        for (const byte of buf) val = val * 256 + byte;
        console.log(val);
      }
    } else if (valueType === REG_QWORD) {
      console.log(
        `${(valueData as Buffer).readBigUInt64LE(0)}`,
      );
    } else if (valueType === REG_NONE) {
      try {
        if ((valueData as Buffer).length > 1) {
          console.log('');
          console.log(hexdump(valueData as Buffer, this.indent));
        } else {
          console.log(' NULL');
        }
      } catch {
        console.log(' NULL');
      }
    } else {
      console.log(`Unknown Type 0x${valueType.toString(16)}!`);
      console.log(hexdump(valueData as Buffer));
    }
  }

  findKey(key: string): string | null {
    if (key === '\\') return '\\';
    return this.keyToNodePath(key).join('\\');
  }

  enumKey(key: Structure | string): string[] {
    const path = this.keyToNodePath(key as string);
    const node = this.findNode(path);
    if (!node) return [];
    return Object.keys(node.childKeys);
  }

  enumValues(key: Structure | string): Buffer[] | null {
    const path = this.keyToNodePath(key as string);
    const node = this.findNode(path);
    if (!node) return null;
    const values = Object.keys(node.data ?? {});
    return values.map((s) => Buffer.from(s, 'utf-8'));
  }

  getValue(
    keyValue: string,
    valueName?: string,
  ): [number, Buffer | number | string] | null {
    const path = this.keyToNodePath(keyValue);
    let keyPath: string[];
    let regValue: string;

    if (valueName === undefined) {
      keyPath = path.slice(0, -1);
      regValue = path[path.length - 1] ?? '';
    } else {
      keyPath = path;
      regValue = valueName;
    }

    try {
      const node = this.findNode(keyPath);
      if (!node || !node.data || !(regValue in node.data))
        return null;
      const [valueType, valueData] = node.data[regValue]!;
      if (valueType === REG_SZ) {
        return [valueType, Buffer.from(valueData, 'utf16le')];
      }
      return [valueType, Buffer.from(valueData, 'hex')];
    } catch {
      return null;
    }
  }

  getClass(_className: string): Buffer | null {
    // Export format does not contain class name
    return null;
  }
}

// ─── Factory ─────────────────────────────────────────────────────────────────

/**
 * Auto-detect registry hive format and instantiate the appropriate parser.
 *
 * @param hive  Path to the registry hive file, or a FileIO object for remote access
 * @param isRemote  Whether the hive is a remote file object
 */
export function getRegistryParser(
  hive: string | FileIO,
  isRemote = false,
): Registry {
  const isFileObject =
    typeof hive !== 'string' &&
    typeof (hive as FileIO).read === 'function' &&
    typeof (hive as FileIO).seek === 'function';

  if (isFileObject) {
    // Remote file object (e.g. secretsdump RemoteFile)
    return new SaveRegistryParser(hive, isRemote);
  }

  // File path -- read header bytes to detect format
  const fd = fs.openSync(hive as string, 'r');
  const buf = Buffer.alloc(64);
  fs.readSync(fd, buf, 0, 64, 0);
  fs.closeSync(fd);

  // Binary hive format starts with 'regf'
  if (buf.subarray(0, 4).toString('latin1') === 'regf') {
    return new SaveRegistryParser(hive as string, isRemote);
  }

  // Check for .reg export format (UTF-16LE header)
  try {
    const header = buf.toString('utf16le');
    if (
      header.includes('Windows Registry Editor') ||
      header.includes('REGEDIT')
    ) {
      return new ExportRegistryParser(hive as string);
    }
  } catch {
    // not valid export format
  }

  throw new Error(
    'Could not determine registry hive format (not a binary hive or export)',
  );
}
