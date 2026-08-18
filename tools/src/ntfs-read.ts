#!/usr/bin/env node
/**
 * Impacket - Collection of TypeScript classes for working with network protocols.
 *
 * Copyright Fortra, LLC and its affiliated companies
 *
 * All rights reserved.
 *
 * This software is provided under a slightly modified version
 * of the Apache Software License. See the accompanying LICENSE file
 * for more information.
 *
 * Description:
 *   Mini shell for browsing an NTFS volume.
 *
 * Author:
 *   Alberto Solino (@agsolino)
 *   TypeScript port
 *
 * Reference for:
 *   Structure. Quick and dirty implementation.. just for fun.. ;)
 *   NOTE: Lots of info (mainly the structs) taken from the NTFS-3G project.
 *
 * ToDo:
 *   [] Support compressed, encrypted files
 */

import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline';
import { openSync, readSync, closeSync, writeSync, existsSync } from 'node:fs';
import path from 'node:path';
import { Structure, hexdump, type FieldDescriptor } from '@impacket/structure';
import { init as initLogger, info, error, debug,
  normalizeArgs, BANNER, initProxy,
} from '@impacket/examples';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Reserved/fixed MFTs
const FIXED_MFTS = 16;

// Attribute types
const STANDARD_INFORMATION = 0x10;
const ATTRIBUTE_LIST = 0x20;
const FILE_NAME = 0x30;
const DATA = 0x80;
const INDEX_ROOT = 0x90;
const INDEX_ALLOCATION = 0xa0;
const END = 0xffffffff;

// FileName type flags
const FILE_NAME_DOS = 0x02;

// File Attribute Flags
const FILE_ATTR_HIDDEN = 0x0002;
const FILE_ATTR_SYSTEM = 0x0004;
const FILE_ATTR_COMPRESSED = 0x0800;
const FILE_ATTR_SPARSE_FILE = 0x0200;
const FILE_ATTR_ENCRYPTED = 0x4000;
const FILE_ATTR_I30_INDEX_PRESENT = 0x10000000;

// NTFS System files
const FILE_MFT = 0;
const FILE_Root = 5;

// Index Entry Flags
const INDEX_ENTRY_NODE = 1;
const INDEX_ENTRY_END = 2;

// Size of the fixed common header of an attribute record
const ATTR_RECORD_HDR_SIZE = 16;

// ---------------------------------------------------------------------------
// NTFS on-disk structures (ported from impacket, backed by @impacket/structure)
// ---------------------------------------------------------------------------

class NTFS_BPB extends Structure {
  static structure: FieldDescriptor[] = [
    ['BytesPerSector', '<H=0'],
    ['SectorsPerCluster', 'B=0'],
    ['ReservedSectors', '<H=0'],
    ['Reserved', '3s=b""'],
    ['Reserved2', '2s=b""'],
    ['MediaDescription', 'B=0'],
    ['Reserved3', '2s=b""'],
    ['Reserved4', '<H=0'],
    ['Reserved5', '<H=0'],
    ['Reserved6', '<L=0'],
    ['Reserved7', '4s=b""'],
  ];
}

class NTFS_EXTENDED_BPB extends Structure {
  static structure: FieldDescriptor[] = [
    ['Reserved', '4s=b""'],
    ['TotalSectors', '<Q=0'],
    ['MFTClusterNumber', '<Q=0'],
    ['MFTMirrClusterNumber', '<Q=0'],
    ['ClusterPerFileRecord', 'b=0'],
    ['Reserved2', '3s=b""'],
    ['ClusterPerIndexBuffer', '<b=0'],
    ['Reserved3', '3s=b""'],
    ['VolumeSerialNumber', '8s=b""'],
    ['CheckSum', '4s=b""'],
  ];
}

class NTFS_BOOT_SECTOR extends Structure {
  static structure: FieldDescriptor[] = [
    ['JmpInstr', '3s=b""'],
    ['OEM_ID', '8s=b""'],
    ['BPB', '25s=b""'],
    ['ExtendedBPB', '48s=b""'],
    ['Bootstrap', '426s=b""'],
    ['EOS', '<H=0'],
  ];
}

class NTFS_MFT_RECORD extends Structure {
  static structure: FieldDescriptor[] = [
    ['MagicLabel', '4s=b""'],
    ['USROffset', '<H=0'],
    ['USRSize', '<H=0'],
    ['LogSeqNum', '<Q=0'],
    ['SeqNum', '<H=0'],
    ['LinkCount', '<H=0'],
    ['AttributesOffset', '<H=0'],
    ['Flags', '<H=0'],
    ['BytesInUse', '<L=0'],
    ['BytesAllocated', '<L=0'],
    ['BaseMftRecord', '<Q=0'],
    ['NextAttrInstance', '<H=0'],
    ['Reserved', '<H=0'],
    ['RecordNumber', '<L=0'],
  ];
}

class NTFS_ATTRIBUTE_RECORD extends Structure {
  static commonHdr: FieldDescriptor[] = [
    ['Type', '<L=0'],
    ['Length', '<L=0'],
    ['NonResident', 'B=0'],
    ['NameLength', 'B=0'],
    ['NameOffset', '<H=0'],
    ['Flags', '<H=0'],
    ['Instance', '<H=0'],
  ];
  static structure: FieldDescriptor[] = [];
}

class NTFS_ATTRIBUTE_RECORD_NON_RESIDENT extends Structure {
  static structure: FieldDescriptor[] = [
    ['LowestVCN', '<Q=0'],
    ['HighestVCN', '<Q=0'],
    ['DataRunsOffset', '<H=0'],
    ['CompressionUnit', '<H=0'],
    ['Reserved1', '4s=""'],
    ['AllocatedSize', '<Q=0'],
    ['DataSize', '<Q=0'],
    ['InitializedSize', '<Q=0'],
  ];
}

class NTFS_ATTRIBUTE_RECORD_RESIDENT extends Structure {
  static structure: FieldDescriptor[] = [
    ['ValueLen', '<L=0'],
    ['ValueOffset', '<H=0'],
    ['Flags', 'B=0'],
    ['Reserved', 'B=0'],
  ];
}

class NTFS_FILE_NAME_ATTR extends Structure {
  static structure: FieldDescriptor[] = [
    ['ParentDirectory', '<Q=0'],
    ['CreationTime', '<Q=0'],
    ['LastDataChangeTime', '<Q=0'],
    ['LastMftChangeTime', '<Q=0'],
    ['LastAccessTime', '<Q=0'],
    ['AllocatedSize', '<Q=0'],
    ['DataSize', '<Q=0'],
    ['FileAttributes', '<L=0'],
    ['EaSize', '<L=0'],
    ['FileNameLen', 'B=0'],
    ['FileNameType', 'B=0'],
    ['_FileName', '_-FileName', 'self["FileNameLen"]*2'],
    ['FileName', ':'],
  ];
}

class NTFS_STANDARD_INFORMATION extends Structure {
  static structure: FieldDescriptor[] = [
    ['CreationTime', '<Q=0'],
    ['LastDataChangeTime', '<Q=0'],
    ['LastMftChangeTime', '<Q=0'],
    ['LastAccessTime', '<Q=0'],
    ['FileAttributes', '<L=0'],
  ];
}

class NTFS_INDEX_HEADER extends Structure {
  static structure: FieldDescriptor[] = [
    ['EntriesOffset', '<L=0'],
    ['IndexLength', '<L=0'],
    ['AllocatedSize', '<L=0'],
    ['Flags', 'B=0'],
    ['Reserved', '3s=b""'],
  ];
}

class NTFS_INDEX_ROOT extends Structure {
  static structure: FieldDescriptor[] = [
    ['Type', '<L=0'],
    ['CollationRule', '<L=0'],
    ['IndexBlockSize', '<L=0'],
    ['ClustersPerIndexBlock', 'B=0'],
    ['Reserved', '3s=b""'],
    ['Index', ':', NTFS_INDEX_HEADER],
  ];
}

class NTFS_INDEX_ALLOCATION extends Structure {
  static structure: FieldDescriptor[] = [
    ['Magic', '4s=b""'],
    ['USROffset', '<H=0'],
    ['USRSize', '<H=0'],
    ['Lsn', '<Q=0'],
    ['IndexVcn', '<Q=0'],
    ['Index', ':', NTFS_INDEX_HEADER],
  ];
}

class NTFS_INDEX_ENTRY_HEADER extends Structure {
  static structure: FieldDescriptor[] = [
    ['IndexedFile', '<Q=0'],
    ['Length', '<H=0'],
    ['KeyLength', '<H=0'],
    ['Flags', '<H=0'],
    ['Reserved', '<H=0'],
  ];
}

class NTFS_INDEX_ENTRY extends Structure {
  static structure: FieldDescriptor[] = [
    ['EntryHeader', ':', NTFS_INDEX_ENTRY_HEADER],
    ['_Key', '_-Key', 'self["EntryHeader"]["KeyLength"]'],
    ['Key', ':'],
    ['_Vcn', '_-Vcn', '(self["EntryHeader"]["Flags"] & 1)*8'],
    ['Vcn', ':'],
  ];
  constructor(data?: Buffer | Uint8Array | null) {
    super(data ?? null, 8);
  }
}

class NTFS_DATA_RUN extends Structure {
  static structure: FieldDescriptor[] = [
    ['LCN', '<q=0'],
    ['Clusters', '<Q=0'],
    ['StartVCN', '<Q=0'],
    ['LastVCN', '<Q=0'],
  ];
}

class NTFS_ATTRIBUTE_LIST_ENTRY extends Structure {
  static structure: FieldDescriptor[] = [
    ['AttributeType', '<L=0'],
    ['EntryLength', '<H=0'],
    ['AttributeNameLength', 'B=0'],
    ['AttributeNameOffset', 'B=0'],
    ['StartingVCN', '<Q=0'],
    ['BaseFileRecord', '<Q=0'],
    ['AttributeID', '<H=0'],
  ];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Coerce a Structure field (may be bigint) into a JS number. */
function num(v: unknown): number {
  return typeof v === 'bigint' ? Number(v) : (v as number);
}

/** NTFS FILETIME (100ns since 1601) -> Unix seconds. Uses BigInt for range. */
function getUnixTime(t: bigint): number {
  let x = t - 116444736000000000n;
  x = x / 10000000n;
  return Number(x);
}

/** Represent a data run internally (LCN may be -1 for sparse). */
interface DataRun {
  LCN: number;
  Clusters: number;
  StartVCN: number;
  LastVCN: number;
}

/** Read a little-endian unsigned integer from up to 8 bytes as a Number. */
function readUIntLE(buf: Buffer): number {
  let v = 0n;
  for (let i = 0; i < buf.length; i++) v |= BigInt(buf[i]!) << BigInt(8 * i);
  return Number(v);
}

/** Read a little-endian signed integer from up to 8 bytes as a Number. */
function readIntLE(buf: Buffer): number {
  const padded = Buffer.alloc(8);
  const sign = buf.length > 0 && (buf[buf.length - 1]! & 0x80) !== 0;
  buf.copy(padded, 0);
  if (sign) {
    for (let i = buf.length; i < 8; i++) padded[i] = 0xff;
  }
  return Number(padded.readBigInt64LE(0));
}

// ---------------------------------------------------------------------------
// Volume file (raw block device / image file access)
// ---------------------------------------------------------------------------

class VolumeFile {
  private fd: number;

  constructor(volumeName: string) {
    this.fd = openSync(volumeName, 'r');
  }

  /** Read exactly `length` bytes starting at absolute byte `position`. */
  read(position: number, length: number): Buffer {
    const buf = Buffer.alloc(length);
    let total = 0;
    while (total < length) {
      let n: number;
      try {
        n = readSync(this.fd, buf, total, length - total, position + total);
      } catch {
        break;
      }
      if (n === 0) break;
      total += n;
    }
    return total === length ? buf : buf.subarray(0, total);
  }

  close(): void {
    try {
      closeSync(this.fd);
    } catch {
      /* ignore */
    }
  }
}

// ---------------------------------------------------------------------------
// Attributes
// ---------------------------------------------------------------------------

class Attribute {
  AttributeName: string | null = null;
  NTFSVolume: NTFS;
  AttributeHeader: NTFS_ATTRIBUTE_RECORD;

  constructor(iNode: INODE, data: Buffer) {
    this.NTFSVolume = iNode.NTFSVolume;
    this.AttributeHeader = new NTFS_ATTRIBUTE_RECORD(data);
    if (this.getRawNameLength() > 0 && this.getType() !== END) {
      const off = num(this.AttributeHeader.get('NameOffset'));
      const len = this.getRawNameLength() * 2;
      this.AttributeName = data.subarray(off, off + len).toString('utf16le');
    }
  }

  private getRawNameLength(): number {
    return num(this.AttributeHeader.get('NameLength'));
  }

  getFlags(): number {
    return num(this.AttributeHeader.get('Flags'));
  }

  getName(): string | null {
    return this.AttributeName;
  }

  isNonResident(): number {
    return num(this.AttributeHeader.get('NonResident'));
  }

  getTotalSize(): number {
    return num(this.AttributeHeader.get('Length'));
  }

  getType(): number {
    return num(this.AttributeHeader.get('Type'));
  }
}

class AttributeResident extends Attribute {
  ResidentHeader: NTFS_ATTRIBUTE_RECORD_RESIDENT;
  AttrValue: Buffer;

  constructor(iNode: INODE, data: Buffer) {
    super(iNode, data);
    debug(`Inside AttributeResident: iNode: ${iNode.INodeNumber}`);
    this.ResidentHeader = new NTFS_ATTRIBUTE_RECORD_RESIDENT(
      data.subarray(ATTR_RECORD_HDR_SIZE),
    );
    const off = num(this.ResidentHeader.get('ValueOffset'));
    const len = num(this.ResidentHeader.get('ValueLen'));
    this.AttrValue = data.subarray(off, off + len);
  }

  override getFlags(): number {
    return num(this.ResidentHeader.get('Flags'));
  }

  getValue(): Buffer | null {
    return this.AttrValue;
  }

  read(offset: number, length: number): Buffer {
    debug(`Inside Read: offset: ${offset}, length: ${length}`);
    return this.AttrValue.subarray(offset, offset + length);
  }

  getDataSize(): number {
    return this.AttrValue.length;
  }
}

class AttributeNonResident extends Attribute {
  _raw_attr_data: Buffer;
  NonResidentHeader: NTFS_ATTRIBUTE_RECORD_NON_RESIDENT;
  AttrValue: Buffer;
  DataRuns: DataRun[] = [];
  ClusterSize = 0;
  data_size: number;
  initialized_size: number;

  constructor(iNode: INODE, data: Buffer) {
    super(iNode, data);
    debug(`Inside AttributeNonResident: iNode: ${iNode.INodeNumber}`);
    this._raw_attr_data = data;
    this.NonResidentHeader = new NTFS_ATTRIBUTE_RECORD_NON_RESIDENT(
      data.subarray(ATTR_RECORD_HDR_SIZE),
    );
    const off = num(this.NonResidentHeader.get('DataRunsOffset'));
    const alloc = num(this.NonResidentHeader.get('AllocatedSize'));
    this.AttrValue = data.subarray(off, off + alloc);
    this.data_size = num(this.NonResidentHeader.get('DataSize'));
    this.initialized_size = num(this.NonResidentHeader.get('InitializedSize'));
    this.parseDataRuns();
  }

  getDataSize(): number {
    return this.data_size;
  }

  getValue(): Buffer | null {
    return null;
  }

  parseDataRuns(): void {
    let data = this.AttrValue;
    if (data == null) return;

    let vcn = 0;
    let prevLcn = 0;

    while (data.length > 0 && data[0] !== 0x00) {
      const header = data[0]!;
      data = data.subarray(1);

      const lengthBytes = header & 0x0f;
      const offsetBytes = header >> 4;

      if (data.length < lengthBytes) break;
      const clusterCount = readUIntLE(data.subarray(0, lengthBytes));
      data = data.subarray(lengthBytes);

      const dr: DataRun = {
        LCN: 0,
        Clusters: clusterCount,
        StartVCN: vcn,
        LastVCN: vcn + clusterCount - 1,
      };

      if (offsetBytes === 0) {
        // Sparse run - no physical location
        dr.LCN = -1;
        debug(
          `Sparse run: VCN ${dr.StartVCN}-${dr.LastVCN}, clusters ${clusterCount}`,
        );
      } else {
        if (data.length < offsetBytes) break;
        const lcnDelta = readIntLE(data.subarray(0, offsetBytes));
        data = data.subarray(offsetBytes);
        prevLcn += lcnDelta;
        dr.LCN = prevLcn;
      }

      this.DataRuns.push(dr);
      vcn += clusterCount;
    }
  }

  readClusters(clusters: number, lcn: number): Buffer | null {
    debug(`Inside ReadClusters: clusters:${clusters}, lcn:${lcn}`);
    if (lcn === -1) {
      return Buffer.alloc(clusters * this.ClusterSize, 0);
    }
    const wanted = clusters * this.ClusterSize;
    const buf = this.NTFSVolume.volumeFD.read(lcn * this.ClusterSize, wanted);
    if (buf.length === 0) return null;
    return buf;
  }

  readVCN(vcn: number, numOfClusters: number): Buffer {
    debug(`Inside ReadVCN: vcn: ${vcn}, numOfClusters: ${numOfClusters}`);
    let buf = Buffer.alloc(0);
    let clustersLeft = numOfClusters;

    for (const dr of this.DataRuns) {
      if (clustersLeft <= 0) break;
      if (vcn > dr.LastVCN) continue;
      if (vcn < dr.StartVCN) break;

      const clustersInRun = dr.LastVCN - vcn + 1;
      const clustersToRead = Math.min(clustersLeft, clustersInRun);

      let lcn: number;
      if (dr.LCN === -1) {
        lcn = -1;
      } else {
        lcn = dr.LCN + (vcn - dr.StartVCN);
      }

      const tmpBuf = this.readClusters(clustersToRead, lcn);
      if (tmpBuf == null) break;
      buf = Buffer.concat([buf, tmpBuf]);
      clustersLeft -= clustersToRead;
      vcn += clustersToRead;
    }

    return buf;
  }

  read(offset: number, length: number): Buffer | null {
    debug(`Inside Read: offset: ${offset}, length: ${length}`);

    if (offset >= this.data_size) return Buffer.alloc(0);
    length = Math.min(length, this.data_size - offset);

    this.ClusterSize =
      this.NTFSVolume.BPB!.BytesPerSector * this.NTFSVolume.BPB!.SectorsPerCluster;

    let buf = Buffer.alloc(0);
    let curOffset = offset;
    let bytesLeft = length;

    while (bytesLeft > 0) {
      const vcn = Math.floor(curOffset / this.ClusterSize);
      const vcnOffset = curOffset % this.ClusterSize;

      const bytesInFirstCluster = this.ClusterSize - vcnOffset;
      let clustersToRead: number;
      if (bytesLeft <= bytesInFirstCluster) {
        clustersToRead = 1;
      } else {
        clustersToRead =
          1 +
          Math.floor(
            (bytesLeft - bytesInFirstCluster + this.ClusterSize - 1) /
              this.ClusterSize,
          );
      }

      const clusterData = this.readVCN(vcn, clustersToRead);
      if (clusterData.length === 0) break;

      const chunk = clusterData.subarray(vcnOffset, vcnOffset + bytesLeft);
      buf = Buffer.concat([buf, chunk]);
      curOffset += chunk.length;
      bytesLeft -= chunk.length;

      if (chunk.length === 0) break;
    }

    if (buf.length === 0) return null;

    // Zero-fill beyond InitializedSize (OS behavior for uninitialized data)
    if (this.initialized_size < offset + buf.length) {
      const validBytes = Math.max(0, this.initialized_size - offset);
      const filled = Buffer.alloc(buf.length, 0);
      buf.copy(filled, 0, 0, validBytes);
      buf = filled;
    }

    return buf;
  }
}

class NonResidentDataAttribute extends AttributeNonResident {
  constructor(iNode: INODE, entries: AttributeListEntry[], attributeName: string | null) {
    const matches = [...entries];
    if (matches.length === 0) throw new Error('No $DATA extents found');

    // Sort extents by StartingVCN to define logical order
    matches.sort((a, b) => a.StartingVCN - b.StartingVCN);

    // Collect attributes and find base extent (StartingVCN == 0)
    const collected: Array<[AttributeListEntry, Attribute]> = [];
    let baseAttr: AttributeNonResident | null = null;
    let baseDataSize: number | null = null;
    let baseInitSize: number | null = null;

    for (const entry of matches) {
      const extInode = iNode.NTFSVolume.getINode(entry.MftRecordNumber);
      const attr = extInode.searchAttribute(DATA, attributeName);
      if (attr == null) continue;
      collected.push([entry, attr]);
      if (entry.StartingVCN === 0) {
        if (attr instanceof AttributeNonResident) {
          baseAttr = attr;
          baseDataSize = attr.NonResidentHeader
            ? num(attr.NonResidentHeader.get('DataSize'))
            : null;
          baseInitSize = attr.NonResidentHeader
            ? num(attr.NonResidentHeader.get('InitializedSize'))
            : null;
        }
      }
    }

    if (collected.length === 0) throw new Error('No usable $DATA extents found');

    // Ensure we have valid base sizes
    if (baseAttr == null) {
      const first = collected[0]![1];
      if (!(first instanceof AttributeNonResident)) {
        throw new Error('No usable $DATA extents found');
      }
      baseAttr = first;
      baseDataSize = num(first.NonResidentHeader.get('DataSize'));
      baseInitSize = num(first.NonResidentHeader.get('InitializedSize'));
    }

    // Initialize from base extent
    super(iNode, baseAttr._raw_attr_data);

    if (collected.length === 1) {
      const [entry] = collected[0]!;
      NonResidentDataAttribute._shiftRuns(this, entry.StartingVCN);
    } else {
      this.mergeExtents(collected, baseDataSize!, baseInitSize!);
    }
  }

  private static _shiftRuns(attr: AttributeNonResident, startVcn: number): void {
    if (startVcn <= 0) return;
    for (const dr of attr.DataRuns) {
      dr.StartVCN += startVcn;
      dr.LastVCN += startVcn;
    }
  }

  private mergeExtents(
    collected: Array<[AttributeListEntry, Attribute]>,
    dataSize: number,
    initSize: number,
  ): void {
    const mergedRuns: DataRun[] = [];
    for (const [entry, attr] of collected) {
      if (!(attr instanceof AttributeNonResident)) continue;
      for (const dr of attr.DataRuns) {
        mergedRuns.push({
          LCN: dr.LCN,
          Clusters: dr.Clusters,
          StartVCN: dr.StartVCN + entry.StartingVCN,
          LastVCN: dr.LastVCN + entry.StartingVCN,
        });
      }
    }
    mergedRuns.sort((a, b) => a.StartVCN - b.StartVCN);
    this.DataRuns = mergedRuns;
    this.data_size = dataSize;
    this.initialized_size = initSize;
  }
}

class AttributeStandardInfo {
  Attribute: AttributeResident;
  StandardInfo: NTFS_STANDARD_INFORMATION;

  constructor(attribute: AttributeResident) {
    debug('Inside AttributeStandardInfo');
    this.Attribute = attribute;
    this.StandardInfo = new NTFS_STANDARD_INFORMATION(attribute.AttrValue);
  }

  getFileAttributes(): number {
    return num(this.StandardInfo.get('FileAttributes'));
  }

  getFileTime(): number | null {
    const t = this.StandardInfo.get('LastDataChangeTime') as bigint;
    if (t > 0n) return getUnixTime(t);
    return null;
  }
}

class AttributeFileName {
  Attribute: AttributeResident;
  FileNameRecord: NTFS_FILE_NAME_ATTR;

  constructor(attribute: AttributeResident) {
    debug('Inside AttributeFileName');
    this.Attribute = attribute;
    this.FileNameRecord = new NTFS_FILE_NAME_ATTR(attribute.AttrValue);
  }

  getFileNameType(): number {
    return num(this.FileNameRecord.get('FileNameType'));
  }

  getFileAttributes(): number {
    return num(this.FileNameRecord.get('FileAttributes'));
  }

  getFileName(): string {
    return (this.FileNameRecord.get('FileName') as Buffer).toString('utf16le');
  }

  getFileSize(): number {
    return num(this.FileNameRecord.get('DataSize'));
  }
}

class AttributeIndexAllocation {
  Attribute: AttributeNonResident;

  constructor(attribute: AttributeNonResident) {
    debug('Inside AttributeIndexAllocation');
    this.Attribute = attribute;
  }

  read(offset: number, length: number): Buffer | null {
    return this.Attribute.read(offset, length);
  }
}

class AttributeIndexRoot {
  Attribute: AttributeResident;
  IndexRootRecord: NTFS_INDEX_ROOT;
  IndexEntries: IndexEntry[] = [];

  constructor(attribute: AttributeResident) {
    debug('Inside AttributeIndexRoot');
    this.Attribute = attribute;
    this.IndexRootRecord = new NTFS_INDEX_ROOT(attribute.AttrValue);
    this.parseIndexEntries();
  }

  parseIndexEntries(): void {
    let data = this.Attribute.AttrValue.subarray(this.IndexRootRecord.length);
    for (;;) {
      const ie = new IndexEntry(data);
      this.IndexEntries.push(ie);
      if (ie.isLastNode()) break;
      data = data.subarray(ie.getSize());
    }
  }

  getType(): number {
    return num(this.IndexRootRecord.get('Type'));
  }
}

class IndexEntry {
  entry: NTFS_INDEX_ENTRY;

  constructor(entry: Buffer) {
    this.entry = new NTFS_INDEX_ENTRY(entry);
  }

  private header(): NTFS_INDEX_ENTRY_HEADER {
    return this.entry.get('EntryHeader') as NTFS_INDEX_ENTRY_HEADER;
  }

  isSubNode(): number {
    return num(this.header().get('Flags')) & INDEX_ENTRY_NODE;
  }

  isLastNode(): number {
    return num(this.header().get('Flags')) & INDEX_ENTRY_END;
  }

  getVCN(): number {
    return readUIntLE(this.entry.get('Vcn') as Buffer);
  }

  getSize(): number {
    return this.entry.length;
  }

  getKey(): Buffer {
    return this.entry.get('Key') as Buffer;
  }

  getINodeNumber(): number {
    const indexedFile = this.header().get('IndexedFile') as bigint;
    return Number(indexedFile & 0x0000ffffffffffffn);
  }
}

class AttributeListEntry {
  EntryHeader: NTFS_ATTRIBUTE_LIST_ENTRY;
  AttributeType: number;
  EntryLength: number;
  StartingVCN: number;
  AttributeID: number;
  MftRecordNumber: number;
  MftSequenceNumber: number;
  AttributeName: string | null = null;

  constructor(entryData: Buffer) {
    this.EntryHeader = new NTFS_ATTRIBUTE_LIST_ENTRY(entryData);
    this.AttributeType = num(this.EntryHeader.get('AttributeType'));
    this.EntryLength = num(this.EntryHeader.get('EntryLength'));
    this.StartingVCN = num(this.EntryHeader.get('StartingVCN'));
    this.AttributeID = num(this.EntryHeader.get('AttributeID'));
    const rawRecord = this.EntryHeader.get('BaseFileRecord') as bigint;
    this.MftRecordNumber = Number(rawRecord & 0x0000ffffffffffffn);
    this.MftSequenceNumber = Number((rawRecord >> 48n) & 0xffffn);
    const nameLen = num(this.EntryHeader.get('AttributeNameLength'));
    if (nameLen > 0) {
      const nameOffset = num(this.EntryHeader.get('AttributeNameOffset'));
      this.AttributeName = entryData
        .subarray(nameOffset, nameOffset + nameLen * 2)
        .toString('utf16le');
    }
  }
}

class AttributeList {
  attribute: AttributeResident | AttributeNonResident;
  Entries: AttributeListEntry[] = [];

  constructor(attribute: AttributeResident | AttributeNonResident) {
    this.attribute = attribute;
    this.parseEntries();
  }

  private parseEntries(): void {
    let data: Buffer | null;
    const value =
      'getValue' in this.attribute ? this.attribute.getValue() : null;
    if (value != null) {
      data = value;
    } else {
      data = this.attribute.read(0, this.attribute.getDataSize());
    }

    if (!data || data.length === 0) return;

    let offset = 0;
    while (offset < data.length) {
      const entryData = data.subarray(offset);
      if (entryData.length < 26) break;
      const listEntry = new AttributeListEntry(entryData);
      if (listEntry.EntryLength === 0) break;
      this.Entries.push(listEntry);
      offset += listEntry.EntryLength;
    }
  }

  getEntries(): AttributeListEntry[] {
    return this.Entries;
  }
}

// ---------------------------------------------------------------------------
// INODE
// ---------------------------------------------------------------------------

class INODE {
  NTFSVolume: NTFS;
  INodeNumber: number | null = null;
  Attributes: Map<number, unknown> = new Map();
  AttributesRaw: Buffer | null = null;
  AttributesLastPos: Buffer | null = null;
  FileAttributes = 0;
  LastDataChangeTime: number | null = null; // unix seconds
  FileName: string | null = null;
  FileSize = 0;

  constructor(NTFSVolume: NTFS) {
    this.NTFSVolume = NTFSVolume;
  }

  isDirectory(): number {
    return this.FileAttributes & FILE_ATTR_I30_INDEX_PRESENT;
  }

  isCompressed(): number {
    return this.FileAttributes & FILE_ATTR_COMPRESSED;
  }

  isEncrypted(): number {
    return this.FileAttributes & FILE_ATTR_ENCRYPTED;
  }

  isSparse(): number {
    return this.FileAttributes & FILE_ATTR_SPARSE_FILE;
  }

  displayName(): void {
    if (this.LastDataChangeTime != null && this.FileName != null) {
      try {
        const size = String(this.FileSize).padStart(15);
        console.log(
          `${this.getPrintableAttributes()} ${formatDateTime(this.LastDataChangeTime)} ${size} ${this.FileName} `,
        );
      } catch (e) {
        error(`Exception when trying to display inode ${this.INodeNumber}: ${e}`);
      }
    }
  }

  getPrintableAttributes(): string {
    let mask = '';
    mask += this.FileAttributes & FILE_ATTR_I30_INDEX_PRESENT ? 'd' : '-';
    mask += this.FileAttributes & FILE_ATTR_HIDDEN ? 'h' : '-';
    mask += this.FileAttributes & FILE_ATTR_SYSTEM ? 'S' : '-';
    mask += this.isCompressed() ? 'C' : '-';
    mask += this.isEncrypted() ? 'E' : '-';
    mask += this.isSparse() ? 's' : '-';
    return mask;
  }

  parseAttributes(): void {
    // Standard Info
    let attr = this.searchAttribute(STANDARD_INFORMATION, null);
    if (attr != null && attr instanceof AttributeResident) {
      const si = new AttributeStandardInfo(attr);
      this.Attributes.set(STANDARD_INFORMATION, si);
      this.FileAttributes |= si.getFileAttributes();
      this.LastDataChangeTime = si.getFileTime();
    }

    // Filename
    attr = this.searchAttribute(FILE_NAME, null);
    while (attr != null) {
      const fn = new AttributeFileName(attr as AttributeResident);
      if (fn.getFileNameType() !== FILE_NAME_DOS) {
        this.FileName = fn.getFileName();
        this.FileSize = fn.getFileSize();
        this.FileAttributes |= fn.getFileAttributes();
        this.Attributes.set(FILE_NAME, fn);
        break;
      }
      attr = this.searchAttribute(FILE_NAME, null, true);
    }

    // Attribute list before Index Allocation
    attr = this.searchAttribute(ATTRIBUTE_LIST, null);
    if (attr != null) {
      const al = new AttributeList(attr as AttributeResident | AttributeNonResident);
      this.Attributes.set(ATTRIBUTE_LIST, al);
    }

    // Index Allocation
    attr = this.searchAttribute(INDEX_ALLOCATION, '$I30');
    if (attr != null && attr instanceof AttributeNonResident) {
      const ia = new AttributeIndexAllocation(attr);
      this.Attributes.set(INDEX_ALLOCATION, ia);
    }

    attr = this.searchAttribute(INDEX_ROOT, '$I30');
    if (attr != null && attr instanceof AttributeResident) {
      const ir = new AttributeIndexRoot(attr);
      this.Attributes.set(INDEX_ROOT, ir);
    }
  }

  searchAttribute(
    attributeType: number,
    attributeName: string | null,
    findNext = false,
  ): AttributeResident | AttributeNonResident | null {
    debug(
      `Inside searchAttribute: type: 0x${attributeType.toString(16)}, name: ${attributeName}`,
    );
    let record: AttributeResident | AttributeNonResident | null = null;

    let data = (findNext ? this.AttributesLastPos : this.AttributesRaw) as Buffer;

    for (;;) {
      if (!data || data.length <= 8) {
        record = null;
        break;
      }

      const probe = new Attribute(this, data);

      if (probe.getType() === END) {
        record = null;
        break;
      }
      if (probe.getTotalSize() === 0) {
        record = null;
        break;
      }

      if (probe.getType() === attributeType && probe.getName() === attributeName) {
        if (probe.isNonResident() === 1) {
          record = new AttributeNonResident(this, data);
        } else {
          record = new AttributeResident(this, data);
        }
        this.AttributesLastPos = data.subarray(probe.getTotalSize());
        break;
      }

      data = data.subarray(probe.getTotalSize());
    }

    // Look for attribute on Attribute List
    if (record == null && this.Attributes.has(ATTRIBUTE_LIST)) {
      const attrList = this.Attributes.get(ATTRIBUTE_LIST) as AttributeList;

      if (attributeType === DATA) {
        const entries = attrList
          .getEntries()
          .filter(
            (entry) =>
              entry.AttributeType === DATA &&
              entry.AttributeName === attributeName,
          );
        try {
          return new NonResidentDataAttribute(this, entries, attributeName);
        } catch {
          return null;
        }
      }

      for (const entry of attrList.getEntries()) {
        if (
          entry.AttributeType === attributeType &&
          entry.AttributeName === attributeName
        ) {
          const extInode = this.NTFSVolume.getINode(entry.MftRecordNumber);
          return extInode.searchAttribute(attributeType, attributeName);
        }
      }
    }

    return record;
  }

  performFixUp(record: Structure, buf: Buffer, numSectors: number): Buffer | null {
    debug('Inside PerformFixUp...');
    const usrOffset = num(record.get('USROffset'));
    const usrSize = num(record.get('USRSize'));
    const magicNum = buf.readUInt16LE(usrOffset);
    const sequenceArray = buf.subarray(usrOffset + 2, usrOffset + 2 + usrSize * 2);

    const dataList = Buffer.from(buf);
    let index = 0;
    let seqIdx = 0;
    for (let i = 0; i < numSectors * 2; i += 2) {
      index += this.NTFSVolume.SectorSize! - 2;
      const lastBytes = buf.readUInt16LE(index);
      if (lastBytes !== magicNum) {
        error(
          `Magic number 0x${magicNum.toString(16)} doesn't match with 0x${lastBytes.toString(16)}`,
        );
        return null;
      }
      dataList[index] = sequenceArray[seqIdx]!;
      dataList[index + 1] = sequenceArray[seqIdx + 1]!;
      seqIdx += 2;
      index += 2;
    }

    return dataList;
  }

  parseIndexBlocks(vcn: number): IndexEntry[] {
    const indexEntries: IndexEntry[] = [];
    if (this.Attributes.has(INDEX_ALLOCATION)) {
      const ia = this.Attributes.get(INDEX_ALLOCATION) as AttributeIndexAllocation;
      let data = ia.read(
        vcn * this.NTFSVolume.IndexBlockSize!,
        this.NTFSVolume.IndexBlockSize!,
      );
      if (data) {
        const iaRec = new NTFS_INDEX_ALLOCATION(data);
        const sectorsPerIB = Math.floor(
          this.NTFSVolume.IndexBlockSize! / this.NTFSVolume.SectorSize!,
        );
        const fixed = this.performFixUp(iaRec, data, sectorsPerIB);
        if (fixed == null) return [];
        const indexHeader = iaRec.get('Index') as NTFS_INDEX_HEADER;
        const entriesOffset = num(indexHeader.get('EntriesOffset'));
        // len(iaRec) - len(NTFS_INDEX_HEADER()) + EntriesOffset
        const skip = iaRec.length - new NTFS_INDEX_HEADER().length + entriesOffset;
        data = fixed.subarray(skip);
        for (;;) {
          const ie = new IndexEntry(data);
          indexEntries.push(ie);
          if (ie.isLastNode()) break;
          data = data.subarray(ie.getSize());
        }
      }
    }
    return indexEntries;
  }

  walkSubNodes(vcn: number): NTFS_FILE_NAME_ATTR[] {
    debug(`Inside walkSubNodes: vcn ${vcn}`);
    const entries = this.parseIndexBlocks(vcn);
    let files: NTFS_FILE_NAME_ATTR[] = [];
    for (const entry of entries) {
      if (entry.isSubNode()) {
        files = files.concat(this.walkSubNodes(entry.getVCN()));
      } else {
        if (entry.getKey().length > 0 && entry.getINodeNumber() > 16) {
          const fn = new NTFS_FILE_NAME_ATTR(entry.getKey());
          if (num(fn.get('FileNameType')) !== FILE_NAME_DOS) {
            files.push(fn);
          }
        }
      }
    }
    return files;
  }

  walk(): NTFS_FILE_NAME_ATTR[] | null {
    debug('Inside Walk...');
    let files: NTFS_FILE_NAME_ATTR[] = [];
    if (this.Attributes.has(INDEX_ROOT)) {
      const ir = this.Attributes.get(INDEX_ROOT) as AttributeIndexRoot;
      if (ir.getType() & FILE_NAME) {
        for (const ie of ir.IndexEntries) {
          if (ie.isSubNode()) {
            files = files.concat(this.walkSubNodes(ie.getVCN()));
          } else {
            if (ie.getKey().length > 0 && ie.getINodeNumber() > 16) {
              const fn = new NTFS_FILE_NAME_ATTR(ie.getKey());
              if (num(fn.get('FileNameType')) !== FILE_NAME_DOS) {
                files.push(fn);
              }
            }
          }
        }
        return files;
      }
      return null;
    }
    return null;
  }

  private findFirstSubNode(vcn: number, toSearch: string): IndexEntry | null {
    const getFileName = (entry: IndexEntry): string | null => {
      if (entry.getKey().length > 0 && entry.getINodeNumber() > 16) {
        const fn = new NTFS_FILE_NAME_ATTR(entry.getKey());
        if (num(fn.get('FileNameType')) !== FILE_NAME_DOS) {
          return (fn.get('FileName') as Buffer).toString('utf16le').toUpperCase();
        }
      }
      return null;
    };

    const entries = this.parseIndexBlocks(vcn);
    for (const ie of entries) {
      const name = getFileName(ie);
      if (name != null) {
        if (name === toSearch) return ie;
        if (toSearch < name) {
          if (ie.isSubNode()) {
            const res = this.findFirstSubNode(ie.getVCN(), toSearch);
            if (res != null) return res;
          } else {
            return null;
          }
        }
      } else {
        if (ie.isSubNode()) {
          const res = this.findFirstSubNode(ie.getVCN(), toSearch);
          if (res != null) return res;
        }
      }
    }
    return null;
  }

  findFirst(fileName: string): IndexEntry | null {
    const getFileName = (entry: IndexEntry): string | null => {
      if (entry.getKey().length > 0 && entry.getINodeNumber() > 16) {
        const fn = new NTFS_FILE_NAME_ATTR(entry.getKey());
        if (num(fn.get('FileNameType')) !== FILE_NAME_DOS) {
          return (fn.get('FileName') as Buffer).toString('utf16le').toUpperCase();
        }
      }
      return null;
    };

    const toSearch = fileName.toUpperCase();

    if (this.Attributes.has(INDEX_ROOT)) {
      const ir = this.Attributes.get(INDEX_ROOT) as AttributeIndexRoot;
      for (const ie of ir.IndexEntries) {
        const name = getFileName(ie);
        if (name != null) {
          if (name === toSearch) return ie;
          if (toSearch < name) {
            if (ie.isSubNode()) {
              const res = this.findFirstSubNode(ie.getVCN(), toSearch);
              if (res != null) return res;
            } else {
              return null;
            }
          }
        } else {
          if (ie.isSubNode()) {
            const res = this.findFirstSubNode(ie.getVCN(), toSearch);
            if (res != null) return res;
          }
        }
      }
    }
    return null;
  }

  getStream(name: string | null): AttributeResident | AttributeNonResident | null {
    return this.searchAttribute(DATA, name, false);
  }
}

// ---------------------------------------------------------------------------
// NTFS volume
// ---------------------------------------------------------------------------

class NTFS {
  private volumeName: string;
  private bootSector: NTFS_BOOT_SECTOR | null = null;
  private MFTStart = 0;
  volumeFD: VolumeFile;
  BPB: { BytesPerSector: number; SectorsPerCluster: number } | null = null;
  ExtendedBPB: NTFS_EXTENDED_BPB | null = null;
  RecordSize: number | null = null;
  IndexBlockSize: number | null = null;
  SectorSize: number | null = null;
  MFTINode: INODE | null = null;

  constructor(volumeName: string) {
    this.volumeName = volumeName;
    this.volumeFD = new VolumeFile(volumeName);
    this.mountVolume();
  }

  private mountVolume(): void {
    debug('Mounting volume...');
    this.readBootSector();
    this.MFTINode = this.getINode(FILE_MFT);
    // Check whether MFT is fragmented
    const attr = this.MFTINode.searchAttribute(DATA, null);
    if (attr == null) {
      this.MFTINode = null;
    }
  }

  private readBootSector(): void {
    debug(`Reading Boot Sector for ${this.volumeName}`);
    const data = this.volumeFD.read(0, 512);
    this.bootSector = new NTFS_BOOT_SECTOR(data);
    const bpb = new NTFS_BPB(this.bootSector.get('BPB') as Buffer);
    this.ExtendedBPB = new NTFS_EXTENDED_BPB(
      this.bootSector.get('ExtendedBPB') as Buffer,
    );
    const bytesPerSector = num(bpb.get('BytesPerSector'));
    const sectorsPerCluster = num(bpb.get('SectorsPerCluster'));
    this.BPB = { BytesPerSector: bytesPerSector, SectorsPerCluster: sectorsPerCluster };
    this.SectorSize = bytesPerSector;
    const clusterSize = bytesPerSector * sectorsPerCluster;
    this.MFTStart = clusterSize * num(this.ExtendedBPB.get('MFTClusterNumber'));

    const cpfr = num(this.ExtendedBPB.get('ClusterPerFileRecord'));
    if (cpfr > 0) {
      this.RecordSize = clusterSize * cpfr;
    } else {
      this.RecordSize = 1 << -cpfr;
    }
    const cpib = num(this.ExtendedBPB.get('ClusterPerIndexBuffer'));
    if (cpib > 0) {
      this.IndexBlockSize = clusterSize * cpib;
    } else {
      this.IndexBlockSize = 1 << -cpib;
    }

    debug(`MFT should start at position ${this.MFTStart}`);
  }

  getINode(iNodeNum: number): INODE {
    debug(`Trying to fetch inode ${iNodeNum}`);

    const newINode = new INODE(this);
    const recordLen = this.RecordSize!;

    let record: Buffer;
    if (this.MFTINode && iNodeNum > FIXED_MFTS) {
      // Fragmented $MFT - read through MFT's $DATA attribute
      const attr = this.MFTINode.searchAttribute(DATA, null);
      if (attr == null) {
        error(`Cannot find MFT $DATA attribute for inode ${iNodeNum}`);
        return newINode;
      }
      const r = attr.read(iNodeNum * this.RecordSize!, this.RecordSize!);
      record = r ?? Buffer.alloc(0);
    } else {
      const diskPosition = this.MFTStart + iNodeNum * this.RecordSize!;
      record = this.volumeFD.read(diskPosition, recordLen);
    }

    if (!record || record.length < recordLen) {
      error(`Failed to read MFT record for inode ${iNodeNum}`);
      return newINode;
    }

    const mftRecord = new NTFS_MFT_RECORD(record);

    const fixed = newINode.performFixUp(
      mftRecord,
      record,
      Math.floor(this.RecordSize! / this.SectorSize!),
    );
    if (fixed == null) {
      error(`FixUp failed for inode ${iNodeNum}`);
      return newINode;
    }

    newINode.INodeNumber = iNodeNum;
    const attributesOffset = num(mftRecord.get('AttributesOffset'));
    newINode.AttributesRaw = fixed.subarray(attributesOffset);
    newINode.parseAttributes();

    return newINode;
  }
}

// ---------------------------------------------------------------------------
// ntpath-style path helpers
// ---------------------------------------------------------------------------

function ntNormpath(p: string): string {
  p = p.replace(/\//g, '\\');
  const isAbs = p.startsWith('\\');
  const comps = p.split('\\');
  const out: string[] = [];
  for (const comp of comps) {
    if (comp === '' || comp === '.') continue;
    if (comp === '..') {
      if (out.length > 0 && out[out.length - 1] !== '..') {
        out.pop();
      } else if (!isAbs) {
        out.push('..');
      }
    } else {
      out.push(comp);
    }
  }
  let result = out.join('\\');
  if (isAbs) result = '\\' + result;
  if (result === '') result = isAbs ? '\\' : '.';
  return result;
}

function ntJoin(a: string, b: string): string {
  if (b.startsWith('\\') || b.startsWith('/')) return b.replace(/\//g, '\\');
  if (a === '' || a.endsWith('\\')) return a + b;
  return a + '\\' + b;
}

function commonPrefix(strs: string[]): string {
  if (strs.length === 0) return '';
  let prefix = strs[0]!;
  for (const s of strs.slice(1)) {
    let i = 0;
    while (i < prefix.length && i < s.length && prefix[i] === s[i]) i++;
    prefix = prefix.slice(0, i);
  }
  return prefix;
}

function formatDateTime(unixSeconds: number): string {
  const d = new Date(unixSeconds * 1000);
  const pad = (n: number): string => String(n).padStart(2, '0');
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  );
}

// ---------------------------------------------------------------------------
// MiniShell
// ---------------------------------------------------------------------------

class MiniShell {
  private volume: NTFS;
  private rootINode: INODE;
  private currentINode: INODE;
  private pwd = '\\';
  private prompt = '\\>';
  private completion: Array<[string, number]> = [];

  constructor(volumePath: string) {
    this.volume = new NTFS(volumePath);
    this.rootINode = this.volume.getINode(FILE_Root);
    this.currentINode = this.rootINode;
    this.do_ls('', false);
  }

  private findPathName(pathName: string): INODE | null {
    if (pathName === '\\') return this.rootINode;
    let tmpINode = this.currentINode;
    const parts = pathName.split('\\');
    for (const part of parts) {
      if (part === '') {
        tmpINode = this.rootINode;
      } else {
        const res = tmpINode.findFirst(part);
        if (res == null) return null;
        tmpINode = this.volume.getINode(res.getINodeNumber());
      }
    }
    return tmpINode;
  }

  do_help(): void {
    console.log(`
 cd {path} - changes the current directory to {path}
 pwd - shows current remote directory
 ls  - lists all the files in the current directory
 lcd - change local directory
 get {filename} - downloads the filename from the current path
 cat {filename} - prints the contents of filename
 hexdump {filename} - hexdumps the contents of filename
 exit - terminates the server process (and this session)
`);
  }

  do_pwd(): void {
    console.log(this.pwd);
  }

  do_lcd(line: string): void {
    if (line === '') {
      console.log(process.cwd());
    } else {
      try {
        process.chdir(line);
        console.log(process.cwd());
      } catch (e) {
        error(String(e));
      }
    }
  }

  do_cd(line: string): void {
    const p = line.replace(/\//g, '\\');
    const oldpwd = this.pwd;
    const newPath = ntNormpath(ntJoin(this.pwd, p));
    if (newPath === this.pwd) return;

    const common = commonPrefix([newPath, oldpwd]);
    let res: INODE | null;
    if (common === oldpwd) {
      res = this.findPathName(ntNormpath(p));
    } else {
      res = this.findPathName(newPath);
    }

    if (res == null) {
      error('Directory not found');
      this.pwd = oldpwd;
      return;
    }
    if (res.isDirectory() === 0) {
      error('Not a directory!');
      this.pwd = oldpwd;
      return;
    }

    this.currentINode = res;
    this.do_ls('', false);
    this.pwd = ntNormpath(ntJoin(this.pwd, p));
    this.prompt = this.pwd + '>';
  }

  do_ls(line: string, display = true): void {
    let entries = this.currentINode.walk();
    if (entries == null) entries = [];
    this.completion = [];
    for (const entry of entries) {
      const inode = new INODE(this.volume);
      inode.FileAttributes = num(entry.get('FileAttributes'));
      inode.FileSize = num(entry.get('DataSize'));
      inode.LastDataChangeTime = getUnixTime(
        entry.get('LastDataChangeTime') as bigint,
      );
      inode.FileName = (entry.get('FileName') as Buffer).toString('utf16le');
      if (display) inode.displayName();
      this.completion.push([inode.FileName, inode.isDirectory()]);
    }
  }

  do_cat(line: string, command?: (buf: Buffer) => void): void {
    let pathName = line.replace(/\//g, '\\');
    pathName = ntNormpath(ntJoin(this.pwd, pathName));
    const res = this.findPathName(pathName);
    if (res == null) {
      error('Not found!');
      return;
    }
    if (res.isDirectory() > 0) {
      error("It's a directory!");
      return;
    }
    if (res.isCompressed() || res.isEncrypted()) {
      error('Cannot handle compressed/encrypted files! :(');
      return;
    }

    const stream = res.getStream(null);
    if (stream == null) {
      error('Cannot read file stream!');
      return;
    }

    const write = command ?? ((buf: Buffer): void => void process.stdout.write(buf));

    const dataSize = stream.getDataSize();
    if (dataSize === 0) {
      info('0 bytes read (empty file)');
      return;
    }

    const chunkSize = 4096 * 10;
    let offset = 0;
    while (offset < dataSize) {
      const toRead = Math.min(chunkSize, dataSize - offset);
      const buf = stream.read(offset, toRead);
      if (!buf || buf.length === 0) break;
      try {
        write(buf);
      } catch {
        return;
      }
      offset += buf.length;
    }

    info(`${offset} bytes read`);
  }

  do_hexdump(line: string): void {
    this.do_cat(line, (buf: Buffer) => {
      process.stdout.write(hexdump(buf));
    });
  }

  do_get(line: string): void {
    let pathName = line.replace(/\//g, '\\');
    pathName = ntNormpath(ntJoin(this.pwd, pathName));
    const localName = path.win32.basename(pathName);
    const fd = openSync(localName, 'w');
    try {
      this.do_cat(line, (buf: Buffer) => {
        writeSync(fd, buf);
      });
    } finally {
      closeSync(fd);
    }
  }

  onecmd(line: string): boolean {
    const trimmed = line.trim();
    if (trimmed === '') return false;
    const spaceIdx = trimmed.indexOf(' ');
    const cmd = (spaceIdx === -1 ? trimmed : trimmed.slice(0, spaceIdx)).toLowerCase();
    const args = spaceIdx === -1 ? '' : trimmed.slice(spaceIdx + 1).trim();

    try {
      switch (cmd) {
        case 'exit':
        case 'quit':
          return true;
        case 'help':
        case '?':
          this.do_help();
          break;
        case 'pwd':
          this.do_pwd();
          break;
        case 'lcd':
          this.do_lcd(args);
          break;
        case 'cd':
          this.do_cd(args);
          break;
        case 'ls':
        case 'dir':
          this.do_ls(args, true);
          break;
        case 'cat':
          this.do_cat(args);
          break;
        case 'hexdump':
          this.do_hexdump(args);
          break;
        case 'get':
          this.do_get(args);
          break;
        default:
          error(`*** Unknown syntax: ${cmd}`);
          break;
      }
    } catch (e) {
      error(String(e));
    }
    return false;
  }

  getPrompt(): string {
    return this.prompt;
  }

  async cmdloop(): Promise<void> {
    console.log('Type help for list of commands');
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    rl.setPrompt(this.prompt);
    rl.prompt();
    for await (const line of rl) {
      const shouldExit = this.onecmd(line);
      if (shouldExit) {
        rl.close();
        break;
      }
      rl.setPrompt(this.prompt);
      rl.prompt();
    }
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printBanner(): void {
  console.log(BANNER + '\n');
}

function printUsage(): void {
  console.log(`NTFS explorer (read-only)

usage: ntfs-read [-h] [-extract EXTRACT] [-debug] [-ts] volume

positional arguments:
  volume            NTFS volume to open (e.g. \\\\.\\C: or /dev/disk1s1)

options:
  -h, --help        show this help message and exit
  -extract EXTRACT  extracts pathname (e.g. \\windows\\system32\\config\\sam)
  -debug            Turn DEBUG output ON
  -ts               Adds timestamp to every logging output
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
        extract: { type: 'string' },
        debug: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        help: { type: 'boolean', short: 'h', default: false },
        proxy: { type: 'string' },
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

  const volume = positionals[0]!;

  if (!existsSync(volume)) {
    error(`Volume "${volume}" does not exist or is not accessible.`);
    process.exit(1);
  }

  let shell: MiniShell;
  try {
    shell = new MiniShell(volume);
  } catch (e) {
    error(`Failed to mount volume: ${e}`);
    process.exit(1);
  }

  if (values.extract != null) {
    shell.onecmd(`get ${values.extract}`);
  } else {
    await shell.cmdloop();
  }

  process.exit(0);
}

main().catch((e) => {
  error(String(e));
  process.exit(1);
});
