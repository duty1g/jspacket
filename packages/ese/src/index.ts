import { Structure, hexdump } from '@impacket/structure';
import type { FieldDescriptor } from '@impacket/structure';
import * as fs from 'node:fs';

export { hexdump };

// Constants

export const FILE_TYPE_DATABASE = 0;
export const FILE_TYPE_STREAMING_FILE = 1;

// Database state
export const JET_dbstateJustCreated = 1;
export const JET_dbstateDirtyShutdown = 2;
export const JET_dbstateCleanShutdown = 3;
export const JET_dbstateBeingConverted = 4;
export const JET_dbstateForceDetach = 5;

// Page Flags
export const FLAGS_ROOT = 1;
export const FLAGS_LEAF = 2;
export const FLAGS_PARENT = 4;
export const FLAGS_EMPTY = 8;
export const FLAGS_SPACE_TREE = 0x20;
export const FLAGS_INDEX = 0x40;
export const FLAGS_LONG_VALUE = 0x80;
export const FLAGS_NEW_FORMAT = 0x2000;
export const FLAGS_NEW_CHECKSUM = 0x2000;

// Tag Flags
export const TAG_UNKNOWN = 0x1;
export const TAG_DEFUNCT = 0x2;
export const TAG_COMMON = 0x4;

// Fixed Page Numbers
export const DATABASE_PAGE_NUMBER = 1;
export const CATALOG_PAGE_NUMBER = 4;
export const CATALOG_BACKUP_PAGE_NUMBER = 24;

// Fixed FatherDataPages
export const DATABASE_FDP = 1;
export const CATALOG_FDP = 2;
export const CATALOG_BACKUP_FDP = 3;

// Catalog Types
export const CATALOG_TYPE_TABLE = 1;
export const CATALOG_TYPE_COLUMN = 2;
export const CATALOG_TYPE_INDEX = 3;
export const CATALOG_TYPE_LONG_VALUE = 4;
export const CATALOG_TYPE_CALLBACK = 5;

// Column Types
export const JET_coltypNil = 0;
export const JET_coltypBit = 1;
export const JET_coltypUnsignedByte = 2;
export const JET_coltypShort = 3;
export const JET_coltypLong = 4;
export const JET_coltypCurrency = 5;
export const JET_coltypIEEESingle = 6;
export const JET_coltypIEEEDouble = 7;
export const JET_coltypDateTime = 8;
export const JET_coltypBinary = 9;
export const JET_coltypText = 10;
export const JET_coltypLongBinary = 11;
export const JET_coltypLongText = 12;
export const JET_coltypSLV = 13;
export const JET_coltypUnsignedLong = 14;
export const JET_coltypLongLong = 15;
export const JET_coltypGUID = 16;
export const JET_coltypUnsignedShort = 17;
export const JET_coltypMax = 18;

export const ColumnTypeToName: Record<number, string> = {
  [JET_coltypNil]: 'NULL',
  [JET_coltypBit]: 'Boolean',
  [JET_coltypUnsignedByte]: 'Signed byte',
  [JET_coltypShort]: 'Signed short',
  [JET_coltypLong]: 'Signed long',
  [JET_coltypCurrency]: 'Currency',
  [JET_coltypIEEESingle]: 'Single precision FP',
  [JET_coltypIEEEDouble]: 'Double precision FP',
  [JET_coltypDateTime]: 'DateTime',
  [JET_coltypBinary]: 'Binary',
  [JET_coltypText]: 'Text',
  [JET_coltypLongBinary]: 'Long Binary',
  [JET_coltypLongText]: 'Long Text',
  [JET_coltypSLV]: 'Obsolete',
  [JET_coltypUnsignedLong]: 'Unsigned long',
  [JET_coltypLongLong]: 'Long long',
  [JET_coltypGUID]: 'GUID',
  [JET_coltypUnsignedShort]: 'Unsigned short',
  [JET_coltypMax]: 'Max',
};

type ColumnSizeEntry = null | [number, string];

export const ColumnTypeSize: Record<number, ColumnSizeEntry> = {
  [JET_coltypNil]: null,
  [JET_coltypBit]: [1, 'B'],
  [JET_coltypUnsignedByte]: [1, 'B'],
  [JET_coltypShort]: [2, '<h'],
  [JET_coltypLong]: [4, '<l'],
  [JET_coltypCurrency]: [8, '<Q'],
  [JET_coltypIEEESingle]: [4, '<f'],
  [JET_coltypIEEEDouble]: [8, '<d'],
  [JET_coltypDateTime]: [8, '<Q'],
  [JET_coltypBinary]: null,
  [JET_coltypText]: null,
  [JET_coltypLongBinary]: null,
  [JET_coltypLongText]: null,
  [JET_coltypSLV]: null,
  [JET_coltypUnsignedLong]: [4, '<L'],
  [JET_coltypLongLong]: [8, '<Q'],
  [JET_coltypGUID]: [16, '16s'],
  [JET_coltypUnsignedShort]: [2, '<H'],
  [JET_coltypMax]: null,
};

// Tagged Data Type Flags
export const TAGGED_DATA_TYPE_VARIABLE_SIZE = 1;
export const TAGGED_DATA_TYPE_COMPRESSED = 2;
export const TAGGED_DATA_TYPE_STORED = 4;
export const TAGGED_DATA_TYPE_MULTI_VALUE = 8;
export const TAGGED_DATA_TYPE_WHO_KNOWS = 10;

// Code pages
export const CODEPAGE_UNICODE = 1200;
export const CODEPAGE_ASCII = 20127;
export const CODEPAGE_WESTERN = 1252;

export const StringCodePages: Record<number, BufferEncoding> = {
  [CODEPAGE_UNICODE]: 'utf16le',
  [CODEPAGE_ASCII]: 'ascii',
  [CODEPAGE_WESTERN]: 'latin1',
};

export type RecordValue = Buffer | string | number | bigint | null;

// Table Cursor
export interface TableCursor {
  TableData: TableInfo;
  FatherDataPageNumber: number;
  CurrentPageData: ESENT_PAGE;
  CurrentTag: number;
}

export interface TableInfo {
  TableEntry: ESENT_LEAF_ENTRY;
  Columns: Map<string, ColumnInfo>;
  Indexes: Map<string, ESENT_LEAF_ENTRY>;
  LongValues: Map<string, ESENT_LEAF_ENTRY>;
}

export interface ColumnInfo {
  entry: ESENT_LEAF_ENTRY;
  Header: ESENT_DATA_DEFINITION_HEADER;
  Record: ESENT_CATALOG_DATA_DEFINITION_ENTRY;
}

// Structures

export class ESENT_JET_SIGNATURE extends Structure {
  static structure: FieldDescriptor[] = [
    ['Random', '<L=0'],
    ['CreationTime', '<Q=0'],
    ['NetBiosName', '16s=b""'],
  ];
}

export class ESENT_DB_HEADER extends Structure {
  static structure: FieldDescriptor[] = [
    ['CheckSum', '<L=0'],
    ['Signature', '"\xef\xcd\xab\x89'],
    ['Version', '<L=0'],
    ['FileType', '<L=0'],
    ['DBTime', '<Q=0'],
    ['DBSignature', ':', ESENT_JET_SIGNATURE],
    ['DBState', '<L=0'],
    ['ConsistentPosition', '<Q=0'],
    ['ConsistentTime', '<Q=0'],
    ['AttachTime', '<Q=0'],
    ['AttachPosition', '<Q=0'],
    ['DetachTime', '<Q=0'],
    ['DetachPosition', '<Q=0'],
    ['LogSignature', ':', ESENT_JET_SIGNATURE],
    ['Unknown', '<L=0'],
    ['PreviousBackup', '24s=b""'],
    ['PreviousIncBackup', '24s=b""'],
    ['CurrentFullBackup', '24s=b""'],
    ['ShadowingDisables', '<L=0'],
    ['LastObjectID', '<L=0'],
    ['WindowsMajorVersion', '<L=0'],
    ['WindowsMinorVersion', '<L=0'],
    ['WindowsBuildNumber', '<L=0'],
    ['WindowsServicePackNumber', '<L=0'],
    ['FileFormatRevision', '<L=0'],
    ['PageSize', '<L=0'],
    ['RepairCount', '<L=0'],
    ['RepairTime', '<Q=0'],
    ['Unknown2', '28s=b""'],
    ['ScrubTime', '<Q=0'],
    ['RequiredLog', '<Q=0'],
    ['UpgradeExchangeFormat', '<L=0'],
    ['UpgradeFreePages', '<L=0'],
    ['UpgradeSpaceMapPages', '<L=0'],
    ['CurrentShadowBackup', '24s=b""'],
    ['CreationFileFormatVersion', '<L=0'],
    ['CreationFileFormatRevision', '<L=0'],
    ['Unknown3', '16s=b""'],
    ['OldRepairCount', '<L=0'],
    ['ECCCount', '<L=0'],
    ['LastECCTime', '<Q=0'],
    ['OldECCFixSuccessCount', '<L=0'],
    ['ECCFixErrorCount', '<L=0'],
    ['LastECCFixErrorTime', '<Q=0'],
    ['OldECCFixErrorCount', '<L=0'],
    ['BadCheckSumErrorCount', '<L=0'],
    ['LastBadCheckSumTime', '<Q=0'],
    ['OldCheckSumErrorCount', '<L=0'],
    ['CommittedLog', '<L=0'],
    ['PreviousShadowCopy', '24s=b""'],
    ['PreviousDifferentialBackup', '24s=b""'],
    ['Unknown4', '40s=b""'],
    ['NLSMajorVersion', '<L=0'],
    ['NLSMinorVersion', '<L=0'],
    ['Unknown5', '148s=b""'],
    ['UnknownFlags', '<L=0'],
  ];
}

const PAGE_HEADER_2003_SP0: FieldDescriptor[] = [
  ['CheckSum', '<L=0'],
  ['PageNumber', '<L=0'],
];

const PAGE_HEADER_0x620_0x0b: FieldDescriptor[] = [
  ['CheckSum', '<L=0'],
  ['ECCCheckSum', '<L=0'],
];

const PAGE_HEADER_WIN7: FieldDescriptor[] = [
  ['CheckSum', '<Q=0'],
];

const PAGE_HEADER_COMMON: FieldDescriptor[] = [
  ['LastModificationTime', '<Q=0'],
  ['PreviousPageNumber', '<L=0'],
  ['NextPageNumber', '<L=0'],
  ['FatherDataPage', '<L=0'],
  ['AvailableDataSize', '<H=0'],
  ['AvailableUncommittedDataSize', '<H=0'],
  ['FirstAvailableDataOffset', '<H=0'],
  ['FirstAvailablePageTag', '<H=0'],
  ['PageFlags', '<L=0'],
];

const PAGE_HEADER_EXTENDED_WIN7: FieldDescriptor[] = [
  ['ExtendedCheckSum1', '<Q=0'],
  ['ExtendedCheckSum2', '<Q=0'],
  ['ExtendedCheckSum3', '<Q=0'],
  ['PageNumber', '<Q=0'],
  ['Unknown', '<Q=0'],
];

export class ESENT_PAGE_HEADER extends Structure {
  constructor(version: number, revision: number, pageSize = 8192, data?: Buffer | null) {
    super(null);
    if (version < 0x620 || (version === 0x620 && revision < 0x0b)) {
      this.structure = [...PAGE_HEADER_2003_SP0, ...PAGE_HEADER_COMMON];
    } else if (version === 0x620 && revision < 0x11) {
      this.structure = [...PAGE_HEADER_0x620_0x0b, ...PAGE_HEADER_COMMON];
    } else {
      this.structure = [...PAGE_HEADER_WIN7, ...PAGE_HEADER_COMMON];
      if (pageSize > 8192) {
        this.structure = [...this.structure, ...PAGE_HEADER_EXTENDED_WIN7];
      }
    }
    if (data) {
      this.fromString(Buffer.from(data));
    }
  }
}

export class ESENT_ROOT_HEADER extends Structure {
  static structure: FieldDescriptor[] = [
    ['InitialNumberOfPages', '<L=0'],
    ['ParentFatherDataPage', '<L=0'],
    ['ExtentSpace', '<L=0'],
    ['SpaceTreePageNumber', '<L=0'],
  ];
}

export class ESENT_BRANCH_HEADER extends Structure {
  static structure: FieldDescriptor[] = [
    ['CommonPageKey', ':'],
  ];
}

const BRANCH_ENTRY_COMMON: FieldDescriptor[] = [
  ['CommonPageKeySize', '<H=0'],
];

const BRANCH_ENTRY_MAIN: FieldDescriptor[] = [
  ['LocalPageKeySize', '<H=0'],
  ['_LocalPageKey', '_-LocalPageKey', 'self["LocalPageKeySize"]'],
  ['LocalPageKey', ':'],
  ['ChildPageNumber', '<L=0'],
];

export class ESENT_BRANCH_ENTRY extends Structure {
  constructor(flags: number, data?: Buffer | null) {
    super(null);
    if (flags & TAG_COMMON) {
      this.structure = [...BRANCH_ENTRY_COMMON, ...BRANCH_ENTRY_MAIN];
    } else {
      this.structure = [...BRANCH_ENTRY_MAIN];
    }
    if (data) {
      this.fromString(Buffer.from(data));
    }
  }
}

export class ESENT_LEAF_HEADER extends Structure {
  static structure: FieldDescriptor[] = [
    ['CommonPageKey', ':'],
  ];
}

const LEAF_ENTRY_COMMON: FieldDescriptor[] = [
  ['CommonPageKeySize', '<H=0'],
];

const LEAF_ENTRY_MAIN: FieldDescriptor[] = [
  ['LocalPageKeySize', '<H=0'],
  ['_LocalPageKey', '_-LocalPageKey', 'self["LocalPageKeySize"]'],
  ['LocalPageKey', ':'],
  ['EntryData', ':'],
];

export class ESENT_LEAF_ENTRY extends Structure {
  constructor(flags: number, data?: Buffer | null) {
    super(null);
    if (flags & TAG_COMMON) {
      this.structure = [...LEAF_ENTRY_COMMON, ...LEAF_ENTRY_MAIN];
    } else {
      this.structure = [...LEAF_ENTRY_MAIN];
    }
    if (data) {
      this.fromString(Buffer.from(data));
    }
  }
}

export class ESENT_SPACE_TREE_HEADER extends Structure {
  static structure: FieldDescriptor[] = [
    ['Unknown', '<Q=0'],
  ];
}

export class ESENT_SPACE_TREE_ENTRY extends Structure {
  static structure: FieldDescriptor[] = [
    ['PageKeySize', '<H=0'],
    ['LastPageNumber', '<L=0'],
    ['NumberOfPages', '<L=0'],
  ];
}

export class ESENT_INDEX_ENTRY extends Structure {
  static structure: FieldDescriptor[] = [
    ['RecordPageKey', ':'],
  ];
}

export class ESENT_DATA_DEFINITION_HEADER extends Structure {
  static structure: FieldDescriptor[] = [
    ['LastFixedSize', '<B=0'],
    ['LastVariableDataType', '<B=0'],
    ['VariableSizeOffset', '<H=0'],
  ];
}

const CATALOG_FIXED: FieldDescriptor[] = [
  ['FatherDataPageID', '<L=0'],
  ['Type', '<H=0'],
  ['Identifier', '<L=0'],
];

const CATALOG_COLUMN_STUFF: FieldDescriptor[] = [
  ['ColumnType', '<L=0'],
  ['SpaceUsage', '<L=0'],
  ['ColumnFlags', '<L=0'],
  ['CodePage', '<L=0'],
];

const CATALOG_OTHER: FieldDescriptor[] = [
  ['FatherDataPageNumber', '<L=0'],
];

const CATALOG_TABLE_STUFF: FieldDescriptor[] = [
  ['SpaceUsage', '<L=0'],
];

const CATALOG_INDEX_STUFF: FieldDescriptor[] = [
  ['SpaceUsage', '<L=0'],
  ['IndexFlags', '<L=0'],
  ['Locale', '<L=0'],
];

const CATALOG_LV_STUFF: FieldDescriptor[] = [
  ['SpaceUsage', '<L=0'],
];

const CATALOG_COMMON: FieldDescriptor[] = [
  ['Trailing', ':'],
];

export class ESENT_CATALOG_DATA_DEFINITION_ENTRY extends Structure {
  constructor(data?: Buffer | null) {
    super(null);
    if (!data || data.length < 6) {
      this.structure = [...CATALOG_FIXED, ...CATALOG_COMMON];
      if (data) this.fromString(Buffer.from(data));
      return;
    }

    const dataType = data.readUInt16LE(4);
    let s: FieldDescriptor[] = [...CATALOG_FIXED];

    if (dataType === CATALOG_TYPE_TABLE) {
      s = [...s, ...CATALOG_OTHER, ...CATALOG_TABLE_STUFF];
    } else if (dataType === CATALOG_TYPE_COLUMN) {
      s = [...s, ...CATALOG_COLUMN_STUFF];
    } else if (dataType === CATALOG_TYPE_INDEX) {
      s = [...s, ...CATALOG_OTHER, ...CATALOG_INDEX_STUFF];
    } else if (dataType === CATALOG_TYPE_LONG_VALUE) {
      s = [...s, ...CATALOG_OTHER, ...CATALOG_LV_STUFF];
    } else if (dataType === CATALOG_TYPE_CALLBACK) {
      throw new Error('CallBack types not supported!');
    } else {
      console.error('Unknown catalog type 0x%s', dataType.toString(16));
      this.structure = [];
      if (data) this.fromString(Buffer.from(data));
      return;
    }

    this.structure = [...s, ...CATALOG_COMMON];
    this.fromString(Buffer.from(data));
  }
}

export function getUnixTime(t: bigint | number): number {
  let val = typeof t === 'bigint' ? t : BigInt(t);
  val -= 116444736000000000n;
  val /= 10000000n;
  return Number(val);
}

export class ESENT_PAGE {
  private dbHeader: ESENT_DB_HEADER;
  data: Buffer;
  record: ESENT_PAGE_HEADER;

  constructor(db: ESENT_DB_HEADER, data: Buffer) {
    this.dbHeader = db;
    this.data = data;
    this.record = new ESENT_PAGE_HEADER(
      db.get('Version') as number,
      db.get('FileFormatRevision') as number,
      db.get('PageSize') as number,
      data,
    );
  }

  printFlags(): void {
    const flags = this.record.get('PageFlags') as number;
    if (flags & FLAGS_EMPTY) console.log('\tEmpty');
    if (flags & FLAGS_INDEX) console.log('\tIndex');
    if (flags & FLAGS_LEAF) console.log('\tLeaf');
    else console.log('\tBranch');
    if (flags & FLAGS_LONG_VALUE) console.log('\tLong Value');
    if (flags & FLAGS_NEW_CHECKSUM) console.log('\tNew Checksum');
    if (flags & FLAGS_NEW_FORMAT) console.log('\tNew Format');
    if (flags & FLAGS_PARENT) console.log('\tParent');
    if (flags & FLAGS_ROOT) console.log('\tRoot');
    if (flags & FLAGS_SPACE_TREE) console.log('\tSpace Tree');
  }

  dump(): void {
    const baseOffset = this.record.length;
    this.record.dump();
    const firstAvail = this.record.get('FirstAvailablePageTag') as number;
    let tags = this.data.subarray(this.data.length - 4 * firstAvail);

    console.log('FLAGS: ');
    this.printFlags();
    console.log();

    const version = this.dbHeader.get('Version') as number;
    const revision = this.dbHeader.get('FileFormatRevision') as number;
    const pageSize = this.dbHeader.get('PageSize') as number;

    for (let i = 0; i < firstAvail; i++) {
      const tag = tags.subarray(tags.length - 4);
      let valueSize: number;
      let valueOffset: number;
      let pageFlags: number;

      if (version === 0x620 && revision > 11 && pageSize > 8192) {
        valueSize = tag.readUInt16LE(0) & 0x7fff;
        valueOffset = tag.readUInt16LE(2) & 0x7fff;
        hexdump(this.data.subarray(baseOffset + valueOffset, baseOffset + valueOffset + 6));
        pageFlags = this.data[baseOffset + valueOffset + 1]! >> 5;
      } else {
        valueSize = tag.readUInt16LE(0) & 0x1fff;
        pageFlags = (tag.readUInt16LE(2) & 0xe000) >> 13;
        valueOffset = tag.readUInt16LE(2) & 0x1fff;
      }

      console.log(
        `TAG ${String(i).padEnd(8)} offset:0x${valueOffset.toString(16).padEnd(6)} flags:0x${pageFlags.toString(16).padEnd(4)} valueSize:0x${valueSize.toString(16)}`,
      );
      tags = tags.subarray(0, tags.length - 4);
    }

    if ((this.record.get('PageFlags') as number) & FLAGS_ROOT) {
      const rootHeader = new ESENT_ROOT_HEADER(this.getTag(0)[1]);
      rootHeader.dump();
    } else if (!((this.record.get('PageFlags') as number) & FLAGS_LEAF)) {
      const [, data] = this.getTag(0);
      const branchHeader = new ESENT_BRANCH_HEADER(data);
      branchHeader.dump();
    } else {
      const [, data] = this.getTag(0);
      if ((this.record.get('PageFlags') as number) & FLAGS_SPACE_TREE) {
        const spaceTreeHeader = new ESENT_SPACE_TREE_HEADER(data);
        spaceTreeHeader.dump();
      } else {
        const leafHeader = new ESENT_LEAF_HEADER(data);
        leafHeader.dump();
      }
    }

    for (let tagNum = 1; tagNum < firstAvail; tagNum++) {
      const [flags, data] = this.getTag(tagNum);
      if (!((this.record.get('PageFlags') as number) & FLAGS_LEAF)) {
        const branchEntry = new ESENT_BRANCH_ENTRY(flags, data);
        branchEntry.dump();
      } else if ((this.record.get('PageFlags') as number) & FLAGS_LEAF) {
        if ((this.record.get('PageFlags') as number) & FLAGS_SPACE_TREE) {
          // Space Tree entry
        } else if ((this.record.get('PageFlags') as number) & FLAGS_INDEX) {
          // Index Entry
        } else if ((this.record.get('PageFlags') as number) & FLAGS_LONG_VALUE) {
          throw new Error('Long value still not supported');
        } else {
          const leafEntry = new ESENT_LEAF_ENTRY(flags, data);
          const entryData = leafEntry.get('EntryData') as Buffer;
          const dataDefHeader = new ESENT_DATA_DEFINITION_HEADER(entryData);
          dataDefHeader.dump();
          const catalogEntry = new ESENT_CATALOG_DATA_DEFINITION_ENTRY(
            entryData.subarray(dataDefHeader.length),
          );
          catalogEntry.dump();
          hexdump(entryData);
        }
      }
    }
  }

  getTag(tagNum: number): [number, Buffer] {
    const firstAvail = this.record.get('FirstAvailablePageTag') as number;
    if (firstAvail < tagNum) {
      throw new Error(`Trying to grab an unknown tag 0x${tagNum.toString(16)}`);
    }

    let tags = this.data.subarray(this.data.length - 4 * firstAvail);
    const baseOffset = this.record.length;

    for (let i = 0; i < tagNum; i++) {
      tags = tags.subarray(0, tags.length - 4);
    }

    const tag = tags.subarray(tags.length - 4);

    const version = this.dbHeader.get('Version') as number;
    const revision = this.dbHeader.get('FileFormatRevision') as number;
    const pageSize = this.dbHeader.get('PageSize') as number;

    if (version === 0x620 && revision >= 17 && pageSize > 8192) {
      const valueSize = tag.readUInt16LE(0) & 0x7fff;
      const valueOffset = tag.readUInt16LE(2) & 0x7fff;
      const tmpData = Buffer.from(this.data.subarray(baseOffset + valueOffset, baseOffset + valueOffset + valueSize));
      const pageFlags = tmpData[1]! >> 5;
      tmpData[1] = tmpData[1]! & 0x1f;
      return [pageFlags, tmpData];
    } else {
      const valueSize = tag.readUInt16LE(0) & 0x1fff;
      const pageFlags = (tag.readUInt16LE(2) & 0xe000) >> 13;
      const valueOffset = tag.readUInt16LE(2) & 0x1fff;
      const tagData = Buffer.from(this.data.subarray(baseOffset + valueOffset, baseOffset + valueOffset + valueSize));
      return [pageFlags, tagData];
    }
  }
}

export interface RemoteFile {
  open(): void;
  read(n: number): Buffer;
  seek(offset: number, whence?: number): void;
  tell(): number;
  close(): void;
}

export class ESENT_DB {
  private fileName: string | RemoteFile;
  private pageSize: number;
  private db: { fd: number } | RemoteFile | null = null;
  private dbHeader!: ESENT_DB_HEADER;
  private totalPages = 0;
  private tables = new Map<string, TableInfo>();
  private currentTable = '';
  private isRemote: boolean;
  private filePos = 0;

  constructor(fileName: string | RemoteFile, pageSize = 8192, isRemote = false) {
    this.fileName = fileName;
    this.pageSize = pageSize;
    this.isRemote = isRemote;
    this.mountDB();
  }

  private fileRead(n: number): Buffer {
    if (this.isRemote) {
      const remote = this.db as RemoteFile;
      return remote.read(n);
    }
    const local = this.db as { fd: number };
    const buf = Buffer.alloc(n);
    const bytesRead = fs.readSync(local.fd, buf, 0, n, this.filePos);
    this.filePos += bytesRead;
    return buf.subarray(0, bytesRead);
  }

  private fileSeek(offset: number, whence = 0): void {
    if (this.isRemote) {
      const remote = this.db as RemoteFile;
      remote.seek(offset, whence);
      return;
    }
    if (whence === 0) {
      this.filePos = offset;
    } else if (whence === 1) {
      this.filePos += offset;
    } else if (whence === 2) {
      const local = this.db as { fd: number };
      const stat = fs.fstatSync(local.fd);
      this.filePos = Number(stat.size) + offset;
    }
  }

  private fileTell(): number {
    if (this.isRemote) {
      const remote = this.db as RemoteFile;
      return remote.tell();
    }
    return this.filePos;
  }

  private mountDB(): void {
    console.debug('Mounting DB...');
    if (this.isRemote) {
      this.db = this.fileName as RemoteFile;
      (this.db as RemoteFile).open();
    } else {
      const fd = fs.openSync(this.fileName as string, 'r');
      this.db = { fd };
    }

    const mainHeader = this.getPage(-1) as Buffer;
    this.dbHeader = new ESENT_DB_HEADER(mainHeader);
    this.pageSize = this.dbHeader.get('PageSize') as number;

    this.fileSeek(0, 2);
    this.totalPages = Math.floor(this.fileTell() / this.pageSize) - 2;

    console.debug(
      'Database Version:0x%s, Revision:0x%s',
      (this.dbHeader.get('Version') as number).toString(16),
      (this.dbHeader.get('FileFormatRevision') as number).toString(16),
    );
    console.debug('Page Size: %d', this.pageSize);
    console.debug('Total Pages in file: %d', this.totalPages);

    this.parseCatalog(CATALOG_PAGE_NUMBER);
  }

  printCatalog(): void {
    const indent = '    ';
    console.log(
      'Database version: 0x%s, 0x%s',
      (this.dbHeader.get('Version') as number).toString(16),
      (this.dbHeader.get('FileFormatRevision') as number).toString(16),
    );
    console.log('Page size: %d', this.pageSize);
    console.log('Number of pages: %d', this.totalPages);
    console.log();
    console.log('Catalog for %s', typeof this.fileName === 'string' ? this.fileName : '<remote>');

    for (const [table, tableInfo] of this.tables) {
      console.log('[%s]', table);
      console.log('%sColumns ', indent);
      for (const [column, colInfo] of tableInfo.Columns) {
        const record = colInfo.Record;
        const id = record.get('Identifier') as number;
        const colType = record.get('ColumnType') as number;
        console.log(
          '%s%d  %s  %s',
          indent + indent,
          id,
          column,
          ColumnTypeToName[colType] ?? 'Unknown',
        );
      }
      console.log('%sIndexes', indent);
      for (const [index] of tableInfo.Indexes) {
        console.log('%s%s', indent + indent, index);
      }
      console.log('');
    }
  }

  private addItem(entry: ESENT_LEAF_ENTRY): void {
    const entryData = entry.get('EntryData') as Buffer;
    const dataDefinitionHeader = new ESENT_DATA_DEFINITION_HEADER(entryData);
    const catalogEntry = new ESENT_CATALOG_DATA_DEFINITION_ENTRY(
      entryData.subarray(dataDefinitionHeader.length),
    );
    const itemName = this.parseItemName(entry);

    const catType = catalogEntry.get('Type') as number;
    if (catType === CATALOG_TYPE_TABLE) {
      const tableInfo: TableInfo = {
        TableEntry: entry,
        Columns: new Map(),
        Indexes: new Map(),
        LongValues: new Map(),
      };
      this.tables.set(itemName, tableInfo);
      this.currentTable = itemName;
    } else if (catType === CATALOG_TYPE_COLUMN) {
      const table = this.tables.get(this.currentTable)!;
      table.Columns.set(itemName, {
        entry,
        Header: dataDefinitionHeader,
        Record: catalogEntry,
      });
    } else if (catType === CATALOG_TYPE_INDEX) {
      const table = this.tables.get(this.currentTable)!;
      table.Indexes.set(itemName, entry);
    } else if (catType === CATALOG_TYPE_LONG_VALUE) {
      this.addLongValue(entry);
    } else {
      throw new Error(`Unknown type 0x${catType.toString(16)}`);
    }
  }

  private parseItemName(entry: ESENT_LEAF_ENTRY): string {
    const entryData = entry.get('EntryData') as Buffer;
    const dataDefinitionHeader = new ESENT_DATA_DEFINITION_HEADER(entryData);

    const lastVarType = dataDefinitionHeader.get('LastVariableDataType') as number;
    const numEntries = lastVarType > 127 ? lastVarType - 127 : lastVarType;
    const varOffset = dataDefinitionHeader.get('VariableSizeOffset') as number;

    const itemLen = entryData.readUInt16LE(varOffset);
    const itemName = entryData.subarray(varOffset + 2 * numEntries, varOffset + 2 * numEntries + itemLen);
    return itemName.toString('utf-8');
  }

  private addLongValue(entry: ESENT_LEAF_ENTRY): void {
    const entryData = entry.get('EntryData') as Buffer;
    const dataDefinitionHeader = new ESENT_DATA_DEFINITION_HEADER(entryData);
    const varOffset = dataDefinitionHeader.get('VariableSizeOffset') as number;

    const lvLen = entryData.readUInt16LE(varOffset);
    const lvName = entryData.subarray(varOffset + 7, varOffset + 7 + lvLen).toString('utf-8');
    const table = this.tables.get(this.currentTable)!;
    table.LongValues.set(lvName, entry);
  }

  private parsePage(page: ESENT_PAGE): void {
    const firstAvail = page.record.get('FirstAvailablePageTag') as number;
    for (let tagNum = 1; tagNum < firstAvail; tagNum++) {
      const [flags, data] = page.getTag(tagNum);
      const pageFlags = page.record.get('PageFlags') as number;
      if (pageFlags & FLAGS_LEAF) {
        if (pageFlags & FLAGS_SPACE_TREE) {
          // skip
        } else if (pageFlags & FLAGS_INDEX) {
          // skip
        } else if (pageFlags & FLAGS_LONG_VALUE) {
          // skip
        } else {
          const leafEntry = new ESENT_LEAF_ENTRY(flags, data);
          this.addItem(leafEntry);
        }
      }
    }
  }

  private parseCatalog(pageNum: number): void {
    const page = this.getPage(pageNum) as ESENT_PAGE;
    this.parsePage(page);

    const firstAvail = page.record.get('FirstAvailablePageTag') as number;
    for (let i = 1; i < firstAvail; i++) {
      const [flags, data] = page.getTag(i);
      const pageFlags = page.record.get('PageFlags') as number;
      if (!(pageFlags & FLAGS_LEAF)) {
        const branchEntry = new ESENT_BRANCH_ENTRY(flags, data);
        this.parseCatalog(branchEntry.get('ChildPageNumber') as number);
      }
    }
  }

  getPage(pageNum: number): Buffer | ESENT_PAGE {
    console.debug(
      'Trying to fetch page %d (0x%s)',
      pageNum,
      ((pageNum + 1) * this.pageSize).toString(16),
    );
    this.fileSeek((pageNum + 1) * this.pageSize, 0);
    let data = this.fileRead(this.pageSize);
    while (data.length < this.pageSize) {
      const remaining = this.pageSize - data.length;
      const more = this.fileRead(remaining);
      data = Buffer.concat([data, more]);
    }
    if (pageNum <= 0) {
      return data;
    }
    return new ESENT_PAGE(this.dbHeader, data);
  }

  close(): void {
    if (this.isRemote) {
      (this.db as RemoteFile).close();
    } else if (this.db) {
      fs.closeSync((this.db as { fd: number }).fd);
    }
  }

  openTable(tableName: string): TableCursor | null {
    if (this.tables.has(tableName)) {
      const tableInfo = this.tables.get(tableName)!;
      const entry = tableInfo.TableEntry;
      const entryData = entry.get('EntryData') as Buffer;
      const dataDefinitionHeader = new ESENT_DATA_DEFINITION_HEADER(entryData);
      const catalogEntry = new ESENT_CATALOG_DATA_DEFINITION_ENTRY(
        entryData.subarray(dataDefinitionHeader.length),
      );

      let pageNum = catalogEntry.get('FatherDataPageNumber') as number;
      let done = false;
      let page: ESENT_PAGE = this.getPage(pageNum) as ESENT_PAGE;

      while (!done) {
        page = this.getPage(pageNum) as ESENT_PAGE;
        const firstAvail = page.record.get('FirstAvailablePageTag') as number;
        if (firstAvail <= 1) {
          done = true;
        }
        for (let i = 1; i < firstAvail; i++) {
          const [flags, data] = page.getTag(i);
          const pFlags = page.record.get('PageFlags') as number;
          if (!(pFlags & FLAGS_LEAF)) {
            const branchEntry = new ESENT_BRANCH_ENTRY(flags, data);
            pageNum = branchEntry.get('ChildPageNumber') as number;
            break;
          } else {
            done = true;
            break;
          }
        }
      }

      const cursor: TableCursor = {
        TableData: tableInfo,
        FatherDataPageNumber: catalogEntry.get('FatherDataPageNumber') as number,
        CurrentPageData: page,
        CurrentTag: 0,
      };
      return cursor;
    }
    return null;
  }

  private getNextTag(cursor: TableCursor): ESENT_LEAF_ENTRY | null {
    const page = cursor.CurrentPageData;
    const firstAvail = page.record.get('FirstAvailablePageTag') as number;

    if (cursor.CurrentTag >= firstAvail) {
      return null;
    }

    const [flags, data] = page.getTag(cursor.CurrentTag);
    const pageFlags = page.record.get('PageFlags') as number;

    if (pageFlags & FLAGS_LEAF) {
      if (pageFlags & FLAGS_SPACE_TREE) {
        throw new Error('FLAGS_SPACE_TREE > 0');
      } else if (pageFlags & FLAGS_INDEX) {
        throw new Error('FLAGS_INDEX > 0');
      } else if (pageFlags & FLAGS_LONG_VALUE) {
        throw new Error('FLAGS_LONG_VALUE > 0');
      } else {
        return new ESENT_LEAF_ENTRY(flags, data);
      }
    }

    return null;
  }

  getNextRow(
    cursor: TableCursor,
    filterTables?: Set<string> | null,
  ): Map<string, RecordValue> | null {
    cursor.CurrentTag += 1;

    const tag = this.getNextTag(cursor);

    if (tag === null) {
      const page = cursor.CurrentPageData;
      const nextPageNum = page.record.get('NextPageNumber') as number;
      if (nextPageNum === 0) {
        return null;
      }
      cursor.CurrentPageData = this.getPage(nextPageNum) as ESENT_PAGE;
      cursor.CurrentTag = 0;
      return this.getNextRow(cursor, filterTables);
    }
    return this.tagToRecord(cursor, tag.get('EntryData') as Buffer, filterTables);
  }

  private tagToRecord(
    cursor: TableCursor,
    tag: Buffer,
    filterTables?: Set<string> | null,
  ): Map<string, RecordValue> {
    const record = new Map<string, RecordValue>();
    const taggedItems = new Map<number, [number, number, number]>();
    let taggedItemsParsed = false;

    const dataDefinitionHeader = new ESENT_DATA_DEFINITION_HEADER(tag);
    const lastVarType = dataDefinitionHeader.get('LastVariableDataType') as number;
    let variableDataBytesProcessed = (lastVarType - 127) * 2;
    let prevItemLen = 0;
    const tagLen = tag.length;
    let fixedSizeOffset = dataDefinitionHeader.length;
    const variableSizeOffset = dataDefinitionHeader.get('VariableSizeOffset') as number;

    const columns = cursor.TableData.Columns;

    for (const [column, colInfo] of columns) {
      if (filterTables && !filterTables.has(column)) {
        continue;
      }
      const columnRecord = colInfo.Record;
      const identifier = columnRecord.get('Identifier') as number;
      const lastFixed = dataDefinitionHeader.get('LastFixedSize') as number;

      if (identifier <= lastFixed) {
        const spaceUsage = columnRecord.get('SpaceUsage') as number;
        record.set(column, Buffer.from(tag.subarray(fixedSizeOffset, fixedSizeOffset + spaceUsage)));
        fixedSizeOffset += spaceUsage;
      } else if (identifier > 127 && identifier <= lastVarType) {
        const index = identifier - 127 - 1;
        let itemLen = tag.readUInt16LE(variableSizeOffset + index * 2);

        if (itemLen & 0x8000) {
          itemLen = prevItemLen;
          record.set(column, null);
        } else {
          const itemValue = Buffer.from(
            tag.subarray(
              variableSizeOffset + variableDataBytesProcessed,
              variableSizeOffset + variableDataBytesProcessed + itemLen - prevItemLen,
            ),
          );
          record.set(column, itemValue);
        }

        variableDataBytesProcessed += itemLen - prevItemLen;
        prevItemLen = itemLen;
      } else if (identifier > 255) {
        if (!taggedItemsParsed && variableDataBytesProcessed + variableSizeOffset < tagLen) {
          let index = variableDataBytesProcessed + variableSizeOffset;
          const firstOffsetTag =
            (tag.readUInt16LE(index + 2) & 0x3fff) + variableDataBytesProcessed + variableSizeOffset;

          while (true) {
            const taggedIdentifier = tag.readUInt16LE(index);
            index += 2;
            const taggedOffset = tag.readUInt16LE(index) & 0x3fff;

            const dbVersion = this.dbHeader.get('Version') as number;
            const dbRevision = this.dbHeader.get('FileFormatRevision') as number;
            const dbPageSize = this.dbHeader.get('PageSize') as number;

            let flagsPresent: number;
            if (dbVersion === 0x620 && dbRevision >= 17 && dbPageSize > 8192) {
              flagsPresent = 1;
            } else {
              flagsPresent = tag.readUInt16LE(index) & 0x4000;
            }
            index += 2;

            taggedItems.set(taggedIdentifier, [taggedOffset, tagLen, flagsPresent]);

            if (index >= firstOffsetTag) {
              break;
            }
          }

          const keys = Array.from(taggedItems.keys());
          let prevKey = keys[0]!;
          for (let i = 1; i < keys.length; i++) {
            const [offset0, , flags] = taggedItems.get(prevKey)!;
            const [offset] = taggedItems.get(keys[i]!)!;
            taggedItems.set(prevKey, [offset0, offset - offset0, flags]);
            prevKey = keys[i]!;
          }
          taggedItemsParsed = true;
        }

        if (taggedItems.has(identifier)) {
          const [tagOffset, itemSize, itemFlagPresent] = taggedItems.get(identifier)!;
          let offsetItem = variableDataBytesProcessed + variableSizeOffset + tagOffset;
          let size = itemSize;

          let itemFlag = 0;
          if (itemFlagPresent > 0) {
            itemFlag = tag[offsetItem]!;
            offsetItem += 1;
            size -= 1;
          }

          if (itemFlag & TAGGED_DATA_TYPE_COMPRESSED) {
            console.error('Unsupported tag column: %s, flag:0x%s', column, itemFlag.toString(16));
            record.set(column, null);
          } else if (itemFlag & TAGGED_DATA_TYPE_MULTI_VALUE) {
            console.debug('Multivalue detected in column %s, returning raw results', column);
            record.set(column, tag.subarray(offsetItem, offsetItem + size).toString('hex'));
          } else {
            record.set(column, Buffer.from(tag.subarray(offsetItem, offsetItem + size)));
          }
        } else {
          record.set(column, null);
        }
      } else {
        record.set(column, null);
      }

      const colValue = record.get(column);
      const colType = columnRecord.get('ColumnType') as number;

      if (typeof colValue === 'string' && colValue.length > 0) {
        // Multi-value hex string — leave as-is
      } else if (colType === JET_coltypText || colType === JET_coltypLongText) {
        if (colValue != null && Buffer.isBuffer(colValue)) {
          const codePage = columnRecord.get('CodePage') as number;
          if (!(codePage in StringCodePages)) {
            throw new Error(`Unknown codepage 0x${codePage.toString(16)}`);
          }
          const encoding = StringCodePages[codePage]!;
          try {
            record.set(column, colValue.toString(encoding));
          } catch {
            console.debug('Error decoding column %s, using replacement', column);
            record.set(column, colValue.toString(encoding));
          }
        }
      } else {
        const unpackInfo = ColumnTypeSize[colType];
        if (colValue != null && Buffer.isBuffer(colValue)) {
          if (unpackInfo === null || unpackInfo === undefined) {
            record.set(column, colValue.toString('hex'));
          } else {
            const fmt = unpackInfo[1];
            record.set(column, unpackValue(fmt, colValue));
          }
        }
      }
    }

    return record;
  }

  /** Get table names in the database */
  getTableNames(): string[] {
    return Array.from(this.tables.keys());
  }
}

function unpackValue(fmt: string, buf: Buffer): number | bigint | Buffer {
  switch (fmt) {
    case 'B':
      return buf.readUInt8(0);
    case '<h':
      return buf.readInt16LE(0);
    case '<H':
      return buf.readUInt16LE(0);
    case '<l':
      return buf.readInt32LE(0);
    case '<L':
      return buf.readUInt32LE(0);
    case '<Q':
      return buf.readBigUInt64LE(0);
    case '<f':
      return buf.readFloatLE(0);
    case '<d':
      return buf.readDoubleLE(0);
    case '16s':
      return Buffer.from(buf.subarray(0, 16));
    default:
      return buf.readUInt32LE(0);
  }
}
