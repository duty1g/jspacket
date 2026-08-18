import { Buffer } from 'node:buffer';
import { Structure, type FieldDescriptor } from '@impacket/structure';

export const SMB_ACE_FLAG_OI = 0x1;
export const SMB_ACE_FLAG_CI = 0x2;
export const SMB_ACE_FLAG_IO = 0x8;
export const SMB_ACE_FLAG_NP = 0x4;
export const SMB_ACE_FLAG_I = 0x10;

export const SEC_INFO_STANDARD_WRITE = 0x8;
export const SEC_INFO_STANDARD_READ = 0x2;
export const SEC_INFO_STANDARD_DELETE = 0x1;

export const SEC_INFO_SPECIFIC_WRITE = 0x116;
export const SEC_INFO_SPECIFIC_EXECUTE = 0x20;
export const SEC_INFO_SPECIFIC_FULL = 0x1ff;

export const SEC_READ_RIGHT = 0x00120089;

export const SUPPORTED_PERMISSIONS: Record<string, number> = {
  R: 0x00120089,
  W: 0x00100116,
  D: 0x00110000,
  X: 0x00000020,
  F: 0x001f01ff,
};

export class FileNTUser extends Structure {
  static structure: FieldDescriptor[] = [
    ['Revision', '<H=1'],
    ['Size', '<H=1'],
    ['NumACEs', '<I=1'],
    ['Buffer', ':'],
  ];
}

export class ACL_SID extends Structure {
  static structure: FieldDescriptor[] = [
    ['Revision', '<B'],
    ['NumAuth', '<B'],
    ['Authority', '6s'],
    ['Subauthorities', ':'],
  ];

  toString(): string {
    const n = Math.floor((this.get('Subauthorities') as Buffer).length / 4);
    const auth = this.get('Authority') as Buffer;
    const authority = auth.readUInt16BE(4);
    const sub = this.get('Subauthorities') as Buffer;
    const subs: number[] = [];
    for (let i = 0; i < n; i++) subs.push(sub.readUInt32LE(i * 4));
    return ['S', this.get('Revision') as number, authority, ...subs].join('-');
  }

  static buildFromString(data: string): ACL_SID {
    const items = data.split('-').slice(1);
    const revision = parseInt(items[0]!, 10);
    const numAuth = parseInt(items[1]!, 10);
    const subLength = items.length - 2;
    const subBuf = Buffer.alloc(subLength * 4);
    for (let i = 0; i < subLength; i++) subBuf.writeUInt32LE(parseInt(items[2 + i]!, 10), i * 4);
    const raw = Buffer.concat([
      Buffer.from([revision, numAuth]),
      Buffer.alloc(5, 0),
      Buffer.from([numAuth]),
      subBuf,
    ]);
    return new ACL_SID(raw);
  }

  equals(other: ACL_SID): boolean {
    return this.toString() === other.toString();
  }

  split(sep: string): string[] {
    return this.toString().split(sep);
  }
}

export class FileNTACE extends Structure {
  static structure: FieldDescriptor[] = [
    ['Type', '<B'],
    ['NTACE_Flags', '<B'],
    ['Size', '<H'],
    ['SpecificRights', '<H'],
    ['StandardRights', '<B'],
    ['GenericRights', '<B'],
    ['_SID', '_-SID', '(self["Size"] - 8)'],
    ['SID', ':=""', ACL_SID],
  ];

  action: string = 'grant';

  getReadableNtaceFlags(): string {
    let flags = '';
    if ((this.get('NTACE_Flags') as number) & SMB_ACE_FLAG_OI) flags += '(OI)';
    if ((this.get('NTACE_Flags') as number) & SMB_ACE_FLAG_CI) flags += '(CI)';
    if ((this.get('NTACE_Flags') as number) & SMB_ACE_FLAG_IO) flags += '(IO)';
    if ((this.get('NTACE_Flags') as number) & SMB_ACE_FLAG_NP) flags += '(NP)';
    if ((this.get('NTACE_Flags') as number) & SMB_ACE_FLAG_I) flags += '(I)';
    return flags;
  }

  getReadableStandardRights(): string {
    let flags = '';
    if ((this.get('StandardRights') as number) & SEC_INFO_STANDARD_READ) flags += '(R)';
    if ((this.get('StandardRights') as number) & SEC_INFO_STANDARD_WRITE) flags += '(w)';
    if ((this.get('StandardRights') as number) & SEC_INFO_STANDARD_DELETE) flags += '(D)';
    return flags;
  }

  getReadableSpecificRights(): string {
    const sr = this.get('SpecificRights') as number;
    if ((sr & SEC_INFO_SPECIFIC_FULL) === SEC_INFO_SPECIFIC_FULL) return '(F)';
    let flags = '';
    if ((sr & SEC_INFO_SPECIFIC_WRITE) === SEC_INFO_SPECIFIC_WRITE) flags += '(W)';
    if ((sr & SEC_INFO_SPECIFIC_EXECUTE) === SEC_INFO_SPECIFIC_EXECUTE) flags += '(X)';
    return flags;
  }

  toString(): string {
    const flags = this.getReadableNtaceFlags();
    const specific = this.getReadableSpecificRights();
    if (specific === '(F)') return flags + specific;
    const standard = this.getReadableStandardRights();
    return flags + standard + specific;
  }
}

export class SecurityAttributes {
  owner: string;
  group: string;
  dacls: Map<string, FileNTACE> = new Map();
  readableDacls: Map<string, string> = new Map();

  constructor(owner: string, group: string) {
    this.owner = owner;
    this.group = group;
  }

  toString(): string {
    const lines = [`Owner:\t${this.owner}`, `Group:\t${this.group}`, 'ACLs:\n\t'];
    for (const [, val] of this.readableDacls) lines.push('\t' + val);
    return lines.join('\n');
  }
}
