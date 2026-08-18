import { Buffer } from 'node:buffer';
import { Structure, type FieldDescriptor } from '@impacket/structure';
import {
  NDR,
  NDRSMALL,
  NDRUSMALL,
  NDRBOOLEAN,
  NDRSHORT,
  NDRUSHORT,
  NDRLONG,
  NDRULONG,
  NDRHYPER,
  NDRUHYPER,
  NDRFLOAT,
  NDRDOUBLEFLOAT,
  NDRPOINTER,
  NDRSTRUCT,
  NDRArray,
  NDRUniConformantArray,
  NDRUniFixedArray,
  NULL,
  type NDRField,
} from './ndr';

export const DWORD = NDRULONG;
export const BOOL = NDRULONG;
export const UCHAR = NDRUSMALL;
export const SHORT = NDRSHORT;

export class LPDWORD extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DWORD]];
}

export class PSHORT extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHORT]];
}

export class PBOOL extends NDRPOINTER {
  static referent: NDRField[] = [['Data', BOOL]];
}

export class LPBYTE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NDRUniConformantArray]];
}
export const PBYTE = LPBYTE;

export const BOOLEAN = NDRBOOLEAN;
export const BYTE = NDRUSMALL;
export const CHAR = NDRSMALL;

export class PCHAR extends NDRPOINTER {
  static referent: NDRField[] = [['Data', CHAR]];
}

export class WIDESTR extends NDRUniFixedArray {
  getDataLen(data: Buffer, offset = 0): number {
    for (let i = offset; i + 1 < data.length; i += 2) {
      if (data[i] === 0 && data[i + 1] === 0) {
        return (i + 2) - offset;
      }
    }
    return data.length - offset;
  }

  set(key: string, value: unknown): void {
    if (key === 'Data') {
      if (typeof value === 'string') {
        this.fields[key] = Buffer.from(value + '\0', 'utf-16le');
      } else {
        this.fields[key] = value;
      }
    } else {
      super.set(key, value);
    }
  }

  get(key: string): unknown {
    if (key === 'Data') {
      const buf = this.fields[key] as Buffer;
      if (Buffer.isBuffer(buf)) {
        return buf.toString('utf-16le').replace(/\0+$/, '');
      }
      return buf;
    }
    return super.get(key);
  }
}

export class STR extends NDRSTRUCT {
  static commonHdr: NDRField[] = [
    ['MaximumCount', '<L=len(Data)'],
    ['Offset', '<L=0'],
    ['ActualCount', '<L=len(Data)'],
  ];
  static commonHdr64: NDRField[] = [
    ['MaximumCount', '<Q=len(Data)'],
    ['Offset', '<Q=0'],
    ['ActualCount', '<Q=len(Data)'],
  ];
  static structure: NDRField[] = [['Data', ':']];

  set(key: string, value: unknown): void {
    if (key === 'Data') {
      if (typeof value === 'string') {
        this.fields[key] = Buffer.from(value, 'utf-8');
      } else {
        this.fields[key] = value;
      }
      this.fields['MaximumCount'] = null;
      this.fields['ActualCount'] = null;
    } else {
      super.set(key, value);
    }
  }

  get(key: string): unknown {
    if (key === 'Data') {
      const buf = this.fields[key] as Buffer;
      if (Buffer.isBuffer(buf)) {
        try {
          return buf.toString('utf-8');
        } catch {
          return buf;
        }
      }
      return buf;
    }
    return super.get(key);
  }

  getDataLen(data: Buffer, offset = 0): number {
    return this.get('ActualCount') as number;
  }
}

export class LPSTR extends NDRPOINTER {
  static referent: NDRField[] = [['Data', STR]];
}

export class WSTR extends NDRSTRUCT {
  static commonHdr: NDRField[] = [
    ['MaximumCount', '<L=len(Data)/2'],
    ['Offset', '<L=0'],
    ['ActualCount', '<L=len(Data)/2'],
  ];
  static commonHdr64: NDRField[] = [
    ['MaximumCount', '<Q=len(Data)/2'],
    ['Offset', '<Q=0'],
    ['ActualCount', '<Q=len(Data)/2'],
  ];
  static structure: NDRField[] = [['Data', ':']];

  set(key: string, value: unknown): void {
    if (key === 'Data') {
      if (typeof value === 'string') {
        this.fields[key] = Buffer.from(value, 'utf-16le');
      } else {
        this.fields[key] = value;
      }
      this.fields['MaximumCount'] = null;
      this.fields['ActualCount'] = null;
    } else {
      super.set(key, value);
    }
  }

  get(key: string): unknown {
    if (key === 'Data') {
      const buf = this.fields[key] as Buffer;
      if (Buffer.isBuffer(buf)) {
        return buf.toString('utf-16le');
      }
      return buf;
    }
    return super.get(key);
  }

  getDataLen(data: Buffer, offset = 0): number {
    return (this.get('ActualCount') as number) * 2;
  }
}

export class LPWSTR extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WSTR]];
}

export const BSTR = LPWSTR;
export const DOUBLE = NDRDOUBLEFLOAT;

export class PDOUBLE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DOUBLE]];
}

export const FLOAT = NDRFLOAT;

export class PFLOAT extends NDRPOINTER {
  static referent: NDRField[] = [['Data', FLOAT]];
}

export const HRESULT = NDRLONG;

export class PHRESULT extends NDRPOINTER {
  static referent: NDRField[] = [['Data', HRESULT]];
}

export const INT = NDRLONG;

export class PINT extends NDRPOINTER {
  static referent: NDRField[] = [['Data', INT]];
}

export const LMSTR = LPWSTR;
export const LONG = NDRLONG;

export class LPLONG extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LONG]];
}
export const PLONG = LPLONG;

export const LONGLONG = NDRHYPER;

export class PLONGLONG extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LONGLONG]];
}

export const LONG64 = NDRUHYPER;

export class PLONG64 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LONG64]];
}

export const LPCSTR = LPSTR;
export const NET_API_STATUS = DWORD;
export const ULONG_PTR = NDRULONG;
export const DWORD_PTR = ULONG_PTR;

export class GUID extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', '16s=b""']];

  getAlignment(): number {
    return 4;
  }
}

export class PGUID extends NDRPOINTER {
  static referent: NDRField[] = [['Data', GUID]];
}

export const UUID = GUID;
export const PUUID = PGUID;
export const NTSTATUS = DWORD;
export const UINT = NDRULONG;

export class PUINT extends NDRPOINTER {
  static referent: NDRField[] = [['Data', UINT]];
}

export const ULONG = NDRULONG;

export class PULONG extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ULONG]];
}
export const LPULONG = PULONG;

export const ULONGLONG = NDRUHYPER;

export class PULONGLONG extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ULONGLONG]];
}

export const USHORT = NDRUSHORT;

export class PUSHORT extends NDRPOINTER {
  static referent: NDRField[] = [['Data', USHORT]];
}

export const WCHAR = WSTR;
export const PWCHAR = LPWSTR;
export const WORD = NDRUSHORT;

export class PWORD extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WORD]];
}
export const LPWORD = PWORD;

export class FILETIME extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwLowDateTime', DWORD],
    ['dwHighDateTime', LONG],
  ];
}

export class PFILETIME extends NDRPOINTER {
  static referent: NDRField[] = [['Data', FILETIME]];
}

export const LARGE_INTEGER = NDRHYPER;

export class PLARGE_INTEGER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LARGE_INTEGER]];
}

export class LUID extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['LowPart', DWORD],
    ['HighPart', LONG],
  ];
}

export class RPC_UNICODE_STRING extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Length', '<H=0'],
    ['MaximumLength', '<H=0'],
    ['Data', LPWSTR],
  ];

  set(key: string, value: unknown): void {
    if (key === 'Data' && !(value instanceof NDR)) {
      if (typeof value === 'string') {
        this.set('Length', value.length * 2);
        this.set('MaximumLength', value.length * 2);
      }
    }
    super.set(key, value);
  }
}

export class PRPC_UNICODE_STRING extends NDRPOINTER {
  static referent: NDRField[] = [['Data', RPC_UNICODE_STRING]];
}

export const ACCESS_MASK = DWORD;

export class OBJECT_TYPE_LIST extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Level', WORD],
    ['Remaining', ACCESS_MASK],
    ['ObjectType', PGUID],
  ];
}

export class POBJECT_TYPE_LIST extends NDRPOINTER {
  static referent: NDRField[] = [['Data', OBJECT_TYPE_LIST]];
}

export class SYSTEMTIME extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['wYear', WORD],
    ['wMonth', WORD],
    ['wDayOfWeek', WORD],
    ['wDay', WORD],
    ['wHour', WORD],
    ['wMinute', WORD],
    ['wSecond', WORD],
    ['wMilliseconds', WORD],
  ];
}

export class PSYSTEMTIME extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SYSTEMTIME]];
}

export class ULARGE_INTEGER extends NDRSTRUCT {
  static structure: NDRField[] = [['QuadPart', LONG64]];
}

export class PULARGE_INTEGER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ULARGE_INTEGER]];
}

export class SID_IDENTIFIER_AUTHORITY extends Structure {
  static structure: FieldDescriptor[] = [['Value', '6s']];
}

export class SID extends Structure {
  static structure: FieldDescriptor[] = [
    ['Revision', '<B'],
    ['SubAuthorityCount', '<B'],
    ['IdentifierAuthority', ':', SID_IDENTIFIER_AUTHORITY],
    ['SubLen', '_-SubAuthority', 'self["SubAuthorityCount"]*4'],
    ['SubAuthority', ':'],
  ];

  formatCanonical(): string {
    const auth = this.get('IdentifierAuthority') as SID_IDENTIFIER_AUTHORITY;
    const authVal = auth.get('Value') as Buffer;
    let ans = `S-${this.get('Revision')}-${authVal[5]}`;
    const count = this.get('SubAuthorityCount') as number;
    const subAuth = this.get('SubAuthority') as Buffer;
    for (let i = 0; i < count; i++) {
      ans += `-${subAuth.readUInt32LE(i * 4)}`;
    }
    return ans;
  }

  fromCanonical(canonical: string): void {
    const items = canonical.split('-');
    this.set('Revision', Number(items[1]));
    const auth = new SID_IDENTIFIER_AUTHORITY();
    auth.set('Value', Buffer.concat([Buffer.alloc(5), Buffer.from([Number(items[2])])]));
    this.set('IdentifierAuthority', auth);
    this.set('SubAuthorityCount', items.length - 3);
    let subAuth = Buffer.alloc(0);
    for (let i = 0; i < items.length - 3; i++) {
      const buf = Buffer.alloc(4);
      buf.writeUInt32LE(Number(items[i + 3]));
      subAuth = Buffer.concat([subAuth, buf]);
    }
    this.set('SubAuthority', subAuth);
  }
}

export class DWORD_ARRAY extends NDRUniConformantArray {
  static item = '<L';
}

export class RPC_SID_IDENTIFIER_AUTHORITY extends NDRUniFixedArray {
  static align = 1;
  static align64 = 1;

  getDataLen(): number {
    return 6;
  }
}

export class RPC_SID extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Revision', NDRSMALL],
    ['SubAuthorityCount', NDRSMALL],
    ['IdentifierAuthority', RPC_SID_IDENTIFIER_AUTHORITY],
    ['SubAuthority', DWORD_ARRAY],
  ];

  getData(soFar = 0): Buffer {
    const subAuth = this.fields['SubAuthority'] as NDRArray;
    const subAuthData = subAuth.fields['Data'] as unknown[];
    this.set('SubAuthorityCount', subAuthData.length);
    return super.getData(soFar);
  }

  fromCanonical(canonical: string): void {
    const items = canonical.split('-');
    this.set('Revision', Number(items[1]));
    const authBuf = Buffer.concat([Buffer.alloc(5), Buffer.from([Number(items[2])])]);
    const auth = new RPC_SID_IDENTIFIER_AUTHORITY();
    auth.fields['Data'] = authBuf;
    this.fields['IdentifierAuthority'] = auth;
    this.set('SubAuthorityCount', items.length - 3);
    const arr = this.fields['SubAuthority'] as DWORD_ARRAY;
    arr.fields['Data'] = [];
    for (let i = 0; i < items.length - 3; i++) {
      (arr.fields['Data'] as number[]).push(Number(items[i + 3]));
    }
  }

  formatCanonical(): string {
    const auth = this.fields['IdentifierAuthority'] as RPC_SID_IDENTIFIER_AUTHORITY;
    const authData = auth.fields['Data'] as Buffer;
    let ans = `S-${this.get('Revision')}-${authData[5]}`;
    const subAuth = this.fields['SubAuthority'] as DWORD_ARRAY;
    const items = subAuth.fields['Data'] as number[];
    const count = this.get('SubAuthorityCount') as number;
    for (let i = 0; i < count; i++) {
      ans += `-${items[i]}`;
    }
    return ans;
  }
}

export class PRPC_SID extends NDRPOINTER {
  static referent: NDRField[] = [['Data', RPC_SID]];
}
export const PSID = PRPC_SID;

export const GENERIC_READ = 0x80000000;
export const GENERIC_WRITE = 0x40000000;
export const GENERIC_EXECUTE = 0x20000000;
export const GENERIC_ALL = 0x10000000;
export const MAXIMUM_ALLOWED = 0x02000000;
export const ACCESS_SYSTEM_SECURITY = 0x01000000;
export const SYNCHRONIZE = 0x00100000;
export const WRITE_OWNER = 0x00080000;
export const WRITE_DACL = 0x00040000;
export const READ_CONTROL = 0x00020000;
export const DELETE = 0x00010000;

export class ACL extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['AclRevision', NDRSMALL],
    ['Sbz1', NDRSMALL],
    ['AclSize', NDRSHORT],
    ['AceCount', NDRSHORT],
    ['Sbz2', NDRSHORT],
  ];
}

export class PACL extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ACL]];
}

export class SECURITY_DESCRIPTOR extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Revision', UCHAR],
    ['Sbz1', UCHAR],
    ['Control', USHORT],
    ['Owner', PSID],
    ['Group', PSID],
    ['Sacl', PACL],
    ['Dacl', PACL],
  ];
}

export const OWNER_SECURITY_INFORMATION = 0x00000001;
export const GROUP_SECURITY_INFORMATION = 0x00000002;
export const DACL_SECURITY_INFORMATION = 0x00000004;
export const SACL_SECURITY_INFORMATION = 0x00000008;
export const LABEL_SECURITY_INFORMATION = 0x00000010;
export const UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000;
export const UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000;
export const PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000;
export const PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;
export const ATTRIBUTE_SECURITY_INFORMATION = 0x00000020;
export const SCOPE_SECURITY_INFORMATION = 0x00000040;
export const BACKUP_SECURITY_INFORMATION = 0x00010000;

export const SECURITY_INFORMATION = DWORD;

export class PSECURITY_INFORMATION extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SECURITY_INFORMATION]];
}
