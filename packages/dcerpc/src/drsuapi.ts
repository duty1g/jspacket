import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { uuidtupToBin, stringToBin } from '@impacket/uuid';
import { Structure, type FieldDescriptor } from '@impacket/structure';
import { transformKey, rc4, desEcbDecryptBlock } from '@impacket/crypto';
import { encodeOID, decodeOID } from '@impacket/asn1';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRENUM,
  NDRUNION,
  NDRPOINTER,
  NDRUniConformantArray,
  NULL,
  type NDRField,
} from './ndr';
import {
  ULONG,
  DWORD,
  BOOL,
  GUID,
  UUID,
  PUUID,
  LPWSTR,
  LONGLONG,
  ULARGE_INTEGER,
  LARGE_INTEGER,
  LPBYTE,
} from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_DRSUAPI = uuidtupToBin(['E3514235-4B06-11D1-AB04-00C04FC2DCD2', '4.0'])!;

class DCERPCSessionError extends DCERPCException {
  constructor(errorString?: string | null, errorCode?: number | null, packet?: unknown) {
    super(errorString, errorCode, packet);
  }

  toString(): string {
    const key = this.error_code;
    if (key != null) {
      return `DRSR SessionError: code: 0x${key.toString(16)}`;
    }
    return `DRSR SessionError: unknown error code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

export const EXOP_ERR_SUCCESS = 0x00000001;
export const EXOP_ERR_UNKNOWN_OP = 0x00000002;
export const EXOP_ERR_FSMO_NOT_OWNER = 0x00000003;
export const EXOP_ERR_UPDATE_ERR = 0x00000004;
export const EXOP_ERR_EXCEPTION = 0x00000005;
export const EXOP_ERR_UNKNOWN_CALLER = 0x00000006;
export const EXOP_ERR_RID_ALLOC = 0x00000007;
export const EXOP_ERR_FSMO_OWNER_DELETED = 0x00000008;
export const EXOP_ERR_FSMO_PENDING_OP = 0x00000009;
export const EXOP_ERR_MISMATCH = 0x0000000a;
export const EXOP_ERR_COULDNT_CONTACT = 0x0000000b;
export const EXOP_ERR_FSMO_REFUSING_ROLES = 0x0000000c;
export const EXOP_ERR_DIR_ERROR = 0x0000000d;
export const EXOP_ERR_FSMO_MISSING_SETTINGS = 0x0000000e;
export const EXOP_ERR_ACCESS_DENIED = 0x0000000f;
export const EXOP_ERR_PARAM_ERROR = 0x00000010;

export class EXOP_ERR extends NDRENUM {
  static align = 4;
  static align64 = 4;
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    1: 'EXOP_ERR_SUCCESS',
    2: 'EXOP_ERR_UNKNOWN_OP',
    3: 'EXOP_ERR_FSMO_NOT_OWNER',
    4: 'EXOP_ERR_UPDATE_ERR',
    5: 'EXOP_ERR_EXCEPTION',
    6: 'EXOP_ERR_UNKNOWN_CALLER',
    7: 'EXOP_ERR_RID_ALLOC',
    8: 'EXOP_ERR_FSMO_OWNER_DELETED',
    9: 'EXOP_ERR_FSMO_PENDING_OP',
    10: 'EXOP_ERR_MISMATCH',
    11: 'EXOP_ERR_COULDNT_CONTACT',
    12: 'EXOP_ERR_FSMO_REFUSING_ROLES',
    13: 'EXOP_ERR_DIR_ERROR',
    14: 'EXOP_ERR_FSMO_MISSING_SETTINGS',
    15: 'EXOP_ERR_ACCESS_DENIED',
    16: 'EXOP_ERR_PARAM_ERROR',
  };
  static enumValues: Record<string, number> = {
    EXOP_ERR_SUCCESS: 1,
    EXOP_ERR_UNKNOWN_OP: 2,
    EXOP_ERR_FSMO_NOT_OWNER: 3,
    EXOP_ERR_UPDATE_ERR: 4,
    EXOP_ERR_EXCEPTION: 5,
    EXOP_ERR_UNKNOWN_CALLER: 6,
    EXOP_ERR_RID_ALLOC: 7,
    EXOP_ERR_FSMO_OWNER_DELETED: 8,
    EXOP_ERR_FSMO_PENDING_OP: 9,
    EXOP_ERR_MISMATCH: 10,
    EXOP_ERR_COULDNT_CONTACT: 11,
    EXOP_ERR_FSMO_REFUSING_ROLES: 12,
    EXOP_ERR_DIR_ERROR: 13,
    EXOP_ERR_FSMO_MISSING_SETTINGS: 14,
    EXOP_ERR_ACCESS_DENIED: 15,
    EXOP_ERR_PARAM_ERROR: 16,
  };
}

export const EXOP_FSMO_REQ_ROLE = 0x00000001;
export const EXOP_FSMO_REQ_RID_ALLOC = 0x00000002;
export const EXOP_FSMO_RID_REQ_ROLE = 0x00000003;
export const EXOP_FSMO_REQ_PDC = 0x00000004;
export const EXOP_FSMO_ABANDON_ROLE = 0x00000005;
export const EXOP_REPL_OBJ = 0x00000006;
export const EXOP_REPL_SECRETS = 0x00000007;

export const ATTRTYP = ULONG;
export const DSTIME = LONGLONG;

export const DRS_EXT_BASE = 0x00000001;
export const DRS_EXT_ASYNCREPL = 0x00000002;
export const DRS_EXT_REMOVEAPI = 0x00000004;
export const DRS_EXT_MOVEREQ_V2 = 0x00000008;
export const DRS_EXT_GETCHG_DEFLATE = 0x00000010;
export const DRS_EXT_DCINFO_V1 = 0x00000020;
export const DRS_EXT_RESTORE_USN_OPTIMIZATION = 0x00000040;
export const DRS_EXT_ADDENTRY = 0x00000080;
export const DRS_EXT_KCC_EXECUTE = 0x00000100;
export const DRS_EXT_ADDENTRY_V2 = 0x00000200;
export const DRS_EXT_LINKED_VALUE_REPLICATION = 0x00000400;
export const DRS_EXT_DCINFO_V2 = 0x00000800;
export const DRS_EXT_INSTANCE_TYPE_NOT_REQ_ON_MOD = 0x00001000;
export const DRS_EXT_CRYPTO_BIND = 0x00002000;
export const DRS_EXT_GET_REPL_INFO = 0x00004000;
export const DRS_EXT_STRONG_ENCRYPTION = 0x00008000;
export const DRS_EXT_DCINFO_VFFFFFFFF = 0x00010000;
export const DRS_EXT_TRANSITIVE_MEMBERSHIP = 0x00020000;
export const DRS_EXT_ADD_SID_HISTORY = 0x00040000;
export const DRS_EXT_POST_BETA3 = 0x00080000;
export const DRS_EXT_GETCHGREQ_V5 = 0x00100000;
export const DRS_EXT_GETMEMBERSHIPS2 = 0x00200000;
export const DRS_EXT_GETCHGREQ_V6 = 0x00400000;
export const DRS_EXT_NONDOMAIN_NCS = 0x00800000;
export const DRS_EXT_GETCHGREQ_V8 = 0x01000000;
export const DRS_EXT_GETCHGREPLY_V5 = 0x02000000;
export const DRS_EXT_GETCHGREPLY_V6 = 0x04000000;
export const DRS_EXT_GETCHGREPLY_V9 = 0x00000100;
export const DRS_EXT_WHISTLER_BETA3 = 0x08000000;
export const DRS_EXT_W2K3_DEFLATE = 0x10000000;
export const DRS_EXT_GETCHGREQ_V10 = 0x20000000;
export const DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART2 = 0x40000000;
export const DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART3 = 0x80000000;

export const DRS_EXT_ADAM = 0x00000001;
export const DRS_EXT_LH_BETA2 = 0x00000002;
export const DRS_EXT_RECYCLE_BIN = 0x00000004;

export const DRS_ASYNC_OP = 0x00000001;
export const DRS_GETCHG_CHECK = 0x00000002;
export const DRS_UPDATE_NOTIFICATION = 0x00000002;
export const DRS_ADD_REF = 0x00000004;
export const DRS_SYNC_ALL = 0x00000008;
export const DRS_DEL_REF = 0x00000008;
export const DRS_WRIT_REP = 0x00000010;
export const DRS_INIT_SYNC = 0x00000020;
export const DRS_PER_SYNC = 0x00000040;
export const DRS_MAIL_REP = 0x00000080;
export const DRS_ASYNC_REP = 0x00000100;
export const DRS_IGNORE_ERROR = 0x00000100;
export const DRS_TWOWAY_SYNC = 0x00000200;
export const DRS_CRITICAL_ONLY = 0x00000400;
export const DRS_GET_ANC = 0x00000800;
export const DRS_GET_NC_SIZE = 0x00001000;
export const DRS_LOCAL_ONLY = 0x00001000;
export const DRS_NONGC_RO_REP = 0x00002000;
export const DRS_SYNC_BYNAME = 0x00004000;
export const DRS_REF_OK = 0x00004000;
export const DRS_FULL_SYNC_NOW = 0x00008000;
export const DRS_NO_SOURCE = 0x00008000;
export const DRS_FULL_SYNC_IN_PROGRESS = 0x00010000;
export const DRS_FULL_SYNC_PACKET = 0x00020000;
export const DRS_SYNC_REQUEUE = 0x00040000;
export const DRS_SYNC_URGENT = 0x00080000;
export const DRS_REF_GCSPN = 0x00100000;
export const DRS_NO_DISCARD = 0x00100000;
export const DRS_NEVER_SYNCED = 0x00200000;
export const DRS_SPECIAL_SECRET_PROCESSING = 0x00400000;
export const DRS_INIT_SYNC_NOW = 0x00800000;
export const DRS_PREEMPTED = 0x01000000;
export const DRS_SYNC_FORCED = 0x02000000;
export const DRS_DISABLE_AUTO_SYNC = 0x04000000;
export const DRS_DISABLE_PERIODIC_SYNC = 0x08000000;
export const DRS_USE_COMPRESSION = 0x10000000;
export const DRS_NEVER_NOTIFY = 0x20000000;
export const DRS_SYNC_PAS = 0x40000000;
export const DRS_GET_ALL_GROUP_MEMBERSHIP = 0x80000000;

export const BND = 0x00000001;
export const SSL = 0x00000002;
export const UDP = 0x00000004;
export const GC = 0x00000008;
export const GSS = 0x00000010;
export const NGO = 0x00000020;
export const SPL = 0x00000040;
export const MD5 = 0x00000080;
export const SGN = 0x00000100;
export const SL = 0x00000200;

export const NTDSAPI_CLIENT_GUID = stringToBin('e24d201a-4fd6-11d1-a3da-0000f875ae0d');
export const NULLGUID = stringToBin('00000000-0000-0000-0000-000000000000');

export const USN = LONGLONG;

export const DS_NAME_FLAG_GCVERIFY = 0x00000004;
export const DS_NAME_FLAG_TRUST_REFERRAL = 0x00000008;
export const DS_NAME_FLAG_PRIVATE_RESOLVE_FPOS = 0x80000000;

export const DS_LIST_SITES = 0xffffffff;
export const DS_LIST_SERVERS_IN_SITE = 0xfffffffe;
export const DS_LIST_DOMAINS_IN_SITE = 0xfffffffd;
export const DS_LIST_SERVERS_FOR_DOMAIN_IN_SITE = 0xfffffffc;
export const DS_LIST_INFO_FOR_SERVER = 0xfffffffb;
export const DS_LIST_ROLES = 0xfffffffa;
export const DS_NT4_ACCOUNT_NAME_SANS_DOMAIN = 0xfffffff9;
export const DS_MAP_SCHEMA_GUID = 0xfffffff8;
export const DS_LIST_DOMAINS = 0xfffffff7;
export const DS_LIST_NCS = 0xfffffff6;
export const DS_ALT_SECURITY_IDENTITIES_NAME = 0xfffffff5;
export const DS_STRING_SID_NAME = 0xfffffff4;
export const DS_LIST_SERVERS_WITH_DCS_IN_SITE = 0xfffffff3;
export const DS_LIST_GLOBAL_CATALOG_SERVERS = 0xfffffff1;
export const DS_NT4_ACCOUNT_NAME_SANS_DOMAIN_EX = 0xfffffff0;
export const DS_USER_PRINCIPAL_NAME_AND_ALTSECID = 0xffffffef;
export const DS_USER_PRINCIPAL_NAME_FOR_LOGON = 0xfffffff2;

export const ENTINF_FROM_MASTER = 0x00000001;
export const ENTINF_DYNAMIC_OBJECT = 0x00000002;
export const ENTINF_REMOTE_MODIFY = 0x00010000;

export const DRS_VERIFY_DSNAMES = 0x00000000;
export const DRS_VERIFY_SIDS = 0x00000001;
export const DRS_VERIFY_SAM_ACCOUNT_NAMES = 0x00000002;
export const DRS_VERIFY_FPOS = 0x00000003;

export const DRS_NT4_CHGLOG_GET_CHANGE_LOG = 0x00000001;
export const DRS_NT4_CHGLOG_GET_SERIAL_NUMBERS = 0x00000002;

export const DRS_MSG_GETCHGREPLY_NATIVE_VERSION_NUMBER = 9;

export class ENCRYPTED_PAYLOAD extends Structure {
  static structure: FieldDescriptor[] = [
    ['Salt', '16s'],
    ['CheckSum', '<L'],
    ['EncryptedData', ':'],
  ];
}

export class NT4SID extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', '28s=b""']];

  getAlignment(): number {
    return 4;
  }
}

export class DRS_HANDLE extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', '20s=b""']];

  getAlignment(): number {
    return 4;
  }
}

export class PDRS_HANDLE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DRS_HANDLE]];
}

export class BYTE_ARRAY extends NDRUniConformantArray {
  static item = 'c';
}

export class PBYTE_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', BYTE_ARRAY]];
}

export class DRS_EXTENSIONS extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cb', DWORD],
    ['rgb', BYTE_ARRAY],
  ];
}

export class PDRS_EXTENSIONS extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DRS_EXTENSIONS]];
}

export class DRS_EXTENSIONS_INT extends Structure {
  static structure: FieldDescriptor[] = [
    ['dwFlags', '<L=0'],
    ['SiteObjGuid', '16s=b""'],
    ['Pid', '<L=0'],
    ['dwReplEpoch', '<L=0'],
    ['dwFlagsExt', '<L=0'],
    ['ConfigObjGUID', '16s=b""'],
    ['dwExtCaps', '<L=0'],
  ];
}

export class DRS_MSG_DCINFOREQ_V1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Domain', LPWSTR],
    ['InfoLevel', DWORD],
  ];
}

export class DRS_MSG_DCINFOREQ extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['V1', DRS_MSG_DCINFOREQ_V1],
  };
}

export class DS_DOMAIN_CONTROLLER_INFO_1W extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['NetbiosName', LPWSTR],
    ['DnsHostName', LPWSTR],
    ['SiteName', LPWSTR],
    ['ComputerObjectName', LPWSTR],
    ['ServerObjectName', LPWSTR],
    ['fIsPdc', BOOL],
    ['fDsEnabled', BOOL],
  ];
}

export class DS_DOMAIN_CONTROLLER_INFO_1W_ARRAY extends NDRUniConformantArray {
  static item = DS_DOMAIN_CONTROLLER_INFO_1W;
}

export class PDS_DOMAIN_CONTROLLER_INFO_1W_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DS_DOMAIN_CONTROLLER_INFO_1W_ARRAY]];
}

export class DRS_MSG_DCINFOREPLY_V1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cItems', DWORD],
    ['rItems', PDS_DOMAIN_CONTROLLER_INFO_1W_ARRAY],
  ];
}

export class DS_DOMAIN_CONTROLLER_INFO_2W extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['NetbiosName', LPWSTR],
    ['DnsHostName', LPWSTR],
    ['SiteName', LPWSTR],
    ['SiteObjectName', LPWSTR],
    ['ComputerObjectName', LPWSTR],
    ['ServerObjectName', LPWSTR],
    ['NtdsDsaObjectName', LPWSTR],
    ['fIsPdc', BOOL],
    ['fDsEnabled', BOOL],
    ['fIsGc', BOOL],
    ['SiteObjectGuid', GUID],
    ['ComputerObjectGuid', GUID],
    ['ServerObjectGuid', GUID],
    ['NtdsDsaObjectGuid', GUID],
  ];
}

export class DS_DOMAIN_CONTROLLER_INFO_2W_ARRAY extends NDRUniConformantArray {
  static item = DS_DOMAIN_CONTROLLER_INFO_2W;
}

export class PDS_DOMAIN_CONTROLLER_INFO_2W_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DS_DOMAIN_CONTROLLER_INFO_2W_ARRAY]];
}

export class DRS_MSG_DCINFOREPLY_V2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cItems', DWORD],
    ['rItems', PDS_DOMAIN_CONTROLLER_INFO_2W_ARRAY],
  ];
}

export class DS_DOMAIN_CONTROLLER_INFO_3W extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['NetbiosName', LPWSTR],
    ['DnsHostName', LPWSTR],
    ['SiteName', LPWSTR],
    ['SiteObjectName', LPWSTR],
    ['ComputerObjectName', LPWSTR],
    ['ServerObjectName', LPWSTR],
    ['NtdsDsaObjectName', LPWSTR],
    ['fIsPdc', BOOL],
    ['fDsEnabled', BOOL],
    ['fIsGc', BOOL],
    ['fIsRodc', BOOL],
    ['SiteObjectGuid', GUID],
    ['ComputerObjectGuid', GUID],
    ['ServerObjectGuid', GUID],
    ['NtdsDsaObjectGuid', GUID],
  ];
}

export class DS_DOMAIN_CONTROLLER_INFO_3W_ARRAY extends NDRUniConformantArray {
  static item = DS_DOMAIN_CONTROLLER_INFO_3W;
}

export class PDS_DOMAIN_CONTROLLER_INFO_3W_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DS_DOMAIN_CONTROLLER_INFO_3W_ARRAY]];
}

export class DRS_MSG_DCINFOREPLY_V3 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cItems', DWORD],
    ['rItems', PDS_DOMAIN_CONTROLLER_INFO_3W_ARRAY],
  ];
}

export class DS_DOMAIN_CONTROLLER_INFO_FFFFFFFFW extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['IPAddress', DWORD],
    ['NotificationCount', DWORD],
    ['secTimeConnected', DWORD],
    ['Flags', DWORD],
    ['TotalRequests', DWORD],
    ['Reserved1', DWORD],
    ['UserName', LPWSTR],
  ];
}

export class DS_DOMAIN_CONTROLLER_INFO_FFFFFFFFW_ARRAY extends NDRUniConformantArray {
  static item = DS_DOMAIN_CONTROLLER_INFO_FFFFFFFFW;
}

export class PDS_DOMAIN_CONTROLLER_INFO_FFFFFFFFW_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DS_DOMAIN_CONTROLLER_INFO_FFFFFFFFW_ARRAY]];
}

export class DRS_MSG_DCINFOREPLY_VFFFFFFFF extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cItems', DWORD],
    ['rItems', PDS_DOMAIN_CONTROLLER_INFO_FFFFFFFFW_ARRAY],
  ];
}

export class DRS_MSG_DCINFOREPLY extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['V1', DRS_MSG_DCINFOREPLY_V1],
    2: ['V2', DRS_MSG_DCINFOREPLY_V2],
    3: ['V3', DRS_MSG_DCINFOREPLY_V3],
    0xffffffff: ['V1', DRS_MSG_DCINFOREPLY_VFFFFFFFF],
  };
}

export class LPWSTR_ARRAY extends NDRUniConformantArray {
  static item = LPWSTR;
}

export class PLPWSTR_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LPWSTR_ARRAY]];
}

export class DRS_MSG_CRACKREQ_V1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['CodePage', ULONG],
    ['LocaleId', ULONG],
    ['dwFlags', DWORD],
    ['formatOffered', DWORD],
    ['formatDesired', DWORD],
    ['cNames', DWORD],
    ['rpNames', PLPWSTR_ARRAY],
  ];
}

export class DRS_MSG_CRACKREQ extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['V1', DRS_MSG_CRACKREQ_V1],
  };
}

export class DS_NAME_FORMAT extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'DS_UNKNOWN_NAME',
    1: 'DS_FQDN_1779_NAME',
    2: 'DS_NT4_ACCOUNT_NAME',
    3: 'DS_DISPLAY_NAME',
    6: 'DS_UNIQUE_ID_NAME',
    7: 'DS_CANONICAL_NAME',
    8: 'DS_USER_PRINCIPAL_NAME',
    9: 'DS_CANONICAL_NAME_EX',
    10: 'DS_SERVICE_PRINCIPAL_NAME',
    11: 'DS_SID_OR_SID_HISTORY_NAME',
    12: 'DS_DNS_DOMAIN_NAME',
  };
  static enumValues: Record<string, number> = {
    DS_UNKNOWN_NAME: 0,
    DS_FQDN_1779_NAME: 1,
    DS_NT4_ACCOUNT_NAME: 2,
    DS_DISPLAY_NAME: 3,
    DS_UNIQUE_ID_NAME: 6,
    DS_CANONICAL_NAME: 7,
    DS_USER_PRINCIPAL_NAME: 8,
    DS_CANONICAL_NAME_EX: 9,
    DS_SERVICE_PRINCIPAL_NAME: 10,
    DS_SID_OR_SID_HISTORY_NAME: 11,
    DS_DNS_DOMAIN_NAME: 12,
  };
}

export class DS_NAME_RESULT_ITEMW extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['status', DWORD],
    ['pDomain', LPWSTR],
    ['pName', LPWSTR],
  ];
}

export class DS_NAME_RESULT_ITEMW_ARRAY extends NDRUniConformantArray {
  static item = DS_NAME_RESULT_ITEMW;
}

export class PDS_NAME_RESULT_ITEMW_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DS_NAME_RESULT_ITEMW_ARRAY]];
}

export class DS_NAME_RESULTW extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cItems', DWORD],
    ['rItems', PDS_NAME_RESULT_ITEMW_ARRAY],
  ];
}

export class PDS_NAME_RESULTW extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DS_NAME_RESULTW]];
}

export class DRS_MSG_CRACKREPLY_V1 extends NDRSTRUCT {
  static structure: NDRField[] = [['pResult', PDS_NAME_RESULTW]];
}

export class DRS_MSG_CRACKREPLY extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['V1', DRS_MSG_CRACKREPLY_V1],
  };
}

export class UPTODATE_CURSOR_V1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['uuidDsa', UUID],
    ['usnHighPropUpdate', USN],
  ];
}

export class UPTODATE_CURSOR_V1_ARRAY extends NDRUniConformantArray {
  static item = UPTODATE_CURSOR_V1;
}

export class UPTODATE_VECTOR_V1_EXT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwVersion', DWORD],
    ['dwReserved1', DWORD],
    ['cNumCursors', DWORD],
    ['dwReserved2', DWORD],
    ['rgCursors', UPTODATE_CURSOR_V1_ARRAY],
  ];
}

export class PUPTODATE_VECTOR_V1_EXT extends NDRPOINTER {
  static referent: NDRField[] = [['Data', UPTODATE_VECTOR_V1_EXT]];
}

export class USN_VECTOR extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['usnHighObjUpdate', USN],
    ['usnReserved', USN],
    ['usnHighPropUpdate', USN],
  ];
}

export class WCHAR_ARRAY extends NDRUniConformantArray {
  static item = 'H';

  set(key: string, value: unknown): void {
    if (key === 'Data' && typeof value === 'string') {
      this.fields['MaximumCount'] = null;
      const arr: number[] = [];
      for (let i = 0; i < value.length; i++) {
        arr.push(value.charCodeAt(i));
      }
      this.fields['Data'] = arr;
    } else {
      super.set(key, value);
    }
  }

  get(key: string): unknown {
    if (key === 'Data') {
      const arr = this.fields['Data'];
      if (Array.isArray(arr)) {
        return arr.map((c) => String.fromCharCode(c as number)).join('');
      }
      return arr;
    }
    return super.get(key);
  }
}

export class DSNAME extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['structLen', ULONG],
    ['SidLen', ULONG],
    ['Guid', GUID],
    ['Sid', NT4SID],
    ['NameLen', ULONG],
    ['StringName', WCHAR_ARRAY],
  ];

  getDataLen(data: Buffer, offset = 0): number {
    return this.get('NameLen') as number;
  }
}

export class PDSNAME extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DSNAME]];
}

export class PDSNAME_ARRAY extends NDRUniConformantArray {
  static item = PDSNAME;
}

export class PPDSNAME_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', PDSNAME_ARRAY]];
}

export class ATTRTYP_ARRAY extends NDRUniConformantArray {
  static item = ATTRTYP;
}

export class PARTIAL_ATTR_VECTOR_V1_EXT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwVersion', DWORD],
    ['dwReserved1', DWORD],
    ['cAttrs', DWORD],
    ['rgPartialAttr', ATTRTYP_ARRAY],
  ];
}

export class PPARTIAL_ATTR_VECTOR_V1_EXT extends NDRPOINTER {
  static referent: NDRField[] = [['Data', PARTIAL_ATTR_VECTOR_V1_EXT]];
}

export class OID_t extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['length', ULONG],
    ['elements', PBYTE_ARRAY],
  ];
}

export class PrefixTableEntry extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ndx', ULONG],
    ['prefix', OID_t],
  ];
}

export class PrefixTableEntry_ARRAY extends NDRUniConformantArray {
  static item = PrefixTableEntry;
}

export class PPrefixTableEntry_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', PrefixTableEntry_ARRAY]];
}

export class SCHEMA_PREFIX_TABLE extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['PrefixCount', DWORD],
    ['pPrefixEntry', PPrefixTableEntry_ARRAY],
  ];
}

export class DRS_MSG_GETCHGREQ_V3 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['uuidDsaObjDest', UUID],
    ['uuidInvocIdSrc', UUID],
    ['pNC', PDSNAME],
    ['usnvecFrom', USN_VECTOR],
    ['pUpToDateVecDestV1', PUPTODATE_VECTOR_V1_EXT],
    ['pPartialAttrVecDestV1', PPARTIAL_ATTR_VECTOR_V1_EXT],
    ['PrefixTableDest', SCHEMA_PREFIX_TABLE],
    ['ulFlags', ULONG],
    ['cMaxObjects', ULONG],
    ['cMaxBytes', ULONG],
    ['ulExtendedOp', ULONG],
  ];
}

export class MTX_ADDR extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['mtx_namelen', ULONG],
    ['mtx_name', PBYTE_ARRAY],
  ];
}

export class PMTX_ADDR extends NDRPOINTER {
  static referent: NDRField[] = [['Data', MTX_ADDR]];
}

export class DRS_MSG_GETCHGREQ_V4 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['uuidTransportObj', UUID],
    ['pmtxReturnAddress', PMTX_ADDR],
    ['V3', DRS_MSG_GETCHGREQ_V3],
  ];
}

export class DRS_MSG_GETCHGREQ_V5 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['uuidDsaObjDest', UUID],
    ['uuidInvocIdSrc', UUID],
    ['pNC', PDSNAME],
    ['usnvecFrom', USN_VECTOR],
    ['pUpToDateVecDestV1', PUPTODATE_VECTOR_V1_EXT],
    ['ulFlags', ULONG],
    ['cMaxObjects', ULONG],
    ['cMaxBytes', ULONG],
    ['ulExtendedOp', ULONG],
    ['liFsmoInfo', ULARGE_INTEGER],
  ];
}

export class DRS_MSG_GETCHGREQ_V7 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['uuidTransportObj', UUID],
    ['pmtxReturnAddress', PMTX_ADDR],
    ['V3', DRS_MSG_GETCHGREQ_V3],
    ['pPartialAttrSet', PPARTIAL_ATTR_VECTOR_V1_EXT],
    ['pPartialAttrSetEx1', PPARTIAL_ATTR_VECTOR_V1_EXT],
    ['PrefixTableDest', SCHEMA_PREFIX_TABLE],
  ];
}

export class DRS_MSG_GETCHGREQ_V8 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['uuidDsaObjDest', UUID],
    ['uuidInvocIdSrc', UUID],
    ['pNC', PDSNAME],
    ['usnvecFrom', USN_VECTOR],
    ['pUpToDateVecDest', PUPTODATE_VECTOR_V1_EXT],
    ['ulFlags', ULONG],
    ['cMaxObjects', ULONG],
    ['cMaxBytes', ULONG],
    ['ulExtendedOp', ULONG],
    ['liFsmoInfo', ULARGE_INTEGER],
    ['pPartialAttrSet', PPARTIAL_ATTR_VECTOR_V1_EXT],
    ['pPartialAttrSetEx1', PPARTIAL_ATTR_VECTOR_V1_EXT],
    ['PrefixTableDest', SCHEMA_PREFIX_TABLE],
  ];
}

export class DRS_MSG_GETCHGREQ_V10 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['uuidDsaObjDest', UUID],
    ['uuidInvocIdSrc', UUID],
    ['pNC', PDSNAME],
    ['usnvecFrom', USN_VECTOR],
    ['pUpToDateVecDest', PUPTODATE_VECTOR_V1_EXT],
    ['ulFlags', ULONG],
    ['cMaxObjects', ULONG],
    ['cMaxBytes', ULONG],
    ['ulExtendedOp', ULONG],
    ['liFsmoInfo', ULARGE_INTEGER],
    ['pPartialAttrSet', PPARTIAL_ATTR_VECTOR_V1_EXT],
    ['pPartialAttrSetEx1', PPARTIAL_ATTR_VECTOR_V1_EXT],
    ['PrefixTableDest', SCHEMA_PREFIX_TABLE],
    ['ulMoreFlags', ULONG],
  ];
}

export class DRS_MSG_GETCHGREQ extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    4: ['V4', DRS_MSG_GETCHGREQ_V4],
    5: ['V5', DRS_MSG_GETCHGREQ_V5],
    7: ['V7', DRS_MSG_GETCHGREQ_V7],
    8: ['V8', DRS_MSG_GETCHGREQ_V8],
    10: ['V10', DRS_MSG_GETCHGREQ_V10],
  };
}

export class ATTRVAL extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['valLen', ULONG],
    ['pVal', PBYTE_ARRAY],
  ];
}

export class ATTRVAL_ARRAY extends NDRUniConformantArray {
  static item = ATTRVAL;
}

export class PATTRVAL_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ATTRVAL_ARRAY]];
}

export class ATTRVALBLOCK extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['valCount', ULONG],
    ['pAVal', PATTRVAL_ARRAY],
  ];
}

export class ATTR extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['attrTyp', ATTRTYP],
    ['AttrVal', ATTRVALBLOCK],
  ];
}

export class ATTR_ARRAY extends NDRUniConformantArray {
  static item = ATTR;
}

export class PATTR_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ATTR_ARRAY]];
}

export class ATTRBLOCK extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['attrCount', ULONG],
    ['pAttr', PATTR_ARRAY],
  ];
}

export class ENTINF extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['pName', PDSNAME],
    ['ulFlags', ULONG],
    ['AttrBlock', ATTRBLOCK],
  ];
}

export class ENTINF_ARRAY extends NDRUniConformantArray {
  static item = ENTINF;
}

export class PENTINF_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ENTINF_ARRAY]];
}

export class PROPERTY_META_DATA_EXT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwVersion', DWORD],
    ['timeChanged', DSTIME],
    ['uuidDsaOriginating', UUID],
    ['usnOriginating', USN],
  ];
}

export class PROPERTY_META_DATA_EXT_ARRAY extends NDRUniConformantArray {
  static item = PROPERTY_META_DATA_EXT;
}

export class PROPERTY_META_DATA_EXT_VECTOR extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cNumProps', DWORD],
    ['rgMetaData', PROPERTY_META_DATA_EXT_ARRAY],
  ];
}

export class PPROPERTY_META_DATA_EXT_VECTOR extends NDRPOINTER {
  static referent: NDRField[] = [['Data', PROPERTY_META_DATA_EXT_VECTOR]];
}

export class REPLENTINFLIST extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['pNextEntInf', NDRPOINTER],
    ['Entinf', ENTINF],
    ['fIsNCPrefix', BOOL],
    ['pParentGuidm', PUUID],
    ['pMetaDataExt', PPROPERTY_META_DATA_EXT_VECTOR],
  ];

  fromString(data: Buffer, offset = 0): number {
    this.fields['pNextEntInf'] = new PREPLENTINFLIST(null, this._isNDR64);
    return super.fromString(data, offset);
  }
}

export class PREPLENTINFLIST extends NDRPOINTER {
  static referent: NDRField[] = [['Data', REPLENTINFLIST]];
}

export class DRS_MSG_GETCHGREPLY_V1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['uuidDsaObjSrc', UUID],
    ['uuidInvocIdSrc', UUID],
    ['pNC', PDSNAME],
    ['usnvecFrom', USN_VECTOR],
    ['usnvecTo', USN_VECTOR],
    ['pUpToDateVecSrcV1', PUPTODATE_VECTOR_V1_EXT],
    ['PrefixTableSrc', SCHEMA_PREFIX_TABLE],
    ['ulExtendedRet', EXOP_ERR],
    ['cNumObjects', ULONG],
    ['cNumBytes', ULONG],
    ['pObjects', PREPLENTINFLIST],
    ['fMoreData', BOOL],
  ];
}

export class DRS_COMPRESSED_BLOB extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cbUncompressedSize', DWORD],
    ['cbCompressedSize', DWORD],
    ['pbCompressedData', BYTE_ARRAY],
  ];
}

export class DRS_MSG_GETCHGREPLY_V2 extends NDRSTRUCT {
  static structure: NDRField[] = [['CompressedV1', DRS_COMPRESSED_BLOB]];
}

export class UPTODATE_CURSOR_V2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['uuidDsa', UUID],
    ['usnHighPropUpdate', USN],
    ['timeLastSyncSuccess', DSTIME],
  ];
}

export class UPTODATE_CURSOR_V2_ARRAY extends NDRUniConformantArray {
  static item = UPTODATE_CURSOR_V2;
}

export class UPTODATE_VECTOR_V2_EXT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwVersion', DWORD],
    ['dwReserved1', DWORD],
    ['cNumCursors', DWORD],
    ['dwReserved2', DWORD],
    ['rgCursors', UPTODATE_CURSOR_V2_ARRAY],
  ];
}

export class PUPTODATE_VECTOR_V2_EXT extends NDRPOINTER {
  static referent: NDRField[] = [['Data', UPTODATE_VECTOR_V2_EXT]];
}

export class VALUE_META_DATA_EXT_V1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['timeCreated', DSTIME],
    ['MetaData', PROPERTY_META_DATA_EXT],
  ];
}

export class VALUE_META_DATA_EXT_V3 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['timeCreated', DSTIME],
    ['MetaData', PROPERTY_META_DATA_EXT],
    ['unused1', DWORD],
    ['unused2', DWORD],
    ['unused3', DWORD],
    ['timeExpired', DSTIME],
  ];
}

export class REPLVALINF_V1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['pObject', PDSNAME],
    ['attrTyp', ATTRTYP],
    ['Aval', ATTRVAL],
    ['fIsPresent', BOOL],
    ['MetaData', VALUE_META_DATA_EXT_V1],
  ];
}

export class REPLVALINF_V1_ARRAY extends NDRUniConformantArray {
  static item = REPLVALINF_V1;
}

export class PREPLVALINF_V1_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', REPLVALINF_V1_ARRAY]];
}

export class REPLVALINF_V3 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['pObject', PDSNAME],
    ['attrTyp', ATTRTYP],
    ['Aval', ATTRVAL],
    ['fIsPresent', BOOL],
    ['MetaData', VALUE_META_DATA_EXT_V3],
  ];
}

export class REPLVALINF_V3_ARRAY extends NDRUniConformantArray {
  static item = REPLVALINF_V3;
}

export class PREPLVALINF_V3_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', REPLVALINF_V3_ARRAY]];
}

export const REPLVALINF_NATIVE = REPLVALINF_V3;

export class DRS_MSG_GETCHGREPLY_V6 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['uuidDsaObjSrc', UUID],
    ['uuidInvocIdSrc', UUID],
    ['pNC', PDSNAME],
    ['usnvecFrom', USN_VECTOR],
    ['usnvecTo', USN_VECTOR],
    ['pUpToDateVecSrc', PUPTODATE_VECTOR_V2_EXT],
    ['PrefixTableSrc', SCHEMA_PREFIX_TABLE],
    ['ulExtendedRet', EXOP_ERR],
    ['cNumObjects', ULONG],
    ['cNumBytes', ULONG],
    ['pObjects', PREPLENTINFLIST],
    ['fMoreData', BOOL],
    ['cNumNcSizeObjects', ULONG],
    ['cNumNcSizeValues', ULONG],
    ['cNumValues', DWORD],
    ['rgValues', PREPLVALINF_V1_ARRAY],
    ['dwDRSError', DWORD],
  ];
}

export class DRS_COMP_ALG_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'DRS_COMP_ALG_NONE',
    1: 'DRS_COMP_ALG_UNUSED',
    2: 'DRS_COMP_ALG_MSZIP',
    3: 'DRS_COMP_ALG_WIN2K3',
  };
  static enumValues: Record<string, number> = {
    DRS_COMP_ALG_NONE: 0,
    DRS_COMP_ALG_UNUSED: 1,
    DRS_COMP_ALG_MSZIP: 2,
    DRS_COMP_ALG_WIN2K3: 3,
  };
}

export class DRS_MSG_GETCHGREPLY_V7 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwCompressedVersion', DWORD],
    ['CompressionAlg', DRS_COMP_ALG_TYPE],
    ['CompressedAny', DRS_COMPRESSED_BLOB],
  ];
}

export class DRS_MSG_GETCHGREPLY_V9 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['uuidDsaObjSrc', UUID],
    ['uuidInvocIdSrc', UUID],
    ['pNC', PDSNAME],
    ['usnvecFrom', USN_VECTOR],
    ['usnvecTo', USN_VECTOR],
    ['pUpToDateVecSrc', PUPTODATE_VECTOR_V2_EXT],
    ['PrefixTableSrc', SCHEMA_PREFIX_TABLE],
    ['ulExtendedRet', EXOP_ERR],
    ['cNumObjects', ULONG],
    ['cNumBytes', ULONG],
    ['pObjects', PREPLENTINFLIST],
    ['fMoreData', BOOL],
    ['cNumNcSizeObjects', ULONG],
    ['cNumNcSizeValues', ULONG],
    ['cNumValues', DWORD],
    ['rgValues', PREPLVALINF_V3_ARRAY],
    ['dwDRSError', DWORD],
  ];
}

export const DRS_MSG_GETCHGREPLY_NATIVE = DRS_MSG_GETCHGREPLY_V9;

export class DRS_MSG_GETCHGREPLY extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['V1', DRS_MSG_GETCHGREPLY_V1],
    2: ['V2', DRS_MSG_GETCHGREPLY_V2],
    6: ['V6', DRS_MSG_GETCHGREPLY_V6],
    7: ['V7', DRS_MSG_GETCHGREPLY_V7],
    9: ['V9', DRS_MSG_GETCHGREPLY_V9],
  };
}

export class DRS_MSG_VERIFYREQ_V1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwFlags', DWORD],
    ['cNames', DWORD],
    ['rpNames', PPDSNAME_ARRAY],
    ['RequiredAttrs', ATTRBLOCK],
    ['PrefixTable', SCHEMA_PREFIX_TABLE],
  ];
}

export class DRS_MSG_VERIFYREQ extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['V1', DRS_MSG_VERIFYREQ_V1],
  };
}

export class DRS_MSG_VERIFYREPLY_V1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['error', DWORD],
    ['cNames', DWORD],
    ['rpEntInf', PENTINF_ARRAY],
    ['PrefixTable', SCHEMA_PREFIX_TABLE],
  ];
}

export class DRS_MSG_VERIFYREPLY extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['V1', DRS_MSG_VERIFYREPLY_V1],
  };
}

export class DRS_MSG_NT4_CHGLOG_REQ_V1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwFlags', DWORD],
    ['PreferredMaximumLength', DWORD],
    ['cbRestart', DWORD],
    ['pRestart', PBYTE_ARRAY],
  ];
}

export class DRS_MSG_NT4_CHGLOG_REQ extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['V1', DRS_MSG_NT4_CHGLOG_REQ_V1],
  };
}

export class NT4_REPLICATION_STATE extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['SamSerialNumber', LARGE_INTEGER],
    ['SamCreationTime', LARGE_INTEGER],
    ['BuiltinSerialNumber', LARGE_INTEGER],
    ['BuiltinCreationTime', LARGE_INTEGER],
    ['LsaSerialNumber', LARGE_INTEGER],
    ['LsaCreationTime', LARGE_INTEGER],
  ];
}

export class DRS_MSG_NT4_CHGLOG_REPLY_V1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cbRestart', DWORD],
    ['cbLog', DWORD],
    ['ReplicationState', NT4_REPLICATION_STATE],
    ['ActualNtStatus', DWORD],
    ['pRestart', PBYTE_ARRAY],
    ['pLog', PBYTE_ARRAY],
  ];
}

export class DRS_MSG_NT4_CHGLOG_REPLY extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['V1', DRS_MSG_NT4_CHGLOG_REPLY_V1],
  };
}

export class DRSBindResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppextServer', PDRS_EXTENSIONS],
    ['phDrs', DRS_HANDLE],
    ['ErrorCode', DWORD],
  ];
}

export class DRSBind extends NDRCALL {
  static opnum = 0;
  static Response = DRSBindResponse;
  static structure: NDRField[] = [
    ['puuidClientDsa', PUUID],
    ['pextClient', PDRS_EXTENSIONS],
  ];
}

export class DRSUnbindResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phDrs', DRS_HANDLE],
    ['ErrorCode', DWORD],
  ];
}

export class DRSUnbind extends NDRCALL {
  static opnum = 1;
  static Response = DRSUnbindResponse;
  static structure: NDRField[] = [['phDrs', DRS_HANDLE]];
}

export class DRSGetNCChangesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pdwOutVersion', DWORD],
    ['pmsgOut', DRS_MSG_GETCHGREPLY],
    ['ErrorCode', DWORD],
  ];
}

export class DRSGetNCChanges extends NDRCALL {
  static opnum = 3;
  static Response = DRSGetNCChangesResponse;
  static structure: NDRField[] = [
    ['hDrs', DRS_HANDLE],
    ['dwInVersion', DWORD],
    ['pmsgIn', DRS_MSG_GETCHGREQ],
  ];
}

export class DRSVerifyNamesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pdwOutVersion', DWORD],
    ['pmsgOut', DRS_MSG_VERIFYREPLY],
    ['ErrorCode', DWORD],
  ];
}

export class DRSVerifyNames extends NDRCALL {
  static opnum = 8;
  static Response = DRSVerifyNamesResponse;
  static structure: NDRField[] = [
    ['hDrs', DRS_HANDLE],
    ['dwInVersion', DWORD],
    ['pmsgIn', DRS_MSG_VERIFYREQ],
  ];
}

export class DRSGetNT4ChangeLogResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pdwOutVersion', DWORD],
    ['pmsgOut', DRS_MSG_NT4_CHGLOG_REPLY],
    ['ErrorCode', DWORD],
  ];
}

export class DRSGetNT4ChangeLog extends NDRCALL {
  static opnum = 11;
  static Response = DRSGetNT4ChangeLogResponse;
  static structure: NDRField[] = [
    ['hDrs', DRS_HANDLE],
    ['dwInVersion', DWORD],
    ['pmsgIn', DRS_MSG_NT4_CHGLOG_REQ],
  ];
}

export class DRSCrackNamesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pdwOutVersion', DWORD],
    ['pmsgOut', DRS_MSG_CRACKREPLY],
    ['ErrorCode', DWORD],
  ];
}

export class DRSCrackNames extends NDRCALL {
  static opnum = 12;
  static Response = DRSCrackNamesResponse;
  static structure: NDRField[] = [
    ['hDrs', DRS_HANDLE],
    ['dwInVersion', DWORD],
    ['pmsgIn', DRS_MSG_CRACKREQ],
  ];
}

export class DRSDomainControllerInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pdwOutVersion', DWORD],
    ['pmsgOut', DRS_MSG_DCINFOREPLY],
    ['ErrorCode', DWORD],
  ];
}

export class DRSDomainControllerInfo extends NDRCALL {
  static opnum = 16;
  static Response = DRSDomainControllerInfoResponse;
  static structure: NDRField[] = [
    ['hDrs', DRS_HANDLE],
    ['dwInVersion', DWORD],
    ['pmsgIn', DRS_MSG_DCINFOREQ],
  ];
}

const OPNUMS = {
  0: [DRSBind, DRSBindResponse] as const,
  1: [DRSUnbind, DRSUnbindResponse] as const,
  3: [DRSGetNCChanges, DRSGetNCChangesResponse] as const,
  12: [DRSCrackNames, DRSCrackNamesResponse] as const,
  16: [DRSDomainControllerInfo, DRSDomainControllerInfoResponse] as const,
};

type DceRequestFn = <T>(req: unknown, uuid?: unknown, checkError?: boolean) => Promise<T>;

function checkNullString(str: string | typeof NULL): string | typeof NULL {
  if (str === NULL) return str;
  if (typeof str !== 'string') return str;
  if (str.length === 0 || str[str.length - 1] !== '\x00') return str + '\x00';
  return str;
}

export async function hDRSUnbind(dce: DCERPC_v5, hDrs: DRS_HANDLE) {
  const request = new DRSUnbind();
  request.set('phDrs', hDrs);
  return (dce as unknown as { request: DceRequestFn }).request<DRSUnbindResponse>(request);
}

export async function hDRSDomainControllerInfo(
  dce: DCERPC_v5,
  hDrs: DRS_HANDLE,
  domain: string,
  infoLevel: number,
) {
  const request = new DRSDomainControllerInfo();
  request.set('hDrs', hDrs);
  request.set('dwInVersion', 1);
  const pmsgIn = request.fields['pmsgIn'] as DRS_MSG_DCINFOREQ;
  pmsgIn.set('tag', 1);
  const v1 = pmsgIn.fields['V1'] as DRS_MSG_DCINFOREQ_V1;
  v1.set('Domain', checkNullString(domain));
  v1.set('InfoLevel', infoLevel);
  return (dce as unknown as { request: DceRequestFn }).request<DRSDomainControllerInfoResponse>(
    request,
  );
}

export async function hDRSCrackNames(
  dce: DCERPC_v5,
  hDrs: DRS_HANDLE,
  flags: number,
  formatOffered: number,
  formatDesired: number,
  rpNames: string[] = [],
) {
  const request = new DRSCrackNames();
  request.set('hDrs', hDrs);
  request.set('dwInVersion', 1);
  const pmsgIn = request.fields['pmsgIn'] as DRS_MSG_CRACKREQ;
  pmsgIn.set('tag', 1);
  const v1 = pmsgIn.fields['V1'] as DRS_MSG_CRACKREQ_V1;
  v1.set('CodePage', 0);
  v1.set('LocaleId', 0);
  v1.set('dwFlags', flags);
  v1.set('formatOffered', formatOffered);
  v1.set('formatDesired', formatDesired);
  v1.set('cNames', rpNames.length);
  const rpNamesPtr = v1.fields['rpNames'] as PLPWSTR_ARRAY;
  const rpNamesArr = rpNamesPtr.fields['Data'] as LPWSTR_ARRAY;
  for (const name of rpNames) {
    const record = new LPWSTR();
    record.set('Data', checkNullString(name) as string);
    (rpNamesArr.fields['Data'] as unknown[]).push(record);
  }
  return (dce as unknown as { request: DceRequestFn }).request<DRSCrackNamesResponse>(request);
}

export function deriveKey(baseKey: number): [Buffer, Buffer] {
  const key = Buffer.alloc(4);
  key.writeUInt32LE(baseKey);
  const key1 = Buffer.from([key[0]!, key[1]!, key[2]!, key[3]!, key[0]!, key[1]!, key[2]!]);
  const key2 = Buffer.from([key[3]!, key[0]!, key[1]!, key[2]!, key[3]!, key[0]!, key[1]!]);
  return [transformKey(key1), transformKey(key2)];
}

export function removeDESLayer(cryptedHash: Buffer, rid: number): Buffer {
  const [key1, key2] = deriveKey(rid);
  return Buffer.concat([
    desEcbDecryptBlock(key1, cryptedHash.subarray(0, 8)),
    desEcbDecryptBlock(key2, cryptedHash.subarray(8, 16)),
  ]);
}

export function decryptAttributeValue(
  dce: DCERPC_v5,
  attribute: Buffer,
): Buffer {
  const sessionKey = (dce as unknown as { getSessionKey: () => Buffer | null }).getSessionKey();
  if (!sessionKey) {
    throw new Error('No session key available');
  }
  const encryptedPayload = new ENCRYPTED_PAYLOAD(attribute);
  const salt = encryptedPayload.get('Salt') as Buffer;
  const finalMD5 = createHash('md5').update(sessionKey).update(salt).digest();
  const plainText = rc4(finalMD5, attribute.subarray(16));
  return plainText.subarray(4);
}

export interface PrefixTableEntryLike {
  ndx: number;
  prefix: { length: number; elements: number[] };
}

export function makeAttid(
  prefixTable: PrefixTableEntryLike[],
  oid: string,
): number {
  const lastValue = Number.parseInt(oid.split('.').pop()!, 10);
  const binaryOID = encodeOID(oid);
  const oidPrefix: number[] = [];
  if (lastValue < 128) {
    for (let i = 0; i < binaryOID.length - 1; i++) {
      oidPrefix.push(binaryOID[i]!);
    }
  } else {
    for (let i = 0; i < binaryOID.length - 2; i++) {
      oidPrefix.push(binaryOID[i]!);
    }
  }

  let fToAdd = true;
  let pos = prefixTable.length;
  for (let j = 0; j < prefixTable.length; j++) {
    const item = prefixTable[j]!;
    if (
      item.prefix.elements.length === oidPrefix.length &&
      item.prefix.elements.every((v, k) => v === oidPrefix[k])
    ) {
      fToAdd = false;
      pos = j;
      break;
    }
  }

  if (fToAdd) {
    const entry: PrefixTableEntryLike = {
      ndx: pos,
      prefix: { length: oidPrefix.length, elements: [...oidPrefix] },
    };
    prefixTable.push(entry);
  }

  let lowerWord = lastValue % 16384;
  if (lastValue >= 16384) {
    lowerWord += 32768;
  }

  const upperWord = pos;
  return (upperWord << 16) + lowerWord;
}

export function oidFromAttid(
  prefixTable: PrefixTableEntryLike[],
  attr: number,
): string | null {
  const upperWord = Math.floor(attr / 65536);
  let lowerWord = attr % 65536;

  for (const item of prefixTable) {
    if (item.ndx === upperWord) {
      const binaryOID: number[] = [];
      for (let i = 0; i < item.prefix.length; i++) {
        binaryOID.push(item.prefix.elements[i]!);
      }
      if (lowerWord < 128) {
        binaryOID.push(lowerWord);
      } else {
        if (lowerWord >= 32768) {
          lowerWord -= 32768;
        }
        binaryOID.push((Math.floor(lowerWord / 128) % 128) + 128);
        binaryOID.push(lowerWord % 128);
      }
      return decodeOID(Buffer.from(binaryOID));
    }
  }

  return null;
}
