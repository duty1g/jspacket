import { Buffer } from 'node:buffer';
import { randomBytes, createHash } from 'node:crypto';
import { uuidtupToBin } from '@impacket/uuid';
import { Structure, type FieldDescriptor } from '@impacket/structure';
import { samEncryptNTLMHash, rc4 } from '@impacket/crypto';
import { ntowfV1, lmowfV1 } from '@impacket/ntlm';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRENUM,
  NDRUNION,
  NDRPOINTER,
  NDRUniConformantArray,
  NDRUniConformantVaryingArray,
  NULL,
  type NDRField,
} from './ndr';
import {
  ULONG,
  USHORT,
  UCHAR,
  LONG,
  LARGE_INTEGER,
  RPC_UNICODE_STRING,
  RPC_SID,
  PRPC_SID,
  PRPC_UNICODE_STRING,
  LPBYTE,
  LPWSTR,
  SECURITY_INFORMATION,
  STR,
  MAXIMUM_ALLOWED,
} from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_SAMR = uuidtupToBin(['12345778-1234-ABCD-EF00-0123456789AC', '1.0'])!;

class DCERPCSessionError extends DCERPCException {
  constructor(errorString?: string | null, errorCode?: number | null, packet?: unknown) {
    super(errorString, errorCode, packet);
    if (packet) {
      this.error_code = (packet as { get: (k: string) => unknown }).get('ErrorCode') as number;
    }
  }

  toString(): string {
    const key = this.error_code;
    if (key != null) {
      return `SAMR SessionError: code: 0x${key.toString(16)}`;
    }
    return `SAMR SessionError: unknown error code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

export const PSamprServerName = LPWSTR;

export const SAM_SERVER_CONNECT = 0x00000001;
export const SAM_SERVER_SHUTDOWN = 0x00000002;
export const SAM_SERVER_INITIALIZE = 0x00000004;
export const SAM_SERVER_CREATE_DOMAIN = 0x00000008;
export const SAM_SERVER_ENUMERATE_DOMAINS = 0x00000010;
export const SAM_SERVER_LOOKUP_DOMAIN = 0x00000020;
export const SAM_SERVER_ALL_ACCESS = 0x000f003f;
export const SAM_SERVER_READ = 0x00020010;
export const SAM_SERVER_WRITE = 0x0002000e;
export const SAM_SERVER_EXECUTE = 0x00020021;

export const DOMAIN_READ_PASSWORD_PARAMETERS = 0x00000001;
export const DOMAIN_WRITE_PASSWORD_PARAMS = 0x00000002;
export const DOMAIN_READ_OTHER_PARAMETERS = 0x00000004;
export const DOMAIN_WRITE_OTHER_PARAMETERS = 0x00000008;
export const DOMAIN_CREATE_USER = 0x00000010;
export const DOMAIN_CREATE_GROUP = 0x00000020;
export const DOMAIN_CREATE_ALIAS = 0x00000040;
export const DOMAIN_GET_ALIAS_MEMBERSHIP = 0x00000080;
export const DOMAIN_LIST_ACCOUNTS = 0x00000100;
export const DOMAIN_LOOKUP = 0x00000200;
export const DOMAIN_ADMINISTER_SERVER = 0x00000400;
export const DOMAIN_ALL_ACCESS = 0x000f07ff;
export const DOMAIN_READ = 0x00020084;
export const DOMAIN_WRITE = 0x0002047a;
export const DOMAIN_EXECUTE = 0x00020301;

export const GROUP_READ_INFORMATION = 0x00000001;
export const GROUP_WRITE_ACCOUNT = 0x00000002;
export const GROUP_ADD_MEMBER = 0x00000004;
export const GROUP_REMOVE_MEMBER = 0x00000008;
export const GROUP_LIST_MEMBERS = 0x00000010;
export const GROUP_ALL_ACCESS = 0x000f001f;
export const GROUP_READ = 0x00020010;
export const GROUP_WRITE = 0x0002000e;
export const GROUP_EXECUTE = 0x00020001;

export const ALIAS_ADD_MEMBER = 0x00000001;
export const ALIAS_REMOVE_MEMBER = 0x00000002;
export const ALIAS_LIST_MEMBERS = 0x00000004;
export const ALIAS_READ_INFORMATION = 0x00000008;
export const ALIAS_WRITE_ACCOUNT = 0x00000010;
export const ALIAS_ALL_ACCESS = 0x000f001f;
export const ALIAS_READ = 0x00020004;
export const ALIAS_WRITE = 0x00020013;
export const ALIAS_EXECUTE = 0x00020008;

export const USER_READ_GENERAL = 0x00000001;
export const USER_READ_PREFERENCES = 0x00000002;
export const USER_WRITE_PREFERENCES = 0x00000004;
export const USER_READ_LOGON = 0x00000008;
export const USER_READ_ACCOUNT = 0x00000010;
export const USER_WRITE_ACCOUNT = 0x00000020;
export const USER_CHANGE_PASSWORD = 0x00000040;
export const USER_FORCE_PASSWORD_CHANGE = 0x00000080;
export const USER_LIST_GROUPS = 0x00000100;
export const USER_READ_GROUP_INFORMATION = 0x00000200;
export const USER_WRITE_GROUP_INFORMATION = 0x00000400;
export const USER_ALL_ACCESS = 0x000f07ff;
export const USER_READ = 0x0002031a;
export const USER_WRITE = 0x00020044;
export const USER_EXECUTE = 0x00020041;

export const USER_ALL_USERNAME = 0x00000001;
export const USER_ALL_FULLNAME = 0x00000002;
export const USER_ALL_USERID = 0x00000004;
export const USER_ALL_PRIMARYGROUPID = 0x00000008;
export const USER_ALL_ADMINCOMMENT = 0x00000010;
export const USER_ALL_USERCOMMENT = 0x00000020;
export const USER_ALL_HOMEDIRECTORY = 0x00000040;
export const USER_ALL_HOMEDIRECTORYDRIVE = 0x00000080;
export const USER_ALL_SCRIPTPATH = 0x00000100;
export const USER_ALL_PROFILEPATH = 0x00000200;
export const USER_ALL_WORKSTATIONS = 0x00000400;
export const USER_ALL_LASTLOGON = 0x00000800;
export const USER_ALL_LASTLOGOFF = 0x00001000;
export const USER_ALL_LOGONHOURS = 0x00002000;
export const USER_ALL_BADPASSWORDCOUNT = 0x00004000;
export const USER_ALL_LOGONCOUNT = 0x00008000;
export const USER_ALL_PASSWORDCANCHANGE = 0x00010000;
export const USER_ALL_PASSWORDMUSTCHANGE = 0x00020000;
export const USER_ALL_PASSWORDLASTSET = 0x00040000;
export const USER_ALL_ACCOUNTEXPIRES = 0x00080000;
export const USER_ALL_USERACCOUNTCONTROL = 0x00100000;
export const USER_ALL_PARAMETERS = 0x00200000;
export const USER_ALL_COUNTRYCODE = 0x00400000;
export const USER_ALL_CODEPAGE = 0x00800000;
export const USER_ALL_NTPASSWORDPRESENT = 0x01000000;
export const USER_ALL_LMPASSWORDPRESENT = 0x02000000;
export const USER_ALL_PRIVATEDATA = 0x04000000;
export const USER_ALL_PASSWORDEXPIRED = 0x08000000;
export const USER_ALL_SECURITYDESCRIPTOR = 0x10000000;
export const USER_ALL_UNDEFINED_MASK = 0xc0000000;

export const SAM_DOMAIN_OBJECT = 0x00000000;
export const SAM_GROUP_OBJECT = 0x10000000;
export const SAM_NON_SECURITY_GROUP_OBJECT = 0x10000001;
export const SAM_ALIAS_OBJECT = 0x20000000;
export const SAM_NON_SECURITY_ALIAS_OBJECT = 0x20000001;
export const SAM_USER_OBJECT = 0x30000000;
export const SAM_MACHINE_ACCOUNT = 0x30000001;
export const SAM_TRUST_ACCOUNT = 0x30000002;
export const SAM_APP_BASIC_GROUP = 0x40000000;
export const SAM_APP_QUERY_GROUP = 0x40000001;

export const SE_GROUP_MANDATORY = 0x00000001;
export const SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002;
export const SE_GROUP_ENABLED = 0x00000004;

export const GROUP_TYPE_ACCOUNT_GROUP = 0x00000002;
export const GROUP_TYPE_RESOURCE_GROUP = 0x00000004;
export const GROUP_TYPE_UNIVERSAL_GROUP = 0x00000008;
export const GROUP_TYPE_SECURITY_ENABLED = 0x80000000;
export const GROUP_TYPE_SECURITY_ACCOUNT = 0x80000002;
export const GROUP_TYPE_SECURITY_RESOURCE = 0x80000004;
export const GROUP_TYPE_SECURITY_UNIVERSAL = 0x80000008;

export const USER_ACCOUNT_DISABLED = 0x00000001;
export const USER_HOME_DIRECTORY_REQUIRED = 0x00000002;
export const USER_PASSWORD_NOT_REQUIRED = 0x00000004;
export const USER_TEMP_DUPLICATE_ACCOUNT = 0x00000008;
export const USER_NORMAL_ACCOUNT = 0x00000010;
export const USER_MNS_LOGON_ACCOUNT = 0x00000020;
export const USER_INTERDOMAIN_TRUST_ACCOUNT = 0x00000040;
export const USER_WORKSTATION_TRUST_ACCOUNT = 0x00000080;
export const USER_SERVER_TRUST_ACCOUNT = 0x00000100;
export const USER_DONT_EXPIRE_PASSWORD = 0x00000200;
export const USER_ACCOUNT_AUTO_LOCKED = 0x00000400;
export const USER_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000800;
export const USER_SMARTCARD_REQUIRED = 0x00001000;
export const USER_TRUSTED_FOR_DELEGATION = 0x00002000;
export const USER_NOT_DELEGATED = 0x00004000;
export const USER_USE_DES_KEY_ONLY = 0x00008000;
export const USER_DONT_REQUIRE_PREAUTH = 0x00010000;
export const USER_PASSWORD_EXPIRED = 0x00020000;
export const USER_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x00040000;
export const USER_NO_AUTH_DATA_REQUIRED = 0x00080000;
export const USER_PARTIAL_SECRETS_ACCOUNT = 0x00100000;
export const USER_USE_AES_KEYS = 0x00200000;

export const UF_SCRIPT = 0x00000001;
export const UF_ACCOUNTDISABLE = 0x00000002;
export const UF_HOMEDIR_REQUIRED = 0x00000008;
export const UF_LOCKOUT = 0x00000010;
export const UF_PASSWD_NOTREQD = 0x00000020;
export const UF_PASSWD_CANT_CHANGE = 0x00000040;
export const UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000080;
export const UF_TEMP_DUPLICATE_ACCOUNT = 0x00000100;
export const UF_NORMAL_ACCOUNT = 0x00000200;
export const UF_INTERDOMAIN_TRUST_ACCOUNT = 0x00000800;
export const UF_WORKSTATION_TRUST_ACCOUNT = 0x00001000;
export const UF_SERVER_TRUST_ACCOUNT = 0x00002000;
export const UF_DONT_EXPIRE_PASSWD = 0x00010000;
export const UF_MNS_LOGON_ACCOUNT = 0x00020000;
export const UF_SMARTCARD_REQUIRED = 0x00040000;
export const UF_TRUSTED_FOR_DELEGATION = 0x00080000;
export const UF_NOT_DELEGATED = 0x00100000;
export const UF_USE_DES_KEY_ONLY = 0x00200000;
export const UF_DONT_REQUIRE_PREAUTH = 0x00400000;
export const UF_PASSWORD_EXPIRED = 0x00800000;
export const UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000;
export const UF_NO_AUTH_DATA_REQUIRED = 0x02000000;
export const UF_PARTIAL_SECRETS_ACCOUNT = 0x04000000;
export const UF_USE_AES_KEYS = 0x08000000;

export const DOMAIN_USER_RID_ADMIN = 0x000001f4;
export const DOMAIN_USER_RID_GUEST = 0x000001f5;
export const DOMAIN_USER_RID_KRBTGT = 0x000001f6;
export const DOMAIN_GROUP_RID_ADMINS = 0x00000200;
export const DOMAIN_GROUP_RID_USERS = 0x00000201;
export const DOMAIN_GROUP_RID_COMPUTERS = 0x00000203;
export const DOMAIN_GROUP_RID_CONTROLLERS = 0x00000204;
export const DOMAIN_ALIAS_RID_ADMINS = 0x00000220;
export const DOMAIN_GROUP_RID_READONLY_CONTROLLERS = 0x00000209;

export const DOMAIN_PASSWORD_COMPLEX = 0x00000001;
export const DOMAIN_PASSWORD_NO_ANON_CHANGE = 0x00000002;
export const DOMAIN_PASSWORD_NO_CLEAR_CHANGE = 0x00000004;
export const DOMAIN_LOCKOUT_ADMINS = 0x00000008;
export const DOMAIN_PASSWORD_STORE_CLEARTEXT = 0x00000010;
export const DOMAIN_REFUSE_PASSWORD_CHANGE = 0x00000020;

export const SAM_VALIDATE_PASSWORD_LAST_SET = 0x00000001;
export const SAM_VALIDATE_BAD_PASSWORD_TIME = 0x00000002;
export const SAM_VALIDATE_LOCKOUT_TIME = 0x00000004;
export const SAM_VALIDATE_BAD_PASSWORD_COUNT = 0x00000008;
export const SAM_VALIDATE_PASSWORD_HISTORY_LENGTH = 0x00000010;
export const SAM_VALIDATE_PASSWORD_HISTORY = 0x00000020;

export class RPC_UNICODE_STRING_ARRAY extends NDRUniConformantVaryingArray {
  static item = RPC_UNICODE_STRING;
}

export class RPC_UNICODE_STRING_ARRAY_C extends NDRUniConformantArray {
  static item = RPC_UNICODE_STRING;
}

export class PRPC_UNICODE_STRING_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', RPC_UNICODE_STRING_ARRAY_C]];
}

export class RPC_STRING extends NDRSTRUCT {
  static commonHdr: NDRField[] = [
    ['MaximumLength', '<H=len(Data)-12'],
    ['Length', '<H=len(Data)-12'],
    ['ReferentID', '<L=0xff'],
  ];
  static commonHdr64: NDRField[] = [
    ['MaximumLength', '<H=len(Data)-24'],
    ['Length', '<H=len(Data)-24'],
    ['ReferentID', '<Q=0xff'],
  ];
  static referent: NDRField[] = [['Data', STR]];
}

export class PRPC_STRING extends NDRPOINTER {
  static referent: NDRField[] = [['Data', RPC_STRING]];
}

export class OLD_LARGE_INTEGER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['LowPart', ULONG],
    ['HighPart', LONG],
  ];
}

export class SID_NAME_USE extends NDRENUM {
  static enumItems: Record<number, string> = {
    1: 'SidTypeUser',
    2: 'SidTypeGroup',
    3: 'SidTypeDomain',
    4: 'SidTypeAlias',
    5: 'SidTypeWellKnownGroup',
    6: 'SidTypeDeletedAccount',
    7: 'SidTypeInvalid',
    8: 'SidTypeUnknown',
    9: 'SidTypeComputer',
    10: 'SidTypeLabel',
  };
  static enumValues: Record<string, number> = {
    SidTypeUser: 1,
    SidTypeGroup: 2,
    SidTypeDomain: 3,
    SidTypeAlias: 4,
    SidTypeWellKnownGroup: 5,
    SidTypeDeletedAccount: 6,
    SidTypeInvalid: 7,
    SidTypeUnknown: 8,
    SidTypeComputer: 9,
    SidTypeLabel: 10,
  };
}

export class USHORT_ARRAY extends NDRUniConformantVaryingArray {
  static item = '<H';
}

export class PUSHORT_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', USHORT_ARRAY]];
}

export class RPC_SHORT_BLOB extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Length', USHORT],
    ['MaximumLength', USHORT],
    ['Buffer', PUSHORT_ARRAY],
  ];
}

export class SAMPR_HANDLE extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', '20s=b""']];
  getAlignment(): number {
    if (this._isNDR64 === true) {
      return 8;
    }
    return 4;
  }
}

export class ENCRYPTED_LM_OWF_PASSWORD extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', '16s=b""']];
  getAlignment(): number {
    return 1;
  }
}

export const ENCRYPTED_NT_OWF_PASSWORD = ENCRYPTED_LM_OWF_PASSWORD;

export class PENCRYPTED_LM_OWF_PASSWORD extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ENCRYPTED_LM_OWF_PASSWORD]];
}

export const PENCRYPTED_NT_OWF_PASSWORD = PENCRYPTED_LM_OWF_PASSWORD;

export class ULONG_ARRAY extends NDRUniConformantArray {
  static item = ULONG;
}

export class PULONG_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ULONG_ARRAY]];
}

export class ULONG_ARRAY_CV extends NDRUniConformantVaryingArray {
  static item = ULONG;
}

export class SAMPR_ULONG_ARRAY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Count', ULONG],
    ['Element', PULONG_ARRAY],
  ];
}

export class SAMPR_SID_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['SidPointer', RPC_SID]];
}

export class PSAMPR_SID_INFORMATION extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAMPR_SID_INFORMATION]];
}

export class SAMPR_SID_INFORMATION_ARRAY extends NDRUniConformantArray {
  static item = PSAMPR_SID_INFORMATION;
}

export class PSAMPR_SID_INFORMATION_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAMPR_SID_INFORMATION_ARRAY]];
}

export class SAMPR_PSID_ARRAY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Count', ULONG],
    ['Sids', PSAMPR_SID_INFORMATION_ARRAY],
  ];
}

export class SAMPR_PSID_ARRAY_OUT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Count', ULONG],
    ['Sids', PSAMPR_SID_INFORMATION_ARRAY],
  ];
}

export class SAMPR_RETURNED_USTRING_ARRAY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Count', ULONG],
    ['Element', PRPC_UNICODE_STRING_ARRAY],
  ];
}

export class SAMPR_RID_ENUMERATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['RelativeId', ULONG],
    ['Name', RPC_UNICODE_STRING],
  ];
}

export class SAMPR_RID_ENUMERATION_ARRAY extends NDRUniConformantArray {
  static item = SAMPR_RID_ENUMERATION;
}

export class PSAMPR_RID_ENUMERATION_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAMPR_RID_ENUMERATION_ARRAY]];
}

export class SAMPR_ENUMERATION_BUFFER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', ULONG],
    ['Buffer', PSAMPR_RID_ENUMERATION_ARRAY],
  ];
}

export class PSAMPR_ENUMERATION_BUFFER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAMPR_ENUMERATION_BUFFER]];
}

export class CHAR_ARRAY extends NDRUniConformantArray {}

export class PCHAR_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', CHAR_ARRAY]];
}

export class SAMPR_SR_SECURITY_DESCRIPTOR extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Length', ULONG],
    ['SecurityDescriptor', PCHAR_ARRAY],
  ];
}

export class PSAMPR_SR_SECURITY_DESCRIPTOR extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAMPR_SR_SECURITY_DESCRIPTOR]];
}

export class GROUP_MEMBERSHIP extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['RelativeId', ULONG],
    ['Attributes', ULONG],
  ];
}

export class GROUP_MEMBERSHIP_ARRAY extends NDRUniConformantArray {
  static item = GROUP_MEMBERSHIP;
}

export class PGROUP_MEMBERSHIP_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', GROUP_MEMBERSHIP_ARRAY]];
}

export class SAMPR_GET_GROUPS_BUFFER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['MembershipCount', ULONG],
    ['Groups', PGROUP_MEMBERSHIP_ARRAY],
  ];
}

export class PSAMPR_GET_GROUPS_BUFFER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAMPR_GET_GROUPS_BUFFER]];
}

export class SAMPR_GET_MEMBERS_BUFFER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['MemberCount', ULONG],
    ['Members', PULONG_ARRAY],
    ['Attributes', PULONG_ARRAY],
  ];
}

export class PSAMPR_GET_MEMBERS_BUFFER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAMPR_GET_MEMBERS_BUFFER]];
}

export class SAMPR_REVISION_INFO_V1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Revision', ULONG],
    ['SupportedFeatures', ULONG],
  ];
}

export class SAMPR_REVISION_INFO extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['V1', SAMPR_REVISION_INFO_V1],
  };
}

export class USER_DOMAIN_PASSWORD_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['MinPasswordLength', USHORT],
    ['PasswordProperties', ULONG],
  ];
}

export class DOMAIN_SERVER_ENABLE_STATE extends NDRENUM {
  static enumItems: Record<number, string> = {
    1: 'DomainServerEnabled',
    2: 'DomainServerDisabled',
  };
  static enumValues: Record<string, number> = {
    DomainServerEnabled: 1,
    DomainServerDisabled: 2,
  };
}

export class DOMAIN_STATE_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['DomainServerState', DOMAIN_SERVER_ENABLE_STATE]];
}

export class DOMAIN_SERVER_ROLE extends NDRENUM {
  static enumItems: Record<number, string> = {
    2: 'DomainServerRoleBackup',
    3: 'DomainServerRolePrimary',
  };
  static enumValues: Record<string, number> = {
    DomainServerRoleBackup: 2,
    DomainServerRolePrimary: 3,
  };
}

export class DOMAIN_PASSWORD_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['MinPasswordLength', USHORT],
    ['PasswordHistoryLength', USHORT],
    ['PasswordProperties', ULONG],
    ['MaxPasswordAge', OLD_LARGE_INTEGER],
    ['MinPasswordAge', OLD_LARGE_INTEGER],
  ];
}

export class DOMAIN_LOGOFF_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['ForceLogoff', OLD_LARGE_INTEGER]];
}

export class DOMAIN_SERVER_ROLE_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['DomainServerRole', DOMAIN_SERVER_ROLE]];
}

export class DOMAIN_MODIFIED_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['DomainModifiedCount', OLD_LARGE_INTEGER],
    ['CreationTime', OLD_LARGE_INTEGER],
  ];
}

export class DOMAIN_MODIFIED_INFORMATION2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['DomainModifiedCount', OLD_LARGE_INTEGER],
    ['CreationTime', OLD_LARGE_INTEGER],
    ['ModifiedCountAtLastPromotion', OLD_LARGE_INTEGER],
  ];
}

export class SAMPR_DOMAIN_GENERAL_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ForceLogoff', OLD_LARGE_INTEGER],
    ['OemInformation', RPC_UNICODE_STRING],
    ['DomainName', RPC_UNICODE_STRING],
    ['ReplicaSourceNodeName', RPC_UNICODE_STRING],
    ['DomainModifiedCount', OLD_LARGE_INTEGER],
    ['DomainServerState', ULONG],
    ['DomainServerRole', ULONG],
    ['UasCompatibilityRequired', UCHAR],
    ['UserCount', ULONG],
    ['GroupCount', ULONG],
    ['AliasCount', ULONG],
  ];
}

export class SAMPR_DOMAIN_GENERAL_INFORMATION2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['I1', SAMPR_DOMAIN_GENERAL_INFORMATION],
    ['LockoutDuration', LARGE_INTEGER],
    ['LockoutObservationWindow', LARGE_INTEGER],
    ['LockoutThreshold', USHORT],
  ];
}

export class SAMPR_DOMAIN_OEM_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['OemInformation', RPC_UNICODE_STRING]];
}

export class SAMPR_DOMAIN_NAME_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['DomainName', RPC_UNICODE_STRING]];
}

export class SAMPR_DOMAIN_REPLICATION_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['ReplicaSourceNodeName', RPC_UNICODE_STRING]];
}

export class SAMPR_DOMAIN_LOCKOUT_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['LockoutDuration', LARGE_INTEGER],
    ['LockoutObservationWindow', LARGE_INTEGER],
    ['LockoutThreshold', USHORT],
  ];
}

export class DOMAIN_INFORMATION_CLASS extends NDRENUM {
  static enumItems: Record<number, string> = {
    1: 'DomainPasswordInformation',
    2: 'DomainGeneralInformation',
    3: 'DomainLogoffInformation',
    4: 'DomainOemInformation',
    5: 'DomainNameInformation',
    6: 'DomainReplicationInformation',
    7: 'DomainServerRoleInformation',
    8: 'DomainModifiedInformation',
    9: 'DomainStateInformation',
    11: 'DomainGeneralInformation2',
    12: 'DomainLockoutInformation',
    13: 'DomainModifiedInformation2',
  };
  static enumValues: Record<string, number> = {
    DomainPasswordInformation: 1,
    DomainGeneralInformation: 2,
    DomainLogoffInformation: 3,
    DomainOemInformation: 4,
    DomainNameInformation: 5,
    DomainReplicationInformation: 6,
    DomainServerRoleInformation: 7,
    DomainModifiedInformation: 8,
    DomainStateInformation: 9,
    DomainGeneralInformation2: 11,
    DomainLockoutInformation: 12,
    DomainModifiedInformation2: 13,
  };
}

export class SAMPR_DOMAIN_INFO_BUFFER extends NDRUNION {
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['Password', DOMAIN_PASSWORD_INFORMATION],
    2: ['General', SAMPR_DOMAIN_GENERAL_INFORMATION],
    3: ['Logoff', DOMAIN_LOGOFF_INFORMATION],
    4: ['Oem', SAMPR_DOMAIN_OEM_INFORMATION],
    5: ['Name', SAMPR_DOMAIN_NAME_INFORMATION],
    7: ['Role', DOMAIN_SERVER_ROLE_INFORMATION],
    6: ['Replication', SAMPR_DOMAIN_REPLICATION_INFORMATION],
    8: ['Modified', DOMAIN_MODIFIED_INFORMATION],
    9: ['State', DOMAIN_STATE_INFORMATION],
    11: ['General2', SAMPR_DOMAIN_GENERAL_INFORMATION2],
    12: ['Lockout', SAMPR_DOMAIN_LOCKOUT_INFORMATION],
    13: ['Modified2', DOMAIN_MODIFIED_INFORMATION2],
  };
}

export class PSAMPR_DOMAIN_INFO_BUFFER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAMPR_DOMAIN_INFO_BUFFER]];
}

export class GROUP_ATTRIBUTE_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['Attributes', ULONG]];
}

export class SAMPR_GROUP_GENERAL_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Name', RPC_UNICODE_STRING],
    ['Attributes', ULONG],
    ['MemberCount', ULONG],
    ['AdminComment', RPC_UNICODE_STRING],
  ];
}

export class SAMPR_GROUP_NAME_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['Name', RPC_UNICODE_STRING]];
}

export class SAMPR_GROUP_ADM_COMMENT_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['AdminComment', RPC_UNICODE_STRING]];
}

export class GROUP_INFORMATION_CLASS extends NDRENUM {
  static enumItems: Record<number, string> = {
    1: 'GroupGeneralInformation',
    2: 'GroupNameInformation',
    3: 'GroupAttributeInformation',
    4: 'GroupAdminCommentInformation',
    5: 'GroupReplicationInformation',
  };
  static enumValues: Record<string, number> = {
    GroupGeneralInformation: 1,
    GroupNameInformation: 2,
    GroupAttributeInformation: 3,
    GroupAdminCommentInformation: 4,
    GroupReplicationInformation: 5,
  };
}

export class SAMPR_GROUP_INFO_BUFFER extends NDRUNION {
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['General', SAMPR_GROUP_GENERAL_INFORMATION],
    2: ['Name', SAMPR_GROUP_NAME_INFORMATION],
    3: ['Attribute', GROUP_ATTRIBUTE_INFORMATION],
    4: ['AdminComment', SAMPR_GROUP_ADM_COMMENT_INFORMATION],
    5: ['DoNotUse', SAMPR_GROUP_GENERAL_INFORMATION],
  };
}

export class PSAMPR_GROUP_INFO_BUFFER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAMPR_GROUP_INFO_BUFFER]];
}

export class SAMPR_ALIAS_GENERAL_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Name', RPC_UNICODE_STRING],
    ['MemberCount', ULONG],
    ['AdminComment', RPC_UNICODE_STRING],
  ];
}

export class SAMPR_ALIAS_NAME_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['Name', RPC_UNICODE_STRING]];
}

export class SAMPR_ALIAS_ADM_COMMENT_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['AdminComment', RPC_UNICODE_STRING]];
}

export class ALIAS_INFORMATION_CLASS extends NDRENUM {
  static enumItems: Record<number, string> = {
    1: 'AliasGeneralInformation',
    2: 'AliasNameInformation',
    3: 'AliasAdminCommentInformation',
  };
  static enumValues: Record<string, number> = {
    AliasGeneralInformation: 1,
    AliasNameInformation: 2,
    AliasAdminCommentInformation: 3,
  };
}

export class SAMPR_ALIAS_INFO_BUFFER extends NDRUNION {
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['General', SAMPR_ALIAS_GENERAL_INFORMATION],
    2: ['Name', SAMPR_ALIAS_NAME_INFORMATION],
    3: ['AdminComment', SAMPR_ALIAS_ADM_COMMENT_INFORMATION],
  };
}

export class PSAMPR_ALIAS_INFO_BUFFER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAMPR_ALIAS_INFO_BUFFER]];
}

export class USER_PRIMARY_GROUP_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['PrimaryGroupId', ULONG]];
}

export class USER_CONTROL_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['UserAccountControl', ULONG]];
}

export class USER_EXPIRES_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['AccountExpires', OLD_LARGE_INTEGER]];
}

export class LOGON_HOURS_ARRAY extends NDRUniConformantVaryingArray {}

export class PLOGON_HOURS_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LOGON_HOURS_ARRAY]];
}

export class SAMPR_LOGON_HOURS extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['UnitsPerWeek', ULONG],
    ['LogonHours', PLOGON_HOURS_ARRAY],
  ];

  getData(soFar = 0): Buffer {
    const logonHoursVal = this.get('LogonHours');
    if (logonHoursVal !== 0) {
      const arr = this.fields['LogonHours'] as PLOGON_HOURS_ARRAY;
      const inner = arr.fields['Data'] as LOGON_HOURS_ARRAY;
      const data = inner.fields['Data'] as unknown[];
      this.set('UnitsPerWeek', data.length * 8);
    }
    return super.getData(soFar);
  }
}

export class SAMPR_USER_ALL_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['LastLogon', OLD_LARGE_INTEGER],
    ['LastLogoff', OLD_LARGE_INTEGER],
    ['PasswordLastSet', OLD_LARGE_INTEGER],
    ['AccountExpires', OLD_LARGE_INTEGER],
    ['PasswordCanChange', OLD_LARGE_INTEGER],
    ['PasswordMustChange', OLD_LARGE_INTEGER],
    ['UserName', RPC_UNICODE_STRING],
    ['FullName', RPC_UNICODE_STRING],
    ['HomeDirectory', RPC_UNICODE_STRING],
    ['HomeDirectoryDrive', RPC_UNICODE_STRING],
    ['ScriptPath', RPC_UNICODE_STRING],
    ['ProfilePath', RPC_UNICODE_STRING],
    ['AdminComment', RPC_UNICODE_STRING],
    ['WorkStations', RPC_UNICODE_STRING],
    ['UserComment', RPC_UNICODE_STRING],
    ['Parameters', RPC_UNICODE_STRING],
    ['LmOwfPassword', RPC_SHORT_BLOB],
    ['NtOwfPassword', RPC_SHORT_BLOB],
    ['PrivateData', RPC_UNICODE_STRING],
    ['SecurityDescriptor', SAMPR_SR_SECURITY_DESCRIPTOR],
    ['UserId', ULONG],
    ['PrimaryGroupId', ULONG],
    ['UserAccountControl', ULONG],
    ['WhichFields', ULONG],
    ['LogonHours', SAMPR_LOGON_HOURS],
    ['BadPasswordCount', USHORT],
    ['LogonCount', USHORT],
    ['CountryCode', USHORT],
    ['CodePage', USHORT],
    ['LmPasswordPresent', UCHAR],
    ['NtPasswordPresent', UCHAR],
    ['PasswordExpired', UCHAR],
    ['PrivateDataSensitive', UCHAR],
  ];
}

export class SAMPR_USER_GENERAL_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['UserName', RPC_UNICODE_STRING],
    ['FullName', RPC_UNICODE_STRING],
    ['PrimaryGroupId', ULONG],
    ['AdminComment', RPC_UNICODE_STRING],
    ['UserComment', RPC_UNICODE_STRING],
  ];
}

export class SAMPR_USER_PREFERENCES_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['UserComment', RPC_UNICODE_STRING],
    ['Reserved1', RPC_UNICODE_STRING],
    ['CountryCode', USHORT],
    ['CodePage', USHORT],
  ];
}

export class SAMPR_USER_PARAMETERS_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['Parameters', RPC_UNICODE_STRING]];
}

export class SAMPR_USER_LOGON_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['UserName', RPC_UNICODE_STRING],
    ['FullName', RPC_UNICODE_STRING],
    ['UserId', ULONG],
    ['PrimaryGroupId', ULONG],
    ['HomeDirectory', RPC_UNICODE_STRING],
    ['HomeDirectoryDrive', RPC_UNICODE_STRING],
    ['ScriptPath', RPC_UNICODE_STRING],
    ['ProfilePath', RPC_UNICODE_STRING],
    ['WorkStations', RPC_UNICODE_STRING],
    ['LastLogon', OLD_LARGE_INTEGER],
    ['LastLogoff', OLD_LARGE_INTEGER],
    ['PasswordLastSet', OLD_LARGE_INTEGER],
    ['PasswordCanChange', OLD_LARGE_INTEGER],
    ['PasswordMustChange', OLD_LARGE_INTEGER],
    ['LogonHours', SAMPR_LOGON_HOURS],
    ['BadPasswordCount', USHORT],
    ['LogonCount', USHORT],
    ['UserAccountControl', ULONG],
  ];
}

export class SAMPR_USER_ACCOUNT_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['UserName', RPC_UNICODE_STRING],
    ['FullName', RPC_UNICODE_STRING],
    ['UserId', ULONG],
    ['PrimaryGroupId', ULONG],
    ['HomeDirectory', RPC_UNICODE_STRING],
    ['HomeDirectoryDrive', RPC_UNICODE_STRING],
    ['ScriptPath', RPC_UNICODE_STRING],
    ['ProfilePath', RPC_UNICODE_STRING],
    ['AdminComment', RPC_UNICODE_STRING],
    ['WorkStations', RPC_UNICODE_STRING],
    ['LastLogon', OLD_LARGE_INTEGER],
    ['LastLogoff', OLD_LARGE_INTEGER],
    ['LogonHours', SAMPR_LOGON_HOURS],
    ['BadPasswordCount', USHORT],
    ['LogonCount', USHORT],
    ['PasswordLastSet', OLD_LARGE_INTEGER],
    ['AccountExpires', OLD_LARGE_INTEGER],
    ['UserAccountControl', ULONG],
  ];
}

export class SAMPR_USER_A_NAME_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['UserName', RPC_UNICODE_STRING]];
}

export class SAMPR_USER_F_NAME_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['FullName', RPC_UNICODE_STRING]];
}

export class SAMPR_USER_NAME_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['UserName', RPC_UNICODE_STRING],
    ['FullName', RPC_UNICODE_STRING],
  ];
}

export class SAMPR_USER_HOME_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['HomeDirectory', RPC_UNICODE_STRING],
    ['HomeDirectoryDrive', RPC_UNICODE_STRING],
  ];
}

export class SAMPR_USER_SCRIPT_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['ScriptPath', RPC_UNICODE_STRING]];
}

export class SAMPR_USER_PROFILE_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['ProfilePath', RPC_UNICODE_STRING]];
}

export class SAMPR_USER_ADMIN_COMMENT_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['AdminComment', RPC_UNICODE_STRING]];
}

export class SAMPR_USER_WORKSTATIONS_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['WorkStations', RPC_UNICODE_STRING]];
}

export class SAMPR_USER_LOGON_HOURS_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['LogonHours', SAMPR_LOGON_HOURS]];
}

export class SAMPR_USER_PASSWORD extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Buffer', '512s=b""'],
    ['Length', ULONG],
  ];
  getAlignment(): number {
    return 4;
  }
}

export class SAMPR_ENCRYPTED_USER_PASSWORD extends NDRSTRUCT {
  static structure: NDRField[] = [['Buffer', '516s=b""']];
  getAlignment(): number {
    return 1;
  }
}

export class PSAMPR_ENCRYPTED_USER_PASSWORD extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAMPR_ENCRYPTED_USER_PASSWORD]];
}

export class SAMPR_ENCRYPTED_USER_PASSWORD_NEW extends NDRSTRUCT {
  static structure: NDRField[] = [['Buffer', '532s=b""']];
  getAlignment(): number {
    return 1;
  }
}

export class SAMPR_USER_INTERNAL1_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EncryptedNtOwfPassword', ENCRYPTED_NT_OWF_PASSWORD],
    ['EncryptedLmOwfPassword', ENCRYPTED_LM_OWF_PASSWORD],
    ['NtPasswordPresent', UCHAR],
    ['LmPasswordPresent', UCHAR],
    ['PasswordExpired', UCHAR],
  ];
}

export class SAMPR_USER_INTERNAL4_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['I1', SAMPR_USER_ALL_INFORMATION],
    ['UserPassword', SAMPR_ENCRYPTED_USER_PASSWORD],
  ];
}

export class SAMPR_USER_INTERNAL4_INFORMATION_NEW extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['I1', SAMPR_USER_ALL_INFORMATION],
    ['UserPassword', SAMPR_ENCRYPTED_USER_PASSWORD_NEW],
  ];
}

export class SAMPR_USER_INTERNAL5_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['UserPassword', SAMPR_ENCRYPTED_USER_PASSWORD],
    ['PasswordExpired', UCHAR],
  ];
}

export class SAMPR_USER_INTERNAL5_INFORMATION_NEW extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['UserPassword', SAMPR_ENCRYPTED_USER_PASSWORD_NEW],
    ['PasswordExpired', UCHAR],
  ];
}

export class SAMPR_USER_RESET_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ExtendedWhichFields', ULONG],
    ['ResetData', RPC_UNICODE_STRING],
  ];
}

export class USER_INFORMATION_CLASS extends NDRENUM {
  static enumItems: Record<number, string> = {
    1: 'UserGeneralInformation',
    2: 'UserPreferencesInformation',
    3: 'UserLogonInformation',
    4: 'UserLogonHoursInformation',
    5: 'UserAccountInformation',
    6: 'UserNameInformation',
    7: 'UserAccountNameInformation',
    8: 'UserFullNameInformation',
    9: 'UserPrimaryGroupInformation',
    10: 'UserHomeInformation',
    11: 'UserScriptInformation',
    12: 'UserProfileInformation',
    13: 'UserAdminCommentInformation',
    14: 'UserWorkStationsInformation',
    16: 'UserControlInformation',
    17: 'UserExpiresInformation',
    18: 'UserInternal1Information',
    20: 'UserParametersInformation',
    21: 'UserAllInformation',
    23: 'UserInternal4Information',
    24: 'UserInternal5Information',
    25: 'UserInternal4InformationNew',
    26: 'UserInternal5InformationNew',
    30: 'UserResetInformation',
  };
  static enumValues: Record<string, number> = {
    UserGeneralInformation: 1,
    UserPreferencesInformation: 2,
    UserLogonInformation: 3,
    UserLogonHoursInformation: 4,
    UserAccountInformation: 5,
    UserNameInformation: 6,
    UserAccountNameInformation: 7,
    UserFullNameInformation: 8,
    UserPrimaryGroupInformation: 9,
    UserHomeInformation: 10,
    UserScriptInformation: 11,
    UserProfileInformation: 12,
    UserAdminCommentInformation: 13,
    UserWorkStationsInformation: 14,
    UserControlInformation: 16,
    UserExpiresInformation: 17,
    UserInternal1Information: 18,
    UserParametersInformation: 20,
    UserAllInformation: 21,
    UserInternal4Information: 23,
    UserInternal5Information: 24,
    UserInternal4InformationNew: 25,
    UserInternal5InformationNew: 26,
    UserResetInformation: 30,
  };
}

export class SAMPR_USER_INFO_BUFFER extends NDRUNION {
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['General', SAMPR_USER_GENERAL_INFORMATION],
    2: ['Preferences', SAMPR_USER_PREFERENCES_INFORMATION],
    3: ['Logon', SAMPR_USER_LOGON_INFORMATION],
    4: ['LogonHours', SAMPR_USER_LOGON_HOURS_INFORMATION],
    5: ['Account', SAMPR_USER_ACCOUNT_INFORMATION],
    6: ['Name', SAMPR_USER_NAME_INFORMATION],
    7: ['AccountName', SAMPR_USER_A_NAME_INFORMATION],
    8: ['FullName', SAMPR_USER_F_NAME_INFORMATION],
    9: ['PrimaryGroup', USER_PRIMARY_GROUP_INFORMATION],
    10: ['Home', SAMPR_USER_HOME_INFORMATION],
    11: ['Script', SAMPR_USER_SCRIPT_INFORMATION],
    12: ['Profile', SAMPR_USER_PROFILE_INFORMATION],
    13: ['AdminComment', SAMPR_USER_ADMIN_COMMENT_INFORMATION],
    14: ['WorkStations', SAMPR_USER_WORKSTATIONS_INFORMATION],
    16: ['Control', USER_CONTROL_INFORMATION],
    17: ['Expires', USER_EXPIRES_INFORMATION],
    18: ['Internal1', SAMPR_USER_INTERNAL1_INFORMATION],
    20: ['Parameters', SAMPR_USER_PARAMETERS_INFORMATION],
    21: ['All', SAMPR_USER_ALL_INFORMATION],
    23: ['Internal4', SAMPR_USER_INTERNAL4_INFORMATION],
    24: ['Internal5', SAMPR_USER_INTERNAL5_INFORMATION],
    25: ['Internal4New', SAMPR_USER_INTERNAL4_INFORMATION_NEW],
    26: ['Internal5New', SAMPR_USER_INTERNAL5_INFORMATION_NEW],
    30: ['Reset', SAMPR_USER_RESET_INFORMATION],
  };
}

export class PSAMPR_USER_INFO_BUFFER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAMPR_USER_INFO_BUFFER]];
}

export class PSAMPR_SERVER_NAME2 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', '4s=b""']];
}

export class SAMPR_DOMAIN_DISPLAY_USER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Index', ULONG],
    ['Rid', ULONG],
    ['AccountControl', ULONG],
    ['AccountName', RPC_UNICODE_STRING],
    ['AdminComment', RPC_UNICODE_STRING],
    ['FullName', RPC_UNICODE_STRING],
  ];
}

export class SAMPR_DOMAIN_DISPLAY_USER_ARRAY extends NDRUniConformantArray {
  static item = SAMPR_DOMAIN_DISPLAY_USER;
}

export class PSAMPR_DOMAIN_DISPLAY_USER_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAMPR_DOMAIN_DISPLAY_USER_ARRAY]];
}

export class SAMPR_DOMAIN_DISPLAY_MACHINE extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Index', ULONG],
    ['Rid', ULONG],
    ['AccountControl', ULONG],
    ['AccountName', RPC_UNICODE_STRING],
    ['AdminComment', RPC_UNICODE_STRING],
  ];
}

export class SAMPR_DOMAIN_DISPLAY_MACHINE_ARRAY extends NDRUniConformantArray {
  static item = SAMPR_DOMAIN_DISPLAY_MACHINE;
}

export class PSAMPR_DOMAIN_DISPLAY_MACHINE_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAMPR_DOMAIN_DISPLAY_MACHINE_ARRAY]];
}

export class SAMPR_DOMAIN_DISPLAY_GROUP extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Index', ULONG],
    ['Rid', ULONG],
    ['AccountControl', ULONG],
    ['AccountName', RPC_UNICODE_STRING],
    ['AdminComment', RPC_UNICODE_STRING],
  ];
}

export class SAMPR_DOMAIN_DISPLAY_GROUP_ARRAY extends NDRUniConformantArray {
  static item = SAMPR_DOMAIN_DISPLAY_GROUP;
}

export class PSAMPR_DOMAIN_DISPLAY_GROUP_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAMPR_DOMAIN_DISPLAY_GROUP_ARRAY]];
}

export class SAMPR_DOMAIN_DISPLAY_OEM_USER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Index', ULONG],
    ['OemAccountName', RPC_STRING],
  ];
}

export class SAMPR_DOMAIN_DISPLAY_OEM_USER_ARRAY extends NDRUniConformantArray {
  static item = SAMPR_DOMAIN_DISPLAY_OEM_USER;
}

export class PSAMPR_DOMAIN_DISPLAY_OEM_USER_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAMPR_DOMAIN_DISPLAY_OEM_USER_ARRAY]];
}

export class SAMPR_DOMAIN_DISPLAY_OEM_GROUP extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Index', ULONG],
    ['OemAccountName', RPC_STRING],
  ];
}

export class SAMPR_DOMAIN_DISPLAY_OEM_GROUP_ARRAY extends NDRUniConformantArray {
  static item = SAMPR_DOMAIN_DISPLAY_OEM_GROUP;
}

export class PSAMPR_DOMAIN_DISPLAY_OEM_GROUP_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAMPR_DOMAIN_DISPLAY_OEM_GROUP_ARRAY]];
}

export class SAMPR_DOMAIN_DISPLAY_USER_BUFFER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', ULONG],
    ['Buffer', PSAMPR_DOMAIN_DISPLAY_USER_ARRAY],
  ];
}

export class SAMPR_DOMAIN_DISPLAY_MACHINE_BUFFER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', ULONG],
    ['Buffer', PSAMPR_DOMAIN_DISPLAY_MACHINE_ARRAY],
  ];
}

export class SAMPR_DOMAIN_DISPLAY_GROUP_BUFFER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', ULONG],
    ['Buffer', PSAMPR_DOMAIN_DISPLAY_GROUP_ARRAY],
  ];
}

export class SAMPR_DOMAIN_DISPLAY_OEM_USER_BUFFER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', ULONG],
    ['Buffer', PSAMPR_DOMAIN_DISPLAY_OEM_USER_ARRAY],
  ];
}

export class SAMPR_DOMAIN_DISPLAY_OEM_GROUP_BUFFER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', ULONG],
    ['Buffer', PSAMPR_DOMAIN_DISPLAY_OEM_GROUP_ARRAY],
  ];
}

export class DOMAIN_DISPLAY_INFORMATION extends NDRENUM {
  static enumItems: Record<number, string> = {
    1: 'DomainDisplayUser',
    2: 'DomainDisplayMachine',
    3: 'DomainDisplayGroup',
    4: 'DomainDisplayOemUser',
    5: 'DomainDisplayOemGroup',
  };
  static enumValues: Record<string, number> = {
    DomainDisplayUser: 1,
    DomainDisplayMachine: 2,
    DomainDisplayGroup: 3,
    DomainDisplayOemUser: 4,
    DomainDisplayOemGroup: 5,
  };
}

export class SAMPR_DISPLAY_INFO_BUFFER extends NDRUNION {
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['UserInformation', SAMPR_DOMAIN_DISPLAY_USER_BUFFER],
    2: ['MachineInformation', SAMPR_DOMAIN_DISPLAY_MACHINE_BUFFER],
    3: ['GroupInformation', SAMPR_DOMAIN_DISPLAY_GROUP_BUFFER],
    4: ['OemUserInformation', SAMPR_DOMAIN_DISPLAY_OEM_USER_BUFFER],
    5: ['OemGroupInformation', SAMPR_DOMAIN_DISPLAY_OEM_GROUP_BUFFER],
  };
}

export class SAM_VALIDATE_PASSWORD_HASH extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Length', ULONG],
    ['Hash', LPBYTE],
  ];
}

export class PSAM_VALIDATE_PASSWORD_HASH extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAM_VALIDATE_PASSWORD_HASH]];
}

export class SAM_VALIDATE_PERSISTED_FIELDS extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['PresentFields', ULONG],
    ['PasswordLastSet', LARGE_INTEGER],
    ['BadPasswordTime', LARGE_INTEGER],
    ['LockoutTime', LARGE_INTEGER],
    ['BadPasswordCount', ULONG],
    ['PasswordHistoryLength', ULONG],
    ['PasswordHistory', PSAM_VALIDATE_PASSWORD_HASH],
  ];
}

export class SAM_VALIDATE_VALIDATION_STATUS extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'SamValidateSuccess',
    1: 'SamValidatePasswordMustChange',
    2: 'SamValidateAccountLockedOut',
    3: 'SamValidatePasswordExpired',
    4: 'SamValidatePasswordIncorrect',
    5: 'SamValidatePasswordIsInHistory',
    6: 'SamValidatePasswordTooShort',
    7: 'SamValidatePasswordTooLong',
    8: 'SamValidatePasswordNotComplexEnough',
    9: 'SamValidatePasswordTooRecent',
    10: 'SamValidatePasswordFilterError',
  };
  static enumValues: Record<string, number> = {
    SamValidateSuccess: 0,
    SamValidatePasswordMustChange: 1,
    SamValidateAccountLockedOut: 2,
    SamValidatePasswordExpired: 3,
    SamValidatePasswordIncorrect: 4,
    SamValidatePasswordIsInHistory: 5,
    SamValidatePasswordTooShort: 6,
    SamValidatePasswordTooLong: 7,
    SamValidatePasswordNotComplexEnough: 8,
    SamValidatePasswordTooRecent: 9,
    SamValidatePasswordFilterError: 10,
  };
}

export class SAM_VALIDATE_STANDARD_OUTPUT_ARG extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ChangedPersistedFields', SAM_VALIDATE_PERSISTED_FIELDS],
    ['ValidationStatus', SAM_VALIDATE_VALIDATION_STATUS],
  ];
}

export class PSAM_VALIDATE_STANDARD_OUTPUT_ARG extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAM_VALIDATE_STANDARD_OUTPUT_ARG]];
}

export class SAM_VALIDATE_AUTHENTICATION_INPUT_ARG extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['InputPersistedFields', SAM_VALIDATE_PERSISTED_FIELDS],
    ['PasswordMatched', UCHAR],
  ];
}

export class SAM_VALIDATE_PASSWORD_CHANGE_INPUT_ARG extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['InputPersistedFields', SAM_VALIDATE_PERSISTED_FIELDS],
    ['ClearPassword', RPC_UNICODE_STRING],
    ['UserAccountName', RPC_UNICODE_STRING],
    ['HashedPassword', SAM_VALIDATE_PASSWORD_HASH],
    ['PasswordMatch', UCHAR],
  ];
}

export class SAM_VALIDATE_PASSWORD_RESET_INPUT_ARG extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['InputPersistedFields', SAM_VALIDATE_PERSISTED_FIELDS],
    ['ClearPassword', RPC_UNICODE_STRING],
    ['UserAccountName', RPC_UNICODE_STRING],
    ['HashedPassword', SAM_VALIDATE_PASSWORD_HASH],
    ['PasswordMustChangeAtNextLogon', UCHAR],
    ['ClearLockout', UCHAR],
  ];
}

export class PASSWORD_POLICY_VALIDATION_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    1: 'SamValidateAuthentication',
    2: 'SamValidatePasswordChange',
    3: 'SamValidatePasswordReset',
  };
  static enumValues: Record<string, number> = {
    SamValidateAuthentication: 1,
    SamValidatePasswordChange: 2,
    SamValidatePasswordReset: 3,
  };
}

export class SAM_VALIDATE_INPUT_ARG extends NDRUNION {
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['ValidateAuthenticationInput', SAM_VALIDATE_AUTHENTICATION_INPUT_ARG],
    2: ['ValidatePasswordChangeInput', SAM_VALIDATE_PASSWORD_CHANGE_INPUT_ARG],
    3: ['ValidatePasswordResetInput', SAM_VALIDATE_PASSWORD_RESET_INPUT_ARG],
  };
}

export class SAM_VALIDATE_OUTPUT_ARG extends NDRUNION {
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['ValidateAuthenticationOutput', SAM_VALIDATE_STANDARD_OUTPUT_ARG],
    2: ['ValidatePasswordChangeOutput', SAM_VALIDATE_STANDARD_OUTPUT_ARG],
    3: ['ValidatePasswordResetOutput', SAM_VALIDATE_STANDARD_OUTPUT_ARG],
  };
}

export class PSAM_VALIDATE_OUTPUT_ARG extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAM_VALIDATE_OUTPUT_ARG]];
}

export class USER_PROPERTIES extends Structure {
  static structure: FieldDescriptor[] = [
    ['Reserved1', '<L=0'],
    ['Length', '<L=0'],
    ['Reserved2', '<H=0'],
    ['Reserved3', '<H=0'],
    ['Reserved4', '96s=""'],
    ['PropertySignature', '<H=0x50'],
  ];
}

export function unpackUserProperties(
  data: Buffer,
): [USER_PROPERTIES, number, Buffer] {
  const userProperties = new USER_PROPERTIES(data);
  const propertyCountOffset = userProperties.length;
  const propertiesEnd = 12 + (userProperties.get('Length') as number);

  if (propertiesEnd < propertyCountOffset) {
    throw new Error('USER_PROPERTIES length shorter than the fixed header');
  }

  if (data.length <= propertiesEnd) {
    throw new Error('USER_PROPERTIES missing Reserved5');
  }

  if (propertiesEnd === propertyCountOffset) {
    userProperties.set('PropertyCount', 0);
    userProperties.set('Reserved5', data.subarray(propertiesEnd, propertiesEnd + 1));
    return [userProperties, 0, Buffer.alloc(0)];
  }

  if (data.length < propertyCountOffset + 2) {
    throw new Error('USER_PROPERTIES missing PropertyCount');
  }

  const propertyCount = data.readUInt16LE(propertyCountOffset);
  userProperties.set('PropertyCount', propertyCount);
  userProperties.set('Reserved5', data.subarray(propertiesEnd, propertiesEnd + 1));

  return [userProperties, propertyCount, data.subarray(propertyCountOffset + 2, propertiesEnd)];
}

export class USER_PROPERTY extends Structure {
  static structure: FieldDescriptor[] = [
    ['NameLength', '<H=0'],
    ['ValueLength', '<H=0'],
    ['Reserved', '<H=0'],
    ['_PropertyName', '_-PropertyName', "self['NameLength']"],
    ['PropertyName', ':'],
    ['_PropertyValue', '_-PropertyValue', "self['ValueLength']"],
    ['PropertyValue', ':'],
  ];
}

export class WDIGEST_CREDENTIALS extends Structure {
  static structure: FieldDescriptor[] = [
    ['Reserved1', 'B=0'],
    ['Reserved2', 'B=0'],
    ['Version', 'B=1'],
    ['NumberOfHashes', 'B=29'],
    ['Reserved3', '12s=""'],
    ['Hash1', '16s=""'],
    ['Hash2', '16s=""'],
    ['Hash3', '16s=""'],
    ['Hash4', '16s=""'],
    ['Hash5', '16s=""'],
    ['Hash6', '16s=""'],
    ['Hash7', '16s=""'],
    ['Hash8', '16s=""'],
    ['Hash9', '16s=""'],
    ['Hash10', '16s=""'],
    ['Hash11', '16s=""'],
    ['Hash12', '16s=""'],
    ['Hash13', '16s=""'],
    ['Hash14', '16s=""'],
    ['Hash15', '16s=""'],
    ['Hash16', '16s=""'],
    ['Hash17', '16s=""'],
    ['Hash18', '16s=""'],
    ['Hash19', '16s=""'],
    ['Hash20', '16s=""'],
    ['Hash21', '16s=""'],
    ['Hash22', '16s=""'],
    ['Hash23', '16s=""'],
    ['Hash24', '16s=""'],
    ['Hash25', '16s=""'],
    ['Hash26', '16s=""'],
    ['Hash27', '16s=""'],
    ['Hash28', '16s=""'],
    ['Hash29', '16s=""'],
  ];
}

export class KERB_KEY_DATA extends Structure {
  static structure: FieldDescriptor[] = [
    ['Reserved1', '<H=0'],
    ['Reserved2', '<H=0'],
    ['Reserved3', '<H=0'],
    ['KeyType', '<L=0'],
    ['KeyLength', '<L=0'],
    ['KeyOffset', '<L=0'],
  ];
}

export class KERB_STORED_CREDENTIAL extends Structure {
  static structure: FieldDescriptor[] = [
    ['Revision', '<H=3'],
    ['Flags', '<H=0'],
    ['CredentialCount', '<H=0'],
    ['OldCredentialCount', '<H=0'],
    ['DefaultSaltLength', '<H=0'],
    ['DefaultSaltMaximumLength', '<H=0'],
    ['DefaultSaltOffset', '<L=0'],
    ['Buffer', ':'],
  ];
}

export class KERB_KEY_DATA_NEW extends Structure {
  static structure: FieldDescriptor[] = [
    ['Reserved1', '<H=0'],
    ['Reserved2', '<H=0'],
    ['Reserved3', '<L=0'],
    ['IterationCount', '<L=0'],
    ['KeyType', '<L=0'],
    ['KeyLength', '<L=0'],
    ['KeyOffset', '<L=0'],
  ];
}

export class KERB_STORED_CREDENTIAL_NEW extends Structure {
  static structure: FieldDescriptor[] = [
    ['Revision', '<H=4'],
    ['Flags', '<H=0'],
    ['CredentialCount', '<H=0'],
    ['ServiceCredentialCount', '<H=0'],
    ['OldCredentialCount', '<H=0'],
    ['OlderCredentialCount', '<H=0'],
    ['DefaultSaltLength', '<H=0'],
    ['DefaultSaltMaximumLength', '<H=0'],
    ['DefaultSaltOffset', '<L=0'],
    ['DefaultIterationCount', '<L=0'],
    ['Buffer', ':'],
  ];
}

export class SamrConnectResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ServerHandle', SAMPR_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class SamrConnect extends NDRCALL {
  static opnum = 0;
  static structure: NDRField[] = [
    ['ServerName', PSAMPR_SERVER_NAME2],
    ['DesiredAccess', ULONG],
  ];
  static Response = SamrConnectResponse;
}

export class SamrCloseHandleResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['SamHandle', SAMPR_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class SamrCloseHandle extends NDRCALL {
  static opnum = 1;
  static structure: NDRField[] = [
    ['SamHandle', SAMPR_HANDLE],
    ['DesiredAccess', LONG],
  ];
  static Response = SamrCloseHandleResponse;
}

export class SamrSetSecurityObjectResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrSetSecurityObject extends NDRCALL {
  static opnum = 2;
  static structure: NDRField[] = [
    ['ObjectHandle', SAMPR_HANDLE],
    ['SecurityInformation', SECURITY_INFORMATION],
    ['SecurityDescriptor', SAMPR_SR_SECURITY_DESCRIPTOR],
  ];
  static Response = SamrSetSecurityObjectResponse;
}

export class SamrQuerySecurityObjectResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['SecurityDescriptor', PSAMPR_SR_SECURITY_DESCRIPTOR],
    ['ErrorCode', ULONG],
  ];
}

export class SamrQuerySecurityObject extends NDRCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['ObjectHandle', SAMPR_HANDLE],
    ['SecurityInformation', SECURITY_INFORMATION],
  ];
  static Response = SamrQuerySecurityObjectResponse;
}

export class SamrLookupDomainInSamServerResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['DomainId', PRPC_SID],
    ['ErrorCode', ULONG],
  ];
}

export class SamrLookupDomainInSamServer extends NDRCALL {
  static opnum = 5;
  static structure: NDRField[] = [
    ['ServerHandle', SAMPR_HANDLE],
    ['Name', RPC_UNICODE_STRING],
  ];
  static Response = SamrLookupDomainInSamServerResponse;
}

export class SamrEnumerateDomainsInSamServerResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['EnumerationContext', ULONG],
    ['Buffer', PSAMPR_ENUMERATION_BUFFER],
    ['CountReturned', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class SamrEnumerateDomainsInSamServer extends NDRCALL {
  static opnum = 6;
  static structure: NDRField[] = [
    ['ServerHandle', SAMPR_HANDLE],
    ['EnumerationContext', ULONG],
    ['PreferedMaximumLength', ULONG],
  ];
  static Response = SamrEnumerateDomainsInSamServerResponse;
}

export class SamrOpenDomainResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class SamrOpenDomain extends NDRCALL {
  static opnum = 7;
  static structure: NDRField[] = [
    ['ServerHandle', SAMPR_HANDLE],
    ['DesiredAccess', ULONG],
    ['DomainId', RPC_SID],
  ];
  static Response = SamrOpenDomainResponse;
}

export class SamrQueryInformationDomainResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Buffer', PSAMPR_DOMAIN_INFO_BUFFER],
    ['ErrorCode', ULONG],
  ];
}

export class SamrQueryInformationDomain extends NDRCALL {
  static opnum = 8;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['DomainInformationClass', DOMAIN_INFORMATION_CLASS],
  ];
  static Response = SamrQueryInformationDomainResponse;
}

export class SamrSetInformationDomainResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrSetInformationDomain extends NDRCALL {
  static opnum = 9;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['DomainInformationClass', DOMAIN_INFORMATION_CLASS],
    ['DomainInformation', SAMPR_DOMAIN_INFO_BUFFER],
  ];
  static Response = SamrSetInformationDomainResponse;
}

export class SamrCreateGroupInDomainResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['GroupHandle', SAMPR_HANDLE],
    ['RelativeId', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class SamrCreateGroupInDomain extends NDRCALL {
  static opnum = 10;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['Name', RPC_UNICODE_STRING],
    ['DesiredAccess', ULONG],
  ];
  static Response = SamrCreateGroupInDomainResponse;
}

export class SamrEnumerateGroupsInDomainResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['EnumerationContext', ULONG],
    ['Buffer', PSAMPR_ENUMERATION_BUFFER],
    ['CountReturned', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class SamrEnumerateGroupsInDomain extends NDRCALL {
  static opnum = 11;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['EnumerationContext', ULONG],
    ['PreferedMaximumLength', ULONG],
  ];
  static Response = SamrEnumerateGroupsInDomainResponse;
}

export class SamrCreateUserInDomainResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['UserHandle', SAMPR_HANDLE],
    ['RelativeId', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class SamrCreateUserInDomain extends NDRCALL {
  static opnum = 12;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['Name', RPC_UNICODE_STRING],
    ['DesiredAccess', ULONG],
  ];
  static Response = SamrCreateUserInDomainResponse;
}

export class SamrEnumerateUsersInDomainResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['EnumerationContext', ULONG],
    ['Buffer', PSAMPR_ENUMERATION_BUFFER],
    ['CountReturned', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class SamrEnumerateUsersInDomain extends NDRCALL {
  static opnum = 13;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['EnumerationContext', ULONG],
    ['UserAccountControl', ULONG],
    ['PreferedMaximumLength', ULONG],
  ];
  static Response = SamrEnumerateUsersInDomainResponse;
}

export class SamrCreateAliasInDomainResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['AliasHandle', SAMPR_HANDLE],
    ['RelativeId', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class SamrCreateAliasInDomain extends NDRCALL {
  static opnum = 14;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['AccountName', RPC_UNICODE_STRING],
    ['DesiredAccess', ULONG],
  ];
  static Response = SamrCreateAliasInDomainResponse;
}

export class SamrEnumerateAliasesInDomainResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['EnumerationContext', ULONG],
    ['Buffer', PSAMPR_ENUMERATION_BUFFER],
    ['CountReturned', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class SamrEnumerateAliasesInDomain extends NDRCALL {
  static opnum = 15;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['EnumerationContext', ULONG],
    ['PreferedMaximumLength', ULONG],
  ];
  static Response = SamrEnumerateAliasesInDomainResponse;
}

export class SamrGetAliasMembershipResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Membership', SAMPR_ULONG_ARRAY],
    ['ErrorCode', ULONG],
  ];
}

export class SamrGetAliasMembership extends NDRCALL {
  static opnum = 16;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['SidArray', SAMPR_PSID_ARRAY],
  ];
  static Response = SamrGetAliasMembershipResponse;
}

export class SamrLookupNamesInDomainResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['RelativeIds', SAMPR_ULONG_ARRAY],
    ['Use', SAMPR_ULONG_ARRAY],
    ['ErrorCode', ULONG],
  ];
}

export class SamrLookupNamesInDomain extends NDRCALL {
  static opnum = 17;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['Count', ULONG],
    ['Names', RPC_UNICODE_STRING_ARRAY],
  ];
  static Response = SamrLookupNamesInDomainResponse;
}

export class SamrLookupIdsInDomainResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Names', SAMPR_RETURNED_USTRING_ARRAY],
    ['Use', SAMPR_ULONG_ARRAY],
    ['ErrorCode', ULONG],
  ];
}

export class SamrLookupIdsInDomain extends NDRCALL {
  static opnum = 18;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['Count', ULONG],
    ['RelativeIds', ULONG_ARRAY_CV],
  ];
  static Response = SamrLookupIdsInDomainResponse;
}

export class SamrOpenGroupResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['GroupHandle', SAMPR_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class SamrOpenGroup extends NDRCALL {
  static opnum = 19;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['DesiredAccess', ULONG],
    ['GroupId', ULONG],
  ];
  static Response = SamrOpenGroupResponse;
}

export class SamrQueryInformationGroupResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Buffer', PSAMPR_GROUP_INFO_BUFFER],
    ['ErrorCode', ULONG],
  ];
}

export class SamrQueryInformationGroup extends NDRCALL {
  static opnum = 20;
  static structure: NDRField[] = [
    ['GroupHandle', SAMPR_HANDLE],
    ['GroupInformationClass', GROUP_INFORMATION_CLASS],
  ];
  static Response = SamrQueryInformationGroupResponse;
}

export class SamrSetInformationGroupResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrSetInformationGroup extends NDRCALL {
  static opnum = 21;
  static structure: NDRField[] = [
    ['GroupHandle', SAMPR_HANDLE],
    ['GroupInformationClass', GROUP_INFORMATION_CLASS],
    ['Buffer', SAMPR_GROUP_INFO_BUFFER],
  ];
  static Response = SamrSetInformationGroupResponse;
}

export class SamrAddMemberToGroupResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrAddMemberToGroup extends NDRCALL {
  static opnum = 22;
  static structure: NDRField[] = [
    ['GroupHandle', SAMPR_HANDLE],
    ['MemberId', ULONG],
    ['Attributes', ULONG],
  ];
  static Response = SamrAddMemberToGroupResponse;
}

export class SamrDeleteGroupResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['GroupHandle', SAMPR_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class SamrDeleteGroup extends NDRCALL {
  static opnum = 23;
  static structure: NDRField[] = [['GroupHandle', SAMPR_HANDLE]];
  static Response = SamrDeleteGroupResponse;
}

export class SamrRemoveMemberFromGroupResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrRemoveMemberFromGroup extends NDRCALL {
  static opnum = 24;
  static structure: NDRField[] = [
    ['GroupHandle', SAMPR_HANDLE],
    ['MemberId', ULONG],
  ];
  static Response = SamrRemoveMemberFromGroupResponse;
}

export class SamrGetMembersInGroupResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Members', PSAMPR_GET_MEMBERS_BUFFER],
    ['ErrorCode', ULONG],
  ];
}

export class SamrGetMembersInGroup extends NDRCALL {
  static opnum = 25;
  static structure: NDRField[] = [['GroupHandle', SAMPR_HANDLE]];
  static Response = SamrGetMembersInGroupResponse;
}

export class SamrSetMemberAttributesOfGroupResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrSetMemberAttributesOfGroup extends NDRCALL {
  static opnum = 26;
  static structure: NDRField[] = [
    ['GroupHandle', SAMPR_HANDLE],
    ['MemberId', ULONG],
    ['Attributes', ULONG],
  ];
  static Response = SamrSetMemberAttributesOfGroupResponse;
}

export class SamrOpenAliasResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['AliasHandle', SAMPR_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class SamrOpenAlias extends NDRCALL {
  static opnum = 27;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['DesiredAccess', ULONG],
    ['AliasId', ULONG],
  ];
  static Response = SamrOpenAliasResponse;
}

export class SamrQueryInformationAliasResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Buffer', PSAMPR_ALIAS_INFO_BUFFER],
    ['ErrorCode', ULONG],
  ];
}

export class SamrQueryInformationAlias extends NDRCALL {
  static opnum = 28;
  static structure: NDRField[] = [
    ['AliasHandle', SAMPR_HANDLE],
    ['AliasInformationClass', ALIAS_INFORMATION_CLASS],
  ];
  static Response = SamrQueryInformationAliasResponse;
}

export class SamrSetInformationAliasResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrSetInformationAlias extends NDRCALL {
  static opnum = 29;
  static structure: NDRField[] = [
    ['AliasHandle', SAMPR_HANDLE],
    ['AliasInformationClass', ALIAS_INFORMATION_CLASS],
    ['Buffer', SAMPR_ALIAS_INFO_BUFFER],
  ];
  static Response = SamrSetInformationAliasResponse;
}

export class SamrDeleteAliasResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['AliasHandle', SAMPR_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class SamrDeleteAlias extends NDRCALL {
  static opnum = 30;
  static structure: NDRField[] = [['AliasHandle', SAMPR_HANDLE]];
  static Response = SamrDeleteAliasResponse;
}

export class SamrAddMemberToAliasResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrAddMemberToAlias extends NDRCALL {
  static opnum = 31;
  static structure: NDRField[] = [
    ['AliasHandle', SAMPR_HANDLE],
    ['MemberId', RPC_SID],
  ];
  static Response = SamrAddMemberToAliasResponse;
}

export class SamrRemoveMemberFromAliasResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrRemoveMemberFromAlias extends NDRCALL {
  static opnum = 32;
  static structure: NDRField[] = [
    ['AliasHandle', SAMPR_HANDLE],
    ['MemberId', RPC_SID],
  ];
  static Response = SamrRemoveMemberFromAliasResponse;
}

export class SamrGetMembersInAliasResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Members', SAMPR_PSID_ARRAY_OUT],
    ['ErrorCode', ULONG],
  ];
}

export class SamrGetMembersInAlias extends NDRCALL {
  static opnum = 33;
  static structure: NDRField[] = [['AliasHandle', SAMPR_HANDLE]];
  static Response = SamrGetMembersInAliasResponse;
}

export class SamrOpenUserResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['UserHandle', SAMPR_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class SamrOpenUser extends NDRCALL {
  static opnum = 34;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['DesiredAccess', ULONG],
    ['UserId', ULONG],
  ];
  static Response = SamrOpenUserResponse;
}

export class SamrDeleteUserResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['UserHandle', SAMPR_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class SamrDeleteUser extends NDRCALL {
  static opnum = 35;
  static structure: NDRField[] = [['UserHandle', SAMPR_HANDLE]];
  static Response = SamrDeleteUserResponse;
}

export class SamrQueryInformationUserResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Buffer', PSAMPR_USER_INFO_BUFFER],
    ['ErrorCode', ULONG],
  ];
}

export class SamrQueryInformationUser extends NDRCALL {
  static opnum = 36;
  static structure: NDRField[] = [
    ['UserHandle', SAMPR_HANDLE],
    ['UserInformationClass', USER_INFORMATION_CLASS],
  ];
  static Response = SamrQueryInformationUserResponse;
}

export class SamrSetInformationUserResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrSetInformationUser extends NDRCALL {
  static opnum = 37;
  static structure: NDRField[] = [
    ['UserHandle', SAMPR_HANDLE],
    ['UserInformationClass', USER_INFORMATION_CLASS],
    ['Buffer', SAMPR_USER_INFO_BUFFER],
  ];
  static Response = SamrSetInformationUserResponse;
}

export class SamrChangePasswordUserResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrChangePasswordUser extends NDRCALL {
  static opnum = 38;
  static structure: NDRField[] = [
    ['UserHandle', SAMPR_HANDLE],
    ['LmPresent', UCHAR],
    ['OldLmEncryptedWithNewLm', PENCRYPTED_LM_OWF_PASSWORD],
    ['NewLmEncryptedWithOldLm', PENCRYPTED_LM_OWF_PASSWORD],
    ['NtPresent', UCHAR],
    ['OldNtEncryptedWithNewNt', PENCRYPTED_NT_OWF_PASSWORD],
    ['NewNtEncryptedWithOldNt', PENCRYPTED_NT_OWF_PASSWORD],
    ['NtCrossEncryptionPresent', UCHAR],
    ['NewNtEncryptedWithNewLm', PENCRYPTED_NT_OWF_PASSWORD],
    ['LmCrossEncryptionPresent', UCHAR],
    ['NewLmEncryptedWithNewNt', PENCRYPTED_NT_OWF_PASSWORD],
  ];
  static Response = SamrChangePasswordUserResponse;
}

export class SamrGetGroupsForUserResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Groups', PSAMPR_GET_GROUPS_BUFFER],
    ['ErrorCode', ULONG],
  ];
}

export class SamrGetGroupsForUser extends NDRCALL {
  static opnum = 39;
  static structure: NDRField[] = [['UserHandle', SAMPR_HANDLE]];
  static Response = SamrGetGroupsForUserResponse;
}

export class SamrQueryDisplayInformationResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['TotalAvailable', ULONG],
    ['TotalReturned', ULONG],
    ['Buffer', SAMPR_DISPLAY_INFO_BUFFER],
    ['ErrorCode', ULONG],
  ];
}

export class SamrQueryDisplayInformation extends NDRCALL {
  static opnum = 40;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION],
    ['Index', ULONG],
    ['EntryCount', ULONG],
    ['PreferredMaximumLength', ULONG],
  ];
  static Response = SamrQueryDisplayInformationResponse;
}

export class SamrGetDisplayEnumerationIndexResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Index', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class SamrGetDisplayEnumerationIndex extends NDRCALL {
  static opnum = 41;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION],
    ['Prefix', RPC_UNICODE_STRING],
  ];
  static Response = SamrGetDisplayEnumerationIndexResponse;
}

export class SamrGetUserDomainPasswordInformationResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['PasswordInformation', USER_DOMAIN_PASSWORD_INFORMATION],
    ['ErrorCode', ULONG],
  ];
}

export class SamrGetUserDomainPasswordInformation extends NDRCALL {
  static opnum = 44;
  static structure: NDRField[] = [['UserHandle', SAMPR_HANDLE]];
  static Response = SamrGetUserDomainPasswordInformationResponse;
}

export class SamrRemoveMemberFromForeignDomainResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrRemoveMemberFromForeignDomain extends NDRCALL {
  static opnum = 45;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['MemberSid', RPC_SID],
  ];
  static Response = SamrRemoveMemberFromForeignDomainResponse;
}

export class SamrQueryInformationDomain2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['Buffer', PSAMPR_DOMAIN_INFO_BUFFER],
    ['ErrorCode', ULONG],
  ];
}

export class SamrQueryInformationDomain2 extends NDRCALL {
  static opnum = 46;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['DomainInformationClass', DOMAIN_INFORMATION_CLASS],
  ];
  static Response = SamrQueryInformationDomain2Response;
}

export class SamrQueryInformationUser2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['Buffer', PSAMPR_USER_INFO_BUFFER],
    ['ErrorCode', ULONG],
  ];
}

export class SamrQueryInformationUser2 extends NDRCALL {
  static opnum = 47;
  static structure: NDRField[] = [
    ['UserHandle', SAMPR_HANDLE],
    ['UserInformationClass', USER_INFORMATION_CLASS],
  ];
  static Response = SamrQueryInformationUser2Response;
}

export class SamrQueryDisplayInformation2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['TotalAvailable', ULONG],
    ['TotalReturned', ULONG],
    ['Buffer', SAMPR_DISPLAY_INFO_BUFFER],
    ['ErrorCode', ULONG],
  ];
}

export class SamrQueryDisplayInformation2 extends NDRCALL {
  static opnum = 48;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION],
    ['Index', ULONG],
    ['EntryCount', ULONG],
    ['PreferredMaximumLength', ULONG],
  ];
  static Response = SamrQueryDisplayInformation2Response;
}

export class SamrGetDisplayEnumerationIndex2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['Index', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class SamrGetDisplayEnumerationIndex2 extends NDRCALL {
  static opnum = 49;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION],
    ['Prefix', RPC_UNICODE_STRING],
  ];
  static Response = SamrGetDisplayEnumerationIndex2Response;
}

export class SamrCreateUser2InDomainResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['UserHandle', SAMPR_HANDLE],
    ['GrantedAccess', ULONG],
    ['RelativeId', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class SamrCreateUser2InDomain extends NDRCALL {
  static opnum = 50;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['Name', RPC_UNICODE_STRING],
    ['AccountType', ULONG],
    ['DesiredAccess', ULONG],
  ];
  static Response = SamrCreateUser2InDomainResponse;
}

export class SamrQueryDisplayInformation3Response extends NDRCALL {
  static structure: NDRField[] = [
    ['TotalAvailable', ULONG],
    ['TotalReturned', ULONG],
    ['Buffer', SAMPR_DISPLAY_INFO_BUFFER],
    ['ErrorCode', ULONG],
  ];
}

export class SamrQueryDisplayInformation3 extends NDRCALL {
  static opnum = 51;
  static structure: NDRField[] = [
    ['DomainHandle', SAMPR_HANDLE],
    ['DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION],
    ['Index', ULONG],
    ['EntryCount', ULONG],
    ['PreferredMaximumLength', ULONG],
  ];
  static Response = SamrQueryDisplayInformation3Response;
}

export class SamrAddMultipleMembersToAliasResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrAddMultipleMembersToAlias extends NDRCALL {
  static opnum = 52;
  static structure: NDRField[] = [
    ['AliasHandle', SAMPR_HANDLE],
    ['MembersBuffer', SAMPR_PSID_ARRAY],
  ];
  static Response = SamrAddMultipleMembersToAliasResponse;
}

export class SamrRemoveMultipleMembersFromAliasResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrRemoveMultipleMembersFromAlias extends NDRCALL {
  static opnum = 53;
  static structure: NDRField[] = [
    ['AliasHandle', SAMPR_HANDLE],
    ['MembersBuffer', SAMPR_PSID_ARRAY],
  ];
  static Response = SamrRemoveMultipleMembersFromAliasResponse;
}

export class SamrOemChangePasswordUser2Response extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrOemChangePasswordUser2 extends NDRCALL {
  static opnum = 54;
  static structure: NDRField[] = [
    ['ServerName', PRPC_STRING],
    ['UserName', RPC_STRING],
    ['NewPasswordEncryptedWithOldLm', PSAMPR_ENCRYPTED_USER_PASSWORD],
    ['OldLmOwfPasswordEncryptedWithNewLm', PENCRYPTED_LM_OWF_PASSWORD],
  ];
  static Response = SamrOemChangePasswordUser2Response;
}

export class SamrUnicodeChangePasswordUser2Response extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrUnicodeChangePasswordUser2 extends NDRCALL {
  static opnum = 55;
  static structure: NDRField[] = [
    ['ServerName', PRPC_UNICODE_STRING],
    ['UserName', RPC_UNICODE_STRING],
    ['NewPasswordEncryptedWithOldNt', PSAMPR_ENCRYPTED_USER_PASSWORD],
    ['OldNtOwfPasswordEncryptedWithNewNt', PENCRYPTED_NT_OWF_PASSWORD],
    ['LmPresent', UCHAR],
    ['NewPasswordEncryptedWithOldLm', PSAMPR_ENCRYPTED_USER_PASSWORD],
    ['OldLmOwfPasswordEncryptedWithNewNt', PENCRYPTED_LM_OWF_PASSWORD],
  ];
  static Response = SamrUnicodeChangePasswordUser2Response;
}

export class SamrGetDomainPasswordInformationResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['PasswordInformation', USER_DOMAIN_PASSWORD_INFORMATION],
    ['ErrorCode', ULONG],
  ];
}

export class SamrGetDomainPasswordInformation extends NDRCALL {
  static opnum = 56;
  static structure: NDRField[] = [['Unused', PRPC_UNICODE_STRING]];
  static Response = SamrGetDomainPasswordInformationResponse;
}

export class SamrConnect2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['ServerHandle', SAMPR_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class SamrConnect2 extends NDRCALL {
  static opnum = 57;
  static structure: NDRField[] = [
    ['ServerName', PSamprServerName],
    ['DesiredAccess', ULONG],
  ];
  static Response = SamrConnect2Response;
}

export class SamrSetInformationUser2Response extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrSetInformationUser2 extends NDRCALL {
  static opnum = 58;
  static structure: NDRField[] = [
    ['UserHandle', SAMPR_HANDLE],
    ['UserInformationClass', USER_INFORMATION_CLASS],
    ['Buffer', SAMPR_USER_INFO_BUFFER],
  ];
  static Response = SamrSetInformationUser2Response;
}

export class SamrConnect4Response extends NDRCALL {
  static structure: NDRField[] = [
    ['ServerHandle', SAMPR_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class SamrConnect4 extends NDRCALL {
  static opnum = 62;
  static structure: NDRField[] = [
    ['ServerName', PSamprServerName],
    ['ClientRevision', ULONG],
    ['DesiredAccess', ULONG],
  ];
  static Response = SamrConnect4Response;
}

export class SamrConnect5Response extends NDRCALL {
  static structure: NDRField[] = [
    ['OutVersion', ULONG],
    ['OutRevisionInfo', SAMPR_REVISION_INFO],
    ['ServerHandle', SAMPR_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class SamrConnect5 extends NDRCALL {
  static opnum = 64;
  static structure: NDRField[] = [
    ['ServerName', PSamprServerName],
    ['DesiredAccess', ULONG],
    ['InVersion', ULONG],
    ['InRevisionInfo', SAMPR_REVISION_INFO],
  ];
  static Response = SamrConnect5Response;
}

export class SamrRidToSidResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Sid', PRPC_SID],
    ['ErrorCode', ULONG],
  ];
}

export class SamrRidToSid extends NDRCALL {
  static opnum = 65;
  static structure: NDRField[] = [
    ['ObjectHandle', SAMPR_HANDLE],
    ['Rid', ULONG],
  ];
  static Response = SamrRidToSidResponse;
}

export class SamrSetDSRMPasswordResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SamrSetDSRMPassword extends NDRCALL {
  static opnum = 66;
  static structure: NDRField[] = [
    ['Unused', PRPC_UNICODE_STRING],
    ['UserId', ULONG],
    ['EncryptedNtOwfPassword', PENCRYPTED_NT_OWF_PASSWORD],
  ];
  static Response = SamrSetDSRMPasswordResponse;
}

export class SamrValidatePasswordResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['OutputArg', PSAM_VALIDATE_OUTPUT_ARG],
    ['ErrorCode', ULONG],
  ];
}

export class SamrValidatePassword extends NDRCALL {
  static opnum = 67;
  static structure: NDRField[] = [
    ['ValidationType', PASSWORD_POLICY_VALIDATION_TYPE],
    ['InputArg', SAM_VALIDATE_INPUT_ARG],
  ];
  static Response = SamrValidatePasswordResponse;
}

const OPNUMS = {
  0: [SamrConnect, SamrConnectResponse] as const,
  1: [SamrCloseHandle, SamrCloseHandleResponse] as const,
  2: [SamrSetSecurityObject, SamrSetSecurityObjectResponse] as const,
  3: [SamrQuerySecurityObject, SamrQuerySecurityObjectResponse] as const,
  5: [SamrLookupDomainInSamServer, SamrLookupDomainInSamServerResponse] as const,
  6: [SamrEnumerateDomainsInSamServer, SamrEnumerateDomainsInSamServerResponse] as const,
  7: [SamrOpenDomain, SamrOpenDomainResponse] as const,
  8: [SamrQueryInformationDomain, SamrQueryInformationDomainResponse] as const,
  9: [SamrSetInformationDomain, SamrSetInformationDomainResponse] as const,
  10: [SamrCreateGroupInDomain, SamrCreateGroupInDomainResponse] as const,
  11: [SamrEnumerateGroupsInDomain, SamrEnumerateGroupsInDomainResponse] as const,
  12: [SamrCreateUserInDomain, SamrCreateUserInDomainResponse] as const,
  13: [SamrEnumerateUsersInDomain, SamrEnumerateUsersInDomainResponse] as const,
  14: [SamrCreateAliasInDomain, SamrCreateAliasInDomainResponse] as const,
  15: [SamrEnumerateAliasesInDomain, SamrEnumerateAliasesInDomainResponse] as const,
  16: [SamrGetAliasMembership, SamrGetAliasMembershipResponse] as const,
  17: [SamrLookupNamesInDomain, SamrLookupNamesInDomainResponse] as const,
  18: [SamrLookupIdsInDomain, SamrLookupIdsInDomainResponse] as const,
  19: [SamrOpenGroup, SamrOpenGroupResponse] as const,
  20: [SamrQueryInformationGroup, SamrQueryInformationGroupResponse] as const,
  21: [SamrSetInformationGroup, SamrSetInformationGroupResponse] as const,
  22: [SamrAddMemberToGroup, SamrAddMemberToGroupResponse] as const,
  23: [SamrDeleteGroup, SamrDeleteGroupResponse] as const,
  24: [SamrRemoveMemberFromGroup, SamrRemoveMemberFromGroupResponse] as const,
  25: [SamrGetMembersInGroup, SamrGetMembersInGroupResponse] as const,
  26: [SamrSetMemberAttributesOfGroup, SamrSetMemberAttributesOfGroupResponse] as const,
  27: [SamrOpenAlias, SamrOpenAliasResponse] as const,
  28: [SamrQueryInformationAlias, SamrQueryInformationAliasResponse] as const,
  29: [SamrSetInformationAlias, SamrSetInformationAliasResponse] as const,
  30: [SamrDeleteAlias, SamrDeleteAliasResponse] as const,
  31: [SamrAddMemberToAlias, SamrAddMemberToAliasResponse] as const,
  32: [SamrRemoveMemberFromAlias, SamrRemoveMemberFromAliasResponse] as const,
  33: [SamrGetMembersInAlias, SamrGetMembersInAliasResponse] as const,
  34: [SamrOpenUser, SamrOpenUserResponse] as const,
  35: [SamrDeleteUser, SamrDeleteUserResponse] as const,
  36: [SamrQueryInformationUser, SamrQueryInformationUserResponse] as const,
  37: [SamrSetInformationUser, SamrSetInformationUserResponse] as const,
  38: [SamrChangePasswordUser, SamrChangePasswordUserResponse] as const,
  39: [SamrGetGroupsForUser, SamrGetGroupsForUserResponse] as const,
  40: [SamrQueryDisplayInformation, SamrQueryDisplayInformationResponse] as const,
  41: [SamrGetDisplayEnumerationIndex, SamrGetDisplayEnumerationIndexResponse] as const,
  44: [SamrGetUserDomainPasswordInformation, SamrGetUserDomainPasswordInformationResponse] as const,
  45: [SamrRemoveMemberFromForeignDomain, SamrRemoveMemberFromForeignDomainResponse] as const,
  46: [SamrQueryInformationDomain2, SamrQueryInformationDomain2Response] as const,
  47: [SamrQueryInformationUser2, SamrQueryInformationUser2Response] as const,
  48: [SamrQueryDisplayInformation2, SamrQueryDisplayInformation2Response] as const,
  49: [SamrGetDisplayEnumerationIndex2, SamrGetDisplayEnumerationIndex2Response] as const,
  50: [SamrCreateUser2InDomain, SamrCreateUser2InDomainResponse] as const,
  51: [SamrQueryDisplayInformation3, SamrQueryDisplayInformation3Response] as const,
  52: [SamrAddMultipleMembersToAlias, SamrAddMultipleMembersToAliasResponse] as const,
  53: [SamrRemoveMultipleMembersFromAlias, SamrRemoveMultipleMembersFromAliasResponse] as const,
  54: [SamrOemChangePasswordUser2, SamrOemChangePasswordUser2Response] as const,
  55: [SamrUnicodeChangePasswordUser2, SamrUnicodeChangePasswordUser2Response] as const,
  56: [SamrGetDomainPasswordInformation, SamrGetDomainPasswordInformationResponse] as const,
  57: [SamrConnect2, SamrConnect2Response] as const,
  58: [SamrSetInformationUser2, SamrSetInformationUser2Response] as const,
  62: [SamrConnect4, SamrConnect4Response] as const,
  64: [SamrConnect5, SamrConnect5Response] as const,
  65: [SamrRidToSid, SamrRidToSidResponse] as const,
  66: [SamrSetDSRMPassword, SamrSetDSRMPasswordResponse] as const,
  67: [SamrValidatePassword, SamrValidatePasswordResponse] as const,
};

type DceRequestFn = <T>(req: unknown, uuid?: unknown, checkError?: boolean) => Promise<T>;

function toBuffer(hash: Buffer | string): Buffer {
  if (Buffer.isBuffer(hash)) return hash;
  try {
    return Buffer.from(hash, 'hex');
  } catch {
    return Buffer.from(hash);
  }
}

export async function hSamrConnect5(
  dce: DCERPC_v5,
  serverName: unknown = '\x00',
  desiredAccess: number = MAXIMUM_ALLOWED,
  inVersion = 1,
  revision = 3,
) {
  const request = new SamrConnect5();
  request.set('ServerName', serverName);
  request.set('DesiredAccess', desiredAccess);
  request.set('InVersion', inVersion);
  const inRevisionInfo = request.fields['InRevisionInfo'] as SAMPR_REVISION_INFO;
  inRevisionInfo.set('tag', inVersion);
  const v1 = inRevisionInfo.fields['V1'] as SAMPR_REVISION_INFO_V1;
  v1.set('Revision', revision);
  return (dce as unknown as { request: DceRequestFn }).request<SamrConnect5Response>(request);
}

export async function hSamrConnect4(
  dce: DCERPC_v5,
  serverName: unknown = '\x00',
  desiredAccess: number = MAXIMUM_ALLOWED,
  clientRevision = 2,
) {
  const request = new SamrConnect4();
  request.set('ServerName', serverName);
  request.set('DesiredAccess', desiredAccess);
  request.set('ClientRevision', clientRevision);
  return (dce as unknown as { request: DceRequestFn }).request<SamrConnect4Response>(request);
}

export async function hSamrConnect2(
  dce: DCERPC_v5,
  serverName: unknown = '\x00',
  desiredAccess: number = MAXIMUM_ALLOWED,
) {
  const request = new SamrConnect2();
  request.set('ServerName', serverName);
  request.set('DesiredAccess', desiredAccess);
  return (dce as unknown as { request: DceRequestFn }).request<SamrConnect2Response>(request);
}

export async function hSamrConnect(
  dce: DCERPC_v5,
  serverName: unknown = '\x00',
  desiredAccess: number = MAXIMUM_ALLOWED,
) {
  const request = new SamrConnect();
  request.set('ServerName', serverName);
  request.set('DesiredAccess', desiredAccess);
  return (dce as unknown as { request: DceRequestFn }).request<SamrConnectResponse>(request);
}

export async function hSamrOpenDomain(
  dce: DCERPC_v5,
  serverHandle: SAMPR_HANDLE,
  desiredAccess: number = MAXIMUM_ALLOWED,
  domainId: unknown = NULL,
) {
  const request = new SamrOpenDomain();
  request.set('ServerHandle', serverHandle);
  request.set('DesiredAccess', desiredAccess);
  request.set('DomainId', domainId);
  return (dce as unknown as { request: DceRequestFn }).request<SamrOpenDomainResponse>(request);
}

export async function hSamrOpenGroup(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  desiredAccess: number = MAXIMUM_ALLOWED,
  groupId = 0,
) {
  const request = new SamrOpenGroup();
  request.set('DomainHandle', domainHandle);
  request.set('DesiredAccess', desiredAccess);
  request.set('GroupId', groupId);
  return (dce as unknown as { request: DceRequestFn }).request<SamrOpenGroupResponse>(request);
}

export async function hSamrOpenAlias(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  desiredAccess: number = MAXIMUM_ALLOWED,
  aliasId = 0,
) {
  const request = new SamrOpenAlias();
  request.set('DomainHandle', domainHandle);
  request.set('DesiredAccess', desiredAccess);
  request.set('AliasId', aliasId);
  return (dce as unknown as { request: DceRequestFn }).request<SamrOpenAliasResponse>(request);
}

export async function hSamrOpenUser(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  desiredAccess: number = MAXIMUM_ALLOWED,
  userId = 0,
) {
  const request = new SamrOpenUser();
  request.set('DomainHandle', domainHandle);
  request.set('DesiredAccess', desiredAccess);
  request.set('UserId', userId);
  return (dce as unknown as { request: DceRequestFn }).request<SamrOpenUserResponse>(request);
}

export async function hSamrEnumerateDomainsInSamServer(
  dce: DCERPC_v5,
  serverHandle: SAMPR_HANDLE,
  enumerationContext = 0,
  preferedMaximumLength = 0xffffffff,
) {
  const request = new SamrEnumerateDomainsInSamServer();
  request.set('ServerHandle', serverHandle);
  request.set('EnumerationContext', enumerationContext);
  request.set('PreferedMaximumLength', preferedMaximumLength);
  try {
    return await (dce as unknown as { request: DceRequestFn }).request<SamrEnumerateDomainsInSamServerResponse>(
      request,
    );
  } catch (e: any) {
    if (e.error_code === 0x105 && e.packet) return e.packet as SamrEnumerateDomainsInSamServerResponse;
    throw e;
  }
}

export async function hSamrEnumerateGroupsInDomain(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  enumerationContext = 0,
  preferedMaximumLength = 0xffffffff,
) {
  const request = new SamrEnumerateGroupsInDomain();
  request.set('DomainHandle', domainHandle);
  request.set('EnumerationContext', enumerationContext);
  request.set('PreferedMaximumLength', preferedMaximumLength);
  return (dce as unknown as { request: DceRequestFn }).request<SamrEnumerateGroupsInDomainResponse>(
    request,
  );
}

export async function hSamrEnumerateAliasesInDomain(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  enumerationContext = 0,
  preferedMaximumLength = 0xffffffff,
) {
  const request = new SamrEnumerateAliasesInDomain();
  request.set('DomainHandle', domainHandle);
  request.set('EnumerationContext', enumerationContext);
  request.set('PreferedMaximumLength', preferedMaximumLength);
  return (dce as unknown as { request: DceRequestFn }).request<SamrEnumerateAliasesInDomainResponse>(
    request,
  );
}

export async function hSamrEnumerateUsersInDomain(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  userAccountControl: number = USER_NORMAL_ACCOUNT,
  enumerationContext = 0,
  preferedMaximumLength = 0xffffffff,
) {
  const request = new SamrEnumerateUsersInDomain();
  request.set('DomainHandle', domainHandle);
  request.set('UserAccountControl', userAccountControl);
  request.set('EnumerationContext', enumerationContext);
  request.set('PreferedMaximumLength', preferedMaximumLength);
  try {
    return await (dce as unknown as { request: DceRequestFn }).request<SamrEnumerateUsersInDomainResponse>(
      request,
    );
  } catch (e: any) {
    if (e.error_code === 0x105 && e.packet) return e.packet as SamrEnumerateUsersInDomainResponse;
    throw e;
  }
}

export async function hSamrQueryDisplayInformation3(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  displayInformationClass: number = DOMAIN_DISPLAY_INFORMATION.enumValues.DomainDisplayUser!,
  index = 0,
  entryCount = 0xffffffff,
  preferedMaximumLength = 0xffffffff,
) {
  const request = new SamrQueryDisplayInformation3();
  request.set('DomainHandle', domainHandle);
  request.set('DisplayInformationClass', displayInformationClass);
  request.set('Index', index);
  request.set('EntryCount', entryCount);
  request.set('PreferredMaximumLength', preferedMaximumLength);
  return (dce as unknown as { request: DceRequestFn }).request<SamrQueryDisplayInformation3Response>(
    request,
  );
}

export async function hSamrQueryDisplayInformation2(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  displayInformationClass: number = DOMAIN_DISPLAY_INFORMATION.enumValues.DomainDisplayUser!,
  index = 0,
  entryCount = 0xffffffff,
  preferedMaximumLength = 0xffffffff,
) {
  const request = new SamrQueryDisplayInformation2();
  request.set('DomainHandle', domainHandle);
  request.set('DisplayInformationClass', displayInformationClass);
  request.set('Index', index);
  request.set('EntryCount', entryCount);
  request.set('PreferredMaximumLength', preferedMaximumLength);
  return (dce as unknown as { request: DceRequestFn }).request<SamrQueryDisplayInformation2Response>(
    request,
  );
}

export async function hSamrQueryDisplayInformation(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  displayInformationClass: number = DOMAIN_DISPLAY_INFORMATION.enumValues.DomainDisplayUser!,
  index = 0,
  entryCount = 0xffffffff,
  preferedMaximumLength = 0xffffffff,
) {
  const request = new SamrQueryDisplayInformation();
  request.set('DomainHandle', domainHandle);
  request.set('DisplayInformationClass', displayInformationClass);
  request.set('Index', index);
  request.set('EntryCount', entryCount);
  request.set('PreferredMaximumLength', preferedMaximumLength);
  return (dce as unknown as { request: DceRequestFn }).request<SamrQueryDisplayInformationResponse>(
    request,
  );
}

export async function hSamrGetDisplayEnumerationIndex2(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  displayInformationClass: number = DOMAIN_DISPLAY_INFORMATION.enumValues.DomainDisplayUser!,
  prefix = '',
) {
  const request = new SamrGetDisplayEnumerationIndex2();
  request.set('DomainHandle', domainHandle);
  request.set('DisplayInformationClass', displayInformationClass);
  request.set('Prefix', prefix);
  return (dce as unknown as { request: DceRequestFn }).request<SamrGetDisplayEnumerationIndex2Response>(
    request,
  );
}

export async function hSamrGetDisplayEnumerationIndex(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  displayInformationClass: number = DOMAIN_DISPLAY_INFORMATION.enumValues.DomainDisplayUser!,
  prefix = '',
) {
  const request = new SamrGetDisplayEnumerationIndex();
  request.set('DomainHandle', domainHandle);
  request.set('DisplayInformationClass', displayInformationClass);
  request.set('Prefix', prefix);
  return (dce as unknown as { request: DceRequestFn }).request<SamrGetDisplayEnumerationIndexResponse>(
    request,
  );
}

export async function hSamrCreateGroupInDomain(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  name: unknown,
  desiredAccess: number = GROUP_ALL_ACCESS,
) {
  const request = new SamrCreateGroupInDomain();
  request.set('DomainHandle', domainHandle);
  request.set('Name', name);
  request.set('DesiredAccess', desiredAccess);
  return (dce as unknown as { request: DceRequestFn }).request<SamrCreateGroupInDomainResponse>(
    request,
  );
}

export async function hSamrCreateAliasInDomain(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  accountName: unknown,
  desiredAccess: number = GROUP_ALL_ACCESS,
) {
  const request = new SamrCreateAliasInDomain();
  request.set('DomainHandle', domainHandle);
  request.set('AccountName', accountName);
  request.set('DesiredAccess', desiredAccess);
  return (dce as unknown as { request: DceRequestFn }).request<SamrCreateAliasInDomainResponse>(
    request,
  );
}

export async function hSamrCreateUser2InDomain(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  name: unknown,
  accountType: number = USER_NORMAL_ACCOUNT,
  desiredAccess: number = GROUP_ALL_ACCESS,
) {
  const request = new SamrCreateUser2InDomain();
  request.set('DomainHandle', domainHandle);
  request.set('Name', name);
  request.set('AccountType', accountType);
  request.set('DesiredAccess', desiredAccess);
  try {
    return await (dce as unknown as { request: DceRequestFn }).request<SamrCreateUser2InDomainResponse>(
      request,
    );
  } catch (e) {
    const err = e as DCERPCSessionError;
    if (err.error_code === 0xc0000022) {
      throw new Error("Authenticating account doesn't have the right to create a new machine account!");
    } else if (err.error_code === 0xc00002e7) {
      throw new Error("Authenticating account's machine account quota exceeded!");
    } else if (err.error_code === 0xc0000062) {
      throw new Error("Account name not accepted, maybe the '$' at the end is missing?");
    }
    throw e;
  }
}

export async function hSamrCreateUserInDomain(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  name: unknown,
  desiredAccess: number = GROUP_ALL_ACCESS,
) {
  const request = new SamrCreateUserInDomain();
  request.set('DomainHandle', domainHandle);
  request.set('Name', name);
  request.set('DesiredAccess', desiredAccess);
  return (dce as unknown as { request: DceRequestFn }).request<SamrCreateUserInDomainResponse>(
    request,
  );
}

export async function hSamrQueryInformationDomain(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  domainInformationClass: number = DOMAIN_INFORMATION_CLASS.enumValues.DomainGeneralInformation2!,
) {
  const request = new SamrQueryInformationDomain();
  request.set('DomainHandle', domainHandle);
  request.set('DomainInformationClass', domainInformationClass);
  return (dce as unknown as { request: DceRequestFn }).request<SamrQueryInformationDomainResponse>(
    request,
  );
}

export async function hSamrQueryInformationDomain2(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  domainInformationClass: number = DOMAIN_INFORMATION_CLASS.enumValues.DomainGeneralInformation2!,
) {
  const request = new SamrQueryInformationDomain2();
  request.set('DomainHandle', domainHandle);
  request.set('DomainInformationClass', domainInformationClass);
  return (dce as unknown as { request: DceRequestFn }).request<SamrQueryInformationDomain2Response>(
    request,
  );
}

export async function hSamrQueryInformationGroup(
  dce: DCERPC_v5,
  groupHandle: SAMPR_HANDLE,
  groupInformationClass: number = GROUP_INFORMATION_CLASS.enumValues.GroupGeneralInformation!,
) {
  const request = new SamrQueryInformationGroup();
  request.set('GroupHandle', groupHandle);
  request.set('GroupInformationClass', groupInformationClass);
  return (dce as unknown as { request: DceRequestFn }).request<SamrQueryInformationGroupResponse>(
    request,
  );
}

export async function hSamrQueryInformationAlias(
  dce: DCERPC_v5,
  aliasHandle: SAMPR_HANDLE,
  aliasInformationClass: number = ALIAS_INFORMATION_CLASS.enumValues.AliasGeneralInformation!,
) {
  const request = new SamrQueryInformationAlias();
  request.set('AliasHandle', aliasHandle);
  request.set('AliasInformationClass', aliasInformationClass);
  return (dce as unknown as { request: DceRequestFn }).request<SamrQueryInformationAliasResponse>(
    request,
  );
}

export async function hSamrQueryInformationUser2(
  dce: DCERPC_v5,
  userHandle: SAMPR_HANDLE,
  userInformationClass: number = USER_INFORMATION_CLASS.enumValues.UserGeneralInformation!,
) {
  const request = new SamrQueryInformationUser2();
  request.set('UserHandle', userHandle);
  request.set('UserInformationClass', userInformationClass);
  return (dce as unknown as { request: DceRequestFn }).request<SamrQueryInformationUser2Response>(
    request,
  );
}

export async function hSamrQueryInformationUser(
  dce: DCERPC_v5,
  userHandle: SAMPR_HANDLE,
  userInformationClass: number = USER_INFORMATION_CLASS.enumValues.UserGeneralInformation!,
) {
  const request = new SamrQueryInformationUser();
  request.set('UserHandle', userHandle);
  request.set('UserInformationClass', userInformationClass);
  return (dce as unknown as { request: DceRequestFn }).request<SamrQueryInformationUserResponse>(
    request,
  );
}

export async function hSamrSetInformationDomain(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  domainInformation: SAMPR_DOMAIN_INFO_BUFFER,
) {
  const request = new SamrSetInformationDomain();
  request.set('DomainHandle', domainHandle);
  request.set('DomainInformationClass', domainInformation.get('tag') as number);
  request.set('DomainInformation', domainInformation);
  return (dce as unknown as { request: DceRequestFn }).request<SamrSetInformationDomainResponse>(
    request,
  );
}

export async function hSamrSetInformationGroup(
  dce: DCERPC_v5,
  groupHandle: SAMPR_HANDLE,
  buffer: SAMPR_GROUP_INFO_BUFFER,
) {
  const request = new SamrSetInformationGroup();
  request.set('GroupHandle', groupHandle);
  request.set('GroupInformationClass', buffer.get('tag') as number);
  request.set('Buffer', buffer);
  return (dce as unknown as { request: DceRequestFn }).request<SamrSetInformationGroupResponse>(
    request,
  );
}

export async function hSamrSetInformationAlias(
  dce: DCERPC_v5,
  aliasHandle: SAMPR_HANDLE,
  buffer: SAMPR_ALIAS_INFO_BUFFER,
) {
  const request = new SamrSetInformationAlias();
  request.set('AliasHandle', aliasHandle);
  request.set('AliasInformationClass', buffer.get('tag') as number);
  request.set('Buffer', buffer);
  return (dce as unknown as { request: DceRequestFn }).request<SamrSetInformationAliasResponse>(
    request,
  );
}

export async function hSamrSetInformationUser2(
  dce: DCERPC_v5,
  userHandle: SAMPR_HANDLE,
  buffer: SAMPR_USER_INFO_BUFFER,
) {
  const request = new SamrSetInformationUser2();
  request.set('UserHandle', userHandle);
  request.set('UserInformationClass', buffer.get('tag') as number);
  request.set('Buffer', buffer);
  return (dce as unknown as { request: DceRequestFn }).request<SamrSetInformationUser2Response>(
    request,
  );
}

export async function hSamrSetInformationUser(
  dce: DCERPC_v5,
  userHandle: SAMPR_HANDLE,
  buffer: SAMPR_USER_INFO_BUFFER,
) {
  const request = new SamrSetInformationUser();
  request.set('UserHandle', userHandle);
  request.set('UserInformationClass', buffer.get('tag') as number);
  request.set('Buffer', buffer);
  return (dce as unknown as { request: DceRequestFn }).request<SamrSetInformationUserResponse>(
    request,
  );
}

export async function hSamrDeleteGroup(dce: DCERPC_v5, groupHandle: SAMPR_HANDLE) {
  const request = new SamrDeleteGroup();
  request.set('GroupHandle', groupHandle);
  return (dce as unknown as { request: DceRequestFn }).request<SamrDeleteGroupResponse>(request);
}

export async function hSamrDeleteAlias(dce: DCERPC_v5, aliasHandle: SAMPR_HANDLE) {
  const request = new SamrDeleteAlias();
  request.set('AliasHandle', aliasHandle);
  return (dce as unknown as { request: DceRequestFn }).request<SamrDeleteAliasResponse>(request);
}

export async function hSamrDeleteUser(dce: DCERPC_v5, userHandle: SAMPR_HANDLE) {
  const request = new SamrDeleteUser();
  request.set('UserHandle', userHandle);
  return (dce as unknown as { request: DceRequestFn }).request<SamrDeleteUserResponse>(request);
}

export async function hSamrAddMemberToGroup(
  dce: DCERPC_v5,
  groupHandle: SAMPR_HANDLE,
  memberId: number,
  attributes: number,
) {
  const request = new SamrAddMemberToGroup();
  request.set('GroupHandle', groupHandle);
  request.set('MemberId', memberId);
  request.set('Attributes', attributes);
  return (dce as unknown as { request: DceRequestFn }).request<SamrAddMemberToGroupResponse>(request);
}

export async function hSamrRemoveMemberFromGroup(
  dce: DCERPC_v5,
  groupHandle: SAMPR_HANDLE,
  memberId: number,
) {
  const request = new SamrRemoveMemberFromGroup();
  request.set('GroupHandle', groupHandle);
  request.set('MemberId', memberId);
  return (dce as unknown as { request: DceRequestFn }).request<SamrRemoveMemberFromGroupResponse>(
    request,
  );
}

export async function hSamrGetMembersInGroup(dce: DCERPC_v5, groupHandle: SAMPR_HANDLE) {
  const request = new SamrGetMembersInGroup();
  request.set('GroupHandle', groupHandle);
  return (dce as unknown as { request: DceRequestFn }).request<SamrGetMembersInGroupResponse>(
    request,
  );
}

export async function hSamrAddMemberToAlias(
  dce: DCERPC_v5,
  aliasHandle: SAMPR_HANDLE,
  memberId: RPC_SID,
) {
  const request = new SamrAddMemberToAlias();
  request.set('AliasHandle', aliasHandle);
  request.set('MemberId', memberId);
  return (dce as unknown as { request: DceRequestFn }).request<SamrAddMemberToAliasResponse>(request);
}

export async function hSamrRemoveMemberFromAlias(
  dce: DCERPC_v5,
  aliasHandle: SAMPR_HANDLE,
  memberId: RPC_SID,
) {
  const request = new SamrRemoveMemberFromAlias();
  request.set('AliasHandle', aliasHandle);
  request.set('MemberId', memberId);
  return (dce as unknown as { request: DceRequestFn }).request<SamrRemoveMemberFromAliasResponse>(
    request,
  );
}

export async function hSamrGetMembersInAlias(dce: DCERPC_v5, aliasHandle: SAMPR_HANDLE) {
  const request = new SamrGetMembersInAlias();
  request.set('AliasHandle', aliasHandle);
  return (dce as unknown as { request: DceRequestFn }).request<SamrGetMembersInAliasResponse>(request);
}

export async function hSamrRemoveMemberFromForeignDomain(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  memberSid: RPC_SID,
) {
  const request = new SamrRemoveMemberFromForeignDomain();
  request.set('DomainHandle', domainHandle);
  request.set('MemberSid', memberSid);
  return (dce as unknown as { request: DceRequestFn }).request<SamrRemoveMemberFromForeignDomainResponse>(
    request,
  );
}

export async function hSamrAddMultipleMembersToAlias(
  dce: DCERPC_v5,
  aliasHandle: SAMPR_HANDLE,
  membersBuffer: SAMPR_PSID_ARRAY,
) {
  const request = new SamrAddMultipleMembersToAlias();
  request.set('AliasHandle', aliasHandle);
  request.set('MembersBuffer', membersBuffer);
  const sidsPtr = membersBuffer.fields['Sids'] as PSAMPR_SID_INFORMATION_ARRAY;
  const sidsArr = sidsPtr.fields['Data'] as SAMPR_SID_INFORMATION_ARRAY;
  const items = sidsArr.fields['Data'] as unknown[];
  membersBuffer.set('Count', items.length);
  return (dce as unknown as { request: DceRequestFn }).request<SamrAddMultipleMembersToAliasResponse>(
    request,
  );
}

export async function hSamrRemoveMultipleMembersFromAlias(
  dce: DCERPC_v5,
  aliasHandle: SAMPR_HANDLE,
  membersBuffer: SAMPR_PSID_ARRAY,
) {
  const request = new SamrRemoveMultipleMembersFromAlias();
  request.set('AliasHandle', aliasHandle);
  request.set('MembersBuffer', membersBuffer);
  const sidsPtr = membersBuffer.fields['Sids'] as PSAMPR_SID_INFORMATION_ARRAY;
  const sidsArr = sidsPtr.fields['Data'] as SAMPR_SID_INFORMATION_ARRAY;
  const items = sidsArr.fields['Data'] as unknown[];
  membersBuffer.set('Count', items.length);
  return (dce as unknown as { request: DceRequestFn }).request<SamrRemoveMultipleMembersFromAliasResponse>(
    request,
  );
}

export async function hSamrGetGroupsForUser(dce: DCERPC_v5, userHandle: SAMPR_HANDLE) {
  const request = new SamrGetGroupsForUser();
  request.set('UserHandle', userHandle);
  return (dce as unknown as { request: DceRequestFn }).request<SamrGetGroupsForUserResponse>(request);
}

export async function hSamrGetAliasMembership(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  sidArray: SAMPR_PSID_ARRAY,
) {
  const request = new SamrGetAliasMembership();
  request.set('DomainHandle', domainHandle);
  request.set('SidArray', sidArray);
  const sidsPtr = sidArray.fields['Sids'] as PSAMPR_SID_INFORMATION_ARRAY;
  const sidsArr = sidsPtr.fields['Data'] as SAMPR_SID_INFORMATION_ARRAY;
  const items = sidsArr.fields['Data'] as unknown[];
  sidArray.set('Count', items.length);
  return (dce as unknown as { request: DceRequestFn }).request<SamrGetAliasMembershipResponse>(request);
}

export async function hSamrChangePasswordUser(
  dce: DCERPC_v5,
  userHandle: SAMPR_HANDLE,
  oldPassword: string,
  newPassword: string,
  oldPwdHashNT: Buffer | string = '',
  newPwdHashLM: Buffer | string = '',
  newPwdHashNT: Buffer | string = '',
) {
  const request = new SamrChangePasswordUser();
  request.set('UserHandle', userHandle);

  let oldPwdHashNTBuf: Buffer;
  if (oldPwdHashNT === '') {
    oldPwdHashNTBuf = ntowfV1(oldPassword);
  } else {
    oldPwdHashNTBuf = toBuffer(oldPwdHashNT);
  }

  let newPwdHashLMBuf: Buffer;
  if (newPwdHashLM === '') {
    newPwdHashLMBuf = lmowfV1(newPassword);
  } else {
    newPwdHashLMBuf = toBuffer(newPwdHashLM);
  }

  let newPwdHashNTBuf: Buffer;
  if (newPwdHashNT === '') {
    newPwdHashNTBuf = ntowfV1(newPassword);
  } else {
    newPwdHashNTBuf = toBuffer(newPwdHashNT);
  }

  request.set('LmPresent', 0);
  request.set('OldLmEncryptedWithNewLm', NULL);
  request.set('NewLmEncryptedWithOldLm', NULL);
  request.set('NtPresent', 1);
  request.set('OldNtEncryptedWithNewNt', samEncryptNTLMHash(oldPwdHashNTBuf, newPwdHashNTBuf));
  request.set('NewNtEncryptedWithOldNt', samEncryptNTLMHash(newPwdHashNTBuf, oldPwdHashNTBuf));
  request.set('NtCrossEncryptionPresent', 0);
  request.set('NewNtEncryptedWithNewLm', NULL);
  request.set('LmCrossEncryptionPresent', 1);
  request.set('NewLmEncryptedWithNewNt', samEncryptNTLMHash(newPwdHashLMBuf, newPwdHashNTBuf));

  return (dce as unknown as { request: DceRequestFn }).request<SamrChangePasswordUserResponse>(request);
}

export async function hSamrUnicodeChangePasswordUser2(
  dce: DCERPC_v5,
  serverName: unknown = '\x00',
  userName: unknown = '',
  oldPassword = '',
  newPassword = '',
  oldPwdHashLM: Buffer | string = '',
  oldPwdHashNT: Buffer | string = '',
) {
  const request = new SamrUnicodeChangePasswordUser2();
  request.set('ServerName', serverName);
  request.set('UserName', userName);

  let oldPwdHashLMBuf: Buffer;
  let oldPwdHashNTBuf: Buffer;
  if (oldPwdHashLM === '' && oldPwdHashNT === '') {
    oldPwdHashLMBuf = lmowfV1(oldPassword);
    oldPwdHashNTBuf = ntowfV1(oldPassword);
  } else {
    oldPwdHashLMBuf = toBuffer(oldPwdHashLM);
    oldPwdHashNTBuf = toBuffer(oldPwdHashNT);
  }

  const newPwdHashNTBuf = ntowfV1(newPassword);

  const samUser = new SAMPR_USER_PASSWORD();
  const encodedPassword = Buffer.from(newPassword, 'utf-16le');
  samUser.set(
    'Buffer',
    Buffer.concat([Buffer.alloc(512 - encodedPassword.length, 0x41), encodedPassword]),
  );
  samUser.set('Length', encodedPassword.length);
  const pwdBuff = samUser.getData();

  const encBuf = rc4(oldPwdHashNTBuf, pwdBuff);
  const newPwdEnc = request.fields['NewPasswordEncryptedWithOldNt'] as PSAMPR_ENCRYPTED_USER_PASSWORD;
  const encData = newPwdEnc.fields['Data'] as SAMPR_ENCRYPTED_USER_PASSWORD;
  encData.set('Buffer', encBuf);
  request.set('OldNtOwfPasswordEncryptedWithNewNt', samEncryptNTLMHash(oldPwdHashNTBuf, newPwdHashNTBuf));
  request.set('LmPresent', 0);
  request.set('NewPasswordEncryptedWithOldLm', NULL);
  request.set('OldLmOwfPasswordEncryptedWithNewNt', NULL);

  return (dce as unknown as { request: DceRequestFn }).request<SamrUnicodeChangePasswordUser2Response>(
    request,
  );
}

export async function hSamrLookupDomainInSamServer(
  dce: DCERPC_v5,
  serverHandle: SAMPR_HANDLE,
  name: unknown,
) {
  const request = new SamrLookupDomainInSamServer();
  request.set('ServerHandle', serverHandle);
  request.set('Name', name);
  return (dce as unknown as { request: DceRequestFn }).request<SamrLookupDomainInSamServerResponse>(
    request,
  );
}

export async function hSamrSetSecurityObject(
  dce: DCERPC_v5,
  objectHandle: SAMPR_HANDLE,
  securityInformation: number,
  securityDescriptor: SAMPR_SR_SECURITY_DESCRIPTOR,
) {
  const request = new SamrSetSecurityObject();
  request.set('ObjectHandle', objectHandle);
  request.set('SecurityInformation', securityInformation);
  request.set('SecurityDescriptor', securityDescriptor);
  return (dce as unknown as { request: DceRequestFn }).request<SamrSetSecurityObjectResponse>(request);
}

export async function hSamrQuerySecurityObject(
  dce: DCERPC_v5,
  objectHandle: SAMPR_HANDLE,
  securityInformation: number,
) {
  const request = new SamrQuerySecurityObject();
  request.set('ObjectHandle', objectHandle);
  request.set('SecurityInformation', securityInformation);
  return (dce as unknown as { request: DceRequestFn }).request<SamrQuerySecurityObjectResponse>(request);
}

export async function hSamrCloseHandle(dce: DCERPC_v5, samHandle: SAMPR_HANDLE) {
  const request = new SamrCloseHandle();
  request.set('SamHandle', samHandle);
  return (dce as unknown as { request: DceRequestFn }).request<SamrCloseHandleResponse>(request);
}

export async function hSamrSetMemberAttributesOfGroup(
  dce: DCERPC_v5,
  groupHandle: SAMPR_HANDLE,
  memberId: number,
  attributes: number,
) {
  const request = new SamrSetMemberAttributesOfGroup();
  request.set('GroupHandle', groupHandle);
  request.set('MemberId', memberId);
  request.set('Attributes', attributes);
  return (dce as unknown as { request: DceRequestFn }).request<SamrSetMemberAttributesOfGroupResponse>(
    request,
  );
}

export async function hSamrGetUserDomainPasswordInformation(
  dce: DCERPC_v5,
  userHandle: SAMPR_HANDLE,
) {
  const request = new SamrGetUserDomainPasswordInformation();
  request.set('UserHandle', userHandle);
  return (dce as unknown as { request: DceRequestFn }).request<SamrGetUserDomainPasswordInformationResponse>(
    request,
  );
}

export async function hSamrGetDomainPasswordInformation(dce: DCERPC_v5) {
  const request = new SamrGetDomainPasswordInformation();
  request.set('Unused', NULL);
  return (dce as unknown as { request: DceRequestFn }).request<SamrGetDomainPasswordInformationResponse>(
    request,
  );
}

export async function hSamrRidToSid(dce: DCERPC_v5, objectHandle: SAMPR_HANDLE, rid: number) {
  const request = new SamrRidToSid();
  request.set('ObjectHandle', objectHandle);
  request.set('Rid', rid);
  return (dce as unknown as { request: DceRequestFn }).request<SamrRidToSidResponse>(request);
}

export async function hSamrValidatePassword(
  dce: DCERPC_v5,
  inputArg: SAM_VALIDATE_INPUT_ARG,
) {
  const request = new SamrValidatePassword();
  request.set('ValidationType', inputArg.get('tag') as number);
  request.set('InputArg', inputArg);
  return (dce as unknown as { request: DceRequestFn }).request<SamrValidatePasswordResponse>(request);
}

export async function hSamrLookupNamesInDomain(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  names: string[],
) {
  const request = new SamrLookupNamesInDomain();
  request.set('DomainHandle', domainHandle);
  request.set('Count', names.length);
  const namesArr = request.fields['Names'] as RPC_UNICODE_STRING_ARRAY;
  for (const name of names) {
    const itemn = new RPC_UNICODE_STRING();
    itemn.set('Data', name);
    (namesArr.fields['Data'] as unknown[]).push(itemn);
  }
  (request.fields['Names'] as RPC_UNICODE_STRING_ARRAY).fields['MaximumCount'] = 1000;
  return (dce as unknown as { request: DceRequestFn }).request<SamrLookupNamesInDomainResponse>(request);
}

export async function hSamrLookupIdsInDomain(
  dce: DCERPC_v5,
  domainHandle: SAMPR_HANDLE,
  ids: number[],
) {
  const request = new SamrLookupIdsInDomain();
  request.set('DomainHandle', domainHandle);
  request.set('Count', ids.length);
  const idsArr = request.fields['RelativeIds'] as ULONG_ARRAY_CV;
  for (const dId of ids) {
    const entry = new (ULONG_ARRAY_CV.item as unknown as new () => NDRSTRUCT)();
    entry.set('Data', dId);
    (idsArr.fields['Data'] as unknown[]).push(entry);
  }
  (request.fields['RelativeIds'] as ULONG_ARRAY_CV).fields['MaximumCount'] = 1000;
  return (dce as unknown as { request: DceRequestFn }).request<SamrLookupIdsInDomainResponse>(request);
}

type SessionKeyProvider = () => Buffer;

export async function hSamrSetPasswordInternal4New(
  dce: DCERPC_v5,
  userHandle: SAMPR_HANDLE,
  password: string,
) {
  const request = new SamrSetInformationUser2();
  request.set('UserHandle', userHandle);
  request.set('UserInformationClass', USER_INFORMATION_CLASS.enumValues.UserInternal4InformationNew);
  const buffer = request.fields['Buffer'] as SAMPR_USER_INFO_BUFFER;
  buffer.set('tag', USER_INFORMATION_CLASS.enumValues.UserInternal4InformationNew);
  const internal4New = buffer.fields['Internal4New'] as SAMPR_USER_INTERNAL4_INFORMATION_NEW;
  const i1 = internal4New.fields['I1'] as SAMPR_USER_ALL_INFORMATION;
  i1.set('WhichFields', 0x01000000 | 0x08000000);
  i1.set('UserName', NULL);
  i1.set('FullName', NULL);
  i1.set('HomeDirectory', NULL);
  i1.set('HomeDirectoryDrive', NULL);
  i1.set('ScriptPath', NULL);
  i1.set('ProfilePath', NULL);
  i1.set('AdminComment', NULL);
  i1.set('WorkStations', NULL);
  i1.set('UserComment', NULL);
  i1.set('Parameters', NULL);
  const lmOwf = i1.fields['LmOwfPassword'] as RPC_SHORT_BLOB;
  lmOwf.set('Buffer', NULL);
  const ntOwf = i1.fields['NtOwfPassword'] as RPC_SHORT_BLOB;
  ntOwf.set('Buffer', NULL);
  i1.set('PrivateData', NULL);
  const secDesc = i1.fields['SecurityDescriptor'] as SAMPR_SR_SECURITY_DESCRIPTOR;
  secDesc.set('SecurityDescriptor', NULL);
  const logonHours = i1.fields['LogonHours'] as SAMPR_LOGON_HOURS;
  logonHours.set('LogonHours', NULL);
  i1.set('PasswordExpired', 1);

  const pwdbuff = Buffer.from(password, 'utf-16le');
  const bufflen = pwdbuff.length;
  const padded = Buffer.concat([Buffer.alloc(512 - bufflen, 0), pwdbuff]);
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32LE(bufflen);
  const fullBuff = Buffer.concat([padded, lenBuf]);
  const salt = randomBytes(16);
  const sessionKey = (dce as any).getRpcTransport().getSmbConnection().getSessionKey();
  const key = createHash('md5').update(salt).update(sessionKey).digest();
  const bufferCrypt = Buffer.concat([rc4(key, fullBuff), salt]);
  const userPassword = internal4New.fields['UserPassword'] as SAMPR_ENCRYPTED_USER_PASSWORD_NEW;
  userPassword.set('Buffer', bufferCrypt);

  return (dce as unknown as { request: DceRequestFn }).request<SamrSetInformationUser2Response>(request);
}

export async function hSamrSetNTInternal1(
  dce: DCERPC_v5,
  userHandle: SAMPR_HANDLE,
  password: string,
  hashNT: Buffer | string = '',
) {
  const request = new SamrSetInformationUser();
  request.set('UserHandle', userHandle);
  request.set('UserInformationClass', USER_INFORMATION_CLASS.enumValues.UserInternal1Information);
  const buffer = request.fields['Buffer'] as SAMPR_USER_INFO_BUFFER;
  buffer.set('tag', USER_INFORMATION_CLASS.enumValues.UserInternal1Information);

  let hashNTBuf: Buffer;
  if (hashNT === '') {
    hashNTBuf = ntowfV1(password);
  } else {
    hashNTBuf = toBuffer(hashNT);
  }

  const sessionKey = (dce as unknown as { getRpcTransport: () => { getSmbConnection: () => { getSessionKey: SessionKeyProvider } } })
    .getRpcTransport()
    .getSmbConnection()
    .getSessionKey();

  const internal1 = buffer.fields['Internal1'] as SAMPR_USER_INTERNAL1_INFORMATION;
  internal1.set('EncryptedNtOwfPassword', samEncryptNTLMHash(hashNTBuf, sessionKey));
  internal1.set('EncryptedLmOwfPassword', NULL);
  internal1.set('NtPasswordPresent', 1);
  internal1.set('LmPasswordPresent', 0);

  return (dce as unknown as { request: DceRequestFn }).request<SamrSetInformationUserResponse>(request);
}
