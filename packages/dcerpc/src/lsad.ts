import { Buffer } from 'node:buffer';
import {
  NDRCALL,
  NDRENUM,
  NDRUNION,
  NDRUniConformantVaryingArray,
  NDRPOINTER,
  NDR,
  NDRSTRUCT,
  NDRUniConformantArray,
  NDRField,
  NULL,
} from './ndr';
import {
  DWORD,
  LPWSTR,
  STR,
  LUID,
  LONG,
  ULONG,
  RPC_UNICODE_STRING,
  PRPC_SID,
  LPBYTE,
  LARGE_INTEGER,
  NTSTATUS,
  RPC_SID,
  ACCESS_MASK,
  UCHAR,
  PRPC_UNICODE_STRING,
  PLARGE_INTEGER,
  USHORT,
  SECURITY_INFORMATION,
  MAXIMUM_ALLOWED,
  GUID,
  SECURITY_DESCRIPTOR,
  OWNER_SECURITY_INFORMATION,
} from './dtypes';
import { DCERPCException } from './rpcrt';
import { uuidtupToBin } from '@impacket/uuid';

export const MSRPC_UUID_LSAD = uuidtupToBin(['12345778-1234-ABCD-EF00-0123456789AB', '0.0'])!;

export class LSAD_DCERPCSessionError extends DCERPCException {}

export const POLICY_VIEW_LOCAL_INFORMATION = 0x00000001;
export const POLICY_VIEW_AUDIT_INFORMATION = 0x00000002;
export const POLICY_GET_PRIVATE_INFORMATION = 0x00000004;
export const POLICY_TRUST_ADMIN = 0x00000008;
export const POLICY_CREATE_ACCOUNT = 0x00000010;
export const POLICY_CREATE_SECRET = 0x00000020;
export const POLICY_CREATE_PRIVILEGE = 0x00000040;
export const POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080;
export const POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100;
export const POLICY_AUDIT_LOG_ADMIN = 0x00000200;
export const POLICY_SERVER_ADMIN = 0x00000400;
export const LSAD_POLICY_LOOKUP_NAMES = 0x00000800;
export const POLICY_NOTIFICATION = 0x00001000;

export const ACCOUNT_VIEW = 0x00000001;
export const ACCOUNT_ADJUST_PRIVILEGES = 0x00000002;
export const ACCOUNT_ADJUST_QUOTAS = 0x00000004;
export const ACCOUNT_ADJUST_SYSTEM_ACCESS = 0x00000008;

export const SECRET_SET_VALUE = 0x00000001;
export const SECRET_QUERY_VALUE = 0x00000002;

export const TRUSTED_QUERY_DOMAIN_NAME = 0x00000001;
export const TRUSTED_QUERY_CONTROLLERS = 0x00000002;
export const TRUSTED_SET_CONTROLLERS = 0x00000004;
export const TRUSTED_QUERY_POSIX = 0x00000008;
export const TRUSTED_SET_POSIX = 0x00000010;
export const TRUSTED_SET_AUTH = 0x00000020;
export const TRUSTED_QUERY_AUTH = 0x00000040;

export const POLICY_MODE_INTERACTIVE = 0x00000001;
export const POLICY_MODE_NETWORK = 0x00000002;
export const POLICY_MODE_BATCH = 0x00000004;
export const POLICY_MODE_SERVICE = 0x00000010;
export const POLICY_MODE_DENY_INTERACTIVE = 0x00000040;
export const POLICY_MODE_DENY_NETWORK = 0x00000080;
export const POLICY_MODE_DENY_BATCH = 0x00000100;
export const POLICY_MODE_DENY_SERVICE = 0x00000200;
export const POLICY_MODE_REMOTE_INTERACTIVE = 0x00000400;
export const POLICY_MODE_DENY_REMOTE_INTERACTIVE = 0x00000800;
export const POLICY_MODE_ALL = 0x00000ff7;
export const POLICY_MODE_ALL_NT4 = 0x00000037;

export const POLICY_AUDIT_EVENT_UNCHANGED = 0x00000000;
export const POLICY_AUDIT_EVENT_NONE = 0x00000004;
export const POLICY_AUDIT_EVENT_SUCCESS = 0x00000001;
export const POLICY_AUDIT_EVENT_FAILURE = 0x00000002;

export const POLICY_KERBEROS_VALIDATE_CLIENT = 0x00000080;

export const LSA_TLN_DISABLED_NEW = 0x00000001;
export const LSA_TLN_DISABLED_ADMIN = 0x00000002;
export const LSA_TLN_DISABLED_CONFLICT = 0x00000004;
export const LSA_SID_DISABLED_ADMIN = 0x00000001;
export const LSA_SID_DISABLED_CONFLICT = 0x00000002;
export const LSA_NB_DISABLED_ADMIN = 0x00000004;
export const LSA_NB_DISABLED_CONFLICT = 0x00000008;
export const LSA_FTRECORD_DISABLED_REASONS = 0x0000ffff;

export class LSAPR_HANDLE extends NDRSTRUCT {
  static align = 1;
  static structure: NDRField[] = [['Data', '20s=""']];
}

export const LSA_UNICODE_STRING = RPC_UNICODE_STRING;

export class STRING extends NDRSTRUCT {
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

  set(key: string, value: unknown): void {
    if (key === 'Data') {
      this.fields['MaximumLength'] = null;
      this.fields['Length'] = null;
    }
    super.set(key, value);
  }
}

export class LSAPR_ACL extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['AclRevision', UCHAR],
    ['Sbz1', UCHAR],
    ['AclSize', USHORT],
    ['Dummy1', NDRUniConformantArray],
  ];
}

export const LSAPR_SECURITY_DESCRIPTOR = SECURITY_DESCRIPTOR;

export class PLSAPR_SECURITY_DESCRIPTOR extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LSAPR_SECURITY_DESCRIPTOR]];
}

export class SECURITY_IMPERSONATION_LEVEL extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'SecurityAnonymous',
    1: 'SecurityIdentification',
    2: 'SecurityImpersonation',
    3: 'SecurityDelegation',
  };
  static enumValues: Record<string, number> = {
    SecurityAnonymous: 0,
    SecurityIdentification: 1,
    SecurityImpersonation: 2,
    SecurityDelegation: 3,
  };
}

export const SECURITY_CONTEXT_TRACKING_MODE = UCHAR;

export class SECURITY_QUALITY_OF_SERVICE extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Length', DWORD],
    ['ImpersonationLevel', SECURITY_IMPERSONATION_LEVEL],
    ['ContextTrackingMode', SECURITY_CONTEXT_TRACKING_MODE],
    ['EffectiveOnly', UCHAR],
  ];
}

export class PSECURITY_QUALITY_OF_SERVICE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SECURITY_QUALITY_OF_SERVICE]];
}

export class LSAPR_OBJECT_ATTRIBUTES extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Length', DWORD],
    ['RootDirectory', LPWSTR],
    ['ObjectName', LPWSTR],
    ['Attributes', DWORD],
    ['SecurityDescriptor', PLSAPR_SECURITY_DESCRIPTOR],
    ['SecurityQualityOfService', PSECURITY_QUALITY_OF_SERVICE],
  ];
}

export class LSAPR_SR_SECURITY_DESCRIPTOR extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Length', DWORD],
    ['SecurityDescriptor', LPBYTE],
  ];
}

export class PLSAPR_SR_SECURITY_DESCRIPTOR extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LSAPR_SR_SECURITY_DESCRIPTOR]];
}

export const SECURITY_DESCRIPTOR_CONTROL = ULONG;

export class POLICY_INFORMATION_CLASS extends NDRENUM {
  static enumItems: Record<number, string> = {
    1: 'PolicyAuditLogInformation',
    2: 'PolicyAuditEventsInformation',
    3: 'PolicyPrimaryDomainInformation',
    4: 'PolicyPdAccountInformation',
    5: 'PolicyAccountDomainInformation',
    6: 'PolicyLsaServerRoleInformation',
    7: 'PolicyReplicaSourceInformation',
    8: 'PolicyInformationNotUsedOnWire',
    9: 'PolicyModificationInformation',
    10: 'PolicyAuditFullSetInformation',
    11: 'PolicyAuditFullQueryInformation',
    12: 'PolicyDnsDomainInformation',
    13: 'PolicyDnsDomainInformationInt',
    14: 'PolicyLocalAccountDomainInformation',
    15: 'PolicyLastEntry',
  };
  static enumValues: Record<string, number> = {
    PolicyAuditLogInformation: 1,
    PolicyAuditEventsInformation: 2,
    PolicyPrimaryDomainInformation: 3,
    PolicyPdAccountInformation: 4,
    PolicyAccountDomainInformation: 5,
    PolicyLsaServerRoleInformation: 6,
    PolicyReplicaSourceInformation: 7,
    PolicyInformationNotUsedOnWire: 8,
    PolicyModificationInformation: 9,
    PolicyAuditFullSetInformation: 10,
    PolicyAuditFullQueryInformation: 11,
    PolicyDnsDomainInformation: 12,
    PolicyDnsDomainInformationInt: 13,
    PolicyLocalAccountDomainInformation: 14,
    PolicyLastEntry: 15,
  };
}

export class POLICY_AUDIT_LOG_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['AuditLogPercentFull', DWORD],
    ['MaximumLogSize', DWORD],
    ['AuditRetentionPeriod', LARGE_INTEGER],
    ['AuditLogFullShutdownInProgress', UCHAR],
    ['TimeToShutdown', LARGE_INTEGER],
    ['NextAuditRecordId', DWORD],
  ];
}

export class LSAD_DWORD_ARRAY extends NDRUniConformantArray {
  static item = DWORD;
}

export class PDWORD_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LSAD_DWORD_ARRAY]];
}

export class LSAPR_POLICY_AUDIT_EVENTS_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['AuditingMode', UCHAR],
    ['EventAuditingOptions', PDWORD_ARRAY],
    ['MaximumAuditEventCount', DWORD],
  ];
}

export class LSAPR_POLICY_PRIMARY_DOM_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Name', RPC_UNICODE_STRING],
    ['Sid', PRPC_SID],
  ];
}

export class LSAPR_POLICY_ACCOUNT_DOM_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['DomainName', RPC_UNICODE_STRING],
    ['DomainSid', PRPC_SID],
  ];
}

export class LSAPR_POLICY_PD_ACCOUNT_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [['Name', RPC_UNICODE_STRING]];
}

export class POLICY_LSA_SERVER_ROLE extends NDRENUM {
  static enumItems: Record<number, string> = {
    2: 'PolicyServerRoleBackup',
    3: 'PolicyServerRolePrimary',
  };
  static enumValues: Record<string, number> = {
    PolicyServerRoleBackup: 2,
    PolicyServerRolePrimary: 3,
  };
}

export class POLICY_LSA_SERVER_ROLE_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [['LsaServerRole', POLICY_LSA_SERVER_ROLE]];
}

export class LSAPR_POLICY_REPLICA_SRCE_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ReplicaSource', RPC_UNICODE_STRING],
    ['ReplicaAccountName', RPC_UNICODE_STRING],
  ];
}

export class POLICY_MODIFICATION_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ModifiedId', LARGE_INTEGER],
    ['DatabaseCreationTime', LARGE_INTEGER],
  ];
}

export class POLICY_AUDIT_FULL_SET_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [['ShutDownOnFull', UCHAR]];
}

export class POLICY_AUDIT_FULL_QUERY_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ShutDownOnFull', UCHAR],
    ['LogIsFull', UCHAR],
  ];
}

export class LSAPR_POLICY_DNS_DOMAIN_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Name', RPC_UNICODE_STRING],
    ['DnsDomainName', RPC_UNICODE_STRING],
    ['DnsForestName', RPC_UNICODE_STRING],
    ['DomainGuid', GUID],
    ['Sid', PRPC_SID],
  ];
}

export class LSAPR_POLICY_INFORMATION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['PolicyAuditLogInfo', POLICY_AUDIT_LOG_INFO],
    2: ['PolicyAuditEventsInfo', LSAPR_POLICY_AUDIT_EVENTS_INFO],
    3: ['PolicyPrimaryDomainInfo', LSAPR_POLICY_PRIMARY_DOM_INFO],
    4: ['PolicyPdAccountInfo', LSAPR_POLICY_PD_ACCOUNT_INFO],
    5: ['PolicyAccountDomainInfo', LSAPR_POLICY_ACCOUNT_DOM_INFO],
    6: ['PolicyServerRoleInfo', POLICY_LSA_SERVER_ROLE_INFO],
    7: ['PolicyReplicaSourceInfo', LSAPR_POLICY_REPLICA_SRCE_INFO],
    9: ['PolicyModificationInfo', POLICY_MODIFICATION_INFO],
    10: ['PolicyAuditFullSetInfo', POLICY_AUDIT_FULL_SET_INFO],
    11: ['PolicyAuditFullQueryInfo', POLICY_AUDIT_FULL_QUERY_INFO],
    12: ['PolicyDnsDomainInfo', LSAPR_POLICY_DNS_DOMAIN_INFO],
    13: ['PolicyDnsDomainInfoInt', LSAPR_POLICY_DNS_DOMAIN_INFO],
    14: ['PolicyLocalAccountDomainInfo', LSAPR_POLICY_ACCOUNT_DOM_INFO],
  };
}

export class PLSAPR_POLICY_INFORMATION extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LSAPR_POLICY_INFORMATION]];
}

export class POLICY_DOMAIN_INFORMATION_CLASS extends NDRENUM {
  static enumItems: Record<number, string> = {
    1: 'PolicyDomainQualityOfServiceInformation',
    2: 'PolicyDomainEfsInformation',
    3: 'PolicyDomainKerberosTicketInformation',
  };
  static enumValues: Record<string, number> = {
    PolicyDomainQualityOfServiceInformation: 1,
    PolicyDomainEfsInformation: 2,
    PolicyDomainKerberosTicketInformation: 3,
  };
}

export class POLICY_DOMAIN_QUALITY_OF_SERVICE_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [['QualityOfService', DWORD]];
}

export class LSAPR_POLICY_DOMAIN_EFS_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['InfoLength', DWORD],
    ['EfsBlob', LPBYTE],
  ];
}

export class POLICY_DOMAIN_KERBEROS_TICKET_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['AuthenticationOptions', DWORD],
    ['MaxServiceTicketAge', LARGE_INTEGER],
    ['MaxTicketAge', LARGE_INTEGER],
    ['MaxRenewAge', LARGE_INTEGER],
    ['MaxClockSkew', LARGE_INTEGER],
    ['Reserved', LARGE_INTEGER],
  ];
}

export class LSAPR_POLICY_DOMAIN_INFORMATION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['PolicyDomainQualityOfServiceInfo', POLICY_DOMAIN_QUALITY_OF_SERVICE_INFO],
    2: ['PolicyDomainEfsInfo', LSAPR_POLICY_DOMAIN_EFS_INFO],
    3: ['PolicyDomainKerbTicketInfo', POLICY_DOMAIN_KERBEROS_TICKET_INFO],
  };
}

export class PLSAPR_POLICY_DOMAIN_INFORMATION extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LSAPR_POLICY_DOMAIN_INFORMATION]];
}

export class POLICY_AUDIT_EVENT_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'AuditCategorySystem',
    1: 'AuditCategoryLogon',
    2: 'AuditCategoryObjectAccess',
    3: 'AuditCategoryPrivilegeUse',
    4: 'AuditCategoryDetailedTracking',
    5: 'AuditCategoryPolicyChange',
    6: 'AuditCategoryAccountManagement',
    7: 'AuditCategoryDirectoryServiceAccess',
    8: 'AuditCategoryAccountLogon',
  };
  static enumValues: Record<string, number> = {
    AuditCategorySystem: 0,
    AuditCategoryLogon: 1,
    AuditCategoryObjectAccess: 2,
    AuditCategoryPrivilegeUse: 3,
    AuditCategoryDetailedTracking: 4,
    AuditCategoryPolicyChange: 5,
    AuditCategoryAccountManagement: 6,
    AuditCategoryDirectoryServiceAccess: 7,
    AuditCategoryAccountLogon: 8,
  };
}

export class LSAPR_ACCOUNT_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['Sid', PRPC_SID]];
}

export class LSAPR_ACCOUNT_INFORMATION_ARRAY extends NDRUniConformantArray {
  static item = LSAPR_ACCOUNT_INFORMATION;
}

export class PLSAPR_ACCOUNT_INFORMATION_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LSAPR_ACCOUNT_INFORMATION_ARRAY]];
}

export class LSAPR_ACCOUNT_ENUM_BUFFER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', ULONG],
    ['Information', PLSAPR_ACCOUNT_INFORMATION_ARRAY],
  ];
}

export class LSAD_RPC_UNICODE_STRING_ARRAY extends NDRUniConformantArray {
  static item = RPC_UNICODE_STRING;
}

export class LSAD_PRPC_UNICODE_STRING_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LSAD_RPC_UNICODE_STRING_ARRAY]];
}

export class LSAPR_USER_RIGHT_SET extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', ULONG],
    ['UserRights', LSAD_PRPC_UNICODE_STRING_ARRAY],
  ];
}

export class LSAPR_LUID_AND_ATTRIBUTES extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Luid', LUID],
    ['Attributes', ULONG],
  ];
}

export class LSAPR_LUID_AND_ATTRIBUTES_ARRAY extends NDRUniConformantArray {
  static item = LSAPR_LUID_AND_ATTRIBUTES;
}

export class LSAPR_PRIVILEGE_SET extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['PrivilegeCount', ULONG],
    ['Control', ULONG],
    ['Privilege', LSAPR_LUID_AND_ATTRIBUTES_ARRAY],
  ];
}

export class PLSAPR_PRIVILEGE_SET extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LSAPR_PRIVILEGE_SET]];
}

export class LSAD_PCHAR_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NDRUniConformantVaryingArray]];
}

export class LSAPR_CR_CIPHER_VALUE extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Length', LONG],
    ['MaximumLength', LONG],
    ['Buffer', LSAD_PCHAR_ARRAY],
  ];
}

export class PLSAPR_CR_CIPHER_VALUE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LSAPR_CR_CIPHER_VALUE]];
}

export class PPLSAPR_CR_CIPHER_VALUE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', PLSAPR_CR_CIPHER_VALUE]];
}

export class LSAPR_TRUST_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Name', RPC_UNICODE_STRING],
    ['Sid', PRPC_SID],
  ];
}

export class TRUSTED_INFORMATION_CLASS extends NDRENUM {
  static enumItems: Record<number, string> = {
    1: 'TrustedDomainNameInformation',
    2: 'TrustedControllersInformation',
    3: 'TrustedPosixOffsetInformation',
    4: 'TrustedPasswordInformation',
    5: 'TrustedDomainInformationBasic',
    6: 'TrustedDomainInformationEx',
    7: 'TrustedDomainAuthInformation',
    8: 'TrustedDomainFullInformation',
    9: 'TrustedDomainAuthInformationInternal',
    10: 'TrustedDomainFullInformationInternal',
    11: 'TrustedDomainInformationEx2Internal',
    12: 'TrustedDomainFullInformation2Internal',
    13: 'TrustedDomainSupportedEncryptionTypes',
  };
  static enumValues: Record<string, number> = {
    TrustedDomainNameInformation: 1,
    TrustedControllersInformation: 2,
    TrustedPosixOffsetInformation: 3,
    TrustedPasswordInformation: 4,
    TrustedDomainInformationBasic: 5,
    TrustedDomainInformationEx: 6,
    TrustedDomainAuthInformation: 7,
    TrustedDomainFullInformation: 8,
    TrustedDomainAuthInformationInternal: 9,
    TrustedDomainFullInformationInternal: 10,
    TrustedDomainInformationEx2Internal: 11,
    TrustedDomainFullInformation2Internal: 12,
    TrustedDomainSupportedEncryptionTypes: 13,
  };
}

export class LSAPR_TRUSTED_DOMAIN_NAME_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [['Name', RPC_UNICODE_STRING]];
}

export class LSAPR_TRUSTED_CONTROLLERS_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Entries', ULONG],
    ['Names', LSAD_PRPC_UNICODE_STRING_ARRAY],
  ];
}

export class TRUSTED_POSIX_OFFSET_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [['Offset', ULONG]];
}

export class LSAPR_TRUSTED_PASSWORD_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Password', PLSAPR_CR_CIPHER_VALUE],
    ['OldPassword', PLSAPR_CR_CIPHER_VALUE],
  ];
}

export const LSAPR_TRUSTED_DOMAIN_INFORMATION_BASIC = LSAPR_TRUST_INFORMATION;

export class LSAPR_TRUSTED_DOMAIN_INFORMATION_EX extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Name', RPC_UNICODE_STRING],
    ['FlatName', RPC_UNICODE_STRING],
    ['Sid', PRPC_SID],
    ['TrustDirection', ULONG],
    ['TrustType', ULONG],
    ['TrustAttributes', ULONG],
  ];
}

export class LSAPR_TRUSTED_DOMAIN_INFORMATION_EX2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Name', RPC_UNICODE_STRING],
    ['FlatName', RPC_UNICODE_STRING],
    ['Sid', PRPC_SID],
    ['TrustDirection', ULONG],
    ['TrustType', ULONG],
    ['TrustAttributes', ULONG],
    ['ForestTrustLength', ULONG],
    ['ForestTrustInfo', LPBYTE],
  ];
}

export class LSAPR_AUTH_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['LastUpdateTime', LARGE_INTEGER],
    ['AuthType', ULONG],
    ['AuthInfoLength', ULONG],
    ['AuthInfo', LPBYTE],
  ];
}

export class PLSAPR_AUTH_INFORMATION extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LSAPR_AUTH_INFORMATION]];
}

export class LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['IncomingAuthInfos', ULONG],
    ['IncomingAuthenticationInformation', PLSAPR_AUTH_INFORMATION],
    ['IncomingPreviousAuthenticationInformation', PLSAPR_AUTH_INFORMATION],
    ['OutgoingAuthInfos', ULONG],
    ['OutgoingAuthenticationInformation', PLSAPR_AUTH_INFORMATION],
    ['OutgoingPreviousAuthenticationInformation', PLSAPR_AUTH_INFORMATION],
  ];
}

export class LSAPR_TRUSTED_DOMAIN_AUTH_BLOB extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['AuthSize', ULONG],
    ['AuthBlob', LPBYTE],
  ];
}

export class LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION_INTERNAL extends NDRSTRUCT {
  static structure: NDRField[] = [['AuthBlob', LSAPR_TRUSTED_DOMAIN_AUTH_BLOB]];
}

export class LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Information', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX],
    ['PosixOffset', TRUSTED_POSIX_OFFSET_INFO],
    ['AuthInformation', LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION],
  ];
}

export class LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION_INTERNAL extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Information', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX],
    ['PosixOffset', TRUSTED_POSIX_OFFSET_INFO],
    ['AuthInformation', LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION_INTERNAL],
  ];
}

export class LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Information', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX],
    ['PosixOffset', TRUSTED_POSIX_OFFSET_INFO],
    ['AuthInformation', LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION],
  ];
}

export class TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES extends NDRSTRUCT {
  static structure: NDRField[] = [['SupportedEncryptionTypes', ULONG]];
}

export class LSAPR_TRUSTED_DOMAIN_INFO extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['TrustedDomainNameInfo', LSAPR_TRUSTED_DOMAIN_NAME_INFO],
    2: ['TrustedControllersInfo', LSAPR_TRUSTED_CONTROLLERS_INFO],
    3: ['TrustedPosixOffsetInfo', TRUSTED_POSIX_OFFSET_INFO],
    4: ['TrustedPasswordInfo', LSAPR_TRUSTED_PASSWORD_INFO],
    5: ['TrustedDomainInfoBasic', LSAPR_TRUSTED_DOMAIN_INFORMATION_BASIC],
    6: ['TrustedDomainInfoEx', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX],
    7: ['TrustedAuthInfo', LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION],
    8: ['TrustedFullInfo', LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION],
    9: ['TrustedAuthInfoInternal', LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION_INTERNAL],
    10: ['TrustedFullInfoInternal', LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION_INTERNAL],
    11: ['TrustedDomainInfoEx2', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX2],
    12: ['TrustedFullInfo2', LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION2],
    13: ['TrustedDomainSETs', TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES],
  };
}

export class LSAPR_TRUST_INFORMATION_ARRAY extends NDRUniConformantArray {
  static item = LSAPR_TRUST_INFORMATION;
}

export class PLSAPR_TRUST_INFORMATION_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LSAPR_TRUST_INFORMATION_ARRAY]];
}

export class LSAPR_TRUSTED_ENUM_BUFFER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Entries', ULONG],
    ['Information', PLSAPR_TRUST_INFORMATION_ARRAY],
  ];
}

export class LSAPR_TRUSTED_DOMAIN_INFORMATION_EX_ARRAY extends NDRUniConformantArray {
  static item = LSAPR_TRUSTED_DOMAIN_INFORMATION_EX;
}

export class PLSAPR_TRUSTED_DOMAIN_INFORMATION_EX_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX_ARRAY]];
}

export class LSAPR_TRUSTED_ENUM_BUFFER_EX extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Entries', ULONG],
    ['EnumerationBuffer', PLSAPR_TRUSTED_DOMAIN_INFORMATION_EX_ARRAY],
  ];
}

export class LSA_FOREST_TRUST_RECORD_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'ForestTrustTopLevelName',
    1: 'ForestTrustTopLevelNameEx',
    2: 'ForestTrustDomainInfo',
  };
  static enumValues: Record<string, number> = {
    ForestTrustTopLevelName: 0,
    ForestTrustTopLevelNameEx: 1,
    ForestTrustDomainInfo: 2,
  };
}

export class LSA_FOREST_TRUST_DOMAIN_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Sid', PRPC_SID],
    ['DnsName', LSA_UNICODE_STRING],
    ['NetbiosName', LSA_UNICODE_STRING],
  ];
}

export class LSA_FOREST_TRUST_DATA_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    0: ['TopLevelName', LSA_UNICODE_STRING],
    1: ['TopLevelName', LSA_UNICODE_STRING],
    2: ['DomainInfo', LSA_FOREST_TRUST_DOMAIN_INFO],
  };
}

export class LSA_FOREST_TRUST_RECORD extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Flags', ULONG],
    ['ForestTrustType', LSA_FOREST_TRUST_RECORD_TYPE],
    ['Time', LARGE_INTEGER],
    ['ForestTrustData', LSA_FOREST_TRUST_DATA_UNION],
  ];
}

export class PLSA_FOREST_TRUST_RECORD extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LSA_FOREST_TRUST_RECORD]];
}

export class LSA_FOREST_TRUST_BINARY_DATA extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Length', ULONG],
    ['Buffer', LPBYTE],
  ];
}

export class LSA_FOREST_TRUST_RECORD_ARRAY extends NDRUniConformantArray {
  static item = PLSA_FOREST_TRUST_RECORD;
}

export class PLSA_FOREST_TRUST_RECORD_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LSA_FOREST_TRUST_RECORD_ARRAY]];
}

export class LSA_FOREST_TRUST_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['RecordCount', ULONG],
    ['Entries', PLSA_FOREST_TRUST_RECORD_ARRAY],
  ];
}

export class PLSA_FOREST_TRUST_INFORMATION extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LSA_FOREST_TRUST_INFORMATION]];
}

export class LSA_FOREST_TRUST_COLLISION_RECORD_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'CollisionTdo',
    1: 'CollisionXref',
    2: 'CollisionOther',
  };
  static enumValues: Record<string, number> = {
    CollisionTdo: 0,
    CollisionXref: 1,
    CollisionOther: 2,
  };
}

export class LSA_FOREST_TRUST_COLLISION_RECORD extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Index', ULONG],
    ['Type', LSA_FOREST_TRUST_COLLISION_RECORD_TYPE],
    ['Flags', ULONG],
    ['Name', LSA_UNICODE_STRING],
  ];
}

export class LSAPR_POLICY_PRIVILEGE_DEF extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Name', RPC_UNICODE_STRING],
    ['LocalValue', LUID],
  ];
}

export class LSAPR_POLICY_PRIVILEGE_DEF_ARRAY extends NDRUniConformantArray {
  static item = LSAPR_POLICY_PRIVILEGE_DEF;
}

export class PLSAPR_POLICY_PRIVILEGE_DEF_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LSAPR_POLICY_PRIVILEGE_DEF_ARRAY]];
}

export class LSAPR_PRIVILEGE_ENUM_BUFFER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Entries', ULONG],
    ['Privileges', PLSAPR_POLICY_PRIVILEGE_DEF_ARRAY],
  ];
}

// RPC CALLS

// Opnum 44
export class LsarOpenPolicy2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarOpenPolicy2 extends NDRCALL {
  static opnum = 44;
  static Response = LsarOpenPolicy2Response;
  static structure: NDRField[] = [
    ['SystemName', LPWSTR],
    ['ObjectAttributes', LSAPR_OBJECT_ATTRIBUTES],
    ['DesiredAccess', ACCESS_MASK],
  ];
}

// Opnum 6
export class LsarOpenPolicyResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarOpenPolicy extends NDRCALL {
  static opnum = 6;
  static Response = LsarOpenPolicyResponse;
  static structure: NDRField[] = [
    ['SystemName', LPWSTR],
    ['ObjectAttributes', LSAPR_OBJECT_ATTRIBUTES],
    ['DesiredAccess', ACCESS_MASK],
  ];
}

// Opnum 46
export class LsarQueryInformationPolicy2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['PolicyInformation', PLSAPR_POLICY_INFORMATION],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarQueryInformationPolicy2 extends NDRCALL {
  static opnum = 46;
  static Response = LsarQueryInformationPolicy2Response;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['InformationClass', POLICY_INFORMATION_CLASS],
  ];
}

// Opnum 7
export class LsarQueryInformationPolicyResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['PolicyInformation', PLSAPR_POLICY_INFORMATION],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarQueryInformationPolicy extends NDRCALL {
  static opnum = 7;
  static Response = LsarQueryInformationPolicyResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['InformationClass', POLICY_INFORMATION_CLASS],
  ];
}

// Opnum 47
export class LsarSetInformationPolicy2Response extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', NTSTATUS]];
}

export class LsarSetInformationPolicy2 extends NDRCALL {
  static opnum = 47;
  static Response = LsarSetInformationPolicy2Response;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['InformationClass', POLICY_INFORMATION_CLASS],
    ['PolicyInformation', LSAPR_POLICY_INFORMATION],
  ];
}

// Opnum 8
export class LsarSetInformationPolicyResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', NTSTATUS]];
}

export class LsarSetInformationPolicy extends NDRCALL {
  static opnum = 8;
  static Response = LsarSetInformationPolicyResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['InformationClass', POLICY_INFORMATION_CLASS],
    ['PolicyInformation', LSAPR_POLICY_INFORMATION],
  ];
}

// Opnum 53
export class LsarQueryDomainInformationPolicyResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['PolicyDomainInformation', PLSAPR_POLICY_DOMAIN_INFORMATION],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarQueryDomainInformationPolicy extends NDRCALL {
  static opnum = 53;
  static Response = LsarQueryDomainInformationPolicyResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['InformationClass', POLICY_DOMAIN_INFORMATION_CLASS],
  ];
}

// Opnum 10
export class LsarCreateAccountResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['AccountHandle', LSAPR_HANDLE],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarCreateAccount extends NDRCALL {
  static opnum = 10;
  static Response = LsarCreateAccountResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['AccountSid', RPC_SID],
    ['DesiredAccess', ACCESS_MASK],
  ];
}

// Opnum 11
export class LsarEnumerateAccountsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['EnumerationContext', ULONG],
    ['EnumerationBuffer', LSAPR_ACCOUNT_ENUM_BUFFER],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarEnumerateAccounts extends NDRCALL {
  static opnum = 11;
  static Response = LsarEnumerateAccountsResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['EnumerationContext', ULONG],
    ['PreferedMaximumLength', ULONG],
  ];
}

// Opnum 17
export class LsarOpenAccountResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['AccountHandle', LSAPR_HANDLE],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarOpenAccount extends NDRCALL {
  static opnum = 17;
  static Response = LsarOpenAccountResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['AccountSid', RPC_SID],
    ['DesiredAccess', ACCESS_MASK],
  ];
}

// Opnum 18
export class LsarEnumeratePrivilegesAccountResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Privileges', PLSAPR_PRIVILEGE_SET],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarEnumeratePrivilegesAccount extends NDRCALL {
  static opnum = 18;
  static Response = LsarEnumeratePrivilegesAccountResponse;
  static structure: NDRField[] = [['AccountHandle', LSAPR_HANDLE]];
}

// Opnum 19
export class LsarAddPrivilegesToAccountResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', NTSTATUS]];
}

export class LsarAddPrivilegesToAccount extends NDRCALL {
  static opnum = 19;
  static Response = LsarAddPrivilegesToAccountResponse;
  static structure: NDRField[] = [
    ['AccountHandle', LSAPR_HANDLE],
    ['Privileges', LSAPR_PRIVILEGE_SET],
  ];
}

// Opnum 20
export class LsarRemovePrivilegesFromAccountResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', NTSTATUS]];
}

export class LsarRemovePrivilegesFromAccount extends NDRCALL {
  static opnum = 20;
  static Response = LsarRemovePrivilegesFromAccountResponse;
  static structure: NDRField[] = [
    ['AccountHandle', LSAPR_HANDLE],
    ['AllPrivileges', UCHAR],
    ['Privileges', PLSAPR_PRIVILEGE_SET],
  ];
}

// Opnum 23
export class LsarGetSystemAccessAccountResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['SystemAccess', ULONG],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarGetSystemAccessAccount extends NDRCALL {
  static opnum = 23;
  static Response = LsarGetSystemAccessAccountResponse;
  static structure: NDRField[] = [['AccountHandle', LSAPR_HANDLE]];
}

// Opnum 24
export class LsarSetSystemAccessAccountResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', NTSTATUS]];
}

export class LsarSetSystemAccessAccount extends NDRCALL {
  static opnum = 24;
  static Response = LsarSetSystemAccessAccountResponse;
  static structure: NDRField[] = [
    ['AccountHandle', LSAPR_HANDLE],
    ['SystemAccess', ULONG],
  ];
}

// Opnum 35
export class LsarEnumerateAccountsWithUserRightResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['EnumerationBuffer', LSAPR_ACCOUNT_ENUM_BUFFER],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarEnumerateAccountsWithUserRight extends NDRCALL {
  static opnum = 35;
  static Response = LsarEnumerateAccountsWithUserRightResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['UserRight', PRPC_UNICODE_STRING],
  ];
}

// Opnum 36
export class LsarEnumerateAccountRightsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['UserRights', LSAPR_USER_RIGHT_SET],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarEnumerateAccountRights extends NDRCALL {
  static opnum = 36;
  static Response = LsarEnumerateAccountRightsResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['AccountSid', RPC_SID],
  ];
}

// Opnum 37
export class LsarAddAccountRightsResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', NTSTATUS]];
}

export class LsarAddAccountRights extends NDRCALL {
  static opnum = 37;
  static Response = LsarAddAccountRightsResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['AccountSid', RPC_SID],
    ['UserRights', LSAPR_USER_RIGHT_SET],
  ];
}

// Opnum 38
export class LsarRemoveAccountRightsResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', NTSTATUS]];
}

export class LsarRemoveAccountRights extends NDRCALL {
  static opnum = 38;
  static Response = LsarRemoveAccountRightsResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['AccountSid', RPC_SID],
    ['AllRights', UCHAR],
    ['UserRights', LSAPR_USER_RIGHT_SET],
  ];
}

// Opnum 16
export class LsarCreateSecretResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['SecretHandle', LSAPR_HANDLE],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarCreateSecret extends NDRCALL {
  static opnum = 16;
  static Response = LsarCreateSecretResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['SecretName', RPC_UNICODE_STRING],
    ['DesiredAccess', ACCESS_MASK],
  ];
}

// Opnum 28
export class LsarOpenSecretResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['SecretHandle', LSAPR_HANDLE],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarOpenSecret extends NDRCALL {
  static opnum = 28;
  static Response = LsarOpenSecretResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['SecretName', RPC_UNICODE_STRING],
    ['DesiredAccess', ACCESS_MASK],
  ];
}

// Opnum 29
export class LsarSetSecretResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', NTSTATUS]];
}

export class LsarSetSecret extends NDRCALL {
  static opnum = 29;
  static Response = LsarSetSecretResponse;
  static structure: NDRField[] = [
    ['SecretHandle', LSAPR_HANDLE],
    ['EncryptedCurrentValue', PLSAPR_CR_CIPHER_VALUE],
    ['EncryptedOldValue', PLSAPR_CR_CIPHER_VALUE],
  ];
}

// Opnum 30
export class LsarQuerySecretResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['EncryptedCurrentValue', PPLSAPR_CR_CIPHER_VALUE],
    ['CurrentValueSetTime', PLARGE_INTEGER],
    ['EncryptedOldValue', PPLSAPR_CR_CIPHER_VALUE],
    ['OldValueSetTime', PLARGE_INTEGER],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarQuerySecret extends NDRCALL {
  static opnum = 30;
  static Response = LsarQuerySecretResponse;
  static structure: NDRField[] = [
    ['SecretHandle', LSAPR_HANDLE],
    ['EncryptedCurrentValue', PPLSAPR_CR_CIPHER_VALUE],
    ['CurrentValueSetTime', PLARGE_INTEGER],
    ['EncryptedOldValue', PPLSAPR_CR_CIPHER_VALUE],
    ['OldValueSetTime', PLARGE_INTEGER],
  ];
}

// Opnum 42
export class LsarStorePrivateDataResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', NTSTATUS]];
}

export class LsarStorePrivateData extends NDRCALL {
  static opnum = 42;
  static Response = LsarStorePrivateDataResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['KeyName', RPC_UNICODE_STRING],
    ['EncryptedData', PLSAPR_CR_CIPHER_VALUE],
  ];
}

// Opnum 43
export class LsarRetrievePrivateDataResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['EncryptedData', PLSAPR_CR_CIPHER_VALUE],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarRetrievePrivateData extends NDRCALL {
  static opnum = 43;
  static Response = LsarRetrievePrivateDataResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['KeyName', RPC_UNICODE_STRING],
    ['EncryptedData', PLSAPR_CR_CIPHER_VALUE],
  ];
}

// Opnum 50
export class LsarEnumerateTrustedDomainsExResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['EnumerationContext', ULONG],
    ['EnumerationBuffer', LSAPR_TRUSTED_ENUM_BUFFER_EX],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarEnumerateTrustedDomainsEx extends NDRCALL {
  static opnum = 50;
  static Response = LsarEnumerateTrustedDomainsExResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['EnumerationContext', ULONG],
    ['PreferedMaximumLength', ULONG],
  ];
}

// Opnum 13
export class LsarEnumerateTrustedDomainsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['EnumerationContext', ULONG],
    ['EnumerationBuffer', LSAPR_TRUSTED_ENUM_BUFFER],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarEnumerateTrustedDomains extends NDRCALL {
  static opnum = 13;
  static Response = LsarEnumerateTrustedDomainsResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['EnumerationContext', ULONG],
    ['PreferedMaximumLength', ULONG],
  ];
}

// Opnum 73
export class LsarQueryForestTrustInformationResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ForestTrustInfo', PLSA_FOREST_TRUST_INFORMATION],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarQueryForestTrustInformation extends NDRCALL {
  static opnum = 73;
  static Response = LsarQueryForestTrustInformationResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['TrustedDomainName', LSA_UNICODE_STRING],
    ['HighestRecordType', LSA_FOREST_TRUST_RECORD_TYPE],
  ];
}

// Opnum 2
export class LsarEnumeratePrivilegesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['EnumerationContext', ULONG],
    ['EnumerationBuffer', LSAPR_PRIVILEGE_ENUM_BUFFER],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarEnumeratePrivileges extends NDRCALL {
  static opnum = 2;
  static Response = LsarEnumeratePrivilegesResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['EnumerationContext', ULONG],
    ['PreferedMaximumLength', ULONG],
  ];
}

// Opnum 31
export class LsarLookupPrivilegeValueResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Value', LUID],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarLookupPrivilegeValue extends NDRCALL {
  static opnum = 31;
  static Response = LsarLookupPrivilegeValueResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['Name', RPC_UNICODE_STRING],
  ];
}

// Opnum 32
export class LsarLookupPrivilegeNameResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Name', PRPC_UNICODE_STRING],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarLookupPrivilegeName extends NDRCALL {
  static opnum = 32;
  static Response = LsarLookupPrivilegeNameResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['Value', LUID],
  ];
}

// Opnum 33
export class LsarLookupPrivilegeDisplayNameResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Name', PRPC_UNICODE_STRING],
    ['LanguageReturned', UCHAR],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarLookupPrivilegeDisplayName extends NDRCALL {
  static opnum = 33;
  static Response = LsarLookupPrivilegeDisplayNameResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['Name', RPC_UNICODE_STRING],
    ['ClientLanguage', USHORT],
    ['ClientSystemDefaultLanguage', USHORT],
  ];
}

// Opnum 3
export class LsarQuerySecurityObjectResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['SecurityDescriptor', PLSAPR_SR_SECURITY_DESCRIPTOR],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarQuerySecurityObject extends NDRCALL {
  static opnum = 3;
  static Response = LsarQuerySecurityObjectResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['SecurityInformation', SECURITY_INFORMATION],
  ];
}

// Opnum 4
export class LsarSetSecurityObjectResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', NTSTATUS]];
}

export class LsarSetSecurityObject extends NDRCALL {
  static opnum = 4;
  static Response = LsarSetSecurityObjectResponse;
  static structure: NDRField[] = [
    ['PolicyHandle', LSAPR_HANDLE],
    ['SecurityInformation', SECURITY_INFORMATION],
    ['SecurityDescriptor', LSAPR_SR_SECURITY_DESCRIPTOR],
  ];
}

// Opnum 34
export class LsarDeleteObjectResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ObjectHandle', LSAPR_HANDLE],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarDeleteObject extends NDRCALL {
  static opnum = 34;
  static Response = LsarDeleteObjectResponse;
  static structure: NDRField[] = [['ObjectHandle', LSAPR_HANDLE]];
}

// Opnum 0
export class LsarCloseResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ObjectHandle', LSAPR_HANDLE],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarClose extends NDRCALL {
  static opnum = 0;
  static Response = LsarCloseResponse;
  static structure: NDRField[] = [['ObjectHandle', LSAPR_HANDLE]];
}

export const OPNUMS: Record<number, [new (data?: Buffer | null, isNDR64?: boolean) => NDR, new (data?: Buffer | null, isNDR64?: boolean) => NDR]> = {
  0: [LsarClose, LsarCloseResponse] as const,
  2: [LsarEnumeratePrivileges, LsarEnumeratePrivilegesResponse] as const,
  3: [LsarQuerySecurityObject, LsarQuerySecurityObjectResponse] as const,
  4: [LsarSetSecurityObject, LsarSetSecurityObjectResponse] as const,
  6: [LsarOpenPolicy, LsarOpenPolicyResponse] as const,
  7: [LsarQueryInformationPolicy, LsarQueryInformationPolicyResponse] as const,
  8: [LsarSetInformationPolicy, LsarSetInformationPolicyResponse] as const,
  10: [LsarCreateAccount, LsarCreateAccountResponse] as const,
  11: [LsarEnumerateAccounts, LsarEnumerateAccountsResponse] as const,
  13: [LsarEnumerateTrustedDomains, LsarEnumerateTrustedDomainsResponse] as const,
  16: [LsarCreateSecret, LsarCreateSecretResponse] as const,
  17: [LsarOpenAccount, LsarOpenAccountResponse] as const,
  18: [LsarEnumeratePrivilegesAccount, LsarEnumeratePrivilegesAccountResponse] as const,
  19: [LsarAddPrivilegesToAccount, LsarAddPrivilegesToAccountResponse] as const,
  20: [LsarRemovePrivilegesFromAccount, LsarRemovePrivilegesFromAccountResponse] as const,
  23: [LsarGetSystemAccessAccount, LsarGetSystemAccessAccountResponse] as const,
  24: [LsarSetSystemAccessAccount, LsarSetSystemAccessAccountResponse] as const,
  28: [LsarOpenSecret, LsarOpenSecretResponse] as const,
  29: [LsarSetSecret, LsarSetSecretResponse] as const,
  30: [LsarQuerySecret, LsarQuerySecretResponse] as const,
  31: [LsarLookupPrivilegeValue, LsarLookupPrivilegeValueResponse] as const,
  32: [LsarLookupPrivilegeName, LsarLookupPrivilegeNameResponse] as const,
  33: [LsarLookupPrivilegeDisplayName, LsarLookupPrivilegeDisplayNameResponse] as const,
  34: [LsarDeleteObject, LsarDeleteObjectResponse] as const,
  35: [LsarEnumerateAccountsWithUserRight, LsarEnumerateAccountsWithUserRightResponse] as const,
  36: [LsarEnumerateAccountRights, LsarEnumerateAccountRightsResponse] as const,
  37: [LsarAddAccountRights, LsarAddAccountRightsResponse] as const,
  38: [LsarRemoveAccountRights, LsarRemoveAccountRightsResponse] as const,
  42: [LsarStorePrivateData, LsarStorePrivateDataResponse] as const,
  43: [LsarRetrievePrivateData, LsarRetrievePrivateDataResponse] as const,
  44: [LsarOpenPolicy2, LsarOpenPolicy2Response] as const,
  46: [LsarQueryInformationPolicy2, LsarQueryInformationPolicy2Response] as const,
  47: [LsarSetInformationPolicy2, LsarSetInformationPolicy2Response] as const,
  50: [LsarEnumerateTrustedDomainsEx, LsarEnumerateTrustedDomainsExResponse] as const,
  53: [LsarQueryDomainInformationPolicy, LsarQueryDomainInformationPolicyResponse] as const,
};

// HELPER FUNCTIONS

type DceRpc = { request<T>(req: unknown): Promise<T> };

export async function hLsarOpenPolicy2(dce: DceRpc, desiredAccess = MAXIMUM_ALLOWED): Promise<any> {
  const request = new LsarOpenPolicy2();
  request.set('SystemName', NULL);
  (request.fields['ObjectAttributes'] as any).set('RootDirectory', NULL);
  (request.fields['ObjectAttributes'] as any).set('ObjectName', NULL);
  (request.fields['ObjectAttributes'] as any).set('SecurityDescriptor', NULL);
  (request.fields['ObjectAttributes'] as any).set('SecurityQualityOfService', NULL);
  request.set('DesiredAccess', desiredAccess);
  return dce.request(request);
}

export async function hLsarOpenPolicy(dce: DceRpc, desiredAccess = MAXIMUM_ALLOWED): Promise<any> {
  const request = new LsarOpenPolicy();
  request.set('SystemName', NULL);
  (request.fields['ObjectAttributes'] as any).set('RootDirectory', NULL);
  (request.fields['ObjectAttributes'] as any).set('ObjectName', NULL);
  (request.fields['ObjectAttributes'] as any).set('SecurityDescriptor', NULL);
  (request.fields['ObjectAttributes'] as any).set('SecurityQualityOfService', NULL);
  request.set('DesiredAccess', desiredAccess);
  return dce.request(request);
}

export async function hLsarQueryInformationPolicy2(dce: DceRpc, policyHandle: any, informationClass: number): Promise<any> {
  const request = new LsarQueryInformationPolicy2();
  request.set('PolicyHandle', policyHandle);
  request.set('InformationClass', informationClass);
  return dce.request(request);
}

export async function hLsarQueryInformationPolicy(dce: DceRpc, policyHandle: any, informationClass: number): Promise<any> {
  const request = new LsarQueryInformationPolicy();
  request.set('PolicyHandle', policyHandle);
  request.set('InformationClass', informationClass);
  return dce.request(request);
}

export async function hLsarQueryDomainInformationPolicy(dce: DceRpc, policyHandle: any, informationClass: number): Promise<any> {
  const request = new LsarQueryInformationPolicy();
  request.set('PolicyHandle', policyHandle);
  request.set('InformationClass', informationClass);
  return dce.request(request);
}

export async function hLsarEnumerateAccounts(dce: DceRpc, policyHandle: any, preferedMaximumLength = 0xffffffff): Promise<any> {
  const request = new LsarEnumerateAccounts();
  request.set('PolicyHandle', policyHandle);
  request.set('PreferedMaximumLength', preferedMaximumLength);
  return dce.request(request);
}

export async function hLsarEnumerateAccountsWithUserRight(dce: DceRpc, policyHandle: any, userRight: any): Promise<any> {
  const request = new LsarEnumerateAccountsWithUserRight();
  request.set('PolicyHandle', policyHandle);
  request.set('UserRight', userRight);
  return dce.request(request);
}

export async function hLsarEnumerateTrustedDomainsEx(dce: DceRpc, policyHandle: any, enumerationContext = 0, preferedMaximumLength = 0xffffffff): Promise<any> {
  const request = new LsarEnumerateTrustedDomainsEx();
  request.set('PolicyHandle', policyHandle);
  request.set('EnumerationContext', enumerationContext);
  request.set('PreferedMaximumLength', preferedMaximumLength);
  return dce.request(request);
}

export async function hLsarEnumerateTrustedDomains(dce: DceRpc, policyHandle: any, enumerationContext = 0, preferedMaximumLength = 0xffffffff): Promise<any> {
  const request = new LsarEnumerateTrustedDomains();
  request.set('PolicyHandle', policyHandle);
  request.set('EnumerationContext', enumerationContext);
  request.set('PreferedMaximumLength', preferedMaximumLength);
  return dce.request(request);
}

export async function hLsarOpenAccount(dce: DceRpc, policyHandle: any, accountSid: string, desiredAccess = MAXIMUM_ALLOWED): Promise<any> {
  const request = new LsarOpenAccount();
  request.set('PolicyHandle', policyHandle);
  (request.fields['AccountSid'] as any).fromCanonical(accountSid);
  request.set('DesiredAccess', desiredAccess);
  return dce.request(request);
}

export async function hLsarClose(dce: DceRpc, objectHandle: any): Promise<any> {
  const request = new LsarClose();
  request.set('ObjectHandle', objectHandle);
  return dce.request(request);
}

export async function hLsarCreateAccount(dce: DceRpc, policyHandle: any, accountSid: string, desiredAccess = MAXIMUM_ALLOWED): Promise<any> {
  const request = new LsarCreateAccount();
  request.set('PolicyHandle', policyHandle);
  (request.fields['AccountSid'] as any).fromCanonical(accountSid);
  request.set('DesiredAccess', desiredAccess);
  return dce.request(request);
}

export async function hLsarDeleteObject(dce: DceRpc, objectHandle: any): Promise<any> {
  const request = new LsarDeleteObject();
  request.set('ObjectHandle', objectHandle);
  return dce.request(request);
}

export async function hLsarEnumeratePrivilegesAccount(dce: DceRpc, accountHandle: any): Promise<any> {
  const request = new LsarEnumeratePrivilegesAccount();
  request.set('AccountHandle', accountHandle);
  return dce.request(request);
}

export async function hLsarGetSystemAccessAccount(dce: DceRpc, accountHandle: any): Promise<any> {
  const request = new LsarGetSystemAccessAccount();
  request.set('AccountHandle', accountHandle);
  return dce.request(request);
}

export async function hLsarSetSystemAccessAccount(dce: DceRpc, accountHandle: any, systemAccess: number): Promise<any> {
  const request = new LsarSetSystemAccessAccount();
  request.set('AccountHandle', accountHandle);
  request.set('SystemAccess', systemAccess);
  return dce.request(request);
}

export async function hLsarAddPrivilegesToAccount(dce: DceRpc, accountHandle: any, privileges: any[]): Promise<any> {
  const request = new LsarAddPrivilegesToAccount();
  request.set('AccountHandle', accountHandle);
  (request.fields['Privileges'] as any).set('PrivilegeCount', privileges.length);
  (request.fields['Privileges'] as any).set('Control', 0);
  for (const priv of privileges) {
    (request.fields['Privileges'] as any).fields['Privilege'].fields['Data'].push(priv);
  }
  return dce.request(request);
}

export async function hLsarRemovePrivilegesFromAccount(dce: DceRpc, accountHandle: any, privileges: any[] | null, allPrivileges = false): Promise<any> {
  const request = new LsarRemovePrivilegesFromAccount();
  request.set('AccountHandle', accountHandle);
  (request.fields['Privileges'] as any).set('Control', 0);
  if (privileges != null) {
    (request.fields['Privileges'] as any).set('PrivilegeCount', privileges.length);
    for (const priv of privileges) {
      (request.fields['Privileges'] as any).fields['Privilege'].fields['Data'].push(priv);
    }
  } else {
    (request.fields['Privileges'] as any).set('PrivilegeCount', NULL);
  }
  request.set('AllPrivileges', allPrivileges);
  return dce.request(request);
}

export async function hLsarEnumerateAccountRights(dce: DceRpc, policyHandle: any, accountSid: string): Promise<any> {
  const request = new LsarEnumerateAccountRights();
  request.set('PolicyHandle', policyHandle);
  (request.fields['AccountSid'] as any).fromCanonical(accountSid);
  return dce.request(request);
}

export async function hLsarAddAccountRights(dce: DceRpc, policyHandle: any, accountSid: string, userRights: string[]): Promise<any> {
  const request = new LsarAddAccountRights();
  request.set('PolicyHandle', policyHandle);
  (request.fields['AccountSid'] as any).fromCanonical(accountSid);
  (request.fields['UserRights'] as any).set('EntriesRead', userRights.length);
  for (const userRight of userRights) {
    const right = new RPC_UNICODE_STRING();
    right.set('Data', userRight);
    (request.fields['UserRights'] as any).fields['UserRights'].fields['Data'].push(right);
  }
  return dce.request(request);
}

export async function hLsarRemoveAccountRights(dce: DceRpc, policyHandle: any, accountSid: string, userRights: string[]): Promise<any> {
  const request = new LsarRemoveAccountRights();
  request.set('PolicyHandle', policyHandle);
  (request.fields['AccountSid'] as any).fromCanonical(accountSid);
  (request.fields['UserRights'] as any).set('EntriesRead', userRights.length);
  for (const userRight of userRights) {
    const right = new RPC_UNICODE_STRING();
    right.set('Data', userRight);
    (request.fields['UserRights'] as any).fields['UserRights'].fields['Data'].push(right);
  }
  return dce.request(request);
}

export async function hLsarCreateSecret(dce: DceRpc, policyHandle: any, secretName: string, desiredAccess = MAXIMUM_ALLOWED): Promise<any> {
  const request = new LsarCreateSecret();
  request.set('PolicyHandle', policyHandle);
  request.set('SecretName', secretName);
  request.set('DesiredAccess', desiredAccess);
  return dce.request(request);
}

export async function hLsarOpenSecret(dce: DceRpc, policyHandle: any, secretName: string, desiredAccess = MAXIMUM_ALLOWED): Promise<any> {
  const request = new LsarOpenSecret();
  request.set('PolicyHandle', policyHandle);
  request.set('SecretName', secretName);
  request.set('DesiredAccess', desiredAccess);
  return dce.request(request);
}

export async function hLsarSetSecret(dce: DceRpc, secretHandle: any, encryptedCurrentValue: Buffer | null, encryptedOldValue: Buffer | null): Promise<any> {
  const request = new LsarSetSecret();
  request.set('SecretHandle', secretHandle);
  if (encryptedCurrentValue != null) {
    (request.fields['EncryptedCurrentValue'] as any).set('Length', encryptedCurrentValue.length);
    (request.fields['EncryptedCurrentValue'] as any).set('MaximumLength', encryptedCurrentValue.length);
    (request.fields['EncryptedCurrentValue'] as any).set('Buffer', Array.from(encryptedCurrentValue));
  }
  if (encryptedOldValue != null) {
    (request.fields['EncryptedOldValue'] as any).set('Length', encryptedOldValue.length);
    (request.fields['EncryptedOldValue'] as any).set('MaximumLength', encryptedOldValue.length);
    (request.fields['EncryptedOldValue'] as any).set('Buffer', Array.from(encryptedOldValue));
  }
  return dce.request(request);
}

export async function hLsarQuerySecret(dce: DceRpc, secretHandle: any): Promise<any> {
  const request = new LsarQuerySecret();
  request.set('SecretHandle', secretHandle);
  (request.fields['EncryptedCurrentValue'] as any).set('Buffer', NULL);
  (request.fields['EncryptedOldValue'] as any).set('Buffer', NULL);
  request.set('OldValueSetTime', NULL);
  return dce.request(request);
}

export async function hLsarRetrievePrivateData(dce: DceRpc, policyHandle: any, keyName: string): Promise<Buffer> {
  const request = new LsarRetrievePrivateData();
  request.set('PolicyHandle', policyHandle);
  request.set('KeyName', keyName);
  const retVal: any = await dce.request(request);
  const ed = retVal.get('EncryptedData');
  const data = ed.get('Buffer');
  if (Array.isArray(data)) {
    return Buffer.from(data as number[]);
  }
  return data as Buffer;
}

export async function hLsarStorePrivateData(dce: DceRpc, policyHandle: any, keyName: string, encryptedData: Buffer | null): Promise<any> {
  const request = new LsarStorePrivateData();
  request.set('PolicyHandle', policyHandle);
  request.set('KeyName', keyName);
  if (encryptedData != null) {
    (request.fields['EncryptedData'] as any).set('Length', encryptedData.length);
    (request.fields['EncryptedData'] as any).set('MaximumLength', encryptedData.length);
    (request.fields['EncryptedData'] as any).set('Buffer', Array.from(encryptedData));
  } else {
    request.set('EncryptedData', NULL);
  }
  return dce.request(request);
}

export async function hLsarEnumeratePrivileges(dce: DceRpc, policyHandle: any, enumerationContext = 0, preferedMaximumLength = 0xffffffff): Promise<any> {
  const request = new LsarEnumeratePrivileges();
  request.set('PolicyHandle', policyHandle);
  request.set('EnumerationContext', enumerationContext);
  request.set('PreferedMaximumLength', preferedMaximumLength);
  return dce.request(request);
}

export async function hLsarLookupPrivilegeValue(dce: DceRpc, policyHandle: any, name: string): Promise<any> {
  const request = new LsarLookupPrivilegeValue();
  request.set('PolicyHandle', policyHandle);
  request.set('Name', name);
  return dce.request(request);
}

export async function hLsarLookupPrivilegeName(dce: DceRpc, policyHandle: any, luid: any): Promise<any> {
  const request = new LsarLookupPrivilegeName();
  request.set('PolicyHandle', policyHandle);
  request.set('Value', luid);
  return dce.request(request);
}

export async function hLsarQuerySecurityObject(dce: DceRpc, policyHandle: any, securityInformation = OWNER_SECURITY_INFORMATION): Promise<Buffer> {
  const request = new LsarQuerySecurityObject();
  request.set('PolicyHandle', policyHandle);
  request.set('SecurityInformation', securityInformation);
  const retVal: any = await dce.request(request);
  const sd = retVal.fields['SecurityDescriptor'].fields['SecurityDescriptor'];
  const data = sd.fields['Data'];
  if (Array.isArray(data)) {
    return Buffer.from(data as number[]);
  }
  return data as Buffer;
}

export async function hLsarSetSecurityObject(dce: DceRpc, policyHandle: any, securityInformation: number, securityDescriptor: Buffer): Promise<any> {
  const request = new LsarSetSecurityObject();
  request.set('PolicyHandle', policyHandle);
  request.set('SecurityInformation', securityInformation);
  (request.fields['SecurityDescriptor'] as any).set('Length', securityDescriptor.length);
  (request.fields['SecurityDescriptor'] as any).set('SecurityDescriptor', Array.from(securityDescriptor));
  return dce.request(request);
}

export async function hLsarSetInformationPolicy2(dce: DceRpc, policyHandle: any, informationClass: number, policyInformation: any): Promise<any> {
  const request = new LsarSetInformationPolicy2();
  request.set('PolicyHandle', policyHandle);
  request.set('InformationClass', informationClass);
  request.set('PolicyInformation', policyInformation);
  return dce.request(request);
}

export async function hLsarSetInformationPolicy(dce: DceRpc, policyHandle: any, informationClass: number, policyInformation: any): Promise<any> {
  const request = new LsarSetInformationPolicy();
  request.set('PolicyHandle', policyHandle);
  request.set('InformationClass', informationClass);
  request.set('PolicyInformation', policyInformation);
  return dce.request(request);
}
