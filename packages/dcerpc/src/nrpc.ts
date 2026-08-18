import { Buffer } from 'node:buffer';
import { createCipheriv, createDecipheriv, createHmac, createHash, randomBytes } from 'node:crypto';
import { uuidtupToBin } from '@impacket/uuid';
import { Structure, type FieldDescriptor } from '@impacket/structure';
import { transformKey, rc4 } from '@impacket/crypto';
import { ntowfV1 } from '@impacket/ntlm';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRENUM,
  NDRUNION,
  NDRPOINTER,
  NDRUniConformantArray,
  NDRUniConformantVaryingArray,
  NDRUniFixedArray,
  NULL,
  type NDRField,
} from './ndr';
import {
  DWORD,
  ULONG,
  USHORT,
  UCHAR,
  LONG,
  LPWSTR,
  WSTR,
  GUID,
  PGUID,
  PRPC_SID,
  RPC_UNICODE_STRING,
  SECURITY_INFORMATION,
  NTSTATUS,
  ULONGLONG,
  LPULONG,
} from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';
import { OLD_LARGE_INTEGER, SAMPR_LOGON_HOURS, PULONG_ARRAY } from './samr';
import { PLSA_FOREST_TRUST_INFORMATION, STRING } from './lsad';

// ============================================================================
// UUID
// ============================================================================

export const MSRPC_UUID_NRPC = uuidtupToBin(['12345678-1234-ABCD-EF00-01234567CFFB', '1.0'])!;

// ============================================================================
// ERROR CLASS
// ============================================================================

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
      return 'NRPC SessionError: code: 0x' + key.toString(16);
    }
    return 'NRPC SessionError: unknown error code: 0x' + (this.error_code ?? 0).toString(16);
  }
}

// ============================================================================
// CONSTANTS
// ============================================================================

// 2.2.1.2.5 NL_DNS_NAME_INFO - Type
export const NlDnsLdapAtSite       = 22;
export const NlDnsGcAtSite         = 25;
export const NlDnsDsaCname         = 28;
export const NlDnsKdcAtSite        = 30;
export const NlDnsDcAtSite         = 32;
export const NlDnsRfc1510KdcAtSite = 34;
export const NlDnsGenericGcAtSite  = 36;

// DnsDomainInfoType
export const NlDnsDomainName      = 1;
export const NlDnsDomainNameAlias = 2;
export const NlDnsForestName      = 3;
export const NlDnsForestNameAlias = 4;
export const NlDnsNdncDomainName  = 5;
export const NlDnsRecordName      = 6;

// 2.2.1.3.15 NL_OSVERSIONINFO_V1 - wSuiteMask
export const VER_SUITE_BACKOFFICE               = 0x00000004;
export const VER_SUITE_BLADE                    = 0x00000400;
export const VER_SUITE_COMPUTE_SERVER           = 0x00004000;
export const VER_SUITE_DATACENTER               = 0x00000080;
export const VER_SUITE_ENTERPRISE               = 0x00000002;
export const VER_SUITE_EMBEDDEDNT               = 0x00000040;
export const VER_SUITE_PERSONAL                 = 0x00000200;
export const VER_SUITE_SINGLEUSERTS             = 0x00000100;
export const VER_SUITE_SMALLBUSINESS            = 0x00000001;
export const VER_SUITE_SMALLBUSINESS_RESTRICTED = 0x00000020;
export const VER_SUITE_STORAGE_SERVER           = 0x00002000;
export const VER_SUITE_TERMINAL                 = 0x00000010;

// wProductType
export const VER_NT_DOMAIN_CONTROLLER = 0x00000002;
export const VER_NT_SERVER            = 0x00000003;
export const VER_NT_WORKSTATION       = 0x00000001;

// 2.2.1.4.18 NETLOGON Specific Access Masks
export const NETLOGON_UAS_LOGON_ACCESS  = 0x0001;
export const NETLOGON_UAS_LOGOFF_ACCESS = 0x0002;
export const NETLOGON_CONTROL_ACCESS    = 0x0004;
export const NETLOGON_QUERY_ACCESS      = 0x0008;
export const NETLOGON_SERVICE_ACCESS    = 0x0010;
export const NETLOGON_FTINFO_ACCESS     = 0x0020;
export const NETLOGON_WKSTA_RPC_ACCESS  = 0x0040;

// 3.5.4.9.1 NetrLogonControl2Ex (Opnum 18) - FunctionCode
export const NETLOGON_CONTROL_QUERY             = 0x00000001;
export const NETLOGON_CONTROL_REPLICATE         = 0x00000002;
export const NETLOGON_CONTROL_SYNCHRONIZE       = 0x00000003;
export const NETLOGON_CONTROL_PDC_REPLICATE     = 0x00000004;
export const NETLOGON_CONTROL_REDISCOVER        = 0x00000005;
export const NETLOGON_CONTROL_TC_QUERY          = 0x00000006;
export const NETLOGON_CONTROL_TRANSPORT_NOTIFY  = 0x00000007;
export const NETLOGON_CONTROL_FIND_USER         = 0x00000008;
export const NETLOGON_CONTROL_CHANGE_PASSWORD   = 0x00000009;
export const NETLOGON_CONTROL_TC_VERIFY         = 0x0000000A;
export const NETLOGON_CONTROL_FORCE_DNS_REG     = 0x0000000B;
export const NETLOGON_CONTROL_QUERY_DNS_REG     = 0x0000000C;
export const NETLOGON_CONTROL_BACKUP_CHANGE_LOG = 0x0000FFFC;
export const NETLOGON_CONTROL_TRUNCATE_LOG      = 0x0000FFFD;
export const NETLOGON_CONTROL_SET_DBFLAG        = 0x0000FFFE;
export const NETLOGON_CONTROL_BREAKPOINT        = 0x0000FFFF;

// ============================================================================
// TYPE ALIASES
// ============================================================================

// 3.5.4.1 RPC Binding Handles for Netlogon Methods
export const LOGONSRV_HANDLE = WSTR;
export const PLOGONSRV_HANDLE = LPWSTR;

const NET_API_STATUS = DWORD;

// ============================================================================
// STRUCTURES
// ============================================================================

// 2.2.1.1.1 CYPHER_BLOCK
export class CYPHER_BLOCK extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', '8s=b""']];

  getAlignment(): number {
    return 1;
  }
}

// 2.2.1.1.3 LM_OWF_PASSWORD
export class CYPHER_BLOCK_ARRAY extends NDRUniFixedArray {
  getDataLen(data: Buffer, offset = 0): number {
    return 16;
  }
}

export class LM_OWF_PASSWORD extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', CYPHER_BLOCK_ARRAY]];
}

// 2.2.1.1.4 NT_OWF_PASSWORD
export const NT_OWF_PASSWORD = LM_OWF_PASSWORD;
const ENCRYPTED_NT_OWF_PASSWORD = NT_OWF_PASSWORD;

// 2.2.1.3.4 NETLOGON_CREDENTIAL
export class UCHAR_FIXED_ARRAY extends NDRUniFixedArray {
  static align = 1;

  getDataLen(data: Buffer, offset = 0): number {
    return 8;
  }
}

export class NETLOGON_CREDENTIAL extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', UCHAR_FIXED_ARRAY]];

  getAlignment(): number {
    return 1;
  }
}

// 2.2.1.1.5 NETLOGON_AUTHENTICATOR
export class NETLOGON_AUTHENTICATOR extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Credential', NETLOGON_CREDENTIAL],
    ['Timestamp', DWORD],
  ];
}

export class PNETLOGON_AUTHENTICATOR extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_AUTHENTICATOR]];
}

// 2.2.1.2.1 DOMAIN_CONTROLLER_INFOW
export class DOMAIN_CONTROLLER_INFOW extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['DomainControllerName', LPWSTR],
    ['DomainControllerAddress', LPWSTR],
    ['DomainControllerAddressType', ULONG],
    ['DomainGuid', GUID],
    ['DomainName', LPWSTR],
    ['DnsForestName', LPWSTR],
    ['Flags', ULONG],
    ['DcSiteName', LPWSTR],
    ['ClientSiteName', LPWSTR],
  ];
}

export class PDOMAIN_CONTROLLER_INFOW extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DOMAIN_CONTROLLER_INFOW]];
}

// 2.2.1.2.2 NL_SITE_NAME_ARRAY
class RPC_UNICODE_STRING_ARRAY extends NDRUniConformantArray {
  static item = RPC_UNICODE_STRING;
}

class PRPC_UNICODE_STRING_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', RPC_UNICODE_STRING_ARRAY]];
}

export class NL_SITE_NAME_ARRAY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntryCount', ULONG],
    ['SiteNames', PRPC_UNICODE_STRING_ARRAY],
  ];
}

export class PNL_SITE_NAME_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NL_SITE_NAME_ARRAY]];
}

// 2.2.1.2.3 NL_SITE_NAME_EX_ARRAY
export class NL_SITE_NAME_EX_ARRAY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntryCount', ULONG],
    ['SiteNames', PRPC_UNICODE_STRING_ARRAY],
    ['SubnetNames', PRPC_UNICODE_STRING_ARRAY],
  ];
}

export class PNL_SITE_NAME_EX_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NL_SITE_NAME_EX_ARRAY]];
}

// 2.2.1.2.4 NL_SOCKET_ADDRESS
// 2.2.1.2.4.1 IPv4 Address Structure
export class IPv4Address extends Structure {
  static structure: FieldDescriptor[] = [
    ['AddressFamily', '<H=0'],
    ['Port', '<H=0'],
    ['Address', '<L=0'],
    ['Padding', '<L=0'],
  ];
}

export class UCHAR_ARRAY extends NDRUniConformantArray {
  static item = 'c';
}

export class PUCHAR_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', UCHAR_ARRAY]];
}

export class NL_SOCKET_ADDRESS extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['lpSockaddr', PUCHAR_ARRAY],
    ['iSockaddrLength', ULONG],
  ];
}

export class NL_SOCKET_ADDRESS_ARRAY extends NDRUniConformantArray {
  static item = NL_SOCKET_ADDRESS;
}

// 2.2.1.2.5 NL_DNS_NAME_INFO
export class NL_DNS_NAME_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Type', ULONG],
    ['DnsDomainInfoType', WSTR],
    ['Priority', ULONG],
    ['Weight', ULONG],
    ['Port', ULONG],
    ['Register', UCHAR],
    ['Status', ULONG],
  ];
}

// 2.2.1.2.6 NL_DNS_NAME_INFO_ARRAY
export class NL_DNS_NAME_INFO_ARRAY_ITEMS extends NDRUniConformantArray {
  static item = NL_DNS_NAME_INFO;
}

export class PNL_DNS_NAME_INFO_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NL_DNS_NAME_INFO_ARRAY_ITEMS]];
}

export class NL_DNS_NAME_INFO_ARRAY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntryCount', ULONG],
    ['DnsNamesInfo', PNL_DNS_NAME_INFO_ARRAY],
  ];
}

// 2.2.1.3.5 NETLOGON_LSA_POLICY_INFO
export class NETLOGON_LSA_POLICY_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['LsaPolicySize', ULONG],
    ['LsaPolicy', PUCHAR_ARRAY],
  ];
}

export class PNETLOGON_LSA_POLICY_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_LSA_POLICY_INFO]];
}

// 2.2.1.3.6 NETLOGON_WORKSTATION_INFO
export class NETLOGON_WORKSTATION_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['LsaPolicy', NETLOGON_LSA_POLICY_INFO],
    ['DnsHostName', LPWSTR],
    ['SiteName', LPWSTR],
    ['Dummy1', LPWSTR],
    ['Dummy2', LPWSTR],
    ['Dummy3', LPWSTR],
    ['Dummy4', LPWSTR],
    ['OsVersion', RPC_UNICODE_STRING],
    ['OsName', RPC_UNICODE_STRING],
    ['DummyString3', RPC_UNICODE_STRING],
    ['DummyString4', RPC_UNICODE_STRING],
    ['WorkstationFlags', ULONG],
    ['KerberosSupportedEncryptionTypes', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class PNETLOGON_WORKSTATION_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_WORKSTATION_INFO]];
}

// 2.2.1.3.7 NL_TRUST_PASSWORD
export class NL_TRUST_PASSWORD_FIXED_ARRAY extends NDRUniFixedArray {
  getDataLen(data: Buffer, offset = 0): number {
    return 516;
  }

  getAlignment(): number {
    return 1;
  }
}

class WCHAR_ARRAY extends NDRUniFixedArray {
  getDataLen(data: Buffer, offset = 0): number {
    return 512;
  }
}

export class NL_TRUST_PASSWORD extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Buffer', WCHAR_ARRAY],
    ['Length', ULONG],
  ];
}

export class PNL_TRUST_PASSWORD extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NL_TRUST_PASSWORD]];
}

// 2.2.1.3.8 NL_PASSWORD_VERSION
export class NL_PASSWORD_VERSION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ReservedField', ULONG],
    ['PasswordVersionNumber', ULONG],
    ['PasswordVersionPresent', ULONG],
  ];
}

// 2.2.1.3.9 NETLOGON_WORKSTATION_INFORMATION
export class NETLOGON_WORKSTATION_INFORMATION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['WorkstationInfo', PNETLOGON_WORKSTATION_INFO],
    2: ['LsaPolicyInfo', PNETLOGON_LSA_POLICY_INFO],
  };
}

// 2.2.1.3.10 NETLOGON_ONE_DOMAIN_INFO
export class NETLOGON_ONE_DOMAIN_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['DomainName', RPC_UNICODE_STRING],
    ['DnsDomainName', RPC_UNICODE_STRING],
    ['DnsForestName', RPC_UNICODE_STRING],
    ['DomainGuid', GUID],
    ['DomainSid', PRPC_SID],
    ['TrustExtension', RPC_UNICODE_STRING],
    ['DummyString2', RPC_UNICODE_STRING],
    ['DummyString3', RPC_UNICODE_STRING],
    ['DummyString4', RPC_UNICODE_STRING],
    ['DummyLong1', ULONG],
    ['DummyLong2', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class NETLOGON_ONE_DOMAIN_INFO_ARRAY extends NDRUniConformantArray {
  static item = NETLOGON_ONE_DOMAIN_INFO;
}

export class PNETLOGON_ONE_DOMAIN_INFO_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_ONE_DOMAIN_INFO_ARRAY]];
}

// 2.2.1.3.11 NETLOGON_DOMAIN_INFO
export class NETLOGON_DOMAIN_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['PrimaryDomain', NETLOGON_ONE_DOMAIN_INFO],
    ['TrustedDomainCount', ULONG],
    ['TrustedDomains', PNETLOGON_ONE_DOMAIN_INFO_ARRAY],
    ['LsaPolicy', NETLOGON_LSA_POLICY_INFO],
    ['DnsHostNameInDs', RPC_UNICODE_STRING],
    ['DummyString2', RPC_UNICODE_STRING],
    ['DummyString3', RPC_UNICODE_STRING],
    ['DummyString4', RPC_UNICODE_STRING],
    ['WorkstationFlags', ULONG],
    ['SupportedEncTypes', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class PNETLOGON_DOMAIN_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_DOMAIN_INFO]];
}

// 2.2.1.3.12 NETLOGON_DOMAIN_INFORMATION
export class NETLOGON_DOMAIN_INFORMATION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['DomainInfo', PNETLOGON_DOMAIN_INFO],
    2: ['LsaPolicyInfo', PNETLOGON_LSA_POLICY_INFO],
  };
}

// 2.2.1.3.13 NETLOGON_SECURE_CHANNEL_TYPE
export class NETLOGON_SECURE_CHANNEL_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'NullSecureChannel',
    1: 'MsvApSecureChannel',
    2: 'WorkstationSecureChannel',
    3: 'TrustedDnsDomainSecureChannel',
    4: 'TrustedDomainSecureChannel',
    5: 'UasServerSecureChannel',
    6: 'ServerSecureChannel',
    7: 'CdcServerSecureChannel',
  };
  static enumValues: Record<string, number> = {
    NullSecureChannel: 0,
    MsvApSecureChannel: 1,
    WorkstationSecureChannel: 2,
    TrustedDnsDomainSecureChannel: 3,
    TrustedDomainSecureChannel: 4,
    UasServerSecureChannel: 5,
    ServerSecureChannel: 6,
    CdcServerSecureChannel: 7,
  };
}

// 2.2.1.3.14 NETLOGON_CAPABILITIES
export class NETLOGON_CAPABILITIES extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['ServerCapabilities', ULONG],
  };
}

// 2.2.1.3.15 NL_OSVERSIONINFO_V1
export class UCHAR_FIXED_128_ARRAY extends NDRUniFixedArray {
  getDataLen(data: Buffer, offset = 0): number {
    return 128;
  }
}

export class NL_OSVERSIONINFO_V1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwOSVersionInfoSize', DWORD],
    ['dwMajorVersion', DWORD],
    ['dwMinorVersion', DWORD],
    ['dwBuildNumber', DWORD],
    ['dwPlatformId', DWORD],
    ['szCSDVersion', UCHAR_FIXED_128_ARRAY],
    ['wServicePackMajor', USHORT],
    ['wServicePackMinor', USHORT],
    ['wSuiteMask', USHORT],
    ['wProductType', UCHAR],
    ['wReserved', UCHAR],
  ];
}

export class PNL_OSVERSIONINFO_V1 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NL_OSVERSIONINFO_V1]];
}

// 2.2.1.3.16 NL_IN_CHAIN_SET_CLIENT_ATTRIBUTES_V1
export class PLPWSTR extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LPWSTR]];
}

export class NL_IN_CHAIN_SET_CLIENT_ATTRIBUTES_V1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ClientDnsHostName', PLPWSTR],
    ['OsVersionInfo', PNL_OSVERSIONINFO_V1],
    ['OsName', PLPWSTR],
  ];
}

// 2.2.1.3.17 NL_IN_CHAIN_SET_CLIENT_ATTRIBUTES
export class NL_IN_CHAIN_SET_CLIENT_ATTRIBUTES extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['V1', NL_IN_CHAIN_SET_CLIENT_ATTRIBUTES_V1],
  };
}

// 2.2.1.3.18 NL_OUT_CHAIN_SET_CLIENT_ATTRIBUTES_V1
export class NL_OUT_CHAIN_SET_CLIENT_ATTRIBUTES_V1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['HubName', PLPWSTR],
    ['OldDnsHostName', PLPWSTR],
    ['SupportedEncTypes', LPULONG],
  ];
}

// 2.2.1.3.19 NL_OUT_CHAIN_SET_CLIENT_ATTRIBUTES
export class NL_OUT_CHAIN_SET_CLIENT_ATTRIBUTES extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['V1', NL_OUT_CHAIN_SET_CLIENT_ATTRIBUTES_V1],
  };
}

// 2.2.1.4.1 LM_CHALLENGE
export class CHAR_FIXED_8_ARRAY extends NDRUniFixedArray {
  getDataLen(data: Buffer, offset = 0): number {
    return 8;
  }
}

export class LM_CHALLENGE extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', CHAR_FIXED_8_ARRAY]];
}

// 2.2.1.4.15 NETLOGON_LOGON_IDENTITY_INFO
export class NETLOGON_LOGON_IDENTITY_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['LogonDomainName', RPC_UNICODE_STRING],
    ['ParameterControl', ULONG],
    ['Reserved', OLD_LARGE_INTEGER],
    ['UserName', RPC_UNICODE_STRING],
    ['Workstation', RPC_UNICODE_STRING],
  ];
}

export class PNETLOGON_LOGON_IDENTITY_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_LOGON_IDENTITY_INFO]];
}

// 2.2.1.4.2 NETLOGON_GENERIC_INFO
export class NETLOGON_GENERIC_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Identity', NETLOGON_LOGON_IDENTITY_INFO],
    ['PackageName', RPC_UNICODE_STRING],
    ['DataLength', ULONG],
    ['LogonData', PUCHAR_ARRAY],
  ];
}

export class PNETLOGON_GENERIC_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_GENERIC_INFO]];
}

// 2.2.1.4.3 NETLOGON_INTERACTIVE_INFO
export class NETLOGON_INTERACTIVE_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Identity', NETLOGON_LOGON_IDENTITY_INFO],
    ['LmOwfPassword', LM_OWF_PASSWORD],
    ['NtOwfPassword', LM_OWF_PASSWORD],
  ];
}

export class PNETLOGON_INTERACTIVE_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_INTERACTIVE_INFO]];
}

// 2.2.1.4.4 NETLOGON_SERVICE_INFO
export class NETLOGON_SERVICE_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Identity', NETLOGON_LOGON_IDENTITY_INFO],
    ['LmOwfPassword', LM_OWF_PASSWORD],
    ['NtOwfPassword', LM_OWF_PASSWORD],
  ];
}

export class PNETLOGON_SERVICE_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_SERVICE_INFO]];
}

// 2.2.1.4.5 NETLOGON_NETWORK_INFO
export class NETLOGON_NETWORK_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Identity', NETLOGON_LOGON_IDENTITY_INFO],
    ['LmChallenge', LM_CHALLENGE],
    ['NtChallengeResponse', STRING],
    ['LmChallengeResponse', STRING],
  ];
}

export class PNETLOGON_NETWORK_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_NETWORK_INFO]];
}

// 2.2.1.4.16 NETLOGON_LOGON_INFO_CLASS
export class NETLOGON_LOGON_INFO_CLASS extends NDRENUM {
  static enumItems: Record<number, string> = {
    1: 'NetlogonInteractiveInformation',
    2: 'NetlogonNetworkInformation',
    3: 'NetlogonServiceInformation',
    4: 'NetlogonGenericInformation',
    5: 'NetlogonInteractiveTransitiveInformation',
    6: 'NetlogonNetworkTransitiveInformation',
    7: 'NetlogonServiceTransitiveInformation',
  };
  static enumValues: Record<string, number> = {
    NetlogonInteractiveInformation: 1,
    NetlogonNetworkInformation: 2,
    NetlogonServiceInformation: 3,
    NetlogonGenericInformation: 4,
    NetlogonInteractiveTransitiveInformation: 5,
    NetlogonNetworkTransitiveInformation: 6,
    NetlogonServiceTransitiveInformation: 7,
  };

  static readonly NetlogonInteractiveInformation           = 1;
  static readonly NetlogonNetworkInformation               = 2;
  static readonly NetlogonServiceInformation               = 3;
  static readonly NetlogonGenericInformation               = 4;
  static readonly NetlogonInteractiveTransitiveInformation = 5;
  static readonly NetlogonNetworkTransitiveInformation     = 6;
  static readonly NetlogonServiceTransitiveInformation     = 7;
}

// 2.2.1.4.6 NETLOGON_LEVEL
export class NETLOGON_LEVEL extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    [NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation]:           ['LogonInteractive', PNETLOGON_INTERACTIVE_INFO],
    [NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveTransitiveInformation]: ['LogonInteractiveTransitive', PNETLOGON_INTERACTIVE_INFO],
    [NETLOGON_LOGON_INFO_CLASS.NetlogonServiceInformation]:               ['LogonService', PNETLOGON_SERVICE_INFO],
    [NETLOGON_LOGON_INFO_CLASS.NetlogonServiceTransitiveInformation]:     ['LogonServiceTransitive', PNETLOGON_SERVICE_INFO],
    [NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkInformation]:               ['LogonNetwork', PNETLOGON_NETWORK_INFO],
    [NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation]:     ['LogonNetworkTransitive', PNETLOGON_NETWORK_INFO],
    [NETLOGON_LOGON_INFO_CLASS.NetlogonGenericInformation]:               ['LogonGeneric', PNETLOGON_GENERIC_INFO],
  };
}

// =============================================================================
// Section 2: Validation / Delta / Control / SSPI Structures
// (Python nrpc.py lines 636-1635)
// =============================================================================

// 2.2.1.4.7 NETLOGON_SID_AND_ATTRIBUTES
export class NETLOGON_SID_AND_ATTRIBUTES extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Sid', PRPC_SID],
    ['Attributes', ULONG],
  ];
}

// 2.2.1.4.8 NETLOGON_VALIDATION_GENERIC_INFO2
export class NETLOGON_VALIDATION_GENERIC_INFO2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['DataLength', ULONG],
    ['ValidationData', PUCHAR_ARRAY],
  ];
}

export class PNETLOGON_VALIDATION_GENERIC_INFO2 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_VALIDATION_GENERIC_INFO2]];
}

// 2.2.1.4.9 USER_SESSION_KEY
export const USER_SESSION_KEY = LM_OWF_PASSWORD;

// 2.2.1.4.10 GROUP_MEMBERSHIP
class GROUP_MEMBERSHIP extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['RelativeId', ULONG],
    ['Attributes', ULONG],
  ];
}

class GROUP_MEMBERSHIP_ARRAY extends NDRUniConformantArray {
  static item = GROUP_MEMBERSHIP;
}

class PGROUP_MEMBERSHIP_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', GROUP_MEMBERSHIP_ARRAY]];
}

// 2.2.1.4.11 NETLOGON_VALIDATION_SAM_INFO
export class LONG_ARRAY extends NDRUniFixedArray {
  getDataLen(data: Buffer, offset = 0): number { return 4 * 10; }
}

export class NETLOGON_VALIDATION_SAM_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['LogonTime', OLD_LARGE_INTEGER],
    ['LogoffTime', OLD_LARGE_INTEGER],
    ['KickOffTime', OLD_LARGE_INTEGER],
    ['PasswordLastSet', OLD_LARGE_INTEGER],
    ['PasswordCanChange', OLD_LARGE_INTEGER],
    ['PasswordMustChange', OLD_LARGE_INTEGER],
    ['EffectiveName', RPC_UNICODE_STRING],
    ['FullName', RPC_UNICODE_STRING],
    ['LogonScript', RPC_UNICODE_STRING],
    ['ProfilePath', RPC_UNICODE_STRING],
    ['HomeDirectory', RPC_UNICODE_STRING],
    ['HomeDirectoryDrive', RPC_UNICODE_STRING],
    ['LogonCount', USHORT],
    ['BadPasswordCount', USHORT],
    ['UserId', ULONG],
    ['PrimaryGroupId', ULONG],
    ['GroupCount', ULONG],
    ['GroupIds', PGROUP_MEMBERSHIP_ARRAY],
    ['UserFlags', ULONG],
    ['UserSessionKey', USER_SESSION_KEY],
    ['LogonServer', RPC_UNICODE_STRING],
    ['LogonDomainName', RPC_UNICODE_STRING],
    ['LogonDomainId', PRPC_SID],
    ['ExpansionRoom', LONG_ARRAY],
  ];
}

export class PNETLOGON_VALIDATION_SAM_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_VALIDATION_SAM_INFO]];
}

// 2.2.1.4.12 NETLOGON_VALIDATION_SAM_INFO2
export class NETLOGON_SID_AND_ATTRIBUTES_ARRAY extends NDRUniConformantArray {
  static item = NETLOGON_SID_AND_ATTRIBUTES;
}

export class PNETLOGON_SID_AND_ATTRIBUTES_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_SID_AND_ATTRIBUTES_ARRAY]];
}

export class NETLOGON_VALIDATION_SAM_INFO2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['LogonTime', OLD_LARGE_INTEGER],
    ['LogoffTime', OLD_LARGE_INTEGER],
    ['KickOffTime', OLD_LARGE_INTEGER],
    ['PasswordLastSet', OLD_LARGE_INTEGER],
    ['PasswordCanChange', OLD_LARGE_INTEGER],
    ['PasswordMustChange', OLD_LARGE_INTEGER],
    ['EffectiveName', RPC_UNICODE_STRING],
    ['FullName', RPC_UNICODE_STRING],
    ['LogonScript', RPC_UNICODE_STRING],
    ['ProfilePath', RPC_UNICODE_STRING],
    ['HomeDirectory', RPC_UNICODE_STRING],
    ['HomeDirectoryDrive', RPC_UNICODE_STRING],
    ['LogonCount', USHORT],
    ['BadPasswordCount', USHORT],
    ['UserId', ULONG],
    ['PrimaryGroupId', ULONG],
    ['GroupCount', ULONG],
    ['GroupIds', PGROUP_MEMBERSHIP_ARRAY],
    ['UserFlags', ULONG],
    ['UserSessionKey', USER_SESSION_KEY],
    ['LogonServer', RPC_UNICODE_STRING],
    ['LogonDomainName', RPC_UNICODE_STRING],
    ['LogonDomainId', PRPC_SID],
    ['ExpansionRoom', LONG_ARRAY],
    ['SidCount', ULONG],
    ['ExtraSids', PNETLOGON_SID_AND_ATTRIBUTES_ARRAY],
  ];
}

export class PNETLOGON_VALIDATION_SAM_INFO2 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_VALIDATION_SAM_INFO2]];
}

// 2.2.1.4.13 NETLOGON_VALIDATION_SAM_INFO4
export class NETLOGON_VALIDATION_SAM_INFO4 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['LogonTime', OLD_LARGE_INTEGER],
    ['LogoffTime', OLD_LARGE_INTEGER],
    ['KickOffTime', OLD_LARGE_INTEGER],
    ['PasswordLastSet', OLD_LARGE_INTEGER],
    ['PasswordCanChange', OLD_LARGE_INTEGER],
    ['PasswordMustChange', OLD_LARGE_INTEGER],
    ['EffectiveName', RPC_UNICODE_STRING],
    ['FullName', RPC_UNICODE_STRING],
    ['LogonScript', RPC_UNICODE_STRING],
    ['ProfilePath', RPC_UNICODE_STRING],
    ['HomeDirectory', RPC_UNICODE_STRING],
    ['HomeDirectoryDrive', RPC_UNICODE_STRING],
    ['LogonCount', USHORT],
    ['BadPasswordCount', USHORT],
    ['UserId', ULONG],
    ['PrimaryGroupId', ULONG],
    ['GroupCount', ULONG],
    ['GroupIds', PGROUP_MEMBERSHIP_ARRAY],
    ['UserFlags', ULONG],
    ['UserSessionKey', USER_SESSION_KEY],
    ['LogonServer', RPC_UNICODE_STRING],
    ['LogonDomainName', RPC_UNICODE_STRING],
    ['LogonDomainId', PRPC_SID],
    ['LMKey', CHAR_FIXED_8_ARRAY],
    ['UserAccountControl', ULONG],
    ['SubAuthStatus', ULONG],
    ['LastSuccessfulILogon', OLD_LARGE_INTEGER],
    ['LastFailedILogon', OLD_LARGE_INTEGER],
    ['FailedILogonCount', ULONG],
    ['Reserved4', ULONG],
    ['SidCount', ULONG],
    ['ExtraSids', PNETLOGON_SID_AND_ATTRIBUTES_ARRAY],
    ['DnsLogonDomainName', RPC_UNICODE_STRING],
    ['Upn', RPC_UNICODE_STRING],
    ['ExpansionString1', RPC_UNICODE_STRING],
    ['ExpansionString2', RPC_UNICODE_STRING],
    ['ExpansionString3', RPC_UNICODE_STRING],
    ['ExpansionString4', RPC_UNICODE_STRING],
    ['ExpansionString5', RPC_UNICODE_STRING],
    ['ExpansionString6', RPC_UNICODE_STRING],
    ['ExpansionString7', RPC_UNICODE_STRING],
    ['ExpansionString8', RPC_UNICODE_STRING],
    ['ExpansionString9', RPC_UNICODE_STRING],
    ['ExpansionString10', RPC_UNICODE_STRING],
  ];
}

export class PNETLOGON_VALIDATION_SAM_INFO4 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_VALIDATION_SAM_INFO4]];
}

// 2.2.1.4.17 NETLOGON_VALIDATION_INFO_CLASS
export class NETLOGON_VALIDATION_INFO_CLASS extends NDRENUM {
  static enumItems: Record<number, string> = {
    1: 'NetlogonValidationUasInfo',
    2: 'NetlogonValidationSamInfo',
    3: 'NetlogonValidationSamInfo2',
    4: 'NetlogonValidationGenericInfo',
    5: 'NetlogonValidationGenericInfo2',
    6: 'NetlogonValidationSamInfo4',
  };
}

// 2.2.1.4.14 NETLOGON_VALIDATION
export class NETLOGON_VALIDATION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    2: ['ValidationSam', PNETLOGON_VALIDATION_SAM_INFO],
    3: ['ValidationSam2', PNETLOGON_VALIDATION_SAM_INFO2],
    5: ['ValidationGeneric2', PNETLOGON_VALIDATION_GENERIC_INFO2],
    6: ['ValidationSam4', PNETLOGON_VALIDATION_SAM_INFO4],
  };
}

// 2.2.1.5.2 NLPR_QUOTA_LIMITS
export class NLPR_QUOTA_LIMITS extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['PagedPoolLimit', ULONG],
    ['NonPagedPoolLimit', ULONG],
    ['MinimumWorkingSetSize', ULONG],
    ['MaximumWorkingSetSize', ULONG],
    ['PagefileLimit', ULONG],
    ['Reserved', OLD_LARGE_INTEGER],
  ];
}

// 2.2.1.5.3 NETLOGON_DELTA_ACCOUNTS
export class NETLOGON_DELTA_ACCOUNTS extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['PrivilegeEntries', ULONG],
    ['PrivilegeControl', ULONG],
    ['PrivilegeAttributes', PULONG_ARRAY],
    ['PrivilegeNames', PRPC_UNICODE_STRING_ARRAY],
    ['QuotaLimits', NLPR_QUOTA_LIMITS],
    ['SystemAccessFlags', ULONG],
    ['SecurityInformation', SECURITY_INFORMATION],
    ['SecuritySize', ULONG],
    ['SecurityDescriptor', PUCHAR_ARRAY],
    ['DummyString1', RPC_UNICODE_STRING],
    ['DummyString2', RPC_UNICODE_STRING],
    ['DummyString3', RPC_UNICODE_STRING],
    ['DummyString4', RPC_UNICODE_STRING],
    ['DummyLong1', ULONG],
    ['DummyLong2', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class PNETLOGON_DELTA_ACCOUNTS extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_DELTA_ACCOUNTS]];
}

// 2.2.1.5.5 NLPR_SID_INFORMATION
export class NLPR_SID_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['SidPointer', PRPC_SID],
  ];
}

// 2.2.1.5.6 NLPR_SID_ARRAY
export class NLPR_SID_INFORMATION_ARRAY extends NDRUniConformantArray {
  static item = NLPR_SID_INFORMATION;
}

export class PNLPR_SID_INFORMATION_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NLPR_SID_INFORMATION_ARRAY]];
}

export class NLPR_SID_ARRAY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Count', ULONG],
    ['Sids', PNLPR_SID_INFORMATION_ARRAY],
  ];
}

// 2.2.1.5.7 NETLOGON_DELTA_ALIAS_MEMBER
export class NETLOGON_DELTA_ALIAS_MEMBER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Members', NLPR_SID_ARRAY],
    ['DummyLong1', ULONG],
    ['DummyLong2', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class PNETLOGON_DELTA_ALIAS_MEMBER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_DELTA_ALIAS_MEMBER]];
}

// 2.2.1.5.8 NETLOGON_DELTA_DELETE_GROUP
export class NETLOGON_DELTA_DELETE_GROUP extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['AccountName', LPWSTR],
    ['DummyString1', RPC_UNICODE_STRING],
    ['DummyString2', RPC_UNICODE_STRING],
    ['DummyString3', RPC_UNICODE_STRING],
    ['DummyString4', RPC_UNICODE_STRING],
    ['DummyLong1', ULONG],
    ['DummyLong2', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class PNETLOGON_DELTA_DELETE_GROUP extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_DELTA_DELETE_GROUP]];
}

// 2.2.1.5.9 NETLOGON_DELTA_DELETE_USER
export class NETLOGON_DELTA_DELETE_USER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['AccountName', LPWSTR],
    ['DummyString1', RPC_UNICODE_STRING],
    ['DummyString2', RPC_UNICODE_STRING],
    ['DummyString3', RPC_UNICODE_STRING],
    ['DummyString4', RPC_UNICODE_STRING],
    ['DummyLong1', ULONG],
    ['DummyLong2', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class PNETLOGON_DELTA_DELETE_USER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_DELTA_DELETE_USER]];
}

// 2.2.1.5.10 NETLOGON_DELTA_DOMAIN
export class NETLOGON_DELTA_DOMAIN extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['DomainName', RPC_UNICODE_STRING],
    ['OemInformation', RPC_UNICODE_STRING],
    ['ForceLogoff', OLD_LARGE_INTEGER],
    ['MinPasswordLength', USHORT],
    ['PasswordHistoryLength', USHORT],
    ['MaxPasswordAge', OLD_LARGE_INTEGER],
    ['MinPasswordAge', OLD_LARGE_INTEGER],
    ['DomainModifiedCount', OLD_LARGE_INTEGER],
    ['DomainCreationTime', OLD_LARGE_INTEGER],
    ['SecurityInformation', SECURITY_INFORMATION],
    ['SecuritySize', ULONG],
    ['SecurityDescriptor', PUCHAR_ARRAY],
    ['DomainLockoutInformation', RPC_UNICODE_STRING],
    ['DummyString2', RPC_UNICODE_STRING],
    ['DummyString3', RPC_UNICODE_STRING],
    ['DummyString4', RPC_UNICODE_STRING],
    ['PasswordProperties', ULONG],
    ['DummyLong2', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class PNETLOGON_DELTA_DOMAIN extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_DELTA_DOMAIN]];
}

// 2.2.1.5.13 NETLOGON_DELTA_GROUP
export class NETLOGON_DELTA_GROUP extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Name', RPC_UNICODE_STRING],
    ['RelativeId', ULONG],
    ['Attributes', ULONG],
    ['AdminComment', RPC_UNICODE_STRING],
    ['SecurityInformation', USHORT],
    ['SecuritySize', ULONG],
    ['SecurityDescriptor', SECURITY_INFORMATION],
    ['DummyString1', RPC_UNICODE_STRING],
    ['DummyString2', RPC_UNICODE_STRING],
    ['DummyString3', RPC_UNICODE_STRING],
    ['DummyString4', RPC_UNICODE_STRING],
    ['DummyLong1', ULONG],
    ['DummyLong2', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class PNETLOGON_DELTA_GROUP extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_DELTA_GROUP]];
}

// 2.2.1.5.24 NETLOGON_RENAME_GROUP
export class NETLOGON_RENAME_GROUP extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['OldName', RPC_UNICODE_STRING],
    ['NewName', RPC_UNICODE_STRING],
    ['DummyString1', RPC_UNICODE_STRING],
    ['DummyString2', RPC_UNICODE_STRING],
    ['DummyString3', RPC_UNICODE_STRING],
    ['DummyString4', RPC_UNICODE_STRING],
    ['DummyLong1', ULONG],
    ['DummyLong2', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class PNETLOGON_DELTA_RENAME_GROUP extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_RENAME_GROUP]];
}

// 2.2.1.5.14 NLPR_LOGON_HOURS
export const NLPR_LOGON_HOURS = SAMPR_LOGON_HOURS;

// 2.2.1.5.15 NLPR_USER_PRIVATE_INFO
export class NLPR_USER_PRIVATE_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['SensitiveData', UCHAR],
    ['DataLength', ULONG],
    ['Data', PUCHAR_ARRAY],
  ];
}

// 2.2.1.5.16 NETLOGON_DELTA_USER
export class NETLOGON_DELTA_USER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['UserName', RPC_UNICODE_STRING],
    ['FullName', RPC_UNICODE_STRING],
    ['UserId', ULONG],
    ['PrimaryGroupId', ULONG],
    ['HomeDirectory', RPC_UNICODE_STRING],
    ['HomeDirectoryDrive', RPC_UNICODE_STRING],
    ['ScriptPath', RPC_UNICODE_STRING],
    ['AdminComment', RPC_UNICODE_STRING],
    ['WorkStations', RPC_UNICODE_STRING],
    ['LastLogon', OLD_LARGE_INTEGER],
    ['LastLogoff', OLD_LARGE_INTEGER],
    ['LogonHours', NLPR_LOGON_HOURS],
    ['BadPasswordCount', USHORT],
    ['LogonCount', USHORT],
    ['PasswordLastSet', OLD_LARGE_INTEGER],
    ['AccountExpires', OLD_LARGE_INTEGER],
    ['UserAccountControl', ULONG],
    ['EncryptedNtOwfPassword', PUCHAR_ARRAY],
    ['EncryptedLmOwfPassword', PUCHAR_ARRAY],
    ['NtPasswordPresent', UCHAR],
    ['LmPasswordPresent', UCHAR],
    ['PasswordExpired', UCHAR],
    ['UserComment', RPC_UNICODE_STRING],
    ['Parameters', RPC_UNICODE_STRING],
    ['CountryCode', USHORT],
    ['CodePage', USHORT],
    ['PrivateData', NLPR_USER_PRIVATE_INFO],
    ['SecurityInformation', SECURITY_INFORMATION],
    ['SecuritySize', ULONG],
    ['SecurityDescriptor', PUCHAR_ARRAY],
    ['ProfilePath', RPC_UNICODE_STRING],
    ['DummyString2', RPC_UNICODE_STRING],
    ['DummyString3', RPC_UNICODE_STRING],
    ['DummyString4', RPC_UNICODE_STRING],
    ['DummyLong1', ULONG],
    ['DummyLong2', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class PNETLOGON_DELTA_USER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_DELTA_USER]];
}

// 2.2.1.5.25 NETLOGON_RENAME_USER
export class NETLOGON_RENAME_USER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['OldName', RPC_UNICODE_STRING],
    ['NewName', RPC_UNICODE_STRING],
    ['DummyString1', RPC_UNICODE_STRING],
    ['DummyString2', RPC_UNICODE_STRING],
    ['DummyString3', RPC_UNICODE_STRING],
    ['DummyString4', RPC_UNICODE_STRING],
    ['DummyLong1', ULONG],
    ['DummyLong2', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class PNETLOGON_DELTA_RENAME_USER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_RENAME_USER]];
}

// 2.2.1.5.17 NETLOGON_DELTA_GROUP_MEMBER
export class NETLOGON_DELTA_GROUP_MEMBER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Members', PULONG_ARRAY],
    ['Attributes', PULONG_ARRAY],
    ['MemberCount', ULONG],
    ['DummyLong1', ULONG],
    ['DummyLong2', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class PNETLOGON_DELTA_GROUP_MEMBER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_DELTA_GROUP_MEMBER]];
}

// 2.2.1.5.4 NETLOGON_DELTA_ALIAS
export class NETLOGON_DELTA_ALIAS extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Name', RPC_UNICODE_STRING],
    ['RelativeId', ULONG],
    ['SecurityInformation', SECURITY_INFORMATION],
    ['SecuritySize', ULONG],
    ['SecurityDescriptor', PUCHAR_ARRAY],
    ['Comment', RPC_UNICODE_STRING],
    ['DummyString2', RPC_UNICODE_STRING],
    ['DummyString3', RPC_UNICODE_STRING],
    ['DummyString4', RPC_UNICODE_STRING],
    ['DummyLong1', ULONG],
    ['DummyLong2', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class PNETLOGON_DELTA_ALIAS extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_DELTA_ALIAS]];
}

// 2.2.1.5.23 NETLOGON_RENAME_ALIAS
export class NETLOGON_RENAME_ALIAS extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['OldName', RPC_UNICODE_STRING],
    ['NewName', RPC_UNICODE_STRING],
    ['DummyString1', RPC_UNICODE_STRING],
    ['DummyString2', RPC_UNICODE_STRING],
    ['DummyString3', RPC_UNICODE_STRING],
    ['DummyString4', RPC_UNICODE_STRING],
    ['DummyLong1', ULONG],
    ['DummyLong2', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class PNETLOGON_DELTA_RENAME_ALIAS extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_RENAME_ALIAS]];
}

// 2.2.1.5.19 NETLOGON_DELTA_POLICY
export class NETLOGON_DELTA_POLICY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['MaximumLogSize', ULONG],
    ['AuditRetentionPeriod', OLD_LARGE_INTEGER],
    ['AuditingMode', UCHAR],
    ['MaximumAuditEventCount', ULONG],
    ['EventAuditingOptions', PULONG_ARRAY],
    ['PrimaryDomainName', RPC_UNICODE_STRING],
    ['PrimaryDomainSid', PRPC_SID],
    ['QuotaLimits', NLPR_QUOTA_LIMITS],
    ['ModifiedId', OLD_LARGE_INTEGER],
    ['DatabaseCreationTime', OLD_LARGE_INTEGER],
    ['SecurityInformation', SECURITY_INFORMATION],
    ['SecuritySize', ULONG],
    ['SecurityDescriptor', PUCHAR_ARRAY],
    ['DummyString1', RPC_UNICODE_STRING],
    ['DummyString2', RPC_UNICODE_STRING],
    ['DummyString3', RPC_UNICODE_STRING],
    ['DummyString4', RPC_UNICODE_STRING],
    ['DummyLong1', ULONG],
    ['DummyLong2', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class PNETLOGON_DELTA_POLICY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_DELTA_POLICY]];
}

// 2.2.1.5.22 NETLOGON_DELTA_TRUSTED_DOMAINS
export class NETLOGON_DELTA_TRUSTED_DOMAINS extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['DomainName', RPC_UNICODE_STRING],
    ['NumControllerEntries', ULONG],
    ['ControllerNames', PRPC_UNICODE_STRING_ARRAY],
    ['SecurityInformation', SECURITY_INFORMATION],
    ['SecuritySize', ULONG],
    ['SecurityDescriptor', PUCHAR_ARRAY],
    ['DummyString1', RPC_UNICODE_STRING],
    ['DummyString2', RPC_UNICODE_STRING],
    ['DummyString3', RPC_UNICODE_STRING],
    ['DummyString4', RPC_UNICODE_STRING],
    ['DummyLong1', ULONG],
    ['DummyLong2', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class PNETLOGON_DELTA_TRUSTED_DOMAINS extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_DELTA_TRUSTED_DOMAINS]];
}

// 2.2.1.5.20 NLPR_CR_CIPHER_VALUE
export class UCHAR_ARRAY2 extends NDRUniConformantVaryingArray {
  static item = UCHAR;
}

export class PUCHAR_ARRAY2 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', UCHAR_ARRAY2]];
}

export class NLPR_CR_CIPHER_VALUE extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Length', ULONG],
    ['MaximumLength', ULONG],
    ['Buffer', PUCHAR_ARRAY2],
  ];
}

// 2.2.1.5.21 NETLOGON_DELTA_SECRET
export class NETLOGON_DELTA_SECRET extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['CurrentValue', NLPR_CR_CIPHER_VALUE],
    ['CurrentValueSetTime', OLD_LARGE_INTEGER],
    ['OldValue', NLPR_CR_CIPHER_VALUE],
    ['OldValueSetTime', OLD_LARGE_INTEGER],
    ['SecurityInformation', SECURITY_INFORMATION],
    ['SecuritySize', ULONG],
    ['SecurityDescriptor', PUCHAR_ARRAY],
    ['DummyString1', RPC_UNICODE_STRING],
    ['DummyString2', RPC_UNICODE_STRING],
    ['DummyString3', RPC_UNICODE_STRING],
    ['DummyString4', RPC_UNICODE_STRING],
    ['DummyLong1', ULONG],
    ['DummyLong2', ULONG],
    ['DummyLong3', ULONG],
    ['DummyLong4', ULONG],
  ];
}

export class PNETLOGON_DELTA_SECRET extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_DELTA_SECRET]];
}

// 2.2.1.5.26 NLPR_MODIFIED_COUNT
export class NLPR_MODIFIED_COUNT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ModifiedCount', OLD_LARGE_INTEGER],
  ];
}

export class PNLPR_MODIFIED_COUNT extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NLPR_MODIFIED_COUNT]];
}

// 2.2.1.5.28 NETLOGON_DELTA_TYPE
export class NETLOGON_DELTA_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    1: 'AddOrChangeDomain',
    2: 'AddOrChangeGroup',
    3: 'DeleteGroup',
    4: 'RenameGroup',
    5: 'AddOrChangeUser',
    6: 'DeleteUser',
    7: 'RenameUser',
    8: 'ChangeGroupMembership',
    9: 'AddOrChangeAlias',
    10: 'DeleteAlias',
    11: 'RenameAlias',
    12: 'ChangeAliasMembership',
    13: 'AddOrChangeLsaPolicy',
    14: 'AddOrChangeLsaTDomain',
    15: 'DeleteLsaTDomain',
    16: 'AddOrChangeLsaAccount',
    17: 'DeleteLsaAccount',
    18: 'AddOrChangeLsaSecret',
    19: 'DeleteLsaSecret',
    20: 'DeleteGroupByName',
    21: 'DeleteUserByName',
    22: 'SerialNumberSkip',
  };
}

// 2.2.1.5.27 NETLOGON_DELTA_UNION
export class NETLOGON_DELTA_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['DeltaDomain', PNETLOGON_DELTA_DOMAIN],
    2: ['DeltaGroup', PNETLOGON_DELTA_GROUP],
    4: ['DeltaRenameGroup', PNETLOGON_DELTA_RENAME_GROUP],
    5: ['DeltaUser', PNETLOGON_DELTA_USER],
    7: ['DeltaRenameUser', PNETLOGON_DELTA_RENAME_USER],
    8: ['DeltaGroupMember', PNETLOGON_DELTA_GROUP_MEMBER],
    9: ['DeltaAlias', PNETLOGON_DELTA_ALIAS],
    11: ['DeltaRenameAlias', PNETLOGON_DELTA_RENAME_ALIAS],
    12: ['DeltaAliasMember', PNETLOGON_DELTA_ALIAS_MEMBER],
    13: ['DeltaPolicy', PNETLOGON_DELTA_POLICY],
    14: ['DeltaTDomains', PNETLOGON_DELTA_TRUSTED_DOMAINS],
    16: ['DeltaAccounts', PNETLOGON_DELTA_ACCOUNTS],
    18: ['DeltaSecret', PNETLOGON_DELTA_SECRET],
    20: ['DeltaDeleteGroup', PNETLOGON_DELTA_DELETE_GROUP],
    21: ['DeltaDeleteUser', PNETLOGON_DELTA_DELETE_USER],
    22: ['DeltaSerialNumberSkip', PNLPR_MODIFIED_COUNT],
  };
}

// 2.2.1.5.18 NETLOGON_DELTA_ID_UNION
export class NETLOGON_DELTA_ID_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['Rid', ULONG],
    2: ['Rid', ULONG],
    3: ['Rid', ULONG],
    4: ['Rid', ULONG],
    5: ['Rid', ULONG],
    6: ['Rid', ULONG],
    7: ['Rid', ULONG],
    8: ['Rid', ULONG],
    9: ['Rid', ULONG],
    10: ['Rid', ULONG],
    11: ['Rid', ULONG],
    12: ['Rid', ULONG],
    20: ['Rid', ULONG],
    21: ['Rid', ULONG],
    13: ['Sid', PRPC_SID],
    14: ['Sid', PRPC_SID],
    15: ['Sid', PRPC_SID],
    16: ['Sid', PRPC_SID],
    17: ['Sid', PRPC_SID],
    18: ['Name', LPWSTR],
    19: ['Name', LPWSTR],
  };
}

// 2.2.1.5.11 NETLOGON_DELTA_ENUM
export class NETLOGON_DELTA_ENUM extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['DeltaType', NETLOGON_DELTA_TYPE],
    ['DeltaID', NETLOGON_DELTA_ID_UNION],
    ['DeltaUnion', NETLOGON_DELTA_UNION],
  ];
}

// 2.2.1.5.12 NETLOGON_DELTA_ENUM_ARRAY
export class NETLOGON_DELTA_ENUM_ARRAY_ARRAY extends NDRUniConformantArray {
  static item = NETLOGON_DELTA_ENUM;
}

export class PNETLOGON_DELTA_ENUM_ARRAY_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_DELTA_ENUM_ARRAY_ARRAY]];
}

export class NETLOGON_DELTA_ENUM_ARRAY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['CountReturned', DWORD],
    ['Deltas', PNETLOGON_DELTA_ENUM_ARRAY_ARRAY],
  ];
}

export class PNETLOGON_DELTA_ENUM_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_DELTA_ENUM_ARRAY]];
}

// 2.2.1.5.29 SYNC_STATE
export class SYNC_STATE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'NormalState',
    1: 'DomainState',
    2: 'GroupState',
    3: 'UasBuiltInGroupState',
    4: 'UserState',
    5: 'GroupMemberState',
    6: 'AliasState',
    7: 'AliasMemberState',
    8: 'SamDoneState',
  };
}

// 2.2.1.6.1 DOMAIN_NAME_BUFFER
export class DOMAIN_NAME_BUFFER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['DomainNameByteCount', ULONG],
    ['DomainNames', PUCHAR_ARRAY],
  ];
}

// 2.2.1.6.2 DS_DOMAIN_TRUSTSW
export class DS_DOMAIN_TRUSTSW extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['NetbiosDomainName', LPWSTR],
    ['DnsDomainName', LPWSTR],
    ['Flags', ULONG],
    ['ParentIndex', ULONG],
    ['TrustType', ULONG],
    ['TrustAttributes', ULONG],
    ['DomainSid', PRPC_SID],
    ['DomainGuid', GUID],
  ];
}

// 2.2.1.6.3 NETLOGON_TRUSTED_DOMAIN_ARRAY
export class DS_DOMAIN_TRUSTSW_ARRAY extends NDRUniConformantArray {
  static item = DS_DOMAIN_TRUSTSW;
}

export class PDS_DOMAIN_TRUSTSW_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DS_DOMAIN_TRUSTSW_ARRAY]];
}

export class NETLOGON_TRUSTED_DOMAIN_ARRAY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['DomainCount', DWORD],
    ['Domains', PDS_DOMAIN_TRUSTSW_ARRAY],
  ];
}

// 2.2.1.6.4 NL_GENERIC_RPC_DATA
export class NL_GENERIC_RPC_DATA extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['UlongEntryCount', ULONG],
    ['UlongData', PULONG_ARRAY],
    ['UnicodeStringEntryCount', ULONG],
    ['UnicodeStringData', PRPC_UNICODE_STRING_ARRAY],
  ];
}

export class PNL_GENERIC_RPC_DATA extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NL_GENERIC_RPC_DATA]];
}

// 2.2.1.7.1 NETLOGON_CONTROL_DATA_INFORMATION
export class NETLOGON_CONTROL_DATA_INFORMATION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    5: ['TrustedDomainName', LPWSTR],
    6: ['TrustedDomainName', LPWSTR],
    9: ['TrustedDomainName', LPWSTR],
    10: ['TrustedDomainName', LPWSTR],
    65534: ['DebugFlag', DWORD],
    8: ['UserName', LPWSTR],
  };
}

// 2.2.1.7.2 NETLOGON_INFO_1
export class NETLOGON_INFO_1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['netlog1_flags', DWORD],
    ['netlog1_pdc_connection_status', NET_API_STATUS],
  ];
}

export class PNETLOGON_INFO_1 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_INFO_1]];
}

// 2.2.1.7.3 NETLOGON_INFO_2
export class NETLOGON_INFO_2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['netlog2_flags', DWORD],
    ['netlog2_pdc_connection_status', NET_API_STATUS],
    ['netlog2_trusted_dc_name', LPWSTR],
    ['netlog2_tc_connection_status', NET_API_STATUS],
  ];
}

export class PNETLOGON_INFO_2 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_INFO_2]];
}

// 2.2.1.7.4 NETLOGON_INFO_3
export class NETLOGON_INFO_3 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['netlog3_flags', DWORD],
    ['netlog3_logon_attempts', DWORD],
    ['netlog3_reserved1', DWORD],
    ['netlog3_reserved2', DWORD],
    ['netlog3_reserved3', DWORD],
    ['netlog3_reserved4', DWORD],
    ['netlog3_reserved5', DWORD],
  ];
}

export class PNETLOGON_INFO_3 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_INFO_3]];
}

// 2.2.1.7.5 NETLOGON_INFO_4
export class NETLOGON_INFO_4 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['netlog4_trusted_dc_name', LPWSTR],
    ['netlog4_trusted_domain_name', LPWSTR],
  ];
}

export class PNETLOGON_INFO_4 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_INFO_4]];
}

// 2.2.1.7.6 NETLOGON_CONTROL_QUERY_INFORMATION
export class NETLOGON_CONTROL_QUERY_INFORMATION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['NetlogonInfo1', PNETLOGON_INFO_1],
    2: ['NetlogonInfo2', PNETLOGON_INFO_2],
    3: ['NetlogonInfo3', PNETLOGON_INFO_3],
    4: ['NetlogonInfo4', PNETLOGON_INFO_4],
  };
}

// 2.2.1.8.1 NETLOGON_VALIDATION_UAS_INFO
export class NETLOGON_VALIDATION_UAS_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['usrlog1_eff_name', DWORD],
    ['usrlog1_priv', DWORD],
    ['usrlog1_auth_flags', DWORD],
    ['usrlog1_num_logons', DWORD],
    ['usrlog1_bad_pw_count', DWORD],
    ['usrlog1_last_logon', DWORD],
    ['usrlog1_last_logoff', DWORD],
    ['usrlog1_logoff_time', DWORD],
    ['usrlog1_kickoff_time', DWORD],
    ['usrlog1_password_age', DWORD],
    ['usrlog1_pw_can_change', DWORD],
    ['usrlog1_pw_must_change', DWORD],
    ['usrlog1_computer', LPWSTR],
    ['usrlog1_domain', LPWSTR],
    ['usrlog1_script_path', LPWSTR],
    ['usrlog1_reserved1', DWORD],
  ];
}

export class PNETLOGON_VALIDATION_UAS_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NETLOGON_VALIDATION_UAS_INFO]];
}

// 2.2.1.8.2 NETLOGON_LOGOFF_UAS_INFO
export class NETLOGON_LOGOFF_UAS_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Duration', DWORD],
    ['LogonCount', USHORT],
  ];
}

// 2.2.1.8.3 UAS_INFO_0
export class UAS_INFO_0 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ComputerName', '16s=""'],
    ['TimeCreated', ULONG],
    ['SerialNumber', ULONG],
  ];
  getAlignment(): number { return 4; }
}

// 2.2.1.8.4 NETLOGON_DUMMY1
export class NETLOGON_DUMMY1 extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['Dummy', ULONG],
  };
}

// 3.5.4.8.2 NetrLogonComputeServerDigest (Opnum 24)
export class CHAR_FIXED_16_ARRAY extends NDRUniFixedArray {
  getDataLen(data: Buffer, offset = 0): number { return 16; }
}

// =============================================================================
// SSPI
// =============================================================================

// Constants
export const NL_AUTH_MESSAGE_NETBIOS_DOMAIN    = 0x1;
export const NL_AUTH_MESSAGE_NETBIOS_HOST      = 0x2;
export const NL_AUTH_MESSAGE_DNS_DOMAIN        = 0x4;
export const NL_AUTH_MESSAGE_DNS_HOST          = 0x8;
export const NL_AUTH_MESSAGE_NETBIOS_HOST_UTF8 = 0x10;

export const NL_AUTH_MESSAGE_REQUEST  = 0x0;
export const NL_AUTH_MESSAGE_RESPONSE = 0x1;

export const NL_SIGNATURE_HMAC_MD5    = 0x77;
export const NL_SIGNATURE_HMAC_SHA256 = 0x13;
export const NL_SEAL_NOT_ENCRYPTED    = 0xffff;
export const NL_SEAL_RC4              = 0x7A;
export const NL_SEAL_AES128           = 0x1A;

// Structures
export class NL_AUTH_MESSAGE extends Structure {
  static structure: FieldDescriptor[] = [
    ['MessageType', '<L=0'],
    ['Flags', '<L=0'],
    ['Buffer', ':'],
  ];
  constructor(data?: Buffer) {
    super(data);
    if (!data) {
      this.set('Buffer', Buffer.alloc(4));
    }
  }
}

export class NL_AUTH_SIGNATURE extends Structure {
  static structure: FieldDescriptor[] = [
    ['SignatureAlgorithm', '<H=0'],
    ['SealAlgorithm', '<H=0'],
    ['Pad', '<H=0xffff'],
    ['Flags', '<H=0'],
    ['SequenceNumber', '8s=""'],
    ['Checksum', '8s=""'],
    ['_Confounder', '_-Confounder', '8'],
    ['Confounder', ':'],
  ];
  constructor(data?: Buffer) {
    super(data);
    if (!data) {
      this.set('Confounder', '');
    }
  }
}

export class NL_AUTH_SHA2_SIGNATURE extends Structure {
  static structure: FieldDescriptor[] = [
    ['SignatureAlgorithm', '<H=0'],
    ['SealAlgorithm', '<H=0'],
    ['Pad', '<H=0xffff'],
    ['Flags', '<H=0'],
    ['SequenceNumber', '8s=""'],
    ['Checksum', '8s=""'],
    ['_Confounder', '_-Confounder', '8'],
    ['Confounder', ':'],
    ['Reserved', '24s=""'],
  ];
  constructor(data?: Buffer) {
    super(data);
    if (!data) {
      this.set('Confounder', '');
    }
  }
}


// ============================================================================
// CRYPTO FUNCTIONS (Section 3.1.4)
// ============================================================================

// Section 3.1.4.4.2
export function ComputeNetlogonCredential(inputData: Buffer, Sk: Buffer): Buffer {
  const k1 = Sk.subarray(0, 7);
  const k3 = transformKey(k1);
  const k2 = Sk.subarray(7, 14);
  const k4 = transformKey(k2);
  const Crypt1 = createCipheriv('des-ecb', k3, Buffer.alloc(0));
  Crypt1.setAutoPadding(false);
  const Crypt2 = createCipheriv('des-ecb', k4, Buffer.alloc(0));
  Crypt2.setAutoPadding(false);
  const cipherText = Crypt1.update(inputData);
  return Crypt2.update(cipherText);
}

// Section 3.1.4.4.1
export function ComputeNetlogonCredentialAES(inputData: Buffer, Sk: Buffer): Buffer {
  const IV = Buffer.alloc(16, 0);
  const Crypt1 = createCipheriv('aes-128-cfb', Sk, IV);
  return Buffer.concat([Crypt1.update(inputData), Crypt1.final()]);
}

// Section 3.1.4.3.1
export function ComputeSessionKeyAES(
  sharedSecret: string,
  clientChallenge: Buffer,
  serverChallenge: Buffer,
  sharedSecretHash: Buffer | null = null,
): Buffer {
  let M4SS: Buffer;
  if (sharedSecretHash === null) {
    M4SS = ntowfV1(sharedSecret);
  } else {
    M4SS = sharedSecretHash;
  }

  const hm = createHmac('sha256', M4SS);
  hm.update(clientChallenge);
  hm.update(serverChallenge);
  const sessionKey = hm.digest();

  return sessionKey.subarray(0, 16);
}

// Section 3.1.4.3.2 Strong-key Session-Key
export function ComputeSessionKeyStrongKey(
  sharedSecret: string,
  clientChallenge: Buffer,
  serverChallenge: Buffer,
  sharedSecretHash: Buffer | null = null,
): Buffer {
  let M4SS: Buffer;
  if (sharedSecretHash === null) {
    M4SS = ntowfV1(sharedSecret);
  } else {
    M4SS = sharedSecretHash;
  }

  const md5 = createHash('md5');
  md5.update(Buffer.alloc(4, 0));
  md5.update(clientChallenge);
  md5.update(serverChallenge);
  const finalMD5 = md5.digest();
  const hm = createHmac('md5', M4SS);
  hm.update(finalMD5);
  return hm.digest();
}

export function deriveSequenceNumber(sequenceNum: number): Buffer {
  const sequenceLow = sequenceNum & 0xffffffff;
  let sequenceHigh = (Math.floor(sequenceNum / 0x100000000)) & 0xffffffff;
  sequenceHigh |= 0x80000000;

  const res = Buffer.alloc(8);
  res.writeUInt32BE(sequenceLow, 0);
  res.writeUInt32BE(sequenceHigh >>> 0, 4);
  return res;
}

export function ComputeNetlogonSignatureAES(
  authSignature: NL_AUTH_SHA2_SIGNATURE,
  message: Buffer,
  confounder: Buffer,
  sessionKey: Buffer,
): Buffer {
  // [MS-NRPC] Section 3.3.4.2.1, point 7
  const hm = createHmac('sha256', sessionKey);
  hm.update(authSignature.getData().subarray(0, 8));
  // If no confidentiality requested, it should be empty
  hm.update(confounder);
  hm.update(message);
  return hm.digest().subarray(0, 8);
}

export function ComputeNetlogonSignatureMD5(
  authSignature: NL_AUTH_SIGNATURE,
  message: Buffer,
  confounder: Buffer,
  sessionKey: Buffer,
): Buffer {
  // [MS-NRPC] Section 3.3.4.2.1, point 7
  const md5 = createHash('md5');
  md5.update(Buffer.alloc(4, 0));
  md5.update(authSignature.getData().subarray(0, 8));
  // If no confidentiality requested, it should be empty
  md5.update(confounder);
  md5.update(message);
  const finalMD5 = md5.digest();
  const hm = createHmac('md5', sessionKey);
  hm.update(finalMD5);
  return hm.digest().subarray(0, 8);
}

export function ComputeNetlogonAuthenticatorAES(
  clientStoredCredential: Buffer,
  sessionKey: Buffer,
): NETLOGON_AUTHENTICATOR {
  // [MS-NRPC] Section 3.1.4.5
  const timestamp = Math.floor(Date.now() / 1000);

  const authenticator = new NETLOGON_AUTHENTICATOR();
  authenticator.set('Timestamp', timestamp);

  let credential = clientStoredCredential.readUInt32LE(0) + timestamp;
  if (credential > 0xffffffff) {
    credential &= 0xffffffff;
  }
  const credBuf = Buffer.alloc(4);
  credBuf.writeUInt32LE(credential >>> 0, 0);

  const input = Buffer.concat([credBuf, clientStoredCredential.subarray(4)]);
  authenticator.set('Credential', ComputeNetlogonCredentialAES(input, sessionKey));
  return authenticator;
}

export function ComputeNetlogonAuthenticator(
  clientStoredCredential: Buffer,
  sessionKey: Buffer,
): NETLOGON_AUTHENTICATOR {
  // [MS-NRPC] Section 3.1.4.5
  const timestamp = Math.floor(Date.now() / 1000);

  const authenticator = new NETLOGON_AUTHENTICATOR();
  authenticator.set('Timestamp', timestamp);

  let credential = clientStoredCredential.readUInt32LE(0) + timestamp;
  if (credential > 0xffffffff) {
    credential &= 0xffffffff;
  }
  const credBuf = Buffer.alloc(4);
  credBuf.writeUInt32LE(credential >>> 0, 0);

  const input = Buffer.concat([credBuf, clientStoredCredential.subarray(4)]);
  authenticator.set('Credential', ComputeNetlogonCredential(input, sessionKey));
  return authenticator;
}

export function encryptSequenceNumberRC4(
  sequenceNum: Buffer,
  checkSum: Buffer,
  sessionKey: Buffer,
): Buffer {
  // [MS-NRPC] Section 3.3.4.2.1, point 9
  const hm = createHmac('md5', sessionKey);
  hm.update(Buffer.alloc(4, 0));
  const hm2 = createHmac('md5', hm.digest());
  hm2.update(checkSum);
  const encryptionKey = hm2.digest();

  return rc4(encryptionKey, sequenceNum);
}

export function decryptSequenceNumberRC4(
  sequenceNum: Buffer,
  checkSum: Buffer,
  sessionKey: Buffer,
): Buffer {
  // [MS-NRPC] Section 3.3.4.2.2, point 5
  return encryptSequenceNumberRC4(sequenceNum, checkSum, sessionKey);
}

export function encryptSequenceNumberAES(
  sequenceNum: Buffer,
  checkSum: Buffer,
  sessionKey: Buffer,
): Buffer {
  // [MS-NRPC] Section 3.3.4.2.1, point 9
  const IV = Buffer.concat([checkSum.subarray(0, 8), checkSum.subarray(0, 8)]);
  const Cipher = createCipheriv('aes-128-cfb', sessionKey, IV);
  return Buffer.concat([Cipher.update(sequenceNum), Cipher.final()]);
}

export function decryptSequenceNumberAES(
  sequenceNum: Buffer,
  checkSum: Buffer,
  sessionKey: Buffer,
): Buffer {
  // [MS-NRPC] Section 3.3.4.2.1, point 9
  const IV = Buffer.concat([checkSum.subarray(0, 8), checkSum.subarray(0, 8)]);
  const Cipher = createDecipheriv('aes-128-cfb', sessionKey, IV);
  return Buffer.concat([Cipher.update(sequenceNum), Cipher.final()]);
}

export function SIGN(
  data: Buffer,
  confounder: Buffer,
  sequenceNum: number,
  key: Buffer,
  aes: boolean = false,
): NL_AUTH_SIGNATURE | NL_AUTH_SHA2_SIGNATURE {
  if (!aes) {
    const signature = new NL_AUTH_SIGNATURE();
    signature.set('SignatureAlgorithm', NL_SIGNATURE_HMAC_MD5);
    if (confounder.length === 0) {
      signature.set('SealAlgorithm', NL_SEAL_NOT_ENCRYPTED);
    } else {
      signature.set('SealAlgorithm', NL_SEAL_RC4);
    }
    signature.set('Checksum', ComputeNetlogonSignatureMD5(signature, data, confounder, key));
    signature.set('SequenceNumber', encryptSequenceNumberRC4(deriveSequenceNumber(sequenceNum), signature.get('Checksum') as Buffer, key));
    return signature;
  } else {
    const signature = new NL_AUTH_SHA2_SIGNATURE();
    signature.set('SignatureAlgorithm', NL_SIGNATURE_HMAC_SHA256);
    if (confounder.length === 0) {
      signature.set('SealAlgorithm', NL_SEAL_NOT_ENCRYPTED);
    } else {
      signature.set('SealAlgorithm', NL_SEAL_AES128);
    }
    signature.set('Checksum', ComputeNetlogonSignatureAES(signature, data, confounder, key));
    signature.set('SequenceNumber', encryptSequenceNumberAES(deriveSequenceNumber(sequenceNum), signature.get('Checksum') as Buffer, key));
    // 2.2.1.3.3 : Reserved: The sender SHOULD set these bytes to zero, and the receiver MUST ignore them.
    signature.set('Reserved', Buffer.alloc(24, 0));
    return signature;
  }
}

export function SEAL(
  data: Buffer,
  confounder: Buffer,
  sequenceNum: number,
  key: Buffer,
  aes: boolean = false,
): [Buffer, NL_AUTH_SIGNATURE | NL_AUTH_SHA2_SIGNATURE] {
  const signature = SIGN(data, confounder, sequenceNum, key, aes);
  const derivedSeqNum = deriveSequenceNumber(sequenceNum);

  const XorKey = Buffer.from(key);
  for (let i = 0; i < XorKey.length; i++) {
    XorKey[i] = XorKey[i]! ^ 0xf0;
  }

  if (!aes) {
    const hm = createHmac('md5', XorKey);
    hm.update(Buffer.alloc(4, 0));
    const hm2 = createHmac('md5', hm.digest());
    hm2.update(derivedSeqNum);
    const encryptionKey = hm2.digest();

    const cfounder = rc4(encryptionKey, confounder);
    const encrypted = rc4(encryptionKey, data);

    signature.set('Confounder', cfounder);

    return [encrypted, signature];
  } else {
    const IV = Buffer.concat([derivedSeqNum, derivedSeqNum]);
    const cipher = createCipheriv('aes-128-cfb', XorKey, IV);
    const cfounder = cipher.update(confounder);
    const encrypted = cipher.update(data);

    signature.set('Confounder', cfounder);

    return [encrypted, signature];
  }
}

export function UNSEAL(
  data: Buffer,
  authData: Buffer,
  key: Buffer,
  aes: boolean = false,
): [Buffer, Buffer] {
  const auth_data = new NL_AUTH_SIGNATURE(authData);
  const XorKey = Buffer.from(key);
  for (let i = 0; i < XorKey.length; i++) {
    XorKey[i] = XorKey[i]! ^ 0xf0;
  }

  if (!aes) {
    const sequenceNum = decryptSequenceNumberRC4(auth_data.get('SequenceNumber') as Buffer, auth_data.get('Checksum') as Buffer, key);
    const hm = createHmac('md5', XorKey);
    hm.update(Buffer.alloc(4, 0));
    const hm2 = createHmac('md5', hm.digest());
    hm2.update(sequenceNum);
    const encryptionKey = hm2.digest();

    const cfounder = rc4(encryptionKey, auth_data.get('Confounder') as Buffer);
    const plain = rc4(encryptionKey, data);

    return [plain, cfounder];
  } else {
    const sequenceNum = decryptSequenceNumberAES(auth_data.get('SequenceNumber') as Buffer, auth_data.get('Checksum') as Buffer, key);
    const IV = Buffer.concat([sequenceNum, sequenceNum]);
    const cipher = createDecipheriv('aes-128-cfb', XorKey, IV);
    const cfounder = cipher.update(auth_data.get('Confounder') as Buffer);
    const plain = cipher.update(data);
    return [plain, cfounder];
  }
}

export function CompressedUtf8String(domainName: string): Buffer {
  if (domainName === null || domainName === undefined) {
    throw new Error('domain_name cannot be None');
  }

  const MAX_LABEL_LENGTH = 63;

  const buf: number[] = [];
  const labels = domainName.split('.');

  for (const label of labels) {
    const labelBytes = Buffer.from(label, 'utf-8');
    if (labelBytes.length > MAX_LABEL_LENGTH) {
      throw new Error('Label exceeded max length of 63 bytes.');
    }
    buf.push(labelBytes.length);
    for (const b of labelBytes) {
      buf.push(b);
    }
  }
  buf.push(0);

  return Buffer.from(buf);
}

function b(str: string): Buffer {
  return Buffer.from(str, 'ascii');
}

export function getSSPType1(
  workstation: string = '',
  domain: string = '',
  signingRequired: boolean = false,
): NL_AUTH_MESSAGE {
  const auth = new NL_AUTH_MESSAGE();
  auth.set('MessageType', NL_AUTH_MESSAGE_REQUEST);
  auth.set('Flags', 0);

  if (domain !== '') {
    if (domain.includes('.')) {
      auth.set('Flags', NL_AUTH_MESSAGE_NETBIOS_HOST | NL_AUTH_MESSAGE_DNS_DOMAIN);
      if (workstation !== '') {
        auth.set('Buffer', Buffer.concat([b(workstation), Buffer.from([0x00]), CompressedUtf8String(domain)]));
      } else {
        auth.set('Buffer', Buffer.concat([Buffer.from('MYHOST\x00'), CompressedUtf8String(domain)]));
      }
    } else {
      auth.set('Flags', NL_AUTH_MESSAGE_NETBIOS_HOST | NL_AUTH_MESSAGE_NETBIOS_DOMAIN);
      if (workstation !== '') {
        auth.set('Buffer', Buffer.concat([b(domain), Buffer.from([0x00]), b(workstation), Buffer.from([0x00])]));
      } else {
        auth.set('Buffer', Buffer.concat([b(domain), Buffer.from('\x00MYHOST\x00')]));
      }
    }
  } else {
    if (workstation !== '') {
      auth.set('Buffer', Buffer.concat([Buffer.from('WORKGROUP\x00'), b(workstation), Buffer.from([0x00])]));
    } else {
      auth.set('Buffer', Buffer.from('WORKGROUP\x00MYHOST\x00'));
    }
  }

  auth.set('Flags', (auth.get('Flags') as number) | NL_AUTH_MESSAGE_NETBIOS_HOST_UTF8);

  if (workstation !== '') {
    auth.set('Buffer', Buffer.concat([
      auth.get('Buffer') as Buffer,
      Buffer.from([workstation.length]),
      b(workstation),
      Buffer.from([0x00]),
    ]));
  } else {
    auth.set('Buffer', Buffer.concat([auth.get('Buffer') as Buffer, Buffer.from('\x06MYHOST\x00')]));
  }

  return auth;
}

// ============================================================================
// RPC CALLS
// ============================================================================

// 3.5.4.3.1 DsrGetDcNameEx2 (Opnum 34)
export class DsrGetDcNameEx2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['DomainControllerInfo', PDOMAIN_CONTROLLER_INFOW],
    ['ErrorCode', NET_API_STATUS],
  ];
}

export class DsrGetDcNameEx2 extends NDRCALL {
  static opnum = 34;
  static Response = DsrGetDcNameEx2Response;
  static structure: NDRField[] = [
    ['ComputerName', PLOGONSRV_HANDLE],
    ['AccountName', LPWSTR],
    ['AllowableAccountControlBits', ULONG],
    ['DomainName', LPWSTR],
    ['DomainGuid', PGUID],
    ['SiteName', LPWSTR],
    ['Flags', ULONG],
  ];
}

// 3.5.4.3.2 DsrGetDcNameEx (Opnum 27)
export class DsrGetDcNameExResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['DomainControllerInfo', PDOMAIN_CONTROLLER_INFOW],
    ['ErrorCode', NET_API_STATUS],
  ];
}

export class DsrGetDcNameEx extends NDRCALL {
  static opnum = 27;
  static Response = DsrGetDcNameExResponse;
  static structure: NDRField[] = [
    ['ComputerName', PLOGONSRV_HANDLE],
    ['DomainName', LPWSTR],
    ['DomainGuid', PGUID],
    ['SiteName', LPWSTR],
    ['Flags', ULONG],
  ];
}

// 3.5.4.3.3 DsrGetDcName (Opnum 20)
export class DsrGetDcNameResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['DomainControllerInfo', PDOMAIN_CONTROLLER_INFOW],
    ['ErrorCode', NET_API_STATUS],
  ];
}

export class DsrGetDcName extends NDRCALL {
  static opnum = 20;
  static Response = DsrGetDcNameResponse;
  static structure: NDRField[] = [
    ['ComputerName', PLOGONSRV_HANDLE],
    ['DomainName', LPWSTR],
    ['DomainGuid', PGUID],
    ['SiteGuid', PGUID],
    ['Flags', ULONG],
  ];
}

// 3.5.4.3.4 NetrGetDCName (Opnum 11)
export class NetrGetDCNameResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Buffer', LPWSTR],
    ['ErrorCode', NET_API_STATUS],
  ];
}

export class NetrGetDCName extends NDRCALL {
  static opnum = 11;
  static Response = NetrGetDCNameResponse;
  static structure: NDRField[] = [
    ['ServerName', LOGONSRV_HANDLE],
    ['DomainName', LPWSTR],
  ];
}

// 3.5.4.3.5 NetrGetAnyDCName (Opnum 13)
export class NetrGetAnyDCNameResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Buffer', LPWSTR],
    ['ErrorCode', NET_API_STATUS],
  ];
}

export class NetrGetAnyDCName extends NDRCALL {
  static opnum = 13;
  static Response = NetrGetAnyDCNameResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
    ['DomainName', LPWSTR],
  ];
}

// 3.5.4.3.6 DsrGetSiteName (Opnum 28)
export class DsrGetSiteNameResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['SiteName', LPWSTR],
    ['ErrorCode', NET_API_STATUS],
  ];
}

export class DsrGetSiteName extends NDRCALL {
  static opnum = 28;
  static Response = DsrGetSiteNameResponse;
  static structure: NDRField[] = [
    ['ComputerName', PLOGONSRV_HANDLE],
  ];
}

// 3.5.4.3.7 DsrGetDcSiteCoverageW (Opnum 38)
export class DsrGetDcSiteCoverageWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['SiteNames', PNL_SITE_NAME_ARRAY],
    ['ErrorCode', NET_API_STATUS],
  ];
}

export class DsrGetDcSiteCoverageW extends NDRCALL {
  static opnum = 38;
  static Response = DsrGetDcSiteCoverageWResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
  ];
}

// 3.5.4.3.8 DsrAddressToSiteNamesW (Opnum 33)
export class DsrAddressToSiteNamesWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['SiteNames', PNL_SITE_NAME_ARRAY],
    ['ErrorCode', NET_API_STATUS],
  ];
}

export class DsrAddressToSiteNamesW extends NDRCALL {
  static opnum = 33;
  static Response = DsrAddressToSiteNamesWResponse;
  static structure: NDRField[] = [
    ['ComputerName', PLOGONSRV_HANDLE],
    ['EntryCount', ULONG],
    ['SocketAddresses', NL_SOCKET_ADDRESS_ARRAY],
  ];
}

// 3.5.4.3.9 DsrAddressToSiteNamesExW (Opnum 37)
export class DsrAddressToSiteNamesExWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['SiteNames', PNL_SITE_NAME_EX_ARRAY],
    ['ErrorCode', NET_API_STATUS],
  ];
}

export class DsrAddressToSiteNamesExW extends NDRCALL {
  static opnum = 37;
  static Response = DsrAddressToSiteNamesExWResponse;
  static structure: NDRField[] = [
    ['ComputerName', PLOGONSRV_HANDLE],
    ['EntryCount', ULONG],
    ['SocketAddresses', NL_SOCKET_ADDRESS_ARRAY],
  ];
}

// 3.5.4.3.10 DsrDeregisterDnsHostRecords (Opnum 41)
export class DsrDeregisterDnsHostRecordsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ErrorCode', NET_API_STATUS],
  ];
}

export class DsrDeregisterDnsHostRecords extends NDRCALL {
  static opnum = 41;
  static Response = DsrDeregisterDnsHostRecordsResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
    ['DnsDomainName', LPWSTR],
    ['DomainGuid', PGUID],
    ['DsaGuid', PGUID],
    ['DnsHostName', WSTR],
  ];
}

// 3.5.4.3.11 DSRUpdateReadOnlyServerDnsRecords (Opnum 48)
export class DSRUpdateReadOnlyServerDnsRecordsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['DnsNames', NL_DNS_NAME_INFO_ARRAY],
    ['ErrorCode', NTSTATUS],
  ];
}

export class DSRUpdateReadOnlyServerDnsRecords extends NDRCALL {
  static opnum = 48;
  static Response = DSRUpdateReadOnlyServerDnsRecordsResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
    ['ComputerName', WSTR],
    ['Authenticator', NETLOGON_AUTHENTICATOR],
    ['SiteName', LPWSTR],
    ['DnsTtl', ULONG],
    ['DnsNames', NL_DNS_NAME_INFO_ARRAY],
  ];
}

// 3.5.4.4.1 NetrServerReqChallenge (Opnum 4)
export class NetrServerReqChallengeResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ServerChallenge', NETLOGON_CREDENTIAL],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrServerReqChallenge extends NDRCALL {
  static opnum = 4;
  static Response = NetrServerReqChallengeResponse;
  static structure: NDRField[] = [
    ['PrimaryName', PLOGONSRV_HANDLE],
    ['ComputerName', WSTR],
    ['ClientChallenge', NETLOGON_CREDENTIAL],
  ];
}

// 3.5.4.4.2 NetrServerAuthenticate3 (Opnum 26)
export class NetrServerAuthenticate3Response extends NDRCALL {
  static structure: NDRField[] = [
    ['ServerCredential', NETLOGON_CREDENTIAL],
    ['NegotiateFlags', ULONG],
    ['AccountRid', ULONG],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrServerAuthenticate3 extends NDRCALL {
  static opnum = 26;
  static Response = NetrServerAuthenticate3Response;
  static structure: NDRField[] = [
    ['PrimaryName', PLOGONSRV_HANDLE],
    ['AccountName', WSTR],
    ['SecureChannelType', NETLOGON_SECURE_CHANNEL_TYPE],
    ['ComputerName', WSTR],
    ['ClientCredential', NETLOGON_CREDENTIAL],
    ['NegotiateFlags', ULONG],
  ];
}

// 3.5.4.4.3 NetrServerAuthenticate2 (Opnum 15)
export class NetrServerAuthenticate2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['ServerCredential', NETLOGON_CREDENTIAL],
    ['NegotiateFlags', ULONG],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrServerAuthenticate2 extends NDRCALL {
  static opnum = 15;
  static Response = NetrServerAuthenticate2Response;
  static structure: NDRField[] = [
    ['PrimaryName', PLOGONSRV_HANDLE],
    ['AccountName', WSTR],
    ['SecureChannelType', NETLOGON_SECURE_CHANNEL_TYPE],
    ['ComputerName', WSTR],
    ['ClientCredential', NETLOGON_CREDENTIAL],
    ['NegotiateFlags', ULONG],
  ];
}

// 3.5.4.4.4 NetrServerAuthenticate (Opnum 5)
export class NetrServerAuthenticateResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ServerCredential', NETLOGON_CREDENTIAL],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrServerAuthenticate extends NDRCALL {
  static opnum = 5;
  static Response = NetrServerAuthenticateResponse;
  static structure: NDRField[] = [
    ['PrimaryName', PLOGONSRV_HANDLE],
    ['AccountName', WSTR],
    ['SecureChannelType', NETLOGON_SECURE_CHANNEL_TYPE],
    ['ComputerName', WSTR],
    ['ClientCredential', NETLOGON_CREDENTIAL],
  ];
}

// 3.5.4.4.5 NetrServerPasswordSet2 (Opnum 30)
export class NetrServerPasswordSet2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrServerPasswordSet2 extends NDRCALL {
  static opnum = 30;
  static Response = NetrServerPasswordSet2Response;
  static structure: NDRField[] = [
    ['PrimaryName', PLOGONSRV_HANDLE],
    ['AccountName', WSTR],
    ['SecureChannelType', NETLOGON_SECURE_CHANNEL_TYPE],
    ['ComputerName', WSTR],
    ['Authenticator', NETLOGON_AUTHENTICATOR],
    // ['ClearNewPassword', NL_TRUST_PASSWORD],
    ['ClearNewPassword', NL_TRUST_PASSWORD_FIXED_ARRAY],
  ];
}

// 3.5.4.4.6 NetrServerPasswordSet (Opnum 6)

// 3.5.4.4.7 NetrServerPasswordGet (Opnum 31)
export class NetrServerPasswordGetResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['EncryptedNtOwfPassword', ENCRYPTED_NT_OWF_PASSWORD],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrServerPasswordGet extends NDRCALL {
  static opnum = 31;
  static Response = NetrServerPasswordGetResponse;
  static structure: NDRField[] = [
    ['PrimaryName', PLOGONSRV_HANDLE],
    ['AccountName', WSTR],
    ['AccountType', NETLOGON_SECURE_CHANNEL_TYPE],
    ['ComputerName', WSTR],
    ['Authenticator', NETLOGON_AUTHENTICATOR],
  ];
}

// 3.5.4.4.8 NetrServerTrustPasswordsGet (Opnum 42)
export class NetrServerTrustPasswordsGetResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['EncryptedNewOwfPassword', ENCRYPTED_NT_OWF_PASSWORD],
    ['EncryptedOldOwfPassword', ENCRYPTED_NT_OWF_PASSWORD],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrServerTrustPasswordsGet extends NDRCALL {
  static opnum = 42;
  static Response = NetrServerTrustPasswordsGetResponse;
  static structure: NDRField[] = [
    ['TrustedDcName', PLOGONSRV_HANDLE],
    ['AccountName', WSTR],
    ['SecureChannelType', NETLOGON_SECURE_CHANNEL_TYPE],
    ['ComputerName', WSTR],
    ['Authenticator', NETLOGON_AUTHENTICATOR],
  ];
}

// 3.5.4.4.9 NetrLogonGetDomainInfo (Opnum 29)
export class NetrLogonGetDomainInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['DomBuffer', NETLOGON_DOMAIN_INFORMATION],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrLogonGetDomainInfo extends NDRCALL {
  static opnum = 29;
  static Response = NetrLogonGetDomainInfoResponse;
  static structure: NDRField[] = [
    ['ServerName', LOGONSRV_HANDLE],
    ['ComputerName', LPWSTR],
    ['Authenticator', NETLOGON_AUTHENTICATOR],
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['Level', DWORD],
    ['WkstaBuffer', NETLOGON_WORKSTATION_INFORMATION],
  ];
}

// 3.5.4.4.10 NetrLogonGetCapabilities (Opnum 21)
export class NetrLogonGetCapabilitiesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['ServerCapabilities', NETLOGON_CAPABILITIES],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrLogonGetCapabilities extends NDRCALL {
  static opnum = 21;
  static Response = NetrLogonGetCapabilitiesResponse;
  static structure: NDRField[] = [
    ['ServerName', LOGONSRV_HANDLE],
    ['ComputerName', LPWSTR],
    ['Authenticator', NETLOGON_AUTHENTICATOR],
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['QueryLevel', DWORD],
  ];
}

// 3.5.4.4.11 NetrChainSetClientAttributes (Opnum 49)

// 3.5.4.5.1 NetrLogonSamLogonEx (Opnum 39)
export class NetrLogonSamLogonExResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ValidationInformation', NETLOGON_VALIDATION],
    ['Authoritative', UCHAR],
    ['ExtraFlags', ULONG],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrLogonSamLogonEx extends NDRCALL {
  static opnum = 39;
  static Response = NetrLogonSamLogonExResponse;
  static structure: NDRField[] = [
    ['LogonServer', LPWSTR],
    ['ComputerName', LPWSTR],
    ['LogonLevel', NETLOGON_LOGON_INFO_CLASS],
    ['LogonInformation', NETLOGON_LEVEL],
    ['ValidationLevel', NETLOGON_VALIDATION_INFO_CLASS],
    ['ExtraFlags', ULONG],
  ];
}

// 3.5.4.5.2 NetrLogonSamLogonWithFlags (Opnum 45)
export class NetrLogonSamLogonWithFlagsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ReturnAuthenticator', PNETLOGON_AUTHENTICATOR],
    ['ValidationInformation', NETLOGON_VALIDATION],
    ['Authoritative', UCHAR],
    ['ExtraFlags', ULONG],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrLogonSamLogonWithFlags extends NDRCALL {
  static opnum = 45;
  static Response = NetrLogonSamLogonWithFlagsResponse;
  static structure: NDRField[] = [
    ['LogonServer', LPWSTR],
    ['ComputerName', LPWSTR],
    ['Authenticator', PNETLOGON_AUTHENTICATOR],
    ['ReturnAuthenticator', PNETLOGON_AUTHENTICATOR],
    ['LogonLevel', NETLOGON_LOGON_INFO_CLASS],
    ['LogonInformation', NETLOGON_LEVEL],
    ['ValidationLevel', NETLOGON_VALIDATION_INFO_CLASS],
    ['ExtraFlags', ULONG],
  ];
}

// 3.5.4.5.3 NetrLogonSamLogon (Opnum 2)
export class NetrLogonSamLogonResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ReturnAuthenticator', PNETLOGON_AUTHENTICATOR],
    ['ValidationInformation', NETLOGON_VALIDATION],
    ['Authoritative', UCHAR],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrLogonSamLogon extends NDRCALL {
  static opnum = 2;
  static Response = NetrLogonSamLogonResponse;
  static structure: NDRField[] = [
    ['LogonServer', LPWSTR],
    ['ComputerName', LPWSTR],
    ['Authenticator', PNETLOGON_AUTHENTICATOR],
    ['ReturnAuthenticator', PNETLOGON_AUTHENTICATOR],
    ['LogonLevel', NETLOGON_LOGON_INFO_CLASS],
    ['LogonInformation', NETLOGON_LEVEL],
    ['ValidationLevel', NETLOGON_VALIDATION_INFO_CLASS],
  ];
}

// 3.5.4.5.4 NetrLogonSamLogoff (Opnum 3)
export class NetrLogonSamLogoffResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ReturnAuthenticator', PNETLOGON_AUTHENTICATOR],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrLogonSamLogoff extends NDRCALL {
  static opnum = 3;
  static Response = NetrLogonSamLogoffResponse;
  static structure: NDRField[] = [
    ['LogonServer', LPWSTR],
    ['ComputerName', LPWSTR],
    ['Authenticator', PNETLOGON_AUTHENTICATOR],
    ['ReturnAuthenticator', PNETLOGON_AUTHENTICATOR],
    ['LogonLevel', NETLOGON_LOGON_INFO_CLASS],
    ['LogonInformation', NETLOGON_LEVEL],
  ];
}

// 3.5.4.6.1 NetrDatabaseDeltas (Opnum 7)
export class NetrDatabaseDeltasResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['DomainModifiedCount', NLPR_MODIFIED_COUNT],
    ['DeltaArray', PNETLOGON_DELTA_ENUM_ARRAY],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrDatabaseDeltas extends NDRCALL {
  static opnum = 7;
  static Response = NetrDatabaseDeltasResponse;
  static structure: NDRField[] = [
    ['PrimaryName', LOGONSRV_HANDLE],
    ['ComputerName', WSTR],
    ['Authenticator', NETLOGON_AUTHENTICATOR],
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['DatabaseID', DWORD],
    ['DomainModifiedCount', NLPR_MODIFIED_COUNT],
    ['PreferredMaximumLength', DWORD],
  ];
}

// 3.5.4.6.2 NetrDatabaseSync2 (Opnum 16)
export class NetrDatabaseSync2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['SyncContext', ULONG],
    ['DeltaArray', PNETLOGON_DELTA_ENUM_ARRAY],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrDatabaseSync2 extends NDRCALL {
  static opnum = 16;
  static Response = NetrDatabaseSync2Response;
  static structure: NDRField[] = [
    ['PrimaryName', LOGONSRV_HANDLE],
    ['ComputerName', WSTR],
    ['Authenticator', NETLOGON_AUTHENTICATOR],
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['DatabaseID', DWORD],
    ['RestartState', SYNC_STATE],
    ['SyncContext', ULONG],
    ['PreferredMaximumLength', DWORD],
  ];
}

// 3.5.4.6.3 NetrDatabaseSync (Opnum 8)
export class NetrDatabaseSyncResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['SyncContext', ULONG],
    ['DeltaArray', PNETLOGON_DELTA_ENUM_ARRAY],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrDatabaseSync extends NDRCALL {
  static opnum = 8;
  static Response = NetrDatabaseSyncResponse;
  static structure: NDRField[] = [
    ['PrimaryName', LOGONSRV_HANDLE],
    ['ComputerName', WSTR],
    ['Authenticator', NETLOGON_AUTHENTICATOR],
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['DatabaseID', DWORD],
    ['SyncContext', ULONG],
    ['PreferredMaximumLength', DWORD],
  ];
}

// 3.5.4.6.4 NetrDatabaseRedo (Opnum 17)
export class NetrDatabaseRedoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['DeltaArray', PNETLOGON_DELTA_ENUM_ARRAY],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrDatabaseRedo extends NDRCALL {
  static opnum = 17;
  static Response = NetrDatabaseRedoResponse;
  static structure: NDRField[] = [
    ['PrimaryName', LOGONSRV_HANDLE],
    ['ComputerName', WSTR],
    ['Authenticator', NETLOGON_AUTHENTICATOR],
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['ChangeLogEntry', PUCHAR_ARRAY],
    ['ChangeLogEntrySize', DWORD],
  ];
}

// 3.5.4.7.1 DsrEnumerateDomainTrusts (Opnum 40)
export class DsrEnumerateDomainTrustsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Domains', NETLOGON_TRUSTED_DOMAIN_ARRAY],
    ['ErrorCode', NTSTATUS],
  ];
}

export class DsrEnumerateDomainTrusts extends NDRCALL {
  static opnum = 40;
  static Response = DsrEnumerateDomainTrustsResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
    ['Flags', ULONG],
  ];
}

// 3.5.4.7.2 NetrEnumerateTrustedDomainsEx (Opnum 36)
export class NetrEnumerateTrustedDomainsExResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Domains', NETLOGON_TRUSTED_DOMAIN_ARRAY],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrEnumerateTrustedDomainsEx extends NDRCALL {
  static opnum = 36;
  static Response = NetrEnumerateTrustedDomainsExResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
  ];
}

// 3.5.4.7.3 NetrEnumerateTrustedDomains (Opnum 19)
export class NetrEnumerateTrustedDomainsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['DomainNameBuffer', DOMAIN_NAME_BUFFER],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrEnumerateTrustedDomains extends NDRCALL {
  static opnum = 19;
  static Response = NetrEnumerateTrustedDomainsResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
  ];
}

// 3.5.4.7.4 NetrGetForestTrustInformation (Opnum 44)
export class NetrGetForestTrustInformationResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['ForestTrustInfo', PLSA_FOREST_TRUST_INFORMATION],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrGetForestTrustInformation extends NDRCALL {
  static opnum = 44;
  static Response = NetrGetForestTrustInformationResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
    ['ComputerName', WSTR],
    ['Authenticator', NETLOGON_AUTHENTICATOR],
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['Flags', DWORD],
  ];
}

// 3.5.4.7.5 DsrGetForestTrustInformation (Opnum 43)
export class DsrGetForestTrustInformationResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ForestTrustInfo', PLSA_FOREST_TRUST_INFORMATION],
    ['ErrorCode', NTSTATUS],
  ];
}

export class DsrGetForestTrustInformation extends NDRCALL {
  static opnum = 43;
  static Response = DsrGetForestTrustInformationResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
    ['TrustedDomainName', LPWSTR],
    ['Flags', DWORD],
  ];
}

// 3.5.4.7.6 NetrServerGetTrustInfo (Opnum 46)
export class NetrServerGetTrustInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['EncryptedNewOwfPassword', ENCRYPTED_NT_OWF_PASSWORD],
    ['EncryptedOldOwfPassword', ENCRYPTED_NT_OWF_PASSWORD],
    ['TrustInfo', PNL_GENERIC_RPC_DATA],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrServerGetTrustInfo extends NDRCALL {
  static opnum = 46;
  static Response = NetrServerGetTrustInfoResponse;
  static structure: NDRField[] = [
    ['TrustedDcName', PLOGONSRV_HANDLE],
    ['AccountName', WSTR],
    ['SecureChannelType', NETLOGON_SECURE_CHANNEL_TYPE],
    ['ComputerName', WSTR],
    ['Authenticator', NETLOGON_AUTHENTICATOR],
  ];
}

// 3.5.4.8.1 NetrLogonGetTrustRid (Opnum 23)
export class NetrLogonGetTrustRidResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Rid', ULONG],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrLogonGetTrustRid extends NDRCALL {
  static opnum = 23;
  static Response = NetrLogonGetTrustRidResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
    ['DomainName', LPWSTR],
  ];
}

// 3.5.4.8.2 NetrLogonComputeServerDigest (Opnum 24)
export class NetrLogonComputeServerDigestResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['NewMessageDigest', CHAR_FIXED_16_ARRAY],
    ['OldMessageDigest', CHAR_FIXED_16_ARRAY],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrLogonComputeServerDigest extends NDRCALL {
  static opnum = 24;
  static Response = NetrLogonComputeServerDigestResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
    ['Rid', ULONG],
    ['Message', UCHAR_ARRAY],
    ['MessageSize', ULONG],
  ];
}

// 3.5.4.8.3 NetrLogonComputeClientDigest (Opnum 25)
export class NetrLogonComputeClientDigestResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['NewMessageDigest', CHAR_FIXED_16_ARRAY],
    ['OldMessageDigest', CHAR_FIXED_16_ARRAY],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrLogonComputeClientDigest extends NDRCALL {
  static opnum = 25;
  static Response = NetrLogonComputeClientDigestResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
    ['DomainName', LPWSTR],
    ['Message', UCHAR_ARRAY],
    ['MessageSize', ULONG],
  ];
}

// 3.5.4.8.4 NetrLogonSendToSam (Opnum 32)
export class NetrLogonSendToSamResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ReturnAuthenticator', NETLOGON_AUTHENTICATOR],
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrLogonSendToSam extends NDRCALL {
  static opnum = 32;
  static Response = NetrLogonSendToSamResponse;
  static structure: NDRField[] = [
    ['PrimaryName', PLOGONSRV_HANDLE],
    ['ComputerName', WSTR],
    ['Authenticator', NETLOGON_AUTHENTICATOR],
    ['OpaqueBuffer', UCHAR_ARRAY],
    ['OpaqueBufferSize', ULONG],
  ];
}

// 3.5.4.8.5 NetrLogonSetServiceBits (Opnum 22)
export class NetrLogonSetServiceBitsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ErrorCode', NTSTATUS],
  ];
}

export class NetrLogonSetServiceBits extends NDRCALL {
  static opnum = 22;
  static Response = NetrLogonSetServiceBitsResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
    ['ServiceBitsOfInterest', DWORD],
    ['ServiceBits', DWORD],
  ];
}

// 3.5.4.8.6 NetrLogonGetTimeServiceParentDomain (Opnum 35)
export class NetrLogonGetTimeServiceParentDomainResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['DomainName', LPWSTR],
    ['PdcSameSite', LONG],
    ['ErrorCode', NET_API_STATUS],
  ];
}

export class NetrLogonGetTimeServiceParentDomain extends NDRCALL {
  static opnum = 35;
  static Response = NetrLogonGetTimeServiceParentDomainResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
  ];
}

// 3.5.4.9.1 NetrLogonControl2Ex (Opnum 18)
export class NetrLogonControl2ExResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Buffer', NETLOGON_CONTROL_QUERY_INFORMATION],
    ['ErrorCode', NET_API_STATUS],
  ];
}

export class NetrLogonControl2Ex extends NDRCALL {
  static opnum = 18;
  static Response = NetrLogonControl2ExResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
    ['FunctionCode', DWORD],
    ['QueryLevel', DWORD],
    ['Data', NETLOGON_CONTROL_DATA_INFORMATION],
  ];
}

// 3.5.4.9.2 NetrLogonControl2 (Opnum 14)
export class NetrLogonControl2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['Buffer', NETLOGON_CONTROL_QUERY_INFORMATION],
    ['ErrorCode', NET_API_STATUS],
  ];
}

export class NetrLogonControl2 extends NDRCALL {
  static opnum = 14;
  static Response = NetrLogonControl2Response;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
    ['FunctionCode', DWORD],
    ['QueryLevel', DWORD],
    ['Data', NETLOGON_CONTROL_DATA_INFORMATION],
  ];
}

// 3.5.4.9.3 NetrLogonControl (Opnum 12)
export class NetrLogonControlResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Buffer', NETLOGON_CONTROL_DATA_INFORMATION],
    ['ErrorCode', NET_API_STATUS],
  ];
}

export class NetrLogonControl extends NDRCALL {
  static opnum = 12;
  static Response = NetrLogonControlResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
    ['FunctionCode', DWORD],
    ['QueryLevel', DWORD],
    ['Data', NETLOGON_CONTROL_DATA_INFORMATION],
  ];
}

// 3.5.4.10.1 NetrLogonUasLogon (Opnum 0)
export class NetrLogonUasLogonResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ValidationInformation', PNETLOGON_VALIDATION_UAS_INFO],
    ['ErrorCode', NET_API_STATUS],
  ];
}

export class NetrLogonUasLogon extends NDRCALL {
  static opnum = 0;
  static Response = NetrLogonUasLogonResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
    ['UserName', WSTR],
    ['Workstation', WSTR],
  ];
}

// 3.5.4.10.2 NetrLogonUasLogoff (Opnum 1)
export class NetrLogonUasLogoffResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['LogoffInformation', NETLOGON_LOGOFF_UAS_INFO],
    ['ErrorCode', NET_API_STATUS],
  ];
}

export class NetrLogonUasLogoff extends NDRCALL {
  static opnum = 1;
  static Response = NetrLogonUasLogoffResponse;
  static structure: NDRField[] = [
    ['ServerName', PLOGONSRV_HANDLE],
    ['UserName', WSTR],
    ['Workstation', WSTR],
  ];
}

// ============================================================================
// OPNUMs and their corresponding structures
// ============================================================================
const OPNUMS: Record<number, readonly [typeof NDRCALL, typeof NDRCALL]> = {
  0: [NetrLogonUasLogon, NetrLogonUasLogonResponse] as const,
  1: [NetrLogonUasLogoff, NetrLogonUasLogoffResponse] as const,
  2: [NetrLogonSamLogon, NetrLogonSamLogonResponse] as const,
  3: [NetrLogonSamLogoff, NetrLogonSamLogoffResponse] as const,
  4: [NetrServerReqChallenge, NetrServerReqChallengeResponse] as const,
  5: [NetrServerAuthenticate, NetrServerAuthenticateResponse] as const,
  // 6: [NetrServerPasswordSet, NetrServerPasswordSetResponse] as const,
  7: [NetrDatabaseDeltas, NetrDatabaseDeltasResponse] as const,
  8: [NetrDatabaseSync, NetrDatabaseSyncResponse] as const,
  // 9: [NetrAccountDeltas, NetrAccountDeltasResponse] as const,
  // 10: [NetrAccountSync, NetrAccountSyncResponse] as const,
  11: [NetrGetDCName, NetrGetDCNameResponse] as const,
  12: [NetrLogonControl, NetrLogonControlResponse] as const,
  13: [NetrGetAnyDCName, NetrGetAnyDCNameResponse] as const,
  14: [NetrLogonControl2, NetrLogonControl2Response] as const,
  15: [NetrServerAuthenticate2, NetrServerAuthenticate2Response] as const,
  16: [NetrDatabaseSync2, NetrDatabaseSync2Response] as const,
  17: [NetrDatabaseRedo, NetrDatabaseRedoResponse] as const,
  18: [NetrLogonControl2Ex, NetrLogonControl2ExResponse] as const,
  19: [NetrEnumerateTrustedDomains, NetrEnumerateTrustedDomainsResponse] as const,
  20: [DsrGetDcName, DsrGetDcNameResponse] as const,
  21: [NetrLogonGetCapabilities, NetrLogonGetCapabilitiesResponse] as const,
  22: [NetrLogonSetServiceBits, NetrLogonSetServiceBitsResponse] as const,
  23: [NetrLogonGetTrustRid, NetrLogonGetTrustRidResponse] as const,
  24: [NetrLogonComputeServerDigest, NetrLogonComputeServerDigestResponse] as const,
  25: [NetrLogonComputeClientDigest, NetrLogonComputeClientDigestResponse] as const,
  26: [NetrServerAuthenticate3, NetrServerAuthenticate3Response] as const,
  27: [DsrGetDcNameEx, DsrGetDcNameExResponse] as const,
  28: [DsrGetSiteName, DsrGetSiteNameResponse] as const,
  29: [NetrLogonGetDomainInfo, NetrLogonGetDomainInfoResponse] as const,
  30: [NetrServerPasswordSet2, NetrServerPasswordSet2Response] as const,
  31: [NetrServerPasswordGet, NetrServerPasswordGetResponse] as const,
  32: [NetrLogonSendToSam, NetrLogonSendToSamResponse] as const,
  33: [DsrAddressToSiteNamesW, DsrAddressToSiteNamesWResponse] as const,
  34: [DsrGetDcNameEx2, DsrGetDcNameEx2Response] as const,
  35: [NetrLogonGetTimeServiceParentDomain, NetrLogonGetTimeServiceParentDomainResponse] as const,
  36: [NetrEnumerateTrustedDomainsEx, NetrEnumerateTrustedDomainsExResponse] as const,
  37: [DsrAddressToSiteNamesExW, DsrAddressToSiteNamesExWResponse] as const,
  38: [DsrGetDcSiteCoverageW, DsrGetDcSiteCoverageWResponse] as const,
  39: [NetrLogonSamLogonEx, NetrLogonSamLogonExResponse] as const,
  40: [DsrEnumerateDomainTrusts, DsrEnumerateDomainTrustsResponse] as const,
  41: [DsrDeregisterDnsHostRecords, DsrDeregisterDnsHostRecordsResponse] as const,
  42: [NetrServerTrustPasswordsGet, NetrServerTrustPasswordsGetResponse] as const,
  43: [DsrGetForestTrustInformation, DsrGetForestTrustInformationResponse] as const,
  44: [NetrGetForestTrustInformation, NetrGetForestTrustInformationResponse] as const,
  45: [NetrLogonSamLogonWithFlags, NetrLogonSamLogonWithFlagsResponse] as const,
  46: [NetrServerGetTrustInfo, NetrServerGetTrustInfoResponse] as const,
  // 48: [DSRUpdateReadOnlyServerDnsRecords, DSRUpdateReadOnlyServerDnsRecordsResponse] as const,
  // 49: [NetrChainSetClientAttributes, NetrChainSetClientAttributesResponse] as const,
};

// ============================================================================
type DceRequestFn = <T>(req: unknown, uuid?: unknown, checkError?: boolean) => Promise<T>;

// HELPER FUNCTIONS
// ============================================================================

function checkNullString(str: string | typeof NULL): string | typeof NULL {
  if (str === NULL) return str;
  if (typeof str !== 'string') return str;
  if (str.length === 0 || str[str.length - 1] !== '\x00') return str + '\x00';
  return str;
}

export async function hNetrServerReqChallenge(
  dce: DCERPC_v5,
  primaryName: string,
  computerName: string,
  clientChallenge: unknown,
): Promise<unknown> {
  const request = new NetrServerReqChallenge();
  request.set('PrimaryName', checkNullString(primaryName));
  request.set('ComputerName', checkNullString(computerName));
  request.set('ClientChallenge', clientChallenge);
  return (dce as unknown as { request: DceRequestFn }).request(request);
}

export async function hNetrServerAuthenticate3(
  dce: DCERPC_v5,
  primaryName: string,
  accountName: string,
  secureChannelType: number,
  computerName: string,
  clientCredential: unknown,
  negotiateFlags: number,
): Promise<unknown> {
  const request = new NetrServerAuthenticate3();
  request.set('PrimaryName', checkNullString(primaryName));
  request.set('AccountName', checkNullString(accountName));
  request.set('SecureChannelType', secureChannelType);
  request.set('ClientCredential', clientCredential);
  request.set('ComputerName', checkNullString(computerName));
  request.set('NegotiateFlags', negotiateFlags);
  return (dce as unknown as { request: DceRequestFn }).request(request);
}

export async function hDsrGetDcNameEx2(
  dce: DCERPC_v5,
  computerName: string,
  accountName: string,
  allowableAccountControlBits: number,
  domainName: string,
  domainGuid: unknown,
  siteName: string,
  flags: number,
): Promise<unknown> {
  const request = new DsrGetDcNameEx2();
  request.set('ComputerName', checkNullString(computerName));
  request.set('AccountName', checkNullString(accountName));
  request.set('AllowableAccountControlBits', allowableAccountControlBits);
  request.set('DomainName', checkNullString(domainName));
  request.set('DomainGuid', domainGuid);
  request.set('SiteName', checkNullString(siteName));
  request.set('Flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request(request);
}

export async function hDsrGetDcNameEx(
  dce: DCERPC_v5,
  computerName: string,
  domainName: string,
  domainGuid: unknown,
  siteName: string,
  flags: number,
): Promise<unknown> {
  const request = new DsrGetDcNameEx();
  request.set('ComputerName', checkNullString(computerName));
  request.set('DomainName', checkNullString(domainName));
  request.set('DomainGuid', domainGuid);
  request.set('SiteName', siteName);
  request.set('Flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request(request);
}

export async function hDsrGetDcName(
  dce: DCERPC_v5,
  computerName: string,
  domainName: string,
  domainGuid: unknown,
  siteGuid: unknown,
  flags: number,
): Promise<unknown> {
  const request = new DsrGetDcName();
  request.set('ComputerName', checkNullString(computerName));
  request.set('DomainName', checkNullString(domainName));
  request.set('DomainGuid', domainGuid);
  request.set('SiteGuid', siteGuid);
  request.set('Flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request(request);
}

export async function hNetrGetAnyDCName(
  dce: DCERPC_v5,
  serverName: string,
  domainName: string,
): Promise<unknown> {
  const request = new NetrGetAnyDCName();
  request.set('ServerName', checkNullString(serverName));
  request.set('DomainName', checkNullString(domainName));
  return (dce as unknown as { request: DceRequestFn }).request(request);
}

export async function hNetrGetDCName(
  dce: DCERPC_v5,
  serverName: string,
  domainName: string,
): Promise<unknown> {
  const request = new NetrGetDCName();
  request.set('ServerName', checkNullString(serverName));
  request.set('DomainName', checkNullString(domainName));
  return (dce as unknown as { request: DceRequestFn }).request(request);
}

export async function hDsrGetSiteName(
  dce: DCERPC_v5,
  computerName: string,
): Promise<unknown> {
  const request = new DsrGetSiteName();
  request.set('ComputerName', checkNullString(computerName));
  return (dce as unknown as { request: DceRequestFn }).request(request);
}

export async function hDsrGetDcSiteCoverageW(
  dce: DCERPC_v5,
  serverName: string,
): Promise<unknown> {
  const request = new DsrGetDcSiteCoverageW();
  request.set('ServerName', checkNullString(serverName));
  return (dce as unknown as { request: DceRequestFn }).request(request);
}

export async function hNetrServerAuthenticate2(
  dce: DCERPC_v5,
  primaryName: string,
  accountName: string,
  secureChannelType: number,
  computerName: string,
  clientCredential: unknown,
  negotiateFlags: number,
): Promise<unknown> {
  const request = new NetrServerAuthenticate2();
  request.set('PrimaryName', checkNullString(primaryName));
  request.set('AccountName', checkNullString(accountName));
  request.set('SecureChannelType', secureChannelType);
  request.set('ClientCredential', clientCredential);
  request.set('ComputerName', checkNullString(computerName));
  request.set('NegotiateFlags', negotiateFlags);
  return (dce as unknown as { request: DceRequestFn }).request(request);
}

export async function hNetrServerAuthenticate(
  dce: DCERPC_v5,
  primaryName: string,
  accountName: string,
  secureChannelType: number,
  computerName: string,
  clientCredential: unknown,
): Promise<unknown> {
  const request = new NetrServerAuthenticate();
  request.set('PrimaryName', checkNullString(primaryName));
  request.set('AccountName', checkNullString(accountName));
  request.set('SecureChannelType', secureChannelType);
  request.set('ClientCredential', clientCredential);
  request.set('ComputerName', checkNullString(computerName));
  return (dce as unknown as { request: DceRequestFn }).request(request);
}

export async function hNetrServerPasswordGet(
  dce: DCERPC_v5,
  primaryName: string,
  accountName: string,
  accountType: number,
  computerName: string,
  authenticator: unknown,
): Promise<unknown> {
  const request = new NetrServerPasswordGet();
  request.set('PrimaryName', checkNullString(primaryName));
  request.set('AccountName', checkNullString(accountName));
  request.set('AccountType', accountType);
  request.set('ComputerName', checkNullString(computerName));
  request.set('Authenticator', authenticator);
  return (dce as unknown as { request: DceRequestFn }).request(request);
}

export async function hNetrServerTrustPasswordsGet(
  dce: DCERPC_v5,
  trustedDcName: string,
  accountName: string,
  secureChannelType: number,
  computerName: string,
  authenticator: unknown,
): Promise<unknown> {
  const request = new NetrServerTrustPasswordsGet();
  request.set('TrustedDcName', checkNullString(trustedDcName));
  request.set('AccountName', checkNullString(accountName));
  request.set('SecureChannelType', secureChannelType);
  request.set('ComputerName', checkNullString(computerName));
  request.set('Authenticator', authenticator);
  return (dce as unknown as { request: DceRequestFn }).request(request);
}

export async function hNetrServerPasswordSet2(
  dce: DCERPC_v5,
  primaryName: string,
  accountName: string,
  secureChannelType: number,
  computerName: string,
  authenticator: unknown,
  clearNewPasswordBlob: unknown,
): Promise<unknown> {
  const request = new NetrServerPasswordSet2();
  request.set('PrimaryName', checkNullString(primaryName));
  request.set('AccountName', checkNullString(accountName));
  request.set('SecureChannelType', secureChannelType);
  request.set('ComputerName', checkNullString(computerName));
  request.set('Authenticator', authenticator);
  request.set('ClearNewPassword', clearNewPasswordBlob);
  return (dce as unknown as { request: DceRequestFn }).request(request);
}

export async function hNetrLogonGetDomainInfo(
  dce: DCERPC_v5,
  serverName: string,
  computerName: string,
  authenticator: unknown,
  returnAuthenticator: unknown = 0,
  level: number = 1,
): Promise<unknown> {
  const request = new NetrLogonGetDomainInfo();
  request.set('ServerName', checkNullString(serverName));
  request.set('ComputerName', checkNullString(computerName));
  request.set('Authenticator', authenticator);
  if (returnAuthenticator === 0) {
    const retAuth = request.fields['ReturnAuthenticator'] as NETLOGON_AUTHENTICATOR;
    retAuth.set('Credential', Buffer.alloc(8, 0));
    retAuth.set('Timestamp', 0);
  } else {
    request.set('ReturnAuthenticator', returnAuthenticator);
  }

  request.set('Level', 1);
  if (level === 1) {
    const wb = request.fields['WkstaBuffer'] as NDRUNION;
    wb.set('tag', 1);
    const wi = wb.get('WorkstationInfo') as NDRSTRUCT;
    wi.set('DnsHostName', NULL);
    wi.set('SiteName', NULL);
    wi.set('OsName', '');
    wi.set('Dummy1', NULL);
    wi.set('Dummy2', NULL);
    wi.set('Dummy3', NULL);
    wi.set('Dummy4', NULL);
  } else {
    const wb = request.fields['WkstaBuffer'] as NDRUNION;
    wb.set('tag', 2);
    const lpi = wb.get('LsaPolicyInfo') as NDRSTRUCT;
    lpi.set('LsaPolicy', NULL);
  }
  return (dce as unknown as { request: DceRequestFn }).request(request);
}

export async function hNetrLogonGetCapabilities(
  dce: DCERPC_v5,
  serverName: string,
  computerName: string,
  authenticator: unknown,
  returnAuthenticator: unknown = 0,
  queryLevel: number = 1,
): Promise<unknown> {
  const request = new NetrLogonGetCapabilities();
  request.set('ServerName', checkNullString(serverName));
  request.set('ComputerName', checkNullString(computerName));
  request.set('Authenticator', authenticator);
  if (returnAuthenticator === 0) {
    const retAuth = request.fields['ReturnAuthenticator'] as NETLOGON_AUTHENTICATOR;
    retAuth.set('Credential', Buffer.alloc(8, 0));
    retAuth.set('Timestamp', 0);
  } else {
    request.set('ReturnAuthenticator', returnAuthenticator);
  }
  request.set('QueryLevel', queryLevel);
  return (dce as unknown as { request: DceRequestFn }).request(request);
}

export async function hNetrServerGetTrustInfo(
  dce: DCERPC_v5,
  trustedDcName: string,
  accountName: string,
  secureChannelType: number,
  computerName: string,
  authenticator: unknown,
): Promise<unknown> {
  const request = new NetrServerGetTrustInfo();
  request.set('TrustedDcName', checkNullString(trustedDcName));
  request.set('AccountName', checkNullString(accountName));
  request.set('SecureChannelType', secureChannelType);
  request.set('ComputerName', checkNullString(computerName));
  request.set('Authenticator', authenticator);
  return (dce as unknown as { request: DceRequestFn }).request(request);
}
