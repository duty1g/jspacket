import { uuidtupToBin } from '@impacket/uuid';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRUNION,
  NDRPOINTER,
  NDRUniConformantArray,
  NDRENUM,
  NULL,
  type NDRField,
} from './ndr';
import { LPWSTR, ULONG, DWORD, BOOL, BYTE, LPDWORD, WORD } from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_DHCPSRV = uuidtupToBin([
  '6BFFD098-A112-3610-9833-46C3F874532D',
  '1.0',
]);
export const MSRPC_UUID_DHCPSRV2 = uuidtupToBin([
  '5B821720-F63B-11D0-AAD2-00C04FC324DB',
  '1.0',
]);

////////////////////////////////////////////////////////////////////////////////
// CONSTANTS
////////////////////////////////////////////////////////////////////////////////
export const DHCP_SRV_HANDLE = LPWSTR;
export const DHCP_IP_ADDRESS = DWORD;
export const DHCP_IP_MASK = DWORD;
export const DHCP_OPTION_ID = DWORD;

// DHCP enumeration flags
export const DHCP_FLAGS_OPTION_DEFAULT = 0x00000000;
export const DHCP_FLAGS_OPTION_IS_VENDOR = 0x00000003;

// Errors
export const ERROR_DHCP_REGISTRY_INIT_FAILED = 0x00004e20;
export const ERROR_DHCP_DATABASE_INIT_FAILED = 0x00004e21;
export const ERROR_DHCP_RPC_INIT_FAILED = 0x00004e22;
export const ERROR_DHCP_NETWORK_INIT_FAILED = 0x00004e23;
export const ERROR_DHCP_SUBNET_EXITS = 0x00004e24;
export const ERROR_DHCP_SUBNET_NOT_PRESENT = 0x00004e25;
export const ERROR_DHCP_PRIMARY_NOT_FOUND = 0x00004e26;
export const ERROR_DHCP_ELEMENT_CANT_REMOVE = 0x00004e27;
export const ERROR_DHCP_OPTION_EXITS = 0x00004e29;
export const ERROR_DHCP_OPTION_NOT_PRESENT = 0x00004e2a;
export const ERROR_DHCP_ADDRESS_NOT_AVAILABLE = 0x00004e2b;
export const ERROR_DHCP_RANGE_FULL = 0x00004e2c;
export const ERROR_DHCP_JET_ERROR = 0x00004e2d;
export const ERROR_DHCP_CLIENT_EXISTS = 0x00004e2e;
export const ERROR_DHCP_INVALID_DHCP_MESSAGE = 0x00004e2f;
export const ERROR_DHCP_INVALID_DHCP_CLIENT = 0x00004e30;
export const ERROR_DHCP_SERVICE_PAUSED = 0x00004e31;
export const ERROR_DHCP_NOT_RESERVED_CLIENT = 0x00004e32;
export const ERROR_DHCP_RESERVED_CLIENT = 0x00004e33;
export const ERROR_DHCP_RANGE_TOO_SMALL = 0x00004e34;
export const ERROR_DHCP_IPRANGE_EXITS = 0x00004e35;
export const ERROR_DHCP_RESERVEDIP_EXITS = 0x00004e36;
export const ERROR_DHCP_INVALID_RANGE = 0x00004e37;
export const ERROR_DHCP_RANGE_EXTENDED = 0x00004e38;
export const ERROR_EXTEND_TOO_SMALL = 0x00004e39;
export const WARNING_EXTENDED_LESS = 0x00004e3a;
export const ERROR_DHCP_JET_CONV_REQUIRED = 0x00004e3b;
export const ERROR_SERVER_INVALID_BOOT_FILE_TABLE = 0x00004e3c;
export const ERROR_SERVER_UNKNOWN_BOOT_FILE_NAME = 0x00004e3d;
export const ERROR_DHCP_SUPER_SCOPE_NAME_TOO_LONG = 0x00004e3e;
export const ERROR_DHCP_IP_ADDRESS_IN_USE = 0x00004e40;
export const ERROR_DHCP_LOG_FILE_PATH_TOO_LONG = 0x00004e41;
export const ERROR_DHCP_UNSUPPORTED_CLIENT = 0x00004e42;
export const ERROR_DHCP_JET97_CONV_REQUIRED = 0x00004e44;
export const ERROR_DHCP_ROGUE_INIT_FAILED = 0x00004e45;
export const ERROR_DHCP_ROGUE_SAMSHUTDOWN = 0x00004e46;
export const ERROR_DHCP_ROGUE_NOT_AUTHORIZED = 0x00004e47;
export const ERROR_DHCP_ROGUE_DS_UNREACHABLE = 0x00004e48;
export const ERROR_DHCP_ROGUE_DS_CONFLICT = 0x00004e49;
export const ERROR_DHCP_ROGUE_NOT_OUR_ENTERPRISE = 0x00004e4a;
export const ERROR_DHCP_ROGUE_STANDALONE_IN_DS = 0x00004e4b;
export const ERROR_DHCP_CLASS_NOT_FOUND = 0x00004e4c;
export const ERROR_DHCP_CLASS_ALREADY_EXISTS = 0x00004e4d;
export const ERROR_DHCP_SCOPE_NAME_TOO_LONG = 0x00004e4e;
export const ERROR_DHCP_DEFAULT_SCOPE_EXITS = 0x00004e4f;
export const ERROR_DHCP_CANT_CHANGE_ATTRIBUTE = 0x00004e50;
export const ERROR_DHCP_IPRANGE_CONV_ILLEGAL = 0x00004e51;
export const ERROR_DHCP_NETWORK_CHANGED = 0x00004e52;
export const ERROR_DHCP_CANNOT_MODIFY_BINDINGS = 0x00004e53;
export const ERROR_DHCP_SUBNET_EXISTS = 0x00004e54;
export const ERROR_DHCP_MSCOPE_EXISTS = 0x00004e55;
export const ERROR_MSCOPE_RANGE_TOO_SMALL = 0x00004e56;
export const ERROR_DHCP_EXEMPTION_EXISTS = 0x00004e57;
export const ERROR_DHCP_EXEMPTION_NOT_PRESENT = 0x00004e58;
export const ERROR_DHCP_INVALID_PARAMETER_OPTION32 = 0x00004e59;
export const ERROR_DDS_NO_DS_AVAILABLE = 0x00004e66;
export const ERROR_DDS_NO_DHCP_ROOT = 0x00004e67;
export const ERROR_DDS_UNEXPECTED_ERROR = 0x00004e68;
export const ERROR_DDS_TOO_MANY_ERRORS = 0x00004e69;
export const ERROR_DDS_DHCP_SERVER_NOT_FOUND = 0x00004e6a;
export const ERROR_DDS_OPTION_ALREADY_EXISTS = 0x00004e6b;
export const ERROR_DDS_OPTION_DOES_NOT_EXIST = 0x00004e6c;
export const ERROR_DDS_CLASS_EXISTS = 0x00004e6d;
export const ERROR_DDS_CLASS_DOES_NOT_EXIST = 0x00004e6e;
export const ERROR_DDS_SERVER_ALREADY_EXISTS = 0x00004e6f;
export const ERROR_DDS_SERVER_DOES_NOT_EXIST = 0x00004e70;
export const ERROR_DDS_SERVER_ADDRESS_MISMATCH = 0x00004e71;
export const ERROR_DDS_SUBNET_EXISTS = 0x00004e72;
export const ERROR_DDS_SUBNET_HAS_DIFF_SSCOPE = 0x00004e73;
export const ERROR_DDS_SUBNET_NOT_PRESENT = 0x00004e74;
export const ERROR_DDS_RESERVATION_NOT_PRESENT = 0x00004e75;
export const ERROR_DDS_RESERVATION_CONFLICT = 0x00004e76;
export const ERROR_DDS_POSSIBLE_RANGE_CONFLICT = 0x00004e77;
export const ERROR_DDS_RANGE_DOES_NOT_EXIST = 0x00004e78;
export const ERROR_DHCP_DELETE_BUILTIN_CLASS = 0x00004e79;
export const ERROR_DHCP_INVALID_SUBNET_PREFIX = 0x00004e7b;
export const ERROR_DHCP_INVALID_DELAY = 0x00004e7c;
export const ERROR_DHCP_LINKLAYER_ADDRESS_EXISTS = 0x00004e7d;
export const ERROR_DHCP_LINKLAYER_ADDRESS_RESERVATION_EXISTS = 0x00004e7e;
export const ERROR_DHCP_LINKLAYER_ADDRESS_DOES_NOT_EXIST = 0x00004e7f;
export const ERROR_DHCP_HARDWARE_ADDRESS_TYPE_ALREADY_EXEMPT = 0x00004e85;
export const ERROR_DHCP_UNDEFINED_HARDWARE_ADDRESS_TYPE = 0x00004e86;
export const ERROR_DHCP_OPTION_TYPE_MISMATCH = 0x00004e87;
export const ERROR_DHCP_POLICY_BAD_PARENT_EXPR = 0x00004e88;
export const ERROR_DHCP_POLICY_EXISTS = 0x00004e89;
export const ERROR_DHCP_POLICY_RANGE_EXISTS = 0x00004e8a;
export const ERROR_DHCP_POLICY_RANGE_BAD = 0x00004e8b;
export const ERROR_DHCP_RANGE_INVALID_IN_SERVER_POLICY = 0x00004e8c;
export const ERROR_DHCP_INVALID_POLICY_EXPRESSION = 0x00004e8d;
export const ERROR_DHCP_INVALID_PROCESSING_ORDER = 0x00004e8e;
export const ERROR_DHCP_POLICY_NOT_FOUND = 0x00004e8f;
export const ERROR_SCOPE_RANGE_POLICY_RANGE_CONFLICT = 0x00004e90;

// DHCP failover error codes
export const ERROR_DHCP_FO_SCOPE_ALREADY_IN_RELATIONSHIP = 0x00004e91;
export const ERROR_DHCP_FO_RELATIONSHIP_EXISTS = 0x00004e92;
export const ERROR_DHCP_FO_RELATIONSHIP_DOES_NOT_EXIST = 0x00004e93;
export const ERROR_DHCP_FO_SCOPE_NOT_IN_RELATIONSHIP = 0x00004e94;
export const ERROR_DHCP_FO_RELATION_IS_SECONDARY = 0x00004e95;
export const ERROR_DHCP_FO_NOT_SUPPORTED = 0x00004e96;
export const ERROR_DHCP_FO_TIME_OUT_OF_SYNC = 0x00004e97;
export const ERROR_DHCP_FO_STATE_NOT_NORMAL = 0x00004e98;
export const ERROR_DHCP_NO_ADMIN_PERMISSION = 0x00004e99;
export const ERROR_DHCP_SERVER_NOT_REACHABLE = 0x00004e9a;
export const ERROR_DHCP_SERVER_NOT_RUNNING = 0x00004e9b;
export const ERROR_DHCP_SERVER_NAME_NOT_RESOLVED = 0x00004e9c;
export const ERROR_DHCP_FO_RELATIONSHIP_NAME_TOO_LONG = 0x00004e9d;
export const ERROR_DHCP_REACHED_END_OF_SELECTION = 0x00004e9e;
export const ERROR_DHCP_FO_ADDSCOPE_LEASES_NOT_SYNCED = 0x00004e9f;
export const ERROR_DHCP_FO_MAX_RELATIONSHIPS = 0x00004ea0;
export const ERROR_DHCP_FO_IPRANGE_TYPE_CONV_ILLEGAL = 0x00004ea1;
export const ERROR_DHCP_FO_MAX_ADD_SCOPES = 0x00004ea2;
export const ERROR_DHCP_FO_BOOT_NOT_SUPPORTED = 0x00004ea3;
export const ERROR_DHCP_FO_RANGE_PART_OF_REL = 0x00004ea4;
export const ERROR_DHCP_FO_SCOPE_SYNC_IN_PROGRESS = 0x00004ea5;
export const ERROR_DHCP_FO_FEATURE_NOT_SUPPORTED = 0x00004ea6;
export const ERROR_DHCP_POLICY_FQDN_RANGE_UNSUPPORTED = 0x00004ea7;
export const ERROR_DHCP_POLICY_FQDN_OPTION_UNSUPPORTED = 0x00004ea8;
export const ERROR_DHCP_POLICY_EDIT_FQDN_UNSUPPORTED = 0x00004ea9;
export const ERROR_DHCP_NAP_NOT_SUPPORTED = 0x00004eaa;
export const ERROR_LAST_DHCP_SERVER_ERROR = 0x00004eab;

class DCERPCSessionError extends DCERPCException {
  static ERROR_MESSAGES: Record<number, [string, string]> = {
    [ERROR_DHCP_JET_ERROR]: [
      'ERROR_DHCP_JET_ERROR',
      'An error occurred while accessing the DHCP server database.',
    ],
    [ERROR_DHCP_SUBNET_NOT_PRESENT]: [
      'ERROR_DHCP_SUBNET_NOT_PRESENT',
      'The specified IPv4 subnet does not exist.',
    ],
    [ERROR_DHCP_SUBNET_EXISTS]: [
      'ERROR_DHCP_SUBNET_EXISTS',
      'The IPv4 scope parameters are incorrect. Either the IPv4 scope already'
        + ' exists, corresponding to the SubnetAddress and SubnetMask members of'
        + ' the structure DHCP_SUBNET_INFO (section 2.2.1.2.8), or there is a'
        + ' range overlap of IPv4 addresses between those associated with the'
        + ' SubnetAddress and SubnetMask fields of the new IPv4 scope and the'
        + ' subnet address and mask of an already existing IPv4 scope',
    ],
    [ERROR_DHCP_INVALID_DHCP_CLIENT]: [
      'ERROR_DHCP_INVALID_DHCP_CLIENT',
      'The DHCP server received an invalid message from the client.',
    ],
  };

  toString(): string {
    const key = this.error_code ?? 0;
    const entry = DCERPCSessionError.ERROR_MESSAGES[key];
    if (entry) {
      return `DHCPM SessionError: code: 0x${key.toString(16)} - ${entry[0]} - ${entry[1]}`;
    }
    return `DHCPM SessionError: unknown error code: 0x${key.toString(16)}`;
  }
}

////////////////////////////////////////////////////////////////////////////////
// STRUCTURES
////////////////////////////////////////////////////////////////////////////////

// 2.2.1.1.3 DHCP_SEARCH_INFO_TYPE
export class DHCP_SEARCH_INFO_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'DhcpClientIpAddress',
    1: 'DhcpClientHardwareAddress',
    2: 'DhcpClientName',
  };
  static enumValues: Record<string, number> = {
    DhcpClientIpAddress: 0,
    DhcpClientHardwareAddress: 1,
    DhcpClientName: 2,
  };
}

export const DhcpClientIpAddress = 0;
export const DhcpClientHardwareAddress = 1;
export const DhcpClientName = 2;

// 2.2.1.1.11 QuarantineStatus
export class QuarantineStatus extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'NOQUARANTINE',
    1: 'RESTRICTEDACCESS',
    2: 'DROPPACKET',
    3: 'PROBATION',
    4: 'EXEMPT',
    5: 'DEFAULTQUARSETTING',
    6: 'NOQUARINFO',
  };
  static enumValues: Record<string, number> = {
    NOQUARANTINE: 0,
    RESTRICTEDACCESS: 1,
    DROPPACKET: 2,
    PROBATION: 3,
    EXEMPT: 4,
    DEFAULTQUARSETTING: 5,
    NOQUARINFO: 6,
  };
}

export const NOQUARANTINE = 0;
export const RESTRICTEDACCESS = 1;
export const DROPPACKET = 2;
export const PROBATION = 3;
export const EXEMPT = 4;
export const DEFAULTQUARSETTING = 5;
export const NOQUARINFO = 6;

// 2.2.1.2.7 DHCP_HOST_INFO
export class DHCP_HOST_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['IpAddress', DHCP_IP_ADDRESS],
    ['NetBiosName', LPWSTR],
    ['HostName', LPWSTR],
  ];
}

// 2.2.1.2.9 DHCP_BINARY_DATA
class BYTE_ARRAY extends NDRUniConformantArray {
  static item = 'c';
}

class PBYTE_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', BYTE_ARRAY]];
}

export class DHCP_BINARY_DATA extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['DataLength', DWORD],
    ['Data_', PBYTE_ARRAY],
  ];
}

export const DHCP_CLIENT_UID = DHCP_BINARY_DATA;

// 2.2.1.2.11 DATE_TIME
export class DATE_TIME extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwLowDateTime', DWORD],
    ['dwHighDateTime', DWORD],
  ];
}

// 2.2.1.2.19 DHCP_CLIENT_INFO_VQ
export class DHCP_CLIENT_INFO_VQ extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ClientIpAddress', DHCP_IP_ADDRESS],
    ['SubnetMask', DHCP_IP_MASK],
    ['ClientHardwareAddress', DHCP_CLIENT_UID],
    ['ClientName', LPWSTR],
    ['ClientComment', LPWSTR],
    ['ClientLeaseExpires', DATE_TIME],
    ['OwnerHost', DHCP_HOST_INFO],
    ['bClientType', BYTE],
    ['AddressState', BYTE],
    ['Status', QuarantineStatus],
    ['ProbationEnds', DATE_TIME],
    ['QuarantineCapable', BOOL],
  ];
}

export class DHCP_CLIENT_SEARCH_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Record<number, NDRField> = {
    [DhcpClientIpAddress]: ['ClientIpAddress', DHCP_IP_ADDRESS],
    [DhcpClientHardwareAddress]: ['ClientHardwareAddress', DHCP_CLIENT_UID],
    [DhcpClientName]: ['ClientName', LPWSTR],
  };
}

export class DHCP_SEARCH_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['SearchType', DHCP_SEARCH_INFO_TYPE],
    ['SearchInfo', DHCP_CLIENT_SEARCH_UNION],
  ];
}

// 2.2.1.2.14 DHCP_CLIENT_INFO_V4
export class DHCP_CLIENT_INFO_V4 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ClientIpAddress', DHCP_IP_ADDRESS],
    ['SubnetMask', DHCP_IP_MASK],
    ['ClientHardwareAddress', DHCP_CLIENT_UID],
    ['ClientName', LPWSTR],
    ['ClientComment', LPWSTR],
    ['ClientLeaseExpires', DATE_TIME],
    ['OwnerHost', DHCP_HOST_INFO],
    ['bClientType', BYTE],
  ];
}

export class DHCP_CLIENT_INFO_V5 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ClientIpAddress', DHCP_IP_ADDRESS],
    ['SubnetMask', DHCP_IP_MASK],
    ['ClientHardwareAddress', DHCP_CLIENT_UID],
    ['ClientName', LPWSTR],
    ['ClientComment', LPWSTR],
    ['ClientLeaseExpires', DATE_TIME],
    ['OwnerHost', DHCP_HOST_INFO],
    ['bClientType', BYTE],
    ['AddressState', BYTE],
  ];
}

export class LPDHCP_CLIENT_INFO_V4 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_CLIENT_INFO_V4]];
}

export class LPDHCP_CLIENT_INFO_V5 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_CLIENT_INFO_V5]];
}

// 2.2.1.2.115 DHCP_CLIENT_INFO_PB
export class DHCP_CLIENT_INFO_PB extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ClientIpAddress', DHCP_IP_ADDRESS],
    ['SubnetMask', DHCP_IP_MASK],
    ['ClientHardwareAddress', DHCP_CLIENT_UID],
    ['ClientName', LPWSTR],
    ['ClientComment', LPWSTR],
    ['ClientLeaseExpires', DATE_TIME],
    ['OwnerHost', DHCP_HOST_INFO],
    ['bClientType', BYTE],
    ['AddressState', BYTE],
    ['Status', QuarantineStatus],
    ['ProbationEnds', DATE_TIME],
    ['QuarantineCapable', BOOL],
    ['FilterStatus', DWORD],
    ['PolicyName', LPWSTR],
  ];
}

export class LPDHCP_CLIENT_INFO_PB extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_CLIENT_INFO_PB]];
}

export class LPDHCP_CLIENT_INFO_VQ extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_CLIENT_INFO_VQ]];
}

export class DHCP_CLIENT_INFO_VQ_ARRAY extends NDRUniConformantArray {
  static item = LPDHCP_CLIENT_INFO_VQ;
}

export class LPDHCP_CLIENT_INFO_VQ_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_CLIENT_INFO_VQ_ARRAY]];
}

export class DHCP_CLIENT_INFO_ARRAY_VQ extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['NumElements', DWORD],
    ['Clients', LPDHCP_CLIENT_INFO_VQ_ARRAY],
  ];
}

export class LPDHCP_CLIENT_INFO_ARRAY_VQ extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_CLIENT_INFO_ARRAY_VQ]];
}

export class DHCP_CLIENT_INFO_V4_ARRAY extends NDRUniConformantArray {
  static item = LPDHCP_CLIENT_INFO_V4;
}

export class DHCP_CLIENT_INFO_V5_ARRAY extends NDRUniConformantArray {
  static item = LPDHCP_CLIENT_INFO_V5;
}

export class LPDHCP_CLIENT_INFO_V4_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_CLIENT_INFO_V4_ARRAY]];
}

export class LPDHCP_CLIENT_INFO_V5_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_CLIENT_INFO_V5_ARRAY]];
}

export class DHCP_CLIENT_INFO_ARRAY_V4 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['NumElements', DWORD],
    ['Clients', LPDHCP_CLIENT_INFO_V4_ARRAY],
  ];
}

export class DHCP_CLIENT_INFO_ARRAY_V5 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['NumElements', DWORD],
    ['Clients', LPDHCP_CLIENT_INFO_V5_ARRAY],
  ];
}

export class LPDHCP_CLIENT_INFO_ARRAY_V5 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_CLIENT_INFO_ARRAY_V5]];
}

export class LPDHCP_CLIENT_INFO_ARRAY_V4 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_CLIENT_INFO_ARRAY_V4]];
}

export class DHCP_IP_ADDRESS_ARRAY extends NDRUniConformantArray {
  static item = DHCP_IP_ADDRESS;
}

export class LPDHCP_IP_ADDRESS_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_IP_ADDRESS_ARRAY]];
}

export class DHCP_IP_ARRAY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['NumElements', DWORD],
    ['Elements', LPDHCP_IP_ADDRESS_ARRAY],
  ];
}

export class DHCP_SUBNET_STATE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'DhcpSubnetEnabled',
    1: 'DhcpSubnetDisabled',
    2: 'DhcpSubnetEnabledSwitched',
    3: 'DhcpSubnetDisabledSwitched',
    4: 'DhcpSubnetInvalidState',
  };
  static enumValues: Record<string, number> = {
    DhcpSubnetEnabled: 0,
    DhcpSubnetDisabled: 1,
    DhcpSubnetEnabledSwitched: 2,
    DhcpSubnetDisabledSwitched: 3,
    DhcpSubnetInvalidState: 4,
  };
}

export const DhcpSubnetEnabled = 0;
export const DhcpSubnetDisabled = 1;
export const DhcpSubnetEnabledSwitched = 2;
export const DhcpSubnetDisabledSwitched = 3;
export const DhcpSubnetInvalidState = 4;

export class DHCP_SUBNET_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['SubnetAddress', DHCP_IP_ADDRESS],
    ['SubnetMask', DHCP_IP_MASK],
    ['SubnetName', LPWSTR],
    ['SubnetComment', LPWSTR],
    ['PrimaryHost', DHCP_HOST_INFO],
    ['SubnetState', DHCP_SUBNET_STATE],
  ];
}

export class LPDHCP_SUBNET_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_SUBNET_INFO]];
}

export class DHCP_OPTION_SCOPE_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'DhcpDefaultOptions',
    1: 'DhcpGlobalOptions',
    2: 'DhcpSubnetOptions',
    3: 'DhcpReservedOptions',
    4: 'DhcpMScopeOptions',
  };
  static enumValues: Record<string, number> = {
    DhcpDefaultOptions: 0,
    DhcpGlobalOptions: 1,
    DhcpSubnetOptions: 2,
    DhcpReservedOptions: 3,
    DhcpMScopeOptions: 4,
  };
}

export const DhcpDefaultOptions = 0;
export const DhcpGlobalOptions = 1;
export const DhcpSubnetOptions = 2;
export const DhcpReservedOptions = 3;
export const DhcpMScopeOptions = 4;

export class DHCP_RESERVED_SCOPE extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ReservedIpAddress', DHCP_IP_ADDRESS],
    ['ReservedIpSubnetAddress', DHCP_IP_ADDRESS],
  ];
}

export class DHCP_OPTION_SCOPE_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Record<number, NDRField> = {
    [DhcpSubnetOptions]: ['SubnetScopeInfo', DHCP_IP_ADDRESS],
    [DhcpReservedOptions]: ['ReservedScopeInfo', DHCP_RESERVED_SCOPE],
    [DhcpMScopeOptions]: ['MScopeInfo', LPWSTR],
  };
}

export class DHCP_OPTION_SCOPE_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ScopeType', DHCP_OPTION_SCOPE_TYPE],
    ['ScopeInfo', DHCP_OPTION_SCOPE_UNION],
  ];
}

export class LPDHCP_OPTION_SCOPE_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_OPTION_SCOPE_INFO]];
}

export class DWORD_DWORD extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['DWord1', DWORD],
    ['DWord2', DWORD],
  ];
}

export class DHCP_BOOTP_IP_RANGE extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['StartAddress', DHCP_IP_ADDRESS],
    ['EndAddress', DHCP_IP_ADDRESS],
    ['BootpAllocated', ULONG],
    ['MaxBootpAllowed', DHCP_IP_ADDRESS],
    ['MaxBootpAllowed', ULONG],
  ];
}

export class DHCP_IP_RESERVATION_V4 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ReservedIpAddress', DHCP_IP_ADDRESS],
    ['ReservedForClient', DHCP_CLIENT_UID],
    ['bAllowedClientTypes', BYTE],
  ];
}

export class DHCP_IP_RANGE extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['StartAddress', DHCP_IP_ADDRESS],
    ['EndAddress', DHCP_IP_ADDRESS],
  ];
}

export class DHCP_IP_CLUSTER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ClusterAddress', DHCP_IP_ADDRESS],
    ['ClusterMask', DWORD],
  ];
}

export class DHCP_SUBNET_ELEMENT_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'DhcpIpRanges',
    1: 'DhcpSecondaryHosts',
    2: 'DhcpReservedIps',
    3: 'DhcpExcludedIpRanges',
    4: 'DhcpIpUsedClusters',
    5: 'DhcpIpRangesDhcpOnly',
    6: 'DhcpIpRangesDhcpBootp',
    7: 'DhcpIpRangesBootpOnly',
  };
  static enumValues: Record<string, number> = {
    DhcpIpRanges: 0,
    DhcpSecondaryHosts: 1,
    DhcpReservedIps: 2,
    DhcpExcludedIpRanges: 3,
    DhcpIpUsedClusters: 4,
    DhcpIpRangesDhcpOnly: 5,
    DhcpIpRangesDhcpBootp: 6,
    DhcpIpRangesBootpOnly: 7,
  };
}

export const DhcpIpRanges = 0;
export const DhcpSecondaryHosts = 1;
export const DhcpReservedIps = 2;
export const DhcpExcludedIpRanges = 3;
export const DhcpIpUsedClusters = 4;
export const DhcpIpRangesDhcpOnly = 5;
export const DhcpIpRangesDhcpBootp = 6;
export const DhcpIpRangesBootpOnly = 7;

export class DHCP_SUBNET_ELEMENT_UNION_V5 extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Record<number, NDRField> = {
    [DhcpIpRanges]: ['IpRange', DHCP_BOOTP_IP_RANGE],
    [DhcpSecondaryHosts]: ['SecondaryHost', DHCP_HOST_INFO],
    [DhcpReservedIps]: ['ReservedIp', DHCP_IP_RESERVATION_V4],
    [DhcpExcludedIpRanges]: ['ExcludeIpRange', DHCP_IP_RANGE],
    [DhcpIpUsedClusters]: ['IpUsedCluster', DHCP_IP_CLUSTER],
  };
}

export class DHCP_SUBNET_ELEMENT_DATA_V5 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ElementType', DHCP_SUBNET_ELEMENT_TYPE],
    ['Element', DHCP_SUBNET_ELEMENT_UNION_V5],
  ];
}

export class LPDHCP_SUBNET_ELEMENT_DATA_V5 extends NDRUniConformantArray {
  static item = DHCP_SUBNET_ELEMENT_DATA_V5;
}

export class DHCP_SUBNET_ELEMENT_INFO_ARRAY_V5 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['NumElements', DWORD],
    ['Elements', LPDHCP_SUBNET_ELEMENT_DATA_V5],
  ];
}

export class LPDHCP_SUBNET_ELEMENT_INFO_ARRAY_V5 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_SUBNET_ELEMENT_INFO_ARRAY_V5]];
}

export class DHCP_OPTION_DATA_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'DhcpByteOption',
    1: 'DhcpWordOption',
    2: 'DhcpDWordOption',
    3: 'DhcpDWordDWordOption',
    4: 'DhcpIpAddressOption',
    5: 'DhcpStringDataOption',
    6: 'DhcpBinaryDataOption',
    7: 'DhcpEncapsulatedDataOption',
    8: 'DhcpIpv6AddressOption',
  };
  static enumValues: Record<string, number> = {
    DhcpByteOption: 0,
    DhcpWordOption: 1,
    DhcpDWordOption: 2,
    DhcpDWordDWordOption: 3,
    DhcpIpAddressOption: 4,
    DhcpStringDataOption: 5,
    DhcpBinaryDataOption: 6,
    DhcpEncapsulatedDataOption: 7,
    DhcpIpv6AddressOption: 8,
  };
}

export const DhcpByteOption = 0;
export const DhcpWordOption = 1;
export const DhcpDWordOption = 2;
export const DhcpDWordDWordOption = 3;
export const DhcpIpAddressOption = 4;
export const DhcpStringDataOption = 5;
export const DhcpBinaryDataOption = 6;
export const DhcpEncapsulatedDataOption = 7;
export const DhcpIpv6AddressOption = 8;

export class DHCP_OPTION_ELEMENT_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Record<number, NDRField> = {
    [DhcpByteOption]: ['ByteOption', BYTE],
    [DhcpWordOption]: ['WordOption', WORD],
    [DhcpDWordOption]: ['DWordOption', DWORD],
    [DhcpDWordDWordOption]: ['DWordDWordOption', DWORD_DWORD],
    [DhcpIpAddressOption]: ['IpAddressOption', DHCP_IP_ADDRESS],
    [DhcpStringDataOption]: ['StringDataOption', LPWSTR],
    [DhcpBinaryDataOption]: ['BinaryDataOption', DHCP_BINARY_DATA],
    [DhcpEncapsulatedDataOption]: ['EncapsulatedDataOption', DHCP_BINARY_DATA],
    [DhcpIpv6AddressOption]: ['Ipv6AddressDataOption', LPWSTR],
  };
}

export class DHCP_OPTION_DATA_ELEMENT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['OptionType', DHCP_OPTION_DATA_TYPE],
    ['Element', DHCP_OPTION_ELEMENT_UNION],
  ];
}

export class DHCP_OPTION_DATA_ELEMENT_ARRAY2 extends NDRUniConformantArray {
  static item = DHCP_OPTION_DATA_ELEMENT;
}

export class LPDHCP_OPTION_DATA_ELEMENT extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_OPTION_DATA_ELEMENT_ARRAY2]];
}

export class DHCP_OPTION_DATA extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['NumElements', DWORD],
    ['Elements', LPDHCP_OPTION_DATA_ELEMENT],
  ];
}

export class DHCP_OPTION_VALUE extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['OptionID', DHCP_OPTION_ID],
    ['Value', DHCP_OPTION_DATA],
  ];
}

export class PDHCP_OPTION_VALUE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_OPTION_VALUE]];
}

export class DHCP_OPTION_VALUE_ARRAY2 extends NDRUniConformantArray {
  static item = DHCP_OPTION_VALUE;
}

export class LPDHCP_OPTION_VALUE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_OPTION_VALUE_ARRAY2]];
}

export class DHCP_OPTION_VALUE_ARRAY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['NumElements', DWORD],
    ['Values', LPDHCP_OPTION_VALUE],
  ];
}

export class LPDHCP_OPTION_VALUE_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_OPTION_VALUE_ARRAY]];
}

export class DHCP_ALL_OPTION_VALUES extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ClassName', LPWSTR],
    ['VendorName', LPWSTR],
    ['IsVendor', BOOL],
    ['OptionsArray', LPDHCP_OPTION_VALUE_ARRAY],
  ];
}

export class OPTION_VALUES_ARRAY extends NDRUniConformantArray {
  static item = DHCP_ALL_OPTION_VALUES;
}

export class LPOPTION_VALUES_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', OPTION_VALUES_ARRAY]];
}

export class DHCP_ALL_OPTIONS_VALUES extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Flags', DWORD],
    ['NumElements', DWORD],
    ['Options', LPOPTION_VALUES_ARRAY],
  ];
}

export class LPDHCP_ALL_OPTION_VALUES extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DHCP_ALL_OPTIONS_VALUES]];
}

////////////////////////////////////////////////////////////////////////////////
// RPC CALLS
////////////////////////////////////////////////////////////////////////////////

// Interface dhcpsrv
export class DhcpGetSubnetInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['SubnetInfo', LPDHCP_SUBNET_INFO],
    ['ErrorCode', ULONG],
  ];
}

export class DhcpGetSubnetInfo extends NDRCALL {
  static opnum = 2;
  static Response = DhcpGetSubnetInfoResponse;
  static structure: NDRField[] = [
    ['ServerIpAddress', DHCP_SRV_HANDLE],
    ['SubnetAddress', DHCP_IP_ADDRESS],
  ];
}

export class DhcpEnumSubnetsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ResumeHandle', LPDWORD],
    ['EnumInfo', DHCP_IP_ARRAY],
    ['EnumRead', DWORD],
    ['EnumTotal', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class DhcpEnumSubnets extends NDRCALL {
  static opnum = 3;
  static Response = DhcpEnumSubnetsResponse;
  static structure: NDRField[] = [
    ['ServerIpAddress', DHCP_SRV_HANDLE],
    ['ResumeHandle', LPDWORD],
    ['PreferredMaximum', DWORD],
  ];
}

export class DhcpGetOptionValueResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['OptionValue', PDHCP_OPTION_VALUE],
    ['ErrorCode', ULONG],
  ];
}

export class DhcpGetOptionValue extends NDRCALL {
  static opnum = 13;
  static Response = DhcpGetOptionValueResponse;
  static structure: NDRField[] = [
    ['ServerIpAddress', DHCP_SRV_HANDLE],
    ['OptionID', DHCP_OPTION_ID],
    ['ScopeInfo', DHCP_OPTION_SCOPE_INFO],
  ];
}

export class DhcpEnumOptionValuesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ResumeHandle', DWORD],
    ['OptionValues', LPDHCP_OPTION_VALUE_ARRAY],
    ['OptionsRead', DWORD],
    ['OptionsTotal', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class DhcpEnumOptionValues extends NDRCALL {
  static opnum = 14;
  static Response = DhcpEnumOptionValuesResponse;
  static structure: NDRField[] = [
    ['ServerIpAddress', DHCP_SRV_HANDLE],
    ['ScopeInfo', DHCP_OPTION_SCOPE_INFO],
    ['ResumeHandle', LPDWORD],
    ['PreferredMaximum', DWORD],
  ];
}

export class DhcpGetClientInfoV4Response extends NDRCALL {
  static structure: NDRField[] = [
    ['ClientInfo', LPDHCP_CLIENT_INFO_V4],
    ['ErrorCode', ULONG],
  ];
}

export class DhcpGetClientInfoV4 extends NDRCALL {
  static opnum = 34;
  static Response = DhcpGetClientInfoV4Response;
  static structure: NDRField[] = [
    ['ServerIpAddress', DHCP_SRV_HANDLE],
    ['SearchInfo', DHCP_SEARCH_INFO],
  ];
}

export class DhcpEnumSubnetClientsV4Response extends NDRCALL {
  static structure: NDRField[] = [
    ['ResumeHandle', LPDWORD],
    ['ClientInfo', LPDHCP_CLIENT_INFO_ARRAY_V4],
    ['ClientsRead', DWORD],
    ['ClientsTotal', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class DhcpEnumSubnetClientsV4 extends NDRCALL {
  static opnum = 35;
  static Response = DhcpEnumSubnetClientsV4Response;
  static structure: NDRField[] = [
    ['ServerIpAddress', DHCP_SRV_HANDLE],
    ['SubnetAddress', DHCP_IP_ADDRESS],
    ['ResumeHandle', DWORD],
    ['PreferredMaximum', DWORD],
  ];
}

// Interface dhcpsrv2
export class DhcpEnumSubnetClientsV5Response extends NDRCALL {
  static structure: NDRField[] = [
    ['ResumeHandle', DWORD],
    ['ClientsInfo', LPDHCP_CLIENT_INFO_ARRAY_V5],
    ['ClientsRead', DWORD],
    ['ClientsTotal', DWORD],
  ];
}

export class DhcpEnumSubnetClientsV5 extends NDRCALL {
  static opnum = 0;
  static Response = DhcpEnumSubnetClientsV5Response;
  static structure: NDRField[] = [
    ['ServerIpAddress', DHCP_SRV_HANDLE],
    ['SubnetAddress', DHCP_IP_ADDRESS],
    ['ResumeHandle', LPDWORD],
    ['PreferredMaximum', DWORD],
  ];
}

export class DhcpGetOptionValueV5Response extends NDRCALL {
  static structure: NDRField[] = [
    ['OptionValue', PDHCP_OPTION_VALUE],
    ['ErrorCode', ULONG],
  ];
}

export class DhcpGetOptionValueV5 extends NDRCALL {
  static opnum = 21;
  static Response = DhcpGetOptionValueV5Response;
  static structure: NDRField[] = [
    ['ServerIpAddress', DHCP_SRV_HANDLE],
    ['Flags', DWORD],
    ['OptionID', DHCP_OPTION_ID],
    ['ClassName', LPWSTR],
    ['VendorName', LPWSTR],
    ['ScopeInfo', DHCP_OPTION_SCOPE_INFO],
  ];
}

export class DhcpEnumOptionValuesV5Response extends NDRCALL {
  static structure: NDRField[] = [
    ['ResumeHandle', DWORD],
    ['OptionValues', LPDHCP_OPTION_VALUE_ARRAY],
    ['OptionsRead', DWORD],
    ['OptionsTotal', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class DhcpEnumOptionValuesV5 extends NDRCALL {
  static opnum = 22;
  static Response = DhcpEnumOptionValuesV5Response;
  static structure: NDRField[] = [
    ['ServerIpAddress', DHCP_SRV_HANDLE],
    ['Flags', DWORD],
    ['ClassName', LPWSTR],
    ['VendorName', LPWSTR],
    ['ScopeInfo', DHCP_OPTION_SCOPE_INFO],
    ['ResumeHandle', LPDWORD],
    ['PreferredMaximum', DWORD],
  ];
}

export class DhcpGetAllOptionValuesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Values', LPDHCP_ALL_OPTION_VALUES],
    ['ErrorCode', ULONG],
  ];
}

export class DhcpGetAllOptionValues extends NDRCALL {
  static opnum = 30;
  static Response = DhcpGetAllOptionValuesResponse;
  static structure: NDRField[] = [
    ['ServerIpAddress', DHCP_SRV_HANDLE],
    ['Flags', DWORD],
    ['ScopeInfo', DHCP_OPTION_SCOPE_INFO],
  ];
}

export class DhcpEnumSubnetElementsV5Response extends NDRCALL {
  static structure: NDRField[] = [
    ['ResumeHandle', DWORD],
    ['EnumElementInfo', LPDHCP_SUBNET_ELEMENT_INFO_ARRAY_V5],
    ['ElementsRead', DWORD],
    ['ElementsTotal', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class DhcpEnumSubnetElementsV5 extends NDRCALL {
  static opnum = 38;
  static Response = DhcpEnumSubnetElementsV5Response;
  static structure: NDRField[] = [
    ['ServerIpAddress', DHCP_SRV_HANDLE],
    ['SubnetAddress', DHCP_IP_ADDRESS],
    ['EnumElementType', DHCP_SUBNET_ELEMENT_TYPE],
    ['ResumeHandle', LPDWORD],
    ['PreferredMaximum', DWORD],
  ];
}

export class DhcpEnumSubnetClientsVQResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ResumeHandle', LPDWORD],
    ['ClientInfo', LPDHCP_CLIENT_INFO_ARRAY_VQ],
    ['ClientsRead', DWORD],
    ['ClientsTotal', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class DhcpEnumSubnetClientsVQ extends NDRCALL {
  static opnum = 47;
  static Response = DhcpEnumSubnetClientsVQResponse;
  static structure: NDRField[] = [
    ['ServerIpAddress', DHCP_SRV_HANDLE],
    ['SubnetAddress', DHCP_IP_ADDRESS],
    ['ResumeHandle', LPDWORD],
    ['PreferredMaximum', DWORD],
  ];
}

export class DhcpV4GetClientInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ClientInfo', LPDHCP_CLIENT_INFO_PB],
    ['ErrorCode', ULONG],
  ];
}

export class DhcpV4GetClientInfo extends NDRCALL {
  static opnum = 123;
  static Response = DhcpV4GetClientInfoResponse;
  static structure: NDRField[] = [
    ['ServerIpAddress', DHCP_SRV_HANDLE],
    ['SearchInfo', DHCP_SEARCH_INFO],
  ];
}

////////////////////////////////////////////////////////////////////////////////
// OPNUMs and their corresponding structures
////////////////////////////////////////////////////////////////////////////////
const OPNUMS: Record<number, [typeof NDRCALL, typeof NDRCALL]> = {
  0: [DhcpEnumSubnetClientsV5, DhcpEnumSubnetClientsV5Response],
  2: [DhcpGetSubnetInfo, DhcpGetSubnetInfoResponse],
  3: [DhcpEnumSubnets, DhcpEnumSubnetsResponse],
  13: [DhcpGetOptionValue, DhcpGetOptionValueResponse],
  14: [DhcpEnumOptionValues, DhcpEnumOptionValuesResponse],
  21: [DhcpGetOptionValueV5, DhcpGetOptionValueV5Response],
  22: [DhcpEnumOptionValuesV5, DhcpEnumOptionValuesV5Response],
  30: [DhcpGetAllOptionValues, DhcpGetAllOptionValuesResponse],
  34: [DhcpGetClientInfoV4, DhcpGetClientInfoV4Response],
  35: [DhcpEnumSubnetClientsV4, DhcpEnumSubnetClientsV4Response],
  38: [DhcpEnumSubnetElementsV5, DhcpEnumSubnetElementsV5Response],
  47: [DhcpEnumSubnetClientsVQ, DhcpEnumSubnetClientsVQResponse],
  123: [DhcpV4GetClientInfo, DhcpV4GetClientInfoResponse],
};

////////////////////////////////////////////////////////////////////////////////
// HELPER FUNCTIONS
////////////////////////////////////////////////////////////////////////////////
type DceRequestFn = <T>(
  req: unknown,
  uuid?: unknown,
  checkError?: boolean,
) => Promise<T>;

export async function hDhcpGetClientInfoV4(
  dce: DCERPC_v5,
  searchType: number,
  searchValue: unknown,
): Promise<DhcpGetClientInfoV4Response> {
  const request = new DhcpGetClientInfoV4();
  request.set('ServerIpAddress', NULL);
  const searchInfo = request.fields['SearchInfo'] as DHCP_SEARCH_INFO;
  searchInfo.set('SearchType', searchType);
  const searchUnion = searchInfo.fields['SearchInfo'] as DHCP_CLIENT_SEARCH_UNION;
  searchUnion.set('tag', searchType);
  if (searchType === DhcpClientIpAddress) {
    searchUnion.set('ClientIpAddress', searchValue);
  } else if (searchType === DhcpClientHardwareAddress) {
    searchUnion.set('ClientHardwareAddress', searchValue);
  } else {
    searchUnion.set('ClientName', searchValue);
  }
  return (dce as unknown as { request: DceRequestFn }).request<DhcpGetClientInfoV4Response>(
    request,
  );
}

export async function hDhcpGetSubnetInfo(
  dce: DCERPC_v5,
  subnetAddress: number,
): Promise<DhcpGetSubnetInfoResponse> {
  const request = new DhcpGetSubnetInfo();
  request.set('ServerIpAddress', NULL);
  request.set('SubnetAddress', subnetAddress);
  return (dce as unknown as { request: DceRequestFn }).request<DhcpGetSubnetInfoResponse>(
    request,
  );
}

export async function hDhcpGetOptionValue(
  dce: DCERPC_v5,
  optionID: number,
  scopetype: number = DhcpDefaultOptions,
  options: unknown = NULL,
): Promise<DhcpGetOptionValueResponse> {
  const request = new DhcpGetOptionValue();
  request.set('ServerIpAddress', NULL);
  request.set('OptionID', optionID);
  const scopeInfo = request.fields['ScopeInfo'] as DHCP_OPTION_SCOPE_INFO;
  scopeInfo.set('ScopeType', scopetype);
  if (scopetype !== DhcpDefaultOptions && scopetype !== DhcpGlobalOptions) {
    const scopeUnion = scopeInfo.fields['ScopeInfo'] as DHCP_OPTION_SCOPE_UNION;
    scopeUnion.set('tag', scopetype);
  }
  if (scopetype === DhcpSubnetOptions) {
    const scopeUnion = scopeInfo.fields['ScopeInfo'] as DHCP_OPTION_SCOPE_UNION;
    scopeUnion.set('SubnetScopeInfo', options);
  } else if (scopetype === DhcpReservedOptions) {
    const scopeUnion = scopeInfo.fields['ScopeInfo'] as DHCP_OPTION_SCOPE_UNION;
    scopeUnion.set('ReservedScopeInfo', options);
  } else if (scopetype === DhcpMScopeOptions) {
    const scopeUnion = scopeInfo.fields['ScopeInfo'] as DHCP_OPTION_SCOPE_UNION;
    scopeUnion.set('MScopeInfo', options);
  }
  return (dce as unknown as { request: DceRequestFn }).request<DhcpGetOptionValueResponse>(
    request,
  );
}

export async function hDhcpEnumOptionValues(
  dce: DCERPC_v5,
  scopetype: number = DhcpDefaultOptions,
  options: unknown = NULL,
  preferredMaximum: number = 0xffffffff,
): Promise<DhcpEnumOptionValuesResponse> {
  const request = new DhcpEnumOptionValues();
  request.set('ServerIpAddress', NULL);
  const scopeInfo = request.fields['ScopeInfo'] as DHCP_OPTION_SCOPE_INFO;
  scopeInfo.set('ScopeType', scopetype);
  if (scopetype !== DhcpDefaultOptions && scopetype !== DhcpGlobalOptions) {
    const scopeUnion = scopeInfo.fields['ScopeInfo'] as DHCP_OPTION_SCOPE_UNION;
    scopeUnion.set('tag', scopetype);
  }
  if (scopetype === DhcpSubnetOptions) {
    const scopeUnion = scopeInfo.fields['ScopeInfo'] as DHCP_OPTION_SCOPE_UNION;
    scopeUnion.set('SubnetScopeInfo', options);
  } else if (scopetype === DhcpReservedOptions) {
    const scopeUnion = scopeInfo.fields['ScopeInfo'] as DHCP_OPTION_SCOPE_UNION;
    scopeUnion.set('ReservedScopeInfo', options);
  } else if (scopetype === DhcpMScopeOptions) {
    const scopeUnion = scopeInfo.fields['ScopeInfo'] as DHCP_OPTION_SCOPE_UNION;
    scopeUnion.set('MScopeInfo', options);
  }
  request.set('ResumeHandle', NULL);
  request.set('PreferredMaximum', preferredMaximum);
  return (dce as unknown as { request: DceRequestFn }).request<DhcpEnumOptionValuesResponse>(
    request,
  );
}

export async function hDhcpEnumOptionValuesV5(
  dce: DCERPC_v5,
  flags: number = DHCP_FLAGS_OPTION_DEFAULT,
  classname: unknown = NULL,
  vendorname: unknown = NULL,
  scopetype: number = DhcpDefaultOptions,
  options: unknown = NULL,
  preferredMaximum: number = 0xffffffff,
): Promise<DhcpEnumOptionValuesV5Response> {
  const request = new DhcpEnumOptionValuesV5();
  request.set('ServerIpAddress', NULL);
  request.set('Flags', flags);
  request.set('ClassName', classname);
  request.set('VendorName', vendorname);
  const scopeInfo = request.fields['ScopeInfo'] as DHCP_OPTION_SCOPE_INFO;
  scopeInfo.set('ScopeType', scopetype);
  const scopeUnion = scopeInfo.fields['ScopeInfo'] as DHCP_OPTION_SCOPE_UNION;
  scopeUnion.set('tag', scopetype);
  if (scopetype === DhcpSubnetOptions) {
    scopeUnion.set('SubnetScopeInfo', options);
  } else if (scopetype === DhcpReservedOptions) {
    scopeUnion.set('ReservedScopeInfo', options);
  } else if (scopetype === DhcpMScopeOptions) {
    scopeUnion.set('MScopeInfo', options);
  }
  request.set('ResumeHandle', NULL);
  request.set('PreferredMaximum', preferredMaximum);
  return (dce as unknown as { request: DceRequestFn }).request<DhcpEnumOptionValuesV5Response>(
    request,
  );
}

export async function hDhcpGetOptionValueV5(
  dce: DCERPC_v5,
  optionId: number,
  flags: number = DHCP_FLAGS_OPTION_DEFAULT,
  classname: unknown = NULL,
  vendorname: unknown = NULL,
  scopetype: number = DhcpDefaultOptions,
  options: unknown = NULL,
): Promise<DhcpGetOptionValueV5Response> {
  const request = new DhcpGetOptionValueV5();
  request.set('ServerIpAddress', NULL);
  request.set('Flags', flags);
  request.set('OptionID', optionId);
  request.set('ClassName', classname);
  request.set('VendorName', vendorname);
  const scopeInfo = request.fields['ScopeInfo'] as DHCP_OPTION_SCOPE_INFO;
  scopeInfo.set('ScopeType', scopetype);
  const scopeUnion = scopeInfo.fields['ScopeInfo'] as DHCP_OPTION_SCOPE_UNION;
  scopeUnion.set('tag', scopetype);
  if (scopetype === DhcpSubnetOptions) {
    scopeUnion.set('SubnetScopeInfo', options);
  } else if (scopetype === DhcpReservedOptions) {
    scopeUnion.set('ReservedScopeInfo', options);
  } else if (scopetype === DhcpMScopeOptions) {
    scopeUnion.set('MScopeInfo', options);
  }
  return (dce as unknown as { request: DceRequestFn }).request<DhcpGetOptionValueV5Response>(
    request,
  );
}

export async function hDhcpGetAllOptionValues(
  dce: DCERPC_v5,
  scopetype: number = DhcpDefaultOptions,
  options: unknown = NULL,
): Promise<DhcpGetAllOptionValuesResponse> {
  const request = new DhcpGetAllOptionValues();
  request.set('ServerIpAddress', NULL);
  request.set('Flags', NULL);
  const scopeInfo = request.fields['ScopeInfo'] as DHCP_OPTION_SCOPE_INFO;
  scopeInfo.set('ScopeType', scopetype);
  const scopeUnion = scopeInfo.fields['ScopeInfo'] as DHCP_OPTION_SCOPE_UNION;
  scopeUnion.set('tag', scopetype);
  if (scopetype === DhcpSubnetOptions) {
    scopeUnion.set('SubnetScopeInfo', options);
  } else if (scopetype === DhcpReservedOptions) {
    scopeUnion.set('ReservedScopeInfo', options);
  } else if (scopetype === DhcpMScopeOptions) {
    scopeUnion.set('MScopeInfo', options);
  }
  return (dce as unknown as { request: DceRequestFn }).request<DhcpGetAllOptionValuesResponse>(
    request,
  );
}

export async function hDhcpEnumSubnets(
  dce: DCERPC_v5,
  preferredMaximum: number = 0xffffffff,
): Promise<DhcpEnumSubnetsResponse> {
  const request = new DhcpEnumSubnets();
  request.set('ServerIpAddress', NULL);
  request.set('ResumeHandle', NULL);
  request.set('PreferredMaximum', preferredMaximum);
  return (dce as unknown as { request: DceRequestFn }).request<DhcpEnumSubnetsResponse>(
    request,
  );
}

export async function hDhcpEnumSubnetClientsVQ(
  dce: DCERPC_v5,
  preferredMaximum: number = 0xffffffff,
): Promise<DhcpEnumSubnetClientsVQResponse> {
  const request = new DhcpEnumSubnetClientsVQ();
  request.set('ServerIpAddress', NULL);
  request.set('SubnetAddress', NULL);
  request.set('ResumeHandle', NULL);
  request.set('PreferredMaximum', preferredMaximum);
  return (dce as unknown as { request: DceRequestFn }).request<DhcpEnumSubnetClientsVQResponse>(
    request,
  );
}

export async function hDhcpEnumSubnetClientsV4(
  dce: DCERPC_v5,
  preferredMaximum: number = 0xffffffff,
): Promise<DhcpEnumSubnetClientsV4Response> {
  const request = new DhcpEnumSubnetClientsV4();
  request.set('ServerIpAddress', NULL);
  request.set('SubnetAddress', NULL);
  request.set('ResumeHandle', NULL);
  request.set('PreferredMaximum', preferredMaximum);
  return (dce as unknown as { request: DceRequestFn }).request<DhcpEnumSubnetClientsV4Response>(
    request,
  );
}

export async function hDhcpEnumSubnetClientsV5(
  dce: DCERPC_v5,
  subnetAddress: number = 0,
  preferredMaximum: number = 0xffffffff,
): Promise<DhcpEnumSubnetClientsV5Response> {
  const request = new DhcpEnumSubnetClientsV5();
  request.set('ServerIpAddress', NULL);
  request.set('SubnetAddress', subnetAddress);
  request.set('ResumeHandle', NULL);
  request.set('PreferredMaximum', preferredMaximum);
  return (dce as unknown as { request: DceRequestFn }).request<DhcpEnumSubnetClientsV5Response>(
    request,
  );
}

export async function hDhcpEnumSubnetElementsV5(
  dce: DCERPC_v5,
  subnetAddress: number,
  elementType: number = DhcpIpRanges,
  preferredMaximum: number = 0xffffffff,
): Promise<DhcpEnumSubnetElementsV5Response> {
  const request = new DhcpEnumSubnetElementsV5();
  request.set('ServerIpAddress', NULL);
  request.set('SubnetAddress', subnetAddress);
  request.set('EnumElementType', elementType);
  request.set('ResumeHandle', NULL);
  request.set('PreferredMaximum', preferredMaximum);
  return (dce as unknown as { request: DceRequestFn }).request<DhcpEnumSubnetElementsV5Response>(
    request,
  );
}
