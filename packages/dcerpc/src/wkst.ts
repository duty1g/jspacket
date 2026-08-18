import { uuidtupToBin } from '@impacket/uuid';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRENUM,
  NDRUNION,
  NDRPOINTER,
  NDRUniConformantArray,
  NDRUniFixedArray,
  NULL,
  type NDRField,
} from './ndr';
import {
  ULONG,
  LONG,
  LPWSTR,
  WSTR,
  WIDESTR,
  LARGE_INTEGER,
  RPC_UNICODE_STRING,
  LPULONG,
  LPLONG,
} from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_WKST = uuidtupToBin(['6BFFD098-A112-3610-9833-46C3F87E345A', '1.0'])!;

class DCERPCSessionError extends DCERPCException {
  constructor(errorString?: string | null, errorCode?: number | null, packet?: unknown) {
    super(errorString, errorCode, packet);
  }

  toString(): string {
    const key = this.error_code;
    if (key != null) {
      return `WKST SessionError: code: 0x${key.toString(16)}`;
    }
    return `WKST SessionError: unknown error code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

export const JOIN_MAX_PASSWORD_LENGTH = 256;
export const JOIN_OBFUSCATOR_LENGTH = 8;
export const MAX_PREFERRED_LENGTH = 0xffffffff;

export const USE_OK = 0x00000000;
export const USE_PAUSED = 0x00000001;
export const USE_SESSLOST = 0x00000002;
export const USE_NETERR = 0x00000003;
export const USE_CONN = 0x00000004;
export const USE_RECONN = 0x00000005;

export const USE_WILDCARD = 0xffffffff;
export const USE_DISKDEV = 0x00000000;
export const USE_SPOOLDEV = 0x00000001;
export const USE_CHARDEV = 0x00000002;
export const USE_IPC = 0x00000003;

export const USE_NOFORCE = 0x00000000;
export const USE_FORCE = 0x00000001;
export const USE_LOTS_OF_FORCE = 0x00000002;

export const NETSETUP_JOIN_DOMAIN = 0x00000001;
export const NETSETUP_ACCT_CREATE = 0x00000002;
export const NETSETUP_ACCT_DELETE = 0x00000004;
export const NETSETUP_DOMAIN_JOIN_IF_JOINED = 0x00000020;
export const NETSETUP_JOIN_UNSECURE = 0x00000040;
export const NETSETUP_MACHINE_PWD_PASSED = 0x00000080;
export const NETSETUP_DEFER_SPN_SET = 0x00000100;
export const NETSETUP_JOIN_DC_ACCOUNT = 0x00000200;
export const NETSETUP_JOIN_WITH_NEW_NAME = 0x00000400;
export const NETSETUP_INSTALL_INVOCATION = 0x00040000;

export const NETSETUP_IGNORE_UNSUPPORTED_FLAGS = 0x10000000;

export const NETSETUP_DNS_NAME_CHANGES_ONLY = 0x00001000;

export class WKSSVC_IDENTIFY_HANDLE extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', WSTR]];
}

export class LPWKSSVC_IDENTIFY_HANDLE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WKSSVC_IDENTIFY_HANDLE]];
}

export class WKSSVC_IMPERSONATE_HANDLE extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', WSTR]];
}

export class LPWKSSVC_IMPERSONATE_HANDLE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WKSSVC_IMPERSONATE_HANDLE]];
}

export class NETSETUP_JOIN_STATUS extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'NetSetupUnknownStatus',
    1: 'NetSetupUnjoined',
    2: 'NetSetupWorkgroupName',
    3: 'NetSetupDomainName',
  };
  static enumValues: Record<string, number> = {
    NetSetupUnknownStatus: 0,
    NetSetupUnjoined: 1,
    NetSetupWorkgroupName: 2,
    NetSetupDomainName: 3,
  };
}

export class NETSETUP_NAME_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'NetSetupUnknown',
    1: 'NetSetupMachine',
    2: 'NetSetupWorkgroup',
    3: 'NetSetupDomain',
    4: 'NetSetupNonExistentDomain',
    5: 'NetSetupDnsMachine',
  };
  static enumValues: Record<string, number> = {
    NetSetupUnknown: 0,
    NetSetupMachine: 1,
    NetSetupWorkgroup: 2,
    NetSetupDomain: 3,
    NetSetupNonExistentDomain: 4,
    NetSetupDnsMachine: 5,
  };
}

export class NET_COMPUTER_NAME_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'NetPrimaryComputerName',
    1: 'NetAlternateComputerNames',
    2: 'NetAllComputerNames',
    3: 'NetComputerNameTypeMax',
  };
  static enumValues: Record<string, number> = {
    NetPrimaryComputerName: 0,
    NetAlternateComputerNames: 1,
    NetAllComputerNames: 2,
    NetComputerNameTypeMax: 3,
  };
}

export class WKSTA_INFO_100 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['wki100_platform_id', ULONG],
    ['wki100_computername', LPWSTR],
    ['wki100_langroup', LPWSTR],
    ['wki100_ver_major', ULONG],
    ['wki100_ver_minor', ULONG],
  ];
}

export class LPWKSTA_INFO_100 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WKSTA_INFO_100]];
}

export class WKSTA_INFO_101 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['wki101_platform_id', ULONG],
    ['wki101_computername', LPWSTR],
    ['wki101_langroup', LPWSTR],
    ['wki101_ver_major', ULONG],
    ['wki101_ver_minor', ULONG],
    ['wki101_lanroot', LPWSTR],
  ];
}

export class LPWKSTA_INFO_101 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WKSTA_INFO_101]];
}

export class WKSTA_INFO_102 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['wki102_platform_id', ULONG],
    ['wki102_computername', LPWSTR],
    ['wki102_langroup', LPWSTR],
    ['wki102_ver_major', ULONG],
    ['wki102_ver_minor', ULONG],
    ['wki102_lanroot', LPWSTR],
    ['wki102_logged_on_users', ULONG],
  ];
}

export class LPWKSTA_INFO_102 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WKSTA_INFO_102]];
}

export class WKSTA_INFO_502 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['wki502_char_wait', ULONG],
    ['wki502_collection_time', ULONG],
    ['wki502_maximum_collection_count', ULONG],
    ['wki502_keep_conn', ULONG],
    ['wki502_max_cmds', ULONG],
    ['wki502_sess_timeout', ULONG],
    ['wki502_siz_char_buf', ULONG],
    ['wki502_max_threads', ULONG],
    ['wki502_lock_quota', ULONG],
    ['wki502_lock_increment', ULONG],
    ['wki502_lock_maximum', ULONG],
    ['wki502_pipe_increment', ULONG],
    ['wki502_pipe_maximum', ULONG],
    ['wki502_cache_file_timeout', ULONG],
    ['wki502_dormant_file_limit', ULONG],
    ['wki502_read_ahead_throughput', ULONG],
    ['wki502_num_mailslot_buffers', ULONG],
    ['wki502_num_srv_announce_buffers', ULONG],
    ['wki502_max_illegal_datagram_events', ULONG],
    ['wki502_illegal_datagram_event_reset_frequency', ULONG],
    ['wki502_log_election_packets', LONG],
    ['wki502_use_opportunistic_locking', LONG],
    ['wki502_use_unlock_behind', LONG],
    ['wki502_use_close_behind', LONG],
    ['wki502_buf_named_pipes', LONG],
    ['wki502_use_lock_read_unlock', LONG],
    ['wki502_utilize_nt_caching', LONG],
    ['wki502_use_raw_read', LONG],
    ['wki502_use_raw_write', LONG],
    ['wki502_use_write_raw_data', LONG],
    ['wki502_use_encryption', LONG],
    ['wki502_buf_files_deny_write', LONG],
    ['wki502_buf_read_only_files', LONG],
    ['wki502_force_core_create_mode', LONG],
    ['wki502_use_512_byte_max_transfer', LONG],
  ];
}

export class LPWKSTA_INFO_502 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WKSTA_INFO_502]];
}

export class WKSTA_INFO_1013 extends NDRSTRUCT {
  static structure: NDRField[] = [['wki1013_keep_conn', ULONG]];
}

export class LPWKSTA_INFO_1013 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WKSTA_INFO_1013]];
}

export class WKSTA_INFO_1018 extends NDRSTRUCT {
  static structure: NDRField[] = [['wki1018_sess_timeout', ULONG]];
}

export class LPWKSTA_INFO_1018 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WKSTA_INFO_1018]];
}

export class WKSTA_INFO_1046 extends NDRSTRUCT {
  static structure: NDRField[] = [['wki1046_dormant_file_limit', ULONG]];
}

export class LPWKSTA_INFO_1046 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WKSTA_INFO_1046]];
}

export class WKSTA_INFO extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    100: ['WkstaInfo100', LPWKSTA_INFO_100],
    101: ['WkstaInfo101', LPWKSTA_INFO_101],
    102: ['WkstaInfo102', LPWKSTA_INFO_102],
    502: ['WkstaInfo502', LPWKSTA_INFO_502],
    1013: ['WkstaInfo1013', LPWKSTA_INFO_1013],
    1018: ['WkstaInfo1018', LPWKSTA_INFO_1018],
    1046: ['WkstaInfo1046', LPWKSTA_INFO_1046],
  };
}

export class LPWKSTA_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WKSTA_INFO]];
}

export class WKSTA_TRANSPORT_INFO_0 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['wkti0_quality_of_service', ULONG],
    ['wkti0_number_of_vcs', ULONG],
    ['wkti0_transport_name', LPWSTR],
    ['wkti0_transport_address', LPWSTR],
    ['wkti0_wan_ish', ULONG],
  ];
}

export class WKSTA_USER_INFO_0 extends NDRSTRUCT {
  static structure: NDRField[] = [['wkui0_username', LPWSTR]];
}

export class WKSTA_USER_INFO_1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['wkui1_username', LPWSTR],
    ['wkui1_logon_domain', LPWSTR],
    ['wkui1_oth_domains', LPWSTR],
    ['wkui1_logon_server', LPWSTR],
  ];
}

export class STAT_WORKSTATION_0 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['StatisticsStartTime', LARGE_INTEGER],
    ['BytesReceived', LARGE_INTEGER],
    ['SmbsReceived', LARGE_INTEGER],
    ['PagingReadBytesRequested', LARGE_INTEGER],
    ['NonPagingReadBytesRequested', LARGE_INTEGER],
    ['CacheReadBytesRequested', LARGE_INTEGER],
    ['NetworkReadBytesRequested', LARGE_INTEGER],
    ['BytesTransmitted', LARGE_INTEGER],
    ['SmbsTransmitted', LARGE_INTEGER],
    ['PagingWriteBytesRequested', LARGE_INTEGER],
    ['NonPagingWriteBytesRequested', LARGE_INTEGER],
    ['CacheWriteBytesRequested', LARGE_INTEGER],
    ['NetworkWriteBytesRequested', LARGE_INTEGER],
    ['InitiallyFailedOperations', ULONG],
    ['FailedCompletionOperations', ULONG],
    ['ReadOperations', ULONG],
    ['RandomReadOperations', ULONG],
    ['ReadSmbs', ULONG],
    ['LargeReadSmbs', ULONG],
    ['SmallReadSmbs', ULONG],
    ['WriteOperations', ULONG],
    ['RandomWriteOperations', ULONG],
    ['WriteSmbs', ULONG],
    ['LargeWriteSmbs', ULONG],
    ['SmallWriteSmbs', ULONG],
    ['RawReadsDenied', ULONG],
    ['RawWritesDenied', ULONG],
    ['NetworkErrors', ULONG],
    ['Sessions', ULONG],
    ['FailedSessions', ULONG],
    ['Reconnects', ULONG],
    ['CoreConnects', ULONG],
    ['Lanman20Connects', ULONG],
    ['Lanman21Connects', ULONG],
    ['LanmanNtConnects', ULONG],
    ['ServerDisconnects', ULONG],
    ['HungSessions', ULONG],
    ['UseCount', ULONG],
    ['FailedUseCount', ULONG],
    ['CurrentCommands', ULONG],
  ];
}

export class LPSTAT_WORKSTATION_0 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', STAT_WORKSTATION_0]];
}

export class WKSTA_USER_INFO_0_ARRAY extends NDRUniConformantArray {
  static item = WKSTA_USER_INFO_0;
}

export class LPWKSTA_USER_INFO_0_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WKSTA_USER_INFO_0_ARRAY]];
}

export class WKSTA_USER_INFO_0_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', ULONG],
    ['Buffer', LPWKSTA_USER_INFO_0_ARRAY],
  ];
}

export class LPWKSTA_USER_INFO_0_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WKSTA_USER_INFO_0_CONTAINER]];
}

export class WKSTA_USER_INFO_1_ARRAY extends NDRUniConformantArray {
  static item = WKSTA_USER_INFO_1;
}

export class LPWKSTA_USER_INFO_1_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WKSTA_USER_INFO_1_ARRAY]];
}

export class WKSTA_USER_INFO_1_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', ULONG],
    ['Buffer', LPWKSTA_USER_INFO_1_ARRAY],
  ];
}

export class LPWKSTA_USER_INFO_1_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WKSTA_USER_INFO_1_CONTAINER]];
}

export class WKSTA_USER_ENUM_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    0: ['Level0', LPWKSTA_USER_INFO_0_CONTAINER],
    1: ['Level1', LPWKSTA_USER_INFO_1_CONTAINER],
  };
}

export class WKSTA_USER_ENUM_STRUCT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Level', ULONG],
    ['WkstaUserInfo', WKSTA_USER_ENUM_UNION],
  ];
}

export class WKSTA_TRANSPORT_INFO_0_ARRAY extends NDRUniConformantArray {
  static item = WKSTA_TRANSPORT_INFO_0;
}

export class LPWKSTA_TRANSPORT_INFO_0_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WKSTA_TRANSPORT_INFO_0_ARRAY]];
}

export class WKSTA_TRANSPORT_INFO_0_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', ULONG],
    ['Buffer', LPWKSTA_TRANSPORT_INFO_0_ARRAY],
  ];
}

export class LPWKSTA_TRANSPORT_INFO_0_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WKSTA_TRANSPORT_INFO_0_CONTAINER]];
}

export class WKSTA_TRANSPORT_ENUM_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    0: ['Level0', LPWKSTA_TRANSPORT_INFO_0_CONTAINER],
  };
}

export class WKSTA_TRANSPORT_ENUM_STRUCT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Level', ULONG],
    ['WkstaTransportInfo', WKSTA_TRANSPORT_ENUM_UNION],
  ];
}

export class WKST_PASSWORD_WCHAR_ARRAY extends WIDESTR {
  getDataLen(data: Buffer, offset = 0): number {
    return JOIN_MAX_PASSWORD_LENGTH;
  }
}

export class WKST_OBFUSCATOR_CHAR_ARRAY extends NDRUniFixedArray {
  getDataLen(data: Buffer, offset = 0): number {
    return JOIN_OBFUSCATOR_LENGTH;
  }
}

export class JOINPR_USER_PASSWORD extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Obfuscator', WKST_OBFUSCATOR_CHAR_ARRAY],
    ['Buffer', WKST_PASSWORD_WCHAR_ARRAY],
  ];
}

export class JOINPR_ENCRYPTED_USER_PASSWORD extends NDRSTRUCT {
  static structure: NDRField[] = [['Buffer', '524s=b""']];

  getAlignment(): number {
    return 1;
  }
}

export class PJOINPR_ENCRYPTED_USER_PASSWORD extends NDRPOINTER {
  static referent: NDRField[] = [['Data', JOINPR_ENCRYPTED_USER_PASSWORD]];
}

export const UNICODE_STRING = WSTR;

export class PUNICODE_STRING extends NDRPOINTER {
  static referent: NDRField[] = [['Data', UNICODE_STRING]];
}

export class UNICODE_STRING_ARRAY extends NDRUniConformantArray {
  static item = RPC_UNICODE_STRING;
}

export class PUNICODE_STRING_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', UNICODE_STRING_ARRAY]];
}

export class NET_COMPUTER_NAME_ARRAY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', ULONG],
    ['ComputerNames', PUNICODE_STRING_ARRAY],
  ];
}

export class PNET_COMPUTER_NAME_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NET_COMPUTER_NAME_ARRAY]];
}

export class USE_INFO_0 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ui0_local', LPWSTR],
    ['ui0_remote', LPWSTR],
  ];
}

export class LPUSE_INFO_0 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', USE_INFO_0]];
}

export class USE_INFO_1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ui1_local', LPWSTR],
    ['ui1_remote', LPWSTR],
    ['ui1_password', LPWSTR],
    ['ui1_status', ULONG],
    ['ui1_asg_type', ULONG],
    ['ui1_refcount', ULONG],
    ['ui1_usecount', ULONG],
  ];
}

export class LPUSE_INFO_1 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', USE_INFO_1]];
}

export class USE_INFO_2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ui2_useinfo', USE_INFO_1],
    ['ui2_username', LPWSTR],
    ['ui2_domainname', LPWSTR],
  ];
}

export class LPUSE_INFO_2 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', USE_INFO_2]];
}

export class USE_INFO_3 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ui3_ui2', USE_INFO_2],
    ['ui3_flags', ULONG],
  ];
}

export class LPUSE_INFO_3 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', USE_INFO_3]];
}

export class USE_INFO extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    0: ['UseInfo0', LPUSE_INFO_0],
    1: ['UseInfo1', LPUSE_INFO_1],
    2: ['UseInfo2', LPUSE_INFO_2],
    3: ['UseInfo3', LPUSE_INFO_3],
  };
}

export class USE_INFO_0_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', ULONG],
    ['Buffer', LPUSE_INFO_0],
  ];
}

export class LPUSE_INFO_0_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', USE_INFO_0_CONTAINER]];
}

export class USE_INFO_1_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', ULONG],
    ['Buffer', LPUSE_INFO_1],
  ];
}

export class LPUSE_INFO_1_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', USE_INFO_1_CONTAINER]];
}

export class USE_INFO_2_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', ULONG],
    ['Buffer', LPUSE_INFO_2],
  ];
}

export class LPUSE_INFO_2_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', USE_INFO_2_CONTAINER]];
}

export class USE_ENUM_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    0: ['Level0', LPUSE_INFO_0_CONTAINER],
    1: ['Level1', LPUSE_INFO_1_CONTAINER],
    2: ['Level2', LPUSE_INFO_2_CONTAINER],
  };
}

export class USE_ENUM_STRUCT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Level', ULONG],
    ['UseInfo', USE_ENUM_UNION],
  ];
}

export class NetrWkstaGetInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['WkstaInfo', WKSTA_INFO],
    ['ErrorCode', ULONG],
  ];
}

export class NetrWkstaGetInfo extends NDRCALL {
  static opnum = 0;
  static Response = NetrWkstaGetInfoResponse;
  static structure: NDRField[] = [
    ['ServerName', LPWKSSVC_IDENTIFY_HANDLE],
    ['Level', ULONG],
  ];
}

export class NetrWkstaSetInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ErrorParameter', LPULONG],
    ['ErrorCode', ULONG],
  ];
}

export class NetrWkstaSetInfo extends NDRCALL {
  static opnum = 1;
  static Response = NetrWkstaSetInfoResponse;
  static structure: NDRField[] = [
    ['ServerName', LPWKSSVC_IDENTIFY_HANDLE],
    ['Level', ULONG],
    ['WkstaInfo', WKSTA_INFO],
    ['ErrorParameter', LPULONG],
  ];
}

export class NetrWkstaUserEnumResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['UserInfo', WKSTA_USER_ENUM_STRUCT],
    ['TotalEntries', ULONG],
    ['ResumeHandle', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class NetrWkstaUserEnum extends NDRCALL {
  static opnum = 2;
  static Response = NetrWkstaUserEnumResponse;
  static structure: NDRField[] = [
    ['ServerName', LPWKSSVC_IDENTIFY_HANDLE],
    ['UserInfo', WKSTA_USER_ENUM_STRUCT],
    ['PreferredMaximumLength', ULONG],
    ['ResumeHandle', LPULONG],
  ];
}

export class NetrWkstaTransportEnumResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['TransportInfo', WKSTA_TRANSPORT_ENUM_STRUCT],
    ['TotalEntries', ULONG],
    ['ResumeHandle', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class NetrWkstaTransportEnum extends NDRCALL {
  static opnum = 5;
  static Response = NetrWkstaTransportEnumResponse;
  static structure: NDRField[] = [
    ['ServerName', LPWKSSVC_IDENTIFY_HANDLE],
    ['TransportInfo', WKSTA_TRANSPORT_ENUM_STRUCT],
    ['PreferredMaximumLength', ULONG],
    ['ResumeHandle', LPULONG],
  ];
}

export class NetrWkstaTransportAddResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ErrorParameter', LPULONG],
    ['ErrorCode', ULONG],
  ];
}

export class NetrWkstaTransportAdd extends NDRCALL {
  static opnum = 6;
  static Response = NetrWkstaTransportAddResponse;
  static structure: NDRField[] = [
    ['ServerName', LPWKSSVC_IDENTIFY_HANDLE],
    ['Level', ULONG],
    ['TransportInfo', WKSTA_TRANSPORT_INFO_0],
    ['ErrorParameter', LPULONG],
  ];
}

export class NetrUseAddResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ErrorParameter', LPULONG],
    ['ErrorCode', ULONG],
  ];
}

export class NetrUseAdd extends NDRCALL {
  static opnum = 8;
  static Response = NetrUseAddResponse;
  static structure: NDRField[] = [
    ['ServerName', LPWKSSVC_IMPERSONATE_HANDLE],
    ['Level', ULONG],
    ['InfoStruct', USE_INFO],
    ['ErrorParameter', LPULONG],
  ];
}

export class NetrUseGetInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['InfoStruct', USE_INFO],
    ['ErrorCode', ULONG],
  ];
}

export class NetrUseGetInfo extends NDRCALL {
  static opnum = 9;
  static Response = NetrUseGetInfoResponse;
  static structure: NDRField[] = [
    ['ServerName', LPWKSSVC_IMPERSONATE_HANDLE],
    ['UseName', WSTR],
    ['Level', ULONG],
  ];
}

export class NetrUseDelResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrUseDel extends NDRCALL {
  static opnum = 10;
  static Response = NetrUseDelResponse;
  static structure: NDRField[] = [
    ['ServerName', LPWKSSVC_IMPERSONATE_HANDLE],
    ['UseName', WSTR],
    ['ForceLevel', ULONG],
  ];
}

export class NetrUseEnumResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['InfoStruct', USE_ENUM_STRUCT],
    ['TotalEntries', ULONG],
    ['ResumeHandle', LPULONG],
    ['ErrorCode', ULONG],
  ];
}

export class NetrUseEnum extends NDRCALL {
  static opnum = 11;
  static Response = NetrUseEnumResponse;
  static structure: NDRField[] = [
    ['ServerName', LPWKSSVC_IMPERSONATE_HANDLE],
    ['InfoStruct', USE_ENUM_STRUCT],
    ['PreferredMaximumLength', ULONG],
    ['ResumeHandle', LPULONG],
  ];
}

export class NetrWorkstationStatisticsGetResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Buffer', LPSTAT_WORKSTATION_0],
    ['ErrorCode', ULONG],
  ];
}

export class NetrWorkstationStatisticsGet extends NDRCALL {
  static opnum = 13;
  static Response = NetrWorkstationStatisticsGetResponse;
  static structure: NDRField[] = [
    ['ServerName', LPWKSSVC_IDENTIFY_HANDLE],
    ['ServiceName', LPWSTR],
    ['Level', ULONG],
    ['Options', ULONG],
  ];
}

export class NetrGetJoinInformationResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['NameBuffer', LPWSTR],
    ['BufferType', NETSETUP_JOIN_STATUS],
    ['ErrorCode', ULONG],
  ];
}

export class NetrGetJoinInformation extends NDRCALL {
  static opnum = 20;
  static Response = NetrGetJoinInformationResponse;
  static structure: NDRField[] = [
    ['ServerName', LPWKSSVC_IMPERSONATE_HANDLE],
    ['NameBuffer', LPWSTR],
  ];
}

export class NetrJoinDomain2Response extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrJoinDomain2 extends NDRCALL {
  static opnum = 22;
  static Response = NetrJoinDomain2Response;
  static structure: NDRField[] = [
    ['ServerName', LPWSTR],
    ['DomainNameParam', WSTR],
    ['MachineAccountOU', LPWSTR],
    ['AccountName', LPWSTR],
    ['Password', PJOINPR_ENCRYPTED_USER_PASSWORD],
    ['Options', ULONG],
  ];
}

export class NetrUnjoinDomain2Response extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrUnjoinDomain2 extends NDRCALL {
  static opnum = 23;
  static Response = NetrUnjoinDomain2Response;
  static structure: NDRField[] = [
    ['ServerName', LPWSTR],
    ['AccountName', LPWSTR],
    ['Password', PJOINPR_ENCRYPTED_USER_PASSWORD],
    ['Options', ULONG],
  ];
}

export class NetrRenameMachineInDomain2Response extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrRenameMachineInDomain2 extends NDRCALL {
  static opnum = 24;
  static Response = NetrRenameMachineInDomain2Response;
  static structure: NDRField[] = [
    ['ServerName', LPWSTR],
    ['MachineName', LPWSTR],
    ['AccountName', LPWSTR],
    ['Password', PJOINPR_ENCRYPTED_USER_PASSWORD],
    ['Options', ULONG],
  ];
}

export class NetrValidateName2Response extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrValidateName2 extends NDRCALL {
  static opnum = 25;
  static Response = NetrValidateName2Response;
  static structure: NDRField[] = [
    ['ServerName', LPWSTR],
    ['NameToValidate', WSTR],
    ['AccountName', LPWSTR],
    ['Password', PJOINPR_ENCRYPTED_USER_PASSWORD],
    ['NameType', NETSETUP_NAME_TYPE],
  ];
}

export class NetrGetJoinableOUs2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['OUCount', LPLONG],
    ['OUs', PUNICODE_STRING_ARRAY],
    ['ErrorCode', ULONG],
  ];
}

export class NetrGetJoinableOUs2 extends NDRCALL {
  static opnum = 26;
  static Response = NetrGetJoinableOUs2Response;
  static structure: NDRField[] = [
    ['ServerName', LPWSTR],
    ['DomainNameParam', WSTR],
    ['AccountName', LPWSTR],
    ['Password', PJOINPR_ENCRYPTED_USER_PASSWORD],
    ['OUCount', ULONG],
  ];
}

export class NetrAddAlternateComputerNameResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrAddAlternateComputerName extends NDRCALL {
  static opnum = 27;
  static Response = NetrAddAlternateComputerNameResponse;
  static structure: NDRField[] = [
    ['ServerName', LPWSTR],
    ['AlternateName', LPWSTR],
    ['DomainAccount', LPWSTR],
    ['EncryptedPassword', PJOINPR_ENCRYPTED_USER_PASSWORD],
    ['Reserved', ULONG],
  ];
}

export class NetrRemoveAlternateComputerNameResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrRemoveAlternateComputerName extends NDRCALL {
  static opnum = 28;
  static Response = NetrRemoveAlternateComputerNameResponse;
  static structure: NDRField[] = [
    ['ServerName', LPWSTR],
    ['AlternateName', LPWSTR],
    ['DomainAccount', LPWSTR],
    ['EncryptedPassword', PJOINPR_ENCRYPTED_USER_PASSWORD],
    ['Reserved', ULONG],
  ];
}

export class NetrSetPrimaryComputerNameResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrSetPrimaryComputerName extends NDRCALL {
  static opnum = 29;
  static Response = NetrSetPrimaryComputerNameResponse;
  static structure: NDRField[] = [
    ['ServerName', LPWSTR],
    ['PrimaryName', LPWSTR],
    ['DomainAccount', LPWSTR],
    ['EncryptedPassword', PJOINPR_ENCRYPTED_USER_PASSWORD],
    ['Reserved', ULONG],
  ];
}

export class NetrEnumerateComputerNamesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ComputerNames', PNET_COMPUTER_NAME_ARRAY],
    ['ErrorCode', ULONG],
  ];
}

export class NetrEnumerateComputerNames extends NDRCALL {
  static opnum = 30;
  static Response = NetrEnumerateComputerNamesResponse;
  static structure: NDRField[] = [
    ['ServerName', LPWKSSVC_IMPERSONATE_HANDLE],
    ['NameType', NET_COMPUTER_NAME_TYPE],
    ['Reserved', ULONG],
  ];
}

const OPNUMS = {
  0: [NetrWkstaGetInfo, NetrWkstaGetInfoResponse] as const,
  1: [NetrWkstaSetInfo, NetrWkstaSetInfoResponse] as const,
  2: [NetrWkstaUserEnum, NetrWkstaUserEnumResponse] as const,
  5: [NetrWkstaTransportEnum, NetrWkstaTransportEnumResponse] as const,
  6: [NetrWkstaTransportAdd, NetrWkstaTransportAddResponse] as const,
  8: [NetrUseAdd, NetrUseAddResponse] as const,
  9: [NetrUseGetInfo, NetrUseGetInfoResponse] as const,
  10: [NetrUseDel, NetrUseDelResponse] as const,
  11: [NetrUseEnum, NetrUseEnumResponse] as const,
  13: [NetrWorkstationStatisticsGet, NetrWorkstationStatisticsGetResponse] as const,
  20: [NetrGetJoinInformation, NetrGetJoinInformationResponse] as const,
  22: [NetrJoinDomain2, NetrJoinDomain2Response] as const,
  23: [NetrUnjoinDomain2, NetrUnjoinDomain2Response] as const,
  24: [NetrRenameMachineInDomain2, NetrRenameMachineInDomain2Response] as const,
  25: [NetrValidateName2, NetrValidateName2Response] as const,
  26: [NetrGetJoinableOUs2, NetrGetJoinableOUs2Response] as const,
  27: [NetrAddAlternateComputerName, NetrAddAlternateComputerNameResponse] as const,
  28: [NetrRemoveAlternateComputerName, NetrRemoveAlternateComputerNameResponse] as const,
  29: [NetrSetPrimaryComputerName, NetrSetPrimaryComputerNameResponse] as const,
  30: [NetrEnumerateComputerNames, NetrEnumerateComputerNamesResponse] as const,
};

type DceRequestFn = <T>(req: unknown, uuid?: unknown, checkError?: boolean) => Promise<T>;

function checkNullString(str: string | typeof NULL): string | typeof NULL {
  if (str === NULL) return str;
  if (typeof str !== 'string') return str;
  if (str.length === 0 || str[str.length - 1] !== '\x00') return str + '\x00';
  return str;
}

export async function hNetrWkstaGetInfo(dce: DCERPC_v5, level: number) {
  const request = new NetrWkstaGetInfo();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  request.set('Level', level);
  return (dce as unknown as { request: DceRequestFn }).request<NetrWkstaGetInfoResponse>(request);
}

export async function hNetrWkstaUserEnum(
  dce: DCERPC_v5,
  level: number,
  preferredMaximumLength = 0xffffffff,
) {
  const request = new NetrWkstaUserEnum();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  const userInfo = request.fields['UserInfo'] as WKSTA_USER_ENUM_STRUCT;
  userInfo.set('Level', level);
  const wkstaUserInfo = userInfo.fields['WkstaUserInfo'] as WKSTA_USER_ENUM_UNION;
  wkstaUserInfo.set('tag', level);
  request.set('PreferredMaximumLength', preferredMaximumLength);
  return (dce as unknown as { request: DceRequestFn }).request<NetrWkstaUserEnumResponse>(request);
}

export async function hNetrWkstaTransportEnum(
  dce: DCERPC_v5,
  level: number,
  resumeHandle = 0,
  preferredMaximumLength = 0xffffffff,
) {
  const request = new NetrWkstaTransportEnum();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  const transportInfo = request.fields['TransportInfo'] as WKSTA_TRANSPORT_ENUM_STRUCT;
  transportInfo.set('Level', level);
  const wkstaTransportInfo = transportInfo.fields['WkstaTransportInfo'] as WKSTA_TRANSPORT_ENUM_UNION;
  wkstaTransportInfo.set('tag', level);
  request.set('ResumeHandle', resumeHandle);
  request.set('PreferredMaximumLength', preferredMaximumLength);
  return (dce as unknown as { request: DceRequestFn }).request<NetrWkstaTransportEnumResponse>(
    request,
  );
}

export async function hNetrWkstaSetInfo(
  dce: DCERPC_v5,
  level: number,
  wkstInfo: unknown,
) {
  const request = new NetrWkstaSetInfo();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  request.set('Level', level);
  const wkstaInfo = request.fields['WkstaInfo'] as WKSTA_INFO;
  wkstaInfo.set('tag', level);
  const armName = `WkstaInfo${level}` as keyof WKSTA_INFO['fields'];
  wkstaInfo.set(armName, wkstInfo);
  return (dce as unknown as { request: DceRequestFn }).request<NetrWkstaSetInfoResponse>(request);
}

export async function hNetrWorkstationStatisticsGet(
  dce: DCERPC_v5,
  serviceName: unknown,
  level: number,
  options: number,
) {
  const request = new NetrWorkstationStatisticsGet();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  request.set('ServiceName', serviceName);
  request.set('Level', level);
  request.set('Options', options);
  return (dce as unknown as { request: DceRequestFn }).request<NetrWorkstationStatisticsGetResponse>(
    request,
  );
}

export async function hNetrGetJoinInformation(dce: DCERPC_v5, nameBuffer: unknown) {
  const request = new NetrGetJoinInformation();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  request.set('NameBuffer', nameBuffer);
  return (dce as unknown as { request: DceRequestFn }).request<NetrGetJoinInformationResponse>(
    request,
  );
}

export async function hNetrJoinDomain2(
  dce: DCERPC_v5,
  domainNameParam: string,
  machineAccountOU: string | typeof NULL,
  accountName: string | typeof NULL,
  password: Buffer | typeof NULL,
  options: number,
) {
  const request = new NetrJoinDomain2();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  request.set('DomainNameParam', checkNullString(domainNameParam) as string);
  request.set('MachineAccountOU', checkNullString(machineAccountOU));
  request.set('AccountName', checkNullString(accountName));
  if (password === NULL) {
    request.set('Password', NULL);
  } else {
    const pw = request.fields['Password'] as PJOINPR_ENCRYPTED_USER_PASSWORD;
    const pwData = pw.fields['Data'] as JOINPR_ENCRYPTED_USER_PASSWORD;
    pwData.set('Buffer', password);
  }
  request.set('Options', options);
  return (dce as unknown as { request: DceRequestFn }).request<NetrJoinDomain2Response>(request);
}

export async function hNetrUnjoinDomain2(
  dce: DCERPC_v5,
  accountName: string | typeof NULL,
  password: Buffer | typeof NULL,
  options: number,
) {
  const request = new NetrUnjoinDomain2();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  request.set('AccountName', checkNullString(accountName));
  if (password === NULL) {
    request.set('Password', NULL);
  } else {
    const pw = request.fields['Password'] as PJOINPR_ENCRYPTED_USER_PASSWORD;
    const pwData = pw.fields['Data'] as JOINPR_ENCRYPTED_USER_PASSWORD;
    pwData.set('Buffer', password);
  }
  request.set('Options', options);
  return (dce as unknown as { request: DceRequestFn }).request<NetrUnjoinDomain2Response>(request);
}

export async function hNetrRenameMachineInDomain2(
  dce: DCERPC_v5,
  machineName: string | typeof NULL,
  accountName: string | typeof NULL,
  password: Buffer | typeof NULL,
  options: number,
) {
  const request = new NetrRenameMachineInDomain2();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  request.set('MachineName', checkNullString(machineName));
  request.set('AccountName', checkNullString(accountName));
  if (password === NULL) {
    request.set('Password', NULL);
  } else {
    const pw = request.fields['Password'] as PJOINPR_ENCRYPTED_USER_PASSWORD;
    const pwData = pw.fields['Data'] as JOINPR_ENCRYPTED_USER_PASSWORD;
    pwData.set('Buffer', password);
  }
  request.set('Options', options);
  return (dce as unknown as { request: DceRequestFn }).request<NetrRenameMachineInDomain2Response>(
    request,
  );
}

export async function hNetrValidateName2(
  dce: DCERPC_v5,
  nameToValidate: string,
  accountName: string | typeof NULL,
  password: Buffer | typeof NULL,
  nameType: number,
) {
  const request = new NetrValidateName2();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  request.set('NameToValidate', checkNullString(nameToValidate) as string);
  request.set('AccountName', checkNullString(accountName));
  if (password === NULL) {
    request.set('Password', NULL);
  } else {
    const pw = request.fields['Password'] as PJOINPR_ENCRYPTED_USER_PASSWORD;
    const pwData = pw.fields['Data'] as JOINPR_ENCRYPTED_USER_PASSWORD;
    pwData.set('Buffer', password);
  }
  request.set('NameType', nameType);
  return (dce as unknown as { request: DceRequestFn }).request<NetrValidateName2Response>(request);
}

export async function hNetrGetJoinableOUs2(
  dce: DCERPC_v5,
  domainNameParam: string,
  accountName: string | typeof NULL,
  password: Buffer | typeof NULL,
  OUCount: number,
) {
  const request = new NetrGetJoinableOUs2();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  request.set('DomainNameParam', checkNullString(domainNameParam) as string);
  request.set('AccountName', checkNullString(accountName));
  if (password === NULL) {
    request.set('Password', NULL);
  } else {
    const pw = request.fields['Password'] as PJOINPR_ENCRYPTED_USER_PASSWORD;
    const pwData = pw.fields['Data'] as JOINPR_ENCRYPTED_USER_PASSWORD;
    pwData.set('Buffer', password);
  }
  request.set('OUCount', OUCount);
  return (dce as unknown as { request: DceRequestFn }).request<NetrGetJoinableOUs2Response>(request);
}

export async function hNetrAddAlternateComputerName(
  dce: DCERPC_v5,
  alternateName: string | typeof NULL,
  domainAccount: string | typeof NULL,
  encryptedPassword: Buffer | typeof NULL,
) {
  const request = new NetrAddAlternateComputerName();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  request.set('AlternateName', checkNullString(alternateName));
  request.set('DomainAccount', checkNullString(domainAccount));
  if (encryptedPassword === NULL) {
    request.set('EncryptedPassword', NULL);
  } else {
    const pw = request.fields['EncryptedPassword'] as PJOINPR_ENCRYPTED_USER_PASSWORD;
    const pwData = pw.fields['Data'] as JOINPR_ENCRYPTED_USER_PASSWORD;
    pwData.set('Buffer', encryptedPassword);
  }
  return (dce as unknown as { request: DceRequestFn }).request<NetrAddAlternateComputerNameResponse>(
    request,
  );
}

export async function hNetrRemoveAlternateComputerName(
  dce: DCERPC_v5,
  alternateName: string | typeof NULL,
  domainAccount: string | typeof NULL,
  encryptedPassword: Buffer | typeof NULL,
) {
  const request = new NetrRemoveAlternateComputerName();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  request.set('AlternateName', checkNullString(alternateName));
  request.set('DomainAccount', checkNullString(domainAccount));
  if (encryptedPassword === NULL) {
    request.set('EncryptedPassword', NULL);
  } else {
    const pw = request.fields['EncryptedPassword'] as PJOINPR_ENCRYPTED_USER_PASSWORD;
    const pwData = pw.fields['Data'] as JOINPR_ENCRYPTED_USER_PASSWORD;
    pwData.set('Buffer', encryptedPassword);
  }
  return (dce as unknown as { request: DceRequestFn }).request<NetrRemoveAlternateComputerNameResponse>(
    request,
  );
}

export async function hNetrSetPrimaryComputerName(
  dce: DCERPC_v5,
  primaryName: string | typeof NULL,
  domainAccount: string | typeof NULL,
  encryptedPassword: Buffer | typeof NULL,
) {
  const request = new NetrSetPrimaryComputerName();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  request.set('PrimaryName', checkNullString(primaryName));
  request.set('DomainAccount', checkNullString(domainAccount));
  if (encryptedPassword === NULL) {
    request.set('EncryptedPassword', NULL);
  } else {
    const pw = request.fields['EncryptedPassword'] as PJOINPR_ENCRYPTED_USER_PASSWORD;
    const pwData = pw.fields['Data'] as JOINPR_ENCRYPTED_USER_PASSWORD;
    pwData.set('Buffer', encryptedPassword);
  }
  return (dce as unknown as { request: DceRequestFn }).request<NetrSetPrimaryComputerNameResponse>(
    request,
  );
}

export async function hNetrEnumerateComputerNames(
  dce: DCERPC_v5,
  nameType: number,
) {
  const request = new NetrEnumerateComputerNames();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  request.set('NameType', nameType);
  return (dce as unknown as { request: DceRequestFn }).request<NetrEnumerateComputerNamesResponse>(
    request,
  );
}

export async function hNetrUseAdd(
  dce: DCERPC_v5,
  level: number,
  infoStruct: unknown,
) {
  const request = new NetrUseAdd();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  request.set('Level', level);
  const infoS = request.fields['InfoStruct'] as USE_INFO;
  infoS.set('tag', level);
  const armName = `UseInfo${level}` as keyof USE_INFO['fields'];
  infoS.set(armName, infoStruct);
  return (dce as unknown as { request: DceRequestFn }).request<NetrUseAddResponse>(request);
}

export async function hNetrUseEnum(
  dce: DCERPC_v5,
  level: number,
  resumeHandle = 0,
  preferredMaximumLength = 0xffffffff,
) {
  const request = new NetrUseEnum();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  const infoStruct = request.fields['InfoStruct'] as USE_ENUM_STRUCT;
  infoStruct.set('Level', level);
  const useInfo = infoStruct.fields['UseInfo'] as USE_ENUM_UNION;
  useInfo.set('tag', level);
  const levelArmName = `Level${level}` as keyof USE_ENUM_UNION['fields'];
  const levelContainer = useInfo.fields[levelArmName] as
    | LPUSE_INFO_0_CONTAINER
    | LPUSE_INFO_1_CONTAINER
    | LPUSE_INFO_2_CONTAINER;
  const containerData = levelContainer.fields['Data'] as
    | USE_INFO_0_CONTAINER
    | USE_INFO_1_CONTAINER
    | USE_INFO_2_CONTAINER;
  containerData.set('Buffer', NULL);
  request.set('PreferredMaximumLength', preferredMaximumLength);
  request.set('ResumeHandle', resumeHandle);
  return (dce as unknown as { request: DceRequestFn }).request<NetrUseEnumResponse>(request);
}

export async function hNetrUseGetInfo(
  dce: DCERPC_v5,
  useName: string,
  level: number,
) {
  const request = new NetrUseGetInfo();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  request.set('UseName', checkNullString(useName) as string);
  request.set('Level', level);
  return (dce as unknown as { request: DceRequestFn }).request<NetrUseGetInfoResponse>(request);
}

export async function hNetrUseDel(
  dce: DCERPC_v5,
  useName: string,
  forceLevel = USE_LOTS_OF_FORCE,
) {
  const request = new NetrUseDel();
  request.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
  request.set('UseName', checkNullString(useName) as string);
  request.set('ForceLevel', forceLevel);
  return (dce as unknown as { request: DceRequestFn }).request<NetrUseDelResponse>(request);
}
