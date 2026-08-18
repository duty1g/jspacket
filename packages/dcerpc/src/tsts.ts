// Impacket-js - TypeScript port of impacket
//
// [MS-TSTS] Terminal Services Terminal Server Runtime Interface Protocol implementation
//
// Interface Implementation based on:
//   [MS-TSTS] - v20210625
//   [MS-TSTS] - v20080207

import { uuidtupToBin, binToString, stringToBin } from '@impacket/uuid';
import {
  NDR,
  NDRCALL,
  NDRSTRUCT,
  NDRPOINTER,
  NDRENUM,
  NDRUNION,
  NDRUniConformantArray,
  NDRUniConformantVaryingArray,
  NDRUniFixedArray,
  UNKNOWNDATA,
  NULL,
  type NDRField,
  type NDRFieldType,
} from './ndr';
import {
  STR,
  WSTR,
  WIDESTR,
  LPWSTR,
  RPC_UNICODE_STRING,
  LONG,
  UINT,
  ULONG,
  PULONG,
  LPDWORD,
  LARGE_INTEGER,
  DWORD,
  USHORT,
  UCHAR,
  PCHAR,
  BYTE,
  PBYTE,
  UUID,
  GUID,
  BOOL,
  BOOLEAN,
} from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

////////////////////////////////////////////////////////////////////////////////
// Constants
////////////////////////////////////////////////////////////////////////////////

export const TermSrvSession_UUID = uuidtupToBin([
  '484809d6-4239-471b-b5bc-61df8c23ac48',
  '1.0',
]);
export const TermSrvNotification_UUID = uuidtupToBin([
  '11899a43-2b68-4a76-92e3-a3d6ad8c26ce',
  '1.0',
]);
export const TermSrvEnumeration_UUID = uuidtupToBin([
  '88143fd0-c28d-4b2b-8fef-8d882f6a9390',
  '1.0',
]);
export const RCMPublic_UUID = uuidtupToBin([
  'bde95fdf-eee0-45de-9e12-e5a61cd0d4fe',
  '1.0',
]);
export const RcmListener_UUID = uuidtupToBin([
  '497d95a6-2d27-4bf5-9bbd-a6046957133c',
  '1.0',
]);
export const SessEnvPublicRpc_UUID = uuidtupToBin([
  '1257b580-ce2f-4109-82d6-a9459d0bf6bc',
  '1.0',
]);
export const LegacyAPI_UUID = uuidtupToBin([
  '5ca4a760-ebb1-11cf-8611-00a0245420ed',
  '1.0',
]);

export const AUDIODRIVENAME_LENGTH = 9;
export const WDPREFIX_LENGTH = 12;
export const STACK_ADDRESS_LENGTH = 128;
export const MAX_BR_NAME = 65;
export const DIRECTORY_LENGTH = 256;
export const INITIALPROGRAM_LENGTH = 256;
export const USERNAME_LENGTH = 20;
export const DOMAIN_LENGTH = 17;
export const PASSWORD_LENGTH = 14;
export const NASISPECIFICNAME_LENGTH = 14;
export const NASIUSERNAME_LENGTH = 47;
export const NASIPASSWORD_LENGTH = 24;
export const NASISESSIONNAME_LENGTH = 16;
export const NASIFILESERVER_LENGTH = 47;
export const CLIENTDATANAME_LENGTH = 7;
export const CLIENTNAME_LENGTH = 20;
export const CLIENTADDRESS_LENGTH = 30;
export const IMEFILENAME_LENGTH = 32;
export const CLIENTLICENSE_LENGTH = 32;
export const CLIENTMODEM_LENGTH = 40;
export const CLIENT_PRODUCT_ID_LENGTH = 32;
export const MAX_COUNTER_EXTENSIONS = 2;
export const WINSTATIONNAME_LENGTH = 32;
export const PROTOCOL_CONSOLE = 0;
export const PROTOCOL_ICA = 1;
export const PROTOCOL_TSHARE = 2;
export const PROTOCOL_RDP = 2;
export const PDNAME_LENGTH = 32;
export const WDNAME_LENGTH = 32;
export const CDNAME_LENGTH = 32;
export const DEVICENAME_LENGTH = 128;
export const MODEMNAME_LENGTH = DEVICENAME_LENGTH;
export const CALLBACK_LENGTH = 50;
export const DLLNAME_LENGTH = 32;
export const WINSTATIONCOMMENT_LENGTH = 60;
export const MAX_LICENSE_SERVER_LENGTH = 1024;
export const LOGONID_CURRENT = ULONG;
export const MAX_PDCONFIG = 10;
export const TERMSRV_TOTAL_SESSIONS = 1;
export const TERMSRV_DISC_SESSIONS = 2;
export const TERMSRV_RECON_SESSIONS = 3;
export const TERMSRV_CURRENT_ACTIVE_SESSIONS = 4;
export const TERMSRV_CURRENT_DISC_SESSIONS = 5;
export const TERMSRV_PENDING_SESSIONS = 6;
export const TERMSRV_SUCC_TOTAL_LOGONS = 7;
export const TERMSRV_SUCC_LOCAL_LOGONS = 8;
export const TERMSRV_SUCC_REMOTE_LOGONS = 9;
export const TERMSRV_SUCC_SESSION0_LOGONS = 10;
export const TERMSRV_CURRENT_TERMINATING_SESSIONS = 11;
export const TERMSRV_CURRENT_LOGGEDON_SESSIONS = 12;
export const NO_FALLBACK_DRIVERS = 0x0;
export const FALLBACK_BESTGUESS = 0x1;
export const FALLBACK_PCL = 0x2;
export const FALLBACK_PS = 0x3;
export const FALLBACK_PCLANDPS = 0x4;
export const VIRTUALCHANNELNAME_LENGTH = 7;

export const WINSTATION_QUERY = 0x00000001;
export const WINSTATION_SET = 0x00000002;
export const WINSTATION_RESET = 0x00000004;
export const WINSTATION_VIRTUAL = 0x00000008;
export const WINSTATION_SHADOW = 0x00000010;
export const WINSTATION_LOGON = 0x00000020;
export const WINSTATION_LOGOFF = 0x00000040;
export const WINSTATION_MSG = 0x00000080;
export const WINSTATION_CONNECT = 0x00000100;
export const WINSTATION_DISCONNECT = 0x00000200;

////////////////////////////////////////////////////////////////////////////////
// Types
////////////////////////////////////////////////////////////////////////////////

export class TS_WCHAR extends WSTR {
  static commonHdr: NDRField[] = [['ActualCount', '<L=len(Data)//2']];
  static commonHdr64: NDRField[] = [['ActualCount', '<Q=len(Data)//2']];
  static structure: NDRField[] = [['Data', ':']];
}

export class TS_LPWCHAR extends NDRPOINTER {
  static referent: NDRField[] = [['Data', TS_WCHAR]];
}

export class TS_CHAR extends STR {
  static commonHdr: NDRField[] = [['ActualCount', '<L=len(Data)']];
  static commonHdr64: NDRField[] = [['ActualCount', '<Q=len(Data)']];
  static structure: NDRField[] = [['Data', ':']];
}

export class SYSTEM_TIMESTAMP extends NDR {
  static structure: NDRField[] = [['Data', '<Q=0']];
}

// 2.2.2.15.1.1 TS_UNICODE_STRING
export class TS_UNICODE_STRING extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Length', USHORT],
    ['MaximumLength', USHORT],
    ['Buffer', LPWSTR],
  ];
}

export class TS_LPCHAR extends NDRPOINTER {
  static referent: NDRField[] = [['Data', TS_CHAR]];
}
export const TS_PBYTE = TS_LPCHAR;

export class TS_WCHAR_STRIPPED extends TS_WCHAR {}

export class WIDESTR_STRIPPED extends WIDESTR {}

export class WSTR_STRIPPED extends WSTR {}

export class LPWCHAR_STRIPPED extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WIDESTR_STRIPPED]];
}

// Module-private array types (collide with nrpc)
class LONG_ARRAY extends NDRUniConformantArray {
  static item: NDRFieldType = 'L';
}

class UCHAR_ARRAY extends NDRUniConformantArray {
  static item: NDRFieldType = 'c';
}

export class LPUCHAR_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', UCHAR_ARRAY]];
}

export class WCHAR_ARRAY_32 extends WIDESTR_STRIPPED {}
export class WCHAR_ARRAY_256 extends WIDESTR_STRIPPED {}
export class WCHAR_ARRAY_33 extends WIDESTR_STRIPPED {}
export class WCHAR_ARRAY_21 extends WIDESTR_STRIPPED {}
export class WCHAR_ARRAY_18 extends WIDESTR_STRIPPED {}
export class WCHAR_ARRAY_4 extends WIDESTR_STRIPPED {}
export class WCHAR_CLIENTNAME_LENGTH extends WIDESTR_STRIPPED {}
export class WCHAR_DOMAIN_LENGTH extends WIDESTR_STRIPPED {}
export class WCHAR_USERNAME_LENGTH extends WIDESTR_STRIPPED {}
export class WCHAR_PASSWORD_LENGTH extends WIDESTR_STRIPPED {}
export class WCHAR_DIRECTORY_LENGTH extends WIDESTR_STRIPPED {}
export class WCHAR_INITIALPROGRAM_LENGTH extends WIDESTR_STRIPPED {}
export class WCHAR_CLIENTADDRESS_LENGTH extends WIDESTR_STRIPPED {}
export class WCHAR_IMEFILENAME_LENGTH extends WIDESTR_STRIPPED {}
export class WCHAR_CLIENTLICENSE_LENGTH extends WIDESTR_STRIPPED {}
export class WCHAR_CLIENTMODEM_LENGTH extends WIDESTR_STRIPPED {}
export class WCHAR_AUDIODRIVENAME_LENGTH extends WIDESTR_STRIPPED {}
export class WCHAR_CLIENT_PRODUCT_ID_LENGTH extends WIDESTR_STRIPPED {}
export class WCHAR_NASIFILESERVER_LENGTH extends WIDESTR_STRIPPED {}
export class WCHAR_CALLBACK_LENGTH extends WIDESTR_STRIPPED {}
export class WCHAR_MAX_BR_NAME extends WIDESTR_STRIPPED {}
export class WCHAR_WINSTATIONCOMMENT_LENGTH extends WIDESTR_STRIPPED {}

////////////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////////////

// Module-private (collides with epm.ts)
class DCERPCSessionError extends DCERPCException {
  toString(): string {
    return `TSTS SessionError: code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

export function ZEROPAD(data: string, size?: number): string {
  if (size === undefined) {
    size = data.length + 1;
  }
  if (data.length > size) throw new Error('Invalid data size!');
  return data + '\0'.repeat(size - data.length);
}

function getUnixTime(t: number): number {
  t -= 116444736000000000;
  t /= 10000000;
  return t;
}

function formatSid(buf: Buffer): string {
  if (!buf || buf.length < 8) return '';
  const revision = buf[0];
  const subAuthCount = buf[1] ?? 0;
  const authority = buf.readUIntBE(2, 6);
  let sid = `S-${revision}-${authority}`;
  for (let i = 0; i < subAuthCount; i++) {
    if (8 + i * 4 + 4 > buf.length) break;
    sid += `-${buf.readUInt32LE(8 + i * 4)}`;
  }
  return sid;
}

const KNOWN_SIDS: Record<string, string> = {
  'S-1-5-10': 'SELF',
  'S-1-5-13': 'TERMINAL SERVER USER',
  'S-1-5-11': 'Authenticated Users',
  'S-1-5-12': 'RESTRICTED',
  'S-1-5-14': 'Authenticated Users',
  'S-1-5-15': 'This Organization',
  'S-1-5-17': 'IUSR',
  'S-1-5-18': 'SYSTEM',
  'S-1-5-19': 'LOCAL SERVICE',
  'S-1-5-20': 'NETWORK SERVICE',
};

export function knownSid(sid: string): string {
  const parts = sid.split('-');
  if (sid.startsWith('S-1-5-90-0-') && parts.length === 6) {
    return `DWM-${parseInt(parts[parts.length - 1]!, 10)}`;
  } else if (sid.startsWith('S-1-5-96-0-') && parts.length === 6) {
    return `UMFD-${parseInt(parts[parts.length - 1]!, 10)}`;
  } else if (KNOWN_SIDS[sid]) {
    return KNOWN_SIDS[sid];
  }
  return sid;
}

class SID extends TS_CHAR {}

////////////////////////////////////////////////////////////////////////////////
// Handles
////////////////////////////////////////////////////////////////////////////////

export class context_handle extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['context_handle_attributes', ULONG],
    ['context_handle_uuid', UUID],
  ];

  constructor(data?: Buffer | null, isNDR64: boolean = false) {
    super(data, isNDR64);
    if (!data) {
      this.set('context_handle_uuid', Buffer.alloc(16, 0));
    }
  }

  getUUID(): string {
    return binToString(this.get('context_handle_uuid') as Buffer);
  }

  tuple(): [string, number] {
    return [
      binToString(this.get('context_handle_uuid') as Buffer),
      this.get('context_handle_attributes') as number,
    ];
  }

  fromTuple(tup: [string, number]): void {
    this.set('context_handle_uuid', stringToBin(tup[0]));
    this.set('context_handle_attributes', tup[1]);
  }

  isNull(): boolean {
    const uuid = this.get('context_handle_uuid') as Buffer;
    return Buffer.isBuffer(uuid) && uuid.equals(Buffer.alloc(16, 0));
  }

  toString(): string {
    return binToString(this.get('context_handle_uuid') as Buffer);
  }
}

// Module-private handle_t (collides with even6.ts)
class handle_t_tsts extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', '20s=b""']];
}

// 2.2.1.2 ENUM_HANDLE
export const ENUM_HANDLE = context_handle;

export class pHandle extends NDRPOINTER {
  static referent: NDRField[] = [['Data', handle_t_tsts]];
}

// 2.2.1.3 HLISTENER
export const HLISTENER = context_handle;

// 2.2.1.4 SERVER_HANDLE
export const SERVER_HANDLE = context_handle;

// 2.2.1.15 NOTIFY_HANDLE
export const NOTIFY_HANDLE = context_handle;

// 2.2.1.1 SESSION_HANDLE
export const SESSION_HANDLE = context_handle;

////////////////////////////////////////////////////////////////////////////////
// Structures
////////////////////////////////////////////////////////////////////////////////

export class MSGBOX_ENUM extends NDRENUM {
  static enumItems: Record<number, string> = {
    3: 'IDABORT',
    2: 'IDCANCEL',
    5: 'IDIGNORE',
    7: 'IDNO',
    1: 'IDOK',
    4: 'IDRETRY',
    6: 'IDYES',
    32001: 'IDASYNC',
    32000: 'IDTIMEOUT',
  };
  static enumValues: Record<string, number> = {
    IDABORT: 3,
    IDCANCEL: 2,
    IDIGNORE: 5,
    IDNO: 7,
    IDOK: 1,
    IDRETRY: 4,
    IDYES: 6,
    IDASYNC: 32001,
    IDTIMEOUT: 32000,
  };
}

export class ShutdownFlags extends NDRENUM {
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    0x00000001: 'WSD_LOGOFF',
    0x00000002: 'WSD_SHUTDOWN',
    0x00000004: 'WSD_REBOOT',
    0x00000008: 'WSD_POWEROFF',
  };
  static enumValues: Record<string, number> = {
    WSD_LOGOFF: 0x00000001,
    WSD_SHUTDOWN: 0x00000002,
    WSD_REBOOT: 0x00000004,
    WSD_POWEROFF: 0x00000008,
  };
}

export class HotKeyModifiers extends NDRENUM {
  static structure: NDRField[] = [['Data', '<H']];
  static enumItems: Record<number, string> = {
    0: 'NONE',
    1: 'Alt',
    2: 'Control',
    4: 'Shift',
    8: 'WindowsKey',
  };
  static enumValues: Record<string, number> = {
    NONE: 0,
    Alt: 1,
    Control: 2,
    Shift: 4,
    WindowsKey: 8,
  };
}

export class EventFlags extends NDRENUM {
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    0x00000000: 'WEVENT_NONE',
    0x00000001: 'WEVENT_CREATE',
    0x00000002: 'WEVENT_DELETE',
    0x00000004: 'WEVENT_RENAME',
    0x00000008: 'WEVENT_CONNECT',
    0x00000010: 'WEVENT_DISCONNECT',
    0x00000020: 'WEVENT_LOGON',
    0x00000040: 'WEVENT_LOGOFF',
    0x00000080: 'WEVENT_STATECHANGE',
    0x00000100: 'WEVENT_LICENSE',
    0x7fffffff: 'WEVENT_ALL',
    0x80000000: 'WEVENT_FLUSH',
  };
  static enumValues: Record<string, number> = {
    WEVENT_NONE: 0x00000000,
    WEVENT_CREATE: 0x00000001,
    WEVENT_DELETE: 0x00000002,
    WEVENT_RENAME: 0x00000004,
    WEVENT_CONNECT: 0x00000008,
    WEVENT_DISCONNECT: 0x00000010,
    WEVENT_LOGON: 0x00000020,
    WEVENT_LOGOFF: 0x00000040,
    WEVENT_STATECHANGE: 0x00000080,
    WEVENT_LICENSE: 0x00000100,
    WEVENT_ALL: 0x7fffffff,
    WEVENT_FLUSH: 0x80000000,
  };
}

export class ADDRESSFAMILY_ENUM extends NDRENUM {
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    16: 'AppleTalk',
    22: 'Atm',
    21: 'Banyan',
    10: 'Ccitt',
    5: 'Chaos',
    24: 'Cluster',
    65537: 'ControllerAreaNetwork',
    9: 'DataKit',
    13: 'DataLink',
    12: 'DecNet',
    8: 'Ecma',
    19: 'FireFox',
    15: 'HyperChannel',
    25: 'Ieee12844',
    3: 'ImpLink',
    2: 'InterNetwork',
    23: 'InterNetworkV6',
    6: 'Ipx',
    26: 'Irda',
    7: 'Iso',
    14: 'Lat',
    29: 'Max',
    17: 'NetBios',
    28: 'NetworkDesigners',
    65536: 'Packet',
    4: 'Pup',
    11: 'Sna',
    1: 'Unix',
    0: 'Unspecified',
    18: 'VoiceView',
  };
  static enumValues: Record<string, number> = {
    AppleTalk: 16,
    Atm: 22,
    Banyan: 21,
    Ccitt: 10,
    Chaos: 5,
    Cluster: 24,
    ControllerAreaNetwork: 65537,
    DataKit: 9,
    DataLink: 13,
    DecNet: 12,
    Ecma: 8,
    FireFox: 19,
    HyperChannel: 15,
    Ieee12844: 25,
    ImpLink: 3,
    InterNetwork: 2,
    InterNetworkV6: 23,
    Ipx: 6,
    Irda: 26,
    Iso: 7,
    Lat: 14,
    Max: 29,
    NetBios: 17,
    NetworkDesigners: 28,
    NS: 6,
    Osi: 7,
    Packet: 65536,
    Pup: 4,
    Sna: 11,
    Unix: 1,
    Unspecified: 0,
    VoiceView: 18,
  };
}

// 2.2.1.5 WINSTATIONNAME
export class WINSTATIONNAME extends WIDESTR_STRIPPED {}

// 2.2.1.6 DLLNAME
export class DLLNAME extends WIDESTR {}

export class PDLLNAME extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DLLNAME]];
}

// 2.2.1.7 DEVICENAME
export class DEVICENAME extends WIDESTR {}

export class PDEVICENAME extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DEVICENAME]];
}

// 2.2.1.13 CLIENTDATANAME
export class CLIENTDATANAME extends STR {}

export class PCLIENTDATANAME extends NDRPOINTER {
  static referent: NDRField[] = [['Data', CLIENTDATANAME]];
}

// 2.2.1.8 WINSTATIONINFOCLASS
export class WINSTATIONINFOCLASS extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'WinStationCreateData',
    1: 'WinStationConfiguration',
    2: 'WinStationPdParams',
    3: 'WinStationWd',
    4: 'WinStationPd',
    5: 'WinStationPrinter',
    6: 'WinStationClient',
    7: 'WinStationModules',
    8: 'WinStationInformation',
    9: 'WinStationTrace',
    10: 'WinStationBeep',
    11: 'WinStationEncryptionOff',
    12: 'WinStationEncryptionPerm',
    13: 'WinStationNtSecurity',
    14: 'WinStationUserToken',
    15: 'WinStationUnused1',
    16: 'WinStationVideoData',
    17: 'WinStationInitialProgram',
    18: 'WinStationCd',
    19: 'WinStationSystemTrace',
    20: 'WinStationVirtualData',
    21: 'WinStationClientData',
    22: 'WinStationSecureDesktopEnter',
    23: 'WinStationSecureDesktopExit',
    24: 'WinStationLoadBalanceSessionTarget',
    25: 'WinStationLoadIndicator',
    26: 'WinStationShadowInfo',
    27: 'WinStationDigProductId',
    28: 'WinStationLockedState',
    29: 'WinStationRemoteAddress',
    30: 'WinStationIdleTime',
    31: 'WinStationLastReconnectType',
    32: 'WinStationDisallowAutoReconnect',
    33: 'WinStationUnused2',
    34: 'WinStationUnused3',
    35: 'WinStationUnused4',
    36: 'WinStationUnused5',
    37: 'WinStationReconnectedFromId',
    38: 'WinStationEffectsPolicy',
    39: 'WinStationType',
    40: 'WinStationInformationEx',
  };
  static enumValues: Record<string, number> = {
    WinStationCreateData: 0,
    WinStationConfiguration: 1,
    WinStationPdParams: 2,
    WinStationWd: 3,
    WinStationPd: 4,
    WinStationPrinter: 5,
    WinStationClient: 6,
    WinStationModules: 7,
    WinStationInformation: 8,
    WinStationTrace: 9,
    WinStationBeep: 10,
    WinStationEncryptionOff: 11,
    WinStationEncryptionPerm: 12,
    WinStationNtSecurity: 13,
    WinStationUserToken: 14,
    WinStationUnused1: 15,
    WinStationVideoData: 16,
    WinStationInitialProgram: 17,
    WinStationCd: 18,
    WinStationSystemTrace: 19,
    WinStationVirtualData: 20,
    WinStationClientData: 21,
    WinStationSecureDesktopEnter: 22,
    WinStationSecureDesktopExit: 23,
    WinStationLoadBalanceSessionTarget: 24,
    WinStationLoadIndicator: 25,
    WinStationShadowInfo: 26,
    WinStationDigProductId: 27,
    WinStationLockedState: 28,
    WinStationRemoteAddress: 29,
    WinStationIdleTime: 30,
    WinStationLastReconnectType: 31,
    WinStationDisallowAutoReconnect: 32,
    WinStationUnused2: 33,
    WinStationUnused3: 34,
    WinStationUnused4: 35,
    WinStationUnused5: 36,
    WinStationReconnectedFromId: 37,
    WinStationEffectsPolicy: 38,
    WinStationType: 39,
    WinStationInformationEx: 40,
  };
}

// 2.2.1.9 WINSTATIONSTATECLASS
export class WINSTATIONSTATECLASS extends NDRENUM {
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    0: 'State_Active',
    1: 'State_Connected',
    2: 'State_ConnectQuery',
    3: 'State_Shadow',
    4: 'State_Disconnected',
    5: 'State_Idle',
    6: 'State_Listen',
    7: 'State_Reset',
    8: 'State_Down',
    9: 'State_Init',
  };
  static enumValues: Record<string, number> = {
    State_Active: 0,
    State_Connected: 1,
    State_ConnectQuery: 2,
    State_Shadow: 3,
    State_Disconnected: 4,
    State_Idle: 5,
    State_Listen: 6,
    State_Reset: 7,
    State_Down: 8,
    State_Init: 9,
  };
}

// 2.2.1.10 SDCLASS
export class SDCLASS extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'SdNone',
    1: 'SdConsole',
    2: 'SdNetwork',
    3: 'SdAsync',
    4: 'SdOemTransport',
  };
  static enumValues: Record<string, number> = {
    SdNone: 0,
    SdConsole: 1,
    SdNetwork: 2,
    SdAsync: 3,
    SdOemTransport: 4,
  };
}

// 2.2.1.11 SHADOWCLASS
export class SHADOWCLASS extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'Shadow_Disable',
    1: 'Shadow_EnableInputNotify',
    2: 'Shadow_EnableInputNoNotify',
    3: 'Shadow_EnableNoInputNotify',
    4: 'Shadow_EnableNoInputNoNotify',
  };
  static enumValues: Record<string, number> = {
    Shadow_Disable: 0,
    Shadow_EnableInputNotify: 1,
    Shadow_EnableInputNoNotify: 2,
    Shadow_EnableNoInputNotify: 3,
    Shadow_EnableNoInputNoNotify: 4,
  };
}

// 2.2.1.12 RECONNECT_TYPE
export class RECONNECT_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'NeverReconnected',
    1: 'ManualReconnect',
    2: 'AutoReconnect',
  };
  static enumValues: Record<string, number> = {
    NeverReconnected: 0,
    ManualReconnect: 1,
    AutoReconnect: 2,
  };
}

export class PRECONNECT_TYPE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', RECONNECT_TYPE]];
}

// 2.2.1.6 BOUNDED_ULONG
export const BOUNDED_ULONG = ULONG;

// 2.2.1.17 UINT_PTR
export class UINT_PTR extends NDRPOINTER {
  static referent: NDRField[] = [['Data', UINT]];
}

// 2.2.1.18 SESSIONTYPE
export class SESSIONTYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'SESSIONTYPE_UNKNOWN',
    1: 'SESSIONTYPE_SERVICES',
    2: 'SESSIONTYPE_LISTENER',
    3: 'SESSIONTYPE_REGULARDESKTOP',
    4: 'SESSIONTYPE_ALTERNATESHELL',
    5: 'SESSIONTYPE_REMOTEAPP',
    6: 'SESSIONTYPE_MEDIACENTEREXT',
  };
  static enumValues: Record<string, number> = {
    SESSIONTYPE_UNKNOWN: 0,
    SESSIONTYPE_SERVICES: 1,
    SESSIONTYPE_LISTENER: 2,
    SESSIONTYPE_REGULARDESKTOP: 3,
    SESSIONTYPE_ALTERNATESHELL: 4,
    SESSIONTYPE_REMOTEAPP: 5,
    SESSIONTYPE_MEDIACENTEREXT: 6,
  };
}

// 2.2.1.19 SHADOW_CONTROL_REQUEST
export class SHADOW_CONTROL_REQUEST extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'SHADOW_CONTROL_REQUEST_VIEW',
    1: 'SHADOW_CONTROL_REQUEST_TAKECONTROL',
    2: 'SHADOW_CONTROL_REQUEST_Count',
  };
  static enumValues: Record<string, number> = {
    SHADOW_CONTROL_REQUEST_VIEW: 0,
    SHADOW_CONTROL_REQUEST_TAKECONTROL: 1,
    SHADOW_CONTROL_REQUEST_Count: 2,
  };
}

// 2.2.1.20 SHADOW_PERMISSION_REQUEST
export class SHADOW_PERMISSION_REQUEST extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'SHADOW_PERMISSION_REQUEST_SILENT',
    1: 'SHADOW_PERMISSION_REQUEST_REQUESTPERMISSION',
    2: 'SHADOW_PERMISSION_REQUEST_Count',
  };
  static enumValues: Record<string, number> = {
    SHADOW_PERMISSION_REQUEST_SILENT: 0,
    SHADOW_PERMISSION_REQUEST_REQUESTPERMISSION: 1,
    SHADOW_PERMISSION_REQUEST_Count: 2,
  };
}

// 2.2.1.21 SHADOW_REQUEST_RESPONSE
export class SHADOW_REQUEST_RESPONSE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'SHADOW_REQUEST_RESPONSE_ALLOW',
    1: 'SHADOW_REQUEST_RESPONSE_DECLINE',
    2: 'SHADOW_REQUEST_RESPONSE_POLICY_PERMISSION_REQUIRED',
    3: 'SHADOW_REQUEST_RESPONSE_POLICY_DISABLED',
    4: 'SHADOW_REQUEST_RESPONSE_POLICY_VIEW_ONLY',
    5: 'SHADOW_REQUEST_RESPONSE_POLICY_VIEW_ONLY_PERMISSION_REQUIRED',
    6: 'SHADOW_REQUEST_RESPONSE_SESSION_ALREADY_CONTROLLED',
  };
  static enumValues: Record<string, number> = {
    SHADOW_REQUEST_RESPONSE_ALLOW: 0,
    SHADOW_REQUEST_RESPONSE_DECLINE: 1,
    SHADOW_REQUEST_RESPONSE_POLICY_PERMISSION_REQUIRED: 2,
    SHADOW_REQUEST_RESPONSE_POLICY_DISABLED: 3,
    SHADOW_REQUEST_RESPONSE_POLICY_VIEW_ONLY: 4,
    SHADOW_REQUEST_RESPONSE_POLICY_VIEW_ONLY_PERMISSION_REQUIRED: 5,
    SHADOW_REQUEST_RESPONSE_SESSION_ALREADY_CONTROLLED: 6,
  };
}

// 2.2.2.1 SESSION_FILTER
export class SESSION_FILTER extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'SF_SERVICES_SESSION_POPUP',
  };
  static enumValues: Record<string, number> = {
    SF_SERVICES_SESSION_POPUP: 0,
  };
}

// 2.2.2.2 PROTOCOLSTATUS_INFO_TYPE
export class PROTOCOLSTATUS_INFO_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'PROTOCOLSTATUS_INFO_BASIC',
    1: 'PROTOCOLSTATUS_INFO_EXTENDED',
  };
  static enumValues: Record<string, number> = {
    PROTOCOLSTATUS_INFO_BASIC: 0,
    PROTOCOLSTATUS_INFO_EXTENDED: 1,
  };
}

// 2.2.2.3 QUERY_SESSION_DATA_TYPE
export class QUERY_SESSION_DATA_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'QUERY_SESSION_DATA_MODULE',
    1: 'QUERY_SESSION_DATA_WDCONFIG',
    2: 'QUERY_SESSION_DATA_VIRTUALDATA',
    3: 'QUERY_SESSION_DATA_LICENSE',
    4: 'QUERY_SESSION_DATA_DEVICEID',
    5: 'QUERY_SESSION_DATA_LICENSE_VALIDATION',
  };
  static enumValues: Record<string, number> = {
    QUERY_SESSION_DATA_MODULE: 0,
    QUERY_SESSION_DATA_WDCONFIG: 1,
    QUERY_SESSION_DATA_VIRTUALDATA: 2,
    QUERY_SESSION_DATA_LICENSE: 3,
    QUERY_SESSION_DATA_DEVICEID: 4,
    QUERY_SESSION_DATA_LICENSE_VALIDATION: 5,
  };
}

// 2.2.2.4.1.1 SESSIONENUM_LEVEL1
export class SESSIONENUM_LEVEL1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['SessionId', LONG],
    ['State', WINSTATIONSTATECLASS],
    ['Name', WCHAR_ARRAY_33],
  ];
}

// 2.2.2.4.1.2 SESSIONENUM_LEVEL2
export class SESSIONENUM_LEVEL2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['SessionId', LONG],
    ['State', WINSTATIONSTATECLASS],
    ['Name', WCHAR_ARRAY_33],
    ['Source', ULONG],
    ['bFullDesktop', BOOLEAN],
    ['SessionType', GUID],
  ];
}

// 2.2.2.4.1.3 SESSIONENUM_LEVEL3
export class SESSIONENUM_LEVEL3 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['SessionId', LONG],
    ['State', WINSTATIONSTATECLASS],
    ['Name', WCHAR_ARRAY_33],
    ['Source', ULONG],
    ['bFullDesktop', BOOLEAN],
    ['SessionType', GUID],
    ['ProtoDataSize', ULONG],
    ['pProtocolData', UCHAR],
  ];
}

// 2.2.2.4.1 SessionInfo
export class SessionInfo extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    0: null,
    1: ['SessionEnum_Level1', SESSIONENUM_LEVEL1],
    2: ['SessionEnum_Level2', SESSIONENUM_LEVEL2],
    3: ['SessionEnum_Level3', SESSIONENUM_LEVEL3],
    default: null,
  };
}

export class SessionInfo_STRUCT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Level', DWORD],
    ['SessionInfo', SessionInfo],
  ];
}

// 2.2.2.4 PSESSIONENUM
export class SESSIONENUM extends NDRUniConformantArray {
  static item: NDRFieldType = SessionInfo_STRUCT;
}

export class PSESSIONENUM extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SESSIONENUM]];
}

// 2.2.2.5.1 SessionInfo_Ex
export const SessionInfo_Ex = SessionInfo;

// 2.2.2.5 PSESSIONENUM_EX
export const PSESSIONENUM_EX = SESSIONENUM;

// 2.2.2.6.1.1 EXECENVDATA_LEVEL1
export class EXECENVDATA_LEVEL1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ExecEnvId', LONG],
    ['State', WINSTATIONSTATECLASS],
    ['SessionName', WCHAR_ARRAY_33],
  ];
}

export class PEXECENVDATA_LEVEL1 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', EXECENVDATA_LEVEL1]];
}

// 2.2.2.6.1.2 EXECENVDATA_LEVEL2
export class EXECENVDATA_LEVEL2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ExecEnvId', LONG],
    ['State', WINSTATIONSTATECLASS],
    ['SessionName', WCHAR_ARRAY_33],
    ['AbsSessionId', LONG],
    ['HostName', WCHAR_ARRAY_33],
    ['UserName', WCHAR_ARRAY_33],
    ['DomainName', WCHAR_ARRAY_33],
    ['FarmName', WCHAR_ARRAY_33],
  ];
}

export class PEXECENVDATA_LEVEL2 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', EXECENVDATA_LEVEL2]];
}

// 2.2.2.6.1 ExecEnvData
export class ExecEnvData extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['ExecEnvEnum_Level1', EXECENVDATA_LEVEL1],
    2: ['ExecEnvEnum_Level2', EXECENVDATA_LEVEL2],
  };
}

export class ExecEnvData_STRUCT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Level', DWORD],
    ['ExecEnvData', ExecEnvData],
  ];
}

// 2.2.2.6 PEXECENVDATA
export class EXECENVDATA extends NDRUniConformantArray {
  static item: NDRFieldType = ExecEnvData_STRUCT;
}

export class PEXECENVDATA extends NDRPOINTER {
  static referent: NDRField[] = [['Data', EXECENVDATA]];
}

// 2.2.2.7.1.1 EXECENVDATAEX_LEVEL1
export class EXECENVDATAEX_LEVEL1 extends NDRSTRUCT {
  // FIXME: this structure does not work
}

// 2.2.2.7.1 ExecEnvDataEx
export class ExecEnvDataEx extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['ExecEnvEnum_Level1', EXECENVDATAEX_LEVEL1],
  };
}

// 2.2.2.7 PEXECENVDATAEX
export class EXECENVDATAEX extends NDRUniConformantArray {
  static item: NDRFieldType = ExecEnvDataEx;
}

export class PEXECENVDATAEX extends NDRPOINTER {
  static referent: NDRField[] = [['Data', EXECENVDATAEX]];
}

// 2.2.2.12.1.1 LISTENERENUM_LEVEL1
export class LISTENERENUM_LEVEL1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Id', LONG],
    ['bListening', BOOL],
    ['Name', WCHAR_ARRAY_33],
  ];
}

// 2.2.2.12.1 ListenerInfo
export class ListenerInfo extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['ListenerEnum_Level1', LISTENERENUM_LEVEL1],
  };
}

export class ListenerInfo_STRUCT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Level', DWORD],
    ['ListenerInfo', ListenerInfo],
  ];
}

// 2.2.2.12 PLISTENERENUM
export class LISTENERENUM extends NDRUniConformantArray {
  static item: NDRFieldType = ListenerInfo_STRUCT;
}

export class PLISTENERENUM extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LISTENERENUM]];
}

// 2.2.2.8 PLSMSESSIONINFORMATION
export class LSMSESSIONINFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['pszUserName', LPWCHAR_STRIPPED],
    ['pszDomain', LPWCHAR_STRIPPED],
    ['pszTerminalName', LPWCHAR_STRIPPED],
    ['SessionState', WINSTATIONSTATECLASS],
    ['DesktopLocked', BOOLEAN],
    ['ConnectTime', SYSTEM_TIMESTAMP],
    ['DisconnectTime', SYSTEM_TIMESTAMP],
    ['LogonTime', SYSTEM_TIMESTAMP],
  ];
}

// 2.2.2.19.1.1 TS_SYSTEMTIME
export class TS_SYSTEMTIME extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['wYear', USHORT],
    ['wMonth', USHORT],
    ['wDayOfWeek', USHORT],
    ['wDay', USHORT],
    ['wHour', USHORT],
    ['wMinute', USHORT],
    ['wSecond', USHORT],
    ['wMilliseconds', USHORT],
  ];
}

// 2.2.2.19.1 TS_TIME_ZONE_INFORMATION
export class TS_TIME_ZONE_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Bias', ULONG],
    ['StandardName', WCHAR_ARRAY_32],
    ['StandardDate', TS_SYSTEMTIME],
    ['StandardBias', ULONG],
    ['DaylightName', WCHAR_ARRAY_32],
    ['DaylightDate', TS_SYSTEMTIME],
    ['DaylightBias', ULONG],
  ];
}

// 2.2.2.19 WINSTATIONCLIENT FLAGS helper
export class WINSTATIONCLIENT_FLAGS extends NDRSTRUCT {
  static structure: NDRField[] = [['flags', '6s=b""']];
}

// 2.2.2.19 WINSTATIONCLIENT
export class WINSTATIONCLIENT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['flags', WINSTATIONCLIENT_FLAGS],
    ['ClientName', WCHAR_CLIENTNAME_LENGTH],
    ['Domain', WCHAR_DOMAIN_LENGTH],
    ['UserName', WCHAR_USERNAME_LENGTH],
    ['Password', WCHAR_PASSWORD_LENGTH],
    ['WorkDirectory', WCHAR_DIRECTORY_LENGTH],
    ['InitialProgram', WCHAR_INITIALPROGRAM_LENGTH],
    ['SerialNumber', ULONG],
    ['EncryptionLevel', BYTE],
    ['ClientAddressFamily', ADDRESSFAMILY_ENUM],
    ['ClientAddress', WCHAR_CLIENTADDRESS_LENGTH],
    ['HRes', USHORT],
    ['VRes', USHORT],
    ['ColorDepth', USHORT],
    ['ProtocolType', USHORT],
    ['KeyboardLayout', ULONG],
    ['KeyboardType', ULONG],
    ['KeyboardSubType', ULONG],
    ['KeyboardFunctionKey', ULONG],
    ['imeFileName', WCHAR_IMEFILENAME_LENGTH],
    ['ClientDirectory', WCHAR_DIRECTORY_LENGTH],
    ['ClientLicense', WCHAR_CLIENTLICENSE_LENGTH],
    ['ClientModem', WCHAR_CLIENTMODEM_LENGTH],
    ['ClientBuildNumber', ULONG],
    ['ClientHardwareId', ULONG],
    ['ClientProductId', USHORT],
    ['OutBufCountHost', USHORT],
    ['OutBufCountClient', USHORT],
    ['OutBufLength', USHORT],
    ['AudioDriverName', WCHAR_AUDIODRIVENAME_LENGTH],
    ['ClientTimeZone', TS_TIME_ZONE_INFORMATION],
    ['ClientSessionId', ULONG],
    ['clientDigProductId', WCHAR_CLIENT_PRODUCT_ID_LENGTH],
    ['PerformanceFlags', ULONG],
    ['ActiveInputLocale', ULONG],
  ];
}

export class PWINSTATIONCLIENT extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WINSTATIONCLIENT]];
}

// 2.2.2.17.1 TS_COUNTER_HEADER
export class TS_COUNTER_HEADER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwCounterID', DWORD],
    ['bResult', BOOLEAN],
  ];
}

// 2.2.2.17 TS_COUNTER
export class TS_COUNTER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['counterHead', TS_COUNTER_HEADER],
    ['dwValue', DWORD],
    ['startTime', LARGE_INTEGER],
  ];
}

export class TS_COUNTER_ARRAY extends NDRUniConformantArray {
  static item: NDRFieldType = TS_COUNTER;
}

export class PTS_COUNTER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', TS_COUNTER_ARRAY]];
}

// 2.2.2.11 LSM_SESSIONINFO_EX_LEVEL1
export class SESSIONFLAGS extends NDRENUM {
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    0xffffffff: 'WTS_SESSIONSTATE_UNKNOWN',
    0x00000000: 'WTS_SESSIONSTATE_LOCK',
    0x00000001: 'WTS_SESSIONSTATE_UNLOCK',
  };
  static enumValues: Record<string, number> = {
    WTS_SESSIONSTATE_UNKNOWN: 0xffffffff,
    WTS_SESSIONSTATE_LOCK: 0x00000000,
    WTS_SESSIONSTATE_UNLOCK: 0x00000001,
  };
}

export class LSM_SESSIONINFO_EX_LEVEL1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['SessionState', WINSTATIONSTATECLASS],
    ['SessionFlags', SESSIONFLAGS],
    ['SessionName', WCHAR_ARRAY_33],
    ['DomainName', WCHAR_ARRAY_18],
    ['UserName', WCHAR_ARRAY_21],
    ['ConnectTime', SYSTEM_TIMESTAMP],
    ['DisconnectTime', SYSTEM_TIMESTAMP],
    ['LogonTime', SYSTEM_TIMESTAMP],
    ['LastInputTime', SYSTEM_TIMESTAMP],
    ['ProtocolDataSize', ULONG],
    ['ProtocolData', TS_LPCHAR],
  ];
}

// 2.2.2.10 LSM_SESSIONINFO_EX
export class LSM_SESSIONINFO_EX extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['LSM_SessionInfo_Level1', LSM_SESSIONINFO_EX_LEVEL1],
  };
}

// 2.2.2.9 PLSMSESSIONINFORMATION_EX
export class PLSMSESSIONINFORMATION_EX extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LSM_SESSIONINFO_EX]];
}

// 2.2.1.14 TNotificationId
export class TNotificationId extends NDRENUM {
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    0x0: 'WTS_NOTIFY_NONE',
    0x1: 'WTS_NOTIFY_CREATE',
    0x2: 'WTS_NOTIFY_CONNECT',
    0x4: 'WTS_NOTIFY_DISCONNECT',
    0x8: 'WTS_NOTIFY_LOGON',
    0x10: 'WTS_NOTIFY_LOGOFF',
    0x20: 'WTS_NOTIFY_SHADOW_START',
    0x40: 'WTS_NOTIFY_SHADOW_STOP',
    0x80: 'WTS_NOTIFY_TERMINATE',
    0x100: 'WTS_NOTIFY_CONSOLE_CONNECT',
    0x200: 'WTS_NOTIFY_CONSOLE_DISCONNECT',
    0x400: 'WTS_NOTIFY_LOCK',
    0x800: 'WTS_NOTIFY_UNLOCK',
    0xffffffff: 'WTS_NOTIFY_ALL',
  };
  static enumValues: Record<string, number> = {
    WTS_NOTIFY_NONE: 0x0,
    WTS_NOTIFY_CREATE: 0x1,
    WTS_NOTIFY_CONNECT: 0x2,
    WTS_NOTIFY_DISCONNECT: 0x4,
    WTS_NOTIFY_LOGON: 0x8,
    WTS_NOTIFY_LOGOFF: 0x10,
    WTS_NOTIFY_SHADOW_START: 0x20,
    WTS_NOTIFY_SHADOW_STOP: 0x40,
    WTS_NOTIFY_TERMINATE: 0x80,
    WTS_NOTIFY_CONSOLE_CONNECT: 0x100,
    WTS_NOTIFY_CONSOLE_DISCONNECT: 0x200,
    WTS_NOTIFY_LOCK: 0x400,
    WTS_NOTIFY_UNLOCK: 0x800,
    WTS_NOTIFY_ALL: 0xffffffff,
  };
}

// 2.2.2.42 SESSION_CHANGE
export class SESSION_CHANGE extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['SessionId', LONG],
    ['TNotificationId', TNotificationId],
  ];
}

export class SESSION_CHANGE_ARRAY extends NDRUniConformantArray {
  static item: NDRFieldType = SESSION_CHANGE;
}

export class PSESSION_CHANGE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SESSION_CHANGE_ARRAY]];
}

// 2.2.2.18.1 CALLBACKCLASS
export class CALLBACKCLASS extends NDRENUM {
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    0: 'Callback_Disable',
    1: 'Callback_Roving',
    2: 'Callback_Fixed',
  };
  static enumValues: Record<string, number> = {
    Callback_Disable: 0,
    Callback_Roving: 1,
    Callback_Fixed: 2,
  };
}

// 2.2.2.18 USERCONFIG FLAGS helper
export class USERCONFIG_FLAGS extends NDRSTRUCT {
  static structure: NDRField[] = [['flags', '7s=b""']];
}

// 2.2.2.18 USERCONFIG
export class USERCONFIG extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['flags', USERCONFIG_FLAGS],
    ['UserName', WCHAR_USERNAME_LENGTH],
    ['Domain', WCHAR_DOMAIN_LENGTH],
    ['Password', WCHAR_PASSWORD_LENGTH],
    ['WorkDirectory', WCHAR_DIRECTORY_LENGTH],
    ['InitialProgram', WCHAR_INITIALPROGRAM_LENGTH],
    ['CallbackNumber', WCHAR_CALLBACK_LENGTH],
    ['Callback', CALLBACKCLASS],
    ['Shadow', SHADOWCLASS],
    ['MaxConnectionTime', ULONG],
    ['MaxDisconnectionTime', ULONG],
    ['MaxIdleTime', ULONG],
    ['KeyboardLayout', ULONG],
    ['MinEncryptionLevel', BYTE],
    ['NWLogonServer', WCHAR_NASIFILESERVER_LENGTH],
    ['PublishedName', WCHAR_MAX_BR_NAME],
    ['WFProfilePath', WCHAR_DIRECTORY_LENGTH],
    ['WFHomeDir', WCHAR_DIRECTORY_LENGTH],
    ['WFHomeDirDrive', WCHAR_ARRAY_4],
  ];
}

export class OEMId extends NDRSTRUCT {
  static structure: NDRField[] = [['OEMId', '4s=""']];
}

// 2.2.2.30.1 WINSTATIONCONFIG
export class WINSTATIONCONFIG extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Comment', WCHAR_WINSTATIONCOMMENT_LENGTH],
    ['User', USERCONFIG],
    ['OEMId', OEMId],
  ];
}

export class PWINSTATIONCONFIG extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WINSTATIONCONFIG]];
}

// NOT_IMPLEMENTED 2.2.2.20.1.2 PROTOCOLCOUNTERS
export class PROTOCOLCOUNTERS extends NDRSTRUCT {}

// NOT_IMPLEMENTED 2.2.2.20.1.3 CACHE_STATISTICS
export class CACHE_STATISTICS extends NDRSTRUCT {}

// NOT_IMPLEMENTED 2.2.2.20.1 PROTOCOLSTATUS
export class PROTOCOLSTATUS extends NDRSTRUCT {}

export class PPROTOCOLSTATUS extends NDRPOINTER {
  static referent: NDRField[] = [['Data', PROTOCOLSTATUS]];
}

// 2.2.2.43 RCM_REMOTEADDRESS
export class IPv4ADDRESS extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', '<L']];
}

export class RCM_REMOTEADDRESS_UNION_CASE_IPV4_4CHAR extends NDRSTRUCT {
  static structure: NDRField[] = [['sin_zero', '4s=b""']];
}

export class RCM_REMOTEADDRESS_UNION_CASE_IPV4 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['sin_port', USHORT],
    ['sin_port2', USHORT],
    ['in_addr', IPv4ADDRESS],
    ['sin_zero', RCM_REMOTEADDRESS_UNION_CASE_IPV4_4CHAR],
  ];
}

export class RCM_REMOTEADDRESS_UNION_CASE_IPV6_8CHAR extends NDRSTRUCT {
  static structure: NDRField[] = [['sin_zero', '8s=b""']];
}

export class RCM_REMOTEADDRESS_UNION_CASE_IPV6 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['sin_port', USHORT],
    ['in_addr', ULONG],
    ['sin_zero', RCM_REMOTEADDRESS_UNION_CASE_IPV6_8CHAR],
    ['sin6_scope_id', ULONG],
  ];
}

export class RCM_REMOTEADDRESS extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', USHORT]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    2: ['ipv4', RCM_REMOTEADDRESS_UNION_CASE_IPV4],
    23: ['ipv6', RCM_REMOTEADDRESS_UNION_CASE_IPV6],
  };
}

export class pResult_ENUM extends NDRENUM {
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    0x00000000: 'STATUS_SUCCESS',
    0xc000000d: 'STATUS_INVALID_PARAMETER',
    0xc0000120: 'STATUS_CANCELLED',
    0xc0000003: 'STATUS_INVALID_INFO_CLASS',
    0xc0000017: 'STATUS_NO_MEMORY',
    0xc0000022: 'STATUS_ACCESS_DENIED',
    0xc0000023: 'STATUS_BUFFER_TOO_SMALL',
    0xc0000002: 'STATUS_NOT_IMPLEMENTED',
    0xc0000004: 'STATUS_INFO_LENGTH_MISMATCH',
    0xc0000001: 'STATUS_UNSUCCESSFUL',
    0xc00a0015: 'STATUS_CTX_WINSTATION_NOT_FOUND',
    0xc000006a: 'STATUS_WRONG_PASSWORD',
    0x80071b6e: 'DOES_NOT_EXISTS_OR_INSUFFICIENT_PERMISSIONS',
    0x80070057: 'INVALID_PARAMETER2',
    0x80070005: 'ERROR_ACCESS_DENIED',
    0x8007139f: 'ERROR_INVALID_STATE',
    0x8007052e: 'ERROR_LOGON_FAILURE',
    0x80070002: 'ERROR_FILE_NOT_FOUND',
    0x8007007a: 'ERROR_STATUS_BUFFER_TOO_SMALL',
  };
  static enumValues: Record<string, number> = {
    STATUS_SUCCESS: 0x00000000,
    STATUS_INVALID_PARAMETER: 0xc000000d,
    STATUS_CANCELLED: 0xc0000120,
    STATUS_INVALID_INFO_CLASS: 0xc0000003,
    STATUS_NO_MEMORY: 0xc0000017,
    STATUS_ACCESS_DENIED: 0xc0000022,
    STATUS_BUFFER_TOO_SMALL: 0xc0000023,
    STATUS_NOT_IMPLEMENTED: 0xc0000002,
    STATUS_INFO_LENGTH_MISMATCH: 0xc0000004,
    STATUS_UNSUCCESSFUL: 0xc0000001,
    STATUS_CTX_WINSTATION_NOT_FOUND: 0xc00a0015,
    STATUS_WRONG_PASSWORD: 0xc000006a,
    DOES_NOT_EXISTS_OR_INSUFFICIENT_PERMISSIONS: 0x80071b6e,
    INVALID_PARAMETER2: 0x80070057,
    ERROR_ACCESS_DENIED: 0x80070005,
    ERROR_INVALID_STATE: 0x8007139f,
    ERROR_LOGON_FAILURE: 0x8007052e,
    ERROR_FILE_NOT_FOUND: 0x80070002,
    ERROR_STATUS_BUFFER_TOO_SMALL: 0x8007007a,
  };
}

// 2.2.2.15.1 TS_SYS_PROCESS_INFORMATION
export class TS_SYS_PROCESS_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['NextEntryOffset', ULONG],
    ['NumberOfThreads', ULONG],
    ['SpareLi1', LARGE_INTEGER],
    ['SpareLi2', LARGE_INTEGER],
    ['SpareLi3', LARGE_INTEGER],
    ['CreateTime', LARGE_INTEGER],
    ['UserTime', LARGE_INTEGER],
    ['KernelTime', LARGE_INTEGER],
    ['ImageNameSize', RPC_UNICODE_STRING],
    ['BasePriority', LONG],
    ['UniqueProcessId', DWORD],
    ['InheritedFromUniqueProcessId', DWORD],
    ['HandleCount', ULONG],
    ['SessionId', ULONG],
    ['SpareUl3', ULONG],
    ['PeakVirtualSize', ULONG],
    ['VirtualSize', ULONG],
    ['PageFaultCount', ULONG],
    ['PeakWorkingSetSize', ULONG],
    ['WorkingSetSize', ULONG],
    ['QuotaPeakPagedPoolUsage', ULONG],
    ['QuotaPagedPoolUsage', ULONG],
    ['QuotaPeakNonPagedPoolUsage', ULONG],
    ['QuotaNonPagedPoolUsage', ULONG],
    ['PagefileUsage', ULONG],
    ['PeakPagefileUsage', ULONG],
    ['PrivatePageCount', ULONG],
    ['ImageName', WSTR_STRIPPED],
    ['pSid', SID],
  ];
}

export class PTS_SYS_PROCESS_INFORMATION extends NDRPOINTER {
  static referent: NDRField[] = [['Data', TS_SYS_PROCESS_INFORMATION]];
}

// 2.2.2.15 TS_ALL_PROCESSES_INFO
export class TS_ALL_PROCESSES_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['pTsProcessInfo', TS_SYS_PROCESS_INFORMATION],
    ['SizeOfSid', DWORD],
    ['pSid', TS_CHAR],
  ];
}

export class TS_ALL_PROCESSES_INFO_ARRAY extends NDRUniConformantVaryingArray {
  static item: NDRFieldType = TS_SYS_PROCESS_INFORMATION;
}

export class PTS_ALL_PROCESSES_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', TS_ALL_PROCESSES_INFO_ARRAY]];
}

// NOT_IMPLEMENTED 2.2.2.30 WINSTATIONCONFIG2
export class WINSTATIONCONFIG2 extends NDRSTRUCT {}

// NOT_IMPLEMENTED 2.2.2.44 CLIENT_STACK_ADDRESS
export class CLIENT_STACK_ADDRESS extends NDRSTRUCT {}

////////////////////////////////////////////////////////////////////////////////
// RPC Calls
////////////////////////////////////////////////////////////////////////////////

// 3.3.4.1 TermSrvSession Methods
// 3.3.4.1.1 RpcOpenSession (Opnum 0)
export class RpcOpenSessionResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phSession', context_handle],
    ['ErrorCode', ULONG],
  ];
}

export class RpcOpenSession extends NDRCALL {
  static opnum = 0;
  static Response = RpcOpenSessionResponse;
  static structure: NDRField[] = [
    ['SessionId', ULONG],
    ['phSession', handle_t_tsts],
  ];
}

// 3.3.4.1.2 RpcCloseSession (Opnum 1)
export class RpcCloseSessionResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcCloseSession extends NDRCALL {
  static opnum = 1;
  static Response = RpcCloseSessionResponse;
  static structure: NDRField[] = [['phSession', context_handle]];
}

// 3.3.4.1.3 RpcConnect (Opnum 2)
export class RpcConnectResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcConnect extends NDRCALL {
  static opnum = 2;
  static Response = RpcConnectResponse;
  static structure: NDRField[] = [
    ['hSession', context_handle],
    ['TargetSessionId', LONG],
    ['szPassword', WSTR],
  ];
}

// 3.3.4.1.4 RpcDisconnect (Opnum 3)
export class RpcDisconnectResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcDisconnect extends NDRCALL {
  static opnum = 3;
  static Response = RpcDisconnectResponse;
  static structure: NDRField[] = [['hSession', context_handle]];
}

// 3.3.4.1.5 RpcLogoff (Opnum 4)
export class RpcLogoffResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcLogoff extends NDRCALL {
  static opnum = 4;
  static Response = RpcLogoffResponse;
  static structure: NDRField[] = [['hSession', context_handle]];
}

// 3.3.4.1.6 RpcGetUserName (Opnum 5)
export class RpcGetUserNameResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pszUserName', LPWCHAR_STRIPPED],
    ['pszDomain', LPWCHAR_STRIPPED],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetUserName extends NDRCALL {
  static opnum = 5;
  static Response = RpcGetUserNameResponse;
  static structure: NDRField[] = [['hSession', context_handle]];
}

// 3.3.4.1.7 RpcGetTerminalName (Opnum 6)
export class RpcGetTerminalNameResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pszTerminalName', LPWCHAR_STRIPPED],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetTerminalName extends NDRCALL {
  static opnum = 6;
  static Response = RpcGetTerminalNameResponse;
  static structure: NDRField[] = [['hSession', context_handle]];
}

// 3.3.4.1.8 RpcGetState (Opnum 7)
export class RpcGetStateResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['plState', WINSTATIONSTATECLASS],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetState extends NDRCALL {
  static opnum = 7;
  static Response = RpcGetStateResponse;
  static structure: NDRField[] = [['hSession', context_handle]];
}

// 3.3.4.1.9 RpcIsSessionDesktopLocked (Opnum 8)
export class RpcIsSessionDesktopLockedResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcIsSessionDesktopLocked extends NDRCALL {
  static opnum = 8;
  static Response = RpcIsSessionDesktopLockedResponse;
  static structure: NDRField[] = [['hSession', context_handle]];
}

// 3.3.4.1.10 RpcShowMessageBox (Opnum 9)
export class RpcShowMessageBoxResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pulResponse', MSGBOX_ENUM],
    ['ErrorCode', ULONG],
  ];
}

export class RpcShowMessageBox extends NDRCALL {
  static opnum = 9;
  static Response = RpcShowMessageBoxResponse;
  static structure: NDRField[] = [
    ['hSession', context_handle],
    ['szTitle', WSTR],
    ['szMessage', WSTR],
    ['ulStyle', ULONG],
    ['ulTimeout', ULONG],
    ['bDoNotWait', BOOL],
  ];
}

// 3.3.4.1.11 RpcGetTimes (Opnum 10)
export class RpcGetTimesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pConnectTime', SYSTEM_TIMESTAMP],
    ['pDisconnectTime', SYSTEM_TIMESTAMP],
    ['pLogonTime', SYSTEM_TIMESTAMP],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetTimes extends NDRCALL {
  static opnum = 10;
  static Response = RpcGetTimesResponse;
  static structure: NDRField[] = [['hSession', context_handle]];
}

// 3.3.4.1.12 RpcGetSessionCounters (Opnum 11)
export class RpcGetSessionCountersResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pCounter', PTS_COUNTER],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetSessionCounters extends NDRCALL {
  static opnum = 11;
  static Response = RpcGetSessionCountersResponse;
  static structure: NDRField[] = [
    ['hBinding', handle_t_tsts],
    ['uEntries', LONG],
  ];
}

// 3.3.4.1.13 RpcGetSessionInformation (Opnum 12)
export class RpcGetSessionInformationResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pSessionInfo', LSMSESSIONINFORMATION],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetSessionInformation extends NDRCALL {
  static opnum = 12;
  static Response = RpcGetSessionInformationResponse;
  static structure: NDRField[] = [['SessionId', LONG]];
}

// OLD 3.2.4.1.14 RpcSwitchToServicesSession (Opnum 13)
export class RpcSwitchToServicesSessionResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcSwitchToServicesSession extends NDRCALL {
  static opnum = 13;
  static Response = RpcSwitchToServicesSessionResponse;
  static structure: NDRField[] = [['hBinding', handle_t_tsts]];
}

// OLD 3.2.4.1.15 RpcRevertFromServicesSession (Opnum 14)
export class RpcRevertFromServicesSessionResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcRevertFromServicesSession extends NDRCALL {
  static opnum = 14;
  static Response = RpcRevertFromServicesSessionResponse;
  static structure: NDRField[] = [['hBinding', handle_t_tsts]];
}

// 3.3.4.1.14 RpcGetLoggedOnCount (Opnum 15)
export class RpcGetLoggedOnCountResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pUserSessions', ULONG],
    ['pDeviceSessions', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetLoggedOnCount extends NDRCALL {
  static opnum = 15;
  static Response = RpcGetLoggedOnCountResponse;
  static structure: NDRField[] = [['hBinding', handle_t_tsts]];
}

// 3.3.4.1.15 RpcGetSessionType (Opnum 16)
export class RpcGetSessionTypeResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pSessionType', SESSIONTYPE],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetSessionType extends NDRCALL {
  static opnum = 16;
  static Response = RpcGetSessionTypeResponse;
  static structure: NDRField[] = [['SessionId', LONG]];
}

// 3.3.4.1.16 RpcGetSessionInformationEx (Opnum 17)
export class RpcGetSessionInformationExResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['LSMSessionInfoExPtr', PLSMSESSIONINFORMATION_EX],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetSessionInformationEx extends NDRCALL {
  static opnum = 17;
  static Response = RpcGetSessionInformationExResponse;
  static structure: NDRField[] = [
    ['SessionId', LONG],
    ['Level', DWORD],
  ];
}

// 3.3.4.2 TermSrvNotification
// 3.3.4.2.1 RpcWaitForSessionState (Opnum 0)
export class RpcWaitForSessionStateResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcWaitForSessionState extends NDRCALL {
  static opnum = 0;
  static Response = RpcWaitForSessionStateResponse;
  static structure: NDRField[] = [
    ['SessionId', LONG],
    ['State', LONG],
    ['Timeout', ULONG],
  ];
}

// 3.3.4.2.2 RpcRegisterAsyncNotification (Opnum 1)
export class RpcRegisterAsyncNotificationResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phNotify', context_handle],
    ['ErrorCode', ULONG],
  ];
}

export class RpcRegisterAsyncNotification extends NDRCALL {
  static opnum = 1;
  static Response = RpcRegisterAsyncNotificationResponse;
  static structure: NDRField[] = [
    ['SessionId', LONG],
    ['Mask', ULONG],
  ];
}

// 3.3.4.2.3 RpcWaitAsyncNotification (Opnum 2)
export class RpcWaitAsyncNotificationResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['SessionChange', PSESSION_CHANGE],
    ['pEntries', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class RpcWaitAsyncNotification extends NDRCALL {
  static opnum = 2;
  static Response = RpcWaitAsyncNotificationResponse;
  static structure: NDRField[] = [['hNotify', context_handle]];
}

// 3.3.4.2.4 RpcUnRegisterAsyncNotification (Opnum 3)
export class RpcUnRegisterAsyncNotificationResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['hNotify', context_handle],
    ['ErrorCode', ULONG],
  ];
}

export class RpcUnRegisterAsyncNotification extends NDRCALL {
  static opnum = 3;
  static Response = RpcUnRegisterAsyncNotificationResponse;
  static structure: NDRField[] = [['hNotify', context_handle]];
}

// 3.3.4.3 TermSrvEnumeration
// 3.3.4.3.1 RpcOpenEnum (Opnum 0)
export class RpcOpenEnumResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phEnum', context_handle],
    ['ErrorCode', ULONG],
  ];
}

export class RpcOpenEnum extends NDRCALL {
  static opnum = 0;
  static Response = RpcOpenEnumResponse;
  static structure: NDRField[] = [['hBinding', handle_t_tsts]];
}

// 3.3.4.3.2 RpcCloseEnum (Opnum 1)
export class RpcCloseEnumResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phEnum', context_handle],
    ['ErrorCode', ULONG],
  ];
}

export class RpcCloseEnum extends NDRCALL {
  static opnum = 1;
  static Response = RpcCloseEnumResponse;
  static structure: NDRField[] = [['phEnum', context_handle]];
}

// 3.3.4.3.3 RpcFilterByState (Opnum 2)
export class RpcFilterByStateResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcFilterByState extends NDRCALL {
  static opnum = 2;
  static Response = RpcFilterByStateResponse;
  static structure: NDRField[] = [
    ['hEnum', context_handle],
    ['State', LONG],
    ['bInvert', BOOL],
  ];
}

// 3.3.4.3.4 RpcFilterByCallersName (Opnum 3)
export class RpcFilterByCallersNameResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcFilterByCallersName extends NDRCALL {
  static opnum = 3;
  static Response = RpcFilterByCallersNameResponse;
  static structure: NDRField[] = [['hEnum', context_handle]];
}

// 3.3.4.3.5 RpcEnumAddFilter (Opnum 4)
export class RpcEnumAddFilterResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcEnumAddFilter extends NDRCALL {
  static opnum = 4;
  static Response = RpcEnumAddFilterResponse;
  static structure: NDRField[] = [
    ['hEnum', context_handle],
    ['hSubEnum', context_handle],
  ];
}

// 3.3.4.3.6 RpcGetEnumResult (Opnum 5)
export class RpcGetEnumResultResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppSessionEnumResult', PSESSIONENUM],
    ['pEntries', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetEnumResult extends NDRCALL {
  static opnum = 5;
  static Response = RpcGetEnumResultResponse;
  static structure: NDRField[] = [
    ['hEnum', context_handle],
    ['Level', DWORD],
  ];
}

// 3.3.4.3.7 RpcFilterBySessionType (Opnum 6)
export class RpcFilterBySessionTypeResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcFilterBySessionType extends NDRCALL {
  static opnum = 6;
  static Response = RpcFilterBySessionTypeResponse;
  static structure: NDRField[] = [
    ['hEnum', context_handle],
    ['pSessionType', GUID],
  ];
}

// 3.3.4.3.8 RpcGetSessionIds (Opnum 8)
export class RpcGetSessionIdsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pSessionIds', LONG_ARRAY],
    ['pcSessionIds', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetSessionIds extends NDRCALL {
  static opnum = 8;
  static Response = RpcGetSessionIdsResponse;
  static structure: NDRField[] = [
    ['handle_t', handle_t_tsts],
    ['Filter', SESSION_FILTER],
    ['MaxEntries', ULONG],
  ];
}

// 3.3.4.3.9 RpcGetEnumResultEx (Opnum 9)
export class RpcGetEnumResultExResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppSessionEnumResult', PSESSIONENUM],
    ['pEntries', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetEnumResultEx extends NDRCALL {
  static opnum = 9;
  static Response = RpcGetEnumResultExResponse;
  static structure: NDRField[] = [
    ['hEnum', context_handle],
    ['Level', DWORD],
  ];
}

// 3.3.4.3.10 RpcGetAllSessions (Opnum 10)
export class RpcGetAllSessionsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pLevel', ULONG],
    ['ppSessionData', PEXECENVDATA],
    ['pcEntries', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetAllSessions extends NDRCALL {
  static opnum = 10;
  static Response = RpcGetAllSessionsResponse;
  static structure: NDRField[] = [['pLevel', ULONG]];
}

// NOT_IMPLEMENTED 3.3.4.3.11 RpcGetAllSessionsEx (Opnum 11)
export class RpcGetAllSessionsExResponse extends NDRCALL {
  static structure: NDRField[] = [['Buffer', UNKNOWNDATA]];
}

export class RpcGetAllSessionsEx extends NDRCALL {
  static opnum = 11;
  static Response = RpcGetAllSessionsExResponse;
  static structure: NDRField[] = [['Level', ULONG]];
}

// 3.5.4.1 RCMPublic
// 3.5.4.1.1 RpcGetClientData (Opnum 0)
export class RpcGetClientDataResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppBuff', PWINSTATIONCLIENT],
    ['pOutBuffByteLen', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetClientData extends NDRCALL {
  static opnum = 0;
  static Response = RpcGetClientDataResponse;
  static structure: NDRField[] = [['SessionId', ULONG]];
}

// 3.5.4.1.2 RpcGetConfigData (Opnum 1)
export class RpcGetConfigDataResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppBuff', PWINSTATIONCONFIG],
    ['pOutBuffByteLen', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetConfigData extends NDRCALL {
  static opnum = 1;
  static Response = RpcGetConfigDataResponse;
  static structure: NDRField[] = [['SessionId', ULONG]];
}

// NOT_IMPLEMENTED 3.5.4.1.3 RpcGetProtocolStatus (Opnum 2)
export class RpcGetProtocolStatusResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppProtoStatus', PROTOCOLSTATUS_INFO_TYPE],
    ['pcbProtoStatus', PPROTOCOLSTATUS],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetProtocolStatus extends NDRCALL {
  static opnum = 2;
  static Response = RpcGetProtocolStatusResponse;
  static structure: NDRField[] = [
    ['SessionId', ULONG],
    ['InfoType', PROTOCOLSTATUS_INFO_TYPE],
  ];
}

// 3.5.4.1.4 RpcGetLastInputTime (Opnum 3)
export class RpcGetLastInputTimeResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pLastInputTime', SYSTEM_TIMESTAMP],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetLastInputTime extends NDRCALL {
  static opnum = 3;
  static Response = RpcGetLastInputTimeResponse;
  static structure: NDRField[] = [['SessionId', ULONG]];
}

// 3.5.4.1.5 RpcGetRemoteAddress (Opnum 4)
export class RpcGetRemoteAddressResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pRemoteAddress', RCM_REMOTEADDRESS],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetRemoteAddress extends NDRCALL {
  static opnum = 4;
  static Response = RpcGetRemoteAddressResponse;
  static structure: NDRField[] = [['SessionId', ULONG]];
}

// 3.5.4.1.6 RpcShadow2 (Opnum 0)
export class RpcShadow2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['pePermission', SHADOW_REQUEST_RESPONSE],
    ['pszInvitation', WSTR],
    ['ErrorCode', ULONG],
  ];
}

export class RpcShadow2 extends NDRCALL {
  static opnum = 0;
  static Response = RpcShadow2Response;
  static structure: NDRField[] = [
    ['TargetSessionId', ULONG],
    ['eRequestControl', SHADOW_CONTROL_REQUEST],
    ['eRequestPermission', SHADOW_PERMISSION_REQUEST],
    ['cchInvitation', ULONG],
  ];
}

// OLD 3.4.4.1.6 RpcShadow (Opnum 5)
export class RpcShadowResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcShadow extends NDRCALL {
  static opnum = 5;
  static Response = RpcShadowResponse;
  static structure: NDRField[] = [
    ['szTargetServerName', WSTR],
    ['TargetSessionId', ULONG],
    ['HotKeyVk', BYTE],
    ['HotkeyModifiers', USHORT],
  ];
}

// OLD 3.4.4.1.7 RpcShadowTarget (Opnum 6)
export class RpcShadowTargetResponse extends NDRCALL {
  static structure: NDRField[] = [['Buffer', UNKNOWNDATA]];
}

export class RpcShadowTarget extends NDRCALL {
  static opnum = 6;
  static Response = RpcShadowTargetResponse;
}

// OLD 3.4.4.1.8 RpcShadowStop (Opnum 7)
export class RpcShadowStopResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcShadowStop extends NDRCALL {
  static opnum = 7;
  static Response = RpcShadowStopResponse;
  static structure: NDRField[] = [['SessionId', ULONG]];
}

// 3.5.4.1.6 RpcGetAllListeners (Opnum 8)
export class RpcGetAllListenersResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppListeners', PLISTENERENUM],
    ['pNumListeners', ULONG],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetAllListeners extends NDRCALL {
  static opnum = 8;
  static Response = RpcGetAllListenersResponse;
  static structure: NDRField[] = [['Level', DWORD]];
}

// NOT_IMPLEMENTED 3.5.4.1.7 RpcGetSessionProtocolLastInputTime (Opnum 9)
export class RpcGetSessionProtocolLastInputTimeResponse extends NDRCALL {
  static structure: NDRField[] = [['Data', UNKNOWNDATA]];
}

export class RpcGetSessionProtocolLastInputTime extends NDRCALL {
  static opnum = 9;
  static Response = RpcGetSessionProtocolLastInputTimeResponse;
}

// NOT_IMPLEMENTED 3.5.4.1.8 RpcGetUserCertificates (Opnum 10)
export class RpcGetUserCertificatesResponse extends NDRCALL {
  static structure: NDRField[] = [['Data', UNKNOWNDATA]];
}

export class RpcGetUserCertificates extends NDRCALL {
  static opnum = 10;
  static Response = RpcGetUserCertificatesResponse;
}

// NOT_IMPLEMENTED 3.5.4.1.9 RpcQuerySessionData (Opnum 11)
export class RpcQuerySessionDataResponse extends NDRCALL {
  static structure: NDRField[] = [['Buffer', UNKNOWNDATA]];
}

export class RpcQuerySessionData extends NDRCALL {
  static opnum = 11;
  static Response = RpcQuerySessionDataResponse;
}

// 3.5.4.2 RCMListener
// 3.5.4.2.1 RpcOpenListener (Opnum 0)
export class RpcOpenListenerResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phListener', context_handle],
    ['ErrorCode', ULONG],
  ];
}

export class RpcOpenListener extends NDRCALL {
  static opnum = 0;
  static Response = RpcOpenListenerResponse;
  static structure: NDRField[] = [['szListenerName', WSTR]];
}

// 3.5.4.2.2 RpcCloseListener (Opnum 1)
export class RpcCloseListenerResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phListener', context_handle],
    ['ErrorCode', ULONG],
  ];
}

export class RpcCloseListener extends NDRCALL {
  static opnum = 1;
  static Response = RpcCloseListenerResponse;
  static structure: NDRField[] = [['phListener', context_handle]];
}

// 3.5.4.2.3 RpcStopListener (Opnum 2)
export class RpcStopListenerResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcStopListener extends NDRCALL {
  static opnum = 2;
  static Response = RpcStopListenerResponse;
  static structure: NDRField[] = [['phListener', context_handle]];
}

// 3.5.4.2.4 RpcStartListener (Opnum 3)
export class RpcStartListenerResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcStartListener extends NDRCALL {
  static opnum = 3;
  static Response = RpcStartListenerResponse;
  static structure: NDRField[] = [['phListener', context_handle]];
}

// 3.5.4.2.5 RpcIsListening (Opnum 4)
export class RpcIsListeningResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pbIsListening', BOOLEAN],
    ['ErrorCode', ULONG],
  ];
}

export class RpcIsListening extends NDRCALL {
  static opnum = 4;
  static Response = RpcIsListeningResponse;
  static structure: NDRField[] = [['phListener', context_handle]];
}

// 3.7.4.1 LegacyApi
// 3.7.4.1.1 RpcWinStationOpenServer (Opnum 0)
export class RpcWinStationOpenServerResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['phServer', context_handle],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationOpenServer extends NDRCALL {
  static opnum = 0;
  static Response = RpcWinStationOpenServerResponse;
  static structure: NDRField[] = [['hBinding', handle_t_tsts]];
}

// 3.7.4.1.2 RpcWinStationCloseServer (Opnum 1)
export class RpcWinStationCloseServerResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationCloseServer extends NDRCALL {
  static opnum = 1;
  static Response = RpcWinStationCloseServerResponse;
  static structure: NDRField[] = [['hServer', context_handle]];
}

// 3.7.4.1.3 RpcIcaServerPing (Opnum 2)
export class RpcIcaServerPingResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcIcaServerPing extends NDRCALL {
  static opnum = 2;
  static Response = RpcIcaServerPingResponse;
  static structure: NDRField[] = [['hServer', context_handle]];
}

// NOT_IMPLEMENTED 3.7.4.1.4 RpcWinStationEnumerate (Opnum 3)
export class RpcWinStationEnumerateResponse extends NDRCALL {
  static structure: NDRField[] = [['pResult', UNKNOWNDATA]];
}

export class RpcWinStationEnumerate extends NDRCALL {
  static opnum = 3;
  static Response = RpcWinStationEnumerateResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['pEntries', PULONG],
    ['pLogonId', PCHAR],
    ['pByteCount', PULONG],
    ['pIndex', PULONG],
  ];
}

// NOT_IMPLEMENTED 3.7.4.1.5 RpcWinStationRename (Opnum 4)
export class RpcWinStationRenameResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationRename extends NDRCALL {
  static opnum = 4;
  static Response = RpcWinStationRenameResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['pWinStationNameOld', TS_WCHAR],
    ['NameOldSize', '<L=len(pWinStationNameOld["Data"])'],
    ['pWinStationNameNew', TS_WCHAR],
    ['NameNewSize', '<L=len(pWinStationNameNew["Data"])'],
  ];
}

// NOT_IMPLEMENTED 3.7.4.1.6 RpcWinStationQueryInformation (Opnum 5)
export class RpcWinStationQueryInformationResponse extends NDRCALL {
  static structure: NDRField[] = [['Buffer', UNKNOWNDATA]];
}

export class RpcWinStationQueryInformation extends NDRCALL {
  static opnum = 5;
  static Response = RpcWinStationQueryInformationResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['LogonId', DWORD],
    ['WinStationInformationClass', DWORD],
    ['buff', ':'],
  ];
}

// NOT_IMPLEMENTED 3.7.4.1.7 RpcWinStationSetInformation (Opnum 6)
export class RpcWinStationSetInformationResponse extends NDRCALL {
  static structure: NDRField[] = [['Buffer', UNKNOWNDATA]];
}

export class RpcWinStationSetInformation extends NDRCALL {
  static opnum = 6;
  static Response = RpcWinStationSetInformationResponse;
}

// 3.7.4.1.8 RpcWinStationSendMessage (Opnum 7)
export class RpcWinStationSendMessageResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['pResponse', DWORD],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationSendMessage extends NDRCALL {
  static opnum = 7;
  static Response = RpcWinStationSendMessageResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['LogonId', DWORD],
    ['pTitle', TS_WCHAR],
    ['TitleLength', '<L=len(pTitle["Data"])'],
    ['pMessage', TS_WCHAR],
    ['MessageLength', '<L=len(pMessage["Data"])'],
    ['Style', DWORD],
    ['Timeout', DWORD],
    ['DoNotWait', BOOLEAN],
  ];
}

// 3.7.4.1.9 RpcLogonIdFromWinStationName (Opnum 8)
export class RpcLogonIdFromWinStationNameResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['pLogonId', DWORD],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcLogonIdFromWinStationName extends NDRCALL {
  static opnum = 8;
  static Response = RpcLogonIdFromWinStationNameResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['pWinStationName', TS_WCHAR],
    ['NameSize', '<L=len(pWinStationName["Data"])'],
  ];
}

// 3.7.4.1.10 RpcWinStationNameFromLogonId (Opnum 9)
export class RpcWinStationNameFromLogonIdResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['pWinStationName', TS_WCHAR_STRIPPED],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationNameFromLogonId extends NDRCALL {
  static opnum = 9;
  static Response = RpcWinStationNameFromLogonIdResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['LoginId', DWORD],
    ['pWinStationName', TS_WCHAR],
    ['NameSize', `<L=${WINSTATIONNAME_LENGTH + 1}`],
  ];
}

// 3.7.4.1.11 RpcWinStationConnect (Opnum 10)
export class RpcWinStationConnectResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationConnect extends NDRCALL {
  static opnum = 10;
  static Response = RpcWinStationConnectResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['ClientLogonId', DWORD],
    ['ConnectLogonId', DWORD],
    ['TargetLogonId', DWORD],
    ['pPassword', TS_WCHAR],
    ['PasswordSize', '<L=len(pPassword["Data"])'],
    ['Wait', BOOLEAN],
  ];
}

// OLD 3.6.4.1.12 RpcWinStationVirtualOpen (Opnum 11)
export class RpcWinStationVirtualOpenResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['pHandle', ULONG],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationVirtualOpen extends NDRCALL {
  static opnum = 11;
  static Response = RpcWinStationVirtualOpenResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['LogonId', DWORD],
    ['Pid', DWORD],
    ['pVirtualName', TS_CHAR],
    ['NameSize', '<L=len(pVirtualName["Data"])'],
  ];
}

// OLD 3.6.4.1.13 RpcWinStationBeepOpen (Opnum 12)
export class RpcWinStationBeepOpenResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['pHandle', ULONG],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationBeepOpen extends NDRCALL {
  static opnum = 12;
  static Response = RpcWinStationBeepOpenResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['LogonId', DWORD],
    ['Pid', DWORD],
  ];
}

// 3.7.4.1.12 RpcWinStationDisconnect (Opnum 13)
export class RpcWinStationDisconnectResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationDisconnect extends NDRCALL {
  static opnum = 13;
  static Response = RpcWinStationDisconnectResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['LoginId', DWORD],
    ['bWait', BOOLEAN],
  ];
}

// 3.7.4.1.13 RpcWinStationReset (Opnum 14)
export class RpcWinStationResetResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationReset extends NDRCALL {
  static opnum = 14;
  static Response = RpcWinStationResetResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['LogonId', DWORD],
    ['bWait', BOOLEAN],
  ];
}

// 3.7.4.1.14 RpcWinStationShutdownSystem (Opnum 15)
export class RpcWinStationShutdownSystemResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationShutdownSystem extends NDRCALL {
  static opnum = 15;
  static Response = RpcWinStationShutdownSystemResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['ClientLogonId', DWORD],
    ['ShutdownFlags', DWORD],
  ];
}

// 3.7.4.1.15 RpcWinStationWaitSystemEvent (Opnum 16)
export class RpcWinStationWaitSystemEventResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['pEventFlags', DWORD],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationWaitSystemEvent extends NDRCALL {
  static opnum = 16;
  static Response = RpcWinStationWaitSystemEventResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['EventMask', DWORD],
  ];
}

// 3.7.4.1.16 RpcWinStationShadow (Opnum 17)
export class RpcWinStationShadowResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationShadow extends NDRCALL {
  static opnum = 17;
  static Response = RpcWinStationShadowResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['LogonId', DWORD],
    ['pTargetServerName', TS_LPWCHAR],
    ['NameSize', '<L=len(pTargetServerName["Data"])'],
    ['TargetLogonId', DWORD],
    ['HotKeyVk', BYTE],
    ['HotkeyModifiers', USHORT],
  ];
}

// OLD 3.6.4.1.19 RpcWinStationShadowTargetSetup (Opnum 18)
export class RpcWinStationShadowTargetSetupResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationShadowTargetSetup extends NDRCALL {
  static opnum = 18;
  static Response = RpcWinStationShadowTargetSetupResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['LogonId', DWORD],
  ];
}

// OLD 3.6.4.1.20 RpcWinStationShadowTarget (Opnum 19)
export class RpcWinStationShadowTargetResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationShadowTarget extends NDRCALL {
  static opnum = 19;
  static Response = RpcWinStationShadowTargetResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['LogonId', DWORD],
    ['pConfig', PBYTE],
    ['ConfigSize', DWORD],
    ['pAddress', PBYTE],
    ['AddressSize', DWORD],
    ['pModuleData', PBYTE],
    ['ModuleDataSize', DWORD],
    ['pThinwireData', PBYTE],
    ['ThinwireDataSize', DWORD],
    ['pClientName', STR],
    ['ClientNameSize', DWORD],
  ];
}

// OLD 3.6.4.1.21 RpcWinStationSetPoolCount (Opnum 26)
export class RpcWinStationSetPoolCountResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationSetPoolCount extends NDRCALL {
  static opnum = 26;
  static Response = RpcWinStationSetPoolCountResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['pLicense', TS_CHAR],
    ['LicenseSize', '<L=len(pLicense["Data"])'],
  ];
}

// OLD 3.6.4.1.22 RpcWinStationQueryUpdateRequired (Opnum 27)
export class RpcWinStationQueryUpdateRequiredResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['pUpdateFlag', DWORD],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationQueryUpdateRequired extends NDRCALL {
  static opnum = 27;
  static Response = RpcWinStationQueryUpdateRequiredResponse;
  static structure: NDRField[] = [['hServer', context_handle]];
}

// OLD 3.6.4.1.23 RpcWinStationCallback (Opnum 28)
export class RpcWinStationCallbackResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationCallback extends NDRCALL {
  static opnum = 28;
  static Response = RpcWinStationCallbackResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['LogonId', DWORD],
    ['pPhoneNumber', TS_WCHAR],
    ['PhoneNumberSize', '<L=len(pPhoneNumber["Data"])'],
  ];
}

// 3.7.4.1.17 RpcWinStationBreakPoint (Opnum 29)
export class RpcWinStationBreakPointResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationBreakPoint extends NDRCALL {
  static opnum = 29;
  static Response = RpcWinStationBreakPointResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['LogonId', DWORD],
    ['KernelFlag', BOOLEAN],
  ];
}

// 3.7.4.1.18 RpcWinStationReadRegistry (Opnum 30)
export class RpcWinStationReadRegistryResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationReadRegistry extends NDRCALL {
  static opnum = 30;
  static Response = RpcWinStationReadRegistryResponse;
  static structure: NDRField[] = [['hServer', context_handle]];
}

// OLD 3.6.4.1.26 RpcWinStationWaitForConnect (Opnum 31)
export class RpcWinStationWaitForConnectResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationWaitForConnect extends NDRCALL {
  static opnum = 31;
  static Response = RpcWinStationWaitForConnectResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['ClientLogonId', DWORD],
    ['ClientProcessId', DWORD],
  ];
}

// OLD 3.6.4.1.27 RpcWinStationNotifyLogon (Opnum 32)
export class RpcWinStationNotifyLogonResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['pfIsRedirected', BOOLEAN],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationNotifyLogon extends NDRCALL {
  static opnum = 32;
  static Response = RpcWinStationNotifyLogonResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['ClientLogonId', DWORD],
    ['ClientProcessId', DWORD],
    ['fUserIsAdmin', BOOLEAN],
    ['UserToken', DWORD],
    ['pDomain', TS_WCHAR],
    ['DomainSize', '<L=len(pDomain["Data"])'],
    ['pUserName', TS_WCHAR],
    ['UserNameSize', '<L=len(pUserName["Data"])'],
    ['pPassword', TS_WCHAR],
    ['PasswordSize', '<L=len(pPassword["Data"])'],
    ['Seed', UCHAR],
    ['pUserConfig', TS_CHAR],
    ['ConfigSize', '<L=len(pUserConfig["Data"])'],
    ['pfIsRedirected', DWORD],
  ];
}

// OLD 3.6.4.1.28 RpcWinStationNotifyLogoff (Opnum 33)
export class RpcWinStationNotifyLogoffResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationNotifyLogoff extends NDRCALL {
  static opnum = 33;
  static Response = RpcWinStationNotifyLogoffResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['ClientLogonId', DWORD],
    ['ClientProcessId', DWORD],
  ];
}

// 3.7.4.1.19 OldRpcWinStationEnumerateProcesses (Opnum 34)
export class OldRpcWinStationEnumerateProcessesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['pProcessBuffer', TS_CHAR],
    ['ErrorCode', BOOLEAN],
  ];
}

export class OldRpcWinStationEnumerateProcesses extends NDRCALL {
  static opnum = 34;
  static Response = OldRpcWinStationEnumerateProcessesResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['ByteCount', DWORD],
  ];
}

// OLD 3.6.4.1.29 RpcWinStationAnnoyancePopup (Opnum 35)
export class RpcWinStationAnnoyancePopupResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
    ['buff', UNKNOWNDATA],
  ];
}

export class RpcWinStationAnnoyancePopup extends NDRCALL {
  static opnum = 35;
  static Response = RpcWinStationAnnoyancePopupResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['LogonIdld', DWORD],
  ];
}

// 3.7.4.1.20 RpcWinStationEnumerateProcesses (Opnum 36)
export class RpcWinStationEnumerateProcessesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['pProcessBuffer', TS_CHAR],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationEnumerateProcesses extends NDRCALL {
  static opnum = 36;
  static Response = RpcWinStationEnumerateProcessesResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['ByteCount', DWORD],
  ];
}

// 3.7.4.1.21 RpcWinStationTerminateProcess (Opnum 37)
export class RpcWinStationTerminateProcessResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationTerminateProcess extends NDRCALL {
  static opnum = 37;
  static Response = RpcWinStationTerminateProcessResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['ProcessId', DWORD],
    ['ExitCode', DWORD],
  ];
}

// OLD 3.6.4.1.32 RpcWinStationNtsdDebug (Opnum 42)
export class RpcWinStationNtsdDebugResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationNtsdDebug extends NDRCALL {
  static opnum = 42;
  static Response = RpcWinStationNtsdDebugResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['LogonId', DWORD],
    ['ProcessId', LONG],
    ['DbgProcessId', ULONG],
    ['DbgThreadId', ULONG],
    ['AttachCompletionRoutine', LPDWORD],
  ];
}

// 3.7.4.1.22 RpcWinStationGetAllProcesses (Opnum 43)
export class RpcWinStationGetAllProcessesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['pNumberOfProcesses', ULONG],
    ['buffer', ':'],
  ];
}

export class RpcWinStationGetAllProcesses extends NDRCALL {
  static opnum = 43;
  static Response = RpcWinStationGetAllProcessesResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['Level', ULONG],
    ['pNumberOfProcesses', ULONG],
  ];
}

// 3.7.4.1.23 RpcWinStationGetProcessSid (Opnum 44)
export class RpcWinStationGetProcessSidResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['pProcessUserSid', TS_LPCHAR],
    ['pdwSizeNeeded', DWORD],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationGetProcessSid extends NDRCALL {
  static opnum = 44;
  static Response = RpcWinStationGetProcessSidResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['dwUniqueProcessId', DWORD],
    ['ProcessStartTime', LARGE_INTEGER],
    ['pProcessUserSid', TS_LPCHAR],
    ['dwSidSize', '<L=len(pProcessUserSid["Data"])'],
    ['pdwSizeNeeded', DWORD],
  ];
}

// NOT_IMPLEMENTED 3.7.4.1.24 RpcWinStationGetTermSrvCountersValue (Opnum 45)
export class RpcWinStationGetTermSrvCountersValueResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['pCounter', PTS_COUNTER],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationGetTermSrvCountersValue extends NDRCALL {
  static opnum = 45;
  static Response = RpcWinStationGetTermSrvCountersValueResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['dwEntries', DWORD],
    ['pCounter', PTS_COUNTER],
  ];
}

// 3.7.4.1.25 RpcWinStationReInitializeSecurity (Opnum 46)
export class RpcWinStationReInitializeSecurityResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationReInitializeSecurity extends NDRCALL {
  static opnum = 46;
  static Response = RpcWinStationReInitializeSecurityResponse;
  static structure: NDRField[] = [['hServer', context_handle]];
}

// 3.7.4.1.26 RpcWinStationGetLanAdapterName (Opnum 53)
export class RpcWinStationGetLanAdapterNameResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ppLanAdapter', TS_WCHAR],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationGetLanAdapterName extends NDRCALL {
  static opnum = 53;
  static Response = RpcWinStationGetLanAdapterNameResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['PdNameSize', '<L=len(pPdName["Data"])'],
    ['pPdName', TS_WCHAR],
    ['LanAdapter', ULONG],
  ];
}

// OLD 3.6.4.1.42 RpcWinStationQueryLogonCredentials (Opnum 55)
export class RpcWinStationQueryLogonCredentialsResponse extends NDRCALL {
  static structure: NDRField[] = [['pResult', UNKNOWNDATA]];
}

export class RpcWinStationQueryLogonCredentials extends NDRCALL {
  static opnum = 55;
  static Response = RpcWinStationQueryLogonCredentialsResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['LogonId', ULONG],
    ['pcbCredentials', ULONG],
  ];
}

// 3.7.4.1.27 RpcWinStationUpdateSettings (Opnum 58)
export class RpcWinStationUpdateSettingsResponse extends NDRCALL {
  static structure: NDRField[] = [['pResult', UNKNOWNDATA]];
}

export class RpcWinStationUpdateSettings extends NDRCALL {
  static opnum = 58;
  static Response = RpcWinStationUpdateSettingsResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['SettingsClass', DWORD],
    ['SettingsParameters', DWORD],
  ];
}

// 3.7.4.1.28 RpcWinStationShadowStop (Opnum 59)
export class RpcWinStationShadowStopResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationShadowStop extends NDRCALL {
  static opnum = 59;
  static Response = RpcWinStationShadowStopResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['LogonId', DWORD],
    ['bWait', BOOLEAN],
  ];
}

// 3.7.4.1.29 RpcWinStationCloseServerEx (Opnum 60)
export class RpcWinStationCloseServerExResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phServer', context_handle],
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationCloseServerEx extends NDRCALL {
  static opnum = 60;
  static Response = RpcWinStationCloseServerExResponse;
  static structure: NDRField[] = [['hServer', context_handle]];
}

// 3.7.4.1.30 RpcWinStationIsHelpAssistantSession (Opnum 61)
export class RpcWinStationIsHelpAssistantSessionResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationIsHelpAssistantSession extends NDRCALL {
  static opnum = 61;
  static Response = RpcWinStationIsHelpAssistantSessionResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['SessionId', ULONG],
  ];
}

// 3.7.4.1.33 RpcConnectCallback (Opnum 66)
export class RpcConnectCallbackResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
    ['out', UNKNOWNDATA],
  ];
}

export class RpcConnectCallback extends NDRCALL {
  static opnum = 61;
  static Response = RpcConnectCallbackResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['TimeOut', DWORD],
    ['AddressType', ULONG],
    ['pAddress', TS_LPCHAR],
    ['AddressSize', '<L=len(pAddress["Data"])'],
  ];
}

// 3.7.4.1.35 RpcWinStationOpenSessionDirectory (Opnum 75)
export class RpcWinStationOpenSessionDirectoryResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pResult', pResult_ENUM],
    ['ErrorCode', BOOLEAN],
  ];
}

export class RpcWinStationOpenSessionDirectory extends NDRCALL {
  static opnum = 75;
  static Response = RpcWinStationOpenSessionDirectoryResponse;
  static structure: NDRField[] = [
    ['hServer', context_handle],
    ['pszServerName', WSTR],
  ];
}

////////////////////////////////////////////////////////////////////////////////
// Helper Functions
////////////////////////////////////////////////////////////////////////////////

type DceRequestFn = <T>(req: unknown, uuid?: unknown, checkError?: boolean) => Promise<T>;

// 3.3.4.1 TermSrvSession
export async function hRpcOpenSession(
  dce: DCERPC_v5,
  SessionId: number,
): Promise<unknown> {
  const request = new RpcOpenSession();
  request.set('SessionId', SessionId);
  const resp = await (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
  return resp.get('phSession');
}

export async function hRpcCloseSession(
  dce: DCERPC_v5,
  phSession: unknown,
): Promise<unknown> {
  const request = new RpcCloseSession();
  request.set('phSession', phSession);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcConnect(
  dce: DCERPC_v5,
  hSession: unknown,
  TargetSessionId: number,
  Password: string | null = null,
): Promise<unknown> {
  if (Password === null) {
    Password = '';
  }
  const request = new RpcConnect();
  request.set('hSession', hSession);
  request.set('TargetSessionId', TargetSessionId);
  request.set('szPassword', Password + '\0');
  try {
    return await (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
  } catch (e) {
    if (e instanceof DCERPCSessionError && e.error_code === 0x1) {
      const resp = new RpcConnectResponse();
      resp.set('ErrorCode', 0);
      return resp;
    }
    throw e;
  }
}

export async function hRpcDisconnect(
  dce: DCERPC_v5,
  hSession: unknown,
): Promise<unknown> {
  const request = new RpcDisconnect();
  request.set('hSession', hSession);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcLogoff(
  dce: DCERPC_v5,
  hSession: unknown,
): Promise<unknown> {
  const request = new RpcLogoff();
  request.set('hSession', hSession);
  try {
    return await (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
  } catch (e) {
    if (e instanceof DCERPCSessionError && e.error_code === 0x10000000) {
      const resp = new RpcLogoffResponse();
      resp.set('ErrorCode', 0);
      return resp;
    }
    throw e;
  }
}

export async function hRpcGetUserName(
  dce: DCERPC_v5,
  hSession: unknown,
): Promise<unknown> {
  const request = new RpcGetUserName();
  request.set('hSession', hSession);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcGetTerminalName(
  dce: DCERPC_v5,
  hSession: unknown,
): Promise<unknown> {
  const request = new RpcGetTerminalName();
  request.set('hSession', hSession);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcGetState(
  dce: DCERPC_v5,
  hSession: unknown,
): Promise<unknown> {
  const request = new RpcGetState();
  request.set('hSession', hSession);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcIsSessionDesktopLocked(
  dce: DCERPC_v5,
  hSession: unknown,
): Promise<unknown> {
  const request = new RpcIsSessionDesktopLocked();
  request.set('hSession', hSession);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcShowMessageBox(
  dce: DCERPC_v5,
  hSession: unknown,
  Title: string | null,
  Message: string | null,
  Style: number = 0,
  Timeout: number = 0,
  DoNotWait: boolean = true,
): Promise<unknown> {
  const titleVal = Title !== null ? Title : ' ';
  const messageVal = Message !== null ? Message : '';
  const request = new RpcShowMessageBox();
  request.set('hSession', hSession);
  request.set('szTitle', titleVal + '\0');
  request.set('szMessage', messageVal + '\0');
  request.set('ulStyle', Style);
  request.set('ulTimeout', Timeout);
  request.set('bDoNotWait', DoNotWait);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcGetTimes(
  dce: DCERPC_v5,
  hSession: unknown,
): Promise<unknown> {
  const request = new RpcGetTimes();
  request.set('hSession', hSession);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcGetSessionCounters(
  dce: DCERPC_v5,
  Entries: number,
): Promise<unknown> {
  const request = new RpcGetSessionCounters();
  request.set('uEntries', Entries);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcGetSessionInformation(
  dce: DCERPC_v5,
  SessionId: number,
): Promise<unknown> {
  const request = new RpcGetSessionInformation();
  request.set('SessionId', SessionId);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcGetLoggedOnCount(
  dce: DCERPC_v5,
): Promise<unknown> {
  const request = new RpcGetLoggedOnCount();
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcGetSessionType(
  dce: DCERPC_v5,
  SessionId: number,
): Promise<unknown> {
  const request = new RpcGetSessionType();
  request.set('SessionId', SessionId);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcGetSessionInformationEx(
  dce: DCERPC_v5,
  SessionId: number,
): Promise<unknown> {
  const request = new RpcGetSessionInformationEx();
  request.set('SessionId', SessionId);
  request.set('Level', 1);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

// 3.3.4.2 TermSrvNotification
export async function hRpcWaitForSessionState(
  dce: DCERPC_v5,
  SessionId: number,
  State: number,
  Timeout: number,
): Promise<unknown> {
  const request = new RpcWaitForSessionState();
  request.set('SessionId', SessionId);
  request.set('State', State);
  request.set('Timeout', Timeout);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcRegisterAsyncNotification(
  dce: DCERPC_v5,
  SessionId: number,
  Mask: number,
): Promise<unknown> {
  const request = new RpcRegisterAsyncNotification();
  request.set('SessionId', SessionId);
  request.set('Mask', Mask);
  const resp = await (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
  return resp.get('phNotify');
}

export async function hRpcWaitAsyncNotification(
  dce: DCERPC_v5,
  hNotify: unknown,
): Promise<unknown> {
  const request = new RpcWaitAsyncNotification();
  request.set('hNotify', hNotify);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcUnRegisterAsyncNotification(
  dce: DCERPC_v5,
  hNotify: unknown,
): Promise<unknown> {
  const request = new RpcUnRegisterAsyncNotification();
  request.set('hNotify', hNotify);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

// 3.3.4.3 TermSrvEnumeration
export async function hRpcOpenEnum(
  dce: DCERPC_v5,
): Promise<unknown> {
  const request = new RpcOpenEnum();
  const resp = await (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
  return resp.get('phEnum');
}

export async function hRpcCloseEnum(
  dce: DCERPC_v5,
  phEnum: unknown,
): Promise<unknown> {
  const request = new RpcCloseEnum();
  request.set('phEnum', phEnum);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcGetEnumResult(
  dce: DCERPC_v5,
  hEnum: unknown,
  Level: number = 1,
): Promise<unknown> {
  const request = new RpcGetEnumResult();
  request.set('hEnum', hEnum);
  request.set('Level', Level);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcGetEnumResultEx(
  dce: DCERPC_v5,
  hEnum: unknown,
  Level: number = 1,
): Promise<unknown> {
  const request = new RpcGetEnumResultEx();
  request.set('hEnum', hEnum);
  request.set('Level', Level);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcGetAllSessions(
  dce: DCERPC_v5,
  Level: number = 1,
): Promise<unknown> {
  const request = new RpcGetAllSessions();
  request.set('pLevel', Level);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

// 3.5.4.1 RCMPublic
export async function hRpcGetClientData(
  dce: DCERPC_v5,
  SessionId: number,
): Promise<unknown> {
  const request = new RpcGetClientData();
  request.set('SessionId', SessionId);
  try {
    return await (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
  } catch {
    return null;
  }
}

export async function hRpcGetConfigData(
  dce: DCERPC_v5,
  SessionId: number,
): Promise<unknown> {
  const request = new RpcGetConfigData();
  request.set('SessionId', SessionId);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcGetLastInputTime(
  dce: DCERPC_v5,
  SessionId: number,
): Promise<unknown> {
  const request = new RpcGetLastInputTime();
  request.set('SessionId', SessionId);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcGetRemoteAddress(
  dce: DCERPC_v5,
  SessionId: number,
): Promise<unknown> {
  const request = new RpcGetRemoteAddress();
  request.set('SessionId', SessionId);
  try {
    return await (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
  } catch {
    return null;
  }
}

export async function hRpcGetAllListeners(
  dce: DCERPC_v5,
): Promise<unknown> {
  const request = new RpcGetAllListeners();
  request.set('Level', 1);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

// 3.5.4.2 RCMListener
export async function hRpcOpenListener(
  dce: DCERPC_v5,
  ListenerName: string,
): Promise<unknown> {
  const request = new RpcOpenListener();
  request.set('szListenerName', ListenerName + '\0');
  const resp = await (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
  return resp.get('phListener');
}

export async function hRpcCloseListener(
  dce: DCERPC_v5,
  phListener: unknown,
): Promise<unknown> {
  const request = new RpcCloseListener();
  request.set('phListener', phListener);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcStopListener(
  dce: DCERPC_v5,
  phListener: unknown,
): Promise<unknown> {
  const request = new RpcStopListener();
  request.set('phListener', phListener);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcStartListener(
  dce: DCERPC_v5,
  phListener: unknown,
): Promise<unknown> {
  const request = new RpcStartListener();
  request.set('phListener', phListener);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

export async function hRpcIsListening(
  dce: DCERPC_v5,
  phListener: unknown,
): Promise<unknown> {
  const request = new RpcIsListening();
  request.set('phListener', phListener);
  return (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
}

// 3.7.4.1 LegacyApi
export async function hRpcWinStationOpenServer(
  dce: DCERPC_v5,
): Promise<unknown> {
  const request = new RpcWinStationOpenServer();
  const resp = await (dce.request as DceRequestFn)(request, undefined, false);
  if ((resp as NDR).get('ErrorCode')) {
    return (resp as NDR).get('phServer');
  }
  return null;
}

export async function hRpcWinStationCloseServer(
  dce: DCERPC_v5,
  hServer: unknown,
): Promise<unknown> {
  const request = new RpcWinStationCloseServer();
  request.set('hServer', hServer);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcIcaServerPing(
  dce: DCERPC_v5,
  hServer: unknown,
): Promise<unknown> {
  const request = new RpcIcaServerPing();
  request.set('hServer', hServer);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationSendMessage(
  dce: DCERPC_v5,
  hServer: unknown,
  LogonId: number,
  Title: string,
  Message: string,
  DoNotWait: boolean = true,
): Promise<unknown> {
  const request = new RpcWinStationSendMessage();
  request.set('hServer', hServer);
  request.set('LogonId', LogonId);
  request.set('pTitle', ZEROPAD(Title, 1024));
  request.set('pMessage', ZEROPAD(Message, 1024));
  request.set('DoNotWait', DoNotWait);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcLogonIdFromWinStationName(
  dce: DCERPC_v5,
  hServer: unknown,
  WinStationName: string,
): Promise<unknown> {
  const request = new RpcLogonIdFromWinStationName();
  request.set('hServer', hServer);
  request.set('pWinStationName', ZEROPAD(WinStationName, WINSTATIONNAME_LENGTH + 1));
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationNameFromLogonId(
  dce: DCERPC_v5,
  hServer: unknown,
  LoginId: number,
): Promise<unknown> {
  const request = new RpcWinStationNameFromLogonId();
  request.set('hServer', hServer);
  request.set('LoginId', LoginId);
  request.set('pWinStationName', ZEROPAD('', WINSTATIONNAME_LENGTH + 1));
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationConnect(
  dce: DCERPC_v5,
  hServer: unknown,
  ClientLogonId: number,
  ConnectLogonId: number,
  TargetLogonId: number,
  Password: string,
  Wait: boolean = false,
): Promise<unknown> {
  const request = new RpcWinStationConnect();
  request.set('hServer', hServer);
  request.set('ClientLogonId', ClientLogonId);
  request.set('ConnectLogonId', ConnectLogonId);
  request.set('TargetLogonId', TargetLogonId);
  request.set('pPassword', Password + '\0');
  request.set('Wait', Wait);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationDisconnect(
  dce: DCERPC_v5,
  hServer: unknown,
  LoginId: number,
  bWait: boolean = false,
): Promise<unknown> {
  const request = new RpcWinStationDisconnect();
  request.set('hServer', hServer);
  request.set('LoginId', LoginId);
  request.set('bWait', bWait);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationReset(
  dce: DCERPC_v5,
  hServer: unknown,
  LogonId: number,
  bWait: boolean = false,
): Promise<unknown> {
  const request = new RpcWinStationReset();
  request.set('hServer', hServer);
  request.set('LogonId', LogonId);
  request.set('bWait', bWait);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationShutdownSystem(
  dce: DCERPC_v5,
  hServer: unknown,
  ClientLogonId: number,
  ShutdownFlagsVal: number,
): Promise<unknown> {
  const request = new RpcWinStationShutdownSystem();
  request.set('hServer', hServer);
  request.set('ClientLogonId', ClientLogonId);
  request.set('ShutdownFlags', ShutdownFlagsVal);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationWaitSystemEvent(
  dce: DCERPC_v5,
  hServer: unknown,
  EventMask: number,
): Promise<unknown> {
  const request = new RpcWinStationWaitSystemEvent();
  request.set('hServer', hServer);
  request.set('EventMask', EventMask);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationShadow(
  dce: DCERPC_v5,
  hServer: unknown,
  LogonId: number,
  pTargetServerName: unknown,
  TargetLogonId: number,
  HotKeyVk: number,
  HotkeyModifiers: number,
): Promise<unknown> {
  const request = new RpcWinStationShadow();
  request.set('hServer', hServer);
  request.set('LogonId', LogonId);
  request.set('pTargetServerName', pTargetServerName);
  request.set('TargetLogonId', TargetLogonId);
  request.set('HotKeyVk', HotKeyVk);
  request.set('HotkeyModifiers', HotkeyModifiers);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationShadowTargetSetup(
  dce: DCERPC_v5,
  hServer: unknown,
  LogonId: number,
): Promise<unknown> {
  const request = new RpcWinStationShadowTargetSetup();
  request.set('hServer', hServer);
  request.set('LogonId', LogonId);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationBreakPoint(
  dce: DCERPC_v5,
  hServer: unknown,
  LogonId: number,
  KernelFlag: boolean,
): Promise<unknown> {
  const request = new RpcWinStationBreakPoint();
  request.set('hServer', hServer);
  request.set('LogonId', LogonId);
  request.set('KernelFlag', KernelFlag);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationReadRegistry(
  dce: DCERPC_v5,
  hServer: unknown,
): Promise<unknown> {
  const request = new RpcWinStationReadRegistry();
  request.set('hServer', hServer);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hOldRpcWinStationEnumerateProcesses(
  dce: DCERPC_v5,
  hServer: unknown,
  ByteCount: number,
): Promise<unknown> {
  const request = new OldRpcWinStationEnumerateProcesses();
  request.set('hServer', hServer);
  request.set('ByteCount', ByteCount);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationEnumerateProcesses(
  dce: DCERPC_v5,
  hServer: unknown,
  ByteCount: number,
): Promise<unknown> {
  const request = new RpcWinStationEnumerateProcesses();
  request.set('hServer', hServer);
  request.set('ByteCount', ByteCount);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationTerminateProcess(
  dce: DCERPC_v5,
  hServer: unknown,
  ProcessId: number,
  ExitCode: number = 0,
): Promise<unknown> {
  const request = new RpcWinStationTerminateProcess();
  request.set('hServer', hServer);
  request.set('ProcessId', ProcessId);
  request.set('ExitCode', ExitCode);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationGetAllProcesses(
  dce: DCERPC_v5,
  hServer: unknown,
): Promise<TS_SYS_PROCESS_INFORMATION[]> {
  const request = new RpcWinStationGetAllProcesses();
  request.set('hServer', hServer);
  request.set('Level', 0);
  request.set('pNumberOfProcesses', 0x8000);
  const resp = await (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request, undefined, false);
  const data = resp.getData();
  const bResult = Boolean(data[data.length - 1]);
  if (!bResult) {
    throw new DCERPCSessionError(undefined, resp.get('pResult') as number);
  }
  const numProcs = resp.get('pNumberOfProcesses') as number;
  const procs: TS_SYS_PROCESS_INFORMATION[] = [];
  if (!numProcs) {
    return procs;
  }
  // Raw parsing as in the Python implementation
  let buf = data.subarray(0, data.length - 1);
  let offset = 0;
  let arrayOffset = 0;
  while (true) {
    const idx = buf.indexOf(Buffer.from([0x02, 0x00]), offset);
    if (idx < 0 || idx > 12 + offset) {
      break;
    }
    offset = idx + 2;
    arrayOffset = offset;
  }
  buf = buf.subarray(arrayOffset);
  let procInfoLen = 0;
  while (buf.length > 1) {
    if (buf.length - procInfoLen < 16) {
      break;
    }
    const slice = buf.subarray(procInfoLen, procInfoLen + 16);
    const b = slice.readUInt32LE(0);
    const c = slice.readUInt32LE(4);
    const d = slice.readUInt32LE(8);
    const e = slice.readUInt32LE(12);
    if (b) {
      buf = buf.subarray(procInfoLen - 4);
    } else if (c) {
      buf = buf.subarray(procInfoLen);
    } else if (d) {
      buf = buf.subarray(procInfoLen + 4);
    } else if (e) {
      buf = buf.subarray(procInfoLen + 8);
    } else {
      break;
    }
    const procInfo = new TS_SYS_PROCESS_INFORMATION();
    procInfo.fromString(buf);
    procs.push(procInfo);
    procInfoLen = procInfo.getData().length;
  }
  return procs;
}

export async function hRpcWinStationGetProcessSid(
  dce: DCERPC_v5,
  hServer: unknown,
  dwUniqueProcessId: number,
  ProcessStartTime: unknown,
): Promise<string | null> {
  const request = new RpcWinStationGetProcessSid();
  request.set('hServer', hServer);
  request.set('dwUniqueProcessId', dwUniqueProcessId);
  request.set('ProcessStartTime', ProcessStartTime);
  request.set('pProcessUserSid', Buffer.alloc(28, 0));
  const resp = await (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request, undefined, false);
  if ((resp.get('pResult') as number) === pResult_ENUM.enumValues['ERROR_STATUS_BUFFER_TOO_SMALL']) {
    const sizeNeeded = resp.get('pdwSizeNeeded') as number;
    request.set('pProcessUserSid', Buffer.alloc(sizeNeeded, 0));
    request.set('dwSidSize', sizeNeeded);
    const resp2 = await (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(request, undefined, false);
    if (resp2.get('ErrorCode')) {
      const sidBuf = resp2.get('pProcessUserSid') as Buffer;
      return formatSid(sidBuf);
    }
  }
  if (resp.get('ErrorCode')) {
    const sidBuf = resp.get('pProcessUserSid') as Buffer;
    return formatSid(sidBuf);
  }
  return null;
}

export async function hRpcWinStationReInitializeSecurity(
  dce: DCERPC_v5,
  hServer: unknown,
): Promise<unknown> {
  const request = new RpcWinStationReInitializeSecurity();
  request.set('hServer', hServer);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationGetLanAdapterName(
  dce: DCERPC_v5,
  hServer: unknown,
  pPdName: unknown,
  LanAdapter: unknown,
): Promise<unknown> {
  const request = new RpcWinStationGetLanAdapterName();
  request.set('hServer', hServer);
  request.set('pPdName', pPdName);
  request.set('LanAdapter', LanAdapter);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationUpdateSettings(
  dce: DCERPC_v5,
  hServer: unknown,
  SettingsClass: number,
  SettingsParameters: number,
): Promise<unknown> {
  const request = new RpcWinStationUpdateSettings();
  request.set('hServer', hServer);
  request.set('SettingsClass', SettingsClass);
  request.set('SettingsParameters', SettingsParameters);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationShadowStop(
  dce: DCERPC_v5,
  hServer: unknown,
  LogonId: number,
  bWait: boolean,
): Promise<unknown> {
  const request = new RpcWinStationShadowStop();
  request.set('hServer', hServer);
  request.set('LogonId', LogonId);
  request.set('bWait', bWait);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationCloseServerEx(
  dce: DCERPC_v5,
  hServer: unknown,
): Promise<unknown> {
  const request = new RpcWinStationCloseServerEx();
  request.set('hServer', hServer);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationIsHelpAssistantSession(
  dce: DCERPC_v5,
  hServer: unknown,
  SessionId: number,
): Promise<unknown> {
  const request = new RpcWinStationIsHelpAssistantSession();
  request.set('hServer', hServer);
  request.set('SessionId', SessionId);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcWinStationOpenSessionDirectory(
  dce: DCERPC_v5,
  hServer: unknown,
  pszServerName: string,
): Promise<unknown> {
  const request = new RpcWinStationOpenSessionDirectory();
  request.set('hServer', hServer);
  request.set('pszServerName', pszServerName);
  return (dce.request as DceRequestFn)(request, undefined, false);
}

export async function hRpcShadow2(
  dce: DCERPC_v5,
  TargetSessionId: number,
  eRequestControl: number,
  eRequestPermission: number,
  cchInvitation: number = 8192,
): Promise<unknown> {
  const request = new RpcShadow2();
  request.set('TargetSessionId', TargetSessionId);
  request.set('eRequestControl', eRequestControl);
  request.set('eRequestPermission', eRequestPermission);
  request.set('cchInvitation', cchInvitation);
  return (dce.request as DceRequestFn)(request, undefined, false);
}
