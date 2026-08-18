// Impacket - Collection of TypeScript classes for working with network protocols.
//
// Copyright Fortra, LLC and its affiliated companies
//
// All rights reserved.
//
// Description:
//   [MS-DCOM] Interface implementation
//
//   Port of impacket/dcerpc/v5/dcomrt.py to TypeScript.

import { Buffer } from 'node:buffer';
import * as net from 'node:net';
import { stringToBin, uuidtupToBin, generate } from '@impacket/uuid';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRPOINTER,
  NDRUniConformantArray,
  UNKNOWNDATA,
  NULL,
  type NDRField,
  type NDRTLSTRUCT,
} from './ndr';
import {
  LPWSTR,
  ULONGLONG,
  HRESULT,
  GUID,
  USHORT,
  WSTR,
  DWORD,
  LPLONG,
  LONG,
  PGUID,
  ULONG,
  UUID,
  WIDESTR,
} from './dtypes';
import {
  DCERPCException,
  TypeSerialization1,
  DCERPC_v5,
  RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
  RPC_C_AUTHN_LEVEL_NONE,
  RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
  RPC_C_AUTHN_GSS_NEGOTIATE,
  RPC_C_AUTHN_WINNT,
} from './rpcrt';
import { DCERPCTransportFactory, DCERPCTransport } from './transport';

// ============================================================================
// CLSIDs and IIDs
// ============================================================================
export const CLSID_ActivationContextInfo = stringToBin('000001a5-0000-0000-c000-000000000046');
export const CLSID_ActivationPropertiesIn = stringToBin('00000338-0000-0000-c000-000000000046');
export const CLSID_ActivationPropertiesOut = stringToBin('00000339-0000-0000-c000-000000000046');
export const CLSID_CONTEXT_EXTENSION = stringToBin('00000334-0000-0000-c000-000000000046');
export const CLSID_ContextMarshaler = stringToBin('0000033b-0000-0000-c000-000000000046');
export const CLSID_ERROR_EXTENSION = stringToBin('0000031c-0000-0000-c000-000000000046');
export const CLSID_ErrorObject = stringToBin('0000031b-0000-0000-c000-000000000046');
export const CLSID_InstanceInfo = stringToBin('000001ad-0000-0000-c000-000000000046');
export const CLSID_InstantiationInfo = stringToBin('000001ab-0000-0000-c000-000000000046');
export const CLSID_PropsOutInfo = stringToBin('00000339-0000-0000-c000-000000000046');
export const CLSID_ScmReplyInfo = stringToBin('000001b6-0000-0000-c000-000000000046');
export const CLSID_ScmRequestInfo = stringToBin('000001aa-0000-0000-c000-000000000046');
export const CLSID_SecurityInfo = stringToBin('000001a6-0000-0000-c000-000000000046');
export const CLSID_ServerLocationInfo = stringToBin('000001a4-0000-0000-c000-000000000046');
export const CLSID_SpecialSystemProperties = stringToBin('000001b9-0000-0000-c000-000000000046');
export const IID_IActivation = uuidtupToBin(['4d9f4ab8-7d1c-11cf-861e-0020af6e7c57', '0.0'])!;
export const IID_IActivationPropertiesIn = uuidtupToBin(['000001A2-0000-0000-C000-000000000046', '0.0'])!;
export const IID_IActivationPropertiesOut = uuidtupToBin(['000001A3-0000-0000-C000-000000000046', '0.0'])!;
export const IID_IContext = uuidtupToBin(['000001c0-0000-0000-C000-000000000046', '0.0'])!;
export const IID_IObjectExporter = uuidtupToBin(['99fcfec4-5260-101b-bbcb-00aa0021347a', '0.0'])!;
export const IID_IRemoteSCMActivator = uuidtupToBin(['000001A0-0000-0000-C000-000000000046', '0.0'])!;
export const IID_IRemUnknown = uuidtupToBin(['00000131-0000-0000-C000-000000000046', '0.0'])!;
export const IID_IRemUnknown2 = uuidtupToBin(['00000143-0000-0000-C000-000000000046', '0.0'])!;
export const IID_IUnknown = uuidtupToBin(['00000000-0000-0000-C000-000000000046', '0.0'])!;
export const IID_IClassFactory = uuidtupToBin(['00000001-0000-0000-C000-000000000046', '0.0'])!;

// ============================================================================
// Protocol Identifiers, from [c706] Annex I
// ============================================================================
export const TOWERID_OSI_TP4 = 0x05;
export const TOWERID_OSI_CLNS = 0x06;
export const TOWERID_DOD_TCP = 0x0007;
export const TOWERID_DOD_UDP = 0x08;
export const TOWERID_DOD_IP = 0x09;
export const TOWERID_RPC_connectionless = 0x0a;
export const TOWERID_RPC_connectionoriented = 0x0b;
export const TOWERID_DNA_Session_Control = 0x02;
export const TOWERID_DNA_Session_Control_V3 = 0x03;
export const TOWERID_DNA_NSP_Transport = 0x04;
export const TOWERID_DNA_Routing = 0x06;
export const TOWERID_Named_Pipes = 0x10;
export const TOWERID_NetBIOS_11 = 0x11;
export const TOWERID_NetBEUI = 0x12;
export const TOWERID_Netware_SPX = 0x13;
export const TOWERID_Netware_IPX = 0x14;
export const TOWERID_Appletalk_Stream = 0x16;
export const TOWERID_Appletalk_Datagram = 0x17;
export const TOWERID_Appletalk = 0x18;
export const TOWERID_NetBIOS_19 = 0x19;
export const TOWERID_VINES_SPP = 0x1a;
export const TOWERID_VINES_IPC = 0x1b;
export const TOWERID_StreetTalk = 0x1c;
export const TOWERID_Unix_Domain_socket = 0x20;
export const TOWERID_null = 0x21;
export const TOWERID_NetBIOS_22 = 0x22;

// ============================================================================
// DCERPCSessionError (module-private per collision rules)
// ============================================================================
class DCERPCSessionError extends DCERPCException {
  constructor(errorString?: string | null, errorCode?: number | null, packet?: unknown) {
    super(errorString, errorCode, packet);
  }

  toString(): string {
    const code = this.error_code ?? 0;
    return `DCOM SessionError: unknown error code: 0x${code.toString(16)}`;
  }
}

// ============================================================================
// CONSTANTS
// ============================================================================
// 2.2.1 OID
export const OID = ULONGLONG;

export class OID_ARRAY extends NDRUniConformantArray {
  static item = OID;
}

export class POID_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', OID_ARRAY]];
}

// 2.2.2 SETID
export const SETID = ULONGLONG;

// 2.2.4 error_status_t
const error_status_t = ULONG;

// 2.2.6 CID
export const CID = GUID;

// 2.2.7 CLSID
export { GUID as CLSID } from './dtypes';
const CLSID = GUID;

// 2.2.8 IID
export const IID = GUID;
export const PIID = PGUID;

// 2.2.9 IPID
export const IPID = GUID;

// 2.2.10 OXID
export const OXID = ULONGLONG;

// 2.2.18 OBJREF flags
export const FLAGS_OBJREF_STANDARD = 0x00000001;
export const FLAGS_OBJREF_HANDLER = 0x00000002;
export const FLAGS_OBJREF_CUSTOM = 0x00000004;
export const FLAGS_OBJREF_EXTENDED = 0x00000008;

// 2.2.18.1 STDOBJREF
export const SORF_NOPING = 0x00001000;

// 2.2.20 Context
export const CTXMSHLFLAGS_BYVAL = 0x00000002;

// 2.2.20.1 PROPMARSHALHEADER
export const CPFLAG_PROPAGATE = 0x00000001;
export const CPFLAG_EXPOSE = 0x00000002;
export const CPFLAG_ENVOY = 0x00000004;

// 2.2.22.2.1 InstantiationInfoData
export const ACTVFLAGS_DISABLE_AAA = 0x00000002;
export const ACTVFLAGS_ACTIVATE_32_BIT_SERVER = 0x00000004;
export const ACTVFLAGS_ACTIVATE_64_BIT_SERVER = 0x00000008;
export const ACTVFLAGS_NO_FAILURE_LOG = 0x00000020;

// 2.2.22.2.2 SpecialPropertiesData
export const SPD_FLAG_USE_CONSOLE_SESSION = 0x00000001;

// 2.2.28.1 IDL Range Constants
export const MAX_REQUESTED_INTERFACES = 0x8000;
export const MAX_REQUESTED_PROTSEQS = 0x8000;
export const MIN_ACTPROP_LIMIT = 1;
export const MAX_ACTPROP_LIMIT = 10;

// ============================================================================
// STRUCTURES
// ============================================================================

// handle_t (module-private per collision rules)
class handle_t extends NDRSTRUCT {
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

  isNull(): boolean {
    const uuid = this.get('context_handle_uuid') as Buffer;
    return Buffer.isBuffer(uuid) && uuid.equals(Buffer.alloc(16, 0));
  }
}

// 2.2.11 COMVERSION
export class COMVERSION extends NDRSTRUCT {
  static defaultMajorVersion = 5;
  static defaultMinorVersion = 7;

  static structure: NDRField[] = [
    ['MajorVersion', USHORT],
    ['MinorVersion', USHORT],
  ];

  static setDefaultVersion(majorVersion?: number, minorVersion?: number): void {
    if (majorVersion !== undefined) {
      COMVERSION.defaultMajorVersion = majorVersion;
    }
    if (minorVersion !== undefined) {
      COMVERSION.defaultMinorVersion = minorVersion;
    }
  }

  constructor(data?: Buffer | null, isNDR64: boolean = false) {
    super(data, isNDR64);
    if (!data) {
      this.set('MajorVersion', COMVERSION.defaultMajorVersion);
      this.set('MinorVersion', COMVERSION.defaultMinorVersion);
    }
  }
}

export class PCOMVERSION extends NDRPOINTER {
  static referent: NDRField[] = [['Data', COMVERSION]];
}

// 2.2.13.1 ORPC_EXTENT
// BYTE_ARRAY (module-private per collision rules)
class BYTE_ARRAY extends NDRUniConformantArray {
  static item = 'c' as unknown as typeof NDRSTRUCT;
}

export class ORPC_EXTENT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['id', GUID],
    ['size', ULONG],
    ['data', BYTE_ARRAY],
  ];
}

// 2.2.13.2 ORPC_EXTENT_ARRAY
export class PORPC_EXTENT extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ORPC_EXTENT]];
}

export class EXTENT_ARRAY extends NDRUniConformantArray {
  static item = PORPC_EXTENT;
}

export class PEXTENT_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', EXTENT_ARRAY]];
}

export class ORPC_EXTENT_ARRAY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['size', ULONG],
    ['reserved', ULONG],
    ['extent', PEXTENT_ARRAY],
  ];
}

export class PORPC_EXTENT_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ORPC_EXTENT_ARRAY]];
}

// 2.2.13.3 ORPCTHIS
export class ORPCTHIS extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['version', COMVERSION],
    ['flags', ULONG],
    ['reserved1', ULONG],
    ['cid', CID],
    ['extensions', PORPC_EXTENT_ARRAY],
  ];
}

// 2.2.13.4 ORPCTHAT
export class ORPCTHAT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['flags', ULONG],
    ['extensions', PORPC_EXTENT_ARRAY],
  ];
}

// 2.2.14 MInterfacePointer
export class MInterfacePointer extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ulCntData', ULONG],
    ['abData', BYTE_ARRAY],
  ];
}

// 2.2.15 PMInterfacePointerInternal
export class PMInterfacePointerInternal extends NDRPOINTER {
  static referent: NDRField[] = [['Data', MInterfacePointer]];
}

// 2.2.16 PMInterfacePointer
export class PMInterfacePointer extends NDRPOINTER {
  static referent: NDRField[] = [['Data', MInterfacePointer]];
}

export class PPMInterfacePointer extends NDRPOINTER {
  static referent: NDRField[] = [['Data', PMInterfacePointer]];
}

// 2.2.18 OBJREF
export class OBJREF extends NDRSTRUCT {
  static commonHdr: NDRField[] = [
    ['signature', ULONG],
    ['flags', ULONG],
    ['iid', GUID],
  ];

  constructor(data?: Buffer | null, isNDR64: boolean = false) {
    super(data, isNDR64);
    if (!data) {
      this.set('signature', 0x574f454d);
    }
  }
}

// 2.2.18.1 STDOBJREF
export class STDOBJREF extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['flags', ULONG],
    ['cPublicRefs', ULONG],
    ['oxid', OXID],
    ['oid', OID],
    ['ipid', IPID],
  ];
}

// 2.2.18.4 OBJREF_STANDARD
export class OBJREF_STANDARD extends OBJREF {
  static structure: NDRField[] = [
    ['std', STDOBJREF],
    ['saResAddr', ':'],
  ];

  constructor(data?: Buffer | null, isNDR64: boolean = false) {
    super(data, isNDR64);
    if (!data) {
      this.set('flags', FLAGS_OBJREF_STANDARD);
    }
  }
}

// 2.2.18.5 OBJREF_HANDLER
export class OBJREF_HANDLER extends OBJREF {
  static structure: NDRField[] = [
    ['std', STDOBJREF],
    ['clsid', CLSID],
    ['saResAddr', ':'],
  ];

  constructor(data?: Buffer | null, isNDR64: boolean = false) {
    super(data, isNDR64);
    if (!data) {
      this.set('flags', FLAGS_OBJREF_HANDLER);
    }
  }
}

// 2.2.18.6 OBJREF_CUSTOM
export class OBJREF_CUSTOM extends OBJREF {
  static structure: NDRField[] = [
    ['clsid', CLSID],
    ['cbExtension', ULONG],
    ['ObjectReferenceSize', ULONG],
    ['pObjectData', ':'],
  ];

  constructor(data?: Buffer | null, isNDR64: boolean = false) {
    super(data, isNDR64);
    if (!data) {
      this.set('flags', FLAGS_OBJREF_CUSTOM);
    }
  }
}

// 2.2.18.8 DATAELEMENT
export class DATAELEMENT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dataID', GUID],
    ['cbSize', ULONG],
    ['cbRounded', ULONG],
    ['Data', ':'],
  ];
}

export class DUALSTRINGARRAYPACKED extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['wNumEntries', USHORT],
    ['wSecurityOffset', USHORT],
    ['aStringArray', ':'],
  ];

  getDataLen(_data: Buffer, _offset = 0): number {
    return (this.get('wNumEntries') as number) * 2;
  }
}

// 2.2.18.7 OBJREF_EXTENDED
export class OBJREF_EXTENDED extends OBJREF {
  static structure: NDRField[] = [
    ['std', STDOBJREF],
    ['Signature1', ULONG],
    ['saResAddr', DUALSTRINGARRAYPACKED],
    ['nElms', ULONG],
    ['Signature2', ULONG],
    ['ElmArray', DATAELEMENT],
  ];

  constructor(data?: Buffer | null, isNDR64: boolean = false) {
    super(data, isNDR64);
    if (!data) {
      this.set('flags', FLAGS_OBJREF_EXTENDED);
      this.set('Signature1', 0x4e535956);
      this.set('Signature2', 0x4e535956);
      this.set('nElms', 0x4e535956);
    }
  }
}

// 2.2.19 DUALSTRINGARRAY
// USHORT_ARRAY (module-private per collision rules)
class USHORT_ARRAY extends NDRUniConformantArray {
  static item = '<H' as unknown as typeof NDRSTRUCT;
}

// PUSHORT_ARRAY (module-private per collision rules)
class PUSHORT_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', USHORT_ARRAY]];
}

export class DUALSTRINGARRAY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['wNumEntries', USHORT],
    ['wSecurityOffset', USHORT],
    ['aStringArray', USHORT_ARRAY],
  ];
}

export class PDUALSTRINGARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DUALSTRINGARRAY]];
}

// 2.2.19.3 STRINGBINDING
export class STRINGBINDING extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['wTowerId', USHORT],
    ['aNetworkAddr', WIDESTR],
  ];
}

// 2.2.19.4 SECURITYBINDING
export class SECURITYBINDING extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['wAuthnSvc', USHORT],
    ['Reserved', USHORT],
    ['aPrincName', WIDESTR],
  ];
}

// 2.2.20.1 PROPMARSHALHEADER
export class PROPMARSHALHEADER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['clsid', CLSID],
    ['policyId', GUID],
    ['flags', ULONG],
    ['cb', ULONG],
    ['ctxProperty', ':'],
  ];
}

export class PROPMARSHALHEADER_ARRAY extends NDRUniConformantArray {
  static item = PROPMARSHALHEADER;
}

// 2.2.20 Context
export class Context extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['MajorVersion', USHORT],
    ['MinVersion', USHORT],
    ['ContextId', GUID],
    ['Flags', ULONG],
    ['Reserved', ULONG],
    ['dwNumExtents', ULONG],
    ['cbExtents', ULONG],
    ['MshlFlags', ULONG],
    ['Count', ULONG],
    ['Frozen', ULONG],
    ['PropMarshalHeader', PROPMARSHALHEADER_ARRAY],
  ];
}

// 2.2.21.3 ErrorInfoString
export class ErrorInfoString extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwMax', ULONG],
    ['dwOffSet', ULONG],
    ['dwActual', IID],
    ['Name', WSTR],
  ];
}

// 2.2.21.2 Custom-Marshaled Error Information Format
export class ORPC_ERROR_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwVersion', ULONG],
    ['dwHelpContext', ULONG],
    ['iid', IID],
    ['dwSourceSignature', ULONG],
    ['Source', ErrorInfoString],
    ['dwDescriptionSignature', ULONG],
    ['Description', ErrorInfoString],
    ['dwHelpFileSignature', ULONG],
    ['HelpFile', ErrorInfoString],
  ];
}

// 2.2.21.5 EntryHeader
export class EntryHeader extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Signature', ULONG],
    ['cbEHBuffer', ULONG],
    ['cbSize', ULONG],
    ['reserved', ULONG],
    ['policyID', GUID],
  ];
}

export class EntryHeader_ARRAY extends NDRUniConformantArray {
  static item = EntryHeader;
}

// 2.2.21.4 Context ORPC Extension
export class ORPC_CONTEXT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['SignatureVersion', ULONG],
    ['Version', ULONG],
    ['cPolicies', ULONG],
    ['cbBuffer', ULONG],
    ['cbSize', ULONG],
    ['hr', ULONG],
    ['hrServer', ULONG],
    ['reserved', ULONG],
    ['EntryHeader', EntryHeader_ARRAY],
    ['PolicyData', ':'],
  ];

  constructor(data?: Buffer | null, isNDR64: boolean = false) {
    super(data, isNDR64);
    if (!data) {
      this.set('SignatureVersion', 0x414e554b);
    }
  }
}

// 2.2.22.1 CustomHeader
export class CLSID_ARRAY extends NDRUniConformantArray {
  static item = CLSID;
}

export class PCLSID_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', CLSID_ARRAY]];
}

// DWORD_ARRAY (module-private per collision rules)
class DWORD_ARRAY extends NDRUniConformantArray {
  static item = DWORD;
}

class PDWORD_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DWORD_ARRAY]];
}

export class CustomHeader extends TypeSerialization1 {
  static structure: NDRField[] = [
    ['totalSize', DWORD],
    ['headerSize', DWORD],
    ['dwReserved', DWORD],
    ['destCtx', DWORD],
    ['cIfs', DWORD],
    ['classInfoClsid', CLSID],
    ['pclsid', PCLSID_ARRAY],
    ['pSizes', PDWORD_ARRAY],
    ['pdwReserved', LPLONG],
  ];

  getData(soFar = 0): Buffer {
    this.set(
      'headerSize',
      TypeSerialization1.prototype.getData.call(this, soFar).length +
        TypeSerialization1.prototype.getDataReferents.call(this, soFar).length,
    );
    this.set('cIfs', (this.get('pclsid') as unknown[]).length);
    return TypeSerialization1.prototype.getData.call(this, soFar);
  }
}

// 2.2.22 Activation Properties BLOB
// NDRTLSTRUCT is just NDRCALL in the TS port
export class ACTIVATION_BLOB extends NDRCALL {
  static structure: NDRField[] = [
    ['dwSize', ULONG],
    ['dwReserved', ULONG],
    ['CustomHeader', CustomHeader],
    ['Property', UNKNOWNDATA],
  ];

  getData(soFar = 0): Buffer {
    const customHeader = this.get('CustomHeader') as CustomHeader;
    const property = this.get('Property') as Buffer;
    const headerData = customHeader.getData(soFar);
    const headerReferents = customHeader.getDataReferents(soFar);
    const propertyLen = Buffer.isBuffer(property) ? property.length : 0;
    this.set('dwSize', headerData.length + headerReferents.length + propertyLen);
    customHeader.set('totalSize', this.get('dwSize'));
    return NDRCALL.prototype.getData.call(this);
  }
}

// 2.2.22.2.1 InstantiationInfoData
export class IID_ARRAY extends NDRUniConformantArray {
  static item = IID;
}

export class PIID_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', IID_ARRAY]];
}

export class InstantiationInfoData extends TypeSerialization1 {
  static structure: NDRField[] = [
    ['classId', CLSID],
    ['classCtx', DWORD],
    ['actvflags', DWORD],
    ['fIsSurrogate', LONG],
    ['cIID', DWORD],
    ['instFlag', DWORD],
    ['pIID', PIID_ARRAY],
    ['thisSize', DWORD],
    ['clientCOMVersion', COMVERSION],
  ];
}

// 2.2.22.2.2 SpecialPropertiesData
export class SpecialPropertiesData extends TypeSerialization1 {
  static structure: NDRField[] = [
    ['dwSessionId', ULONG],
    ['fRemoteThisSessionId', LONG],
    ['fClientImpersonating', LONG],
    ['fPartitionIDPresent', LONG],
    ['dwDefaultAuthnLvl', DWORD],
    ['guidPartition', GUID],
    ['dwPRTFlags', DWORD],
    ['dwOrigClsctx', DWORD],
    ['dwFlags', DWORD],
    ['Reserved0', DWORD],
    ['Reserved0_2', DWORD],
    ['Reserved', '32s=""'],
  ];
}

// 2.2.22.2.3 InstanceInfoData
export class InstanceInfoData extends TypeSerialization1 {
  static structure: NDRField[] = [
    ['fileName', LPWSTR],
    ['mode', DWORD],
    ['ifdROT', PMInterfacePointer],
    ['ifdStg', PMInterfacePointer],
  ];
}

// 2.2.22.2.4.1 customREMOTE_REQUEST_SCM_INFO
export class customREMOTE_REQUEST_SCM_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ClientImpLevel', DWORD],
    ['cRequestedProtseqs', USHORT],
    ['pRequestedProtseqs', PUSHORT_ARRAY],
  ];
}

export class PcustomREMOTE_REQUEST_SCM_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', customREMOTE_REQUEST_SCM_INFO]];
}

// 2.2.22.2.4 ScmRequestInfoData
export class ScmRequestInfoData extends TypeSerialization1 {
  static structure: NDRField[] = [
    ['pdwReserved', LPLONG],
    ['remoteRequest', PcustomREMOTE_REQUEST_SCM_INFO],
  ];
}

// 2.2.22.2.5 ActivationContextInfoData
export class ActivationContextInfoData extends TypeSerialization1 {
  static structure: NDRField[] = [
    ['clientOK', LONG],
    ['bReserved1', LONG],
    ['dwReserved1', DWORD],
    ['dwReserved2', DWORD],
    ['pIFDClientCtx', PMInterfacePointer],
    ['pIFDPrototypeCtx', PMInterfacePointer],
  ];
}

// 2.2.22.2.6 LocationInfoData
export class LocationInfoData extends TypeSerialization1 {
  static structure: NDRField[] = [
    ['machineName', LPWSTR],
    ['processId', DWORD],
    ['apartmentId', DWORD],
    ['contextId', DWORD],
  ];
}

// 2.2.22.2.7.1 COSERVERINFO
export class COSERVERINFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwReserved1', DWORD],
    ['pwszName', LPWSTR],
    ['pdwReserved', LPLONG],
    ['dwReserved2', DWORD],
  ];
}

export class PCOSERVERINFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', COSERVERINFO]];
}

// 2.2.22.2.7 SecurityInfoData
export class SecurityInfoData extends TypeSerialization1 {
  static structure: NDRField[] = [
    ['dwAuthnFlags', DWORD],
    ['pServerInfo', PCOSERVERINFO],
    ['pdwReserved', LPLONG],
  ];
}

// 2.2.22.2.8.1 customREMOTE_REPLY_SCM_INFO
export class customREMOTE_REPLY_SCM_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Oxid', OXID],
    ['pdsaOxidBindings', PDUALSTRINGARRAY],
    ['ipidRemUnknown', IPID],
    ['authnHint', DWORD],
    ['serverVersion', COMVERSION],
  ];
}

export class PcustomREMOTE_REPLY_SCM_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', customREMOTE_REPLY_SCM_INFO]];
}

// 2.2.22.2.8 ScmReplyInfoData
export class ScmReplyInfoData extends TypeSerialization1 {
  static structure: NDRField[] = [
    ['pdwReserved', DWORD],
    ['remoteReply', PcustomREMOTE_REPLY_SCM_INFO],
  ];
}

// 2.2.22.2.9 PropsOutInfo
export class HRESULT_ARRAY extends NDRUniConformantArray {
  static item = HRESULT;
}

export class PHRESULT_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', HRESULT_ARRAY]];
}

export class MInterfacePointer_ARRAY extends NDRUniConformantArray {
  static item = MInterfacePointer;
}

export class PMInterfacePointer_ARRAY extends NDRUniConformantArray {
  static item = PMInterfacePointer;
}

export class PPMInterfacePointer_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', PMInterfacePointer_ARRAY]];
}

export class PropsOutInfo extends TypeSerialization1 {
  static structure: NDRField[] = [
    ['cIfs', DWORD],
    ['piid', PIID_ARRAY],
    ['phresults', PHRESULT_ARRAY],
    ['ppIntfData', PPMInterfacePointer_ARRAY],
  ];
}

// 2.2.23 REMINTERFACEREF
export class REMINTERFACEREF extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ipid', IPID],
    ['cPublicRefs', LONG],
    ['cPrivateRefs', LONG],
  ];
}

export class REMINTERFACEREF_ARRAY extends NDRUniConformantArray {
  static item = REMINTERFACEREF;
}

// 2.2.24 REMQIRESULT
export class REMQIRESULT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['hResult', HRESULT],
    ['std', STDOBJREF],
  ];
}

// 2.2.25 PREMQIRESULT
export class PREMQIRESULT extends NDRPOINTER {
  static referent: NDRField[] = [['Data', REMQIRESULT]];
}

// 2.2.26 REFIPID
export const REFIPID = GUID;

// ============================================================================
// RPC CALLS
// ============================================================================
export class DCOMCALL extends NDRCALL {
  static commonHdr: NDRField[] = [['ORPCthis', ORPCTHIS]];
}

export class DCOMANSWER extends NDRCALL {
  static commonHdr: NDRField[] = [['ORPCthat', ORPCTHAT]];
}

// 3.1.2.5.1.1 IObjectExporter::ResolveOxid (Opnum 0)
export class ResolveOxidResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppdsaOxidBindings', PDUALSTRINGARRAY],
    ['pipidRemUnknown', IPID],
    ['pAuthnHint', DWORD],
    ['ErrorCode', error_status_t],
  ];
}

export class ResolveOxid extends NDRCALL {
  static opnum = 0;
  static Response = ResolveOxidResponse;
  static structure: NDRField[] = [
    ['pOxid', OXID],
    ['cRequestedProtseqs', USHORT],
    ['arRequestedProtseqs', USHORT_ARRAY],
  ];
}

// 3.1.2.5.1.2 IObjectExporter::SimplePing (Opnum 1)
export class SimplePingResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', error_status_t]];
}

export class SimplePing extends NDRCALL {
  static opnum = 1;
  static Response = SimplePingResponse;
  static structure: NDRField[] = [['pSetId', SETID]];
}

// 3.1.2.5.1.3 IObjectExporter::ComplexPing (Opnum 2)
export class ComplexPingResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pSetId', SETID],
    ['pPingBackoffFactor', USHORT],
    ['ErrorCode', error_status_t],
  ];
}

export class ComplexPing extends NDRCALL {
  static opnum = 2;
  static Response = ComplexPingResponse;
  static structure: NDRField[] = [
    ['pSetId', SETID],
    ['SequenceNum', USHORT],
    ['cAddToSet', USHORT],
    ['cDelFromSet', USHORT],
    ['AddToSet', POID_ARRAY],
    ['DelFromSet', POID_ARRAY],
  ];
}

// 3.1.2.5.1.4 IObjectExporter::ServerAlive (Opnum 3)
export class ServerAliveResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', error_status_t]];
}

export class ServerAlive extends NDRCALL {
  static opnum = 3;
  static Response = ServerAliveResponse;
  static structure: NDRField[] = [];
}

// 3.1.2.5.1.5 IObjectExporter::ResolveOxid2 (Opnum 4)
export class ResolveOxid2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['ppdsaOxidBindings', PDUALSTRINGARRAY],
    ['pipidRemUnknown', IPID],
    ['pAuthnHint', DWORD],
    ['pComVersion', COMVERSION],
    ['ErrorCode', error_status_t],
  ];
}

export class ResolveOxid2 extends NDRCALL {
  static opnum = 4;
  static Response = ResolveOxid2Response;
  static structure: NDRField[] = [
    ['pOxid', OXID],
    ['cRequestedProtseqs', USHORT],
    ['arRequestedProtseqs', USHORT_ARRAY],
  ];
}

// 3.1.2.5.1.6 IObjectExporter::ServerAlive2 (Opnum 5)
export class ServerAlive2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['pComVersion', COMVERSION],
    ['ppdsaOrBindings', PDUALSTRINGARRAY],
    ['pReserved', LPLONG],
    ['ErrorCode', error_status_t],
  ];
}

export class ServerAlive2 extends NDRCALL {
  static opnum = 5;
  static Response = ServerAlive2Response;
  static structure: NDRField[] = [];
}

// 3.1.2.5.2.3.1 IActivation:: RemoteActivation (Opnum 0)
export class RemoteActivationResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ORPCthat', ORPCTHAT],
    ['pOxid', OXID],
    ['ppdsaOxidBindings', PDUALSTRINGARRAY],
    ['pipidRemUnknown', IPID],
    ['pAuthnHint', DWORD],
    ['pServerVersion', COMVERSION],
    ['phr', HRESULT],
    ['ppInterfaceData', PMInterfacePointer_ARRAY],
    ['pResults', HRESULT_ARRAY],
    ['ErrorCode', error_status_t],
  ];
}

export class RemoteActivation extends NDRCALL {
  static opnum = 0;
  static Response = RemoteActivationResponse;
  static structure: NDRField[] = [
    ['ORPCthis', ORPCTHIS],
    ['Clsid', GUID],
    ['pwszObjectName', LPWSTR],
    ['pObjectStorage', PMInterfacePointer],
    ['ClientImpLevel', DWORD],
    ['Mode', DWORD],
    ['Interfaces', DWORD],
    ['pIIDs', PIID_ARRAY],
    ['cRequestedProtseqs', USHORT],
    ['aRequestedProtseqs', USHORT_ARRAY],
  ];
}

// 3.1.2.5.2.3.2 IRemoteSCMActivator::RemoteGetClassObject (Opnum 3)
export class RemoteGetClassObjectResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ORPCthat', ORPCTHAT],
    ['ppActProperties', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

export class RemoteGetClassObject extends NDRCALL {
  static opnum = 3;
  static Response = RemoteGetClassObjectResponse;
  static structure: NDRField[] = [
    ['ORPCthis', ORPCTHIS],
    ['pActProperties', PMInterfacePointer],
  ];
}

// 3.1.2.5.2.3.3 IRemoteSCMActivator::RemoteCreateInstance (Opnum 4)
export class RemoteCreateInstanceResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ORPCthat', ORPCTHAT],
    ['ppActProperties', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

export class RemoteCreateInstance extends NDRCALL {
  static opnum = 4;
  static Response = RemoteCreateInstanceResponse;
  static structure: NDRField[] = [
    ['ORPCthis', ORPCTHIS],
    ['pUnkOuter', PMInterfacePointer],
    ['pActProperties', PMInterfacePointer],
  ];
}

// 3.1.1.5.6.1.1 IRemUnknown::RemQueryInterface (Opnum 3)
export class RemQueryInterfaceResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppQIResults', PREMQIRESULT],
    ['ErrorCode', error_status_t],
  ];
}

export class RemQueryInterface extends DCOMCALL {
  static opnum = 3;
  static Response = RemQueryInterfaceResponse;
  static structure: NDRField[] = [
    ['ripid', REFIPID],
    ['cRefs', ULONG],
    ['cIids', USHORT],
    ['iids', IID_ARRAY],
  ];
}

// 3.1.1.5.6.1.2 IRemUnknown::RemAddRef (Opnum 4)
export class RemAddRefResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pResults', DWORD_ARRAY],
    ['ErrorCode', error_status_t],
  ];
}

export class RemAddRef extends DCOMCALL {
  static opnum = 4;
  static Response = RemAddRefResponse;
  static structure: NDRField[] = [
    ['cInterfaceRefs', USHORT],
    ['InterfaceRefs', REMINTERFACEREF_ARRAY],
  ];
}

// 3.1.1.5.6.1.3 IRemUnknown::RemRelease (Opnum 5)
export class RemReleaseResponse extends DCOMANSWER {
  static structure: NDRField[] = [['ErrorCode', error_status_t]];
}

export class RemRelease extends DCOMCALL {
  static opnum = 5;
  static Response = RemReleaseResponse;
  static structure: NDRField[] = [
    ['cInterfaceRefs', USHORT],
    ['InterfaceRefs', REMINTERFACEREF_ARRAY],
  ];
}

// ============================================================================
// OPNUMs and their corresponding structures (module-private)
// ============================================================================
const OPNUMS: Record<number, unknown> = {};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

type DceRequestFn = <T>(req: unknown, uuid?: unknown, checkError?: boolean) => Promise<T>;

function parseStringBindings(oxidsData: Buffer, securityOffset: number): STRINGBINDING[] {
  let strBindings = oxidsData.subarray(0, securityOffset * 2);
  const stringBindings: STRINGBINDING[] = [];
  while (strBindings.length > 0) {
    if (strBindings[0] === 0x00 && strBindings[1] === 0x00) {
      break;
    }
    const binding = new STRINGBINDING(strBindings);
    stringBindings.push(binding);
    strBindings = strBindings.subarray(binding.getData().length);
  }
  return stringBindings;
}

function parseSecurityBindings(data: Buffer): void {
  let securityBindings = data;
  while (securityBindings.length >= 2) {
    if (securityBindings[0] === 0x00 && securityBindings[1] === 0x00) {
      break;
    }
    const secBinding = new SECURITYBINDING(securityBindings);
    securityBindings = securityBindings.subarray(secBinding.getData().length);
  }
}

function oxidsToBuffer(aStringArray: number[]): Buffer {
  const bufs: Buffer[] = [];
  for (const x of aStringArray) {
    const buf = Buffer.allocUnsafe(2);
    buf.writeUInt16LE(x);
    bufs.push(buf);
  }
  return Buffer.concat(bufs);
}

export class DCOMConnection {
  static PINGTIMER: ReturnType<typeof setInterval> | null = null;
  static OID_ADD: Record<string, Set<number>> = {};
  static OID_DEL: Record<string, Set<number>> = {};
  static OID_SET: Record<string, { oids: Set<number>; setid: number }> = {};
  static PORTMAPS: Record<string, DCERPC_v5> = {};

  private __target: string;
  private __userName: string;
  private __password: string;
  private __domain: string;
  private __lmhash: string;
  private __nthash: string;
  private __aesKey: string;
  private __TGT: unknown;
  private __TGS: unknown;
  private __authLevel: number;
  private __portmap: DCERPC_v5 | null = null;
  private __oxidResolver: boolean;
  private __doKerberos: boolean;
  private __kdcHost: string | null;
  private __remoteHost: string | null;

  constructor(
    target: string,
    username = '',
    password = '',
    domain = '',
    lmhash = '',
    nthash = '',
    aesKey = '',
    TGT: unknown = null,
    TGS: unknown = null,
    authLevel: number = RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
    oxidResolver = false,
    doKerberos = false,
    kdcHost: string | null = null,
    remoteHost: string | null = null,
  ) {
    this.__target = target;
    this.__userName = username;
    this.__password = password;
    this.__domain = domain;
    this.__lmhash = lmhash;
    this.__nthash = nthash;
    this.__aesKey = aesKey;
    this.__TGT = TGT;
    this.__TGS = TGS;
    this.__authLevel = authLevel;
    this.__oxidResolver = oxidResolver;
    this.__doKerberos = doKerberos;
    this.__kdcHost = kdcHost;
    this.__remoteHost = remoteHost;
  }

  static addOid(target: string, oid: number): void {
    if (!(target in DCOMConnection.OID_ADD)) {
      DCOMConnection.OID_ADD[target] = new Set();
    }
    DCOMConnection.OID_ADD[target]!.add(oid);
    if (!(target in DCOMConnection.OID_SET)) {
      DCOMConnection.OID_SET[target] = { oids: new Set(), setid: 0 };
    }
  }

  static delOid(target: string, oid: number): void {
    if (!(target in DCOMConnection.OID_DEL)) {
      DCOMConnection.OID_DEL[target] = new Set();
    }
    DCOMConnection.OID_DEL[target]!.add(oid);
    if (!(target in DCOMConnection.OID_SET)) {
      DCOMConnection.OID_SET[target] = { oids: new Set(), setid: 0 };
    }
  }

  static async pingServer(): Promise<void> {
    try {
      for (const target of Object.keys(DCOMConnection.OID_SET)) {
        let addedOids = new Set<number>();
        let deletedOids = new Set<number>();
        if (target in DCOMConnection.OID_ADD) {
          addedOids = DCOMConnection.OID_ADD[target]!;
          delete DCOMConnection.OID_ADD[target];
        }
        if (target in DCOMConnection.OID_DEL) {
          deletedOids = DCOMConnection.OID_DEL[target]!;
          delete DCOMConnection.OID_DEL[target];
        }

        const objExporter = new IObjectExporter(DCOMConnection.PORTMAPS[target]!);

        if (addedOids.size > 0 || deletedOids.size > 0) {
          const setId = DCOMConnection.OID_SET[target]!.setid ?? 0;
          const resp = await objExporter.ComplexPing(setId, 0, [...addedOids], [...deletedOids]);
          for (const oid of deletedOids) {
            DCOMConnection.OID_SET[target]!.oids.delete(oid);
          }
          for (const oid of addedOids) {
            DCOMConnection.OID_SET[target]!.oids.add(oid);
          }
          DCOMConnection.OID_SET[target]!.setid = (resp as unknown as Record<string, unknown>)['pSetId'] as number;
        } else {
          await objExporter.SimplePing(DCOMConnection.OID_SET[target]!.setid);
        }
      }
    } catch (e) {
      // There might be exceptions when sending packets
      // We should try to continue though.
      console.error(String(e));
    }
  }

  initTimer(): void {
    if (this.__oxidResolver) {
      if (DCOMConnection.PINGTIMER === null) {
        DCOMConnection.PINGTIMER = setInterval(() => {
          void DCOMConnection.pingServer();
        }, 120_000);
        // Allow the process to exit even if the timer is running
        if (DCOMConnection.PINGTIMER && typeof DCOMConnection.PINGTIMER === 'object' && 'unref' in DCOMConnection.PINGTIMER) {
          (DCOMConnection.PINGTIMER as NodeJS.Timeout).unref();
        }
      }
    }
  }

  async initConnection(): Promise<void> {
    const stringBinding = `ncacn_ip_tcp:${this.__target}`;
    const rpctransport = DCERPCTransportFactory(stringBinding);

    const t = rpctransport as any;
    if (this.__remoteHost) {
      if ('setRemoteHost' in rpctransport) {
        t.setRemoteHost(this.__remoteHost);
      }
      if ('setRemoteName' in rpctransport) {
        t.setRemoteName(this.__target);
      }
    }

    if ('setCredentials' in rpctransport) {
      t.setCredentials(
        this.__userName,
        this.__password,
        this.__domain,
        this.__lmhash,
        this.__nthash,
        this.__aesKey,
        this.__TGT,
        this.__TGS,
      );
    }
    if ('setKerberos' in rpctransport) {
      t.setKerberos(this.__doKerberos, this.__kdcHost);
    }

    this.__portmap = t.getDceRpc() as DCERPC_v5;
    this.__portmap.setAuthLevel(this.__authLevel);
    if (this.__doKerberos) {
      this.__portmap.setAuthType(RPC_C_AUTHN_GSS_NEGOTIATE);
    }
    await this.__portmap.connect();
    DCOMConnection.PORTMAPS[this.__target] = this.__portmap;
  }

  async CoCreateInstanceEx(clsid: Buffer, iid: Buffer): Promise<IRemUnknown2> {
    const scm = new IRemoteSCMActivator(this.__portmap!);
    const iInterface = await scm.RemoteCreateInstance(clsid, iid);
    this.initTimer();
    return iInterface;
  }

  getDceRpc(): DCERPC_v5 {
    return DCOMConnection.PORTMAPS[this.__target]!;
  }

  disconnect(): void {
    if (this.__target in DCOMConnection.PORTMAPS) {
      delete DCOMConnection.PORTMAPS[this.__target];
    }
    if (this.__target in DCOMConnection.OID_SET) {
      delete DCOMConnection.OID_SET[this.__target];
    }
    if (DCOMConnection.PINGTIMER && Object.keys(DCOMConnection.PORTMAPS).length === 0) {
      clearInterval(DCOMConnection.PINGTIMER);
      DCOMConnection.PINGTIMER = null;
    }
    if (this.__target in INTERFACE.CONNECTIONS) {
      delete INTERFACE.CONNECTIONS[this.__target];
    }
    if (this.__portmap) {
      this.__portmap.disconnect();
    }
  }
}

export class CLASS_INSTANCE {
  private __stringBindings: STRINGBINDING[];
  private __ORPCthis: ORPCTHIS;
  private __authType: number;
  private __authLevel: number;

  constructor(ORPCthis: ORPCTHIS, stringBindings: STRINGBINDING[]) {
    this.__stringBindings = stringBindings;
    this.__ORPCthis = ORPCthis;
    this.__authType = RPC_C_AUTHN_WINNT;
    this.__authLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
  }

  getORPCthis(): ORPCTHIS {
    return this.__ORPCthis;
  }

  getStringBindings(): STRINGBINDING[] {
    return this.__stringBindings;
  }

  getAuthLevel(): number {
    if (RPC_C_AUTHN_LEVEL_NONE < this.__authLevel && this.__authLevel < RPC_C_AUTHN_LEVEL_PKT_PRIVACY) {
      if (this.__authType === RPC_C_AUTHN_WINNT) {
        return RPC_C_AUTHN_LEVEL_PKT_INTEGRITY;
      } else {
        return RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
      }
    }
    return this.__authLevel;
  }

  setAuthLevel(level: number): void {
    this.__authLevel = level;
  }

  getAuthType(): number {
    return this.__authType;
  }

  setAuthType(authType: number): void {
    this.__authType = authType;
  }
}

export class INTERFACE {
  static CONNECTIONS: Record<string, Record<string, Record<number, { dce: DCERPC_v5; currentBinding: Buffer | null }>>> = {};

  protected __target: string;
  protected __iPid: Buffer | null;
  protected __oid: number | null;
  protected __oxid: number | null;
  protected __cinstance: CLASS_INSTANCE | null;
  protected __objRef: Buffer | null;
  protected __ipidRemUnknown: Buffer | null;

  // Connection key for thread-name keying; in Node.js we use a fixed string
  private static readonly CONNECTION_KEY = 'main';

  constructor(options: {
    cinstance?: CLASS_INSTANCE | null;
    objRef?: Buffer | null;
    ipidRemUnknown?: Buffer | null;
    iPid?: Buffer | null;
    oxid?: number | null;
    oid?: number | null;
    target?: string | null;
    interfaceInstance?: INTERFACE | null;
  }) {
    const {
      cinstance = null,
      objRef = null,
      ipidRemUnknown = null,
      iPid = null,
      oxid = null,
      oid = null,
      target = null,
      interfaceInstance = null,
    } = options;

    if (interfaceInstance !== null) {
      this.__target = interfaceInstance.getTarget();
      this.__iPid = interfaceInstance.getIPid();
      this.__oid = interfaceInstance.getOid();
      this.__oxid = interfaceInstance.getOxid();
      this.__cinstance = interfaceInstance.getCinstance();
      this.__objRef = interfaceInstance.getObjRef();
      this.__ipidRemUnknown = interfaceInstance.getIpidRemUnknown();
    } else {
      if (target === null) {
        throw new Error('No target');
      }
      this.__target = target;
      this.__iPid = iPid ?? null;
      this.__oid = oid ?? null;
      this.__oxid = oxid ?? null;
      this.__cinstance = cinstance ?? null;
      this.__objRef = objRef ?? null;
      this.__ipidRemUnknown = ipidRemUnknown ?? null;

      if (!(this.__target in INTERFACE.CONNECTIONS)) {
        INTERFACE.CONNECTIONS[this.__target] = {};
        INTERFACE.CONNECTIONS[this.__target]![INTERFACE.CONNECTION_KEY] = {};
      }

      if (objRef !== null && objRef !== undefined) {
        this.processInterface(objRef);
      }
    }
  }

  processInterface(data: Buffer): void {
    const objRefType = new OBJREF(data).get('flags') as number;
    let objRef: OBJREF | null = null;

    if (objRefType === FLAGS_OBJREF_CUSTOM) {
      objRef = new OBJREF_CUSTOM(data);
    } else if (objRefType === FLAGS_OBJREF_HANDLER) {
      objRef = new OBJREF_HANDLER(data);
    } else if (objRefType === FLAGS_OBJREF_STANDARD) {
      objRef = new OBJREF_STANDARD(data);
    } else if (objRefType === FLAGS_OBJREF_EXTENDED) {
      objRef = new OBJREF_EXTENDED(data);
    } else {
      console.error(`Unknown OBJREF Type! 0x${objRefType.toString(16)}`);
    }

    if (objRef && objRefType !== FLAGS_OBJREF_CUSTOM) {
      const std = objRef.get('std') as STDOBJREF;
      if (((std.get('flags') as number) & SORF_NOPING) === 0) {
        DCOMConnection.addOid(this.__target, std.get('oid') as number);
      }
      this.__iPid = std.get('ipid') as Buffer;
      this.__oid = std.get('oid') as number;
      this.__oxid = std.get('oxid') as number;
      if (this.__oxid === null || this.__oxid === undefined) {
        throw new Error('OXID is None');
      }
    }
  }

  getOxid(): number | null {
    return this.__oxid;
  }

  setOxid(oxid: number): void {
    this.__oxid = oxid;
  }

  getOid(): number | null {
    return this.__oid;
  }

  setOid(oid: number): void {
    this.__oid = oid;
  }

  getTarget(): string {
    return this.__target;
  }

  getIPid(): Buffer | null {
    return this.__iPid;
  }

  setIPid(iPid: Buffer): void {
    this.__iPid = iPid;
  }

  getObjRef(): Buffer | null {
    return this.__objRef;
  }

  setObjRef(objRef: Buffer): void {
    this.__objRef = objRef;
  }

  getIpidRemUnknown(): Buffer | null {
    return this.__ipidRemUnknown;
  }

  getDceRpc(): DCERPC_v5 {
    return INTERFACE.CONNECTIONS[this.__target]![INTERFACE.CONNECTION_KEY]![this.__oxid!]!.dce;
  }

  getCinstance(): CLASS_INSTANCE | null {
    return this.__cinstance;
  }

  setCinstance(cinstance: CLASS_INSTANCE): void {
    this.__cinstance = cinstance;
  }

  isFqdn(): boolean {
    // If it's an IPv4 or IPv6 address, return false; otherwise it's a FQDN
    if (net.isIP(this.__target) !== 0) {
      return false;
    }
    if (this.__target.includes(':')) {
      return false;
    }
    return true;
  }

  async connect(iid?: Buffer | null): Promise<void> {
    const connKey = INTERFACE.CONNECTION_KEY;
    if (this.__target in INTERFACE.CONNECTIONS) {
      if (
        connKey in INTERFACE.CONNECTIONS[this.__target]! &&
        this.__oxid !== null &&
        this.__oxid in INTERFACE.CONNECTIONS[this.__target]![connKey]!
      ) {
        const dce = INTERFACE.CONNECTIONS[this.__target]![connKey]![this.__oxid]!.dce;
        const currentBinding = INTERFACE.CONNECTIONS[this.__target]![connKey]![this.__oxid]!.currentBinding;
        if (iid && currentBinding && currentBinding.equals(iid)) {
          // reuse existing binding
        } else if (iid) {
          const newDce = await dce.alterCtx(iid);
          INTERFACE.CONNECTIONS[this.__target]![connKey]![this.__oxid]!.dce = newDce;
          INTERFACE.CONNECTIONS[this.__target]![connKey]![this.__oxid]!.currentBinding = iid;
        }
      } else {
        const stringBindings = this.getCinstance()!.getStringBindings();
        // No OXID present, we should create a new connection and store it
        let stringBinding: string | null = null;
        const isTargetFQDN = this.isFqdn();

        for (const strBinding of stringBindings) {
          if ((strBinding.get('wTowerId') as number) === 7) {
            const networkAddr = strBinding.get('aNetworkAddr') as string;
            let binding: string;
            let bindingPort = '';
            if (networkAddr.includes('[')) {
              const idx = networkAddr.indexOf('[');
              binding = networkAddr.substring(0, idx);
              bindingPort = networkAddr.substring(idx);
            } else {
              binding = networkAddr;
              bindingPort = '';
            }

            if (binding.toUpperCase().includes(this.getTarget().toUpperCase())) {
              stringBinding = 'ncacn_ip_tcp:' + networkAddr.replace(/\0$/, '');
              break;
            } else if (isTargetFQDN && binding.toUpperCase().includes(this.getTarget().toUpperCase().split('.')[0]!)) {
              stringBinding = `ncacn_ip_tcp:${this.getTarget()}${bindingPort}`;
              break;
            }
          }
        }

        if (stringBinding === null) {
          // Fallback: use the target directly with the DCOM port from any binding
          let dcomPort = '';
          for (const strBinding of stringBindings) {
            if ((strBinding.get('wTowerId') as number) === 7) {
              const networkAddr = strBinding.get('aNetworkAddr') as string;
              if (networkAddr.includes('[')) {
                dcomPort = networkAddr.substring(networkAddr.indexOf('['));
                break;
              }
            }
          }
          stringBinding = `ncacn_ip_tcp:${this.getTarget()}${dcomPort}`;
        }

        const dcomInterface = DCERPCTransportFactory(stringBinding);

        if ('setCredentials' in dcomInterface && this.__target in DCOMConnection.PORTMAPS) {
          const portmap = DCOMConnection.PORTMAPS[this.__target]!;
          if ('getCredentials' in portmap) {
            const creds = (portmap as unknown as { getCredentials(): unknown[] }).getCredentials();
            (dcomInterface as unknown as Record<string, Function>)['setCredentials']!(...creds);
          }
        }

        if ('setConnectTimeout' in dcomInterface) {
          (dcomInterface as unknown as Record<string, Function>)['setConnectTimeout']!(300);
        }

        const dce = (dcomInterface as unknown as Record<string, Function>)['getDceRpc']!() as DCERPC_v5;

        if (!iid) {
          throw new Error('IID is None');
        }

        dce.setAuthLevel(this.__cinstance!.getAuthLevel());
        dce.setAuthType(this.__cinstance!.getAuthType());
        await dce.connect();
        await dce.bind(iid);

        if (this.__oxid === null) {
          throw new Error('OXID NONE, something wrong!!!');
        }

        if (!(connKey in INTERFACE.CONNECTIONS[this.__target]!)) {
          INTERFACE.CONNECTIONS[this.__target]![connKey] = {};
        }
        INTERFACE.CONNECTIONS[this.__target]![connKey]![this.__oxid] = {
          dce,
          currentBinding: iid,
        };
      }
    } else {
      throw new Error('No connection created');
    }
  }

  async request(req: NDRCALL, iid?: Buffer | null, uuid?: Buffer | null): Promise<NDRCALL> {
    req.set('ORPCthis', this.getCinstance()!.getORPCthis());
    const orpcThisField = req.fields['ORPCthis'] as ORPCTHIS;
    orpcThisField.set('flags', 0);
    orpcThisField.set('extensions', NULL);
    await this.connect(iid);
    const dce = this.getDceRpc();
    try {
      const resp = await (dce as unknown as { request: DceRequestFn }).request<NDRCALL>(req, uuid ?? undefined);
      return resp;
    } catch (e) {
      if (String(e).includes('RPC_E_DISCONNECTED')) {
        let msg = String(e) + '\n';
        msg += "DCOM keep-alive pinging it might not be working as expected. You can't be idle for more than 14 minutes!\n";
        msg += 'You should exit the app and start again\n';
        throw new DCERPCException(msg);
      }
      throw e;
    }
  }

  disconnect(): void {
    const connKey = INTERFACE.CONNECTION_KEY;
    if (
      this.__target in INTERFACE.CONNECTIONS &&
      connKey in INTERFACE.CONNECTIONS[this.__target]! &&
      this.__oxid !== null &&
      this.__oxid in INTERFACE.CONNECTIONS[this.__target]![connKey]!
    ) {
      INTERFACE.CONNECTIONS[this.__target]![connKey]![this.__oxid]!.dce.disconnect();
    }
  }
}

// 3.1.1.5.6.1 IRemUnknown Methods
export class IRemUnknown extends INTERFACE {
  protected _iid: Buffer;

  constructor(iface: INTERFACE) {
    super({ interfaceInstance: iface });
    this._iid = IID_IRemUnknown;
    this.setOxid(iface.getOxid()!);
  }

  async RemQueryInterface(cRefs: number, iids: Buffer[]): Promise<IRemUnknown2> {
    const request = new RemQueryInterface();
    request.set('ORPCthis', this.getCinstance()!.getORPCthis());
    const orpcThis = request.get('ORPCthis') as ORPCTHIS;
    orpcThis.set('flags', 0);
    request.set('ripid', this.getIPid());
    request.set('cRefs', cRefs);
    request.set('cIids', iids.length);
    for (const iid of iids) {
      const _iid = new (IID as typeof GUID)();
      _iid.set('Data', iid);
      (request.get('iids') as unknown[]).push(_iid);
    }
    const resp = await this.request(request, IID_IRemUnknown, this.getIpidRemUnknown());
    const ppQIResults = resp.get('ppQIResults') as REMQIRESULT;
    const std = ppQIResults.get('std') as STDOBJREF;
    return new IRemUnknown2(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: null,
        ipidRemUnknown: this.getIpidRemUnknown(),
        iPid: std.get('ipid') as Buffer,
        oxid: std.get('oxid') as number,
        oid: std.get('oid') as number,
        target: this.getTarget(),
      }),
    );
  }

  async RemAddRef(): Promise<NDRCALL> {
    const request = new RemAddRef();
    request.set('ORPCthis', this.getCinstance()!.getORPCthis());
    const orpcThis = request.get('ORPCthis') as ORPCTHIS;
    orpcThis.set('flags', 0);
    request.set('cInterfaceRefs', 1);
    const element = new REMINTERFACEREF();
    element.set('ipid', this.getIPid());
    element.set('cPublicRefs', 1);
    (request.get('InterfaceRefs') as unknown[]).push(element);
    return this.request(request, IID_IRemUnknown, this.getIpidRemUnknown());
  }

  async RemRelease(): Promise<NDRCALL> {
    const request = new RemRelease();
    request.set('ORPCthis', this.getCinstance()!.getORPCthis());
    const orpcThis = request.get('ORPCthis') as ORPCTHIS;
    orpcThis.set('flags', 0);
    request.set('cInterfaceRefs', 1);
    const element = new REMINTERFACEREF();
    element.set('ipid', this.getIPid());
    element.set('cPublicRefs', 1);
    (request.get('InterfaceRefs') as unknown[]).push(element);
    const resp = await this.request(request, IID_IRemUnknown, this.getIpidRemUnknown());
    DCOMConnection.delOid(this.getTarget(), this.getOid()!);
    return resp;
  }
}

// 3.1.1.5.7 IRemUnknown2 Interface
export class IRemUnknown2 extends IRemUnknown {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IRemUnknown2;
  }
}

// 3.1.2.5.1 IObjectExporter Methods
export class IObjectExporter {
  private __portmap: DCERPC_v5;

  constructor(dce: DCERPC_v5) {
    this.__portmap = dce;
  }

  async ResolveOxid(pOxid: number, arRequestedProtseqs: number[]): Promise<STRINGBINDING[]> {
    await this.__portmap.connect();
    await this.__portmap.bind(IID_IObjectExporter);
    const request = new ResolveOxid();
    request.set('pOxid', pOxid);
    request.set('cRequestedProtseqs', arRequestedProtseqs.length);
    for (const protSeq of arRequestedProtseqs) {
      (request.get('arRequestedProtseqs') as unknown[]).push(protSeq);
    }
    const resp = await (this.__portmap as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
    const bindings = resp.get('ppdsaOxidBindings') as DUALSTRINGARRAY;
    const aStringArray = bindings.get('aStringArray') as number[];
    const oxids = oxidsToBuffer(aStringArray);
    const secOffset = bindings.get('wSecurityOffset') as number;
    return parseStringBindings(oxids, secOffset);
  }

  async SimplePing(setId: number): Promise<NDRCALL> {
    await this.__portmap.connect();
    await this.__portmap.bind(IID_IObjectExporter);
    const request = new SimplePing();
    request.set('pSetId', setId);
    return (this.__portmap as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
  }

  async ComplexPing(setId = 0, sequenceNum = 0, addToSet: number[] = [], delFromSet: number[] = []): Promise<NDRCALL> {
    await this.__portmap.connect();
    await this.__portmap.bind(IID_IObjectExporter);
    const request = new ComplexPing();
    request.set('pSetId', setId);
    request.set('SequenceNum', setId);
    request.set('cAddToSet', addToSet.length);
    request.set('cDelFromSet', delFromSet.length);
    if (addToSet.length > 0) {
      for (const oid of addToSet) {
        const oidn = new (OID as typeof NDRSTRUCT)();
        oidn.set('Data', oid);
        (request.get('AddToSet') as unknown[]).push(oidn);
      }
    } else {
      request.set('AddToSet', NULL);
    }
    if (delFromSet.length > 0) {
      for (const oid of delFromSet) {
        const oidn = new (OID as typeof NDRSTRUCT)();
        oidn.set('Data', oid);
        (request.get('DelFromSet') as unknown[]).push(oidn);
      }
    } else {
      request.set('DelFromSet', NULL);
    }
    return (this.__portmap as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
  }

  async ServerAlive(): Promise<NDRCALL> {
    await this.__portmap.connect();
    await this.__portmap.bind(IID_IObjectExporter);
    const request = new ServerAlive();
    return (this.__portmap as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
  }

  async ResolveOxid2(pOxid: number, arRequestedProtseqs: number[]): Promise<STRINGBINDING[]> {
    await this.__portmap.connect();
    await this.__portmap.bind(IID_IObjectExporter);
    const request = new ResolveOxid2();
    request.set('pOxid', pOxid);
    request.set('cRequestedProtseqs', arRequestedProtseqs.length);
    for (const protSeq of arRequestedProtseqs) {
      (request.get('arRequestedProtseqs') as unknown[]).push(protSeq);
    }
    const resp = await (this.__portmap as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
    const bindings = resp.get('ppdsaOxidBindings') as DUALSTRINGARRAY;
    const aStringArray = bindings.get('aStringArray') as number[];
    const oxids = oxidsToBuffer(aStringArray);
    const secOffset = bindings.get('wSecurityOffset') as number;
    return parseStringBindings(oxids, secOffset);
  }

  async ServerAlive2(): Promise<STRINGBINDING[]> {
    await this.__portmap.connect();
    await this.__portmap.bind(IID_IObjectExporter);
    const request = new ServerAlive2();
    const resp = await (this.__portmap as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
    const bindings = resp.get('ppdsaOrBindings') as DUALSTRINGARRAY;
    const aStringArray = bindings.get('aStringArray') as number[];
    const oxids = oxidsToBuffer(aStringArray);
    const secOffset = bindings.get('wSecurityOffset') as number;
    return parseStringBindings(oxids, secOffset);
  }
}

// 3.1.2.5.2.1 IActivation Methods
export class IActivation {
  private __portmap: DCERPC_v5;

  constructor(dce: DCERPC_v5) {
    this.__portmap = dce;
  }

  async RemoteActivation(clsId: Buffer, iid: Buffer): Promise<IRemUnknown2> {
    await this.__portmap.bind(IID_IActivation);
    const orpcThis = new ORPCTHIS();
    orpcThis.set('cid', generate());
    orpcThis.set('extensions', NULL);
    orpcThis.set('flags', 1);

    const request = new RemoteActivation();
    request.set('Clsid', clsId);
    request.set('pwszObjectName', NULL);
    request.set('pObjectStorage', NULL);
    request.set('ClientImpLevel', 2);
    request.set('Mode', 0);
    request.set('Interfaces', 1);

    const _iid = new (IID as typeof GUID)();
    _iid.set('Data', iid);
    (request.get('pIIDs') as unknown[]).push(_iid);
    request.set('cRequestedProtseqs', 1);
    (request.get('aRequestedProtseqs') as unknown[]).push(7);

    const resp = await (this.__portmap as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
    const ipidRemUnknown = resp.get('pipidRemUnknown') as Buffer;

    const respBindings = resp.get('ppdsaOxidBindings') as DUALSTRINGARRAY;
    const aStringArray = respBindings.get('aStringArray') as number[];
    const oxids = oxidsToBuffer(aStringArray);
    const secOffset = respBindings.get('wSecurityOffset') as number;
    const stringBindings = parseStringBindings(oxids, secOffset);
    parseSecurityBindings(oxids.subarray(secOffset * 2));

    const classInstance = new CLASS_INSTANCE(orpcThis, stringBindings);
    const ppInterfaceData = resp.get('ppInterfaceData') as { get(k: string): unknown }[];
    const abData = ppInterfaceData[0]!.get('abData') as Buffer[];
    const transport = this.__portmap.getRpcTransport();
    const remoteName = transport ? (transport as any).getRemoteName() as string : '';
    return new IRemUnknown2(
      new INTERFACE({
        cinstance: classInstance,
        objRef: Buffer.concat(abData.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from([x as unknown as number])))),
        ipidRemUnknown,
        target: remoteName,
      }),
    );
  }
}

// 3.1.2.5.2.2 IRemoteSCMActivator Methods
export class IRemoteSCMActivator {
  private __portmap: DCERPC_v5;

  constructor(dce: DCERPC_v5) {
    this.__portmap = dce;
  }

  private buildActivationBlob(clsId: Buffer, iid: Buffer): { activationBLOB: ACTIVATION_BLOB; orpcThis: ORPCTHIS } {
    const orpcThis = new ORPCTHIS();
    orpcThis.set('cid', generate());
    orpcThis.set('extensions', NULL);
    orpcThis.set('flags', 1);

    const activationBLOB = new ACTIVATION_BLOB();
    const customHeader = activationBLOB.get('CustomHeader') as CustomHeader;
    customHeader.set('destCtx', 2);
    customHeader.set('pdwReserved', NULL);

    const clsid1 = new (CLSID as typeof GUID)();
    clsid1.set('Data', CLSID_InstantiationInfo);
    (customHeader.get('pclsid') as unknown[]).push(clsid1);

    const clsid2 = new (CLSID as typeof GUID)();
    clsid2.set('Data', CLSID_ActivationContextInfo);
    (customHeader.get('pclsid') as unknown[]).push(clsid2);

    const clsid3 = new (CLSID as typeof GUID)();
    clsid3.set('Data', CLSID_ServerLocationInfo);
    (customHeader.get('pclsid') as unknown[]).push(clsid3);

    const clsid4 = new (CLSID as typeof GUID)();
    clsid4.set('Data', CLSID_ScmRequestInfo);
    (customHeader.get('pclsid') as unknown[]).push(clsid4);

    const parts: Buffer[] = [];

    // InstantiationInfo
    const instantiationInfo = new InstantiationInfoData();
    instantiationInfo.set('classId', clsId);
    instantiationInfo.set('cIID', 1);
    const _iid = new (IID as typeof GUID)();
    _iid.set('Data', iid);
    (instantiationInfo.get('pIID') as unknown[]).push(_iid);

    const dword1 = new (DWORD as typeof NDRSTRUCT)();
    const marshaled1 = Buffer.concat([instantiationInfo.getData(), instantiationInfo.getDataReferents()]);
    const pad1 = (8 - (marshaled1.length % 8)) % 8;
    dword1.set('Data', marshaled1.length + pad1);
    (customHeader.get('pSizes') as unknown[]).push(dword1);
    instantiationInfo.set('thisSize', marshaled1.length + pad1);
    parts.push(marshaled1, Buffer.alloc(pad1, 0xfa));

    // ActivationContextInfoData
    const activationInfo = new ActivationContextInfoData();
    activationInfo.set('pIFDClientCtx', NULL);
    activationInfo.set('pIFDPrototypeCtx', NULL);
    const dword2 = new (DWORD as typeof NDRSTRUCT)();
    const marshaled2 = Buffer.concat([activationInfo.getData(), activationInfo.getDataReferents()]);
    const pad2 = (8 - (marshaled2.length % 8)) % 8;
    dword2.set('Data', marshaled2.length + pad2);
    (customHeader.get('pSizes') as unknown[]).push(dword2);
    parts.push(marshaled2, Buffer.alloc(pad2, 0xfa));

    // ServerLocation
    const locationInfo = new LocationInfoData();
    locationInfo.set('machineName', NULL);
    const dword3 = new (DWORD as typeof NDRSTRUCT)();
    dword3.set('Data', locationInfo.getData().length);
    (customHeader.get('pSizes') as unknown[]).push(dword3);
    parts.push(locationInfo.getData(), locationInfo.getDataReferents());

    // ScmRequestInfo
    const scmInfo = new ScmRequestInfoData();
    scmInfo.set('pdwReserved', NULL);
    const remoteRequest = scmInfo.get('remoteRequest') as customREMOTE_REQUEST_SCM_INFO;
    remoteRequest.set('cRequestedProtseqs', 1);
    (remoteRequest.get('pRequestedProtseqs') as unknown[]).push(7);
    const dword4 = new (DWORD as typeof NDRSTRUCT)();
    const marshaled4 = Buffer.concat([scmInfo.getData(), scmInfo.getDataReferents()]);
    const pad4 = (8 - (marshaled4.length % 8)) % 8;
    dword4.set('Data', marshaled4.length + pad4);
    (customHeader.get('pSizes') as unknown[]).push(dword4);
    parts.push(marshaled4, Buffer.alloc(pad4, 0xfa));

    activationBLOB.set('Property', Buffer.concat(parts));

    return { activationBLOB, orpcThis };
  }

  private parseActivationResponse(respData: Buffer[]): {
    stringBindings: STRINGBINDING[];
    ipidRemUnknown: Buffer;
    propsOut: PropsOutInfo;
    authnHint: number;
  } {
    const joinedData = Buffer.concat(
      respData.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from([x as unknown as number]))),
    );

    const objRefType = new OBJREF(joinedData).get('flags') as number;
    let objRef: OBJREF_CUSTOM | OBJREF_HANDLER | OBJREF_STANDARD | OBJREF_EXTENDED | null = null;
    if (objRefType === FLAGS_OBJREF_CUSTOM) {
      objRef = new OBJREF_CUSTOM(joinedData);
    } else if (objRefType === FLAGS_OBJREF_HANDLER) {
      objRef = new OBJREF_HANDLER(joinedData);
    } else if (objRefType === FLAGS_OBJREF_STANDARD) {
      objRef = new OBJREF_STANDARD(joinedData);
    } else if (objRefType === FLAGS_OBJREF_EXTENDED) {
      objRef = new OBJREF_EXTENDED(joinedData);
    } else {
      console.error(`Unknown OBJREF Type! 0x${objRefType.toString(16)}`);
    }

    const activationBlob = new ACTIVATION_BLOB(objRef!.get('pObjectData') as Buffer);
    const customHeaderResult = activationBlob.get('CustomHeader') as CustomHeader;
    const pSizes = customHeaderResult.get('pSizes') as { get(k: string): number }[];
    const property = activationBlob.get('Property') as Buffer;

    const size0 = pSizes[0]!.get('Data');
    const size1 = pSizes[1]!.get('Data');
    const propOutput = property.subarray(0, size0);
    const scmReply = property.subarray(size0, size0 + size1);

    const scmr = new ScmReplyInfoData();
    const size = scmr.fromString(scmReply);
    scmr.fromStringReferents(scmReply.subarray(size));

    const remoteReply = scmr.get('remoteReply') as customREMOTE_REPLY_SCM_INFO;
    const ipidRemUnknown = remoteReply.get('ipidRemUnknown') as Buffer;
    const replyBindings = remoteReply.get('pdsaOxidBindings') as DUALSTRINGARRAY;
    const aStringArray = replyBindings.get('aStringArray') as number[];
    const oxids = oxidsToBuffer(aStringArray);
    const secOffset = replyBindings.get('wSecurityOffset') as number;
    const stringBindings = parseStringBindings(oxids, secOffset);
    parseSecurityBindings(oxids.subarray(secOffset * 2));

    const propsOut = new PropsOutInfo();
    const propsSize = propsOut.fromString(propOutput);
    propsOut.fromStringReferents(propOutput.subarray(propsSize));

    const authnHint = remoteReply.get('authnHint') as number;
    return { stringBindings, ipidRemUnknown, propsOut, authnHint };
  }

  async RemoteGetClassObject(clsId: Buffer, iid: Buffer): Promise<IRemUnknown2> {
    await this.__portmap.bind(IID_IRemoteSCMActivator);
    const { activationBLOB, orpcThis } = this.buildActivationBlob(clsId, iid);

    const request = new RemoteGetClassObject();
    request.set('ORPCthis', orpcThis);

    const objrefcustom = new OBJREF_CUSTOM();
    objrefcustom.set('iid', IID_IActivationPropertiesIn.subarray(0, -4));
    objrefcustom.set('clsid', CLSID_ActivationPropertiesIn);
    objrefcustom.set('pObjectData', activationBLOB.getData());
    objrefcustom.set('ObjectReferenceSize', (objrefcustom.get('pObjectData') as Buffer).length + 8);

    const pActProperties = request.get('pActProperties') as MInterfacePointer;
    pActProperties.set('ulCntData', objrefcustom.getData().length);
    pActProperties.set('abData', [...objrefcustom.getData()]);

    const resp = await (this.__portmap as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
    const ppActProperties = resp.get('ppActProperties') as { get(k: string): unknown };
    const abData = ppActProperties.get('abData') as Buffer[];

    const { stringBindings, ipidRemUnknown, propsOut, authnHint } = this.parseActivationResponse(abData);

    const classInstance = new CLASS_INSTANCE(orpcThis, stringBindings);
    classInstance.setAuthLevel(authnHint);
    classInstance.setAuthType(this.__portmap.getAuthType());

    const ppIntfData = propsOut.get('ppIntfData') as { get(k: string): unknown }[];
    const intfAbData = ppIntfData[0]!.get('abData') as Buffer[];
    const transport = this.__portmap.getRpcTransport();
    const remoteName = transport ? (transport as any).getRemoteName() as string : '';
    return new IRemUnknown2(
      new INTERFACE({
        cinstance: classInstance,
        objRef: Buffer.concat(intfAbData.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from([x as unknown as number])))),
        ipidRemUnknown,
        target: remoteName,
      }),
    );
  }

  async RemoteCreateInstance(clsId: Buffer, iid: Buffer): Promise<IRemUnknown2> {
    await this.__portmap.bind(IID_IRemoteSCMActivator);
    const { activationBLOB, orpcThis } = this.buildActivationBlob(clsId, iid);

    const request = new RemoteCreateInstance();
    request.set('ORPCthis', orpcThis);
    request.set('pUnkOuter', NULL);

    const objrefcustom = new OBJREF_CUSTOM();
    objrefcustom.set('iid', IID_IActivationPropertiesIn.subarray(0, -4));
    objrefcustom.set('clsid', CLSID_ActivationPropertiesIn);
    objrefcustom.set('pObjectData', activationBLOB.getData());
    objrefcustom.set('ObjectReferenceSize', (objrefcustom.get('pObjectData') as Buffer).length + 8);

    const pActProperties = request.get('pActProperties') as MInterfacePointer;
    pActProperties.set('ulCntData', objrefcustom.getData().length);
    pActProperties.set('abData', [...objrefcustom.getData()]);

    const resp = await (this.__portmap as unknown as { request: DceRequestFn }).request<NDRCALL>(request);
    const ppActProperties = resp.get('ppActProperties') as { get(k: string): unknown };
    const abData = ppActProperties.get('abData') as Buffer[];

    const { stringBindings, ipidRemUnknown, propsOut, authnHint } = this.parseActivationResponse(abData);

    const classInstance = new CLASS_INSTANCE(orpcThis, stringBindings);
    classInstance.setAuthLevel(authnHint);
    classInstance.setAuthType(this.__portmap.getAuthType());

    const ppIntfData = propsOut.get('ppIntfData') as { get(k: string): unknown }[];
    const intfAbData = ppIntfData[0]!.get('abData') as Buffer[];
    const transport = this.__portmap.getRpcTransport();
    const remoteName = transport ? (transport as any).getRemoteName() as string : '';
    return new IRemUnknown2(
      new INTERFACE({
        cinstance: classInstance,
        objRef: Buffer.concat(intfAbData.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from([x as unknown as number])))),
        ipidRemUnknown,
        target: remoteName,
      }),
    );
  }
}
