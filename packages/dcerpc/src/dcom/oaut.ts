// Impacket - Collection of TypeScript classes for working with network protocols.
//
// Copyright Fortra, LLC and its affiliated companies
//
// All rights reserved.
//
// Description:
//   [MS-OAUT]: OLE Automation Protocol Implementation
//              This was used as a way to test the DCOM runtime. Further
//              testing is needed to verify it is working as expected
//
//   Port of impacket/dcerpc/v5/dcom/oaut.py to TypeScript.

import { Buffer } from 'node:buffer';
import { stringToBin } from '@impacket/uuid';
import {
  NDR,
  NDRSTRUCT,
  NDRPOINTER,
  NDRENUM,
  NDRUNION,
  NDRUSHORT,
  NDRUniConformantArray,
  NDRUniConformantVaryingArray,
  NULL,
  type NDRField,
  type NDRFieldType,
  NDRCALL,
} from '../ndr';
import {
  LPWSTR,
  ULONG,
  DWORD,
  SHORT,
  GUID,
  USHORT,
  LONG,
  WSTR,
  BYTE,
  LONGLONG,
  FLOAT,
  DOUBLE,
  HRESULT,
  PSHORT,
  PLONG,
  PLONGLONG,
  PFLOAT,
  PDOUBLE,
  PHRESULT,
  CHAR,
  ULONGLONG,
  INT,
  UINT,
  PCHAR,
  PUSHORT,
  PULONG,
  PULONGLONG,
  PINT,
  PUINT,
} from '../dtypes';
import { DCERPCException, type DCERPC_v5 } from '../rpcrt';
import {
  DCOMCALL,
  DCOMANSWER,
  IRemUnknown2,
  PMInterfacePointer,
  PPMInterfacePointer,
  INTERFACE,
  MInterfacePointer,
  MInterfacePointer_ARRAY,
} from '../dcomrt';

// ============================================================================
// DCERPCSessionError (module-private per collision rules)
// ============================================================================
class DCERPCSessionError extends DCERPCException {
  constructor(errorString?: string | null, errorCode?: number | null, packet?: unknown) {
    super(errorString, errorCode, packet);
  }

  toString(): string {
    const code = this.error_code ?? 0;
    return `OAUT SessionError: unknown error code: 0x${code.toString(16)}`;
  }
}

// ============================================================================
// CONSTANTS
// ============================================================================
// 1.9 Standards Assignments
export const IID_IDispatch = stringToBin('00020400-0000-0000-C000-000000000046');
export const IID_ITypeInfo = stringToBin('00020401-0000-0000-C000-000000000046');
export const IID_ITypeComp = stringToBin('00020403-0000-0000-C000-000000000046');
export const IID_NULL = stringToBin('00000000-0000-0000-0000-000000000000');

const error_status_t = ULONG;

export const LCID = DWORD;
const WORD = NDRUSHORT;

// 2.2.2 IID
const IID = GUID;

// 2.2.3 LPOLESTR
export const LPOLESTR = LPWSTR;
export const OLESTR = WSTR;

// 2.2.4 REFIID
export const REFIID = IID;

// 2.2.25 DATE
export const DATE = DOUBLE;

export class PDATE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DATE]];
}

// 2.2.27 VARIANT_BOOL
export const VARIANT_BOOL = USHORT;

export class PVARIANT_BOOL extends NDRPOINTER {
  static referent: NDRField[] = [['Data', VARIANT_BOOL]];
}

// 3.1.4.4 IDispatch::Invoke (Opnum 6)
// dwFlags
export const DISPATCH_METHOD = 0x00000001;
export const DISPATCH_PROPERTYGET = 0x00000002;
export const DISPATCH_PROPERTYPUT = 0x00000004;
export const DISPATCH_PROPERTYPUTREF = 0x00000008;
export const DISPATCH_zeroVarResult = 0x00020000;
export const DISPATCH_zeroExcepInfo = 0x00040000;
export const DISPATCH_zeroArgErr = 0x00080000;

// ============================================================================
// STRUCTURES
// ============================================================================

// 2.2.26 DECIMAL
export class DECIMAL extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['wReserved', WORD],
    ['scale', BYTE],
    ['sign', BYTE],
    ['Hi32', ULONG],
    ['Lo64', ULONGLONG],
  ];
}

export class PDECIMAL extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DECIMAL]];
}

// 2.2.7 VARIANT Type Constants
export class VARENUM extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'VT_EMPTY',
    1: 'VT_NULL',
    2: 'VT_I2',
    3: 'VT_I4',
    4: 'VT_R4',
    5: 'VT_R8',
    6: 'VT_CY',
    7: 'VT_DATE',
    8: 'VT_BSTR',
    9: 'VT_DISPATCH',
    0xa: 'VT_ERROR',
    0xb: 'VT_BOOL',
    0xc: 'VT_VARIANT',
    0xd: 'VT_UNKNOWN',
    0xe: 'VT_DECIMAL',
    0x10: 'VT_I1',
    0x11: 'VT_UI1',
    0x12: 'VT_UI2',
    0x13: 'VT_UI4',
    0x14: 'VT_I8',
    0x15: 'VT_UI8',
    0x16: 'VT_INT',
    0x17: 'VT_UINT',
    0x18: 'VT_VOID',
    0x19: 'VT_HRESULT',
    0x1a: 'VT_PTR',
    0x1b: 'VT_SAFEARRAY',
    0x1c: 'VT_CARRAY',
    0x1d: 'VT_USERDEFINED',
    0x1e: 'VT_LPSTR',
    0x1f: 'VT_LPWSTR',
    0x24: 'VT_RECORD',
    0x25: 'VT_INT_PTR',
    0x26: 'VT_UINT_PTR',
    0x2000: 'VT_ARRAY',
    0x4000: 'VT_BYREF',
    0x4024: 'VT_RECORD_OR_VT_BYREF',
    0x4011: 'VT_UI1_OR_VT_BYREF',
    0x4002: 'VT_I2_OR_VT_BYREF',
    0x4003: 'VT_I4_OR_VT_BYREF',
    0x4014: 'VT_I8_OR_VT_BYREF',
    0x4004: 'VT_R4_OR_VT_BYREF',
    0x4005: 'VT_R8_OR_VT_BYREF',
    0x400b: 'VT_BOOL_OR_VT_BYREF',
    0x400a: 'VT_ERROR_OR_VT_BYREF',
    0x4006: 'VT_CY_OR_VT_BYREF',
    0x4007: 'VT_DATE_OR_VT_BYREF',
    0x4008: 'VT_BSTR_OR_VT_BYREF',
    0x400d: 'VT_UNKNOWN_OR_VT_BYREF',
    0x4009: 'VT_DISPATCH_OR_VT_BYREF',
    0x6000: 'VT_ARRAY_OR_VT_BYREF',
    0x400c: 'VT_VARIANT_OR_VT_BYREF',
    0x4010: 'VT_I1_OR_VT_BYREF',
    0x4012: 'VT_UI2_OR_VT_BYREF',
    0x4013: 'VT_UI4_OR_VT_BYREF',
    0x4015: 'VT_UI8_OR_VT_BYREF',
    0x4016: 'VT_INT_OR_VT_BYREF',
    0x4017: 'VT_UINT_OR_VT_BYREF',
    0x400e: 'VT_DECIMAL_OR_VT_BYREF',
  };
  static enumValues: Record<string, number> = {
    VT_EMPTY: 0,
    VT_NULL: 1,
    VT_I2: 2,
    VT_I4: 3,
    VT_R4: 4,
    VT_R8: 5,
    VT_CY: 6,
    VT_DATE: 7,
    VT_BSTR: 8,
    VT_DISPATCH: 9,
    VT_ERROR: 0xa,
    VT_BOOL: 0xb,
    VT_VARIANT: 0xc,
    VT_UNKNOWN: 0xd,
    VT_DECIMAL: 0xe,
    VT_I1: 0x10,
    VT_UI1: 0x11,
    VT_UI2: 0x12,
    VT_UI4: 0x13,
    VT_I8: 0x14,
    VT_UI8: 0x15,
    VT_INT: 0x16,
    VT_UINT: 0x17,
    VT_VOID: 0x18,
    VT_HRESULT: 0x19,
    VT_PTR: 0x1a,
    VT_SAFEARRAY: 0x1b,
    VT_CARRAY: 0x1c,
    VT_USERDEFINED: 0x1d,
    VT_LPSTR: 0x1e,
    VT_LPWSTR: 0x1f,
    VT_RECORD: 0x24,
    VT_INT_PTR: 0x25,
    VT_UINT_PTR: 0x26,
    VT_ARRAY: 0x2000,
    VT_BYREF: 0x4000,
    VT_RECORD_OR_VT_BYREF: 0x4024,
    VT_UI1_OR_VT_BYREF: 0x4011,
    VT_I2_OR_VT_BYREF: 0x4002,
    VT_I4_OR_VT_BYREF: 0x4003,
    VT_I8_OR_VT_BYREF: 0x4014,
    VT_R4_OR_VT_BYREF: 0x4004,
    VT_R8_OR_VT_BYREF: 0x4005,
    VT_BOOL_OR_VT_BYREF: 0x400b,
    VT_ERROR_OR_VT_BYREF: 0x400a,
    VT_CY_OR_VT_BYREF: 0x4006,
    VT_DATE_OR_VT_BYREF: 0x4007,
    VT_BSTR_OR_VT_BYREF: 0x4008,
    VT_UNKNOWN_OR_VT_BYREF: 0x400d,
    VT_DISPATCH_OR_VT_BYREF: 0x4009,
    VT_ARRAY_OR_VT_BYREF: 0x6000,
    VT_VARIANT_OR_VT_BYREF: 0x400c,
    VT_I1_OR_VT_BYREF: 0x4010,
    VT_UI2_OR_VT_BYREF: 0x4012,
    VT_UI4_OR_VT_BYREF: 0x4013,
    VT_UI8_OR_VT_BYREF: 0x4015,
    VT_INT_OR_VT_BYREF: 0x4016,
    VT_UINT_OR_VT_BYREF: 0x4017,
    VT_DECIMAL_OR_VT_BYREF: 0x400e,
  };

  // Static numeric constants for use as union tags
  static VT_EMPTY = 0;
  static VT_NULL = 1;
  static VT_I2 = 2;
  static VT_I4 = 3;
  static VT_R4 = 4;
  static VT_R8 = 5;
  static VT_CY = 6;
  static VT_DATE = 7;
  static VT_BSTR = 8;
  static VT_DISPATCH = 9;
  static VT_ERROR = 0xa;
  static VT_BOOL = 0xb;
  static VT_VARIANT = 0xc;
  static VT_UNKNOWN = 0xd;
  static VT_DECIMAL = 0xe;
  static VT_I1 = 0x10;
  static VT_UI1 = 0x11;
  static VT_UI2 = 0x12;
  static VT_UI4 = 0x13;
  static VT_I8 = 0x14;
  static VT_UI8 = 0x15;
  static VT_INT = 0x16;
  static VT_UINT = 0x17;
  static VT_VOID = 0x18;
  static VT_HRESULT = 0x19;
  static VT_PTR = 0x1a;
  static VT_SAFEARRAY = 0x1b;
  static VT_CARRAY = 0x1c;
  static VT_USERDEFINED = 0x1d;
  static VT_LPSTR = 0x1e;
  static VT_LPWSTR = 0x1f;
  static VT_RECORD = 0x24;
  static VT_INT_PTR = 0x25;
  static VT_UINT_PTR = 0x26;
  static VT_ARRAY = 0x2000;
  static VT_BYREF = 0x4000;
  static VT_RECORD_OR_VT_BYREF = 0x4024;
  static VT_UI1_OR_VT_BYREF = 0x4011;
  static VT_I2_OR_VT_BYREF = 0x4002;
  static VT_I4_OR_VT_BYREF = 0x4003;
  static VT_I8_OR_VT_BYREF = 0x4014;
  static VT_R4_OR_VT_BYREF = 0x4004;
  static VT_R8_OR_VT_BYREF = 0x4005;
  static VT_BOOL_OR_VT_BYREF = 0x400b;
  static VT_ERROR_OR_VT_BYREF = 0x400a;
  static VT_CY_OR_VT_BYREF = 0x4006;
  static VT_DATE_OR_VT_BYREF = 0x4007;
  static VT_BSTR_OR_VT_BYREF = 0x4008;
  static VT_UNKNOWN_OR_VT_BYREF = 0x400d;
  static VT_DISPATCH_OR_VT_BYREF = 0x4009;
  static VT_ARRAY_OR_VT_BYREF = 0x6000;
  static VT_VARIANT_OR_VT_BYREF = 0x400c;
  static VT_I1_OR_VT_BYREF = 0x4010;
  static VT_UI2_OR_VT_BYREF = 0x4012;
  static VT_UI4_OR_VT_BYREF = 0x4013;
  static VT_UI8_OR_VT_BYREF = 0x4015;
  static VT_INT_OR_VT_BYREF = 0x4016;
  static VT_UINT_OR_VT_BYREF = 0x4017;
  static VT_DECIMAL_OR_VT_BYREF = 0x400e;
}

// 2.2.8 SAFEARRAY Feature Constants
export class SF_TYPE extends NDRENUM {
  // [v1_enum] type
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    [VARENUM.VT_ERROR]: 'SF_ERROR',
    [VARENUM.VT_I1]: 'SF_I1',
    [VARENUM.VT_I2]: 'SF_I2',
    [VARENUM.VT_I4]: 'SF_I4',
    [VARENUM.VT_I8]: 'SF_I8',
    [VARENUM.VT_BSTR]: 'SF_BSTR',
    [VARENUM.VT_UNKNOWN]: 'SF_UNKNOWN',
    [VARENUM.VT_DISPATCH]: 'SF_DISPATCH',
    [VARENUM.VT_VARIANT]: 'SF_VARIANT',
    [VARENUM.VT_RECORD]: 'SF_RECORD',
    [VARENUM.VT_UNKNOWN | 0x8000]: 'SF_HAVEIID',
  };
  static enumValues: Record<string, number> = {
    SF_ERROR: VARENUM.VT_ERROR,
    SF_I1: VARENUM.VT_I1,
    SF_I2: VARENUM.VT_I2,
    SF_I4: VARENUM.VT_I4,
    SF_I8: VARENUM.VT_I8,
    SF_BSTR: VARENUM.VT_BSTR,
    SF_UNKNOWN: VARENUM.VT_UNKNOWN,
    SF_DISPATCH: VARENUM.VT_DISPATCH,
    SF_VARIANT: VARENUM.VT_VARIANT,
    SF_RECORD: VARENUM.VT_RECORD,
    SF_HAVEIID: VARENUM.VT_UNKNOWN | 0x8000,
  };

  static SF_ERROR = VARENUM.VT_ERROR;
  static SF_I1 = VARENUM.VT_I1;
  static SF_I2 = VARENUM.VT_I2;
  static SF_I4 = VARENUM.VT_I4;
  static SF_I8 = VARENUM.VT_I8;
  static SF_BSTR = VARENUM.VT_BSTR;
  static SF_UNKNOWN = VARENUM.VT_UNKNOWN;
  static SF_DISPATCH = VARENUM.VT_DISPATCH;
  static SF_VARIANT = VARENUM.VT_VARIANT;
  static SF_RECORD = VARENUM.VT_RECORD;
  static SF_HAVEIID = VARENUM.VT_UNKNOWN | 0x8000;
}

// 2.2.10 CALLCONV Calling Convention Constants
export class CALLCONV extends NDRENUM {
  // [v1_enum] type
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    1: 'CC_CDECL',
    2: 'CC_PASCAL',
    4: 'CC_STDCALL',
  };
  static enumValues: Record<string, number> = {
    CC_CDECL: 1,
    CC_PASCAL: 2,
    CC_STDCALL: 4,
  };
}

// 2.2.12 FUNCKIND Function Access Constants
export class FUNCKIND extends NDRENUM {
  // [v1_enum] type
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    1: 'FUNC_PUREVIRTUAL',
    3: 'FUNC_STATIC',
    4: 'FUNC_DISPATCH',
  };
  static enumValues: Record<string, number> = {
    FUNC_PUREVIRTUAL: 1,
    FUNC_STATIC: 3,
    FUNC_DISPATCH: 4,
  };
}

// 2.2.14 INVOKEKIND Function Invocation Constants
export class INVOKEKIND extends NDRENUM {
  // [v1_enum] type
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    1: 'INVOKE_FUNC',
    2: 'INVOKE_PROPERTYGET',
    4: 'INVOKE_PROPERTYPUT',
    8: 'INVOKE_PROPERTYPUTREF',
  };
  static enumValues: Record<string, number> = {
    INVOKE_FUNC: 1,
    INVOKE_PROPERTYGET: 2,
    INVOKE_PROPERTYPUT: 4,
    INVOKE_PROPERTYPUTREF: 8,
  };
}

// 2.2.17 TYPEKIND Type Kind Constants
export class TYPEKIND extends NDRENUM {
  // [v1_enum] type
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    0: 'TKIND_ENUM',
    1: 'TKIND_RECORD',
    2: 'TKIND_MODULE',
    3: 'TKIND_INTERFACE',
    4: 'TKIND_DISPATCH',
    5: 'TKIND_COCLASS',
    6: 'TKIND_ALIAS',
    7: 'TKIND_UNION',
  };
  static enumValues: Record<string, number> = {
    TKIND_ENUM: 0,
    TKIND_RECORD: 1,
    TKIND_MODULE: 2,
    TKIND_INTERFACE: 3,
    TKIND_DISPATCH: 4,
    TKIND_COCLASS: 5,
    TKIND_ALIAS: 6,
    TKIND_UNION: 7,
  };
}

// 2.2.23 BSTR
// 2.2.23.1 FLAGGED_WORD_BLOB
class USHORT_ARRAY extends NDRUniConformantArray {
  static item = '<H' as unknown as typeof NDRSTRUCT;
}

export class FLAGGED_WORD_BLOB extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cBytes', ULONG],
    ['clSize', ULONG],
    ['asData', USHORT_ARRAY],
  ];
}

// 2.2.23.2 BSTR Type Definition (module-private per collision rules)
class BSTR extends NDRPOINTER {
  static referent: NDRField[] = [['Data', FLAGGED_WORD_BLOB]];
}

export class PBSTR extends NDRPOINTER {
  static referent: NDRField[] = [['Data', BSTR]];
}

// 2.2.24 CURRENCY
export class CURRENCY extends NDRSTRUCT {
  static structure: NDRField[] = [['int64', LONGLONG]];
}

export class PCURRENCY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', CURRENCY]];
}

// 2.2.28.2 BRECORD
// 2.2.28.2.1 _wireBRECORD
// BYTE_ARRAY (module-private per collision rules)
class BYTE_ARRAY extends NDRUniConformantArray {
  static item = 'c' as unknown as typeof NDRSTRUCT;
}

export class _wireBRECORD extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['fFlags', LONGLONG],
    ['clSize', LONGLONG],
    ['pRecInfo', MInterfacePointer],
    ['pRecord', BYTE_ARRAY],
  ];
}

export class BRECORD extends NDRPOINTER {
  static referent: NDRField[] = [['Data', _wireBRECORD]];
}

// 2.2.30 SAFEARRAY
// 2.2.30.1 SAFEARRAYBOUND
export class SAFEARRAYBOUND extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cElements', ULONG],
    ['lLbound', LONG],
  ];
}

export class PSAFEARRAYBOUND extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAFEARRAYBOUND]];
}

// 2.2.30.2 SAFEARR_BSTR
export class BSTR_ARRAY extends NDRUniConformantArray {
  static item = BSTR;
}

export class PBSTR_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', BSTR_ARRAY]];
}

export class SAFEARR_BSTR extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Size', ULONG],
    ['aBstr', PBSTR_ARRAY],
  ];
}

// 2.2.30.3 SAFEARR_UNKNOWN
export class SAFEARR_UNKNOWN extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Size', ULONG],
    ['apUnknown', MInterfacePointer_ARRAY],
  ];
}

// 2.2.30.4 SAFEARR_DISPATCH
export class SAFEARR_DISPATCH extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Size', ULONG],
    ['apDispatch', MInterfacePointer_ARRAY],
  ];
}

// 2.2.30.6 SAFEARR_BRECORD
export class BRECORD_ARRAY extends NDRUniConformantArray {
  static item = BRECORD;
}

export class SAFEARR_BRECORD extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Size', ULONG],
    ['aRecord', BRECORD_ARRAY],
  ];
}

// 2.2.30.7 SAFEARR_HAVEIID
export class SAFEARR_HAVEIID extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Size', ULONG],
    ['apUnknown', MInterfacePointer_ARRAY],
    ['iid', IID],
  ];
}

// 2.2.30.8 Scalar-Sized Arrays
// 2.2.30.8.1 BYTE_SIZEDARR
export class BYTE_SIZEDARR extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['clSize', ULONG],
    ['pData', BYTE_ARRAY],
  ];
}

// 2.2.30.8.2 WORD_SIZEDARR
class WORD_ARRAY extends NDRUniConformantArray {
  static item = '<H' as unknown as typeof NDRSTRUCT;
}

export class WORD_SIZEDARR extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['clSize', ULONG],
    ['pData', WORD_ARRAY],
  ];
}

// 2.2.30.8.3 DWORD_SIZEDARR
// DWORD_ARRAY (module-private per collision rules)
class DWORD_ARRAY extends NDRUniConformantArray {
  static item = '<L' as unknown as typeof NDRSTRUCT;
}

export class DWORD_SIZEDARR extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['clSize', ULONG],
    ['pData', DWORD_ARRAY],
  ];
}

// 2.2.30.8.4 HYPER_SIZEDARR
class HYPER_ARRAY extends NDRUniConformantArray {
  static item = '<Q' as unknown as typeof NDRSTRUCT;
}

export class HYPER_SIZEDARR extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['clSize', ULONG],
    ['pData', HYPER_ARRAY],
  ];
}

// 2.2.36 HREFTYPE
export const HREFTYPE = DWORD;

// 2.2.30.5 SAFEARR_VARIANT
// Forward-declared: VARIANT is defined below but referenced here.
// We use a class getter pattern to break the circular reference.
export class VARIANT_ARRAY extends NDRUniConformantArray {
  static get item(): typeof NDRSTRUCT {
    return VARIANT as unknown as typeof NDRSTRUCT;
  }
}

export class PVARIANT_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', VARIANT_ARRAY]];
}

export class PVARIANT extends NDRPOINTER {
  static get referent(): NDRField[] {
    return [['Data', VARIANT]];
  }
}

export class SAFEARR_VARIANT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Size', ULONG],
    ['aVariant', VARIANT_ARRAY],
  ];
}

// 2.2.30.9 SAFEARRAYUNION
export class SAFEARRAYUNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    [SF_TYPE.SF_BSTR]: ['BstrStr', SAFEARR_BSTR],
    [SF_TYPE.SF_UNKNOWN]: ['UnknownStr', SAFEARR_UNKNOWN],
    [SF_TYPE.SF_DISPATCH]: ['DispatchStr', SAFEARR_DISPATCH],
    [SF_TYPE.SF_VARIANT]: ['VariantStr', SAFEARR_VARIANT],
    [SF_TYPE.SF_RECORD]: ['RecordStr', SAFEARR_BRECORD],
    [SF_TYPE.SF_HAVEIID]: ['HaveIidStr', SAFEARR_HAVEIID],
    [SF_TYPE.SF_I1]: ['ByteStr', BYTE_SIZEDARR],
    [SF_TYPE.SF_I2]: ['WordStr', WORD_SIZEDARR],
    [SF_TYPE.SF_I4]: ['LongStr', DWORD_SIZEDARR],
    [SF_TYPE.SF_I8]: ['HyperStr', HYPER_SIZEDARR],
  };
}

// 2.2.30.10 SAFEARRAY
export class SAFEARRAYBOUND_ARRAY extends NDRUniConformantArray {
  static item = SAFEARRAYBOUND;
}

export class PSAFEARRAYBOUND_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAFEARRAYBOUND_ARRAY]];
}

export class SAFEARRAY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cDims', USHORT],
    ['fFeatures', USHORT],
    ['cbElements', ULONG],
    ['cLocks', ULONG],
    ['uArrayStructs', SAFEARRAYUNION],
    ['rgsabound', SAFEARRAYBOUND_ARRAY],
  ];
}

export class PSAFEARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SAFEARRAY]];
}

// 2.2.29 VARIANT
// 2.2.29.1 _wireVARIANT
export class EMPTY extends NDR {
  static align = 0;
  static structure: NDRField[] = [];
}

export class varUnion extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    [VARENUM.VT_I8]: ['llVal', LONGLONG],
    [VARENUM.VT_I4]: ['lVal', LONG],
    [VARENUM.VT_UI1]: ['bVal', BYTE],
    [VARENUM.VT_I2]: ['iVal', SHORT],
    [VARENUM.VT_R4]: ['fltVal', FLOAT],
    [VARENUM.VT_R8]: ['dblVal', DOUBLE],
    [VARENUM.VT_BOOL]: ['boolVal', VARIANT_BOOL],
    [VARENUM.VT_ERROR]: ['scode', HRESULT],
    [VARENUM.VT_CY]: ['cyVal', CURRENCY],
    [VARENUM.VT_DATE]: ['date', DATE],
    [VARENUM.VT_BSTR]: ['bstrVal', BSTR],
    [VARENUM.VT_UNKNOWN]: ['punkVal', PMInterfacePointer],
    [VARENUM.VT_DISPATCH]: ['pdispVal', PMInterfacePointer],
    [VARENUM.VT_ARRAY]: ['parray', SAFEARRAY],
    [VARENUM.VT_RECORD]: ['brecVal', BRECORD],
    [VARENUM.VT_RECORD_OR_VT_BYREF]: ['brecVal', BRECORD],
    [VARENUM.VT_UI1_OR_VT_BYREF]: ['pbVal', BYTE],
    [VARENUM.VT_I2_OR_VT_BYREF]: ['piVal', PSHORT],
    [VARENUM.VT_I4_OR_VT_BYREF]: ['plVal', PLONG],
    [VARENUM.VT_I8_OR_VT_BYREF]: ['pllVal', PLONGLONG],
    [VARENUM.VT_R4_OR_VT_BYREF]: ['pfltVal', PFLOAT],
    [VARENUM.VT_R8_OR_VT_BYREF]: ['pdblVal', PDOUBLE],
    [VARENUM.VT_BOOL_OR_VT_BYREF]: ['pboolVal', PVARIANT_BOOL],
    [VARENUM.VT_ERROR_OR_VT_BYREF]: ['pscode', PHRESULT],
    [VARENUM.VT_CY_OR_VT_BYREF]: ['pcyVal', PCURRENCY],
    [VARENUM.VT_DATE_OR_VT_BYREF]: ['pdate', PDATE],
    [VARENUM.VT_BSTR_OR_VT_BYREF]: ['pbstrVal', PBSTR],
    [VARENUM.VT_UNKNOWN_OR_VT_BYREF]: ['ppunkVal', PPMInterfacePointer],
    [VARENUM.VT_DISPATCH_OR_VT_BYREF]: ['ppdispVal', PPMInterfacePointer],
    [VARENUM.VT_ARRAY_OR_VT_BYREF]: ['pparray', PSAFEARRAY],
    [VARENUM.VT_VARIANT_OR_VT_BYREF]: ['pvarVal', PVARIANT],
    [VARENUM.VT_I1]: ['cVal', CHAR],
    [VARENUM.VT_UI2]: ['uiVal', USHORT],
    [VARENUM.VT_UI4]: ['ulVal', ULONG],
    [VARENUM.VT_UI8]: ['ullVal', ULONGLONG],
    [VARENUM.VT_INT]: ['intVal', INT],
    [VARENUM.VT_UINT]: ['uintVal', UINT],
    [VARENUM.VT_DECIMAL]: ['decVal', DECIMAL],
    [VARENUM.VT_I1_OR_VT_BYREF]: ['pcVal', PCHAR],
    [VARENUM.VT_UI2_OR_VT_BYREF]: ['puiVal', PUSHORT],
    [VARENUM.VT_UI4_OR_VT_BYREF]: ['pulVal', PULONG],
    [VARENUM.VT_UI8_OR_VT_BYREF]: ['pullVal', PULONGLONG],
    [VARENUM.VT_INT_OR_VT_BYREF]: ['pintVal', PINT],
    [VARENUM.VT_UINT_OR_VT_BYREF]: ['puintVal', PUINT],
    [VARENUM.VT_DECIMAL_OR_VT_BYREF]: ['pdecVal', PDECIMAL],
    [VARENUM.VT_EMPTY]: ['empty', EMPTY],
    [VARENUM.VT_NULL]: ['null', EMPTY],
  };
}

export class wireVARIANTStr extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['clSize', DWORD],
    ['rpcReserved', DWORD],
    ['vt', USHORT],
    ['wReserved1', USHORT],
    ['wReserved2', USHORT],
    ['wReserved3', USHORT],
    ['_varUnion', varUnion],
  ];

  getAlignment(): number {
    return 8;
  }
}

export class VARIANT extends NDRPOINTER {
  static referent: NDRField[] = [['Data', wireVARIANTStr]];
}

// 2.2.32 DISPID
export const DISPID = LONG;

// 2.2.33 DISPPARAMS
// DISPID_ARRAY (module-private per collision rules)
class DISPID_ARRAY extends NDRUniConformantArray {
  static item = '<L' as unknown as typeof NDRSTRUCT;
}

class PDISPID_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DISPID_ARRAY]];
}

export class DISPPARAMS extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['rgvarg', PVARIANT_ARRAY],
    ['rgdispidNamedArgs', PDISPID_ARRAY],
    ['cArgs', UINT],
    ['cNamedArgs', UINT],
  ];
}

// 2.2.34 EXCEPINFO
export class EXCEPINFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['wCode', WORD],
    ['wReserved', WORD],
    ['bstrSource', BSTR],
    ['bstrDescription', BSTR],
    ['bstrHelpFile', BSTR],
    ['dwHelpContext', DWORD],
    ['pvReserved', ULONG],
    ['pfnDeferredFillIn', ULONG],
    ['scode', HRESULT],
  ];
}

// 2.2.35 MEMBERID
export const MEMBERID = DISPID;

// 2.2.37 TYPEDESC - forward declarations for mutual recursion
export class PTYPEDESC extends NDRPOINTER {
  static get referent(): NDRField[] {
    return [['Data', TYPEDESC]];
  }
}

// 2.2.38 ARRAYDESC
export class ARRAYDESC extends NDRSTRUCT {
  static get structure(): NDRField[] {
    return [
      ['tdescElem', TYPEDESC],
      ['cDims', USHORT],
      ['rgbounds', SAFEARRAYBOUND_ARRAY],
    ];
  }
}

// 2.2.37 TYPEDESC
export class tdUnion extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', USHORT]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    [VARENUM.VT_PTR]: ['lptdesc', PTYPEDESC],
    [VARENUM.VT_SAFEARRAY]: ['lptdesc', PTYPEDESC],
    [VARENUM.VT_CARRAY]: ['lpadesc', ARRAYDESC],
    [VARENUM.VT_USERDEFINED]: ['hreftype', HREFTYPE],
    default: null,
  };
}

export class TYPEDESC extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['vtType', tdUnion],
    ['vt', VARENUM],
  ];

  getAlignment(): number {
    return 4;
  }
}

// 2.2.48 SCODE
export const SCODE = LONG;

export class SCODE_ARRAY extends NDRUniConformantArray {
  static item = SCODE;
}

export class PSCODE_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SCODE_ARRAY]];
}

// 2.2.39 PARAMDESCEX
export class PARAMDESCEX extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cBytes', ULONG],
    ['varDefaultValue', VARIANT],
  ];
}

export class PPARAMDESCEX extends NDRPOINTER {
  static referent: NDRField[] = [['Data', PARAMDESCEX]];
}

// 2.2.40 PARAMDESC
export class PARAMDESC extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['pparamdescex', PPARAMDESCEX],
    ['wParamFlags', USHORT],
  ];
}

// 2.2.41 ELEMDESC
export class ELEMDESC extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['tdesc', TYPEDESC],
    ['paramdesc', PARAMDESC],
  ];
}

export class ELEMDESC_ARRAY extends NDRUniConformantArray {
  static item = ELEMDESC;
}

export class PELEMDESC_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ELEMDESC_ARRAY]];
}

// 2.2.42 FUNCDESC
export class FUNCDESC extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['memid', MEMBERID],
    ['lReserved1', PSCODE_ARRAY],
    ['lprgelemdescParam', PELEMDESC_ARRAY],
    ['funckind', FUNCKIND],
    ['invkind', INVOKEKIND],
    ['callconv', CALLCONV],
    ['cParams', SHORT],
    ['cParamsOpt', SHORT],
    ['oVft', SHORT],
    ['cReserved2', SHORT],
    ['elemdescFunc', ELEMDESC],
    ['wFuncFlags', WORD],
  ];
}

export class LPFUNCDESC extends NDRPOINTER {
  static referent: NDRField[] = [['Data', FUNCDESC]];
}

// 2.2.44 TYPEATTR
export class TYPEATTR extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['guid', GUID],
    ['lcid', LCID],
    ['dwReserved1', DWORD],
    ['dwReserved2', DWORD],
    ['dwReserved3', DWORD],
    ['lpstrReserved4', LPOLESTR],
    ['cbSizeInstance', ULONG],
    ['typeKind', TYPEKIND],
    ['cFuncs', WORD],
    ['cVars', WORD],
    ['cImplTypes', WORD],
    ['cbSizeVft', WORD],
    ['cbAlignment', WORD],
    ['wTypeFlags', WORD],
    ['wMajorVerNum', WORD],
    ['wMinorVerNum', WORD],
    ['tdescAlias', TYPEDESC],
    ['dwReserved5', DWORD],
    ['dwReserved6', WORD],
  ];
}

export class PTYPEATTR extends NDRPOINTER {
  static referent: NDRField[] = [['Data', TYPEATTR]];
}

export class BSTR_ARRAY_CV extends NDRUniConformantVaryingArray {
  static item = BSTR;
}

class UINT_ARRAY extends NDRUniConformantArray {
  static item = '<L' as unknown as typeof NDRSTRUCT;
}

export class OLESTR_ARRAY extends NDRUniConformantArray {
  static item = LPOLESTR;
}

// ============================================================================
// RPC CALLS
// ============================================================================

// 3.1.4.1 IDispatch::GetTypeInfoCount (Opnum 3)
export class IDispatch_GetTypeInfoCount extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [['pwszMachineName', LPWSTR]];
}

export class IDispatch_GetTypeInfoCountResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pctinfo', ULONG],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.2 IDispatch::GetTypeInfo (Opnum 4)
export class IDispatch_GetTypeInfo extends DCOMCALL {
  static opnum = 4;
  static structure: NDRField[] = [
    ['iTInfo', ULONG],
    ['lcid', DWORD],
  ];
}

export class IDispatch_GetTypeInfoResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppTInfo', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3 IDispatch::GetIDsOfNames (Opnum 5)
export class IDispatch_GetIDsOfNames extends DCOMCALL {
  static opnum = 5;
  static structure: NDRField[] = [
    ['riid', REFIID],
    ['rgszNames', OLESTR_ARRAY],
    ['cNames', UINT],
    ['lcid', LCID],
  ];
}

export class IDispatch_GetIDsOfNamesResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['rgDispId', DISPID_ARRAY],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4 IDispatch::Invoke (Opnum 6)
export class IDispatch_Invoke extends DCOMCALL {
  static opnum = 6;
  static structure: NDRField[] = [
    ['dispIdMember', DISPID],
    ['riid', REFIID],
    ['lcid', LCID],
    ['dwFlags', DWORD],
    ['pDispParams', DISPPARAMS],
    ['cVarRef', UINT],
    ['rgVarRefIdx', UINT_ARRAY],
    ['rgVarRef', VARIANT_ARRAY],
  ];
}

export class IDispatch_InvokeResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pVarResult', VARIANT],
    ['pExcepInfo', EXCEPINFO],
    ['pArgErr', UINT],
    ['ErrorCode', error_status_t],
  ];
}

// 3.7.4.1 ITypeInfo::GetTypeAttr (Opnum 3)
export class ITypeInfo_GetTypeAttr extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [];
}

export class ITypeInfo_GetTypeAttrResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppTypeAttr', PTYPEATTR],
    ['pReserved', DWORD],
    ['ErrorCode', error_status_t],
  ];
}

// 3.7.4.2 ITypeInfo::GetTypeComp (Opnum 4)
export class ITypeInfo_GetTypeComp extends DCOMCALL {
  static opnum = 4;
  static structure: NDRField[] = [];
}

export class ITypeInfo_GetTypeCompResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppTComp', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.7.4.3 ITypeInfo::GetFuncDesc (Opnum 5)
export class ITypeInfo_GetFuncDesc extends DCOMCALL {
  static opnum = 5;
  static structure: NDRField[] = [['index', UINT]];
}

export class ITypeInfo_GetFuncDescResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppFuncDesc', LPFUNCDESC],
    ['pReserved', DWORD],
    ['ErrorCode', error_status_t],
  ];
}

// 3.7.4.5 ITypeInfo::GetNames (Opnum 7)
export class ITypeInfo_GetNames extends DCOMCALL {
  static opnum = 7;
  static structure: NDRField[] = [
    ['memid', MEMBERID],
    ['cMaxNames', UINT],
  ];
}

export class ITypeInfo_GetNamesResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['rgBstrNames', BSTR_ARRAY_CV],
    ['pcNames', UINT],
    ['ErrorCode', error_status_t],
  ];
}

// 3.7.4.8 ITypeInfo::GetDocumentation (Opnum 12)
export class ITypeInfo_GetDocumentation extends DCOMCALL {
  static opnum = 12;
  static structure: NDRField[] = [
    ['memid', MEMBERID],
    ['refPtrFlags', DWORD],
  ];
}

export class ITypeInfo_GetDocumentationResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pBstrName', BSTR],
    ['pBstrDocString', BSTR],
    ['pdwHelpContext', DWORD],
    ['ErrorCode', error_status_t],
  ];
}

// ============================================================================
// OPNUMs and their corresponding structures (module-private)
// ============================================================================
const OPNUMS: Record<number, unknown> = {};

// ============================================================================
// HELPER FUNCTIONS AND INTERFACES
// ============================================================================

// 4.8.5 Enumerating All Methods in an Interface
export async function enumerateMethods(
  iInterface: IDispatch,
): Promise<Record<string, Record<string, string>>> {
  const methods: Record<string, Record<string, string>> = {};
  const typeInfoCount = await iInterface.GetTypeInfoCount();
  if ((typeInfoCount.get('pctinfo') as number) === 0) {
    console.error('Automation Server does not support type information for this object');
    return {};
  }
  const iTypeInfo = await iInterface.GetTypeInfo();
  const iTypeAttr = await iTypeInfo.GetTypeAttr();
  const ppTypeAttr = iTypeAttr.get('ppTypeAttr') as NDRCALL;
  const cFuncs = ppTypeAttr.get('cFuncs') as number;
  for (let x = 0; x < cFuncs; x++) {
    const funcDesc = await iTypeInfo.GetFuncDesc(x);
    const ppFuncDesc = funcDesc.get('ppFuncDesc') as NDRCALL;
    const memid = ppFuncDesc.get('memid') as number;
    const names = await iTypeInfo.GetNames(memid, 255);
    const rgBstrNames = names.get('rgBstrNames') as unknown[];
    const pcNames = names.get('pcNames') as number;
    let name = '';
    if (pcNames > 0) {
      const firstBstr = rgBstrNames[0] as NDRCALL;
      name = firstBstr.get('asData') as string;
      methods[name] = {};
      for (let param = 1; param < pcNames; param++) {
        const paramBstr = rgBstrNames[param] as NDRCALL;
        methods[name]![paramBstr.get('asData') as string] = '';
      }
    }
    if (ppFuncDesc.get('elemdescFunc') !== NULL) {
      const elemdescFunc = ppFuncDesc.get('elemdescFunc') as NDRCALL;
      const tdesc = elemdescFunc.get('tdesc') as NDRCALL;
      methods[name]!['ret'] = String(tdesc.get('vt'));
    }
  }
  return methods;
}

function checkNullString(s: unknown): unknown {
  if (s === NULL) {
    return s;
  }
  const str = s as string;
  if (str.slice(-1) !== '\x00') {
    return str + '\x00';
  }
  return str;
}

export class ITypeComp extends IRemUnknown2 {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_ITypeComp;
  }
}

export class ITypeInfo extends IRemUnknown2 {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_ITypeInfo;
  }

  async GetTypeAttr(): Promise<NDRCALL> {
    const request = new ITypeInfo_GetTypeAttr();
    return this.request(request, this._iid, this.getIPid());
  }

  async GetTypeComp(): Promise<ITypeComp> {
    const request = new ITypeInfo_GetTypeComp();
    const resp = await this.request(request, this._iid, this.getIPid());
    const ppTComp = resp.get('ppTComp') as NDRCALL;
    const abData = ppTComp.get('abData') as Buffer[];
    return new ITypeComp(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: Buffer.concat(abData),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
    );
  }

  async GetFuncDesc(index: number): Promise<NDRCALL> {
    const request = new ITypeInfo_GetFuncDesc();
    request.set('index', index);
    return this.request(request, this._iid, this.getIPid());
  }

  async GetNames(memid: number, cMaxNames: number = 10): Promise<NDRCALL> {
    const request = new ITypeInfo_GetNames();
    request.set('memid', memid);
    request.set('cMaxNames', cMaxNames);
    return this.request(request, this._iid, this.getIPid());
  }

  async GetDocumentation(memid: number, refPtrFlags: number = 15): Promise<NDRCALL> {
    const request = new ITypeInfo_GetDocumentation();
    request.set('memid', memid);
    request.set('refPtrFlags', refPtrFlags);
    return this.request(request, this._iid, this.getIPid());
  }
}

export class IDispatch extends IRemUnknown2 {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IDispatch;
  }

  async GetTypeInfoCount(): Promise<NDRCALL> {
    const request = new IDispatch_GetTypeInfoCount();
    return this.request(request, this._iid, this.getIPid());
  }

  async GetTypeInfo(): Promise<ITypeInfo> {
    const request = new IDispatch_GetTypeInfo();
    request.set('iTInfo', 0);
    request.set('lcid', 0);
    const resp = await this.request(request, this._iid, this.getIPid());
    const ppTInfo = resp.get('ppTInfo') as NDRCALL;
    const abData = ppTInfo.get('abData') as Buffer[];
    return new ITypeInfo(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: Buffer.concat(abData),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
    );
  }

  async GetIDsOfNames(rgszNames: string[], lcid: number = 0): Promise<number[]> {
    const request = new IDispatch_GetIDsOfNames();
    request.set('riid', IID_NULL);
    const namesArr = request.get('rgszNames') as unknown[];
    for (const name of rgszNames) {
      const tmpName = new (LPOLESTR as unknown as new () => NDRCALL)();
      tmpName.set('Data', checkNullString(name));
      namesArr.push(tmpName);
    }
    request.set('cNames', rgszNames.length);
    request.set('lcid', lcid);
    const resp = await this.request(request, this._iid, this.getIPid());
    const rgDispId = resp.get('rgDispId') as number[];
    const IDs: number[] = [];
    for (const id of rgDispId) {
      IDs.push(id);
    }
    return IDs;
  }

  async Invoke(
    dispIdMember: number,
    lcid: number,
    dwFlags: number,
    pDispParams: DISPPARAMS,
    cVarRef: number,
    rgVarRefIdx: unknown,
    rgVarRef: unknown,
  ): Promise<NDRCALL> {
    const request = new IDispatch_Invoke();
    request.set('dispIdMember', dispIdMember);
    request.set('riid', IID_NULL);
    request.set('lcid', lcid);
    request.set('dwFlags', dwFlags);
    request.set('pDispParams', pDispParams);
    request.set('cVarRef', cVarRef);
    request.set('rgVarRefIdx', rgVarRefIdx);
    request.set('rgVarRef', rgVarRef);
    return this.request(request, this._iid, this.getIPid());
  }
}

// Link request classes to their response classes
(IDispatch_GetTypeInfoCount as any).Response = IDispatch_GetTypeInfoCountResponse;
(IDispatch_GetTypeInfo as any).Response = IDispatch_GetTypeInfoResponse;
(IDispatch_GetIDsOfNames as any).Response = IDispatch_GetIDsOfNamesResponse;
(IDispatch_Invoke as any).Response = IDispatch_InvokeResponse;
(ITypeInfo_GetTypeAttr as any).Response = ITypeInfo_GetTypeAttrResponse;
(ITypeInfo_GetTypeComp as any).Response = ITypeInfo_GetTypeCompResponse;
(ITypeInfo_GetFuncDesc as any).Response = ITypeInfo_GetFuncDescResponse;
(ITypeInfo_GetNames as any).Response = ITypeInfo_GetNamesResponse;
(ITypeInfo_GetDocumentation as any).Response = ITypeInfo_GetDocumentationResponse;
