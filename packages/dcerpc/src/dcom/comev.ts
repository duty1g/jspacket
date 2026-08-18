// Impacket - Collection of TypeScript classes for working with network protocols.
//
// Copyright Fortra, LLC and its affiliated companies
//
// All rights reserved.
//
// Description:
//   [MS-COMEV]: Component Object Model Plus (COM+) Event System Protocol.
//               This was used as a way to test the DCOM runtime. Further
//               testing is needed to verify it is working as expected
//
//   Port of impacket/dcerpc/v5/dcom/comev.py to TypeScript.

import { Buffer } from 'node:buffer';
import { stringToBin, uuidtupToBin } from '@impacket/uuid';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRENUM,
  NDRUniConformantVaryingArray,
  type NDRField,
} from '../ndr';
import {
  DCOMCALL,
  DCOMANSWER,
  IRemUnknown,
  IRemUnknown2,
  PMInterfacePointer,
  INTERFACE,
} from '../dcomrt';
import { INT, ULONG, LONG, BOOLEAN } from '../dtypes';
import { DCERPCException } from '../rpcrt';

// BSTR is module-private in oaut.ts, so we define a local placeholder.
// TODO: Consolidate with oaut.ts BSTR if it becomes exported.
class BSTR extends NDRSTRUCT {
  static structure: NDRField[] = [];
}

// Import VARIANT from oaut.ts (it is exported there)
import { VARIANT } from './oaut';

// ============================================================================
// DCERPCSessionError (module-private per collision rules)
// ============================================================================
class DCERPCSessionError extends DCERPCException {
  constructor(errorString?: string | null, errorCode?: number | null, packet?: unknown) {
    super(errorString, errorCode, packet);
  }

  toString(): string {
    const code = this.error_code ?? 0;
    return `COMEV SessionError: unknown error code: 0x${code.toString(16)}`;
  }
}

// ============================================================================
// CONSTANTS
// ============================================================================
// 1.9 Standards Assignments
export const CLSID_EventSystem = stringToBin('4E14FBA2-2E22-11D1-9964-00C04FBBB345');
export const CLSID_EventSystem2 = stringToBin('99CC098F-A48A-4e9c-8E58-965C0AFC19D5');
export const CLSID_EventClass = stringToBin('cdbec9c0-7a68-11d1-88f9-0080c7d771bf');
export const CLSID_EventSubscription = stringToBin('7542e960-79c7-11d1-88f9-0080c7d771bf');
export const GUID_DefaultAppPartition = stringToBin('41E90F3E-56C1-4633-81C3-6E8BAC8BDD70');
export const IID_IEventSystem = uuidtupToBin(['4E14FB9F-2E22-11D1-9964-00C04FBBB345', '0.0'])!;
export const IID_IEventSystem2 = uuidtupToBin(['99CC098F-A48A-4e9c-8E58-965C0AFC19D5', '0.0'])!;
export const IID_IEventSystemInitialize = uuidtupToBin(['a0e8f27a-888c-11d1-b763-00c04fb926af', '0.0'])!;
export const IID_IEventObjectCollection = uuidtupToBin(['f89ac270-d4eb-11d1-b682-00805fc79216', '0.0'])!;
export const IID_IEnumEventObject = uuidtupToBin(['F4A07D63-2E25-11D1-9964-00C04FBBB345', '0.0'])!;
export const IID_IEventSubscription = uuidtupToBin(['4A6B0E15-2E38-11D1-9965-00C04FBBB345', '0.0'])!;
export const IID_IEventSubscription2 = uuidtupToBin(['4A6B0E16-2E38-11D1-9965-00C04FBBB345', '0.0'])!;
export const IID_IEventSubscription3 = uuidtupToBin(['FBC1D17D-C498-43a0-81AF-423DDD530AF6', '0.0'])!;
export const IID_IEventClass = uuidtupToBin(['fb2b72a0-7a68-11d1-88f9-0080c7d771bf', '0.0'])!;
export const IID_IEventClass2 = uuidtupToBin(['fb2b72a1-7a68-11d1-88f9-0080c7d771bf', '0.0'])!;
export const IID_IEventClass3 = uuidtupToBin(['7FB7EA43-2D76-4ea8-8CD9-3DECC270295E', '0.0'])!;

const error_status_t = ULONG;

// 2.2.2.2 Property Value Types
// Module-private to avoid collision with oaut.ts VARENUM
class VARENUM extends NDRENUM {
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
  };
}

// ============================================================================
// STRUCTURES
// ============================================================================
// 2.2.44 TYPEATTR
// Module-private to avoid collision with oaut.ts TYPEATTR
class TYPEATTR extends NDRSTRUCT {
  static structure: NDRField[] = [];
}

// Module-private to avoid collision with vds.ts OBJECT_ARRAY
class OBJECT_ARRAY extends NDRUniConformantVaryingArray {
  static item = PMInterfacePointer;
}

// ============================================================================
// RPC CALLS
// ============================================================================

// 3.1.4.1 IEventSystem
// 3.1.4.1.1 Query (Opnum 7)
export class IEventSystem_Query extends DCOMCALL {
  static opnum = 7;
  static structure: NDRField[] = [
    ['progID', BSTR],
    ['queryCriteria', BSTR],
  ];
}

export class IEventSystem_QueryResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['errorIndex', INT],
    ['ppInterface', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.1.2 Store (Opnum 8)
export class IEventSystem_Store extends DCOMCALL {
  static opnum = 8;
  static structure: NDRField[] = [
    ['progID', BSTR],
    ['pInterface', PMInterfacePointer],
  ];
}

export class IEventSystem_StoreResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.1.3 Remove (Opnum 9)
export class IEventSystem_Remove extends DCOMCALL {
  static opnum = 9;
  static structure: NDRField[] = [
    ['progID', BSTR],
    ['queryCriteria', BSTR],
  ];
}

export class IEventSystem_RemoveResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['errorIndex', INT],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.1.4 get_EventObjectChangeEventClassID (Opnum 10)
export class IEventSystem_get_EventObjectChangeEventClassID extends DCOMCALL {
  static opnum = 10;
  static structure: NDRField[] = [];
}

export class IEventSystem_get_EventObjectChangeEventClassIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrEventClassID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.1.5 QueryS (Opnum 11)
export class IEventSystem_QueryS extends DCOMCALL {
  static opnum = 11;
  static structure: NDRField[] = [
    ['progID', BSTR],
    ['queryCriteria', BSTR],
  ];
}

export class IEventSystem_QuerySResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pInterface', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.1.6 RemoveS (Opnum 12)
export class IEventSystem_RemoveS extends DCOMCALL {
  static opnum = 12;
  static structure: NDRField[] = [
    ['progID', BSTR],
    ['queryCriteria', BSTR],
  ];
}

export class IEventSystem_RemoveSResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// ============================================================================
// 3.1.4.2 IEventClass
// 3.1.4.2.1 get_EventClassID (Opnum 7)
export class IEventClass_get_EventClassID extends DCOMCALL {
  static opnum = 7;
  static structure: NDRField[] = [];
}

export class IEventClass_get_EventClassIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrEventClassID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.2.2 put_EventClassID (Opnum 8)
export class IEventClass_put_EventClassID extends DCOMCALL {
  static opnum = 8;
  static structure: NDRField[] = [
    ['bstrEventClassID', BSTR],
  ];
}

export class IEventClass_put_EventClassIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.2.3 get_EventClassName (Opnum 9)
export class IEventClass_get_EventClassName extends DCOMCALL {
  static opnum = 9;
  static structure: NDRField[] = [];
}

export class IEventClass_get_EventClassNameResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrEventClassName', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.2.4 put_EventClassName (Opnum 10)
export class IEventClass_put_EventClassName extends DCOMCALL {
  static opnum = 10;
  static structure: NDRField[] = [
    ['bstrEventClassName', BSTR],
  ];
}

export class IEventClass_put_EventClassNameResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.2.5 get_OwnerSID (Opnum 11)
export class IEventClass_get_OwnerSID extends DCOMCALL {
  static opnum = 11;
  static structure: NDRField[] = [];
}

export class IEventClass_get_OwnerSIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrOwnerSID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.2.6 put_OwnerSID (Opnum 12)
export class IEventClass_put_OwnerSID extends DCOMCALL {
  static opnum = 12;
  static structure: NDRField[] = [
    ['bstrOwnerSID', BSTR],
  ];
}

export class IEventClass_put_OwnerSIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.2.7 get_FiringInterfaceID (Opnum 13)
export class IEventClass_get_FiringInterfaceID extends DCOMCALL {
  static opnum = 13;
  static structure: NDRField[] = [];
}

export class IEventClass_get_FiringInterfaceIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrFiringInterfaceID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.2.8 put_FiringInterfaceID (Opnum 14)
export class IEventClass_put_FiringInterfaceID extends DCOMCALL {
  static opnum = 14;
  static structure: NDRField[] = [
    ['bstrFiringInterfaceID', BSTR],
  ];
}

export class IEventClass_put_FiringInterfaceIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.2.9 get_Description (Opnum 15)
export class IEventClass_get_Description extends DCOMCALL {
  static opnum = 15;
  static structure: NDRField[] = [];
}

export class IEventClass_get_DescriptionResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrDescription', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.2.10 put_Description (Opnum 16)
export class IEventClass_put_Description extends DCOMCALL {
  static opnum = 16;
  static structure: NDRField[] = [
    ['bstrDescription', BSTR],
  ];
}

export class IEventClass_put_DescriptionResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.2.11 get_TypeLib (Opnum 19)
export class IEventClass_get_TypeLib extends DCOMCALL {
  static opnum = 19;
  static structure: NDRField[] = [];
}

export class IEventClass_get_TypeLibResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrTypeLib', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.2.12 put_TypeLib (Opnum 20)
export class IEventClass_put_TypeLib extends DCOMCALL {
  static opnum = 20;
  static structure: NDRField[] = [
    ['bstrTypeLib', BSTR],
  ];
}

export class IEventClass_put_TypeLibResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// ============================================================================
// 3.1.4.3 IEventClass2
// 3.1.4.3.1 get_PublisherID (Opnum 21)
export class IEventClass2_get_PublisherID extends DCOMCALL {
  static opnum = 21;
  static structure: NDRField[] = [];
}

export class IEventClass2_get_PublisherIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrSubscriptionID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.2 put_PublisherID (Opnum 22)
export class IEventClass2_put_PublisherID extends DCOMCALL {
  static opnum = 22;
  static structure: NDRField[] = [
    ['bstrPublisherID', BSTR],
  ];
}

export class IEventClass2_put_PublisherIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.3 get_MultiInterfacePublisherFilterCLSID (Opnum 23)
export class IEventClass2_get_MultiInterfacePublisherFilterCLSID extends DCOMCALL {
  static opnum = 23;
  static structure: NDRField[] = [];
}

export class IEventClass2_get_MultiInterfacePublisherFilterCLSIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrPubFilCLSID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.4 put_MultiInterfacePublisherFilterCLSID (Opnum 24)
export class IEventClass2_put_MultiInterfacePublisherFilterCLSID extends DCOMCALL {
  static opnum = 24;
  static structure: NDRField[] = [
    ['bstrPubFilCLSID', BSTR],
  ];
}

export class IEventClass2_put_MultiInterfacePublisherFilterCLSIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.5 get_AllowInprocActivation (Opnum 25)
export class IEventClass2_get_AllowInprocActivation extends DCOMCALL {
  static opnum = 25;
  static structure: NDRField[] = [];
}

export class IEventClass2_get_AllowInprocActivationResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pfAllowInprocActivation', BOOLEAN],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.6 put_AllowInprocActivation (Opnum 26)
export class IEventClass2_put_AllowInprocActivation extends DCOMCALL {
  static opnum = 26;
  static structure: NDRField[] = [
    ['fAllowInprocActivation', BOOLEAN],
  ];
}

export class IEventClass2_put_AllowInprocActivationResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.7 get_FireInParallel (Opnum 27)
export class IEventClass2_get_FireInParallel extends DCOMCALL {
  static opnum = 27;
  static structure: NDRField[] = [];
}

export class IEventClass2_get_FireInParallelResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pfFireInParallel', BOOLEAN],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.8 put_FireInParallel (Opnum 28)
export class IEventClass2_put_FireInParallel extends DCOMCALL {
  static opnum = 28;
  static structure: NDRField[] = [
    ['pfFireInParallel', BOOLEAN],
  ];
}

export class IEventClass2_put_FireInParallelResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// ============================================================================
// 3.1.4.4 IEventSubscription
// 3.1.4.4.1 get_SubscriptionID (Opnum 7)
export class IEventSubscription_get_SubscriptionID extends DCOMCALL {
  static opnum = 7;
  static structure: NDRField[] = [];
}

export class IEventSubscription_get_SubscriptionIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrSubscriptionID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.2 put_SubscriptionID (Opnum 8)
export class IEventSubscription_put_SubscriptionID extends DCOMCALL {
  static opnum = 8;
  static structure: NDRField[] = [
    ['bstrSubscriptionID', BSTR],
  ];
}

export class IEventSubscription_put_SubscriptionIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.3 get_SubscriptionName (Opnum 9)
export class IEventSubscription_get_SubscriptionName extends DCOMCALL {
  static opnum = 9;
  static structure: NDRField[] = [];
}

export class IEventSubscription_get_SubscriptionNameResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrSubscriptionName', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.4 put_SubscriptionName (Opnum 10)
export class IEventSubscription_put_SubscriptionName extends DCOMCALL {
  static opnum = 10;
  static structure: NDRField[] = [
    ['strSubscriptionID', BSTR],
  ];
}

export class IEventSubscription_put_SubscriptionNameResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.5 get_PublisherID (Opnum 11)
export class IEventSubscription_get_PublisherID extends DCOMCALL {
  static opnum = 11;
  static structure: NDRField[] = [];
}

export class IEventSubscription_get_PublisherIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrPublisherID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.6 put_PublisherID (Opnum 12)
export class IEventSubscription_put_PublisherID extends DCOMCALL {
  static opnum = 12;
  static structure: NDRField[] = [
    ['bstrPublisherID', BSTR],
  ];
}

export class IEventSubscription_put_PublisherIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.7 get_EventClassID (Opnum 13)
export class IEventSubscription_get_EventClassID extends DCOMCALL {
  static opnum = 13;
  static structure: NDRField[] = [];
}

export class IEventSubscription_get_EventClassIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrEventClassID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.8 put_EventClassID (Opnum 14)
export class IEventSubscription_put_EventClassID extends DCOMCALL {
  static opnum = 14;
  static structure: NDRField[] = [
    ['bstrEventClassID', BSTR],
  ];
}

export class IEventSubscription_put_EventClassIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.9 get_MethodName (Opnum 15)
export class IEventSubscription_get_MethodName extends DCOMCALL {
  static opnum = 15;
  static structure: NDRField[] = [];
}

export class IEventSubscription_get_MethodNameResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrMethodName', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.10 put_MethodName (Opnum 16)
export class IEventSubscription_put_MethodName extends DCOMCALL {
  static opnum = 16;
  static structure: NDRField[] = [
    ['bstrMethodName', BSTR],
  ];
}

export class IEventSubscription_put_MethodNameResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.11 get_SubscriberCLSID (Opnum 17)
export class IEventSubscription_get_SubscriberCLSID extends DCOMCALL {
  static opnum = 17;
  static structure: NDRField[] = [];
}

export class IEventSubscription_get_SubscriberCLSIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrSubscriberCLSID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.12 put_SubscriberCLSID (Opnum 18)
export class IEventSubscription_put_SubscriberCLSID extends DCOMCALL {
  static opnum = 18;
  static structure: NDRField[] = [
    ['bstrSubscriberCLSID', BSTR],
  ];
}

export class IEventSubscription_put_SubscriberCLSIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.13 get_SubscriberInterface (Opnum 19)
export class IEventSubscription_get_SubscriberInterface extends DCOMCALL {
  static opnum = 19;
  static structure: NDRField[] = [];
}

export class IEventSubscription_get_SubscriberInterfaceResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppSubscriberInterface', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.14 put_SubscriberInterface (Opnum 20)
export class IEventSubscription_put_SubscriberInterface extends DCOMCALL {
  static opnum = 20;
  static structure: NDRField[] = [
    ['pSubscriberInterface', PMInterfacePointer],
  ];
}

export class IEventSubscription_put_SubscriberInterfaceResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.15 get_PerUser (Opnum 21)
export class IEventSubscription_get_PerUser extends DCOMCALL {
  static opnum = 21;
  static structure: NDRField[] = [];
}

export class IEventSubscription_get_PerUserResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pfPerUser', BOOLEAN],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.16 put_PerUser (Opnum 22)
export class IEventSubscription_put_PerUser extends DCOMCALL {
  static opnum = 22;
  static structure: NDRField[] = [
    ['fPerUser', BOOLEAN],
  ];
}

export class IEventSubscription_put_PerUserResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.17 get_OwnerSID (Opnum 23)
export class IEventSubscription_get_OwnerSID extends DCOMCALL {
  static opnum = 23;
  static structure: NDRField[] = [];
}

export class IEventSubscription_get_OwnerSIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrOwnerSID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.18 put_OwnerSID (Opnum 24)
export class IEventSubscription_put_OwnerSID extends DCOMCALL {
  static opnum = 24;
  static structure: NDRField[] = [
    ['bstrOwnerSID', BSTR],
  ];
}

export class IEventSubscription_put_OwnerSIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.19 get_Enabled (Opnum 25)
export class IEventSubscription_get_Enabled extends DCOMCALL {
  static opnum = 25;
  static structure: NDRField[] = [];
}

export class IEventSubscription_get_EnabledResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pfEnabled', BOOLEAN],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.20 put_Enabled (Opnum 26)
export class IEventSubscription_put_Enabled extends DCOMCALL {
  static opnum = 26;
  static structure: NDRField[] = [
    ['fEnabled', BOOLEAN],
  ];
}

export class IEventSubscription_put_EnabledResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.21 get_Description (Opnum 27)
export class IEventSubscription_get_Description extends DCOMCALL {
  static opnum = 27;
  static structure: NDRField[] = [];
}

export class IEventSubscription_get_DescriptionResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrDescription', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.22 put_Description (Opnum 28)
export class IEventSubscription_put_Description extends DCOMCALL {
  static opnum = 28;
  static structure: NDRField[] = [
    ['bstrDescription', BSTR],
  ];
}

export class IEventSubscription_put_DescriptionResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.23 get_MachineName (Opnum 29)
export class IEventSubscription_get_MachineName extends DCOMCALL {
  static opnum = 29;
  static structure: NDRField[] = [];
}

export class IEventSubscription_get_MachineNameResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrMachineName', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.24 put_MachineName (Opnum 30)
export class IEventSubscription_put_MachineName extends DCOMCALL {
  static opnum = 30;
  static structure: NDRField[] = [
    ['bstrMachineName', BSTR],
  ];
}

export class IEventSubscription_put_MachineNameResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.25 GetPublisherProperty (Opnum 31)
export class IEventSubscription_GetPublisherProperty extends DCOMCALL {
  static opnum = 31;
  static structure: NDRField[] = [
    ['bstrPropertyName', BSTR],
  ];
}

export class IEventSubscription_GetPublisherPropertyResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['propertyValue', VARIANT],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.26 PutPublisherProperty (Opnum 32)
export class IEventSubscription_PutPublisherProperty extends DCOMCALL {
  static opnum = 32;
  static structure: NDRField[] = [
    ['bstrPropertyName', BSTR],
    ['propertyValue', VARIANT],
  ];
}

export class IEventSubscription_PutPublisherPropertyResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.27 RemovePublisherProperty (Opnum 33)
export class IEventSubscription_RemovePublisherProperty extends DCOMCALL {
  static opnum = 33;
  static structure: NDRField[] = [
    ['bstrPropertyName', BSTR],
  ];
}

export class IEventSubscription_RemovePublisherPropertyResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.28 GetPublisherPropertyCollection (Opnum 34)
export class IEventSubscription_GetPublisherPropertyCollection extends DCOMCALL {
  static opnum = 34;
  static structure: NDRField[] = [];
}

export class IEventSubscription_GetPublisherPropertyCollectionResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['collection', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.29 GetSubscriberProperty (Opnum 35)
export class IEventSubscription_GetSubscriberProperty extends DCOMCALL {
  static opnum = 35;
  static structure: NDRField[] = [
    ['bstrPropertyName', BSTR],
  ];
}

export class IEventSubscription_GetSubscriberPropertyResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['propertyValue', VARIANT],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.30 PutSubscriberProperty (Opnum 36)
export class IEventSubscription_PutSubscriberProperty extends DCOMCALL {
  static opnum = 36;
  static structure: NDRField[] = [
    ['bstrPropertyName', BSTR],
    ['propertyValue', VARIANT],
  ];
}

export class IEventSubscription_PutSubscriberPropertyResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.31 RemoveSubscriberProperty (Opnum 37)
export class IEventSubscription_RemoveSubscriberProperty extends DCOMCALL {
  static opnum = 37;
  static structure: NDRField[] = [
    ['bstrPropertyName', BSTR],
  ];
}

export class IEventSubscription_RemoveSubscriberPropertyResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.32 GetSubscriberPropertyCollection (Opnum 38)
export class IEventSubscription_GetSubscriberPropertyCollection extends DCOMCALL {
  static opnum = 38;
  static structure: NDRField[] = [];
}

export class IEventSubscription_GetSubscriberPropertyCollectionResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['collection', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.33 get_InterfaceID (Opnum 39)
export class IEventSubscription_get_InterfaceID extends DCOMCALL {
  static opnum = 39;
  static structure: NDRField[] = [];
}

export class IEventSubscription_get_InterfaceIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrInterfaceID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.34 put_InterfaceID (Opnum 40)
export class IEventSubscription_put_InterfaceID extends DCOMCALL {
  static opnum = 40;
  static structure: NDRField[] = [
    ['bstrInterfaceID', BSTR],
  ];
}

export class IEventSubscription_put_InterfaceIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// ============================================================================
// 3.1.4.5 IEnumEventObject
// 3.1.4.5.1 Clone (Opnum 3)
export class IEnumEventObject_Clone extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [];
}

export class IEnumEventObject_CloneResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppInterface', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.5.2 Next (Opnum 4)
export class IEnumEventObject_Next extends DCOMCALL {
  static opnum = 4;
  static structure: NDRField[] = [
    ['cReqElem', ULONG],
  ];
}

export class IEnumEventObject_NextResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppInterface', OBJECT_ARRAY],
    ['cRetElem', ULONG],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.5.3 Reset (Opnum 5)
export class IEnumEventObject_Reset extends DCOMCALL {
  static opnum = 5;
  static structure: NDRField[] = [];
}

export class IEnumEventObject_ResetResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.5.4 Skip (Opnum 6)
export class IEnumEventObject_Skip extends DCOMCALL {
  static opnum = 6;
  static structure: NDRField[] = [
    ['cSkipElem', ULONG],
  ];
}

export class IEnumEventObject_SkipResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// ============================================================================
// 3.1.4.6 IEventObjectCollection
// 3.1.4.6.1 get__NewEnum (Opnum 7)
export class IEventObjectCollection_get__NewEnum extends DCOMCALL {
  static opnum = 7;
  static structure: NDRField[] = [];
}

export class IEventObjectCollection_get__NewEnumResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppUnkEnum', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.6.2 get_Item (Opnum 8)
export class IEventObjectCollection_get_Item extends DCOMCALL {
  static opnum = 8;
  static structure: NDRField[] = [
    ['objectID', BSTR],
  ];
}

export class IEventObjectCollection_get_ItemResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pItem', VARIANT],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.6.3 get_NewEnum (Opnum 9)
export class IEventObjectCollection_get_NewEnum extends DCOMCALL {
  static opnum = 9;
  static structure: NDRField[] = [];
}

export class IEventObjectCollection_get_NewEnumResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppEnum', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.6.4 get_Count (Opnum 10)
export class IEventObjectCollection_get_Count extends DCOMCALL {
  static opnum = 10;
  static structure: NDRField[] = [];
}

export class IEventObjectCollection_get_CountResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pCount', LONG],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.6.5 Add (Opnum 11)
export class IEventObjectCollection_Add extends DCOMCALL {
  static opnum = 11;
  static structure: NDRField[] = [
    ['item', VARIANT],
    ['objectID', BSTR],
  ];
}

export class IEventObjectCollection_AddResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.6.6 Remove (Opnum 12)
export class IEventObjectCollection_Remove extends DCOMCALL {
  static opnum = 12;
  static structure: NDRField[] = [
    ['objectID', BSTR],
  ];
}

export class IEventObjectCollection_RemoveResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// ============================================================================
// 3.1.4.7 IEventClass3
// 3.1.4.7.1 get_EventClassPartitionID (Opnum 29)
export class IEventClass3_get_EventClassPartitionID extends DCOMCALL {
  static opnum = 29;
  static structure: NDRField[] = [];
}

export class IEventClass3_get_EventClassPartitionIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrEventClassPartitionID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.7.2 put_EventClassPartitionID (Opnum 30)
export class IEventClass3_put_EventClassPartitionID extends DCOMCALL {
  static opnum = 30;
  static structure: NDRField[] = [
    ['bstrEventClassPartitionID', BSTR],
  ];
}

export class IEventClass3_put_EventClassPartitionIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.7.3 get_EventClassApplicationID (Opnum 31)
export class IEventClass3_get_EventClassApplicationID extends DCOMCALL {
  static opnum = 31;
  static structure: NDRField[] = [];
}

export class IEventClass3_get_EventClassApplicationIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrEventClassApplicationID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.7.4 put_EventClassApplicationID (Opnum 32)
export class IEventClass3_put_EventClassApplicationID extends DCOMCALL {
  static opnum = 32;
  static structure: NDRField[] = [
    ['bstrEventClassApplicationID', BSTR],
  ];
}

export class IEventClass3_put_EventClassApplicationIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// ============================================================================
// 3.1.4.8 IEventSubscription2
// 3.1.4.8.1 get_FilterCriteria (Opnum 41)
export class IEventSubscription2_get_FilterCriteria extends DCOMCALL {
  static opnum = 41;
  static structure: NDRField[] = [];
}

export class IEventSubscription2_get_FilterCriteriaResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrFilterCriteria', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.8.2 put_FilterCriteria (Opnum 42)
export class IEventSubscription2_put_FilterCriteria extends DCOMCALL {
  static opnum = 42;
  static structure: NDRField[] = [
    ['bstrFilterCriteria', BSTR],
  ];
}

export class IEventSubscription2_put_FilterCriteriaResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.8.3 get_SubscriberMoniker (Opnum 43)
export class IEventSubscription2_get_SubscriberMoniker extends DCOMCALL {
  static opnum = 43;
  static structure: NDRField[] = [];
}

export class IEventSubscription2_get_SubscriberMonikerResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrMoniker', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.8.4 put_SubscriberMoniker (Opnum 44)
export class IEventSubscription2_put_SubscriberMoniker extends DCOMCALL {
  static opnum = 44;
  static structure: NDRField[] = [
    ['bstrMoniker', BSTR],
  ];
}

export class IEventSubscription2_put_SubscriberMonikerResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// ============================================================================
// 3.1.4.9 IEventSubscription3
// 3.1.4.9.1 get_EventClassPartitionID (Opnum 45)
export class IEventSubscription3_get_EventClassPartitionID extends DCOMCALL {
  static opnum = 45;
  static structure: NDRField[] = [];
}

export class IEventSubscription3_get_EventClassPartitionIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrEventClassPartitionID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.9.2 put_EventClassPartitionID (Opnum 46)
export class IEventSubscription3_put_EventClassPartitionID extends DCOMCALL {
  static opnum = 46;
  static structure: NDRField[] = [
    ['bstrEventClassPartitionID', BSTR],
  ];
}

export class IEventSubscription3_put_EventClassPartitionIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.9.3 get_EventClassApplicationID (Opnum 47)
export class IEventSubscription3_get_EventClassApplicationID extends DCOMCALL {
  static opnum = 47;
  static structure: NDRField[] = [];
}

export class IEventSubscription3_get_EventClassApplicationIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrEventClassApplicationID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.9.4 put_EventClassApplicationID (Opnum 48)
export class IEventSubscription3_put_EventClassApplicationID extends DCOMCALL {
  static opnum = 48;
  static structure: NDRField[] = [
    ['bstrEventClassPartitionID', BSTR],
  ];
}

export class IEventSubscription3_put_EventClassApplicationIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.9.5 get_SubscriberPartitionID (Opnum 49)
export class IEventSubscription3_get_SubscriberPartitionID extends DCOMCALL {
  static opnum = 49;
  static structure: NDRField[] = [];
}

export class IEventSubscription3_get_SubscriberPartitionIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrSubscriberPartitionID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.9.6 put_SubscriberPartitionID (Opnum 50)
export class IEventSubscription3_put_SubscriberPartitionID extends DCOMCALL {
  static opnum = 50;
  static structure: NDRField[] = [
    ['bstrSubscriberPartitionID', BSTR],
  ];
}

export class IEventSubscription3_put_SubscriberPartitionIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.9.7 get_SubscriberApplicationID (Opnum 51)
export class IEventSubscription3_get_SubscriberApplicationID extends DCOMCALL {
  static opnum = 51;
  static structure: NDRField[] = [];
}

export class IEventSubscription3_get_SubscriberApplicationIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pbstrSubscriberApplicationID', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.9.8 put_SubscriberApplicationID (Opnum 52)
export class IEventSubscription3_put_SubscriberApplicationID extends DCOMCALL {
  static opnum = 52;
  static structure: NDRField[] = [
    ['bstrSubscriberApplicationID', BSTR],
  ];
}

export class IEventSubscription3_put_SubscriberApplicationIDResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// ============================================================================
// 3.1.4.10 IEventSystem2
// 3.1.4.10.1 GetVersion (Opnum 13)
export class IEventSystem2_GetVersion extends DCOMCALL {
  static opnum = 13;
  static structure: NDRField[] = [];
}

export class IEventSystem2_GetVersionResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pnVersion', INT],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.10.2 VerifyTransientSubscribers (Opnum 14)
export class IEventSystem2_VerifyTransientSubscribers extends DCOMCALL {
  static opnum = 14;
  static structure: NDRField[] = [];
}

export class IEventSystem2_VerifyTransientSubscribersResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// ============================================================================
// 3.1.4.11 IEventSystemInitialize
// 3.1.4.11.1 SetCOMCatalogBehaviour (Opnum 3)
export class IEventSystemInitialize_SetCOMCatalogBehaviour extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['bRetainSubKeys', BOOLEAN],
  ];
}

export class IEventSystemInitialize_SetCOMCatalogBehaviourResponse extends DCOMANSWER {
  static structure: NDRField[] = [
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

// Helper to concatenate abData from an interface pointer response
function concatAbData(abData: unknown): Buffer {
  const arr = abData as Buffer[];
  return Buffer.concat(
    arr.map((x) =>
      Buffer.isBuffer(x) ? x : Buffer.from([x as unknown as number]),
    ),
  );
}

// NOTE: In the original Python, IEventClass extends IDispatch (from oaut.py).
// Since oaut.ts is not yet implemented, we extend IRemUnknown2 directly.
// TODO: Change to extend IDispatch when oaut.ts is available.
export class IEventClass extends IRemUnknown2 {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IEventClass;
  }

  async get_EventClassID(): Promise<NDRCALL> {
    const request = new IEventClass_get_EventClassID();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_EventClassID(bstrEventClassID: unknown): Promise<NDRCALL> {
    const request = new IEventClass_put_EventClassID();
    request.set('bstrEventClassID', bstrEventClassID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_EventClassName(): Promise<NDRCALL> {
    const request = new IEventClass_get_EventClassName();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_EventClassName(bstrEventClassName: unknown): Promise<NDRCALL> {
    const request = new IEventClass_put_EventClassName();
    request.set('bstrEventClassName', bstrEventClassName);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_OwnerSID(): Promise<NDRCALL> {
    const request = new IEventClass_get_OwnerSID();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_OwnerSID(bstrOwnerSID: unknown): Promise<NDRCALL> {
    const request = new IEventClass_put_OwnerSID();
    request.set('bstrOwnerSID', bstrOwnerSID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_FiringInterfaceID(): Promise<NDRCALL> {
    const request = new IEventClass_get_FiringInterfaceID();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_FiringInterfaceID(bstrFiringInterfaceID: unknown): Promise<NDRCALL> {
    const request = new IEventClass_put_FiringInterfaceID();
    request.set('bstrFiringInterfaceID', bstrFiringInterfaceID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_Description(): Promise<NDRCALL> {
    const request = new IEventClass_get_Description();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_Description(bstrDescription: unknown): Promise<NDRCALL> {
    const request = new IEventClass_put_Description();
    request.set('bstrDescription', bstrDescription);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_TypeLib(): Promise<NDRCALL> {
    const request = new IEventClass_get_TypeLib();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_TypeLib(bstrTypeLib: unknown): Promise<NDRCALL> {
    const request = new IEventClass_put_TypeLib();
    request.set('bstrTypeLib', bstrTypeLib);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }
}

export class IEventClass2 extends IEventClass {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IEventClass2;
  }

  async get_PublisherID(): Promise<NDRCALL> {
    const request = new IEventClass2_get_PublisherID();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_PublisherID(bstrPublisherID: unknown): Promise<NDRCALL> {
    const request = new IEventClass2_put_PublisherID();
    request.set('bstrPublisherID', bstrPublisherID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_MultiInterfacePublisherFilterCLSID(): Promise<NDRCALL> {
    const request = new IEventClass2_get_MultiInterfacePublisherFilterCLSID();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_MultiInterfacePublisherFilterCLSID(bstrPubFilCLSID: unknown): Promise<NDRCALL> {
    const request = new IEventClass2_put_MultiInterfacePublisherFilterCLSID();
    request.set('bstrPubFilCLSID', bstrPubFilCLSID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_AllowInprocActivation(): Promise<NDRCALL> {
    const request = new IEventClass2_get_AllowInprocActivation();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_AllowInprocActivation(fAllowInprocActivation: unknown): Promise<NDRCALL> {
    const request = new IEventClass2_put_AllowInprocActivation();
    request.set('fAllowInprocActivation', fAllowInprocActivation);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_FireInParallel(): Promise<NDRCALL> {
    const request = new IEventClass2_get_FireInParallel();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_FireInParallel(fFireInParallel: unknown): Promise<NDRCALL> {
    const request = new IEventClass2_put_FireInParallel();
    request.set('pfFireInParallel', fFireInParallel);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }
}

export class IEventClass3 extends IEventClass2 {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IEventClass3;
  }

  async get_EventClassPartitionID(): Promise<NDRCALL> {
    const request = new IEventClass3_get_EventClassPartitionID();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_EventClassPartitionID(bstrEventClassPartitionID: unknown): Promise<NDRCALL> {
    const request = new IEventClass3_put_EventClassPartitionID();
    request.set('bstrEventClassPartitionID', bstrEventClassPartitionID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_EventClassApplicationID(): Promise<NDRCALL> {
    const request = new IEventClass3_get_EventClassApplicationID();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_EventClassApplicationID(bstrEventClassApplicationID: unknown): Promise<NDRCALL> {
    const request = new IEventClass3_put_EventClassApplicationID();
    request.set('bstrEventClassApplicationID', bstrEventClassApplicationID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }
}

// NOTE: In the original Python, IEventSubscription extends IDispatch.
// TODO: Change to extend IDispatch when oaut.ts is available.
export class IEventSubscription extends IRemUnknown2 {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IEventSubscription;
  }

  async get_SubscriptionID(): Promise<NDRCALL> {
    const request = new IEventSubscription_get_SubscriptionID();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_SubscriptionID(bstrSubscriptionID: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription_put_SubscriptionID();
    request.set('bstrSubscriptionID', bstrSubscriptionID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_SubscriptionName(): Promise<NDRCALL> {
    const request = new IEventSubscription_get_SubscriptionName();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_SubscriptionName(bstrSubscriptionName: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription_put_SubscriptionName();
    request.set('bstrSubscriptionName', bstrSubscriptionName);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_PublisherID(): Promise<NDRCALL> {
    const request = new IEventSubscription_get_PublisherID();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_PublisherID(bstrPublisherID: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription_put_PublisherID();
    request.set('bstrPublisherID', bstrPublisherID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_EventClassID(): Promise<NDRCALL> {
    const request = new IEventSubscription_get_EventClassID();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_EventClassID(pbstrEventClassID: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription_put_EventClassID();
    request.set('pbstrEventClassID', pbstrEventClassID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_MethodName(): Promise<NDRCALL> {
    const request = new IEventSubscription_get_MethodName();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_MethodName(bstrMethodName: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription_put_MethodName();
    request.set('bstrMethodName', bstrMethodName);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_SubscriberCLSID(): Promise<NDRCALL> {
    const request = new IEventSubscription_get_SubscriberCLSID();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_SubscriberCLSID(bstrSubscriberCLSID: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription_put_SubscriberCLSID();
    request.set('bstrSubscriberCLSID', bstrSubscriberCLSID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_SubscriberInterface(): Promise<NDRCALL> {
    const request = new IEventSubscription_get_SubscriberInterface();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_SubscriberInterface(pSubscriberInterface: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription_put_SubscriberInterface();
    request.set('pSubscriberInterface', pSubscriberInterface);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_PerUser(): Promise<NDRCALL> {
    const request = new IEventSubscription_get_PerUser();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_PerUser(fPerUser: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription_put_PerUser();
    request.set('fPerUser', fPerUser);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_OwnerSID(): Promise<NDRCALL> {
    const request = new IEventSubscription_get_OwnerSID();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_OwnerSID(bstrOwnerSID: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription_put_OwnerSID();
    request.set('bstrOwnerSID', bstrOwnerSID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_Enabled(): Promise<NDRCALL> {
    const request = new IEventSubscription_get_Enabled();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_Enabled(fEnabled: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription_put_Enabled();
    request.set('fEnabled', fEnabled);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_Description(): Promise<NDRCALL> {
    const request = new IEventSubscription_get_Description();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_Description(bstrDescription: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription_put_Description();
    request.set('bstrDescription', bstrDescription);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_MachineName(): Promise<NDRCALL> {
    const request = new IEventSubscription_get_MachineName();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_MachineName(bstrMachineName: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription_put_MachineName();
    request.set('bstrMachineName', bstrMachineName);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async GetPublisherProperty(): Promise<NDRCALL> {
    const request = new IEventSubscription_GetPublisherProperty();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async PutPublisherProperty(bstrPropertyName: unknown, propertyValue: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription_PutPublisherProperty();
    request.set('bstrPropertyName', bstrPropertyName);
    request.set('propertyValue', propertyValue);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async RemovePublisherProperty(bstrPropertyName: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription_RemovePublisherProperty();
    request.set('bstrPropertyName', bstrPropertyName);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async GetPublisherPropertyCollection(): Promise<NDRCALL> {
    const request = new IEventSubscription_GetPublisherPropertyCollection();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async GetSubscriberProperty(): Promise<NDRCALL> {
    const request = new IEventSubscription_GetSubscriberProperty();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async PutSubscriberProperty(bstrPropertyName: unknown, propertyValue: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription_PutSubscriberProperty();
    request.set('bstrPropertyName', bstrPropertyName);
    request.set('propertyValue', propertyValue);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async RemoveSubscriberProperty(bstrPropertyName: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription_RemoveSubscriberProperty();
    request.set('bstrPropertyName', bstrPropertyName);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async GetSubscriberPropertyCollection(): Promise<NDRCALL> {
    const request = new IEventSubscription_GetSubscriberPropertyCollection();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_InterfaceID(): Promise<NDRCALL> {
    const request = new IEventSubscription_get_InterfaceID();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_InterfaceID(bstrInterfaceID: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription_put_InterfaceID();
    request.set('bstrInterfaceID', bstrInterfaceID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }
}

export class IEventSubscription2 extends IEventSubscription {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IEventSubscription2;
  }

  async get_FilterCriteria(): Promise<NDRCALL> {
    const request = new IEventSubscription2_get_FilterCriteria();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_FilterCriteria(bstrFilterCriteria: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription2_put_FilterCriteria();
    request.set('bstrFilterCriteria', bstrFilterCriteria);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_SubscriberMoniker(): Promise<NDRCALL> {
    const request = new IEventSubscription2_get_SubscriberMoniker();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_SubscriberMoniker(bstrMoniker: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription2_put_SubscriberMoniker();
    request.set('bstrMoniker', bstrMoniker);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }
}

export class IEventSubscription3 extends IEventSubscription2 {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IEventSubscription3;
  }

  async get_EventClassPartitionID(): Promise<NDRCALL> {
    const request = new IEventSubscription3_get_EventClassPartitionID();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_EventClassPartitionID(bstrEventClassPartitionID: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription3_put_EventClassPartitionID();
    request.set('bstrEventClassPartitionID', bstrEventClassPartitionID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_EventClassApplicationID(): Promise<NDRCALL> {
    const request = new IEventSubscription3_get_EventClassApplicationID();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_EventClassApplicationID(bstrEventClassApplicationID: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription3_put_EventClassApplicationID();
    request.set('bstrEventClassApplicationID', bstrEventClassApplicationID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_SubscriberPartitionID(): Promise<NDRCALL> {
    const request = new IEventSubscription3_get_SubscriberPartitionID();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_SubscriberPartitionID(bstrSubscriberPartitionID: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription3_put_SubscriberPartitionID();
    request.set('bstrSubscriberPartitionID', bstrSubscriberPartitionID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_SubscriberApplicationID(): Promise<NDRCALL> {
    const request = new IEventSubscription3_get_SubscriberApplicationID();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async put_SubscriberApplicationID(bstrSubscriberApplicationID: unknown): Promise<NDRCALL> {
    const request = new IEventSubscription3_put_SubscriberApplicationID();
    request.set('bstrSubscriberApplicationID', bstrSubscriberApplicationID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }
}

// NOTE: In the original Python, IEnumEventObject extends IDispatch.
// TODO: Change to extend IDispatch when oaut.ts is available.
export class IEnumEventObject extends IRemUnknown2 {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IEnumEventObject;
  }

  async Clone(): Promise<IEnumEventObject> {
    const request = new IEnumEventObject_Clone();
    const resp = await this.request(request, this._iid, this.getIPid());
    const ppInterface = resp.get('ppInterface') as { get(k: string): unknown };
    const abData = ppInterface.get('abData') as Buffer[];
    return new IEnumEventObject(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: concatAbData(abData),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
    );
  }

  async Next(cReqElem: number): Promise<IEventClass2[]> {
    const request = new IEnumEventObject_Next();
    request.set('cReqElem', cReqElem);
    const resp = await this.request(request, this._iid, this.getIPid());
    const interfaces: IEventClass2[] = [];
    const ppInterface = resp.get('ppInterface') as Array<{ get(k: string): unknown }>;
    for (const iface of ppInterface) {
      const abData = iface.get('abData') as Buffer[];
      interfaces.push(
        new IEventClass2(
          new INTERFACE({
            cinstance: this.getCinstance(),
            objRef: concatAbData(abData),
            ipidRemUnknown: this.getIpidRemUnknown(),
            target: this.getTarget(),
          }),
        ),
      );
    }
    return interfaces;
  }

  async Reset(): Promise<NDRCALL> {
    const request = new IEnumEventObject_Reset();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async Skip(cSkipElem: number): Promise<NDRCALL> {
    const request = new IEnumEventObject_Skip();
    request.set('cSkipElem', cSkipElem);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }
}

// NOTE: In the original Python, IEventObjectCollection extends IDispatch.
// TODO: Change to extend IDispatch when oaut.ts is available.
export class IEventObjectCollection extends IRemUnknown2 {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IEventObjectCollection;
  }

  async get__NewEnum(): Promise<IEnumEventObject> {
    const request = new IEventObjectCollection_get__NewEnum();
    const resp = await this.request(request, this._iid, this.getIPid());
    // Note: original Python accesses resp['ppEnum'] but response struct field is 'ppUnkEnum'
    const ppEnum = resp.get('ppEnum') as { get(k: string): unknown };
    const abData = ppEnum.get('abData') as Buffer[];
    return new IEnumEventObject(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: concatAbData(abData),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
    );
  }

  async get_Item(objectID: string): Promise<NDRCALL> {
    const request = new IEventObjectCollection_get_Item();
    (request.get('objectID') as { set(k: string, v: unknown): void }).set('asData', objectID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async get_NewEnum(): Promise<IEnumEventObject> {
    const request = new IEventObjectCollection_get_NewEnum();
    const resp = await this.request(request, this._iid, this.getIPid());
    const ppEnum = resp.get('ppEnum') as { get(k: string): unknown };
    const abData = ppEnum.get('abData') as Buffer[];
    return new IEnumEventObject(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: concatAbData(abData),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
    );
  }

  async get_Count(): Promise<NDRCALL> {
    const request = new IEventObjectCollection_get_Count();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async Add(item: unknown, objectID: string): Promise<NDRCALL> {
    const request = new IEventObjectCollection_Add();
    request.set('item', item);
    (request.get('objectID') as { set(k: string, v: unknown): void }).set('asData', objectID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async Remove(objectID: string): Promise<NDRCALL> {
    const request = new IEventObjectCollection_Remove();
    (request.get('objectID') as { set(k: string, v: unknown): void }).set('asData', objectID);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }
}

// NOTE: In the original Python, IEventSystem extends IDispatch.
// TODO: Change to extend IDispatch when oaut.ts is available.
export class IEventSystem extends IRemUnknown2 {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IEventSystem;
  }

  async Query(progID: string, queryCriteria: string): Promise<IEventObjectCollection> {
    const request = new IEventSystem_Query();
    (request.get('progID') as { set(k: string, v: unknown): void }).set('asData', progID);
    (request.get('queryCriteria') as { set(k: string, v: unknown): void }).set('asData', queryCriteria);
    const resp = await this.request(request, this._iid, this.getIPid());
    const ppInterface = resp.get('ppInterface') as { get(k: string): unknown };
    const abData = ppInterface.get('abData') as Buffer[];
    const iInterface = new IRemUnknown2(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: concatAbData(abData),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
    );
    const qi = await iInterface.RemQueryInterface(1, [IID_IEventObjectCollection]);
    return new IEventObjectCollection(qi);
  }

  async Store(progID: string, pInterface: unknown): Promise<NDRCALL> {
    const request = new IEventSystem_Store();
    (request.get('progID') as { set(k: string, v: unknown): void }).set('asData', progID);
    request.set('pInterface', pInterface);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async Remove(progID: string, queryCriteria: unknown): Promise<NDRCALL> {
    const request = new IEventSystem_Remove();
    (request.get('progID') as { set(k: string, v: unknown): void }).set('asData', progID);
    request.set('queryCriteria', queryCriteria);
    const resp = await this.request(request, undefined, this.getIPid());
    return resp;
  }

  async get_EventObjectChangeEventClassID(): Promise<NDRCALL> {
    const request = new IEventSystem_get_EventObjectChangeEventClassID();
    const resp = await this.request(request, undefined, this.getIPid());
    return resp;
  }

  async QueryS(progID: string, queryCriteria: string): Promise<IEventObjectCollection> {
    const request = new IEventSystem_QueryS();
    (request.get('progID') as { set(k: string, v: unknown): void }).set('asData', progID);
    (request.get('queryCriteria') as { set(k: string, v: unknown): void }).set('asData', queryCriteria);
    const resp = await this.request(request, undefined, this.getIPid());
    const pInterface = resp.get('pInterface') as { get(k: string): unknown };
    const abData = pInterface.get('abData') as Buffer[];
    const iInterface = new IRemUnknown2(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: concatAbData(abData),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
    );
    const qi = await iInterface.RemQueryInterface(1, [IID_IEventObjectCollection]);
    return new IEventObjectCollection(qi);
  }

  async RemoveS(progID: string, queryCriteria: string): Promise<NDRCALL> {
    const request = new IEventSystem_RemoveS();
    (request.get('progID') as { set(k: string, v: unknown): void }).set('asData', progID);
    (request.get('queryCriteria') as { set(k: string, v: unknown): void }).set('asData', queryCriteria);
    const resp = await this.request(request, undefined, this.getIPid());
    return resp;
  }
}

export class IEventSystem2 extends IEventSystem {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IEventSystem2;
  }

  async GetVersion(): Promise<NDRCALL> {
    const request = new IEventSystem2_GetVersion();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }

  async VerifyTransientSubscribers(): Promise<NDRCALL> {
    // Note: original Python uses IEventSystem2_GetVersion() here (likely a bug)
    const request = new IEventSystem2_GetVersion();
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }
}

export class IEventSystemInitialize extends IRemUnknown {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IEventSystemInitialize;
  }

  async SetCOMCatalogBehaviour(bRetainSubKeys: unknown): Promise<NDRCALL> {
    // Note: original Python uses IEventSystem2_GetVersion() here (likely a bug)
    const request = new IEventSystem2_GetVersion();
    request.set('bRetainSubKeys', bRetainSubKeys);
    const resp = await this.request(request, this._iid, this.getIPid());
    return resp;
  }
}

// Suppress unused warnings for module-private items used only for side effects or as placeholders
void DCERPCSessionError;
void OPNUMS;
void VARENUM;
void TYPEATTR;
