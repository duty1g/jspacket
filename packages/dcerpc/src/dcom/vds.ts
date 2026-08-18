// Impacket - Collection of TypeScript classes for working with network protocols.
//
// Copyright Fortra, LLC and its affiliated companies
//
// All rights reserved.
//
// Description:
//   [MS-VDS]: Virtual Disk Service (VDS) Protocol
//             This was used as a way to test the DCOM runtime. Further
//             testing is needed to verify it is working as expected
//
//   Port of impacket/dcerpc/v5/dcom/vds.py to TypeScript.

import { stringToBin } from '@impacket/uuid';
import {
  NDRSTRUCT,
  NDRUniConformantVaryingArray,
  NDRENUM,
  NDRCALL,
  type NDRField,
} from '../ndr';
import {
  DCOMCALL,
  DCOMANSWER,
  IRemUnknown2,
  PMInterfacePointer,
  INTERFACE,
} from '../dcomrt';
import { LPWSTR, ULONG, DWORD, SHORT, GUID } from '../dtypes';
import { DCERPCException } from '../rpcrt';

// ============================================================================
// DCERPCSessionError (module-private per collision rules)
// ============================================================================
class DCERPCSessionError extends DCERPCException {
  constructor(errorString?: string | null, errorCode?: number | null, packet?: unknown) {
    super(errorString, errorCode, packet);
  }

  toString(): string {
    const code = this.error_code ?? 0;
    return `VDS SessionError: unknown error code: 0x${code.toString(16)}`;
  }
}

// ============================================================================
// CONSTANTS
// ============================================================================
// 1.9 Standards Assignments
export const CLSID_VirtualDiskService = stringToBin('7D1933CB-86F6-4A98-8628-01BE94C9A575');
export const IID_IEnumVdsObject = stringToBin('118610B7-8D94-4030-B5B8-500889788E4E');
export const IID_IVdsAdviseSink = stringToBin('8326CD1D-CF59-4936-B786-5EFC08798E25');
export const IID_IVdsAsync = stringToBin('D5D23B6D-5A55-4492-9889-397A3C2D2DBC');
export const IID_IVdsServiceInitialization = stringToBin('4AFC3636-DB01-4052-80C3-03BBCB8D3C69');
export const IID_IVdsService = stringToBin('0818A8EF-9BA9-40D8-A6F9-E22833CC771E');
export const IID_IVdsSwProvider = stringToBin('9AA58360-CE33-4F92-B658-ED24B14425B8');
export const IID_IVdsProvider = stringToBin('10C5E575-7984-4E81-A56B-431F5F92AE42');

const error_status_t = ULONG;

// 2.2.1.1.3 VDS_OBJECT_ID
export const VDS_OBJECT_ID = GUID;

// ============================================================================
// STRUCTURES
// ============================================================================
// 2.2.2.1.3.1 VDS_SERVICE_PROP
export class VDS_SERVICE_PROP extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['pwszVersion', LPWSTR],
    ['ulFlags', ULONG],
  ];
}

export class OBJECT_ARRAY extends NDRUniConformantVaryingArray {
  static item = PMInterfacePointer;
}

// 2.2.2.7.1.1 VDS_PROVIDER_TYPE
export class VDS_PROVIDER_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'VDS_PT_UNKNOWN',
    1: 'VDS_PT_SOFTWARE',
    2: 'VDS_PT_HARDWARE',
    3: 'VDS_PT_VIRTUALDISK',
    4: 'VDS_PT_MAX',
  };
  static enumValues: Record<string, number> = {
    VDS_PT_UNKNOWN: 0,
    VDS_PT_SOFTWARE: 1,
    VDS_PT_HARDWARE: 2,
    VDS_PT_VIRTUALDISK: 3,
    VDS_PT_MAX: 4,
  };
}

// 2.2.2.7.2.1 VDS_PROVIDER_PROP
export class VDS_PROVIDER_PROP extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['id', VDS_OBJECT_ID],
    ['pwszName', LPWSTR],
    ['guidVersionId', GUID],
    ['pwszVersion', LPWSTR],
    ['type', VDS_PROVIDER_TYPE],
    ['ulFlags', ULONG],
    ['ulStripeSizeFlags', ULONG],
    ['sRebuildPriority', SHORT],
  ];
}

// ============================================================================
// RPC CALLS
// ============================================================================

// 3.4.5.2.5.1 IVdsServiceInitialization::Initialize (Opnum 3)
export class IVdsServiceInitialization_Initialize extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['pwszMachineName', LPWSTR],
  ];
}

export class IVdsServiceInitialization_InitializeResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.4.5.2.4.1 IVdsService::IsServiceReady (Opnum 3)
export class IVdsService_IsServiceReady extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [];
}

export class IVdsService_IsServiceReadyResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.4.5.2.4.2 IVdsService::WaitForServiceReady (Opnum 4)
export class IVdsService_WaitForServiceReady extends DCOMCALL {
  static opnum = 4;
  static structure: NDRField[] = [];
}

export class IVdsService_WaitForServiceReadyResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.4.5.2.4.3 IVdsService::GetProperties (Opnum 5)
export class IVdsService_GetProperties extends DCOMCALL {
  static opnum = 5;
  static structure: NDRField[] = [];
}

export class IVdsService_GetPropertiesResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pServiceProp', VDS_SERVICE_PROP],
    ['ErrorCode', error_status_t],
  ];
}

// 3.4.5.2.4.4 IVdsService::QueryProviders (Opnum 6)
export class IVdsService_QueryProviders extends DCOMCALL {
  static opnum = 6;
  static structure: NDRField[] = [
    ['masks', DWORD],
  ];
}

export class IVdsService_QueryProvidersResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppEnum', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.1.1 IEnumVdsObject Interface
// 3.4.5.2.1.1 IEnumVdsObject::Next (Opnum 3)
export class IEnumVdsObject_Next extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['celt', ULONG],
  ];
}

export class IEnumVdsObject_NextResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppObjectArray', OBJECT_ARRAY],
    ['pcFetched', ULONG],
    ['ErrorCode', error_status_t],
  ];
}

// 3.4.5.2.14.1 IVdsProvider::GetProperties (Opnum 3)
export class IVdsProvider_GetProperties extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [];
}

export class IVdsProvider_GetPropertiesResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pProviderProp', VDS_PROVIDER_PROP],
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
export class IEnumVdsObject extends IRemUnknown2 {
  async Next(celt = 0xffff): Promise<IRemUnknown2[]> {
    const request = new IEnumVdsObject_Next();
    request.set('ORPCthis', this.getCinstance()!.getORPCthis());
    (request.get('ORPCthis') as { set(k: string, v: unknown): void }).set('flags', 0);
    request.set('celt', celt);
    let resp: NDRCALL;
    try {
      resp = await this.request(request, undefined, this.getIPid());
    } catch (e: unknown) {
      resp = (e as { get_packet(): NDRCALL }).get_packet();
      // If it is S_FALSE(1) means less items were returned
      if ((resp.get('ErrorCode') as number) !== 1) {
        throw e;
      }
    }
    const interfaces: IRemUnknown2[] = [];
    const ppObjectArray = resp!.get('ppObjectArray') as Array<{ get(k: string): unknown }>;
    for (const iface of ppObjectArray) {
      const abData = iface.get('abData') as Buffer[];
      interfaces.push(
        new IRemUnknown2(
          new INTERFACE({
            cinstance: this.getCinstance(),
            objRef: Buffer.concat(abData.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from([x as unknown as number])))),
            ipidRemUnknown: this.getIpidRemUnknown(),
            target: this.getTarget(),
          }),
        ),
      );
    }
    return interfaces;
  }
}

export class IVdsProvider extends IRemUnknown2 {
  async GetProperties(): Promise<NDRCALL> {
    const request = new IVdsProvider_GetProperties();
    request.set('ORPCthis', this.getCinstance()!.getORPCthis());
    (request.get('ORPCthis') as { set(k: string, v: unknown): void }).set('flags', 0);
    return this.request(request, undefined, this.getIPid());
  }
}

export class IVdsServiceInitialization extends IRemUnknown2 {
  constructor(iface: INTERFACE) {
    super(iface);
  }

  async Initialize(): Promise<NDRCALL> {
    const request = new IVdsServiceInitialization_Initialize();
    request.set('ORPCthis', this.getCinstance()!.getORPCthis());
    (request.get('ORPCthis') as { set(k: string, v: unknown): void }).set('flags', 0);
    request.set('pwszMachineName', '\x00');
    return this.request(request, undefined, this.getIPid());
  }
}

export class IVdsService extends IRemUnknown2 {
  constructor(iface: INTERFACE) {
    super(iface);
  }

  async IsServiceReady(): Promise<NDRCALL> {
    const request = new IVdsService_IsServiceReady();
    request.set('ORPCthis', this.getCinstance()!.getORPCthis());
    (request.get('ORPCthis') as { set(k: string, v: unknown): void }).set('flags', 0);
    let resp: NDRCALL;
    try {
      resp = await this.request(request, undefined, this.getIPid());
    } catch (e: unknown) {
      resp = (e as { get_packet(): NDRCALL }).get_packet();
    }
    return resp!;
  }

  async WaitForServiceReady(): Promise<NDRCALL> {
    const request = new IVdsService_WaitForServiceReady();
    request.set('ORPCthis', this.getCinstance()!.getORPCthis());
    (request.get('ORPCthis') as { set(k: string, v: unknown): void }).set('flags', 0);
    return this.request(request, undefined, this.getIPid());
  }

  async GetProperties(): Promise<NDRCALL> {
    const request = new IVdsService_GetProperties();
    request.set('ORPCthis', this.getCinstance()!.getORPCthis());
    (request.get('ORPCthis') as { set(k: string, v: unknown): void }).set('flags', 0);
    return this.request(request, undefined, this.getIPid());
  }

  async QueryProviders(masks: number): Promise<IEnumVdsObject> {
    const request = new IVdsService_QueryProviders();
    request.set('ORPCthis', this.getCinstance()!.getORPCthis());
    (request.get('ORPCthis') as { set(k: string, v: unknown): void }).set('flags', 0);
    request.set('masks', masks);
    const resp = await this.request(request, undefined, this.getIPid());
    const ppEnum = resp.get('ppEnum') as { get(k: string): unknown };
    const abData = ppEnum.get('abData') as Buffer[];
    return new IEnumVdsObject(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: Buffer.concat(abData.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from([x as unknown as number])))),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
    );
  }
}
