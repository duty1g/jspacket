// Impacket - Collection of TypeScript classes for working with network protocols.
//
// Copyright Fortra, LLC and its affiliated companies
//
// All rights reserved.
//
// Description:
//   [MS-SCMP]: Shadow Copy Management Protocol Interface implementation
//              This was used as a way to test the DCOM runtime. Further
//              testing is needed to verify it is working as expected
//
//   Port of impacket/dcerpc/v5/dcom/scmp.py to TypeScript.

import { stringToBin } from '@impacket/uuid';
import {
  NDRSTRUCT,
  NDRENUM,
  NDRUNION,
  type NDRField,
  NDRCALL,
} from '../ndr';
import { LONG, LONGLONG, ULONG, WSTR } from '../dtypes';
import {
  DCOMCALL,
  DCOMANSWER,
  IRemUnknown2,
  PMInterfacePointer,
  INTERFACE,
} from '../dcomrt';
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
    return `SCMP SessionError: unknown error code: 0x${code.toString(16)}`;
  }
}

// ============================================================================
// CONSTANTS
// ============================================================================
// 1.9 Standards Assignments
export const CLSID_ShadowCopyProvider = stringToBin('0b5a2c52-3eb9-470a-96e2-6c6d4570e40f');
export const IID_IVssSnapshotMgmt = stringToBin('FA7DF749-66E7-4986-A27F-E2F04AE53772');
export const IID_IVssEnumObject = stringToBin('AE1C7110-2F60-11d3-8A39-00C04F72D8E3');
export const IID_IVssDifferentialSoftwareSnapshotMgmt = stringToBin('214A0F28-B737-4026-B847-4F9E37D79529');
export const IID_IVssEnumMgmtObject = stringToBin('01954E6B-9254-4e6e-808C-C9E05D007696');
export const IID_ShadowCopyProvider = stringToBin('B5946137-7B9F-4925-AF80-51ABD60B20D5');

// 2.2.1.1 VSS_ID
export class VSS_ID extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Data', '16s=""'],
  ];

  getAlignment(): number {
    return 2;
  }
}

// 2.2.1.2 VSS_PWSZ
export const VSS_PWSZ = WSTR;

// 2.2.1.3 VSS_TIMESTAMP
export const VSS_TIMESTAMP = LONGLONG;

const error_status_t = LONG;

// ============================================================================
// STRUCTURES
// ============================================================================

// 2.2.2.1 VSS_OBJECT_TYPE Enumeration
export class VSS_OBJECT_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'VSS_OBJECT_UNKNOWN',
    1: 'VSS_OBJECT_NONE',
    2: 'VSS_OBJECT_SNAPSHOT_SET',
    3: 'VSS_OBJECT_SNAPSHOT',
    4: 'VSS_OBJECT_PROVIDER',
    5: 'VSS_OBJECT_TYPE_COUNT',
  };
  static enumValues: Record<string, number> = {
    VSS_OBJECT_UNKNOWN: 0,
    VSS_OBJECT_NONE: 1,
    VSS_OBJECT_SNAPSHOT_SET: 2,
    VSS_OBJECT_SNAPSHOT: 3,
    VSS_OBJECT_PROVIDER: 4,
    VSS_OBJECT_TYPE_COUNT: 5,
  };
}

// 2.2.2.2 VSS_MGMT_OBJECT_TYPE Enumeration
export class VSS_MGMT_OBJECT_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'VSS_MGMT_OBJECT_UNKNOWN',
    1: 'VSS_MGMT_OBJECT_VOLUME',
    2: 'VSS_MGMT_OBJECT_DIFF_VOLUME',
    3: 'VSS_MGMT_OBJECT_DIFF_AREA',
  };
  static enumValues: Record<string, number> = {
    VSS_MGMT_OBJECT_UNKNOWN: 0,
    VSS_MGMT_OBJECT_VOLUME: 1,
    VSS_MGMT_OBJECT_DIFF_VOLUME: 2,
    VSS_MGMT_OBJECT_DIFF_AREA: 3,
  };
}

// 2.2.2.3 VSS_VOLUME_SNAPSHOT_ATTRIBUTES Enumeration
export class VSS_VOLUME_SNAPSHOT_ATTRIBUTES extends NDRENUM {
  static enumItems: Record<number, string> = {
    0x01: 'VSS_VOLSNAP_ATTR_PERSISTENT',
    0x02: 'VSS_VOLSNAP_ATTR_NO_AUTORECOVERY',
    0x04: 'VSS_VOLSNAP_ATTR_CLIENT_ACCESSIBLE',
    0x08: 'VSS_VOLSNAP_ATTR_NO_AUTO_RELEASE',
    0x10: 'VSS_VOLSNAP_ATTR_NO_WRITERS',
  };
  static enumValues: Record<string, number> = {
    VSS_VOLSNAP_ATTR_PERSISTENT: 0x01,
    VSS_VOLSNAP_ATTR_NO_AUTORECOVERY: 0x02,
    VSS_VOLSNAP_ATTR_CLIENT_ACCESSIBLE: 0x04,
    VSS_VOLSNAP_ATTR_NO_AUTO_RELEASE: 0x08,
    VSS_VOLSNAP_ATTR_NO_WRITERS: 0x10,
  };
}

// 2.2.2.4 VSS_SNAPSHOT_STATE Enumeration
export class VSS_SNAPSHOT_STATE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0x01: 'VSS_SS_UNKNOWN',
    0x0c: 'VSS_SS_CREATED',
  };
  static enumValues: Record<string, number> = {
    VSS_SS_UNKNOWN: 0x01,
    VSS_SS_CREATED: 0x0c,
  };
}

// 2.2.2.5 VSS_PROVIDER_TYPE Enumeration
export class VSS_PROVIDER_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'VSS_PROV_UNKNOWN',
  };
  static enumValues: Record<string, number> = {
    VSS_PROV_UNKNOWN: 0,
  };
}

// 2.2.3.7 VSS_VOLUME_PROP Structure
export class VSS_VOLUME_PROP extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['m_pwszVolumeName', VSS_PWSZ],
    ['m_pwszVolumeDisplayName', VSS_PWSZ],
  ];
}

// 2.2.3.5 VSS_MGMT_OBJECT_UNION Union
export class VSS_MGMT_OBJECT_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [
    ['tag', ULONG],
  ];
  static union: Record<number, NDRField> = {
    1: ['Vol', VSS_VOLUME_PROP],
    // VSS_MGMT_OBJECT_DIFF_VOLUME: ['DiffVol', VSS_DIFF_VOLUME_PROP],
    // VSS_MGMT_OBJECT_DIFF_AREA: ['DiffArea', VSS_DIFF_AREA_PROP],
  };
}

// 2.2.3.6 VSS_MGMT_OBJECT_PROP Structure
export class VSS_MGMT_OBJECT_PROP extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Type', VSS_MGMT_OBJECT_TYPE],
    ['Obj', VSS_MGMT_OBJECT_UNION],
  ];
}

// ============================================================================
// RPC CALLS
// ============================================================================

// 3.1.3 IVssEnumMgmtObject Details

// 3.1.3.1 Next (Opnum 3)
export class IVssEnumMgmtObject_Next extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['celt', ULONG],
  ];
}

export class IVssEnumMgmtObject_NextResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['rgelt', VSS_MGMT_OBJECT_PROP],
    ['pceltFetched', ULONG],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.2.1 Next (Opnum 3)
export class IVssEnumObject_Next extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['celt', ULONG],
  ];
}

export class IVssEnumObject_NextResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['rgelt', VSS_MGMT_OBJECT_PROP],
    ['pceltFetched', ULONG],
    ['ErrorCode', error_status_t],
  ];
}

export class GetProviderMgmtInterface extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['ProviderId', VSS_ID],
    ['InterfaceId', VSS_ID],
  ];
}

export class GetProviderMgmtInterfaceResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppItf', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

export class QueryVolumesSupportedForSnapshots extends DCOMCALL {
  static opnum = 4;
  static structure: NDRField[] = [
    ['ProviderId', VSS_ID],
    ['IContext', LONG],
  ];
}

export class QueryVolumesSupportedForSnapshotsResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppEnum', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

export class QuerySnapshotsByVolume extends DCOMCALL {
  static opnum = 5;
  static structure: NDRField[] = [
    ['pwszVolumeName', VSS_PWSZ],
    ['ProviderId', VSS_ID],
  ];
}

export class QuerySnapshotsByVolumeResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppEnum', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.5 QueryDiffAreasForVolume (Opnum 6)
export class QueryDiffAreasForVolume extends DCOMCALL {
  static opnum = 6;
  static structure: NDRField[] = [
    ['pwszVolumeName', VSS_PWSZ],
  ];
}

export class QueryDiffAreasForVolumeResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppEnum', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.6 QueryDiffAreasOnVolume (Opnum 7)
export class QueryDiffAreasOnVolume extends DCOMCALL {
  static opnum = 7;
  static structure: NDRField[] = [
    ['pwszVolumeName', VSS_PWSZ],
  ];
}

export class QueryDiffAreasOnVolumeResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppEnum', PMInterfacePointer],
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
export class IVssEnumMgmtObject extends IRemUnknown2 {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IVssEnumMgmtObject!;
  }

  async Next(celt: number): Promise<NDRCALL> {
    const request = new IVssEnumMgmtObject_Next();
    request.set('ORPCthis', this.getCinstance()!.getORPCthis());
    (request.get('ORPCthis') as { set(k: string, v: unknown): void }).set('flags', 0);
    request.set('celt', celt);
    return this.request(request, this._iid, this.getIPid());
  }
}

export class IVssEnumObject extends IRemUnknown2 {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IVssEnumObject!;
  }

  async Next(celt: number): Promise<NDRCALL> {
    const request = new IVssEnumObject_Next();
    request.set('ORPCthis', this.getCinstance()!.getORPCthis());
    (request.get('ORPCthis') as { set(k: string, v: unknown): void }).set('flags', 0);
    request.set('celt', celt);
    return this.request(request, this._iid, this.getIPid());
  }
}

export class IVssSnapshotMgmt extends IRemUnknown2 {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IVssSnapshotMgmt!;
  }

  async GetProviderMgmtInterface(
    providerId: Buffer = IID_ShadowCopyProvider!,
    interfaceId: Buffer = IID_IVssDifferentialSoftwareSnapshotMgmt!,
  ): Promise<IVssDifferentialSoftwareSnapshotMgmt> {
    const req = new GetProviderMgmtInterface();
    const classInstance = this.getCinstance()!;
    req.set('ORPCthis', classInstance.getORPCthis());
    (req.get('ORPCthis') as { set(k: string, v: unknown): void }).set('flags', 0);
    req.set('ProviderId', providerId);
    req.set('InterfaceId', interfaceId);
    const resp = await this.request(req, this._iid, this.getIPid());
    const ppItf = resp.get('ppItf') as { get(k: string): unknown };
    const abData = ppItf.get('abData') as Buffer[];
    return new IVssDifferentialSoftwareSnapshotMgmt(
      new INTERFACE({
        cinstance: classInstance,
        objRef: Buffer.concat(abData.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from([x as unknown as number])))),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
    );
  }

  async QueryVolumesSupportedForSnapshots(
    providerId: Buffer,
    iContext: number,
  ): Promise<IVssEnumMgmtObject> {
    const req = new QueryVolumesSupportedForSnapshots();
    const classInstance = this.getCinstance()!;
    req.set('ORPCthis', classInstance.getORPCthis());
    (req.get('ORPCthis') as { set(k: string, v: unknown): void }).set('flags', 0);
    req.set('ProviderId', providerId);
    req.set('IContext', iContext);
    const resp = await this.request(req, this._iid, this.getIPid());
    const ppEnum = resp.get('ppEnum') as { get(k: string): unknown };
    const abData = ppEnum.get('abData') as Buffer[];
    return new IVssEnumMgmtObject(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: Buffer.concat(abData.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from([x as unknown as number])))),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
    );
  }

  async QuerySnapshotsByVolume(
    volumeName: string,
    providerId: Buffer = IID_ShadowCopyProvider!,
  ): Promise<IVssEnumObject> {
    const req = new QuerySnapshotsByVolume();
    const classInstance = this.getCinstance()!;
    req.set('ORPCthis', classInstance.getORPCthis());
    (req.get('ORPCthis') as { set(k: string, v: unknown): void }).set('flags', 0);
    req.set('pwszVolumeName', volumeName);
    req.set('ProviderId', providerId);
    let resp: NDRCALL;
    try {
      resp = await this.request(req, this._iid, this.getIPid());
    } catch (e) {
      if (e instanceof DCERPCException) {
        console.error(String(e));
      }
      throw e;
    }
    const ppEnum = resp.get('ppEnum') as { get(k: string): unknown };
    const abData = ppEnum.get('abData') as Buffer[];
    return new IVssEnumObject(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: Buffer.concat(abData.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from([x as unknown as number])))),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
    );
  }
}

export class IVssDifferentialSoftwareSnapshotMgmt extends IRemUnknown2 {
  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IVssDifferentialSoftwareSnapshotMgmt!;
  }

  async QueryDiffAreasOnVolume(pwszVolumeName: string): Promise<IVssEnumMgmtObject> {
    const req = new QueryDiffAreasOnVolume();
    const classInstance = this.getCinstance()!;
    req.set('ORPCthis', classInstance.getORPCthis());
    (req.get('ORPCthis') as { set(k: string, v: unknown): void }).set('flags', 0);
    req.set('pwszVolumeName', pwszVolumeName);
    const resp = await this.request(req, this._iid, this.getIPid());
    const ppEnum = resp.get('ppEnum') as { get(k: string): unknown };
    const abData = ppEnum.get('abData') as Buffer[];
    return new IVssEnumMgmtObject(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: Buffer.concat(abData.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from([x as unknown as number])))),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
    );
  }

  async QueryDiffAreasForVolume(pwszVolumeName: string): Promise<IVssEnumMgmtObject> {
    const req = new QueryDiffAreasForVolume();
    const classInstance = this.getCinstance()!;
    req.set('ORPCthis', classInstance.getORPCthis());
    (req.get('ORPCthis') as { set(k: string, v: unknown): void }).set('flags', 0);
    req.set('pwszVolumeName', pwszVolumeName);
    const resp = await this.request(req, this._iid, this.getIPid());
    const ppEnum = resp.get('ppEnum') as { get(k: string): unknown };
    const abData = ppEnum.get('abData') as Buffer[];
    return new IVssEnumMgmtObject(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: Buffer.concat(abData.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from([x as unknown as number])))),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
    );
  }
}
