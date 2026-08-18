import { Buffer } from 'node:buffer';
import { uuidtupToBin } from '@impacket/uuid';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRENUM,
  NDRPOINTER,
  NDRUniConformantArray,
  NULL,
  type NDRField,
} from './ndr';
import {
  ULONG,
  LONG,
  PRPC_SID,
  RPC_SID,
  RPC_UNICODE_STRING,
  LPWSTR,
  PRPC_UNICODE_STRING,
  NTSTATUS,
  ACCESS_MASK,
} from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';
import {
  LsarClose,
  LsarCloseResponse,
  LsarOpenPolicy2,
  LsarOpenPolicy2Response,
} from './lsad';

export const MSRPC_UUID_LSAT = uuidtupToBin(['12345778-1234-ABCD-EF00-0123456789AB', '0.0'])!;

export const POLICY_LOOKUP_NAMES = 0x00000800;

class LsaprSecurityDescriptor extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Length', ULONG],
    ['SecurityDescriptor', '0s=""'],
  ];
}

class PLsaprSecurityDescriptor extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LsaprSecurityDescriptor]];
}

class LsaprSecurityQos extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Length', ULONG],
    ['ImpersonationLevel', ULONG],
    ['ContextTrackingMode', ULONG],
    ['EffectiveOnly', ULONG],
  ];
}

class PLsaprSecurityQos extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LsaprSecurityQos]];
}

class LsaprObjectAttributes extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Length', ULONG],
    ['RootDirectory', LPWSTR],
    ['ObjectName', LPWSTR],
    ['Attributes', ULONG],
    ['SecurityDescriptor', PLsaprSecurityDescriptor],
    ['SecurityQualityOfService', PLsaprSecurityQos],
  ];
}

class SidNameUse extends NDRENUM {
  static enumItems = {
    1: 'SidTypeUser',
    2: 'SidTypeGroup',
    3: 'SidTypeDomain',
    4: 'SidTypeAlias',
    5: 'SidTypeWellKnownGroup',
    6: 'SidTypeDeletedAccount',
    7: 'SidTypeInvalid',
    8: 'SidTypeUnknown',
    9: 'SidTypeComputer',
  };
  static enumValues = {
    SidTypeUser: 1,
    SidTypeGroup: 2,
    SidTypeDomain: 3,
    SidTypeAlias: 4,
    SidTypeWellKnownGroup: 5,
    SidTypeDeletedAccount: 6,
    SidTypeInvalid: 7,
    SidTypeUnknown: 8,
    SidTypeComputer: 9,
  };
}

export class LsaprHandle extends NDRSTRUCT {
  static align = 1;
  static structure: NDRField[] = [['Data', '20s=""']];
}

export class LsaprTrustInformation extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Name', RPC_UNICODE_STRING],
    ['Sid', PRPC_SID],
  ];
}

export class LsaprTrustInformationArray extends NDRUniConformantArray {
  static item = LsaprTrustInformation;
}

export class PLsaprTrustInformationArray extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LsaprTrustInformationArray]];
}

export class LsaprReferencedDomainList extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Entries', ULONG],
    ['Domains', PLsaprTrustInformationArray],
    ['MaxEntries', ULONG],
  ];
}

export class PLsaprReferencedDomainList extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LsaprReferencedDomainList]];
}

export class LsaTranslatedSid extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Use', SidNameUse],
    ['RelativeId', ULONG],
    ['DomainIndex', LONG],
  ];
}

export class LsaTranslatedSidArray extends NDRUniConformantArray {
  static item = LsaTranslatedSid;
}

export class PLsaTranslatedSidArray extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LsaTranslatedSidArray]];
}

export class LsaprTranslatedSids extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Entries', ULONG],
    ['Sids', PLsaTranslatedSidArray],
  ];
}

export class LsapLookupLevel extends NDRENUM {
  static enumItems = {
    1: 'LsapLookupWksta',
    2: 'LsapLookupPDC',
    3: 'LsapLookupTDL',
    4: 'LsapLookupGC',
    5: 'LsapLookupXForestReferral',
    6: 'LsapLookupXForestResolve',
    7: 'LsapLookupRODCReferralToFullDC',
  };
  static enumValues = {
    LsapLookupWksta: 1,
    LsapLookupPDC: 2,
    LsapLookupTDL: 3,
    LsapLookupGC: 4,
    LsapLookupXForestReferral: 5,
    LsapLookupXForestResolve: 6,
    LsapLookupRODCReferralToFullDC: 7,
  };
}

export class LsaprSidInformation extends NDRSTRUCT {
  static structure: NDRField[] = [['Sid', PRPC_SID]];
}

export class LsaprSidInformationArray extends NDRUniConformantArray {
  static item = LsaprSidInformation;
}

export class PLsaprSidInformationArray extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LsaprSidInformationArray]];
}

export class LsaprSidEnumBuffer extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Entries', ULONG],
    ['SidInfo', PLsaprSidInformationArray],
  ];
}

export class LsaprTranslatedName extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Use', SidNameUse],
    ['Name', RPC_UNICODE_STRING],
    ['DomainIndex', LONG],
  ];
}

export class LsaprTranslatedNameArray extends NDRUniConformantArray {
  static item = LsaprTranslatedName;
}

export class PLsaprTranslatedNameArray extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LsaprTranslatedNameArray]];
}

export class LsaprTranslatedNames extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Entries', ULONG],
    ['Names', PLsaprTranslatedNameArray],
  ];
}

export class LsaprTranslatedNameEx extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Use', SidNameUse],
    ['Name', RPC_UNICODE_STRING],
    ['DomainIndex', LONG],
    ['Flags', ULONG],
  ];
}

export class LsaprTranslatedNameExArray extends NDRUniConformantArray {
  static item = LsaprTranslatedNameEx;
}

export class PLsaprTranslatedNameExArray extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LsaprTranslatedNameExArray]];
}

export class LsaprTranslatedNamesEx extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Entries', ULONG],
    ['Names', PLsaprTranslatedNameExArray],
  ];
}

export class LsaprTranslatedSidEx extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Use', SidNameUse],
    ['RelativeId', ULONG],
    ['DomainIndex', LONG],
    ['Flags', ULONG],
  ];
}

export class LsaprTranslatedSidExArray extends NDRUniConformantArray {
  static item = LsaprTranslatedSidEx;
}

export class PLsaprTranslatedSidExArray extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LsaprTranslatedSidExArray]];
}

export class LsaprTranslatedSidsEx extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Entries', ULONG],
    ['Sids', PLsaprTranslatedSidExArray],
  ];
}

export class LsaprTranslatedSidEx2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Use', SidNameUse],
    ['Sid', PRPC_SID],
    ['DomainIndex', LONG],
    ['Flags', ULONG],
  ];
}

export class LsaprTranslatedSidEx2Array extends NDRUniConformantArray {
  static item = LsaprTranslatedSidEx2;
}

export class PLsaprTranslatedSidEx2Array extends NDRPOINTER {
  static referent: NDRField[] = [['Data', LsaprTranslatedSidEx2Array]];
}

export class LsaprTranslatedSidsEx2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Entries', ULONG],
    ['Sids', PLsaprTranslatedSidEx2Array],
  ];
}

export class RpcUnicodeStringArray extends NDRUniConformantArray {
  static item = RPC_UNICODE_STRING;
}

export class LsarGetUserNameResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['UserName', PRPC_UNICODE_STRING],
    ['DomainName', PRPC_UNICODE_STRING],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarGetUserName extends NDRCALL {
  static opnum = 45;
  static structure: NDRField[] = [
    ['SystemName', LPWSTR],
    ['UserName', PRPC_UNICODE_STRING],
    ['DomainName', PRPC_UNICODE_STRING],
  ];
  static Response = LsarGetUserNameResponse;
}

export class LsarLookupNames4Response extends NDRCALL {
  static structure: NDRField[] = [
    ['ReferencedDomains', PLsaprReferencedDomainList],
    ['TranslatedSids', LsaprTranslatedSidsEx2],
    ['MappedCount', ULONG],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarLookupNames4 extends NDRCALL {
  static opnum = 77;
  static structure: NDRField[] = [
    ['Count', ULONG],
    ['Names', RpcUnicodeStringArray],
    ['TranslatedSids', LsaprTranslatedSidsEx2],
    ['LookupLevel', LsapLookupLevel],
    ['MappedCount', ULONG],
    ['LookupOptions', ULONG],
    ['ClientRevision', ULONG],
  ];
  static Response = LsarLookupNames4Response;
}

export class LsarLookupNames3Response extends NDRCALL {
  static structure: NDRField[] = [
    ['ReferencedDomains', PLsaprReferencedDomainList],
    ['TranslatedSids', LsaprTranslatedSidsEx2],
    ['MappedCount', ULONG],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarLookupNames3 extends NDRCALL {
  static opnum = 68;
  static structure: NDRField[] = [
    ['PolicyHandle', LsaprHandle],
    ['Count', ULONG],
    ['Names', RpcUnicodeStringArray],
    ['TranslatedSids', LsaprTranslatedSidsEx2],
    ['LookupLevel', LsapLookupLevel],
    ['MappedCount', ULONG],
    ['LookupOptions', ULONG],
    ['ClientRevision', ULONG],
  ];
  static Response = LsarLookupNames3Response;
}

export class LsarLookupNames2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['ReferencedDomains', PLsaprReferencedDomainList],
    ['TranslatedSids', LsaprTranslatedSidsEx],
    ['MappedCount', ULONG],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarLookupNames2 extends NDRCALL {
  static opnum = 58;
  static structure: NDRField[] = [
    ['PolicyHandle', LsaprHandle],
    ['Count', ULONG],
    ['Names', RpcUnicodeStringArray],
    ['TranslatedSids', LsaprTranslatedSidsEx],
    ['LookupLevel', LsapLookupLevel],
    ['MappedCount', ULONG],
    ['LookupOptions', ULONG],
    ['ClientRevision', ULONG],
  ];
  static Response = LsarLookupNames2Response;
}

export class LsarLookupNamesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ReferencedDomains', PLsaprReferencedDomainList],
    ['TranslatedSids', LsaprTranslatedSids],
    ['MappedCount', ULONG],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarLookupNames extends NDRCALL {
  static opnum = 14;
  static structure: NDRField[] = [
    ['PolicyHandle', LsaprHandle],
    ['Count', ULONG],
    ['Names', RpcUnicodeStringArray],
    ['TranslatedSids', LsaprTranslatedSids],
    ['LookupLevel', LsapLookupLevel],
    ['MappedCount', ULONG],
  ];
  static Response = LsarLookupNamesResponse;
}

export class LsarLookupSids3Response extends NDRCALL {
  static structure: NDRField[] = [
    ['ReferencedDomains', PLsaprReferencedDomainList],
    ['TranslatedNames', LsaprTranslatedNamesEx],
    ['MappedCount', ULONG],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarLookupSids3 extends NDRCALL {
  static opnum = 76;
  static structure: NDRField[] = [
    ['SidEnumBuffer', LsaprSidEnumBuffer],
    ['TranslatedNames', LsaprTranslatedNamesEx],
    ['LookupLevel', LsapLookupLevel],
    ['MappedCount', ULONG],
    ['LookupOptions', ULONG],
    ['ClientRevision', ULONG],
  ];
  static Response = LsarLookupSids3Response;
}

export class LsarLookupSids2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['ReferencedDomains', PLsaprReferencedDomainList],
    ['TranslatedNames', LsaprTranslatedNamesEx],
    ['MappedCount', ULONG],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarLookupSids2 extends NDRCALL {
  static opnum = 57;
  static structure: NDRField[] = [
    ['PolicyHandle', LsaprHandle],
    ['SidEnumBuffer', LsaprSidEnumBuffer],
    ['TranslatedNames', LsaprTranslatedNamesEx],
    ['LookupLevel', LsapLookupLevel],
    ['MappedCount', ULONG],
    ['LookupOptions', ULONG],
    ['ClientRevision', ULONG],
  ];
  static Response = LsarLookupSids2Response;
}

export class LsarLookupSidsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ReferencedDomains', PLsaprReferencedDomainList],
    ['TranslatedNames', LsaprTranslatedNames],
    ['MappedCount', ULONG],
    ['ErrorCode', NTSTATUS],
  ];
}

export class LsarLookupSids extends NDRCALL {
  static opnum = 15;
  static structure: NDRField[] = [
    ['PolicyHandle', LsaprHandle],
    ['SidEnumBuffer', LsaprSidEnumBuffer],
    ['TranslatedNames', LsaprTranslatedNames],
    ['LookupLevel', LsapLookupLevel],
    ['MappedCount', ULONG],
  ];
  static Response = LsarLookupSidsResponse;
}

const OPNUMS = {
  0: [LsarClose, LsarCloseResponse] as const,
  14: [LsarLookupNames, LsarLookupNamesResponse] as const,
  15: [LsarLookupSids, LsarLookupSidsResponse] as const,
  44: [LsarOpenPolicy2, LsarOpenPolicy2Response] as const,
  45: [LsarGetUserName, LsarGetUserNameResponse] as const,
  57: [LsarLookupSids2, LsarLookupSids2Response] as const,
  58: [LsarLookupNames2, LsarLookupNames2Response] as const,
  68: [LsarLookupNames3, LsarLookupNames3Response] as const,
  76: [LsarLookupSids3, LsarLookupSids3Response] as const,
  77: [LsarLookupNames4, LsarLookupNames4Response] as const,
};

type DceRequestFn = <T>(req: unknown, uuid?: unknown, checkError?: boolean) => Promise<T>;

export async function hLsarGetUserName(
  dce: DCERPC_v5,
  userName: unknown = NULL,
  domainName: unknown = NULL,
) {
  const request = new LsarGetUserName();
  request.set('SystemName', NULL);
  request.set('UserName', userName);
  request.set('DomainName', domainName);
  return (dce as unknown as { request: DceRequestFn }).request<LsarGetUserNameResponse>(request);
}

export async function hLsarLookupNames4(
  dce: DCERPC_v5,
  names: string[],
  lookupLevel: number = LsapLookupLevel.enumValues.LsapLookupWksta,
  lookupOptions = 0x00000000,
  clientRevision = 0x00000001,
) {
  const request = new LsarLookupNames4();
  request.set('Count', names.length);
  const namesArr = request.fields['Names'] as RpcUnicodeStringArray;
  for (const name of names) {
    const itemn = new RPC_UNICODE_STRING();
    itemn.set('Data', name);
    (namesArr.fields['Data'] as unknown[]).push(itemn);
  }
  const translatedSids = request.fields['TranslatedSids'] as LsaprTranslatedSidsEx2;
  translatedSids.set('Sids', NULL);
  request.set('LookupLevel', lookupLevel);
  request.set('LookupOptions', lookupOptions);
  request.set('ClientRevision', clientRevision);
  return (dce as unknown as { request: DceRequestFn }).request<LsarLookupNames4Response>(request);
}

export async function hLsarLookupNames3(
  dce: DCERPC_v5,
  policyHandle: LsaprHandle,
  names: string[],
  lookupLevel: number = LsapLookupLevel.enumValues.LsapLookupWksta,
  lookupOptions = 0x00000000,
  clientRevision = 0x00000001,
) {
  const request = new LsarLookupNames3();
  request.set('PolicyHandle', policyHandle);
  request.set('Count', names.length);
  const namesArr = request.fields['Names'] as RpcUnicodeStringArray;
  for (const name of names) {
    const itemn = new RPC_UNICODE_STRING();
    itemn.set('Data', name);
    (namesArr.fields['Data'] as unknown[]).push(itemn);
  }
  const translatedSids = request.fields['TranslatedSids'] as LsaprTranslatedSidsEx2;
  translatedSids.set('Sids', NULL);
  request.set('LookupLevel', lookupLevel);
  request.set('LookupOptions', lookupOptions);
  request.set('ClientRevision', clientRevision);
  return (dce as unknown as { request: DceRequestFn }).request<LsarLookupNames3Response>(request);
}

export async function hLsarLookupNames2(
  dce: DCERPC_v5,
  policyHandle: LsaprHandle,
  names: string[],
  lookupLevel: number = LsapLookupLevel.enumValues.LsapLookupWksta,
  lookupOptions = 0x00000000,
  clientRevision = 0x00000001,
) {
  const request = new LsarLookupNames2();
  request.set('PolicyHandle', policyHandle);
  request.set('Count', names.length);
  const namesArr = request.fields['Names'] as RpcUnicodeStringArray;
  for (const name of names) {
    const itemn = new RPC_UNICODE_STRING();
    itemn.set('Data', name);
    (namesArr.fields['Data'] as unknown[]).push(itemn);
  }
  const translatedSids = request.fields['TranslatedSids'] as LsaprTranslatedSidsEx;
  translatedSids.set('Sids', NULL);
  request.set('LookupLevel', lookupLevel);
  request.set('LookupOptions', lookupOptions);
  request.set('ClientRevision', clientRevision);
  return (dce as unknown as { request: DceRequestFn }).request<LsarLookupNames2Response>(request);
}

export async function hLsarLookupNames(
  dce: DCERPC_v5,
  policyHandle: LsaprHandle,
  names: string[],
  lookupLevel: number = LsapLookupLevel.enumValues.LsapLookupWksta,
) {
  const request = new LsarLookupNames();
  request.set('PolicyHandle', policyHandle);
  request.set('Count', names.length);
  const namesArr = request.fields['Names'] as RpcUnicodeStringArray;
  for (const name of names) {
    const itemn = new RPC_UNICODE_STRING();
    itemn.set('Data', name);
    (namesArr.fields['Data'] as unknown[]).push(itemn);
  }
  const translatedSids = request.fields['TranslatedSids'] as LsaprTranslatedSids;
  translatedSids.set('Sids', NULL);
  request.set('LookupLevel', lookupLevel);
  return (dce as unknown as { request: DceRequestFn }).request<LsarLookupNamesResponse>(request);
}

export async function hLsarLookupSids2(
  dce: DCERPC_v5,
  policyHandle: LsaprHandle,
  sids: string[],
  lookupLevel: number = LsapLookupLevel.enumValues.LsapLookupWksta,
  lookupOptions = 0x00000000,
  clientRevision = 0x00000001,
) {
  const request = new LsarLookupSids2();
  request.set('PolicyHandle', policyHandle);
  const sidEnumBuffer = request.fields['SidEnumBuffer'] as LsaprSidEnumBuffer;
  sidEnumBuffer.set('Entries', sids.length);
  const sidInfoPtr = sidEnumBuffer.fields['SidInfo'] as PLsaprSidInformationArray;
  const sidInfoArr = sidInfoPtr.fields['Data'] as LsaprSidInformationArray;
  for (const sid of sids) {
    const itemn = new LsaprSidInformation();
    const sidPtr = itemn.fields['Sid'] as PRPC_SID;
    const sidData = sidPtr.fields['Data'] as RPC_SID;
    sidData.fromCanonical(sid);
    (sidInfoArr.fields['Data'] as unknown[]).push(itemn);
  }
  const translatedNames = request.fields['TranslatedNames'] as LsaprTranslatedNamesEx;
  translatedNames.set('Names', NULL);
  request.set('LookupLevel', lookupLevel);
  request.set('LookupOptions', lookupOptions);
  request.set('ClientRevision', clientRevision);
  return (dce as unknown as { request: DceRequestFn }).request<LsarLookupSids2Response>(request);
}

export async function hLsarLookupSids(
  dce: DCERPC_v5,
  policyHandle: LsaprHandle,
  sids: string[],
  lookupLevel: number = LsapLookupLevel.enumValues.LsapLookupWksta,
) {
  const request = new LsarLookupSids();
  request.set('PolicyHandle', policyHandle);
  const sidEnumBuffer = request.fields['SidEnumBuffer'] as LsaprSidEnumBuffer;
  sidEnumBuffer.set('Entries', sids.length);
  const sidInfoPtr = sidEnumBuffer.fields['SidInfo'] as PLsaprSidInformationArray;
  const sidInfoArr = sidInfoPtr.fields['Data'] as LsaprSidInformationArray;
  for (const sid of sids) {
    const itemn = new LsaprSidInformation();
    const sidPtr = itemn.fields['Sid'] as PRPC_SID;
    const sidData = sidPtr.fields['Data'] as RPC_SID;
    sidData.fromCanonical(sid);
    (sidInfoArr.fields['Data'] as unknown[]).push(itemn);
  }
  const translatedNames = request.fields['TranslatedNames'] as LsaprTranslatedNames;
  translatedNames.set('Names', NULL);
  request.set('LookupLevel', lookupLevel);
  return (dce as unknown as { request: DceRequestFn }).request<LsarLookupSidsResponse>(request);
}

