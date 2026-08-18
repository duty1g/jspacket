import { Buffer } from 'node:buffer';
import {
  TagClass,
  TagForm,
  parseTLV,
  parseTLVs,
  encodeTLV,
  encodeInteger,
  decodeInteger,
  encodeBoolean,
  decodeBoolean,
  encodeOctetString,
  encodeEnumerated,
  decodeEnumerated,
} from '@impacket/asn1';

export const CONTROL_PAGEDRESULTS = '1.2.840.113556.1.4.319';
export const CONTROL_SDFLAGS = '1.2.840.113556.1.4.801';
export const NOTIFICATION_DISCONNECT = '1.3.6.1.4.1.1466.20036';

export const KNOWN_NOTIFICATIONS: Record<string, string> = {
  [NOTIFICATION_DISCONNECT]: 'Notice of Disconnection',
};

export enum ResultCode {
  success = 0,
  operationsError = 1,
  protocolError = 2,
  timeLimitExceeded = 3,
  sizeLimitExceeded = 4,
  compareFalse = 5,
  compareTrue = 6,
  authMethodNotSupported = 7,
  strongerAuthRequired = 8,
  referral = 10,
  adminLimitExceeded = 11,
  unavailableCriticalExtension = 12,
  confidentialityRequired = 13,
  saslBindInProgress = 14,
  noSuchAttribute = 16,
  undefinedAttributeType = 17,
  inappropriateMatching = 18,
  constraintViolation = 19,
  attributeOrValueExists = 20,
  invalidAttributeSyntax = 21,
  noSuchObject = 32,
  aliasProblem = 33,
  invalidDNSyntax = 34,
  aliasDereferencingProblem = 36,
  inappropriateAuthentication = 48,
  invalidCredentials = 49,
  insufficientAccessRights = 50,
  busy = 51,
  unavailable = 52,
  unwillingToPerform = 53,
  loopDetect = 54,
  namingViolation = 64,
  objectClassViolation = 65,
  notAllowedOnNonLeaf = 66,
  notAllowedOnRDN = 67,
  entryAlreadyExists = 68,
  objectClassModsProhibited = 69,
  affectsMultipleDSAs = 71,
  other = 80,
}

export enum Scope {
  baseObject = 0,
  singleLevel = 1,
  wholeSubtree = 2,
}

export enum DerefAliases {
  neverDerefAliases = 0,
  derefInSearching = 1,
  derefFindingBaseObj = 2,
  derefAlways = 3,
}

export enum Operation {
  add = 0,
  delete = 1,
  replace = 2,
}

export const maxInt = 2147483647;

function app(tag: number, constructed = true): number {
  return TagClass.APPLICATION | (constructed ? TagForm.CONSTRUCTED : TagForm.PRIMITIVE) | tag;
}

function ctx(tag: number, constructed = false): number {
  return TagClass.CONTEXT | (constructed ? TagForm.CONSTRUCTED : TagForm.PRIMITIVE) | tag;
}

export interface LdapControl {
  controlType: string;
  criticality: boolean;
  controlValue: Buffer | null;
}

export interface LdapMessage {
  messageID: number;
  protocolOp: Buffer;
  controls: LdapControl[] | null;
  raw: Buffer;
}

export function encodeMessageID(id: number): Buffer {
  return encodeTLV(TagClass.UNIVERSAL, false, 2, encodeInteger(id));
}

export function encodeLDAPString(value: string): Buffer {
  return Buffer.from(value, 'utf8');
}

export function encodeLDAPOID(value: string): Buffer {
  return Buffer.from(value, 'ascii');
}

export function encodeLDAPDN(value: string): Buffer {
  return encodeLDAPString(value);
}

export function encodeAttributeDescription(value: string): Buffer {
  return encodeLDAPString(value);
}

export function encodeAttributeValue(value: string | Buffer): Buffer {
  if (Buffer.isBuffer(value)) return value;
  return Buffer.from(value, 'utf8');
}

export interface AttributeValueAssertion {
  attributeDesc: string;
  assertionValue: string | Buffer;
}

export function encodeAttributeValueAssertion(ava: AttributeValueAssertion): Buffer {
  return Buffer.concat([
    encodeTLV(TagClass.UNIVERSAL, false, 4, encodeAttributeDescription(ava.attributeDesc)),
    encodeTLV(TagClass.UNIVERSAL, false, 4, encodeAttributeValue(ava.assertionValue)),
  ]);
}

export interface PartialAttribute {
  type: string;
  vals: (string | Buffer)[];
}

export function encodePartialAttribute(attr: PartialAttribute): Buffer {
  const vals = Buffer.concat(
    attr.vals.map((v) => encodeTLV(TagClass.UNIVERSAL, false, 4, encodeAttributeValue(v))),
  );
  const valsSet = encodeTLV(TagClass.UNIVERSAL, true, 17, vals);
  const inner = Buffer.concat([
    encodeTLV(TagClass.UNIVERSAL, false, 4, encodeAttributeDescription(attr.type)),
    valsSet,
  ]);
  return encodeTLV(TagClass.UNIVERSAL, true, 16, inner);
}

export function encodePartialAttributeList(attrs: PartialAttribute[]): Buffer {
  return encodeTLV(
    TagClass.UNIVERSAL,
    true,
    16,
    Buffer.concat(attrs.map((a) => encodePartialAttribute(a))),
  );
}

export interface Attribute {
  type: string;
  vals: (string | Buffer)[];
}

export function encodeAttribute(attr: Attribute): Buffer {
  return encodePartialAttribute(attr);
}

export function encodeAttributeList(attrs: Attribute[]): Buffer {
  return encodeTLV(
    TagClass.UNIVERSAL,
    true,
    16,
    Buffer.concat(attrs.map((a) => encodeAttribute(a))),
  );
}

export function encodeAttributeSelection(attrs: string[]): Buffer {
  return encodeTLV(
    TagClass.UNIVERSAL,
    true,
    16,
    Buffer.concat(attrs.map((a) => encodeTLV(TagClass.UNIVERSAL, false, 4, encodeLDAPString(a)))),
  );
}

export interface LDAPResult {
  resultCode: number;
  matchedDN: string;
  diagnosticMessage: string;
  referral: string[] | null;
}

export function decodeLDAPResult(buf: Buffer): LDAPResult {
  let data = buf;
  const outer = parseTLV(buf);
  if (outer.cls === TagClass.APPLICATION) data = outer.value;
  const tlvs = parseTLVs(data);
  const resultCode = Number(decodeEnumerated(tlvs[0]!.value));
  const matchedDN = tlvs[1]!.value.toString('utf8');
  const diagnosticMessage = tlvs[2]!.value.toString('utf8');
  let referral: string[] | null = null;
  if (tlvs.length > 3 && tlvs[3]!.cls === TagClass.CONTEXT && tlvs[3]!.tag === 3) {
    const refTLVs = parseTLVs(tlvs[3]!.value);
    referral = refTLVs.map((t) => t.value.toString('utf8'));
  }
  return { resultCode, matchedDN, diagnosticMessage, referral };
}

export interface SaslCredentials {
  mechanism: string;
  credentials: Buffer | null;
}

export type AuthenticationChoice =
  | { simple: Buffer }
  | { sasl: SaslCredentials }
  | { sicilyPackageDiscovery: Buffer }
  | { sicilyNegotiate: Buffer }
  | { sicilyResponse: Buffer };

export function encodeAuthenticationChoice(auth: AuthenticationChoice): Buffer {
  if ('simple' in auth) {
    return encodeTLV(TagClass.CONTEXT, false, 0, auth.simple);
  }
  if ('sasl' in auth) {
    const parts: Buffer[] = [
      encodeTLV(TagClass.UNIVERSAL, false, 4, Buffer.from(auth.sasl.mechanism, 'utf8')),
    ];
    if (auth.sasl.credentials !== null) {
      parts.push(encodeTLV(TagClass.UNIVERSAL, false, 4, auth.sasl.credentials));
    }
    return encodeTLV(TagClass.CONTEXT, true, 3, Buffer.concat(parts));
  }
  if ('sicilyPackageDiscovery' in auth) {
    return encodeTLV(TagClass.CONTEXT, false, 9, auth.sicilyPackageDiscovery);
  }
  if ('sicilyNegotiate' in auth) {
    return encodeTLV(TagClass.CONTEXT, false, 10, auth.sicilyNegotiate);
  }
  if ('sicilyResponse' in auth) {
    return encodeTLV(TagClass.CONTEXT, false, 11, auth.sicilyResponse);
  }
  throw new Error('Unknown authentication choice');
}

export interface BindRequest {
  version: number;
  name: string;
  authentication: AuthenticationChoice;
}

export function encodeBindRequest(req: BindRequest): Buffer {
  const body = Buffer.concat([
    encodeTLV(TagClass.UNIVERSAL, false, 2, encodeInteger(req.version)),
    encodeTLV(TagClass.UNIVERSAL, false, 4, encodeLDAPDN(req.name)),
    encodeAuthenticationChoice(req.authentication),
  ]);
  return encodeTLV(TagClass.APPLICATION, true, 0, body);
}

export interface BindResponse extends LDAPResult {
  serverSaslCreds: Buffer | null;
}

export function decodeBindResponse(buf: Buffer): BindResponse {
  let data = buf;
  const outer = parseTLV(buf);
  if (outer.cls === TagClass.APPLICATION) {
    data = outer.value;
  } else {
    data = buf;
  }
  const tlvs = parseTLVs(data);
  const resultCode = Number(decodeEnumerated(tlvs[0]!.value));
  const matchedDN = tlvs[1]!.value.toString('utf8');
  const diagnosticMessage = tlvs[2]!.value.toString('utf8');
  let referral: string[] | null = null;
  let serverSaslCreds: Buffer | null = null;
  for (let i = 3; i < tlvs.length; i++) {
    const t = tlvs[i]!;
    if (t.cls === TagClass.CONTEXT && t.tag === 3) {
      const refTLVs = parseTLVs(t.value);
      referral = refTLVs.map((r) => r.value.toString('utf8'));
    } else if (t.cls === TagClass.CONTEXT && t.tag === 7) {
      serverSaslCreds = t.value;
    }
  }
  return { resultCode, matchedDN, diagnosticMessage, referral, serverSaslCreds };
}

export function encodeUnbindRequest(): Buffer {
  return encodeTLV(TagClass.APPLICATION, false, 2, Buffer.alloc(0));
}

export type Filter =
  | { and: Filter[] }
  | { or: Filter[] }
  | { not: Filter[] }
  | { equalityMatch: AttributeValueAssertion }
  | { substrings: SubstringFilter }
  | { greaterOrEqual: AttributeValueAssertion }
  | { lessOrEqual: AttributeValueAssertion }
  | { present: string }
  | { approxMatch: AttributeValueAssertion }
  | { extensibleMatch: MatchingRuleAssertion };

export interface SubstringFilter {
  type: string;
  substrings: Substring[];
}

export type Substring = { initial: string } | { any: string } | { final: string };

export interface MatchingRuleAssertion {
  matchingRule?: string;
  type?: string;
  matchValue: string | Buffer;
  dnAttributes: boolean;
}

export function encodeFilter(f: Filter): Buffer {
  if ('and' in f) {
    const body = Buffer.concat(f.and.map((sub) => encodeFilter(sub)));
    return encodeTLV(TagClass.CONTEXT, true, 0, body);
  }
  if ('or' in f) {
    const body = Buffer.concat(f.or.map((sub) => encodeFilter(sub)));
    return encodeTLV(TagClass.CONTEXT, true, 1, body);
  }
  if ('not' in f) {
    const body = Buffer.concat(f.not.map((sub) => encodeFilter(sub)));
    return encodeTLV(TagClass.CONTEXT, true, 2, body);
  }
  if ('equalityMatch' in f) {
    const body = encodeAttributeValueAssertion(f.equalityMatch);
    return encodeTLV(TagClass.CONTEXT, true, 3, body);
  }
  if ('substrings' in f) {
    const subParts = f.substrings.substrings.map((s) => {
      if ('initial' in s)
        return encodeTLV(TagClass.CONTEXT, false, 0, Buffer.from(s.initial, 'utf8'));
      if ('any' in s) return encodeTLV(TagClass.CONTEXT, false, 1, Buffer.from(s.any, 'utf8'));
      return encodeTLV(TagClass.CONTEXT, false, 2, Buffer.from(s.final, 'utf8'));
    });
    const subSeq = encodeTLV(TagClass.UNIVERSAL, true, 16, Buffer.concat(subParts));
    const body = Buffer.concat([
      encodeTLV(TagClass.UNIVERSAL, false, 4, encodeAttributeDescription(f.substrings.type)),
      subSeq,
    ]);
    return encodeTLV(TagClass.CONTEXT, true, 4, body);
  }
  if ('greaterOrEqual' in f) {
    const body = encodeAttributeValueAssertion(f.greaterOrEqual);
    return encodeTLV(TagClass.CONTEXT, true, 5, body);
  }
  if ('lessOrEqual' in f) {
    const body = encodeAttributeValueAssertion(f.lessOrEqual);
    return encodeTLV(TagClass.CONTEXT, true, 6, body);
  }
  if ('present' in f) {
    return encodeTLV(TagClass.CONTEXT, false, 7, encodeAttributeDescription(f.present));
  }
  if ('approxMatch' in f) {
    const body = encodeAttributeValueAssertion(f.approxMatch);
    return encodeTLV(TagClass.CONTEXT, true, 8, body);
  }
  if ('extensibleMatch' in f) {
    const m = f.extensibleMatch;
    const parts: Buffer[] = [];
    if (m.matchingRule !== undefined) {
      parts.push(encodeTLV(TagClass.CONTEXT, false, 1, Buffer.from(m.matchingRule, 'utf8')));
    }
    if (m.type !== undefined) {
      parts.push(encodeTLV(TagClass.CONTEXT, false, 2, encodeAttributeDescription(m.type)));
    }
    parts.push(encodeTLV(TagClass.CONTEXT, false, 3, encodeAttributeValue(m.matchValue)));
    parts.push(encodeTLV(TagClass.CONTEXT, false, 4, encodeBoolean(m.dnAttributes)));
    return encodeTLV(TagClass.CONTEXT, true, 9, Buffer.concat(parts));
  }
  throw new Error('Unknown filter type');
}

export interface SearchRequest {
  baseObject: string;
  scope: Scope;
  derefAliases: DerefAliases;
  sizeLimit: number;
  timeLimit: number;
  typesOnly: boolean;
  filter: Filter;
  attributes: string[];
}

export function encodeSearchRequest(req: SearchRequest): Buffer {
  const body = Buffer.concat([
    encodeTLV(TagClass.UNIVERSAL, false, 4, encodeLDAPDN(req.baseObject)),
    encodeTLV(TagClass.UNIVERSAL, false, 10, encodeEnumerated(req.scope)),
    encodeTLV(TagClass.UNIVERSAL, false, 10, encodeEnumerated(req.derefAliases)),
    encodeTLV(TagClass.UNIVERSAL, false, 2, encodeInteger(req.sizeLimit)),
    encodeTLV(TagClass.UNIVERSAL, false, 2, encodeInteger(req.timeLimit)),
    encodeTLV(TagClass.UNIVERSAL, false, 1, encodeBoolean(req.typesOnly)),
    encodeFilter(req.filter),
    encodeAttributeSelection(req.attributes),
  ]);
  return encodeTLV(TagClass.APPLICATION, true, 3, body);
}

export interface SearchResultEntry {
  objectName: string;
  attributes: PartialAttribute[];
}

export function decodeSearchResultEntry(buf: Buffer): SearchResultEntry {
  let data = buf;
  const outer = parseTLV(buf);
  if (outer.cls === TagClass.APPLICATION) data = outer.value;
  const tlvs = parseTLVs(data);
  const objectName = tlvs[0]!.value.toString('utf8');
  const attrTLVs = parseTLVs(tlvs[1]!.value);
  const attributes: PartialAttribute[] = attrTLVs.map((attrTLV) => {
    const parts = parseTLVs(attrTLV.value);
    const type = parts[0]!.value.toString('utf8');
    const valTLVs = parseTLVs(parts[1]!.value);
    const vals = valTLVs.map((v) => v.value);
    return { type, vals };
  });
  return { objectName, attributes };
}

export interface SearchResultReference {
  uris: string[];
}

export function decodeSearchResultReference(buf: Buffer): SearchResultReference {
  let data = buf;
  const outer = parseTLV(buf);
  if (outer.cls === TagClass.APPLICATION) data = outer.value;
  const tlvs = parseTLVs(data);
  return { uris: tlvs.map((t) => t.value.toString('utf8')) };
}

export function encodeSearchResultDone(result: LDAPResult): Buffer {
  const body = encodeLDAPResultRaw(result);
  return encodeTLV(TagClass.APPLICATION, true, 5, body);
}

function encodeLDAPResultRaw(result: LDAPResult): Buffer {
  const parts: Buffer[] = [
    encodeTLV(TagClass.UNIVERSAL, false, 10, encodeEnumerated(result.resultCode)),
    encodeTLV(TagClass.UNIVERSAL, false, 4, encodeLDAPDN(result.matchedDN)),
    encodeTLV(TagClass.UNIVERSAL, false, 4, encodeLDAPString(result.diagnosticMessage)),
  ];
  if (result.referral !== null) {
    const refBody = Buffer.concat(
      result.referral.map((r) => encodeTLV(TagClass.UNIVERSAL, false, 4, Buffer.from(r, 'utf8'))),
    );
    parts.push(encodeTLV(TagClass.CONTEXT, true, 3, refBody));
  }
  return Buffer.concat(parts);
}

export interface ModifyRequest {
  object: string;
  changes: ModifyChange[];
}

export interface ModifyChange {
  operation: Operation;
  modification: PartialAttribute;
}

export function encodeModifyRequest(req: ModifyRequest): Buffer {
  const changesBody = Buffer.concat(
    req.changes.map((c) => {
      const changeBody = Buffer.concat([
        encodeTLV(TagClass.UNIVERSAL, false, 10, encodeEnumerated(c.operation)),
        encodePartialAttribute(c.modification),
      ]);
      return encodeTLV(TagClass.UNIVERSAL, true, 16, changeBody);
    }),
  );
  const body = Buffer.concat([
    encodeTLV(TagClass.UNIVERSAL, false, 4, encodeLDAPDN(req.object)),
    encodeTLV(TagClass.UNIVERSAL, true, 16, changesBody),
  ]);
  return encodeTLV(TagClass.APPLICATION, true, 6, body);
}

export function encodeModifyResponse(result: LDAPResult): Buffer {
  return encodeTLV(TagClass.APPLICATION, true, 7, encodeLDAPResultRaw(result));
}

export interface AddRequest {
  entry: string;
  attributes: Attribute[];
}

export function encodeAddRequest(req: AddRequest): Buffer {
  const body = Buffer.concat([
    encodeTLV(TagClass.UNIVERSAL, false, 4, encodeLDAPDN(req.entry)),
    encodeAttributeList(req.attributes),
  ]);
  return encodeTLV(TagClass.APPLICATION, true, 8, body);
}

export function encodeAddResponse(result: LDAPResult): Buffer {
  return encodeTLV(TagClass.APPLICATION, true, 9, encodeLDAPResultRaw(result));
}

export function encodeDelRequest(dn: string): Buffer {
  return encodeTLV(TagClass.APPLICATION, false, 10, encodeLDAPDN(dn));
}

export function encodeDelResponse(result: LDAPResult): Buffer {
  return encodeTLV(TagClass.APPLICATION, true, 11, encodeLDAPResultRaw(result));
}

export interface ModifyDNRequest {
  entry: string;
  newrdn: string;
  deleteoldrdn: boolean;
  newSuperior?: string;
}

export function encodeModifyDNRequest(req: ModifyDNRequest): Buffer {
  const parts: Buffer[] = [
    encodeTLV(TagClass.UNIVERSAL, false, 4, encodeLDAPDN(req.entry)),
    encodeTLV(TagClass.UNIVERSAL, false, 4, encodeLDAPDN(req.newrdn)),
    encodeTLV(TagClass.UNIVERSAL, false, 1, encodeBoolean(req.deleteoldrdn)),
  ];
  if (req.newSuperior !== undefined) {
    parts.push(encodeTLV(TagClass.CONTEXT, false, 0, encodeLDAPDN(req.newSuperior)));
  }
  return encodeTLV(TagClass.APPLICATION, true, 12, Buffer.concat(parts));
}

export function encodeModifyDNResponse(result: LDAPResult): Buffer {
  return encodeTLV(TagClass.APPLICATION, true, 13, encodeLDAPResultRaw(result));
}

export interface CompareRequest {
  entry: string;
  ava: AttributeValueAssertion;
}

export function encodeCompareRequest(req: CompareRequest): Buffer {
  const body = Buffer.concat([
    encodeTLV(TagClass.UNIVERSAL, false, 4, encodeLDAPDN(req.entry)),
    encodeAttributeValueAssertion(req.ava),
  ]);
  return encodeTLV(TagClass.APPLICATION, true, 14, body);
}

export function encodeCompareResponse(result: LDAPResult): Buffer {
  return encodeTLV(TagClass.APPLICATION, true, 15, encodeLDAPResultRaw(result));
}

export function encodeAbandonRequest(messageID: number): Buffer {
  return encodeTLV(TagClass.APPLICATION, false, 16, encodeInteger(messageID));
}

export interface ExtendedRequest {
  requestName: string;
  requestValue: Buffer | null;
}

export function encodeExtendedRequest(req: ExtendedRequest): Buffer {
  const parts: Buffer[] = [encodeTLV(TagClass.CONTEXT, false, 0, encodeLDAPOID(req.requestName))];
  if (req.requestValue !== null) {
    parts.push(encodeTLV(TagClass.CONTEXT, false, 1, req.requestValue));
  }
  return encodeTLV(TagClass.APPLICATION, true, 23, Buffer.concat(parts));
}

export interface ExtendedResponse extends LDAPResult {
  responseName: string | null;
  responseValue: Buffer | null;
}

export function decodeExtendedResponse(buf: Buffer): ExtendedResponse {
  let data = buf;
  const outer = parseTLV(buf);
  if (outer.cls === TagClass.APPLICATION) data = outer.value;
  const tlvs = parseTLVs(data);
  const resultCode = Number(decodeEnumerated(tlvs[0]!.value));
  const matchedDN = tlvs[1]!.value.toString('utf8');
  const diagnosticMessage = tlvs[2]!.value.toString('utf8');
  let referral: string[] | null = null;
  let responseName: string | null = null;
  let responseValue: Buffer | null = null;
  for (let i = 3; i < tlvs.length; i++) {
    const t = tlvs[i]!;
    if (t.cls === TagClass.CONTEXT && t.tag === 3) {
      const refTLVs = parseTLVs(t.value);
      referral = refTLVs.map((r) => r.value.toString('utf8'));
    } else if (t.cls === TagClass.CONTEXT && t.tag === 10) {
      responseName = t.value.toString('ascii');
    } else if (t.cls === TagClass.CONTEXT && t.tag === 11) {
      responseValue = t.value;
    }
  }
  return { resultCode, matchedDN, diagnosticMessage, referral, responseName, responseValue };
}

export interface IntermediateResponse {
  responseName: string | null;
  responseValue: Buffer | null;
}

export function decodeIntermediateResponse(buf: Buffer): IntermediateResponse {
  let data = buf;
  const outer = parseTLV(buf);
  if (outer.cls === TagClass.APPLICATION) data = outer.value;
  const tlvs = parseTLVs(data);
  let responseName: string | null = null;
  let responseValue: Buffer | null = null;
  for (const t of tlvs) {
    if (t.cls === TagClass.CONTEXT && t.tag === 0) {
      responseName = t.value.toString('ascii');
    } else if (t.cls === TagClass.CONTEXT && t.tag === 1) {
      responseValue = t.value;
    }
  }
  return { responseName, responseValue };
}

export function encodeControl(ctrl: LdapControl): Buffer {
  const parts: Buffer[] = [
    encodeTLV(TagClass.UNIVERSAL, false, 4, encodeLDAPOID(ctrl.controlType)),
  ];
  if (ctrl.criticality) {
    parts.push(encodeTLV(TagClass.UNIVERSAL, false, 1, encodeBoolean(true)));
  }
  if (ctrl.controlValue !== null) {
    parts.push(encodeTLV(TagClass.UNIVERSAL, false, 4, ctrl.controlValue));
  }
  return encodeTLV(TagClass.UNIVERSAL, true, 16, Buffer.concat(parts));
}

export function encodeControls(controls: LdapControl[]): Buffer {
  const body = Buffer.concat(controls.map((c) => encodeControl(c)));
  return encodeTLV(TagClass.CONTEXT, true, 0, body);
}

export function decodeControls(buf: Buffer): LdapControl[] {
  let data = buf;
  const outer = parseTLV(buf);
  if (outer.cls === TagClass.CONTEXT && outer.tag === 0) {
    data = outer.value;
  }
  const tlvs = parseTLVs(data);
  return tlvs.map((t) => decodeControl(t.value));
}

export function decodeControl(buf: Buffer): LdapControl {
  let data = buf;
  const outer = parseTLV(buf);
  if (outer.cls === TagClass.UNIVERSAL && outer.tag === 16 && outer.constructed) {
    data = outer.value;
  }
  const tlvs = parseTLVs(data);
  const controlType = tlvs[0]!.value.toString('ascii');
  let criticality = false;
  let controlValue: Buffer | null = null;
  for (let i = 1; i < tlvs.length; i++) {
    const t = tlvs[i]!;
    if (t.cls === TagClass.UNIVERSAL && t.tag === 1) {
      criticality = decodeBoolean(t.value);
    } else if (t.cls === TagClass.UNIVERSAL && t.tag === 4) {
      controlValue = t.value;
    }
  }
  return { controlType, criticality, controlValue };
}

export interface SimplePagedResultsControlValue {
  size: number;
  cookie: Buffer;
}

export function encodeSimplePagedResultsControlValue(val: SimplePagedResultsControlValue): Buffer {
  const body = Buffer.concat([
    encodeTLV(TagClass.UNIVERSAL, false, 2, encodeInteger(val.size)),
    encodeTLV(TagClass.UNIVERSAL, false, 4, val.cookie),
  ]);
  return body;
}

export function decodeSimplePagedResultsControlValue(buf: Buffer): SimplePagedResultsControlValue {
  const tlvs = parseTLVs(buf);
  const size = Number(decodeInteger(tlvs[0]!.value));
  const cookie = tlvs[1]!.value;
  return { size, cookie };
}

export function createSimplePagedResultsControl(
  size: number,
  cookie: Buffer = Buffer.alloc(0),
  criticality?: boolean,
): LdapControl {
  const controlValue = encodeSimplePagedResultsControlValue({ size, cookie });
  return {
    controlType: CONTROL_PAGEDRESULTS,
    criticality: criticality ?? false,
    controlValue,
  };
}

export interface SDFlagsControlValue {
  flags: number;
}

export function encodeSDFlagsControlValue(val: SDFlagsControlValue): Buffer {
  // MS-ADTS 3.1.1.3.4.1.11: SDFlagsRequestValue ::= SEQUENCE { Flags INTEGER }
  const flagsInt = encodeTLV(TagClass.UNIVERSAL, false, 2, encodeInteger(val.flags));
  return encodeTLV(TagClass.UNIVERSAL, true, 16, flagsInt);
}

export function decodeSDFlagsControlValue(buf: Buffer): SDFlagsControlValue {
  // Unwrap the SEQUENCE, then read the INTEGER inside it.
  const outer = parseTLVs(buf);
  const seq = outer[0]!;
  const inner = parseTLVs(seq.value);
  const flags = Number(decodeInteger(inner[0]!.value));
  return { flags };
}

export function createSDFlagsControl(flags = 0x00000007, criticality?: boolean): LdapControl {
  return {
    controlType: CONTROL_SDFLAGS,
    criticality: criticality ?? false,
    controlValue: encodeSDFlagsControlValue({ flags }),
  };
}

export function encodeLDAPMessage(
  messageID: number,
  protocolOp: Buffer,
  controls: LdapControl[] | null = null,
): Buffer {
  const parts: Buffer[] = [encodeMessageID(messageID), protocolOp];
  if (controls !== null && controls.length > 0) {
    parts.push(encodeControls(controls));
  }
  return encodeTLV(TagClass.UNIVERSAL, true, 16, Buffer.concat(parts));
}

export interface DecodedLDAPMessage {
  messageID: number;
  protocolOpTag: number;
  protocolOpCls: number;
  protocolOpConstructed: boolean;
  protocolOpValue: Buffer;
  controls: LdapControl[] | null;
  raw: Buffer;
  remaining: Buffer;
}

export function decodeLDAPMessage(buf: Buffer): DecodedLDAPMessage {
  const msgTLV = parseTLV(buf);
  const inner = msgTLV.value;
  const innerTLVs = parseTLVs(inner);
  const messageID = Number(decodeInteger(innerTLVs[0]!.value));
  const opTLV = innerTLVs[1]!;
  let controls: LdapControl[] | null = null;
  for (let i = 2; i < innerTLVs.length; i++) {
    const t = innerTLVs[i]!;
    if (t.cls === TagClass.CONTEXT && t.tag === 0) {
      controls = decodeControls(t.value);
    }
  }
  return {
    messageID,
    protocolOpTag: opTLV.tag,
    protocolOpCls: opTLV.cls,
    protocolOpConstructed: opTLV.constructed,
    protocolOpValue: opTLV.value,
    controls,
    raw: Buffer.from(buf.subarray(0, msgTLV.totalLength)),
    remaining: Buffer.from(buf.subarray(msgTLV.totalLength)),
  };
}

export function decodeAllLDAPMessages(buf: Buffer): DecodedLDAPMessage[] {
  const messages: DecodedLDAPMessage[] = [];
  let remaining = buf;
  while (remaining.length > 0) {
    const msg = decodeLDAPMessage(remaining);
    messages.push(msg);
    remaining = msg.remaining;
  }
  return messages;
}

export enum ProtocolOpTag {
  bindRequest = 0,
  bindResponse = 1,
  unbindRequest = 2,
  searchRequest = 3,
  searchResEntry = 4,
  searchResDone = 5,
  searchResRef = 19,
  modifyRequest = 6,
  modifyResponse = 7,
  addRequest = 8,
  addResponse = 9,
  delRequest = 10,
  delResponse = 11,
  modDNRequest = 12,
  modDNResponse = 13,
  compareRequest = 14,
  compareResponse = 15,
  abandonRequest = 16,
  extendedReq = 23,
  extendedResp = 24,
  intermediateResponse = 25,
}
