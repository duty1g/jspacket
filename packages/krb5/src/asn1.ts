import { Buffer } from 'node:buffer';
import {
  type AnyValue,
  Asn1BitString,
  Asn1Boolean,
  Asn1GeneralString,
  Asn1GeneralizedTime,
  Asn1Integer,
  type Asn1Node,
  Asn1OctetString,
  Asn1Sequence,
  Asn1SequenceOf,
  type Asn1String,
  type NamedComponent,
  TagClass,
  applicationTag,
  explicitTag,
} from '@impacket/asn1';

function sequenceComponent(
  name: string,
  tagValue: number,
  node: Asn1Node,
  opts: { optional?: boolean; default?: AnyValue } = {},
): NamedComponent {
  return {
    name,
    node,
    optional: opts.optional,
    default: opts.default,
    tagging: explicitTag(tagValue),
  };
}

function sequenceOptionalComponent(name: string, tagValue: number, node: Asn1Node): NamedComponent {
  return {
    name,
    node,
    optional: true,
    tagging: explicitTag(tagValue),
  };
}

function vnoComponent(tagValue: number, name = 'pvno'): NamedComponent {
  return sequenceComponent(name, tagValue, new Asn1Integer(5));
}

function msgTypeComponent(tagValue: number, _values: number[]): NamedComponent {
  return sequenceComponent('msg-type', tagValue, new Asn1Integer());
}

export function seqSet(seq: Asn1Sequence, name: string, value: AnyValue): void {
  seq.set(name, value);
}

export function seqSetIter(seq: Asn1Sequence, name: string, values: AnyValue[]): void {
  const comp = seq.getComponent(name) as unknown as Asn1SequenceOf;
  for (const v of values) {
    const Ctor = comp.elementNode.constructor as new () => typeof comp.elementNode;
    const item = new Ctor();
    if (typeof v === 'number' || typeof v === 'bigint') {
      (item as Asn1Integer).value = v as bigint | number;
    } else if (Buffer.isBuffer(v)) {
      (item as Asn1OctetString).value = Buffer.from(v);
    } else if (typeof v === 'string') {
      (item as unknown as Asn1String).value = v;
    }
    comp.add(item);
  }
  seq.set(name, comp);
}

export function principalToAsn1(principal: { type: number; components: string[] }): Asn1Sequence {
  const pn = PrincipalName();
  pn.set('name-type', principal.type);
  const nameString = pn.getComponent('name-string') as unknown as Asn1SequenceOf;
  for (const c of principal.components) {
    nameString.add(new KerberosString(c));
  }
  pn.set('name-string', nameString);
  return pn;
}

export function seqSetFlags(seq: Asn1Sequence, name: string, flags: number[]): void {
  const bits = Buffer.alloc(4);
  for (const f of flags) bits[Math.floor(f / 8)]! |= 1 << (7 - (f % 8));
  seq.set(name, bits);
}

export class Int32 extends Asn1Integer {}

export class UInt32 extends Asn1Integer {}

export class Microseconds extends Asn1Integer {}

export class KerberosString extends Asn1GeneralString {}

export class Realm extends KerberosString {}

export function PrincipalName(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('name-type', 0, new Int32()),
    sequenceComponent('name-string', 1, new Asn1SequenceOf(new KerberosString())),
  ];
  return s;
}

export class KerberosTime extends Asn1GeneralizedTime {}

export function HostAddress(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('addr-type', 0, new Int32()),
    sequenceComponent('address', 1, new Asn1OctetString()),
  ];
  return s;
}

export function HostAddresses(): Asn1SequenceOf {
  return new Asn1SequenceOf(HostAddress());
}

export function AuthorizationData(): Asn1SequenceOf {
  const element = new Asn1Sequence();
  element.components = [
    sequenceComponent('ad-type', 0, new Int32()),
    sequenceComponent('ad-data', 1, new Asn1OctetString()),
  ];
  return new Asn1SequenceOf(element);
}

export function PA_DATA(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('padata-type', 1, new Int32()),
    sequenceComponent('padata-value', 2, new Asn1OctetString()),
  ];
  return s;
}

export class KerberosFlags extends Asn1BitString {}

export function EncryptedData(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('etype', 0, new Int32()),
    sequenceOptionalComponent('kvno', 1, new UInt32()),
    sequenceComponent('cipher', 2, new Asn1OctetString()),
  ];
  return s;
}

export function EncryptionKey(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('keytype', 0, new Int32()),
    sequenceComponent('keyvalue', 1, new Asn1OctetString()),
  ];
  return s;
}

export function Checksum(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('cksumtype', 0, new Int32()),
    sequenceComponent('checksum', 1, new Asn1OctetString()),
  ];
  return s;
}

export function Ticket(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.tagging = applicationTag(1);
  s.components = [
    vnoComponent(0, 'tkt-vno'),
    sequenceComponent('realm', 1, new Realm()),
    sequenceComponent('sname', 2, PrincipalName()),
    sequenceComponent('enc-part', 3, EncryptedData()),
  ];
  return s;
}

export function TicketFlags(): KerberosFlags {
  return new KerberosFlags();
}

export function TransitedEncoding(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('tr-type', 0, new Int32()),
    sequenceComponent('contents', 1, new Asn1OctetString()),
  ];
  return s;
}

export function EncTicketPart(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.tagging = applicationTag(3);
  s.components = [
    sequenceComponent('flags', 0, new KerberosFlags()),
    sequenceComponent('key', 1, EncryptionKey()),
    sequenceComponent('crealm', 2, new Realm()),
    sequenceComponent('cname', 3, PrincipalName()),
    sequenceComponent('transited', 4, TransitedEncoding()),
    sequenceComponent('authtime', 5, new KerberosTime()),
    sequenceOptionalComponent('starttime', 6, new KerberosTime()),
    sequenceComponent('endtime', 7, new KerberosTime()),
    sequenceOptionalComponent('renew-till', 8, new KerberosTime()),
    sequenceOptionalComponent('caddr', 9, HostAddresses()),
    sequenceOptionalComponent('authorization-data', 10, AuthorizationData()),
  ];
  return s;
}

export function KDCOptions(): KerberosFlags {
  return new KerberosFlags();
}

export function KDC_REQ_BODY(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('kdc-options', 0, KDCOptions()),
    sequenceOptionalComponent('cname', 1, PrincipalName()),
    sequenceComponent('realm', 2, new Realm()),
    sequenceOptionalComponent('sname', 3, PrincipalName()),
    sequenceOptionalComponent('from', 4, new KerberosTime()),
    sequenceComponent('till', 5, new KerberosTime()),
    sequenceOptionalComponent('rtime', 6, new KerberosTime()),
    sequenceComponent('nonce', 7, new UInt32()),
    sequenceComponent('etype', 8, new Asn1SequenceOf(new Int32())),
    sequenceOptionalComponent('addresses', 9, HostAddresses()),
    sequenceOptionalComponent('enc-authorization-data', 10, EncryptedData()),
    sequenceOptionalComponent('additional-tickets', 11, new Asn1SequenceOf(Ticket())),
  ];
  return s;
}

export function KDC_REQ(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    vnoComponent(1),
    msgTypeComponent(2, []),
    sequenceOptionalComponent('padata', 3, new Asn1SequenceOf(PA_DATA())),
    sequenceComponent('req-body', 4, KDC_REQ_BODY()),
  ];
  return s;
}

export function AS_REQ(): Asn1Sequence {
  const s = KDC_REQ();
  s.tagging = applicationTag(10);
  return s;
}

export function TGS_REQ(): Asn1Sequence {
  const s = KDC_REQ();
  s.tagging = applicationTag(12);
  return s;
}

export function KDC_REP(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    vnoComponent(0),
    msgTypeComponent(1, []),
    sequenceOptionalComponent('padata', 2, new Asn1SequenceOf(PA_DATA())),
    sequenceComponent('crealm', 3, new Realm()),
    sequenceComponent('cname', 4, PrincipalName()),
    sequenceComponent('ticket', 5, Ticket()),
    sequenceComponent('enc-part', 6, EncryptedData()),
  ];
  return s;
}

export function LastReq(): Asn1SequenceOf {
  const element = new Asn1Sequence();
  element.components = [
    sequenceComponent('lr-type', 0, new Int32()),
    sequenceComponent('lr-value', 1, new KerberosTime()),
  ];
  return new Asn1SequenceOf(element);
}

export function METHOD_DATA(): Asn1SequenceOf {
  return new Asn1SequenceOf(PA_DATA());
}

export function EncKDCRepPart(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('key', 0, EncryptionKey()),
    sequenceComponent('last-req', 1, LastReq()),
    sequenceComponent('nonce', 2, new UInt32()),
    sequenceOptionalComponent('key-expiration', 3, new KerberosTime()),
    sequenceComponent('flags', 4, TicketFlags()),
    sequenceComponent('authtime', 5, new KerberosTime()),
    sequenceOptionalComponent('starttime', 6, new KerberosTime()),
    sequenceComponent('endtime', 7, new KerberosTime()),
    sequenceOptionalComponent('renew-till', 8, new KerberosTime()),
    sequenceComponent('srealm', 9, new Realm()),
    sequenceComponent('sname', 10, PrincipalName()),
    sequenceOptionalComponent('caddr', 11, HostAddresses()),
    sequenceOptionalComponent('encrypted_pa_data', 12, METHOD_DATA()),
  ];
  return s;
}

export function EncASRepPart(): Asn1Sequence {
  const s = EncKDCRepPart();
  s.tagging = applicationTag(25);
  return s;
}

export function EncTGSRepPart(): Asn1Sequence {
  const s = EncKDCRepPart();
  s.tagging = applicationTag(26);
  return s;
}

export function AS_REP(): Asn1Sequence {
  const s = KDC_REP();
  s.tagging = applicationTag(11);
  return s;
}

export function TGS_REP(): Asn1Sequence {
  const s = KDC_REP();
  s.tagging = applicationTag(13);
  return s;
}

export function APOptions(): KerberosFlags {
  return new KerberosFlags();
}

export function Authenticator(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.tagging = applicationTag(2);
  s.components = [
    vnoComponent(0, 'authenticator-vno'),
    sequenceComponent('crealm', 1, new Realm()),
    sequenceComponent('cname', 2, PrincipalName()),
    sequenceOptionalComponent('cksum', 3, Checksum()),
    sequenceComponent('cusec', 4, new Microseconds()),
    sequenceComponent('ctime', 5, new KerberosTime()),
    sequenceOptionalComponent('subkey', 6, EncryptionKey()),
    sequenceOptionalComponent('seq-number', 7, new UInt32()),
    sequenceOptionalComponent('authorization-data', 8, AuthorizationData()),
  ];
  return s;
}

export function AP_REQ(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.tagging = applicationTag(14);
  s.components = [
    vnoComponent(0),
    msgTypeComponent(1, [14]),
    sequenceComponent('ap-options', 2, APOptions()),
    sequenceComponent('ticket', 3, Ticket()),
    sequenceComponent('authenticator', 4, EncryptedData()),
  ];
  return s;
}

export function AP_REP(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.tagging = applicationTag(15);
  s.components = [
    vnoComponent(0),
    msgTypeComponent(1, [15]),
    sequenceComponent('enc-part', 2, EncryptedData()),
  ];
  return s;
}

export function EncAPRepPart(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.tagging = applicationTag(27);
  s.components = [
    sequenceComponent('ctime', 0, new KerberosTime()),
    sequenceComponent('cusec', 1, new Microseconds()),
    sequenceOptionalComponent('subkey', 2, EncryptionKey()),
    sequenceOptionalComponent('seq-number', 3, new UInt32()),
  ];
  return s;
}

export function KRB_SAFE_BODY(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('user-data', 0, new Asn1OctetString()),
    sequenceOptionalComponent('timestamp', 1, new KerberosTime()),
    sequenceOptionalComponent('usec', 2, new Microseconds()),
    sequenceOptionalComponent('seq-number', 3, new UInt32()),
    sequenceComponent('s-address', 4, HostAddress()),
    sequenceOptionalComponent('r-address', 5, HostAddress()),
  ];
  return s;
}

export function KRB_SAFE(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.tagging = applicationTag(20);
  s.components = [
    vnoComponent(0),
    msgTypeComponent(1, [20]),
    sequenceComponent('safe-body', 2, KRB_SAFE_BODY()),
    sequenceComponent('cksum', 3, Checksum()),
  ];
  return s;
}

export function KRB_PRIV(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.tagging = applicationTag(21);
  s.components = [
    vnoComponent(0),
    msgTypeComponent(1, [21]),
    sequenceComponent('enc-part', 3, EncryptedData()),
  ];
  return s;
}

export function EncKrbPrivPart(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.tagging = applicationTag(28);
  s.components = [
    sequenceComponent('user-data', 0, new Asn1OctetString()),
    sequenceOptionalComponent('timestamp', 1, new KerberosTime()),
    sequenceOptionalComponent('cusec', 2, new Microseconds()),
    sequenceOptionalComponent('seq-number', 3, new UInt32()),
    sequenceComponent('s-address', 4, HostAddress()),
    sequenceOptionalComponent('r-address', 5, HostAddress()),
  ];
  return s;
}

export function KRB_CRED(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.tagging = applicationTag(22);
  s.components = [
    vnoComponent(0),
    msgTypeComponent(1, [22]),
    sequenceOptionalComponent('tickets', 2, new Asn1SequenceOf(Ticket())),
    sequenceComponent('enc-part', 3, EncryptedData()),
  ];
  return s;
}

export function KrbCredInfo(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('key', 0, EncryptionKey()),
    sequenceOptionalComponent('prealm', 1, new Realm()),
    sequenceOptionalComponent('pname', 2, PrincipalName()),
    sequenceOptionalComponent('flags', 3, TicketFlags()),
    sequenceOptionalComponent('authtime', 4, new KerberosTime()),
    sequenceOptionalComponent('starttime', 5, new KerberosTime()),
    sequenceOptionalComponent('endtime', 6, new KerberosTime()),
    sequenceOptionalComponent('renew-till', 7, new KerberosTime()),
    sequenceOptionalComponent('srealm', 8, new Realm()),
    sequenceOptionalComponent('sname', 9, PrincipalName()),
    sequenceOptionalComponent('caddr', 10, HostAddresses()),
  ];
  return s;
}

export function EncKrbCredPart(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.tagging = applicationTag(29);
  s.components = [
    sequenceComponent('ticket-info', 0, new Asn1SequenceOf(KrbCredInfo())),
    sequenceOptionalComponent('nonce', 1, new UInt32()),
    sequenceOptionalComponent('timestamp', 2, new KerberosTime()),
    sequenceOptionalComponent('usec', 3, new Microseconds()),
    sequenceOptionalComponent('s-address', 4, HostAddress()),
    sequenceOptionalComponent('r-address', 5, HostAddress()),
  ];
  return s;
}

export function KRB_ERROR(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.tagging = applicationTag(30);
  s.components = [
    vnoComponent(0),
    msgTypeComponent(1, [30]),
    sequenceOptionalComponent('ctime', 2, new KerberosTime()),
    sequenceOptionalComponent('cusec', 3, new Microseconds()),
    sequenceComponent('stime', 4, new KerberosTime()),
    sequenceComponent('susec', 5, new Microseconds()),
    sequenceComponent('error-code', 6, new Int32()),
    sequenceOptionalComponent('crealm', 7, new Realm()),
    sequenceOptionalComponent('cname', 8, PrincipalName()),
    sequenceComponent('realm', 9, new Realm()),
    sequenceComponent('sname', 10, PrincipalName()),
    sequenceOptionalComponent('e-text', 11, new KerberosString()),
    sequenceOptionalComponent('e-data', 12, new Asn1OctetString()),
  ];
  return s;
}

export function TYPED_DATA(): Asn1SequenceOf {
  const element = new Asn1Sequence();
  element.components = [
    sequenceComponent('data-type', 0, new Int32()),
    sequenceOptionalComponent('data-value', 1, new Asn1OctetString()),
  ];
  return new Asn1SequenceOf(element);
}

export function PA_ENC_TIMESTAMP(): Asn1Sequence {
  return EncryptedData();
}

export function PA_ENC_TS_ENC(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('patimestamp', 0, new KerberosTime()),
    sequenceOptionalComponent('pausec', 1, new Microseconds()),
  ];
  return s;
}

export function ETYPE_INFO_ENTRY(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('etype', 0, new Int32()),
    sequenceOptionalComponent('salt', 1, new Asn1OctetString()),
  ];
  return s;
}

export function ETYPE_INFO(): Asn1SequenceOf {
  return new Asn1SequenceOf(ETYPE_INFO_ENTRY());
}

export function ETYPE_INFO2_ENTRY(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('etype', 0, new Int32()),
    sequenceOptionalComponent('salt', 1, new KerberosString()),
    sequenceOptionalComponent('s2kparams', 2, new Asn1OctetString()),
  ];
  return s;
}

export function ETYPE_INFO2(): Asn1SequenceOf {
  return new Asn1SequenceOf(ETYPE_INFO2_ENTRY());
}

export function AD_IF_RELEVANT(): Asn1SequenceOf {
  return AuthorizationData();
}

export function AD_KDCIssued(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('ad-checksum', 0, Checksum()),
    sequenceOptionalComponent('i-realm', 1, new Realm()),
    sequenceOptionalComponent('i-sname', 2, PrincipalName()),
    sequenceComponent('elements', 3, AuthorizationData()),
  ];
  return s;
}

export function AD_AND_OR(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('condition-count', 0, new Int32()),
    sequenceOptionalComponent('elements', 1, AuthorizationData()),
  ];
  return s;
}

export function AD_MANDATORY_FOR_KDC(): Asn1SequenceOf {
  return AuthorizationData();
}

export function KERB_PA_PAC_REQUEST(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    {
      name: 'include-pac',
      node: new Asn1Boolean(),
      optional: false,
      tagging: explicitTag(0),
    },
  ];
  return s;
}

export function PA_FOR_USER_ENC(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('userName', 0, PrincipalName()),
    sequenceOptionalComponent('userRealm', 1, new Realm()),
    sequenceOptionalComponent('cksum', 2, Checksum()),
    sequenceOptionalComponent('auth-package', 3, new KerberosString()),
  ];
  return s;
}

export function KERB_ERROR_DATA(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('data-type', 1, new Int32()),
    sequenceComponent('data-value', 2, new Asn1OctetString()),
  ];
  return s;
}

export function PA_PAC_OPTIONS(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [sequenceComponent('flags', 0, new KerberosFlags())];
  return s;
}

export function KERB_KEY_LIST_REQ(): Asn1SequenceOf {
  return new Asn1SequenceOf(new Int32());
}

export function KERB_KEY_LIST_REP(): Asn1SequenceOf {
  return new Asn1SequenceOf(EncryptionKey());
}

export function KERB_SUPERSEDED_BY_USER(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('name', 0, PrincipalName()),
    sequenceOptionalComponent('userRealm', 1, new Realm()),
  ];
  return s;
}

export function S4UUserID(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('nonce', 0, new UInt32()),
    sequenceComponent('cname', 1, PrincipalName()),
    sequenceOptionalComponent('crealm', 2, new Realm()),
    sequenceOptionalComponent('subject-certificate', 3, new Asn1OctetString()),
    sequenceOptionalComponent('options', 4, new KerberosFlags()),
  ];
  return s;
}

export function PA_S4U_X509_USER(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    {
      name: 'user-id',
      node: S4UUserID(),
      optional: false,
      tagging: { explicit: true, implicit: false, tag: 0, cls: TagClass.CONTEXT },
    },
    {
      name: 'checksum',
      node: Checksum(),
      optional: false,
      tagging: { explicit: true, implicit: false, tag: 1, cls: TagClass.CONTEXT },
    },
  ];
  return s;
}

export function KERB_DMSA_KEY_PACKAGE(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('current-keys', 0, new Asn1SequenceOf(EncryptionKey())),
    sequenceOptionalComponent('previous-keys', 1, new Asn1SequenceOf(EncryptionKey())),
    sequenceComponent('effective-time', 2, new KerberosTime()),
    sequenceOptionalComponent('reserved', 3, new Asn1OctetString()),
    sequenceComponent('expiration-time', 4, new KerberosTime()),
  ];
  return s;
}

export function ChangePasswdData(): Asn1Sequence {
  const s = new Asn1Sequence();
  s.components = [
    sequenceComponent('newpasswd', 0, new Asn1OctetString()),
    sequenceOptionalComponent('targname', 1, PrincipalName()),
    sequenceOptionalComponent('targrealm', 2, new Realm()),
  ];
  return s;
}
