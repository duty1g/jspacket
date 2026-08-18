/**
 * @impacket/asn1 — ASN.1 DER encoder/decoder + schema layer
 *
 * Replaces pyasn1 for the impacket-js port. Impacket's krb5/asn1.py, ldapasn1.py,
 * spnego.py, and negoex.py all build on pyasn1's declarative schema API:
 *   - Sequence/Set with named, tagged components (context/explicit/implicit)
 *   - Integer, OctetString, BitString, GeneralString, GeneralizedTime, OID
 *   - Optional components and union constraints
 *
 * This package mirrors that with a small, faithful codec. DER (Distinguished
 * Encoding Rules) is used — definite-length, minimal encoding.
 *
 * Tag classes:
 *   0x00 universal    0x40 application   0x80 context   0xc0 private
 *
 * Tag forms:
 *   0x00 primitive    0x20 constructed
 *
 * Universal tag numbers:
 *   1 BOOLEAN  2 INTEGER  3 BIT STRING  4 OCTET STRING  5 NULL  6 OID
 *   10 ENUMERATED  12 UTF8String  16 SEQUENCE  17 SET
 *   19 PrintableString  20 TeletexString  22 IA5String
 *   23 UTCTime  24 GeneralizedTime  26 VisibleString  27 GeneralString
 */

import { Buffer } from 'node:buffer';

export enum TagClass {
  UNIVERSAL = 0x00,
  APPLICATION = 0x40,
  CONTEXT = 0x80,
  PRIVATE = 0xc0,
}

export enum TagForm {
  PRIMITIVE = 0x00,
  CONSTRUCTED = 0x20,
}

export const UNIVERSAL = {
  BOOLEAN: 1,
  INTEGER: 2,
  BIT_STRING: 3,
  OCTET_STRING: 4,
  NULL: 5,
  OID: 6,
  ENUMERATED: 10,
  UTF8_STRING: 12,
  SEQUENCE: 16,
  SET: 17,
  PRINTABLE_STRING: 19,
  TELETEX_STRING: 20,
  IA5_STRING: 22,
  UTC_TIME: 23,
  GENERALIZED_TIME: 24,
  VISIBLE_STRING: 26,
  GENERAL_STRING: 27,
} as const;

/** A decoded TLV. */
export interface TLV {
  cls: TagClass;
  constructed: boolean;
  tag: number;
  value: Buffer;
  /** byte offset of the start of the value in the original buffer */
  offset: number;
  /** total byte length of the whole TLV (tag+len+value) */
  totalLength: number;
}

/** Encode a tag byte (single or multi-byte for tag numbers >= 31). */
function encodeTag(cls: TagClass, constructed: boolean, tag: number): Buffer {
  const form = constructed ? TagForm.CONSTRUCTED : TagForm.PRIMITIVE;
  if (tag < 31) {
    return Buffer.from([cls | form | tag]);
  }
  // long form: first byte = cls|form|0x1f, then base-128 big-endian, last byte high bit 0
  const bytes: number[] = [tag & 0x7f];
  tag >>= 7;
  while (tag > 0) {
    bytes.unshift((tag & 0x7f) | 0x80);
    tag >>= 7;
  }
  return Buffer.concat([Buffer.from([cls | form | 0x1f]), Buffer.from(bytes)]);
}

/** Encode DER length (short form < 128, long form otherwise). */
function encodeLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.concat([Buffer.from([0x80 | bytes.length]), Buffer.from(bytes)]);
}

/** Decode a tag starting at `offset`; returns [tagValue, tagByteLen, constructed]. */
function decodeTag(buf: Buffer, offset: number): [number, number, boolean, TagClass] {
  const first = buf[offset]!;
  const cls = (first & 0xc0) as TagClass;
  const constructed = (first & 0x20) !== 0;
  const low5 = first & 0x1f;
  if (low5 < 0x1f) return [low5, 1, constructed, cls];
  let tag = 0;
  let i = 1;
  let b = buf[offset + i]!;
  do {
    tag = (tag << 7) | (b & 0x7f);
    i++;
    if (b & 0x80) b = buf[offset + i]!;
  } while (b & 0x80);
  return [tag, i, constructed, cls];
}

/** Decode a DER length starting at `offset`; returns [length, byteLen].
 *  Supports indefinite length (0x80) by scanning for end-of-contents (0x00 0x00). */
function decodeLength(buf: Buffer, offset: number): [number, number] {
  const first = buf[offset]!;
  if (first < 0x80) return [first, 1];
  const n = first & 0x7f;
  if (n === 0) {
    let end = offset + 1;
    let depth = 1;
    while (end < buf.length && depth > 0) {
      if (buf[end] === 0x00 && buf[end + 1] === 0x00) {
        depth--;
        end += 2;
      } else {
        const [, tagLen] = decodeTag(buf, end);
        const [innerLen, innerLenBytes] = decodeLength(buf, end + tagLen);
        if (innerLen >= 0) {
          end += tagLen + innerLenBytes + innerLen;
        } else {
          end += tagLen + innerLenBytes;
        }
        depth++;
      }
    }
    return [end - offset - 1, 1];
  }
  let len = 0;
  for (let i = 1; i <= n; i++) len = (len << 8) | buf[offset + i]!;
  return [len, n + 1];
}

/** Parse a single TLV from `buf` at `offset`. */
export function parseTLV(buf: Buffer, offset = 0): TLV {
  const [tag, tagLen, constructed, cls] = decodeTag(buf, offset);
  const [len, lenLen] = decodeLength(buf, offset + tagLen);
  const valueStart = offset + tagLen + lenLen;
  return {
    cls,
    constructed,
    tag,
    value: buf.subarray(valueStart, valueStart + len),
    offset: valueStart,
    totalLength: tagLen + lenLen + len,
  };
}

/** Parse all TLVs in a constructed value. */
export function parseTLVs(buf: Buffer): TLV[] {
  const out: TLV[] = [];
  let off = 0;
  while (off < buf.length) {
    const tlv = parseTLV(buf, off);
    out.push(tlv);
    off += tlv.totalLength;
  }
  return out;
}

/** Encode a complete TLV. */
export function encodeTLV(cls: TagClass, constructed: boolean, tag: number, value: Buffer): Buffer {
  return Buffer.concat([encodeTag(cls, constructed, tag), encodeLength(value.length), value]);
}

// ---------------------------------------------------------------------------
// Universal value encoders/decoders
// ---------------------------------------------------------------------------

/** INTEGER (two's complement, big-endian, minimal). */
export function encodeInteger(value: number | bigint): Buffer {
  const n = BigInt(value);
  if (n === 0n) return Buffer.from([0]);
  const bytes: number[] = [];
  if (n < 0n) {
    // Find minimal byte width w such that -2^(8w-1) <= n, then encode as 2^(8w) + n.
    let width = 1;
    while (-(1n << BigInt(8 * width - 1)) > n) width++;
    const v = (1n << BigInt(8 * width)) + n;
    let m = v;
    for (let i = 0; i < width; i++) {
      bytes.unshift(Number(m & 0xffn));
      m >>= 8n;
    }
  } else {
    let m = n;
    while (m > 0n) {
      bytes.unshift(Number(m & 0xffn));
      m >>= 8n;
    }
    if (bytes[0]! & 0x80) bytes.unshift(0);
  }
  return Buffer.from(bytes);
}

export function decodeInteger(buf: Buffer): bigint {
  if (buf.length === 0) return 0n;
  let n = BigInt(buf[0]! & 0x80 ? -1 : 0);
  for (const b of buf) n = (n << 8n) | BigInt(b);
  return n;
}

export function encodeIntegerNumber(value: number): number {
  return Number(decodeInteger(encodeInteger(value)));
}

/** BOOLEAN. */
export function encodeBoolean(value: boolean): Buffer {
  return Buffer.from([value ? 0xff : 0x00]);
}
export function decodeBoolean(buf: Buffer): boolean {
  return buf.length > 0 && buf[0] !== 0;
}

/** OCTET STRING. */
export function encodeOctetString(value: Buffer | string): Buffer {
  return Buffer.isBuffer(value) ? value : Buffer.from(value, 'latin1');
}
export function decodeOctetString(buf: Buffer): Buffer {
  return buf;
}

/** BIT STRING — first byte is the number of unused bits in the last byte. */
export function encodeBitString(bits: Buffer, unusedBits = 0): Buffer {
  return Buffer.concat([Buffer.from([unusedBits]), bits]);
}
export function decodeBitString(buf: Buffer): { bits: Buffer; unusedBits: number } {
  return { bits: buf.subarray(1), unusedBits: buf[0] ?? 0 };
}

/** NULL. */
export function encodeNull(): Buffer {
  return Buffer.alloc(0);
}

/** OBJECT IDENTIFIER. */
export function encodeOID(dots: string): Buffer {
  const parts = dots.split('.').map((s) => Number.parseInt(s, 10));
  if (parts.length < 2) throw new Error('OID must have at least 2 components');
  const out: number[] = [parts[0]! * 40 + parts[1]!];
  for (let i = 2; i < parts.length; i++) {
    let n = parts[i]!;
    const bytes: number[] = [n & 0x7f];
    n >>= 7;
    while (n > 0) {
      bytes.unshift((n & 0x7f) | 0x80);
      n >>= 7;
    }
    out.push(...bytes);
  }
  return Buffer.from(out);
}

export function decodeOID(buf: Buffer): string {
  if (buf.length === 0) return '';
  const parts: number[] = [];
  const first = buf[0]!;
  parts.push(Math.floor(first / 40));
  parts.push(first % 40);
  let n = 0;
  for (let i = 1; i < buf.length; i++) {
    n = (n << 7) | (buf[i]! & 0x7f);
    if ((buf[i]! & 0x80) === 0) {
      parts.push(n);
      n = 0;
    }
  }
  return parts.join('.');
}

/** ENUMERATED — same encoding as INTEGER. */
export const encodeEnumerated = encodeInteger;
export const decodeEnumerated = decodeInteger;

/** GeneralString / PrintableString / IA5String / UTF8String. */
export function encodeString(value: string, encoding: BufferEncoding = 'latin1'): Buffer {
  return Buffer.from(value, encoding);
}
export function decodeString(buf: Buffer, encoding: BufferEncoding = 'latin1'): string {
  return buf.toString(encoding);
}

/** UTCTime: YYMMDDHHMMSSZ. */
export function encodeUTCTime(d: Date): Buffer {
  const pad = (n: number, w = 2) => String(n).padStart(w, '0');
  const yy = d.getUTCFullYear() % 100;
  return Buffer.from(
    `${pad(yy)}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}` +
      `${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`,
    'ascii',
  );
}
export function decodeUTCTime(buf: Buffer): Date {
  const s = buf.toString('ascii');
  const yy = Number.parseInt(s.slice(0, 2), 10);
  const year = yy < 50 ? 2000 + yy : 1900 + yy;
  const mo = Number.parseInt(s.slice(2, 4), 10) - 1;
  const dd = Number.parseInt(s.slice(4, 6), 10);
  const hh = Number.parseInt(s.slice(6, 8), 10);
  const mi = Number.parseInt(s.slice(8, 10), 10);
  const ss = s.length >= 12 ? Number.parseInt(s.slice(10, 12), 10) : 0;
  return new Date(Date.UTC(year, mo, dd, hh, mi, ss));
}

/** GeneralizedTime: YYYYMMDDHHMMSSZ. */
export function encodeGeneralizedTime(d: Date): Buffer {
  const pad = (n: number, w = 2) => String(n).padStart(w, '0');
  return Buffer.from(
    `${pad(d.getUTCFullYear(), 4)}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}` +
      `${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`,
    'ascii',
  );
}
export function decodeGeneralizedTime(buf: Buffer): Date {
  const s = buf.toString('ascii');
  const y = Number.parseInt(s.slice(0, 4), 10);
  const mo = Number.parseInt(s.slice(4, 6), 10) - 1;
  const d = Number.parseInt(s.slice(6, 8), 10);
  const h = Number.parseInt(s.slice(8, 10), 10);
  const mi = Number.parseInt(s.slice(10, 12), 10);
  const ss = s.length >= 14 ? Number.parseInt(s.slice(12, 14), 10) : 0;
  return new Date(Date.UTC(y, mo, d, h, mi, ss));
}

// ---------------------------------------------------------------------------
// Schema layer — mirrors pyasn1's Sequence/Set/NamedType API
// ---------------------------------------------------------------------------

export type AnyValue =
  | Buffer
  | bigint
  | number
  | boolean
  | string
  | Date
  | null
  | Asn1Node
  | AnyValue[]
  | { oid: string };

/** Tagging mode for a component. */
export interface TaggingMode {
  cls?: TagClass;
  /** explicit tagging (default) — wraps the inner value in an extra tag */
  explicit?: boolean;
  /** implicit tagging — replaces the inner tag */
  implicit?: boolean;
  tag: number;
}

/** Base ASN.1 node type. */
export abstract class Asn1Node {
  abstract cls: TagClass;
  abstract constructed: boolean;
  abstract tag: number;
  /** Encoding/decoding tag override (for explicit/implicit tagging). */
  tagging?: TaggingMode;
  optional = false;
  default?: AnyValue;

  /** Encode this node's value (without tagging wrapper). */
  abstract encodeValue(): Buffer;
  /** Decode this node's value from a TLV value. */
  abstract decodeValue(value: Buffer): AnyValue | Record<string, AnyValue>;

  /** Encode the full TLV including any tagging wrapper. */
  encode(): Buffer {
    const inner = this.encodeValue();
    const body = this.constructed ? inner : inner;
    if (this.tagging) {
      const t = this.tagging;
      if (t.implicit) {
        // implicit: replace the tag
        return encodeTLV(t.cls ?? TagClass.CONTEXT, this.constructed, t.tag, inner);
      }
      // explicit: wrap with an extra tag
      const innerTLV = encodeTLV(this.cls, this.constructed, this.tag, inner);
      return encodeTLV(t.cls ?? TagClass.CONTEXT, true, t.tag, innerTLV);
    }
    return encodeTLV(this.cls, this.constructed, this.tag, body);
  }

  /** Decode from a TLV (handling tagging wrappers). */
  decode(buf: Buffer): AnyValue {
    let tlv = parseTLV(buf);
    if (this.tagging) {
      if (this.tagging.explicit === false || this.tagging.implicit) {
        // implicit: the tlv value is our value
      } else {
        // explicit: unwrap one layer
        tlv = parseTLV(tlv.value);
      }
    }
    return this.decodeValue(tlv.value) as AnyValue;
  }
}

/** INTEGER node. */
export class Asn1Integer extends Asn1Node {
  cls = TagClass.UNIVERSAL;
  constructed = false;
  tag: number = UNIVERSAL.INTEGER;
  value: bigint | number = 0n;
  constructor(v?: bigint | number) {
    super();
    if (v !== undefined) this.value = v;
  }
  set(v: bigint | number): this {
    this.value = v;
    return this;
  }
  encodeValue(): Buffer {
    return encodeInteger(this.value);
  }
  decodeValue(buf: Buffer): bigint {
    const v = decodeInteger(buf);
    this.value = v;
    return v;
  }
  get(): bigint {
    return typeof this.value === 'bigint' ? this.value : BigInt(this.value);
  }
}

/** BOOLEAN node. */
export class Asn1Boolean extends Asn1Node {
  cls = TagClass.UNIVERSAL;
  constructed = false;
  tag = UNIVERSAL.BOOLEAN;
  value = false;
  constructor(v?: boolean) {
    super();
    if (v !== undefined) this.value = v;
  }
  encodeValue(): Buffer {
    return encodeBoolean(this.value);
  }
  decodeValue(buf: Buffer): boolean {
    return decodeBoolean(buf);
  }
}

/** OCTET STRING node. */
export class Asn1OctetString extends Asn1Node {
  cls = TagClass.UNIVERSAL;
  constructed = false;
  tag = UNIVERSAL.OCTET_STRING;
  value = Buffer.alloc(0);
  encoding: BufferEncoding = 'latin1';
  constructor(v?: Buffer | string) {
    super();
    if (v !== undefined)
      this.value = typeof v === 'string' ? Buffer.from(v, this.encoding) : Buffer.from(v);
  }
  encodeValue(): Buffer {
    return this.value;
  }
  decodeValue(buf: Buffer): Buffer {
    this.value = Buffer.from(buf);
    return buf;
  }
}

/** GeneralString / PrintableString / IA5String / UTF8String node. */
export class Asn1String extends Asn1Node {
  cls = TagClass.UNIVERSAL;
  constructed = false;
  tag: number = UNIVERSAL.GENERAL_STRING;
  value = '';
  encoding: BufferEncoding = 'latin1';
  constructor(
    v?: string,
    tag: number = UNIVERSAL.GENERAL_STRING,
    encoding: BufferEncoding = 'latin1',
  ) {
    super();
    this.tag = tag;
    this.encoding = encoding;
    if (v !== undefined) this.value = v;
  }
  encodeValue(): Buffer {
    return encodeString(this.value, this.encoding);
  }
  decodeValue(buf: Buffer): string {
    this.value = decodeString(buf, this.encoding);
    return this.value;
  }
}

export class Asn1GeneralString extends Asn1String {
  constructor(v?: string) {
    super(v, UNIVERSAL.GENERAL_STRING, 'latin1');
  }
}
export class Asn1PrintableString extends Asn1String {
  constructor(v?: string) {
    super(v, UNIVERSAL.PRINTABLE_STRING, 'latin1');
  }
}
export class Asn1IA5String extends Asn1String {
  constructor(v?: string) {
    super(v, UNIVERSAL.IA5_STRING, 'latin1');
  }
}
export class Asn1UTF8String extends Asn1String {
  constructor(v?: string) {
    super(v, UNIVERSAL.UTF8_STRING, 'utf8');
  }
}

/** BIT STRING node. */
export class Asn1BitString extends Asn1Node {
  cls = TagClass.UNIVERSAL;
  constructed = false;
  tag = UNIVERSAL.BIT_STRING;
  value = Buffer.alloc(0);
  unusedBits = 0;
  constructor(v?: Buffer) {
    super();
    if (v !== undefined) this.value = Buffer.from(v);
  }
  encodeValue(): Buffer {
    return encodeBitString(this.value, this.unusedBits);
  }
  decodeValue(buf: Buffer): Buffer {
    const r = decodeBitString(buf);
    this.value = Buffer.from(r.bits);
    this.unusedBits = r.unusedBits;
    return r.bits;
  }
}

/** NULL node. */
export class Asn1Null extends Asn1Node {
  cls = TagClass.UNIVERSAL;
  constructed = false;
  tag = UNIVERSAL.NULL;
  encodeValue(): Buffer {
    return encodeNull();
  }
  decodeValue(): null {
    return null;
  }
}

/** OID node. */
export class Asn1OID extends Asn1Node {
  cls = TagClass.UNIVERSAL;
  constructed = false;
  tag = UNIVERSAL.OID;
  value = '';
  constructor(v?: string) {
    super();
    if (v !== undefined) this.value = v;
  }
  encodeValue(): Buffer {
    return encodeOID(this.value);
  }
  decodeValue(buf: Buffer): string {
    this.value = decodeOID(buf);
    return this.value;
  }
}

/** ENUMERATED node. */
export class Asn1Enumerated extends Asn1Integer {
  tag: number = UNIVERSAL.ENUMERATED;
}

/** GeneralizedTime node. */
export class Asn1GeneralizedTime extends Asn1Node {
  cls = TagClass.UNIVERSAL;
  constructed = false;
  tag = UNIVERSAL.GENERALIZED_TIME;
  value: Date = new Date(0);
  constructor(v?: Date) {
    super();
    if (v !== undefined) this.value = v;
  }
  encodeValue(): Buffer {
    return encodeGeneralizedTime(this.value);
  }
  decodeValue(buf: Buffer): Date {
    this.value = decodeGeneralizedTime(buf);
    return this.value;
  }
}

/** UTCTime node. */
export class Asn1UTCTime extends Asn1Node {
  cls = TagClass.UNIVERSAL;
  constructed = false;
  tag = UNIVERSAL.UTC_TIME;
  value: Date = new Date(0);
  constructor(v?: Date) {
    super();
    if (v !== undefined) this.value = v;
  }
  encodeValue(): Buffer {
    return encodeUTCTime(this.value);
  }
  decodeValue(buf: Buffer): Date {
    this.value = decodeUTCTime(buf);
    return this.value;
  }
}

/** Any node — stores raw TLV bytes (used for opaque fields). */
export class Asn1Any extends Asn1Node {
  cls = TagClass.UNIVERSAL;
  constructed = false;
  tag = 0;
  value = Buffer.alloc(0);
  encodeValue(): Buffer {
    return this.value;
  }
  decodeValue(buf: Buffer): Buffer {
    this.value = Buffer.from(buf);
    return buf;
  }
  decode(buf: Buffer): Buffer {
    this.value = Buffer.from(buf);
    return buf;
  }
}

/** A named component in a Sequence/Set. */
export interface NamedComponent {
  name: string;
  node: Asn1Node;
  optional?: boolean;
  default?: AnyValue;
  tagging?: TaggingMode;
}

/** Sequence / Set node. */
export class Asn1Sequence extends Asn1Node {
  cls = TagClass.UNIVERSAL;
  constructed = true;
  tag: number = UNIVERSAL.SEQUENCE;
  components: NamedComponent[] = [];
  /** Stored child values, keyed by name. */
  values: Record<string, AnyValue> = {};
  /** When set, encode() returns these raw DER bytes instead of re-encoding from values. */
  _rawData: Buffer | null = null;

  addComponent(
    name: string,
    node: Asn1Node,
    opts?: { optional?: boolean; default?: AnyValue; tagging?: TaggingMode },
  ): this {
    this.components.push({
      name,
      node,
      optional: opts?.optional,
      default: opts?.default,
      tagging: opts?.tagging,
    });
    return this;
  }

  set(name: string, value: AnyValue): this {
    this.values[name] = value;
    return this;
  }
  get(name: string): AnyValue | undefined {
    return this.values[name];
  }
  getComponent(name: string): Asn1Node {
    const c = this.components.find((c) => c.name === name);
    if (!c) throw new Error(`Component '${name}' not found`);
    return cloneNode(c.node);
  }

  encodeValue(): Buffer {
    const parts: Buffer[] = [];
    for (const c of this.components) {
      const v = this.values[c.name];
      if (v === undefined) {
        if (c.default !== undefined) continue;
        if (c.optional) continue;
        const clone = cloneNode(c.node);
        const encoded = clone.encode();
        if (c.tagging && c.tagging.explicit !== false && !c.tagging.implicit) {
          parts.push(encodeTLV(c.tagging.cls ?? TagClass.CONTEXT, true, c.tagging.tag, encoded));
        } else {
          parts.push(encoded);
        }
        continue;
      }
      const child = cloneNode(c.node);
      setNodeValue(child, v);
      const encoded = child.encode();
      if (c.tagging && c.tagging.explicit !== false && !c.tagging.implicit) {
        parts.push(encodeTLV(c.tagging.cls ?? TagClass.CONTEXT, true, c.tagging.tag, encoded));
      } else {
        if (c.tagging) child.tagging = c.tagging;
        parts.push(child.encode());
      }
    }
    return Buffer.concat(parts);
  }

  decodeValue(buf: Buffer): Record<string, AnyValue> {
    const tlvs = parseTLVs(buf);
    const used = new Array<boolean>(tlvs.length).fill(false);
    for (const c of this.components) {
      const tagNum = componentTagNumber(c);
      let matchedIdx = -1;
      if (tagNum !== undefined) {
        const wantCls = c.tagging?.cls ?? TagClass.CONTEXT;
        for (let j = 0; j < tlvs.length; j++) {
          if (!used[j] && tlvs[j]!.cls === wantCls && tlvs[j]!.tag === tagNum) {
            matchedIdx = j;
            break;
          }
        }
      } else {
        for (let j = 0; j < tlvs.length; j++) {
          if (!used[j]) {
            matchedIdx = j;
            break;
          }
        }
      }
      if (matchedIdx === -1) {
        if (c.optional || c.default !== undefined) continue;
        throw new Error(`Missing required component '${c.name}'`);
      }
      used[matchedIdx] = true;
      const child = cloneNode(c.node);
      const matchedTlv = tlvs[matchedIdx]!;
      if (c.tagging && c.tagging.explicit !== false && !c.tagging.implicit) {
        const v = child.decode(matchedTlv.value);
        this.values[c.name] = v as AnyValue;
      } else if (c.tagging && c.tagging.implicit) {
        const fullTLV = reconstructTLV(matchedTlv);
        child.tagging = c.tagging;
        const v = child.decode(fullTLV);
        this.values[c.name] = v as AnyValue;
      } else {
        const fullTLV = reconstructTLV(matchedTlv);
        const v = child.decode(fullTLV);
        this.values[c.name] = v as AnyValue;
      }
    }
    return this.values;
  }

  encode(): Buffer {
    if (this._rawData) return this._rawData;
    return Asn1Node.prototype.encode.call(this);
  }
}

/** Reconstruct the original DER bytes of a parsed TLV. */
function reconstructTLV(tlv: TLV): Buffer {
  return encodeTLV(tlv.cls, tlv.constructed, tlv.tag, tlv.value);
}

/** Extract the effective tag number from a component's tagging mode. */
function componentTagNumber(c: NamedComponent): number | undefined {
  if (c.tagging) return c.tagging.tag;
  return undefined;
}

/** Set node — same as Sequence but with SET tag. */
export class Asn1Set extends Asn1Sequence {
  tag: number = UNIVERSAL.SET;
}

/** SEQUENCE OF — homogeneous sequence of `elementNode`. */
export class Asn1SequenceOf extends Asn1Node {
  cls = TagClass.UNIVERSAL;
  constructed = true;
  tag: number = UNIVERSAL.SEQUENCE;
  elementNode: Asn1Node;
  items: Asn1Node[] = [];

  constructor(elementNode: Asn1Node) {
    super();
    this.elementNode = elementNode;
  }

  add(item: Asn1Node): this {
    this.items.push(item);
    return this;
  }

  encodeValue(): Buffer {
    return Buffer.concat(this.items.map((i) => i.encode()));
  }

  decodeValue(buf: Buffer): Asn1Node[] {
    const tlvs = parseTLVs(buf);
    this.items = tlvs.map((tlv) => {
      const child = cloneNode(this.elementNode);
      child.decode(reconstructTLV(tlv));
      return child;
    });
    return this.items;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function cloneNode(node: Asn1Node): Asn1Node {
  if (node instanceof Asn1SequenceOf) {
    const clone = new Asn1SequenceOf(node.elementNode);
    clone.tag = node.tag;
    clone.cls = node.cls;
    clone.constructed = node.constructed;
    clone.tagging = node.tagging;
    return clone;
  }
  const Ctor = node.constructor as new () => Asn1Node;
  const clone = new Ctor();
  clone.tag = node.tag;
  clone.cls = node.cls;
  clone.constructed = node.constructed;
  clone.tagging = node.tagging;
  if (node instanceof Asn1Sequence && clone instanceof Asn1Sequence) {
    clone.components = node.components;
  }
  return clone;
}

function setNodeValue(node: Asn1Node, value: AnyValue): void {
  // Buffer generic variance (ArrayBuffer vs ArrayBufferLike) is handled via any.
  if (node instanceof Asn1Integer) node.value = value as bigint | number;
  else if (node instanceof Asn1Boolean) node.value = value as boolean;
  else if (node instanceof Asn1OctetString) (node as { value: Buffer }).value = value as Buffer;
  else if (node instanceof Asn1String) node.value = value as string;
  else if (node instanceof Asn1BitString) (node as { value: Buffer }).value = value as Buffer;
  else if (node instanceof Asn1OID) node.value = value as string;
  else if (node instanceof Asn1GeneralizedTime) node.value = value as Date;
  else if (node instanceof Asn1UTCTime) node.value = value as Date;
  else if (node instanceof Asn1Any) (node as { value: Buffer }).value = value as Buffer;
  else if (node instanceof Asn1SequenceOf) {
    if (value instanceof Asn1SequenceOf) {
      (node as Asn1SequenceOf).items = value.items;
    } else if (Array.isArray(value)) {
      (node as Asn1SequenceOf).items = value as Asn1Node[];
    }
  }
  else if (node instanceof Asn1Sequence) {
    if (value instanceof Asn1Sequence) {
      node.values = { ...(value as Asn1Sequence).values };
      if ((value as Asn1Sequence)._rawData) node._rawData = (value as Asn1Sequence)._rawData;
    } else {
      const v = value as Record<string, AnyValue>;
      for (const k of Object.keys(v)) node.values[k] = v[k]!;
    }
  }
}

/** Explicit context tag helper (mirrors pyasn1 explicitTag). */
export function explicitTag(tag: number, cls: TagClass = TagClass.CONTEXT): TaggingMode {
  return { explicit: true, implicit: false, tag, cls };
}

/** Implicit context tag helper (mirrors pyasn1 implicitTag). */
export function implicitTag(tag: number, cls: TagClass = TagClass.CONTEXT): TaggingMode {
  return { explicit: false, implicit: true, tag, cls };
}

/** Application tag helper (mirrors _application_tag in krb5/asn1.py). */
export function applicationTag(tag: number): TaggingMode {
  return { explicit: true, implicit: false, tag, cls: TagClass.APPLICATION };
}
