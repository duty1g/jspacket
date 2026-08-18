/**
 * @impacket/structure - TypeScript port of impacket/structure.py
 *
 * Binary structure builder/parser. Subclasses declare `commonHdr` and/or
 * `structure` as ordered lists of field descriptors:
 *   [fieldName, format]                  -- primitive field
 *   [fieldName, ':', Class]              -- nested structure / passthrough
 *   [fieldName, format, unpackCode]     -- void field with unpack hook
 *
 * Format specifiers mirror Python `struct` plus impacket extensions:
 *   x c b B h H l L i I q Q s p f d = @ ! < >
 *   :       raw bytes passthrough
 *   z       asciiz (NUL-terminated)
 *   u       UTF-16LE NUL-NUL terminated
 *   w       DCE-RPC/NDR conformant string
 *   '<fmt>-<field>'   length-of-`field` packed as `<fmt>`
 *   '<count>*<fmt>'   array; count may be empty (greedy), a number, or a fmt
 *   '<fmt>=<code>'    pack `<code>` (eval'd in field scope) as `<fmt>`
 *   '<fmt>&<field>'  address-of-`field` (presence gate)
 *   '%...'           printf pack-only
 *   'xxxx            literal bytes (quote)
 *   _                void (skip on pack; optional unpack code)
 *
 * Python's `struct` byte order prefix is required for multi-byte specifiers.
 */

import { Buffer } from 'node:buffer';

const ENC = 'latin1';

const PRINTABLE =
  '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ';

/** Encode a string/Buffer/number to a Buffer using latin-1 (mirrors Python `b()`). */
function toBuffer(x: string | Buffer | Uint8Array | number | PackValue): Buffer {
  if (Buffer.isBuffer(x)) return x;
  if (x instanceof Uint8Array) return Buffer.from(x);
  if (typeof x === 'number') return Buffer.from([x & 0xff]);
  if (typeof x === 'string') return Buffer.from(x, ENC);
  if (x == null) return Buffer.alloc(0);
  // Fallback: coerce via String for bigint/boolean/etc.
  return Buffer.from(String(x), ENC);
}

export type FieldType = string;
export type FieldDescriptor =
  | [string, FieldType]
  | [string, FieldType, StructureConstructor | string];

export type StructureConstructor = new (data?: Buffer | null, alignment?: number) => Structure;

/** Packable value kinds. */
export type PackValue =
  | Buffer
  | Uint8Array
  | string
  | number
  | bigint
  | boolean
  | null
  | undefined
  | Structure
  | { getData(): Buffer | Uint8Array }
  | PackValue[];

/** Returns the alignment of a struct format string (not the size). */
export function calcalign(format: string): number {
  let fmt = format;
  const prefixes = new Set(['=', '@', '!', '<', '>']);
  if (fmt.length && prefixes.has(fmt[0]!)) fmt = fmt.slice(1);
  const m = /^(\d*)(.*)$/.exec(fmt);
  const spec = m![2];
  if (!spec) return 0;
  // s and p have alignment 1 regardless of count
  if (spec[0] === 's' || spec[0] === 'p') return 1;
  try {
    return primitiveSize(spec[0]!);
  } catch {
    return 0;
  }
}

/** Matches Python struct.calcsize for the formats impacket uses. */
export function calcsize(format: string): number {
  // Node has no native struct module; we implement the subset impacket uses.
  // Impacket always uses a leading byte-order prefix for multi-byte specifiers.
  // Single-byte specifiers (x,c,b,B,?,s,p with count) work without prefix.
  let i = 0;
  let size = 0;
  let itemSize = 1;
  // strip byte-order prefix
  const prefixes = new Set(['=', '@', '!', '<', '>']);
  if (i < format.length && prefixes.has(format[0]!)) i++;
  while (i < format.length) {
    const ch = format[i]!;
    if (ch >= '0' && ch <= '9') {
      let n = 0;
      while (i < format.length && format[i]! >= '0' && format[i]! <= '9') {
        n = n * 10 + Number(format[i]);
        i++;
      }
      // repeat count for next specifier
      const next = format[i]!;
      itemSize = primitiveSize(next);
      size += n * itemSize;
      i++;
      continue;
    }
    itemSize = primitiveSize(ch);
    size += itemSize;
    i++;
  }
  return size;
}

function primitiveSize(ch: string): number {
  switch (ch) {
    case 'x':
    case 'c':
    case 'b':
    case 'B':
    case '?':
      return 1;
    case 'h':
    case 'H':
      return 2;
    case 'i':
    case 'I':
    case 'l':
    case 'L':
    case 'f':
      return 4;
    case 'q':
    case 'Q':
    case 'd':
      return 8;
    case 's':
    case 'p':
      return 1;
    default:
      throw new Error(`bad char in struct format: '${ch}'`);
  }
}

/** Pack a single struct-style format (Python struct.pack) for a value or array. */
export function structPack(format: string, value: PackValue): Buffer {
  // Determine byte order
  let endian: '<' | '>' | '=' | '@' | '!' = '<';
  let fmt = format;
  const prefixes: Record<string, '<' | '>' | '=' | '@' | '!'> = {
    '<': '<',
    '>': '>',
    '=': '=',
    '@': '=',
    '!': '>',
  };
  if (fmt.length && prefixes[fmt[0]!]) {
    endian = prefixes[fmt[0]!]!;
    fmt = fmt.slice(1);
  }
  // Parse "Nspec" form
  const m = /^(\d*)(.*)$/.exec(fmt);
  const count = m![1] ? Number(m![1]) : 1;
  const spec = m![2];

  if (spec === 's') {
    const buf = toBuffer(value as string | Buffer);
    if (count === 0) return Buffer.alloc(0);
    const out = Buffer.alloc(count, 0);
    buf.copy(out, 0, 0, Math.min(buf.length, count));
    return out;
  }
  if (spec === 'p') {
    const buf = toBuffer(value as string | Buffer);
    const out = Buffer.alloc(count, 0);
    const len = Math.min(buf.length, count - 1, 255);
    out[0] = len;
    buf.copy(out, 1, 0, len);
    return out;
  }
  if (spec === 'x') {
    return Buffer.alloc(count, 0);
  }

  // numeric / char / boolean: repeat produces an array
  const values: number[] | bigint[] = Array.isArray(value)
    ? (value as number[])
    : [value as number];
  return structPackRepeated(endian, spec!, count, values as number[]);
}

function structPackRepeated(
  endian: '<' | '>' | '=' | '@' | '!',
  spec: string,
  count: number,
  values: (number | bigint | boolean | string)[],
): Buffer {
  const le = endian !== '>';
  const buf = Buffer.alloc(primitiveSize(spec) * count);
  for (let i = 0; i < count; i++) {
    const v = values[i] ?? 0;
    switch (spec) {
      case 'c': {
        const b = typeof v === 'string' ? v.charCodeAt(0) : (v as number);
        buf.writeUInt8(b & 0xff, i);
        break;
      }
      case 'b': {
        const n = (v as number) & 0xff;
        buf.writeInt8(n > 127 ? n - 256 : n, i);
        break;
      }
      case 'B':
        buf.writeUInt8((v as number) & 0xff, i);
        break;
      case '?':
        buf.writeUInt8(v ? 1 : 0, i);
        break;
      case 'h':
        le
          ? buf.writeInt16LE((v as number) & 0xffff, i * 2)
          : buf.writeInt16BE((v as number) & 0xffff, i * 2);
        break;
      case 'H':
        le
          ? buf.writeUInt16LE((v as number) & 0xffff, i * 2)
          : buf.writeUInt16BE((v as number) & 0xffff, i * 2);
        break;
      case 'i':
      case 'l':
        le ? buf.writeInt32LE(v as number | 0, i * 4) : buf.writeInt32BE(v as number | 0, i * 4);
        break;
      case 'I':
      case 'L':
        le
          ? buf.writeUInt32LE((v as number) >>> 0, i * 4)
          : buf.writeUInt32BE((v as number) >>> 0, i * 4);
        break;
      case 'q': {
        const n = BigInt(v as number | bigint);
        le ? buf.writeBigInt64LE(n, i * 8) : buf.writeBigInt64BE(n, i * 8);
        break;
      }
      case 'Q': {
        const n = BigInt(v as number | bigint) & 0xffffffffffffffffn;
        le ? buf.writeBigUInt64LE(n, i * 8) : buf.writeBigUInt64BE(n, i * 8);
        break;
      }
      case 'f':
        le ? buf.writeFloatLE(v as number, i * 4) : buf.writeFloatBE(v as number, i * 4);
        break;
      case 'd':
        le ? buf.writeDoubleLE(v as number, i * 8) : buf.writeDoubleLE(v as number, i * 8);
        break;
      default:
        throw new Error(`Unsupported struct spec '${spec}'`);
    }
  }
  return buf;
}

/** Unpack a single struct-style format returning the first scalar/array. */
export function structUnpack(format: string, data: Buffer): number | bigint | boolean | string | Buffer {
  let endian: '<' | '>' | '=' | '@' | '!' = '<';
  let fmt = format;
  const prefixes: Record<string, '<' | '>' | '=' | '@' | '!'> = {
    '<': '<',
    '>': '>',
    '=': '=',
    '@': '=',
    '!': '>',
  };
  if (fmt.length && prefixes[fmt[0]!]) {
    endian = prefixes[fmt[0]!]!;
    fmt = fmt.slice(1);
  }
  const m = /^(\d*)(.*)$/.exec(fmt);
  const count = m![1] ? Number(m![1]) : 1;
  const spec = m![2];
  const le = endian !== '>';

  if (spec === 's') {
    return data.subarray(0, count);
  }
  if (spec === 'p') {
    const len = data[0]!;
    return data.subarray(1, 1 + Math.min(len, count - 1));
  }
  if (spec === 'x') {
    return Buffer.alloc(0);
  }
  if (count > 1) {
    const out: (number | bigint | boolean | string | Buffer)[] = [];
    const itemSize = primitiveSize(spec!);
    for (let i = 0; i < count; i++) out.push(readScalar(le, spec!, data.subarray(i * itemSize)));
    return out as unknown as number;
  }
  return readScalar(le, spec!, data);
}

function readScalar(
  le: boolean,
  spec: string,
  data: Buffer,
): number | bigint | boolean | string | Buffer {
  switch (spec) {
    case 'c':
    case 'b':
      return data.readInt8(0);
    case 'B':
      return data.readUInt8(0);
    case '?':
      return data.readUInt8(0) !== 0;
    case 'h':
      return le ? data.readInt16LE(0) : data.readInt16BE(0);
    case 'H':
      return le ? data.readUInt16LE(0) : data.readUInt16BE(0);
    case 'i':
    case 'l':
      return le ? data.readInt32LE(0) : data.readInt32BE(0);
    case 'I':
    case 'L':
      return le ? data.readUInt32LE(0) : data.readUInt32BE(0);
    case 'q':
      return le ? data.readBigInt64LE(0) : data.readBigInt64BE(0);
    case 'Q':
      return le ? data.readBigUInt64LE(0) : data.readBigUInt64BE(0);
    case 'f':
      return le ? data.readFloatLE(0) : data.readFloatBE(0);
    case 'd':
      return le ? data.readDoubleLE(0) : data.readDoubleBE(0);
    default:
      throw new Error(`Unsupported struct spec '${spec}'`);
  }
}

/** Matches Python `str.split` semantics with a maxsplit arg. */
function pySplit(s: string, sep: string, maxsplit = -1): string[] {
  if (sep === '') throw new Error('empty separator');
  const out: string[] = [];
  let i = 0;
  while (maxsplit < 0 || out.length < maxsplit) {
    const idx = s.indexOf(sep, i);
    if (idx === -1) break;
    out.push(s.slice(i, idx));
    i = idx + sep.length;
  }
  out.push(s.slice(i));
  return out;
}

const NULL_NULL_RE = /\x00\x00/g;

export class Structure {
  static commonHdr: FieldDescriptor[] = [];
  static structure: FieldDescriptor[] = [];

  static ENCODING = ENC;

  commonHdr: FieldDescriptor[] = (this.constructor as typeof Structure).commonHdr;
  structure: FieldDescriptor[] = (this.constructor as typeof Structure).structure;
  alignment = 0;
  debug = 0;
  ENCODING = ENC;

  fields: Record<string, PackValue> = {};
  rawData: Buffer | null = null;
  data: Buffer | null = null;

  constructor(data: Buffer | Uint8Array | null = null, alignment = 0) {
    if (!this.alignment) this.alignment = alignment;
    this.fields = {};
    this.rawData = data ? Buffer.from(data) : null;
    if (data != null) this.fromString(Buffer.from(data));
    else this.data = null;
  }

  static fromFile(read: (n: number) => Buffer): Structure {
    const answer = new (this as unknown as new () => Structure)();
    answer.fromString(read(answer.length));
    return answer;
  }

  setAlignment(a: number): void {
    this.alignment = a;
  }
  setData(d: Buffer): void {
    this.data = d;
  }

  b(x: string | Buffer | number): Buffer {
    return toBuffer(x);
  }

  packField(fieldName: string, format?: string): Buffer {
    if (format === undefined) format = this.formatForField(fieldName);
    const has = Object.prototype.hasOwnProperty.call(this.fields, fieldName);
    return this.pack(format!, has ? this.fields[fieldName]! : null, fieldName);
  }

  getData(): Buffer {
    if (this.data != null) {
      return this.data;
    }
    let data = Buffer.alloc(0);
    for (const field of [...this.commonHdr, ...this.structure]) {
      let chunk: Buffer;
      try {
        chunk = this.packField(field[0], field[1]);
      } catch (e) {
        const has = Object.prototype.hasOwnProperty.call(this.fields, field[0]);
        const ctx = has ? ` | ${field[1]} | ${String(this.fields[field[0]])}` : ` | ${field[1]}`;
        (e as Error).message +=
          ` When packing field '${field[0]}${ctx}' in ${(this.constructor as { name: string }).name}`;
        throw e;
      }
      data = Buffer.concat([data, chunk]);
      if (this.alignment) {
        const rem = data.length % this.alignment;
        if (rem) data = Buffer.concat([data, Buffer.alloc(this.alignment - rem, 0)]);
      }
    }
    return data;
  }

  fromString(data: Buffer): this {
    this.rawData = data;
    for (const field of [...this.commonHdr, ...this.structure]) {
      const [name, fmt] = field;
      const dataClassOrCode = field.length > 2 ? field[2] : null;
      const size = this.calcUnpackSize(fmt, data, name);
      this.fields[name] = this.unpack(fmt, data.subarray(0, size), dataClassOrCode, name);
      (this as any)[name] = this.fields[name];
      const packSize = this.calcPackSize(fmt, this.fields[name]!, name);
      const step =
        this.alignment && packSize % this.alignment
          ? packSize + (this.alignment - (packSize % this.alignment))
          : packSize;
      data = data.subarray(step);
    }
    this.data = null;
    return this;
  }

  set(key: string, value: PackValue): void {
    this.fields[key] = value;
    (this as any)[key] = value;
    this.data = null;
  }
  get(key: string): PackValue {
    return this.fields[key]!;
  }
  del(key: string): void {
    delete this.fields[key];
  }
  has(key: string): boolean {
    return Object.prototype.hasOwnProperty.call(this.fields, key);
  }

  toString(): string {
    return this.getData().toString('hex');
  }
  get length(): number {
    return this.getData().length;
  }

  pack(format: string, data: PackValue, field?: string): Buffer {
    if (field) {
      const addr = this.findAddressFieldFor(field);
      if (addr != null && data == null) return Buffer.alloc(0);
    }
    // void / length-prefix
    if (format[0] === '_') return Buffer.alloc(0);
    // quote literal
    if (format[0] === "'" || format[0] === '"') return toBuffer(format.slice(1));
    // code specifier  fmt=expr
    const eqParts = pySplit(format, '=');
    if (eqParts.length >= 2) {
      try {
        return this.pack(eqParts[0]!, data);
      } catch {
        const scope: Record<string, unknown> = { self: this, ...this.fields };
        const val = evalExpr(eqParts.slice(1).join('='), scope);
        return this.pack(eqParts[0]!, val as PackValue);
      }
    }
    // address specifier fmt&field
    const ampParts = pySplit(format, '&');
    if (ampParts.length === 2) {
      try {
        return this.pack(ampParts[0]!, data);
      } catch {
        if (ampParts[1]! in this.fields && this.fields[ampParts[1]!] != null) {
          const id = objId(this.fields[ampParts[1]!] as object);
          const bits = calcsize(ampParts[0]!) * 8;
          return this.pack(ampParts[0]!, id & ((1 << bits) - 1));
        }
        return this.pack(ampParts[0]!, 0);
      }
    }
    // length specifier fmt-field
    const dashParts = pySplit(format, '-');
    if (dashParts.length === 2) {
      try {
        return this.pack(dashParts[0]!, data);
      } catch {
        return this.pack(dashParts[0]!, this.calcPackFieldSize(dashParts[1]!));
      }
    }
    // array specifier fmt*fmt (count may be empty/number/fmt)
    const starParts = pySplit(format, '*');
    if (starParts.length === 2) {
      const [countFmt, itemFmt] = starParts;
      const arr = Array.isArray(data) ? data : data == null ? [] : [data];
      let body = Buffer.alloc(0);
      for (const each of arr) body = Buffer.concat([body, this.pack(itemFmt!, each)]);
      if (countFmt) {
        if (/^\d+$/.test(countFmt)) {
          if (Number(countFmt) !== arr.length)
            throw new Error(
              'Array field has a constant size, and it does not match the actual value',
            );
        } else {
          return Buffer.concat([this.pack(countFmt, arr.length), body]);
        }
      }
      return body;
    }
    // printf
    if (format[0] === '%') return toBuffer(printfLike(format, data));
    // asciiz
    if (format[0] === 'z') {
      const buf = toBuffer(data as string | Buffer);
      return Buffer.concat([buf, Buffer.from([0])]);
    }
    // unicode (UTF-16LE NUL-NUL)
    if (format[0] === 'u') {
      const buf = toBuffer(data as string | Buffer);
      const pad = buf.length & 1 ? Buffer.from([0]) : Buffer.alloc(0);
      return Buffer.concat([buf, Buffer.from([0, 0]), pad]);
    }
    // NDR conformant string
    if (format[0] === 'w') {
      let buf = toBuffer(data as string | Buffer);
      if (buf.length === 0) buf = Buffer.from([0, 0]);
      else if (buf.length & 1) buf = Buffer.concat([buf, Buffer.from([0])]);
      const len = Buffer.alloc(4);
      len.writeUInt32LE(buf.length / 2, 0);
      return Buffer.concat([len, len, Buffer.from([0, 0, 0, 0]), buf]);
    }
    if (data == null) throw new Error('Trying to pack None');
    // literal passthrough
    if (format[0] === ':') {
      if (data instanceof Structure) return data.getData();
      if (data && typeof (data as { getData?: unknown }).getData === 'function')
        return Buffer.from((data as { getData(): Buffer | Uint8Array }).getData());
      if (typeof data === 'number') return Buffer.from([data & 0xff]);
      return toBuffer(data as string | Buffer);
    }
    // struct-style: ensure 's' data is a Buffer
    if (format[format.length - 1] === 's') {
      if (Buffer.isBuffer(data) || data instanceof Uint8Array) return structPack(format, data);
      if (typeof data === 'string') return structPack(format, data);
      return structPack(format, toBuffer(data));
    }
    return structPack(format, data as PackValue);
  }

  unpack(
    format: string,
    data: Buffer,
    dataClassOrCode: StructureConstructor | string | null = null,
    field?: string,
  ): PackValue {
    if (field) {
      const addr = this.findAddressFieldFor(field);
      if (addr != null && !this.fields[addr]) return null as unknown as PackValue;
    }
    if (format[0] === '_') {
      if (typeof dataClassOrCode === 'string') {
        const scope: Record<string, unknown> = { self: this, inputDataLeft: data, ...this.fields };
        return evalExpr(dataClassOrCode, scope) as PackValue;
      }
      return null as unknown as PackValue;
    }
    if (format[0] === "'" || format[0] === '"') {
      const answer = format.slice(1);
      if (toBuffer(answer).equals(data)) return answer;
      throw new Error(
        `Unpacked data does not match constant '${data.toString('hex')}' should be '${answer}'`,
      );
    }
    const ampParts = pySplit(format, '&');
    if (ampParts.length === 2) return this.unpack(ampParts[0]!, data);
    const eqParts = pySplit(format, '=');
    if (eqParts.length >= 2) return this.unpack(eqParts[0]!, data);
    const dashParts = pySplit(format, '-');
    if (dashParts.length === 2) return this.unpack(dashParts[0]!, data);
    const starParts = pySplit(format, '*');
    if (starParts.length === 2) {
      const [countFmt, itemFmt] = starParts;
      const answer: PackValue[] = [];
      let sofar = 0;
      let number: number;
      if (countFmt && /^\d+$/.test(countFmt)) {
        number = Number(countFmt);
      } else if (countFmt) {
        sofar += this.calcUnpackSize(countFmt, data, field);
        number = Number(this.unpack(countFmt, data.subarray(0, sofar)));
      } else {
        number = -1;
      }
      while (number !== 0 && sofar < data.length) {
        const nsofar = sofar + this.calcUnpackSize(itemFmt!, data.subarray(sofar), field);
        answer.push(this.unpack(itemFmt!, data.subarray(sofar, nsofar), dataClassOrCode));
        number -= 1;
        sofar = nsofar;
      }
      return answer as unknown as PackValue;
    }
    if (format[0] === '%') return printfLike(format, data) as unknown as PackValue;
    if (format === 'z') {
      if (data[data.length - 1] !== 0)
        throw new Error(
          `${field ?? 'unknown'} 'z' field is not NUL terminated: ${data.toString('hex')}`,
        );
      return data.subarray(0, data.length - 1).toString(ENC);
    }
    if (format === 'u') {
      if (data.subarray(data.length - 2).toString('hex') !== '0000')
        throw new Error(
          `${field ?? 'unknown'} 'u' field is not NUL-NUL terminated: ${data.toString('hex')}`,
        );
      return data.subarray(0, data.length - 2);
    }
    if (format === 'w') {
      const l = data.readUInt32LE(0);
      return data.subarray(12, 12 + l * 2);
    }
    if (format === ':') {
      if (Buffer.isBuffer(data) && dataClassOrCode == null) return data;
      if (typeof dataClassOrCode === 'function')
        return new dataClassOrCode(data) as unknown as PackValue;
      return data;
    }
    return structUnpack(format, data) as unknown as PackValue;
  }

  calcPackSize(format: string, data: PackValue, field?: string): number {
    if (field) {
      const addr = this.findAddressFieldFor(field);
      if (addr != null && !this.fields[addr]) return 0;
    }
    if (format[0] === '_') return 0;
    if (format[0] === "'" || format[0] === '"') return format.length - 1;
    const ampParts = pySplit(format, '&');
    if (ampParts.length === 2) return this.calcPackSize(ampParts[0]!, data);
    const eqParts = pySplit(format, '=');
    if (eqParts.length >= 2) return this.calcPackSize(eqParts[0]!, data);
    const dashParts = pySplit(format, '-');
    if (dashParts.length === 2) return this.calcPackSize(dashParts[0]!, data);
    const starParts = pySplit(format, '*');
    if (starParts.length === 2) {
      const [countFmt, itemFmt] = starParts;
      let answer = 0;
      if (countFmt && /^\d+$/.test(countFmt)) {
        const arr = Array.isArray(data) ? data : [];
        if (Number(countFmt) !== arr.length)
          throw new Error(
            'Array field has a constant size, and it does not match the actual value',
          );
      } else if (countFmt) {
        const arr = Array.isArray(data) ? data : [];
        answer += this.calcPackSize(countFmt, arr.length);
      }
      const arr = Array.isArray(data) ? data : data == null ? [] : [data];
      for (const each of arr) answer += this.calcPackSize(itemFmt!, each);
      return answer;
    }
    if (format[0] === '%') return printfLike(format, data).length;
    if (format[0] === 'z') {
      const d = toBuffer(data as string | Buffer);
      return d.length + 1;
    }
    if (format[0] === 'u') {
      const d = toBuffer(data as string | Buffer);
      const l = d.length;
      return l + (l & 1 ? 3 : 2);
    }
    if (format[0] === 'w') {
      const d = toBuffer(data as string | Buffer);
      const l = d.length;
      return 12 + l + (l % 2);
    }
    if (format[0] === ':') {
      if (data instanceof Structure) return data.getData().length;
      if (data && typeof (data as { getData?: unknown }).getData === 'function')
        return Buffer.from((data as { getData(): Buffer | Uint8Array }).getData()).length;
      if (typeof data === 'number') return 1;
      return toBuffer(data as string | Buffer).length;
    }
    return calcsize(format);
  }

  calcUnpackSize(format: string, data: Buffer, field?: string): number {
    if (format[0] === '_') return 0;
    const addr = this.findAddressFieldFor(field);
    if (addr != null && !this.fields[addr]) return 0;
    try {
      const lengthField = this.findLengthFieldFor(field);
      if (lengthField && this.fields[lengthField] != null) {
        const lenVal = Number(this.fields[lengthField]);
        if (!Number.isNaN(lenVal)) return lenVal;
      }
    } catch {
      // ignore
    }
    if (format[0] === "'" || format[0] === '"') return format.length - 1;
    const ampParts = pySplit(format, '&');
    if (ampParts.length === 2) return this.calcUnpackSize(ampParts[0]!, data);
    const eqParts = pySplit(format, '=');
    if (eqParts.length >= 2) return this.calcUnpackSize(eqParts[0]!, data, field);
    const dashParts = pySplit(format, '-');
    if (dashParts.length === 2) return this.calcUnpackSize(dashParts[0]!, data);
    const starParts = pySplit(format, '*');
    if (starParts.length === 2) {
      const [countFmt, itemFmt] = starParts;
      let answer = 0;
      if (countFmt) {
        let number: number;
        if (/^\d+$/.test(countFmt)) number = Number(countFmt);
        else {
          answer += this.calcUnpackSize(countFmt, data);
          number = Number(this.unpack(countFmt, data.subarray(0, answer)));
        }
        while (number > 0) {
          number -= 1;
          answer += this.calcUnpackSize(itemFmt!, data.subarray(answer));
        }
      } else {
        while (answer < data.length) answer += this.calcUnpackSize(itemFmt!, data.subarray(answer));
      }
      return answer;
    }
    if (format[0] === '%')
      throw new Error("Can't guess the size of a printf like specifier for unpacking");
    if (format[0] === 'z') {
      const idx = data.indexOf(0);
      if (idx === -1)
        throw new ValueError(`Can't find NUL terminator in field '${field ?? 'unknown'}'`);
      return idx + 1;
    }
    if (format[0] === 'u') {
      NULL_NULL_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = NULL_NULL_RE.exec(data.toString('binary')))) {
        if (m.index % 2 === 0) return m.index + 2;
      }
      throw new ValueError(
        `Can't find NUL-NUL terminator in UTF-16le string '${data.toString('hex')}'`,
      );
    }
    if (format[0] === 'w') {
      const l = data.readUInt32LE(0);
      return 12 + l * 2;
    }
    if (format[0] === ':') return data.length;
    return calcsize(format);
  }

  calcPackFieldSize(fieldName: string | undefined, format?: string): number {
    if (format === undefined) format = this.formatForField(fieldName ?? '');
    return this.calcPackSize(format, this.fields[fieldName!]!);
  }

  formatForField(fieldName: string): string {
    for (const f of [...this.commonHdr, ...this.structure]) if (f[0] === fieldName) return f[1];
    throw new Error(`Field ${fieldName} not found`);
  }

  getFieldCode(fieldName: string): string | StructureConstructor | null {
    for (const f of [...this.commonHdr, ...this.structure]) {
      if (f[0] === fieldName) return f.length > 2 ? (f[2] as string | StructureConstructor) : null;
    }
    return null;
  }

  findAddressFieldFor(fieldName: string | undefined): string | null {
    const descriptor = `&${fieldName ?? ''}`;
    for (const f of [...this.commonHdr, ...this.structure]) {
      if (f[1].endsWith(descriptor)) return f[0];
    }
    return null;
  }

  findLengthFieldFor(fieldName: string | undefined): string | null {
    const descriptor = `-${fieldName ?? ''}`;
    for (const f of [...this.commonHdr, ...this.structure]) {
      if (f[1].endsWith(descriptor)) return f[0];
    }
    return null;
  }

  zeroValue(format: string): PackValue {
    const starParts = pySplit(format, '*');
    if (starParts.length === 2) {
      const [countFmt, itemFmt] = starParts;
      if (countFmt && /^\d+$/.test(countFmt)) {
        return new Array(Number(countFmt)).fill(this.zeroValue(itemFmt!)) as PackValue;
      }
    }
    if (format.includes('*')) return [] as unknown as PackValue;
    if (format.includes('s')) return Buffer.alloc(0);
    if (['z', ':', 'u'].includes(format)) return Buffer.alloc(0);
    if (format === 'w') return Buffer.from([0, 0]);
    return 0;
  }

  clear(): void {
    for (const f of [...this.commonHdr, ...this.structure])
      this.fields[f[0]] = this.zeroValue(f[1]);
  }

  dump(msg?: string, indent = 0): string[] {
    const lines: string[] = [];
    const name = msg ?? (this.constructor as { name: string }).name;
    lines.push(`\n${name}`);
    const ind = ' '.repeat(indent);
    const fixedFields: string[] = [];
    for (const f of [...this.commonHdr, ...this.structure]) {
      const i = f[0];
      if (i in this.fields) {
        fixedFields.push(i);
        const v = this.fields[i]!;
        if (v instanceof Structure) {
          lines.push(...v.dump(`${ind}${i}:{`, indent + 4));
          lines.push(`${ind}}`);
        } else {
          lines.push(`${ind}${i}: {${String(v)}}`);
        }
      }
    }
    const remaining = Object.keys(this.fields).filter((k) => !fixedFields.includes(k));
    for (const i of remaining) {
      const v = this.fields[i]!;
      if (v instanceof Structure) {
        lines.push(...v.dump(`${ind}${i}:{`, indent + 4));
        lines.push(`${ind}}`);
      } else lines.push(`${ind}${i}: {${String(v)}}`);
    }
    return lines;
  }
}

class ValueError extends Error {
  constructor(m: string) {
    super(m);
    this.name = 'ValueError';
  }
}

/** Object id stand-in for the Python `id()` address-field feature. */
const idMap = new WeakMap<object, number>();
let idCounter = 0x1000;
function objId(v: object): number {
  let id = idMap.get(v);
  if (id === undefined) {
    id = idCounter++;
    idMap.set(v, id);
  }
  return id;
}

/** Minimal printf-style formatter (handles %08x %s %d etc. with one value). */
function printfLike(fmt: string, value: PackValue): string {
  // impacket uses single-value printf; we support the common conversions.
  return fmt.replace(/%(-?\d*)(\.?\d+)?[sdhHboxXf%]/g, (m, width, _prec, _full) => {
    if (m === '%%') return '%';
    const w = width ? Number(width) : undefined;
    const v: unknown = Array.isArray(value) ? value[0] : value;
    const conv = m[m.length - 1];
    switch (conv) {
      case 's':
        return w ? String(v).padEnd(w).slice(0, Math.abs(w)) : String(v);
      case 'd':
        return w ? String(Number(v)).padStart(w, '0').slice(w) : String(Number(v));
      case 'x':
        return (Number(v) >>> 0).toString(16).padStart(w ?? 0, '0');
      case 'X':
        return (Number(v) >>> 0)
          .toString(16)
          .toUpperCase()
          .padStart(w ?? 0, '0');
      case 'o':
        return (Number(v) >>> 0).toString(8);
      case 'b':
        return (Number(v) >>> 0).toString(2);
      case 'f':
        return String(Number(v));
      default:
        return m;
    }
  });
}

/** Minimal expression evaluator for the `=code` and `_unpack` forms.
 *  Supports simple arithmetic, field references, and len()/id()/int().
 *  `self` is wrapped in a Proxy so `self["fieldName"]` reads from the
 *  Structure's fields map (mirroring Python's __getitem__). */
function convertTernary(code: string): string {
  let result = '';
  let i = 0;
  while (i < code.length) {
    const ifIdx = code.indexOf(' if ', i);
    if (ifIdx === -1) {
      result += code.slice(i);
      break;
    }
    const elseIdx = code.indexOf(' else ', ifIdx + 4);
    if (elseIdx === -1) {
      result += code.slice(i);
      break;
    }
    let trueStart = ifIdx - 1;
    while (trueStart >= i && /\w/.test(code[trueStart]!)) trueStart--;
    trueStart++;
    const trueVal = code.slice(trueStart, ifIdx);
    result += code.slice(i, trueStart);
    const cond = code.slice(ifIdx + 4, elseIdx);
    let parenDepth = 0;
    for (let j = i; j < ifIdx; j++) {
      if (code[j] === '(') parenDepth++;
      else if (code[j] === ')') parenDepth--;
    }
    let falseEnd = elseIdx + 6;
    let curParenDepth = parenDepth;
    while (falseEnd < code.length) {
      const ch = code[falseEnd]!;
      if (ch === '(') curParenDepth++;
      else if (ch === ')') {
        if (curParenDepth <= parenDepth) break;
        curParenDepth--;
      }
      falseEnd++;
    }
    const falseVal = code.slice(elseIdx + 6, falseEnd);
    result += `(${cond}) ? (${trueVal}) : (${falseVal})`;
    i = falseEnd;
  }
  return result;
}

export function evalExpr(code: string, scope: Record<string, unknown>): unknown {
  const len = (x: unknown): number =>
    x == null ? 0 : typeof x === 'string' ? x.length : ((x as { length?: number }).length ?? 0);
  const id = (x: object): number => objId(x);
  const int = (x: unknown): number => (typeof x === 'number' ? x : Number(x) | 0);
  const str = (x: unknown): string => String(x);
  const b = (x: unknown): Buffer => {
    if (Buffer.isBuffer(x)) return x;
    if (typeof x === 'string') return Buffer.from(x, 'latin1');
    return Buffer.alloc(0);
  };
  const wrappedScope: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(scope)) {
    if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(k)) continue;
    wrappedScope[k] = v instanceof Structure ? wrapStructure(v) : v;
  }
  const jsCode = convertTernary(
    code
      .replace(/\/\//g, '/')
      .replace(/\bb"([^"]*)"/g, 'Buffer.from("$1","latin1")')
      .replace(/\bb'([^']*)'/g, "Buffer.from('$1','latin1')")
  );
  let fn: Function;
  try {
    fn = new Function(
      ...Object.keys(wrappedScope),
      'len',
      'id',
      'int',
      'str',
      'b',
      `return (${jsCode});`,
    );
  } catch (e) {
    console.error(`evalExpr parse error: ${jsCode}`);
    throw e;
  }
  return fn(...Object.values(wrappedScope), len, id, int, str, b);
}

function wrapStructure(s: Structure): Structure {
  return new Proxy(s, {
    get(target, prop: string) {
      if (prop in target) return (target as unknown as Record<string, unknown>)[prop];
      if (prop === 'SIZE' || prop === '_SIZE' || prop === '_CTX_ITEM_LEN') {
        const ctor = target.constructor as unknown as Record<string, unknown>;
        if (typeof ctor[prop] !== 'undefined') return ctor[prop];
      }
      if (target.has(prop)) return target.get(prop);
      return undefined;
    },
  }) as Structure;
}

export function prettyPrint(x: number): string {
  const ch = String.fromCharCode(x & 0xff);
  return PRINTABLE.includes(ch) ? ch : '.';
}

export function hexdump(data: Buffer | Uint8Array | number | null, indent = ''): string {
  if (data == null) return '';
  let buf: Buffer;
  if (typeof data === 'number') buf = Buffer.from(String(data), 'utf8');
  else buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const strLen = buf.length;
  let out = '';
  let i = 0;
  while (i < strLen) {
    let line = ` ${indent}${i.toString(16).padStart(4, '0')}   `;
    for (let j = 0; j < 16; j++) {
      if (i + j < strLen) line += `${buf[i + j]!.toString(16).padStart(2, '0').toUpperCase()} `;
      else line += '   ';
      if (j % 16 === 7) line += ' ';
    }
    line += '  ';
    line += Array.from(buf.subarray(i, i + 16), prettyPrint).join('');
    out += line + '\n';
    i += 16;
  }
  return out;
}

export function parseBitmask(dict: Record<number, string>, value: number): string {
  let ret = '';
  for (let i = 0; i <= 31; i++) {
    const flag = 1 << i;
    if ((value & flag) === 0) continue;
    if (dict[flag]) ret += `${dict[flag]} | `;
    else ret += `0x${(flag >>> 0).toString(16).toUpperCase().padStart(8, '0')} | `;
  }
  return ret.length === 0 ? '0' : ret.slice(0, -3);
}
