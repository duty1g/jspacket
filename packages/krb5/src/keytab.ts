import { Buffer } from 'node:buffer';
import { readFileSync, writeFileSync } from 'node:fs';
import { Enctype } from './crypto.js';

export class KeytabException extends Error {}

function readU16BE(buf: Buffer, offset: number): number {
  return buf.readUInt16BE(offset);
}

function readU32BE(buf: Buffer, offset: number): number {
  return buf.readUInt32BE(offset);
}

function readI32BE(buf: Buffer, offset: number): number {
  return buf.readInt32BE(offset);
}

export class KtCountedOctetString {
  data: Buffer = Buffer.alloc(0);

  static fromBuffer(buf: Buffer, offset: number): [KtCountedOctetString, number] {
    const length = readU16BE(buf, offset);
    const data = buf.subarray(offset + 2, offset + 2 + length);
    const cos = new KtCountedOctetString();
    cos.data = Buffer.from(data);
    return [cos, offset + 2 + length];
  }

  getData(): Buffer {
    const len = Buffer.alloc(2);
    len.writeUInt16BE(this.data.length, 0);
    return Buffer.concat([len, this.data]);
  }

  get length(): number {
    return 2 + this.data.length;
  }
}

export class KeytabKeyBlock {
  keytype = 0;
  keyvalue: KtCountedOctetString = new KtCountedOctetString();

  static fromBuffer(buf: Buffer, offset: number): [KeytabKeyBlock, number] {
    const kb = new KeytabKeyBlock();
    kb.keytype = readU16BE(buf, offset);
    const [kv, newOff] = KtCountedOctetString.fromBuffer(buf, offset + 2);
    kb.keyvalue = kv;
    return [kb, newOff];
  }

  getData(): Buffer {
    const kt = Buffer.alloc(2);
    kt.writeUInt16BE(this.keytype, 0);
    return Buffer.concat([kt, this.keyvalue.getData()]);
  }

  hexlifiedValue(): string {
    return this.keyvalue.data.toString('hex');
  }

  prettyKeytype(): string {
    try {
      return Enctype[this.keytype] as string;
    } catch {
      return `UNKNOWN:0x${this.keytype.toString(16)}`;
    }
  }
}

export class KeytabPrincipal {
  num_components = 0;
  realm: KtCountedOctetString = new KtCountedOctetString();
  components: KtCountedOctetString[] = [];
  name_type = 0;

  static fromBuffer(buf: Buffer, offset: number): [KeytabPrincipal, number] {
    const p = new KeytabPrincipal();
    p.num_components = readU16BE(buf, offset);
    let off = offset + 2;
    const [realm, off2] = KtCountedOctetString.fromBuffer(buf, off);
    p.realm = realm;
    off = off2;
    for (let i = 0; i < p.num_components; i++) {
      const [comp, newOff] = KtCountedOctetString.fromBuffer(buf, off);
      p.components.push(comp);
      off = newOff;
    }
    p.name_type = readU32BE(buf, off);
    return [p, off + 4];
  }

  getData(): Buffer {
    const parts: Buffer[] = [];
    const nc = Buffer.alloc(2);
    nc.writeUInt16BE(this.components.length, 0);
    parts.push(nc);
    parts.push(this.realm.getData());
    for (const c of this.components) {
      parts.push(c.getData());
    }
    const nt = Buffer.alloc(4);
    nt.writeUInt32BE(this.name_type, 0);
    parts.push(nt);
    return Buffer.concat(parts);
  }

  prettyPrint(): string {
    const comps = this.components.map((c) => c.data.toString('utf8'));
    const realm = this.realm.data.toString('utf8');
    return `${comps.join('/')}@${realm}`;
  }
}

export class KeytabEntry {
  size = 0;
  principal: KeytabPrincipal = new KeytabPrincipal();
  timestamp = 0;
  vno8 = 0;
  keyblock: KeytabKeyBlock = new KeytabKeyBlock();
  kvno = 0;
  deleted = true;
  rest: Buffer = Buffer.alloc(0);

  static fromBuffer(buf: Buffer, offset: number): [KeytabEntry, number] {
    const e = new KeytabEntry();
    const sizeRaw = readI32BE(buf, offset);
    e.size = Math.abs(sizeRaw) + 4;
    e.deleted = sizeRaw < 0;
    let off = offset + 4;
    [e.principal, off] = KeytabPrincipal.fromBuffer(buf, off);
    e.timestamp = readU32BE(buf, off);
    off += 4;
    e.vno8 = buf[off]!;
    off += 1;
    [e.keyblock, off] = KeytabKeyBlock.fromBuffer(buf, off);
    e.kvno = e.vno8;
    const lenMain = off - offset;
    if (e.size > lenMain) {
      e.rest = Buffer.from(buf.subarray(lenMain, e.size));
      if (
        e.rest.length >= 4 &&
        !(e.rest[0] === 0 && e.rest[1] === 0 && e.rest[2] === 0 && e.rest[3] === 0)
      ) {
        e.kvno = readU32BE(e.rest, 0);
      }
    }
    return [e, offset + e.size];
  }

  getData(): Buffer {
    const parts: Buffer[] = [];
    parts.push(this.principal.getData());
    const ts = Buffer.alloc(4);
    ts.writeUInt32BE(this.timestamp, 0);
    parts.push(ts);
    parts.push(Buffer.from([this.vno8]));
    parts.push(this.keyblock.getData());
    if (this.rest.length > 0) parts.push(this.rest);
    const body = Buffer.concat(parts);
    const sizeField = Buffer.alloc(4);
    const contentSize = body.length;
    sizeField.writeInt32BE(this.deleted ? -contentSize : contentSize, 0);
    this.size = contentSize + 4;
    return Buffer.concat([sizeField, body]);
  }
}

export class Keytab {
  static GetkeyEnctypePreference = [Enctype.AES256, Enctype.AES128, Enctype.RC4];
  entries: KeytabEntry[] = [];

  constructor(data?: Buffer) {
    if (data !== undefined) {
      this.parse(data);
    }
  }

  parse(data: Buffer): void {
    const version = readU16BE(data, 0);
    void version;
    let off = 2;
    while (off < data.length) {
      const [entry, newOff] = KeytabEntry.fromBuffer(data, off);
      this.entries.push(entry);
      off = newOff;
    }
  }

  getData(): Buffer {
    const parts: Buffer[] = [];
    const hdr = Buffer.alloc(2);
    hdr.writeUInt16BE(0x0502, 0);
    parts.push(hdr);
    for (const e of this.entries) {
      parts.push(e.getData());
    }
    return Buffer.concat(parts);
  }

  getKey(
    principal: string,
    specificEncType: number | null = null,
    ignoreRealm = true,
  ): KeytabKeyBlock | null {
    let p = principal.toUpperCase();
    if (ignoreRealm) p = p.split('@')[0]!;
    const matchingKeys: Record<number, KeytabEntry> = {};
    for (const entry of this.entries) {
      const entryPrincipal = entry.principal.prettyPrint().toUpperCase();
      if (entryPrincipal === p || (ignoreRealm && entryPrincipal.split('@')[0] === p)) {
        const keytype = entry.keyblock.keytype;
        if (specificEncType !== null && keytype === specificEncType) {
          return entry.keyblock;
        }
        if (specificEncType === null) {
          matchingKeys[keytype] = entry;
        }
      }
    }
    if (specificEncType === null && Object.keys(matchingKeys).length > 0) {
      for (const pref of Keytab.GetkeyEnctypePreference) {
        if (pref in matchingKeys) {
          return matchingKeys[pref]!.keyblock;
        }
      }
    }
    return null;
  }

  static loadFile(fileName: string): Keytab {
    return new Keytab(readFileSync(fileName));
  }

  saveFile(fileName: string): void {
    writeFileSync(fileName, this.getData());
  }
}
