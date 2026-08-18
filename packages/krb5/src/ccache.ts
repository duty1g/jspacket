import { Buffer } from 'node:buffer';
import { readFileSync, writeFileSync } from 'node:fs';
import * as asn1 from './asn1.js';
import * as constants from './constants.js';
import * as crypto from './crypto.js';
import * as types from './types.js';

export const DELTA_TIME = 1;

export class KerberosCCacheException extends Error {}

function readU16BE(buf: Buffer, offset: number): number {
  return buf.readUInt16BE(offset);
}

function readU32BE(buf: Buffer, offset: number): number {
  return buf.readUInt32BE(offset);
}

export class CountedOctetString {
  data: Buffer = Buffer.alloc(0);

  static fromBuffer(buf: Buffer, offset: number): [CountedOctetString, number] {
    const length = readU32BE(buf, offset);
    const data = buf.subarray(offset + 4, offset + 4 + length);
    return [
      Object.assign(new CountedOctetString(), { data: Buffer.from(data) }),
      offset + 4 + length,
    ];
  }

  getData(): Buffer {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(this.data.length, 0);
    return Buffer.concat([len, this.data]);
  }

  get length(): number {
    return 4 + this.data.length;
  }
}

export class KeyBlock {
  keytype = 0;
  etype = 0;
  keyvalue: Buffer = Buffer.alloc(0);
  version = 4;

  static fromBuffer(buf: Buffer, offset: number, version: number): [KeyBlock, number] {
    const kb = new KeyBlock();
    kb.version = version;
    kb.keytype = readU16BE(buf, offset);
    kb.etype = readU16BE(buf, offset + 2);
    let keylen: number;
    let dataOff: number;
    if (version === 3) {
      const etype2 = readU16BE(buf, offset + 4);
      void etype2;
      keylen = readU16BE(buf, offset + 6);
      dataOff = offset + 8;
    } else {
      keylen = readU16BE(buf, offset + 4);
      dataOff = offset + 6;
    }
    kb.keyvalue = Buffer.from(buf.subarray(dataOff, dataOff + keylen));
    const totalLen = (version === 3 ? 8 : 6) + keylen;
    return [kb, offset + totalLen];
  }

  getData(): Buffer {
    const parts: Buffer[] = [];
    const kt = Buffer.alloc(2);
    kt.writeUInt16BE(this.keytype, 0);
    parts.push(kt);
    const et = Buffer.alloc(2);
    et.writeUInt16BE(this.etype, 0);
    parts.push(et);
    if (this.version === 3) {
      const et2 = Buffer.alloc(2);
      et2.writeUInt16BE(this.etype, 0);
      parts.push(et2);
    }
    const kl = Buffer.alloc(2);
    kl.writeUInt16BE(this.keyvalue.length, 0);
    parts.push(kl);
    parts.push(this.keyvalue);
    return Buffer.concat(parts);
  }
}

export class Times {
  authtime = 0;
  starttime = 0;
  endtime = 0;
  renew_till = 0;

  static SIZE = 16;

  static fromBuffer(buf: Buffer, offset: number): [Times, number] {
    const t = new Times();
    t.authtime = readU32BE(buf, offset);
    t.starttime = readU32BE(buf, offset + 4);
    t.endtime = readU32BE(buf, offset + 8);
    t.renew_till = readU32BE(buf, offset + 12);
    return [t, offset + 16];
  }

  getData(): Buffer {
    const buf = Buffer.alloc(16);
    buf.writeUInt32BE(this.authtime, 0);
    buf.writeUInt32BE(this.starttime, 4);
    buf.writeUInt32BE(this.endtime, 8);
    buf.writeUInt32BE(this.renew_till, 12);
    return buf;
  }
}

export class Address {
  addrtype = 0;
  data: CountedOctetString = new CountedOctetString();

  static fromBuffer(buf: Buffer, offset: number): [Address, number] {
    const a = new Address();
    a.addrtype = readU16BE(buf, offset);
    const [cos, newOff] = CountedOctetString.fromBuffer(buf, offset + 2);
    a.data = cos;
    return [a, newOff];
  }

  getData(): Buffer {
    const at = Buffer.alloc(2);
    at.writeUInt16BE(this.addrtype, 0);
    return Buffer.concat([at, this.data.getData()]);
  }
}

export class AuthData {
  authtype = 0;
  data: CountedOctetString = new CountedOctetString();

  static fromBuffer(buf: Buffer, offset: number): [AuthData, number] {
    const a = new AuthData();
    a.authtype = readU16BE(buf, offset);
    const [cos, newOff] = CountedOctetString.fromBuffer(buf, offset + 2);
    a.data = cos;
    return [a, newOff];
  }

  getData(): Buffer {
    const at = Buffer.alloc(2);
    at.writeUInt16BE(this.authtype, 0);
    return Buffer.concat([at, this.data.getData()]);
  }
}

export class PrincipalCCache {
  name_type = 0;
  num_components = 0;
  realm: CountedOctetString = new CountedOctetString();
  components: CountedOctetString[] = [];

  static fromBuffer(buf: Buffer, offset: number): [PrincipalCCache, number] {
    const p = new PrincipalCCache();
    p.name_type = readU32BE(buf, offset);
    p.num_components = readU32BE(buf, offset + 4);
    let off = offset + 8;
    const [realm, off2] = CountedOctetString.fromBuffer(buf, off);
    p.realm = realm;
    off = off2;
    for (let i = 0; i < p.num_components; i++) {
      const [comp, newOff] = CountedOctetString.fromBuffer(buf, off);
      p.components.push(comp);
      off = newOff;
    }
    return [p, off];
  }

  getData(): Buffer {
    const parts: Buffer[] = [];
    const hdr = Buffer.alloc(8);
    hdr.writeUInt32BE(this.name_type, 0);
    hdr.writeUInt32BE(this.components.length, 4);
    parts.push(hdr);
    parts.push(this.realm.getData());
    for (const c of this.components) {
      parts.push(c.getData());
    }
    return Buffer.concat(parts);
  }

  prettyPrint(): string {
    const comps = this.components.map((c) => c.data.toString('utf8'));
    const realm = this.realm.data.toString('utf8');
    return `${comps.join('/')}@${realm}`;
  }

  toPrincipal(): types.Principal {
    return new types.Principal(this.prettyPrint(), null, this.name_type);
  }

  fromPrincipal(principal: types.Principal): void {
    this.name_type = principal.type;
    this.num_components = principal.components.length;
    this.realm = new CountedOctetString();
    this.realm.data = Buffer.from(principal.realm ?? '', 'utf8');
    this.components = principal.components.map((c) => {
      const cos = new CountedOctetString();
      cos.data = Buffer.from(c, 'utf8');
      return cos;
    });
  }
}

export class Credential {
  client: PrincipalCCache = new PrincipalCCache();
  server: PrincipalCCache = new PrincipalCCache();
  key: KeyBlock = new KeyBlock();
  time: Times = new Times();
  is_skey = 0;
  tktflags = 0;
  num_address = 0;
  addresses: Address[] = [];
  authData: AuthData[] = [];
  ticket: CountedOctetString = new CountedOctetString();
  secondTicket: CountedOctetString = new CountedOctetString();

  static fromBuffer(buf: Buffer, offset: number, version: number): [Credential, number] {
    const cred = new Credential();
    let off = offset;
    [cred.client, off] = PrincipalCCache.fromBuffer(buf, off);
    [cred.server, off] = PrincipalCCache.fromBuffer(buf, off);
    [cred.key, off] = KeyBlock.fromBuffer(buf, off, version);
    [cred.time, off] = Times.fromBuffer(buf, off);
    cred.is_skey = buf[off]!;
    off += 1;
    cred.tktflags = readU32BE(buf, off);
    off += 4;
    cred.num_address = readU32BE(buf, off);
    off += 4;
    for (let i = 0; i < cred.num_address; i++) {
      const [addr, newOff] = Address.fromBuffer(buf, off);
      cred.addresses.push(addr);
      off = newOff;
    }
    const numAuthData = readU32BE(buf, off);
    off += 4;
    for (let i = 0; i < numAuthData; i++) {
      const [ad, newOff] = AuthData.fromBuffer(buf, off);
      cred.authData.push(ad);
      off = newOff;
    }
    [cred.ticket, off] = CountedOctetString.fromBuffer(buf, off);
    [cred.secondTicket, off] = CountedOctetString.fromBuffer(buf, off);
    return [cred, off];
  }

  getData(): Buffer {
    const parts: Buffer[] = [];
    parts.push(this.client.getData());
    parts.push(this.server.getData());
    parts.push(this.key.getData());
    parts.push(this.time.getData());
    parts.push(Buffer.from([this.is_skey]));
    const flags = Buffer.alloc(4);
    flags.writeUInt32BE(this.tktflags, 0);
    parts.push(flags);
    const na = Buffer.alloc(4);
    na.writeUInt32BE(this.addresses.length, 0);
    parts.push(na);
    for (const a of this.addresses) parts.push(a.getData());
    const nad = Buffer.alloc(4);
    nad.writeUInt32BE(this.authData.length, 0);
    parts.push(nad);
    for (const ad of this.authData) parts.push(ad.getData());
    parts.push(this.ticket.getData());
    parts.push(this.secondTicket.getData());
    return Buffer.concat(parts);
  }

  getServerPrincipal(): string {
    return this.server.prettyPrint();
  }

  toTGT(): { data: Buffer; cipher: crypto.EnctypeProfile; sessionKey: crypto.Key } {
    const asRep = asn1.AS_REP();
    asRep.set('pvno', 5);
    asRep.set('msg-type', constants.ApplicationTagNumbers.AS_REQ);
    asRep.set('crealm', this.client.realm.data.toString('utf8'));
    const clientComponents = this.client.components.map(c => c.data.toString('utf8'));
    const clientPrincipal = asn1.principalToAsn1({
      type: this.client.name_type,
      components: clientComponents,
    });
    asRep.set('cname', clientPrincipal);

    const ticket = asn1.Ticket();
    ticket._rawData = this.ticket.data;
    asRep.set('ticket', ticket);

    const encPart = asn1.EncryptedData();
    encPart.set('etype', this.key.keytype);
    encPart.set('cipher', Buffer.alloc(0));
    asRep.set('enc-part', encPart);

    const cipher = crypto._get_enctype_profile(this.key.keytype);
    const sessionKey = new crypto.Key(this.key.keytype, this.key.keyvalue);

    return { data: asRep.encode(), cipher, sessionKey };
  }

  toTGS(): { data: Buffer; cipher: crypto.EnctypeProfile; sessionKey: crypto.Key } {
    const tgsRep = asn1.TGS_REP();
    tgsRep.set('pvno', 5);
    tgsRep.set('msg-type', constants.ApplicationTagNumbers.TGS_REP);
    tgsRep.set('crealm', this.client.realm.data.toString('utf8'));
    const clientComponents = this.client.components.map(c => c.data.toString('utf8'));
    const clientPrincipal = asn1.principalToAsn1({
      type: this.client.name_type,
      components: clientComponents,
    });
    tgsRep.set('cname', clientPrincipal);

    const ticket = asn1.Ticket();
    ticket._rawData = this.ticket.data;
    tgsRep.set('ticket', ticket);

    const encPart = asn1.EncryptedData();
    encPart.set('etype', this.key.keytype);
    encPart.set('cipher', Buffer.alloc(0));
    tgsRep.set('enc-part', encPart);

    const cipher = crypto._get_enctype_profile(this.key.keytype);
    const sessionKey = new crypto.Key(this.key.keytype, this.key.keyvalue);

    return { data: tgsRep.encode(), cipher, sessionKey };
  }
}

export class CCache {
  headers: { tag: number; taglen: number; tagdata: Buffer }[] = [];
  principal: PrincipalCCache = new PrincipalCCache();
  credentials: Credential[] = [];

  constructor(data?: Buffer) {
    if (data !== undefined) {
      this.parse(data);
    }
  }

  parse(data: Buffer): void {
    const _offset = 0;
    const ccacheVersion = data[1]!;
    if (ccacheVersion === 1 || ccacheVersion === 2) {
      throw new KerberosCCacheException('CCache version 1 and 2 not supported');
    }
    let off = 0;
    if (ccacheVersion === 4) {
      const fileFormatVersion = readU16BE(data, 0);
      void fileFormatVersion;
      const headerlen = readU16BE(data, 2);
      off = 4;
      this.headers = [];
      let remaining = headerlen;
      while (remaining > 0) {
        const tag = readU16BE(data, off);
        const taglen = readU16BE(data, off + 2);
        const tagdata = Buffer.from(data.subarray(off + 4, off + 4 + taglen));
        this.headers.push({ tag, taglen, tagdata });
        const consumed = 4 + taglen;
        remaining -= consumed;
        off += consumed;
      }
    } else {
      off = 2;
    }
    [this.principal, off] = PrincipalCCache.fromBuffer(data, off);
    this.credentials = [];
    while (off < data.length) {
      const [cred, newOff] = Credential.fromBuffer(data, off, ccacheVersion);
      if (!cred.server.prettyPrint().includes('krb5_ccache_conf_data')) {
        this.credentials.push(cred);
      }
      off = newOff;
    }
  }

  getData(): Buffer {
    const parts: Buffer[] = [];
    const miniHeader = Buffer.alloc(4);
    miniHeader.writeUInt16BE(0x0504, 0);
    miniHeader.writeUInt16BE(12, 2);
    parts.push(miniHeader);
    for (const h of this.headers) {
      const hdr = Buffer.alloc(4);
      hdr.writeUInt16BE(h.tag, 0);
      hdr.writeUInt16BE(h.tagdata.length, 2);
      parts.push(hdr);
      parts.push(h.tagdata);
    }
    parts.push(this.principal.getData());
    for (const cred of this.credentials) {
      parts.push(cred.getData());
    }
    return Buffer.concat(parts);
  }

  getCredential(server: string): Credential | null {
    const upper = server.toUpperCase();
    for (const c of this.credentials) {
      const sp = c.server.prettyPrint().toUpperCase();
      if (sp === upper) return c;
      if (sp.split('@')[0] === upper) return c;
      if (sp.split('@')[0] === upper.split('@')[0]) return c;
    }
    return null;
  }

  setDefaultHeader(): void {
    this.headers = [
      { tag: 1, taglen: 8, tagdata: Buffer.from([0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]) },
    ];
  }

  static loadFile(fileName: string): CCache {
    const data = readFileSync(fileName);
    return new CCache(data);
  }

  saveFile(fileName: string): void {
    writeFileSync(fileName, this.getData());
  }

  prettyPrint(): string {
    const lines: string[] = [];
    lines.push(`Primary Principal: ${this.principal.prettyPrint()}`);
    lines.push('Credentials:');
    for (let i = 0; i < this.credentials.length; i++) {
      lines.push(`[${i}]`);
      lines.push(`  Client: ${this.credentials[i]!.client.prettyPrint()}`);
      lines.push(`  Server: ${this.credentials[i]!.server.prettyPrint()}`);
      lines.push(
        `  Key: (0x${this.credentials[i]!.key.keytype.toString(16)}) ${this.credentials[i]!.key.keyvalue.toString('hex')}`,
      );
    }
    return lines.join('\n');
  }
}
