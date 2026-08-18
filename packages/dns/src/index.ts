/**
 * @impacket/dns - TypeScript port of impacket/dns.py
 *
 * DNS protocol implementation based on:
 *   - RFC 1034/1035 - Domain Names
 *   - RFC 2671 - EDNS0
 *   - RFC 2782 - DNS SRV
 *   - and others (see original Python source)
 */

import { Buffer } from 'node:buffer';
import * as net from 'node:net';

// ---------------------------------------------------------------------------
// DNS Flags
// ---------------------------------------------------------------------------

export const DNSFlags = {
  // QR - Query/Response - 1 bit
  QR_QUERY:               0b0000000000000000,
  QR_RESPONSE:            0b1000000000000000,
  // OP - Opcode - 4 bits
  OP_STANDARD_QUERY:      0b0000000000000000,
  OP_INVERSE_QUERY:       0b0100000000000000,
  OP_STATUS_QUERY:        0b0010000000000000,
  OP_NOTIFY:              0b0000100000000000,
  OP_UPDATE:              0b0100100000000000,
  // AA - Authority Answer - 1 bit
  AA_NOT_AUTH_ANSWER:     0b0000000000000000,
  AA_AUTH_ANSWER:         0b0000010000000000,
  // TC - Truncated - 1 bit
  TC_NOT_TRUNCATED:       0b0000000000000000,
  TC_TRUNCATED:           0b0000001000000000,
  // RD - Recursion Desired - 1 bit
  RD_NOT_RECURSIVE_QUERY: 0b0000000000000000,
  RD_RECURSIVE_QUERY:     0b0000000100000000,
  // RA - Recursion Available - 1 bit
  RA_NOT_AVAILABLE:       0b0000000000000000,
  RA_AVAILABLE:           0b0000000010000000,
  // Z - 3 bits
  Z:                      0b0000000000000000,
  // AD - Authenticated Data - 1 bit
  AUTHENTICATED_DATA:     0b0000000000100000,
  // CD - Checking Disabled - 1 bit
  CHECKING_DISABLED:      0b0000000000010000,
  // RCODE - 4 bits
  RCODE_NO_ERROR:         0b0000000000000000,
  RCODE_FORMAT_ERROR:     0b0000000000001000,
  RCODE_SERVER_FAILURE:   0b0000000000000100,
  RCODE_NAME_ERROR:       0b0000000000001100,
  RCODE_NOT_IMPLEMENTED:  0b0000000000000010,
  RCODE_REFUSED:          0b0000000000001010,
  RCODE_YXDOMAIN:         0b0000000000000110,
  RCODE_YXRRSET:          0b0000000000001110,
  RCODE_NXRRSET:          0b0000000000000001,
  RCODE_NOAUTH:           0b0000000000001001,
  RCODE_NOTZONE:          0b0000000000000101,
} as const;

// ---------------------------------------------------------------------------
// DNS Type
// ---------------------------------------------------------------------------

export const DNSType = {
  A:           1,
  NS:          2,
  MD:          3,
  MF:          4,
  CNAME:       5,
  SOA:         6,
  MB:          7,
  MG:          8,
  MR:          9,
  NULL:        10,
  WKS:         11,
  PTR:         12,
  HINFO:       13,
  MINFO:       14,
  MX:          15,
  TXT:         16,
  RP:          17,
  AFSDB:       18,
  X25:         19,
  ISDN:        20,
  RT:          21,
  NSAP:        22,
  NSAP_PTR:    23,
  SIG:         24,
  KEY:         25,
  PX:          26,
  GPOS:        27,
  AAAA:        28,
  LOC:         29,
  NXT:         30,
  EID:         31,
  NB:          32,
  NBSTAT:      33,
  ATMA:        34,
  NAPTR:       35,
  KX:          36,
  CERT:        37,
  A6:          38,
  DNAME:       39,
  SINK:        40,
  OPT:         41,
  APL:         42,
  DS:          43,
  SSHFP:       44,
  IPSECKEY:    45,
  RRSIG:       46,
  NSEC:        47,
  DNSKEY:      48,
  DHCID:       49,
  NSEC3:       50,
  NSEC3PARAM:  51,
  HIP:         55,
  NINFO:       56,
  RKEY:        57,
  SPF:         99,
  UINFO:       100,
  UID:         101,
  GID:         102,
  UNSPEC:      103,
  TKEY:        249,
  TSIG:        250,
  IXFR:        251,
  AXFR:        252,
  MAILB:       253,
  MAILA:       254,
  ALL:         255,
  DNSSEC:      32769,
} as const;

const dnsTypeNameMap = new Map<number, string>();
for (const [name, val] of Object.entries(DNSType)) {
  dnsTypeNameMap.set(val, name);
}

export function getTypeName(type: number): string | undefined {
  return dnsTypeNameMap.get(type);
}

// ---------------------------------------------------------------------------
// DNS Class
// ---------------------------------------------------------------------------

export const DNSClass = {
  RESERVED: 0,
  IN:       1,
  CH:       3,
  HS:       4,
  NONE:     254,
  ANY:      255,
} as const;

const dnsClassNameMap = new Map<number, string>();
for (const [name, val] of Object.entries(DNSClass)) {
  dnsClassNameMap.set(val, name);
}

export function getClassName(type: number): string | undefined {
  return dnsClassNameMap.get(type);
}

// ---------------------------------------------------------------------------
// Types for parsed records
// ---------------------------------------------------------------------------

export interface DNSQuestion {
  qname: Buffer;
  qtype: number;
  qclass: number;
}

export interface DNSResourceData {
  IPAddress?: string;
  PrimaryNS?: Buffer | string;
  AdminMB?: Buffer | string;
  SerialNumber?: number;
  RefreshInterval?: number;
  RetryInterval?: number;
  ExpirationLimit?: number;
  MinimumTTL?: number;
  Preference?: number;
  MailExchanger?: Buffer | string;
  Name?: string;
  RDATA?: Buffer;
  [key: string]: unknown;
}

export type DNSAnswer = [Buffer, number, number, number, DNSResourceData];

export type DNSOPTAnswer = [Buffer, number, number, number, number, number, DNSResourceData];

export type DNSRecord = DNSAnswer | DNSOPTAnswer;

// ---------------------------------------------------------------------------
// Minimal ProtocolPacket-like base for DNS header/body management
// ---------------------------------------------------------------------------

/**
 * DNS packet parser/builder.
 *
 * The message header is present in all messages and is always 12 bytes.
 * Contains various flags and values which control the transaction.
 */
export class DNS {
  private static readonly TYPE_LEN       = 2;
  private static readonly CLASS_LEN      = 2;
  private static readonly TTL_LEN        = 4;
  private static readonly RDLENGTH_LEN   = 2;
  private static readonly TYPE_A_LEN     = 4;
  private static readonly SERIAL_LEN     = 4;
  private static readonly REFRESH_LEN    = 4;
  private static readonly RETRY_LEN      = 4;
  private static readonly EXPIRATION_LEN = 4;
  private static readonly MINTTL_LEN     = 4;
  private static readonly PREF_LEN       = 2;
  private static readonly IS_POINTER     = 0b11000000;
  private static readonly OFFSETMASK     = 0b00111111;

  private readonly HEADER_BASE_SIZE = 12;

  private header: Buffer;
  private body: Buffer;

  constructor(aBuffer?: Buffer | null) {
    this.header = Buffer.alloc(this.HEADER_BASE_SIZE);
    this.body = Buffer.alloc(0);
    if (aBuffer) {
      this.loadPacket(aBuffer);
    }
  }

  // ------------- low-level header helpers ----------------------------------

  private loadPacket(data: Buffer): void {
    this.header = Buffer.from(data.subarray(0, this.HEADER_BASE_SIZE));
    this.body = Buffer.from(data.subarray(this.HEADER_BASE_SIZE));
  }

  private getWord(offset: number): number {
    return this.header.readUInt16BE(offset);
  }

  private setWord(offset: number, value: number): void {
    this.header.writeUInt16BE(value & 0xffff, offset);
  }

  private getBodyAsBuffer(): Buffer {
    return this.body;
  }

  private loadBody(data: Buffer): void {
    this.body = Buffer.from(data);
  }

  /** Return the full packet (header + body). */
  toBuffer(): Buffer {
    return Buffer.concat([this.header, this.body]);
  }

  // ------------- public field accessors ------------------------------------

  getTransactionId(): number { return this.getWord(0); }
  setTransactionId(value: number): void { this.setWord(0, value); }

  getTransactionIdTcp(): number { return this.getWord(2); }
  setTransactionIdTcp(value: number): void { this.setWord(2, value); }

  getFlags(): number { return this.getWord(2); }
  setFlags(value: number): void { this.setWord(2, value); }

  getFlagsTcp(): number { return this.getWord(4); }
  setFlagsTcp(value: number): void { this.setWord(4, value); }

  getQdcount(): number { return this.getWord(4); }
  setQdcount(value: number): void { this.setWord(4, value); }

  getQdcountTcp(): number { return this.getWord(6); }
  setQdcountTcp(value: number): void { this.setWord(6, value); }

  getAncount(): number { return this.getWord(6); }
  setAncount(value: number): void { this.setWord(6, value); }

  getNscount(): number { return this.getWord(8); }
  setNscount(value: number): void { this.setWord(8, value); }

  getArcount(): number { return this.getWord(10); }
  setArcount(value: number): void { this.setWord(10, value); }

  getHeaderSize(): number { return this.HEADER_BASE_SIZE; }

  // ------------- compressed message parsing --------------------------------

  parseCompressedMessage(buf: Buffer, offset = 0): [number, Buffer] {
    if (offset >= buf.length) {
      throw new Error('No more data to parse. Offset is bigger than length of buffer.');
    }
    const byte = buf[offset]!;
    if ((byte & 0xc0) === 0xc0) {
      // Pointer
      const pointer = buf.readUInt16BE(offset);
      const pointerOffset = (pointer & 0x3fff) - this.HEADER_BASE_SIZE;
      if (offset === pointerOffset) {
        throw new Error('The infinite loop is in DNS decompression. Encountered pointer points to the current offset.');
      }
      offset += 2;
      const name = this.parseCompressedMessage(buf, pointerOffset)[1];
      return [offset, name];
    } else {
      // Label
      if (byte === 0x00) {
        offset += 1;
        return [offset, Buffer.alloc(0)];
      }
      offset += 1;
      const name = buf.subarray(offset, offset + byte);
      offset += byte;
      const [newOffset, rest] = this.parseCompressedMessage(buf, offset);
      if (rest.length === 0) {
        return [newOffset, Buffer.from(name)];
      } else {
        return [newOffset, Buffer.concat([name, Buffer.from('.'), rest])];
      }
    }
  }

  // ------------- question section ------------------------------------------

  getQuestions(): DNSQuestion[] {
    return this._getQuestions()[0];
  }

  private _getQuestions(): [DNSQuestion[], number] {
    const aux: DNSQuestion[] = [];
    let offset = 0;
    const qdcount = this.getQdcount();
    const data = this.getBodyAsBuffer();
    for (let i = 0; i < qdcount; i++) {
      let qname: Buffer;
      [offset, qname] = this.parseCompressedMessage(data, offset);
      const qtype  = data.readUInt16BE(offset);
      offset += DNS.TYPE_LEN;
      const qclass = data.readUInt16BE(offset);
      offset += DNS.CLASS_LEN;
      aux.push({ qname, qtype, qclass });
    }
    return [aux, offset];
  }

  getQuestionsTcp(): DNSQuestion[] {
    return this._getQuestionsTcp()[0];
  }

  private _getQuestionsTcp(): [DNSQuestion[], number] {
    const aux: DNSQuestion[] = [];
    let offset = 2;
    const qdcount = this.getQdcountTcp();
    const data = this.getBodyAsBuffer();
    for (let i = 0; i < qdcount; i++) {
      let qname: Buffer;
      [offset, qname] = this.parseCompressedMessage(data, offset);
      const qtype  = data.readUInt16BE(offset);
      offset += DNS.TYPE_LEN;
      const qclass = data.readUInt16BE(offset);
      offset += DNS.CLASS_LEN;
      aux.push({ qname, qtype, qclass });
    }
    return [aux, offset];
  }

  // ------------- answer / authority / additional sections -------------------

  getAnswers(): DNSRecord[] {
    return this._getAnswers()[0];
  }

  private _getAnswers(): [DNSRecord[], number] {
    const offset = this._getQuestions()[1];
    const ancount = this.getAncount();
    return this._processAnswerStructure(offset, ancount);
  }

  getAuthoritative(): DNSRecord[] {
    return this._getAuthoritative()[0];
  }

  private _getAuthoritative(): [DNSRecord[], number] {
    const offset = this._getAnswers()[1];
    const nscount = this.getNscount();
    return this._processAnswerStructure(offset, nscount);
  }

  getAdditionals(): DNSRecord[] {
    return this._getAdditionals()[0];
  }

  private _getAdditionals(): [DNSRecord[], number] {
    const offset = this._getAuthoritative()[1];
    const arcount = this.getArcount();
    return this._processAnswerStructure(offset, arcount);
  }

  private _processAnswerStructure(offset: number, num: number): [DNSRecord[], number] {
    const aux: DNSRecord[] = [];
    const data = this.getBodyAsBuffer();
    for (let i = 0; i < num; i++) {
      let qname: Buffer;
      [offset, qname] = this.parseCompressedMessage(data, offset);

      const qtype = data.readUInt16BE(offset);
      offset += DNS.TYPE_LEN;

      const qclass = data.readUInt16BE(offset);
      offset += DNS.CLASS_LEN;

      const qttlRaw = data.subarray(offset, offset + DNS.TTL_LEN);
      const qttl = data.readUInt32BE(offset);
      offset += DNS.TTL_LEN;

      const qrdlength = data.readUInt16BE(offset);
      offset += DNS.RDLENGTH_LEN;

      const qrdata: DNSResourceData = {};

      if (qtype === DNSType.A) {
        // IPv4 address
        const ipBuf = data.subarray(offset, offset + qrdlength);
        qrdata.IPAddress = `${ipBuf[0]}.${ipBuf[1]}.${ipBuf[2]}.${ipBuf[3]}`;
        offset += DNS.TYPE_A_LEN;
      } else if (qtype === DNSType.SOA) {
        let primaryNs: Buffer;
        [offset, primaryNs] = this.parseCompressedMessage(data, offset);
        qrdata.PrimaryNS = primaryNs;

        let adminMb: Buffer;
        [offset, adminMb] = this.parseCompressedMessage(data, offset);
        qrdata.AdminMB = adminMb;

        qrdata.SerialNumber = data.readUInt32BE(offset);
        offset += DNS.SERIAL_LEN;
        qrdata.RefreshInterval = data.readUInt32BE(offset);
        offset += DNS.REFRESH_LEN;
        qrdata.RetryInterval = data.readUInt32BE(offset);
        offset += DNS.RETRY_LEN;
        qrdata.ExpirationLimit = data.readUInt32BE(offset);
        offset += DNS.EXPIRATION_LEN;
        qrdata.MinimumTTL = data.readUInt32BE(offset);
        offset += DNS.MINTTL_LEN;
      } else if (qtype === DNSType.MX) {
        qrdata.Preference = data.readUInt16BE(offset);
        let mailExch: Buffer;
        [offset, mailExch] = this.parseCompressedMessage(data, offset);
        qrdata.MailExchanger = mailExch;
      } else if (qtype === DNSType.PTR || qtype === DNSType.NS || qtype === DNSType.CNAME) {
        let name: Buffer;
        [offset, name] = this.parseCompressedMessage(data, offset);
        qrdata.Name = name.toString('ascii');
      } else if (qtype === DNSType.OPT) {
        // RFC 2671 4.3
        const udpPayloadSize = qclass;
        const extRcode = qttlRaw[0]!;
        const version = qttlRaw[1]!;
        const flags = qttlRaw.readUInt16BE(2);
        qrdata.RDATA = Buffer.from(data.subarray(offset, offset + qrdlength));
        offset += qrdlength;
        aux.push([qname, qtype, udpPayloadSize, extRcode, version, flags, qrdata] as DNSOPTAnswer);
        continue;
      } else {
        // Unknown type, skip
        offset += qrdlength;
      }

      aux.push([qname, qtype, qclass, qttl, qrdata] as DNSAnswer);
    }
    return [aux, offset];
  }

  // ------------- raw section helpers ---------------------------------------

  private _getQuestionsRaw(): Buffer {
    if (this.getQdcount() === 0) return Buffer.alloc(0);
    const questionsOffset = this._getQuestions()[1];
    return this.getBodyAsBuffer().subarray(0, questionsOffset);
  }

  private _getAnswersRaw(): Buffer {
    if (this.getAncount() === 0) return Buffer.alloc(0);
    const questionsOffset = this._getQuestions()[1];
    const answersOffset = this._getAnswers()[1];
    return this.getBodyAsBuffer().subarray(questionsOffset, answersOffset);
  }

  private _getAuthoritativeRaw(): Buffer {
    if (this.getNscount() === 0) return Buffer.alloc(0);
    const answersOffset = this._getAnswers()[1];
    const authoritativeOffset = this._getAuthoritative()[1];
    return this.getBodyAsBuffer().subarray(answersOffset, authoritativeOffset);
  }

  private _getAdditionalsRaw(): Buffer {
    if (this.getArcount() === 0) return Buffer.alloc(0);
    const authoritativeOffset = this._getAuthoritative()[1];
    return this.getBodyAsBuffer().subarray(authoritativeOffset);
  }

  // ------------- mutators --------------------------------------------------

  addAnswer(answerRaw: Buffer): void {
    const questionsRaw = this._getQuestionsRaw();
    const answersRaw = this._getAnswersRaw();
    const authoritativeRaw = this._getAuthoritativeRaw();
    const additionalsRaw = this._getAdditionalsRaw();

    const body = Buffer.concat([questionsRaw, answersRaw, answerRaw, authoritativeRaw, additionalsRaw]);
    this.loadBody(body);

    this.setAncount(this.getAncount() + 1);
  }

  isEdns0(): boolean {
    const additionals = this.getAdditionals();
    for (const item of additionals) {
      if (item[1] === DNSType.OPT) return true;
    }
    return false;
  }

  // ------------- string representation -------------------------------------

  toString(): string {
    let res = '';

    const id      = this.getTransactionId();
    const flags   = this.getFlags();
    const qdcount = this.getQdcount();
    const ancount = this.getAncount();
    const nscount = this.getNscount();
    const arcount = this.getArcount();

    res += 'DNS ';
    res += (flags & DNSFlags.QR_RESPONSE) ? 'RESPONSE\n' : 'QUERY\n';

    const hex4 = (v: number) => '0x' + v.toString(16).padStart(4, '0');
    res += ` - Transaction ID -- [${hex4(id)}] ${id}\n`;
    res += ` - Flags ----------- [${hex4(flags)}] ${flags}\n`;
    res += ` - QdCount --------- [${hex4(qdcount)}] ${qdcount}\n`;
    res += ` - AnCount --------- [${hex4(ancount)}] ${ancount}\n`;
    res += ` - NsCount --------- [${hex4(nscount)}] ${nscount}\n`;
    res += ` - ArCount --------- [${hex4(arcount)}] ${arcount}\n`;

    if (qdcount > 0) {
      res += ' - Questions:\n';
      const questions = this.getQuestions();
      for (const q of questions) {
        const tn = getTypeName(q.qtype) ?? 'UNKNOWN';
        const cn = getClassName(q.qclass) ?? 'UNKNOWN';
        res += `  * Domain: ${q.qname.toString('ascii')} - Type: ${tn} [${hex4(q.qtype)}] - Class: ${cn} [${hex4(q.qclass)}]\n`;
      }
    }

    if (ancount > 0) {
      res += ' - Answers:\n';
      const answers = this.getAnswers();
      for (const a of answers) {
        const [qname, qtype] = a;
        if (qtype === DNSType.OPT) continue;
        const answer = a as DNSAnswer;
        const tn = getTypeName(answer[1]) ?? 'UNKNOWN';
        const cn = getClassName(answer[2]) ?? 'UNKNOWN';
        res += `  * Domain: ${(answer[0] as Buffer).toString('ascii')} - Type: ${tn} [${hex4(answer[1])}] - Class: ${cn} [${hex4(answer[2])}] - TTL: ${answer[3]} seconds - ${JSON.stringify(answer[4])}\n`;
      }
    }

    if (nscount > 0) {
      res += ' - Authoritative:\n';
      const authoritative = this.getAuthoritative();
      for (const a of authoritative) {
        if (a[1] === DNSType.OPT) continue;
        const answer = a as DNSAnswer;
        const tn = getTypeName(answer[1]) ?? 'UNKNOWN';
        const cn = getClassName(answer[2]) ?? 'UNKNOWN';
        res += `  * Domain: ${(answer[0] as Buffer).toString('ascii')} - Type: ${tn} [${hex4(answer[1])}] - Class: ${cn} [${hex4(answer[2])}] - TTL: ${answer[3]} seconds - ${JSON.stringify(answer[4])}\n`;
      }
    }

    if (arcount > 0) {
      res += ' - Additionals:\n';
      const additionals = this.getAdditionals();
      for (const additional of additionals) {
        const qtype = additional[1];
        if (qtype === DNSType.OPT) {
          const opt = additional as DNSOPTAnswer;
          const tn = getTypeName(opt[1]) ?? 'UNKNOWN';
          const hex2 = (v: number) => '0x' + v.toString(16).padStart(2, '0');
          res += `  * Name: <Root> - Type: ${tn} [${hex4(opt[1])}] - udp payload size: [${opt[2]}] - extended RCODE: [${hex2(opt[3])}] - EDNS0 version: [${hex2(opt[4])}] - Z Flags: [${hex2(opt[5])}] - RDATA: [${(opt[6].RDATA as Buffer).toString('hex')}]\n`;
        } else {
          const answer = additional as DNSAnswer;
          const tn = getTypeName(answer[1]) ?? 'UNKNOWN';
          const cn = getClassName(answer[2]) ?? 'UNKNOWN';
          res += `  * Domain: ${(answer[0] as Buffer).toString('ascii')} - Type: ${tn} [${hex4(answer[1])}] - Class: ${cn} [${hex4(answer[2])}] - TTL: ${answer[3]} seconds - ${JSON.stringify(answer[4])}\n`;
        }
      }
    }

    return res;
  }
}
