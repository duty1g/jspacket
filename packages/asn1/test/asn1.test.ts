import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import {
  Asn1GeneralString,
  Asn1Integer,
  Asn1OID,
  Asn1OctetString,
  Asn1Sequence,
  TagClass,
  applicationTag,
  decodeInteger,
  decodeOID,
  encodeInteger,
  encodeOID,
  encodeTLV,
  explicitTag,
  parseTLV,
} from '../src/index.js';

describe('ASN.1 primitives', () => {
  it('INTEGER round-trips (positive)', () => {
    const enc = encodeInteger(12345);
    expect(enc.toString('hex')).toBe('3039');
    expect(decodeInteger(enc)).toBe(12345n);
  });

  it('INTEGER round-trips (negative, two-s complement)', () => {
    const enc = encodeInteger(-1);
    expect(enc.toString('hex')).toBe('ff');
    expect(decodeInteger(enc)).toBe(-1n);
  });

  it('INTEGER round-trips (large)', () => {
    const n = 0x0102030405060708n;
    const enc = encodeInteger(n);
    expect(decodeInteger(enc)).toBe(n);
  });

  it('OID round-trips', () => {
    const oid = '1.2.840.113549.1.1.1'; // RSA encryption
    const enc = encodeOID(oid);
    expect(enc.toString('hex')).toBe('2a864886f70d010101');
    expect(decodeOID(enc)).toBe(oid);
  });

  it('TLV encode/parse', () => {
    const v = Buffer.from('hello', 'ascii');
    const tlv = encodeTLV(TagClass.UNIVERSAL, false, 4, v);
    expect(tlv.toString('hex')).toBe('040568656c6c6f');
    const parsed = parseTLV(tlv);
    expect(parsed.tag).toBe(4);
    expect(parsed.value.toString('ascii')).toBe('hello');
  });
});

describe('ASN.1 schema nodes', () => {
  it('Asn1Integer node round-trip', () => {
    const n = new Asn1Integer(42);
    const enc = n.encode();
    expect(enc.toString('hex')).toBe('02012a');
    const n2 = new Asn1Integer();
    n2.decode(enc);
    expect(n2.get()).toBe(42n);
  });

  it('Asn1OctetString node round-trip', () => {
    const o = new Asn1OctetString(Buffer.from('data', 'ascii'));
    const enc = o.encode();
    expect(enc.toString('hex')).toBe('040464617461');
  });

  it('Asn1Sequence round-trip with explicit tagging', () => {
    const seq = new Asn1Sequence();
    seq.addComponent('version', new Asn1Integer(0), { tagging: explicitTag(0) });
    seq.addComponent('name', new Asn1GeneralString('impacket'));
    seq.set('version', 0);
    seq.set('name', 'impacket');
    const enc = seq.encode();
    expect(enc[0]!).toBe(0x30); // SEQUENCE
    const seq2 = new Asn1Sequence();
    seq2.components = [
      { name: 'version', node: new Asn1Integer(), tagging: explicitTag(0) },
      { name: 'name', node: new Asn1GeneralString() },
    ];
    seq2.decodeValue(parseTLV(enc).value);
    expect(seq2.get('name')).toBe('impacket');
  });

  it('applicationTag wraps a sequence', () => {
    const inner = new Asn1Sequence();
    inner.addComponent('x', new Asn1Integer(1));
    inner.set('x', 1);
    inner.tagging = applicationTag(10);
    const enc = inner.encode();
    expect(enc[0]! & 0xc0).toBe(TagClass.APPLICATION);
  });
});
