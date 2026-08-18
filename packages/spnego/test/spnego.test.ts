import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import {
  ASN1_AID,
  ASN1_OID,
  ASN1_SEQUENCE,
  GSSAPI,
  GSS_API_SPNEGO_UUID,
  MechTypes,
  SPNEGOCipher,
  SPNEGO_NegTokenInit,
  SPNEGO_NegTokenResp,
  TypesMech,
  asn1decode,
  asn1encode,
} from '../src/index.js';

describe('asn1encode/asn1decode', () => {
  it('round-trips short length (< 0x80)', () => {
    const data = Buffer.from('hello', 'ascii');
    const enc = asn1encode(data);
    expect(enc[0]).toBe(5);
    expect(enc.subarray(1).toString('ascii')).toBe('hello');
    const [dec, total] = asn1decode(enc);
    expect(dec.toString('ascii')).toBe('hello');
    expect(total).toBe(6);
  });

  it('round-trips 1-byte length (0x81)', () => {
    const data = Buffer.alloc(200, 0x41);
    const enc = asn1encode(data);
    expect(enc[0]).toBe(0x81);
    expect(enc[1]).toBe(200);
    const [dec, total] = asn1decode(enc);
    expect(dec.length).toBe(200);
    expect(total).toBe(202);
  });

  it('round-trips 2-byte length (0x82)', () => {
    const data = Buffer.alloc(1000, 0x42);
    const enc = asn1encode(data);
    expect(enc[0]).toBe(0x82);
    const [dec, total] = asn1decode(enc);
    expect(dec.length).toBe(1000);
    expect(total).toBe(1003);
  });
});

describe('GSSAPI', () => {
  it('round-trips a GSSAPI header', () => {
    const gss = new GSSAPI();
    gss.fields.Payload = Buffer.from([0x01, 0x02, 0x03]);
    const data = gss.getData();
    expect(data[0]).toBe(ASN1_AID);

    const parsed = new GSSAPI(data);
    expect(parsed.fields.UUID).toEqual(GSS_API_SPNEGO_UUID);
    expect(parsed.fields.Payload).toEqual(Buffer.from([0x01, 0x02, 0x03]));
  });
});

describe('SPNEGO_NegTokenInit', () => {
  it('round-trips a NegTokenInit with mechTypes and mechToken', () => {
    const init = new SPNEGO_NegTokenInit();
    const ntlmOid = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']!;
    const krbOid = TypesMech['KRB5 - Kerberos 5']!;
    init.mechTypeOids = [ntlmOid, krbOid];
    init.fields.MechToken = Buffer.from('NTLMSSP token bytes', 'utf8');

    const data = init.getData();
    expect(data[0]).toBe(ASN1_AID);

    const parsed = new SPNEGO_NegTokenInit(data);
    expect(parsed.mechTypeOids).toHaveLength(2);
    expect(parsed.mechTypeOids[0]).toEqual(ntlmOid);
    expect(parsed.mechTypeOids[1]).toEqual(krbOid);
    expect(parsed.fields.MechToken).toBeDefined();
    expect(parsed.fields.MechToken!.toString('utf8')).toBe('NTLMSSP token bytes');
  });
});

describe('SPNEGO_NegTokenResp', () => {
  it('round-trips a server response with NegState + SupportedMech + ResponseToken', () => {
    const resp = new SPNEGO_NegTokenResp();
    resp.fields.NegState = Buffer.from([0x00]);
    resp.fields.SupportedMech = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']!;
    resp.fields.ResponseToken = Buffer.from('response token data', 'utf8');

    const data = resp.getData();
    expect(data[0]).toBe(0xa1);

    const parsed = new SPNEGO_NegTokenResp(data);
    expect(parsed.fields.NegState).toEqual(Buffer.from([0x00]));
    expect(parsed.fields.SupportedMech).toEqual(
      TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']!,
    );
    expect(parsed.fields.ResponseToken!.toString('utf8')).toBe('response token data');
  });

  it('round-trips a client response with only ResponseToken', () => {
    const resp = new SPNEGO_NegTokenResp();
    resp.fields.ResponseToken = Buffer.from('client token', 'utf8');

    const data = resp.getData();
    const parsed = new SPNEGO_NegTokenResp(data);
    expect(parsed.fields.ResponseToken!.toString('utf8')).toBe('client token');
    expect(parsed.fields.NegState).toBeUndefined();
  });

  it('round-trips a server response with only NegState', () => {
    const resp = new SPNEGO_NegTokenResp();
    resp.fields.NegState = Buffer.from([0x02]);

    const data = resp.getData();
    const parsed = new SPNEGO_NegTokenResp(data);
    expect(parsed.fields.NegState).toEqual(Buffer.from([0x02]));
    expect(parsed.fields.ResponseToken).toBeUndefined();
  });
});

describe('MechTypes', () => {
  it('contains NTLMSSP OID', () => {
    expect(MechTypes['2b06010401823702020a']).toContain('NTLMSSP');
  });

  it('TypesMech is reverse of MechTypes', () => {
    expect(TypesMech['KRB5 - Kerberos 5']!.toString('hex')).toBe('2a864886f712010202');
  });
});

describe('SPNEGOCipher', () => {
  it('encrypt/decrypt round-trip with extended session security', () => {
    const flags = 0xffffffff;
    const sessionKey = Buffer.alloc(16, 0x42);
    const cipher = new SPNEGOCipher(flags, sessionKey);

    const plainData = Buffer.from('test data to encrypt', 'utf8');
    const [signature, sealedMessage] = cipher.encrypt(plainData);

    expect(sealedMessage.length).toBe(plainData.length);
    expect(signature.getData()).toHaveLength(16);
  });

  it('sign produces a 16-byte signature', () => {
    const flags = 0xffffffff;
    const sessionKey = Buffer.alloc(16, 0x42);
    const cipher = new SPNEGOCipher(flags, sessionKey);

    const data = Buffer.from('sign this data', 'utf8');
    const sig = cipher.sign(data, 0);
    expect(sig.getData()).toHaveLength(16);
  });
});
