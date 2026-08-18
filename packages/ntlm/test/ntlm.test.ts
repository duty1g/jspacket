import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import {
  AV_PAIRS,
  NTLMAuthChallenge,
  NTLMAuthChallengeResponse,
  NTLMAuthNegotiate,
  NTLMSSP_AV_DNS_HOSTNAME,
  NTLMSSP_AV_DOMAINNAME,
  NTLMSSP_AV_HOSTNAME,
  NTLMSSP_AV_TIME,
  NTLMSSP_NEGOTIATE_UNICODE,
  computeLmhash,
  computeNthash,
  computeResponseNTLMv2,
  getNTLMSSPType1,
  getNTLMSSPType3,
  ntowfV2,
} from '../src/index.js';

describe('NTLM hashes', () => {
  it('computeNthash matches known NTLM hash of password', () => {
    expect(computeNthash('password').toString('hex')).toBe('8846f7eaee8fb117ad06bdd830b7586c');
  });

  it('computeLmhash matches known LM hash of password', () => {
    // LM("Password") = E52CAC67419A9A224A3B108F3FA6CB6D
    expect(computeLmhash('Password').toString('hex')).toBe('e52cac67419a9a224a3b108f3fa6cb6d');
  });
});

describe('AV_PAIRS', () => {
  it('round-trips', () => {
    const av = new AV_PAIRS();
    av.set(NTLMSSP_AV_HOSTNAME, Buffer.from('HOST', 'utf16le'));
    av.set(NTLMSSP_AV_DOMAINNAME, Buffer.from('DOM', 'utf16le'));
    const data = av.getData();
    const back = new AV_PAIRS(data);
    expect(back.get(NTLMSSP_AV_HOSTNAME)![1].toString('utf16le')).toBe('HOST');
    expect(back.get(NTLMSSP_AV_DOMAINNAME)![1].toString('utf16le')).toBe('DOM');
  });
});

describe('NTLMSSP messages', () => {
  it('Type 1 round-trips', () => {
    const t1 = getNTLMSSPType1('WORKSTATION', 'DOMAIN', true);
    const bytes = t1.getData();
    expect(bytes.subarray(0, 8).toString('ascii')).toBe('NTLMSSP\x00');
    expect(bytes.readUInt32LE(8)).toBe(1); // message_type
    const back = new NTLMAuthNegotiate(bytes);
    expect(Number(back.get('message_type'))).toBe(1);
    expect(Number(back.get('flags')) & NTLMSSP_NEGOTIATE_UNICODE).toBeTruthy();
  });

  it('Type 2 (Challenge) round-trips', () => {
    // Build a minimal challenge message by hand.
    const challenge = Buffer.alloc(8, 0x11);
    const targetInfo = Buffer.from(
      '0200' + '0c00' + Buffer.from('DOMAIN', 'utf16le').toString('hex') + '00000000',
      'hex',
    );
    const hdr = Buffer.alloc(40);
    Buffer.from('NTLMSSP\x00').copy(hdr, 0);
    hdr.writeUInt32LE(2, 8); // message_type
    const targetName = Buffer.from('DOMAIN', 'utf16le');
    hdr.writeUInt16LE(targetName.length, 12);
    hdr.writeUInt16LE(targetName.length, 14);
    hdr.writeUInt32LE(48, 16); // domain_offset (40 header + 8 tail)
    hdr.writeUInt32LE(0x20089, 20); // flags
    challenge.copy(hdr, 24);
    Buffer.alloc(8, 0).copy(hdr, 32); // reserved
    const tail = Buffer.alloc(8);
    tail.writeUInt16LE(targetInfo.length, 0);
    tail.writeUInt16LE(targetInfo.length, 2);
    tail.writeUInt32LE(48 + targetName.length, 4);
    const full = Buffer.concat([hdr, tail, targetName, targetInfo]);
    const ch = new NTLMAuthChallenge(full);
    expect(Number(ch.get('message_type'))).toBe(2);
    expect((ch.get('challenge') as Buffer).toString('hex')).toBe(challenge.toString('hex'));
    expect((ch.get('domain_name') as Buffer).toString('utf16le')).toBe('DOMAIN');
  });

  it('Type 3 (Authenticate) builds and round-trips via full handshake', () => {
    const t1 = getNTLMSSPType1('WS', 'DOM', true);
    const t1Bytes = t1.getData();

    // Server challenge
    const serverChallenge = Buffer.alloc(8, 0x22);
    const targetInfo = new AV_PAIRS();
    targetInfo.set(NTLMSSP_AV_DNS_HOSTNAME, Buffer.from('server.dom', 'utf16le'));
    targetInfo.set(NTLMSSP_AV_TIME, Buffer.alloc(8, 0));
    const ti = targetInfo.getData();
    const targetName = Buffer.from('DOM', 'utf16le');
    const hdr = Buffer.alloc(40);
    Buffer.from('NTLMSSP\x00').copy(hdr, 0);
    hdr.writeUInt32LE(2, 8);
    hdr.writeUInt16LE(targetName.length, 12);
    hdr.writeUInt16LE(targetName.length, 14);
    hdr.writeUInt32LE(48, 16);
    hdr.writeUInt32LE(0x20089, 20);
    serverChallenge.copy(hdr, 24);
    const tail = Buffer.alloc(8);
    tail.writeUInt16LE(ti.length, 0);
    tail.writeUInt16LE(ti.length, 2);
    tail.writeUInt32LE(48 + targetName.length, 4);
    const t2 = Buffer.concat([hdr, tail, targetName, ti]);

    const [t3, sessionKey] = getNTLMSSPType3(
      new NTLMAuthNegotiate(t1Bytes),
      t2,
      'user',
      'password',
      'DOM',
    );
    expect(sessionKey.length).toBe(16);
    const t3Bytes = t3.getData();
    expect(t3Bytes.subarray(0, 8).toString('ascii')).toBe('NTLMSSP\x00');
    expect(t3Bytes.readUInt32LE(8)).toBe(3);
    const t3Back = new NTLMAuthChallengeResponse();
    t3Back.fromString(t3Bytes);
    expect(t3Back.getUserString()).toBe('DOM/USER');
  });
});

describe('NTLMv2 response', () => {
  it('NTOWFv2 matches known vector', () => {
    // [MS-NLMP] 4.2.4: NTOWFv2("User","Password","Domain")
    const v = ntowfV2('User', 'Password', 'Domain');
    expect(v.toString('hex')).toBe('0c868a403bfd7a93a3001ef22ef02e3f');
  });

  it('computeResponseNTLMv2 produces 16-byte session base key', () => {
    const serverChallenge = Buffer.alloc(8, 0x01);
    const clientChallenge = Buffer.alloc(8, 0x02);
    const ti = new AV_PAIRS();
    ti.set(NTLMSSP_AV_DNS_HOSTNAME, Buffer.from('host', 'utf16le'));
    ti.set(NTLMSSP_AV_TIME, Buffer.alloc(8, 0));
    const [nt, lm, sk] = computeResponseNTLMv2(
      0x20089,
      serverChallenge,
      clientChallenge,
      ti.getData(),
      'Domain',
      'User',
      'Password',
    );
    expect(sk.length).toBe(16);
    // NT response = 16-byte NTProofStr + temp blob
    expect(nt.length).toBeGreaterThan(16);
    expect(lm.length).toBe(16 + 8);
  });
});
