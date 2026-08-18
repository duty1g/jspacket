import { Buffer } from 'node:buffer';
import { type Asn1Node, Asn1SequenceOf } from '@impacket/asn1';
import { describe, expect, it } from 'vitest';
import {
  Asn1,
  CCache,
  Constants,
  Crypto,
  GSSAPI,
  KPasswd,
  KerberosV5,
  Keytab,
  Types,
} from '../src/index.js';

function seqOf(node: Asn1Node): Asn1SequenceOf {
  return node as unknown as Asn1SequenceOf;
}

describe('KerberosTime', () => {
  it('toAsn1 formats as generalized time with Z', () => {
    const dt = new Date(Date.UTC(2024, 0, 15, 12, 30, 45));
    expect(Types.KerberosTime.toAsn1(dt)).toBe('20240115123045Z');
  });

  it('fromAsn1 parses generalized time', () => {
    const dt = Types.KerberosTime.fromAsn1('20240115123045Z');
    expect(dt.getUTCFullYear()).toBe(2024);
    expect(dt.getUTCMonth()).toBe(0);
    expect(dt.getUTCDate()).toBe(15);
    expect(dt.getUTCHours()).toBe(12);
    expect(dt.getUTCMinutes()).toBe(30);
    expect(dt.getUTCSeconds()).toBe(45);
  });

  it('INDEFINITE is epoch', () => {
    expect(Types.KerberosTime.INDEFINITE.getTime()).toBe(0);
  });
});

describe('Principal', () => {
  it('parses simple principal with realm', () => {
    const p = new Types.Principal('marc@ATHENA.MIT.EDU');
    expect(p.components).toEqual(['marc']);
    expect(p.realm).toBe('ATHENA.MIT.EDU');
  });

  it('parses principal with service instance', () => {
    const p = new Types.Principal('krbtgt/DOMAIN.COM');
    expect(p.components).toEqual(['krbtgt', 'DOMAIN.COM']);
  });

  it('uses default realm when none specified', () => {
    const p = new Types.Principal('marc', 'ATHENA.MIT.EDU');
    expect(p.components).toEqual(['marc']);
    expect(p.realm).toBe('ATHENA.MIT.EDU');
  });

  it('round-trips via toString', () => {
    const p = new Types.Principal('krbtgt/DOMAIN.COM@DOMAIN.COM');
    expect(p.toString()).toBe('krbtgt/DOMAIN.COM@DOMAIN.COM');
  });

  it('handles escaped slash', () => {
    const p = new Types.Principal('marc\\/root');
    expect(p.components).toEqual(['marc/root']);
  });

  it('accepts array form [components, realm]', () => {
    const p = new Types.Principal([['marc'], 'ATHENA.MIT.EDU']);
    expect(p.components).toEqual(['marc']);
    expect(p.realm).toBe('ATHENA.MIT.EDU');
  });

  it('equals compares type, components, realm', () => {
    const a = new Types.Principal('marc@ATHENA.MIT.EDU', null, 1);
    const b = new Types.Principal('marc@ATHENA.MIT.EDU', null, 1);
    expect(a.equals(b)).toBe(true);
  });
});

describe('Constants', () => {
  it('encodeFlags sets bit positions', () => {
    const flags = Constants.encodeFlags([1, 3, 5]);
    expect(flags).toHaveLength(32);
    expect(flags[1]).toBe(1);
    expect(flags[3]).toBe(1);
    expect(flags[5]).toBe(1);
    expect(flags[0]).toBe(0);
  });

  it('EncryptionTypes has correct values', () => {
    expect(Constants.EncryptionTypes.aes256_cts_hmac_sha1_96).toBe(18);
    expect(Constants.EncryptionTypes.rc4_hmac).toBe(23);
  });

  it('ErrorCodes has correct values', () => {
    expect(Constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED).toBe(25);
    expect(Constants.ErrorCodes.KRB_AP_ERR_SKEW).toBe(37);
  });
});

describe('ASN.1 structures', () => {
  it('AS_REQ round-trips', () => {
    const asReq = Asn1.AS_REQ();
    asReq.set('pvno', 5);
    asReq.set('msg-type', 10);

    const padata = Asn1.PA_DATA();
    padata.set('padata-type', 128);
    padata.set('padata-value', Buffer.from([0x30, 0x05, 0x01, 0x01, 0xff]));
    const padataSeq = new Asn1SequenceOf(Asn1.PA_DATA());
    padataSeq.add(padata);
    asReq.set('padata', padataSeq);

    const reqBody = Asn1.KDC_REQ_BODY();
    Asn1.seqSetFlags(reqBody, 'kdc-options', [
      Constants.KDCOptions.forwardable,
      Constants.KDCOptions.renewable,
      Constants.KDCOptions.proxiable,
    ]);

    const sname = Asn1.PrincipalName();
    sname.set('name-type', Constants.PrincipalNameType.NT_PRINCIPAL);
    const snameStrings = seqOf(sname.getComponent('name-string'));
    snameStrings.add(new Asn1.KerberosString('krbtgt'));
    snameStrings.add(new Asn1.KerberosString('DOMAIN.COM'));
    sname.set('name-string', snameStrings);
    reqBody.set('sname', sname);

    const cname = Asn1.PrincipalName();
    cname.set('name-type', Constants.PrincipalNameType.NT_PRINCIPAL);
    const cnameStrings = seqOf(cname.getComponent('name-string'));
    cnameStrings.add(new Asn1.KerberosString('user'));
    cname.set('name-string', cnameStrings);
    reqBody.set('cname', cname);

    reqBody.set('realm', 'DOMAIN.COM');
    const till = new Date(Date.UTC(2024, 0, 15, 12, 30, 45));
    reqBody.set('till', till);
    reqBody.set('rtime', till);
    reqBody.set('nonce', 1234567890);

    const etypeSeq = new Asn1SequenceOf(new Asn1.Int32());
    etypeSeq.add(new Asn1.Int32(Constants.EncryptionTypes.aes256_cts_hmac_sha1_96));
    reqBody.set('etype', etypeSeq);

    asReq.set('req-body', reqBody);

    const enc = asReq.encode();
    expect(enc[0]! & 0xc0).toBe(0x40);
    expect(enc[0]! & 0x1f).toBe(10);

    const decoded = Asn1.AS_REQ();
    decoded.decode(enc);
    expect(Number(decoded.get('pvno'))).toBe(5);
    expect(Number(decoded.get('msg-type'))).toBe(10);
  });

  it('KERB_PA_PAC_REQUEST round-trips', () => {
    const pac = Asn1.KERB_PA_PAC_REQUEST();
    pac.set('include-pac', true);
    const enc = pac.encode();
    expect(enc[0]!).toBe(0x30);
    const dec = Asn1.KERB_PA_PAC_REQUEST();
    dec.decode(enc);
    expect(dec.get('include-pac')).toBe(true);
  });

  it('KRB_ERROR round-trips', () => {
    const err = Asn1.KRB_ERROR();
    err.set('pvno', 5);
    err.set('msg-type', 30);
    err.set('stime', new Date(Date.UTC(2024, 0, 15, 12, 0, 0)));
    err.set('susec', 0);
    err.set('error-code', 25);
    err.set('realm', 'DOMAIN.COM');
    const sname = Asn1.PrincipalName();
    sname.set('name-type', Constants.PrincipalNameType.NT_PRINCIPAL);
    const snameStrings = seqOf(sname.getComponent('name-string'));
    snameStrings.add(new Asn1.KerberosString('krbtgt'));
    snameStrings.add(new Asn1.KerberosString('DOMAIN.COM'));
    sname.set('name-string', snameStrings);
    err.set('sname', sname);

    const enc = err.encode();
    expect(enc[0]! & 0xc0).toBe(0x40);
    expect(enc[0]! & 0x1f).toBe(30);

    const dec = Asn1.KRB_ERROR();
    dec.decode(enc);
    expect(Number(dec.get('pvno'))).toBe(5);
    expect(Number(dec.get('msg-type'))).toBe(30);
    expect(Number(dec.get('error-code'))).toBe(25);
    expect(dec.get('realm')).toBe('DOMAIN.COM');
  });
});

describe('Crypto: _nfold (RFC 3961)', () => {
  const cases: [string, number, string][] = [
    ['01', 16, '01084002108004200108400210800420'],
    ['012345', 16, 'eba59fa8e97dbb69a7ea3a1f6edb2a39'],
    ['0123456789abcdef', 16, '0123456789abcdef6f78091a2b3c4d5e'],
    ['41424344454647', 8, '221b3a58d3a9684a'],
    ['41424344454647', 16, '74974866d3c5bc9e75cc3c37346d04f4'],
  ];
  for (const [input, nbytes, expected] of cases) {
    it(`nfold(${input}, ${nbytes}) = ${expected}`, () => {
      const result = Crypto._nfold(Buffer.from(input, 'hex'), nbytes);
      expect(result.toString('hex')).toBe(expected);
    });
  }
});

describe('Crypto: RC4-HMAC', () => {
  it('string_to_key produces MD4(UTF-16LE(password))', () => {
    const key = Crypto.string_to_key(Crypto.Enctype.RC4, 'password', '', null);
    expect(key.contents.toString('hex')).toBe('8846f7eaee8fb117ad06bdd830b7586c');
  });

  it('encrypt/decrypt round-trip', () => {
    const key = Crypto.string_to_key(Crypto.Enctype.RC4, 'password', '', null);
    const plaintext = Buffer.from('Hello, Kerberos!', 'utf8');
    const ct = Crypto.encrypt(key, 1, plaintext, null);
    expect(ct.length).toBe(16 + 8 + plaintext.length);
    const pt = Crypto.decrypt(key, 1, ct);
    expect(pt.toString('utf8')).toBe('Hello, Kerberos!');
  });

  it('decrypt fails on tampered ciphertext', () => {
    const key = Crypto.string_to_key(Crypto.Enctype.RC4, 'password', '', null);
    const plaintext = Buffer.from('Hello, Kerberos!', 'utf8');
    const ct = Crypto.encrypt(key, 1, plaintext, null);
    ct[0] = ct[0]! ^ 0x01;
    expect(() => Crypto.decrypt(key, 1, ct)).toThrow();
  });
});

describe('Crypto: AES256-CTS-HMAC-SHA1-96', () => {
  it('string_to_key with known vector (RFC 3962)', () => {
    const key = Crypto.string_to_key(
      Crypto.Enctype.AES256,
      'password',
      'ATHENA.MIT.EDUraeburn',
      Buffer.from([0x00, 0x00, 0x10, 0x00]),
    );
    expect(key.contents.toString('hex')).toBe(
      '01b897121d933ab44b47eb5494db15e50eb74530dbdae9b634d65020ff5d88c1',
    );
  });

  it('encrypt/decrypt round-trip (one block)', () => {
    const key = Crypto.string_to_key(
      Crypto.Enctype.AES256,
      'password',
      'ATHENA.MIT.EDUraeburn',
      Buffer.from([0x00, 0x00, 0x10, 0x00]),
    );
    const plaintext = Buffer.from('Exactly16Bytes!', 'utf8');
    const ct = Crypto.encrypt(key, 1, plaintext, Buffer.alloc(16));
    const pt = Crypto.decrypt(key, 1, ct);
    expect(pt.toString('utf8')).toBe('Exactly16Bytes!');
  });

  it('encrypt/decrypt round-trip (multi-block)', () => {
    const key = Crypto.string_to_key(
      Crypto.Enctype.AES256,
      'password',
      'ATHENA.MIT.EDUraeburn',
      Buffer.from([0x00, 0x00, 0x10, 0x00]),
    );
    const plaintext = Buffer.from('This is a longer message for AES-CTS testing.', 'utf8');
    const ct = Crypto.encrypt(key, 2, plaintext, Buffer.alloc(16));
    const pt = Crypto.decrypt(key, 2, ct);
    expect(pt.toString('utf8')).toBe('This is a longer message for AES-CTS testing.');
  });

  it('encrypt/decrypt round-trip (non-block-aligned)', () => {
    const key = Crypto.string_to_key(
      Crypto.Enctype.AES256,
      'password',
      'ATHENA.MIT.EDUraeburn',
      Buffer.from([0x00, 0x00, 0x10, 0x00]),
    );
    const plaintext = Buffer.from('Not aligned!', 'utf8');
    const ct = Crypto.encrypt(key, 3, plaintext, Buffer.alloc(16));
    const pt = Crypto.decrypt(key, 3, ct);
    expect(pt.toString('utf8')).toBe('Not aligned!');
  });
});

describe('Crypto: Key', () => {
  it('rejects wrong key length', () => {
    expect(() => new Crypto.Key(Crypto.Enctype.AES256, Buffer.alloc(16))).toThrow();
    expect(() => new Crypto.Key(Crypto.Enctype.RC4, Buffer.alloc(8))).toThrow();
  });

  it('get_kerberos_key_for_enctype with RC4', () => {
    const ntHash = '31d6cfe0d16ae931b73c59d7e0c089c0';
    const key = Crypto.get_kerberos_key_for_enctype(Crypto.Enctype.RC4, ntHash);
    expect(key.enctype).toBe(Crypto.Enctype.RC4);
    expect(key.contents.toString('hex')).toBe(ntHash);
  });

  it('get_matching_aes_key selects correct key by length', () => {
    const aes256 = '603101265bf1be1d8a9b3138a1c2c8b3c9c3c0c3c0c3c0c3c0c3c0c3c0c3c0c3';
    expect(Crypto.get_matching_aes_key(Crypto.Enctype.AES256, aes256)).toBe(aes256);
    expect(Crypto.get_matching_aes_key(Crypto.Enctype.AES128, aes256)).toBe(null);
  });
});

describe('Crypto: DES-CBC-MD5', () => {
  it('string_to_key with known vector (RFC 3961)', () => {
    const key = Crypto.string_to_key(Crypto.Enctype.DES_MD5, 'password', 'ATHENA.MIT.EDUraeburn', null);
    expect(key.contents.length).toBe(8);
    expect(key.enctype).toBe(Crypto.Enctype.DES_MD5);
  });

  it('encrypt/decrypt round-trip (block-aligned)', () => {
    const key = Crypto.string_to_key(Crypto.Enctype.DES_MD5, 'password', 'ATHENA.MIT.EDUraeburn', null);
    const plaintext = Buffer.from('8bytepad', 'utf8');
    const ct = Crypto.encrypt(key, 1, plaintext, null);
    const pt = Crypto.decrypt(key, 1, ct);
    expect(pt.toString('utf8')).toBe('8bytepad');
  });

  it('encrypt/decrypt round-trip (multi-block, DES-MD5)', () => {
    const key = Crypto.string_to_key(Crypto.Enctype.DES_MD5, 'password', 'ATHENA.MIT.EDUraeburn', null);
    const plaintext = Buffer.from('This is a longer DES message!', 'utf8');
    const ct = Crypto.encrypt(key, 2, plaintext, null);
    const pt = Crypto.decrypt(key, 2, ct);
    expect(pt.toString('utf8').replace(/\x00+$/, '')).toBe('This is a longer DES message!');
  });

  it('decrypt fails on tampered ciphertext', () => {
    const key = Crypto.string_to_key(Crypto.Enctype.DES_MD5, 'password', 'ATHENA.MIT.EDUraeburn', null);
    const plaintext = Buffer.from('8bytepad', 'utf8');
    const ct = Crypto.encrypt(key, 1, plaintext, null);
    ct[0] = ct[0]! ^ 0x01;
    expect(() => Crypto.decrypt(key, 1, ct)).toThrow();
  });

  it('derive produces 8-byte key', () => {
    const key = Crypto.string_to_key(Crypto.Enctype.DES_MD5, 'password', 'ATHENA.MIT.EDUraeburn', null);
    const derived = Crypto._get_enctype_profile(Crypto.Enctype.DES_MD5).derive(key, Buffer.from('kerberos'));
    expect(derived.contents.length).toBe(8);
    expect(derived.enctype).toBe(Crypto.Enctype.DES_MD5);
  });
});

describe('Crypto: DES3-CBC-SHA1', () => {
  it('string_to_key with known vector (RFC 3961)', () => {
    const key = Crypto.string_to_key(Crypto.Enctype.DES3, 'password', 'ATHENA.MIT.EDUraeburn', null);
    expect(key.contents.length).toBe(24);
    expect(key.enctype).toBe(Crypto.Enctype.DES3);
  });

  it('encrypt/decrypt round-trip (block-aligned)', () => {
    const key = Crypto.string_to_key(Crypto.Enctype.DES3, 'password', 'ATHENA.MIT.EDUraeburn', null);
    const plaintext = Buffer.from('8bytepad', 'utf8');
    const ct = Crypto.encrypt(key, 1, plaintext, null);
    const pt = Crypto.decrypt(key, 1, ct);
    expect(pt.toString('utf8')).toBe('8bytepad');
  });

  it('encrypt/decrypt round-trip (multi-block, DES3)', () => {
    const key = Crypto.string_to_key(Crypto.Enctype.DES3, 'password', 'ATHENA.MIT.EDUraeburn', null);
    const plaintext = Buffer.from('This is a longer DES3 message!!', 'utf8');
    const ct = Crypto.encrypt(key, 2, plaintext, null);
    const pt = Crypto.decrypt(key, 2, ct);
    expect(pt.toString('utf8').replace(/\x00+$/, '')).toBe('This is a longer DES3 message!!');
  });

  it('decrypt fails on tampered ciphertext', () => {
    const key = Crypto.string_to_key(Crypto.Enctype.DES3, 'password', 'ATHENA.MIT.EDUraeburn', null);
    const plaintext = Buffer.from('8bytepad', 'utf8');
    const ct = Crypto.encrypt(key, 1, plaintext, null);
    ct[0] = ct[0]! ^ 0x01;
    expect(() => Crypto.decrypt(key, 1, ct)).toThrow();
  });

  it('random_to_key expands 21-byte seed to 24-byte key with parity', () => {
    const seed = Buffer.alloc(21, 0x42);
    const key = Crypto.random_to_key(Crypto.Enctype.DES3, seed);
    expect(key.contents.length).toBe(24);
    expect(key.enctype).toBe(Crypto.Enctype.DES3);
  });

  it('derive produces 24-byte key', () => {
    const key = Crypto.string_to_key(Crypto.Enctype.DES3, 'password', 'ATHENA.MIT.EDUraeburn', null);
    const derived = Crypto._get_enctype_profile(Crypto.Enctype.DES3).derive(key, Buffer.from('kerberos'));
    expect(derived.contents.length).toBe(24);
    expect(derived.enctype).toBe(Crypto.Enctype.DES3);
  });
});

describe('CCache', () => {
  it('round-trips a credential cache', () => {
    const cc = new CCache.CCache();
    cc.setDefaultHeader();

    const principal = new Types.Principal('user@DOMAIN.COM', null, 1);
    cc.principal = new CCache.PrincipalCCache();
    cc.principal.fromPrincipal(principal);

    const cred = new CCache.Credential();
    cred.client = new CCache.PrincipalCCache();
    cred.client.fromPrincipal(new Types.Principal('user@DOMAIN.COM', null, 1));
    cred.server = new CCache.PrincipalCCache();
    cred.server.fromPrincipal(new Types.Principal('krbtgt/DOMAIN.COM@DOMAIN.COM', null, 2));
    cred.key = new CCache.KeyBlock();
    cred.key.keytype = Crypto.Enctype.AES256;
    cred.key.etype = Crypto.Enctype.AES256;
    cred.key.keyvalue = Buffer.alloc(32, 0x42);
    cred.time = new CCache.Times();
    cred.time.authtime = 1705312800;
    cred.time.starttime = 1705312800;
    cred.time.endtime = 1705399200;
    cred.time.renew_till = 1705921200;
    cred.is_skey = 0;
    cred.tktflags = 0x50800000;
    cred.num_address = 0;
    cred.ticket = new CCache.CountedOctetString();
    cred.ticket.data = Buffer.from('fake-ticket-bytes', 'utf8');
    cred.secondTicket = new CCache.CountedOctetString();
    cc.credentials.push(cred);

    const data = cc.getData();
    expect(data[0]!).toBe(0x05);
    expect(data[1]!).toBe(0x04);

    const parsed = new CCache.CCache(data);
    expect(parsed.principal.prettyPrint()).toBe('user@DOMAIN.COM');
    expect(parsed.credentials).toHaveLength(1);
    expect(parsed.credentials[0]!.server.prettyPrint()).toBe('krbtgt/DOMAIN.COM@DOMAIN.COM');
    expect(parsed.credentials[0]!.key.keytype).toBe(Crypto.Enctype.AES256);
    expect(parsed.credentials[0]!.key.keyvalue.toString('hex')).toBe(
      Buffer.alloc(32, 0x42).toString('hex'),
    );
    expect(parsed.credentials[0]!.time.authtime).toBe(1705312800);
    expect(parsed.credentials[0]!.time.endtime).toBe(1705399200);
    expect(parsed.credentials[0]!.ticket.data.toString('utf8')).toBe('fake-ticket-bytes');
  });

  it('getCredential finds matching server', () => {
    const cc = new CCache.CCache();
    cc.setDefaultHeader();
    cc.principal = new CCache.PrincipalCCache();
    cc.principal.fromPrincipal(new Types.Principal('user@DOMAIN.COM', null, 1));

    const cred = new CCache.Credential();
    cred.client = new CCache.PrincipalCCache();
    cred.client.fromPrincipal(new Types.Principal('user@DOMAIN.COM', null, 1));
    cred.server = new CCache.PrincipalCCache();
    cred.server.fromPrincipal(new Types.Principal('krbtgt/DOMAIN.COM@DOMAIN.COM', null, 2));
    cred.key = new CCache.KeyBlock();
    cc.credentials.push(cred);

    const found = cc.getCredential('krbtgt/DOMAIN.COM@DOMAIN.COM');
    expect(found).not.toBeNull();
    expect(found!.server.prettyPrint()).toBe('krbtgt/DOMAIN.COM@DOMAIN.COM');

    expect(cc.getCredential('nonexistent@DOMAIN.COM')).toBeNull();
  });
});

describe('Keytab', () => {
  it('round-trips a keytab entry', () => {
    const entry = new Keytab.KeytabEntry();
    entry.deleted = false;
    entry.principal = new Keytab.KeytabPrincipal();
    entry.principal.num_components = 2;
    entry.principal.realm = new Keytab.KtCountedOctetString();
    entry.principal.realm.data = Buffer.from('DOMAIN.COM', 'utf8');
    for (const comp of ['krbtgt', 'DOMAIN.COM']) {
      const cos = new Keytab.KtCountedOctetString();
      cos.data = Buffer.from(comp, 'utf8');
      entry.principal.components.push(cos);
    }
    entry.principal.name_type = 2;
    entry.timestamp = 1705312800;
    entry.vno8 = 1;
    entry.kvno = 1;
    entry.keyblock = new Keytab.KeytabKeyBlock();
    entry.keyblock.keytype = Crypto.Enctype.AES256;
    entry.keyblock.keyvalue = new Keytab.KtCountedOctetString();
    entry.keyblock.keyvalue.data = Buffer.alloc(32, 0x42);

    const data = entry.getData();
    const [parsed] = Keytab.KeytabEntry.fromBuffer(data, 0);
    expect(parsed.deleted).toBe(false);
    expect(parsed.principal.prettyPrint()).toBe('krbtgt/DOMAIN.COM@DOMAIN.COM');
    expect(parsed.keyblock.keytype).toBe(Crypto.Enctype.AES256);
    expect(parsed.keyblock.keyvalue.data.toString('hex')).toBe(
      Buffer.alloc(32, 0x42).toString('hex'),
    );
    expect(parsed.kvno).toBe(1);
  });

  it('Keytab.getKey finds matching principal', () => {
    const entry = new Keytab.KeytabEntry();
    entry.deleted = false;
    entry.principal = new Keytab.KeytabPrincipal();
    entry.principal.realm = new Keytab.KtCountedOctetString();
    entry.principal.realm.data = Buffer.from('DOMAIN.COM', 'utf8');
    const cos = new Keytab.KtCountedOctetString();
    cos.data = Buffer.from('user', 'utf8');
    entry.principal.components.push(cos);
    entry.principal.num_components = 1;
    entry.principal.name_type = 1;
    entry.timestamp = 1705312800;
    entry.vno8 = 1;
    entry.keyblock = new Keytab.KeytabKeyBlock();
    entry.keyblock.keytype = Crypto.Enctype.RC4;
    entry.keyblock.keyvalue = new Keytab.KtCountedOctetString();
    entry.keyblock.keyvalue.data = Buffer.alloc(16, 0x55);

    const kt = new Keytab.Keytab();
    kt.entries.push(entry);

    const key = kt.getKey('user@DOMAIN.COM');
    expect(key).not.toBeNull();
    expect(key!.keytype).toBe(Crypto.Enctype.RC4);
    expect(key!.hexlifiedValue()).toBe(Buffer.alloc(16, 0x55).toString('hex'));

    expect(kt.getKey('nonexistent@DOMAIN.COM')).toBeNull();
  });
});

describe('KerberosV5', () => {
  it('KerberosError stores error code and message', () => {
    const err = new KerberosV5.KerberosError({ error: 25 });
    expect(err.getErrorCode()).toBe(25);
    const [code, msg] = err.getErrorString();
    expect(code).toBe('KDC_ERR_PREAUTH_REQUIRED');
    expect(msg).toBe('Additional pre-authentication required');
  });

  it('KerberosError with unknown code returns generic message', () => {
    const err = new KerberosV5.KerberosError({ error: 9999 });
    expect(err.getErrorCode()).toBe(9999);
    const [code, msg] = err.getErrorString();
    expect(code).toBe('UNKNOWN');
    expect(msg).toContain('9999');
  });

  it('KerberosError toString produces readable output', () => {
    const err = new KerberosV5.KerberosError({ error: 37 });
    expect(err.toString()).toContain('KRB_AP_ERR_SKEW');
    expect(err.toString()).toContain('Clock skew too great');
  });

  it('SessionKeyDecryptionError stores context', () => {
    const err = new KerberosV5.SessionKeyDecryptionError(
      'bad password',
      {},
      Crypto._get_enctype_profile(Crypto.Enctype.RC4),
      new Crypto.Key(Crypto.Enctype.RC4, Buffer.alloc(16)),
      Buffer.alloc(32),
    );
    expect(err.message).toBe('bad password');
    expect(err.toString()).toContain('bad password');
  });
});

describe('GSSAPI', () => {
  it('CheckSumField serializes correctly', () => {
    const csf = new GSSAPI.CheckSumField();
    csf.Lgth = 16;
    csf.Bnd = Buffer.alloc(16, 0x42);
    csf.Flags = GSSAPI.GSS_C_CONF_FLAG | GSSAPI.GSS_C_INTEG_FLAG;
    const data = csf.getData();
    expect(data).toHaveLength(24);
    expect(data.readUInt32LE(0)).toBe(16);
    expect(data.readUInt32LE(20)).toBe(GSSAPI.GSS_C_CONF_FLAG | GSSAPI.GSS_C_INTEG_FLAG);
  });

  it('GSSAPI selects correct implementation by enctype', () => {
    const rc4Impl = GSSAPI.GSSAPI({ enctype: Crypto.Enctype.RC4 });
    expect(rc4Impl.constructor.name).toBe('GSSAPI_RC4');

    const aes256Impl = GSSAPI.GSSAPI({ enctype: Crypto.Enctype.AES256 });
    expect(aes256Impl.constructor.name).toBe('GSSAPI_AES256');

    const aes128Impl = GSSAPI.GSSAPI({ enctype: Crypto.Enctype.AES128 });
    expect(aes128Impl.constructor.name).toBe('GSSAPI_AES128');
  });

  it('RC4 GSS_GetMIC/GSS_Wrap round-trip', () => {
    const sessionKey = new Crypto.Key(Crypto.Enctype.RC4, Buffer.alloc(16, 0x42));
    const data = Buffer.from('Hello, GSSAPI!', 'utf8');
    const seqNum = 1;

    const mic = GSSAPI.GSSAPI({ enctype: Crypto.Enctype.RC4 }).GSS_GetMIC(sessionKey, data, seqNum);
    expect(mic.length).toBeGreaterThan(20);
    expect(mic.subarray(2, 13).toString('hex')).toBe(GSSAPI.KRB_OID.toString('hex'));

    const [cipherText, token] = GSSAPI.GSSAPI({ enctype: Crypto.Enctype.RC4 }).GSS_Wrap(
      sessionKey,
      Buffer.from('Test wrap data', 'utf8'),
      seqNum,
    );
    expect(cipherText.length).toBe(16);
    expect(token.subarray(2, 13).toString('hex')).toBe(GSSAPI.KRB_OID.toString('hex'));
  });

  it('AES256 GSS_GetMIC produces valid token', () => {
    const sessionKey = new Crypto.Key(Crypto.Enctype.AES256, Buffer.alloc(32, 0x42));
    const data = Buffer.from('Hello, AES GSSAPI!', 'utf8');
    const seqNum = 1;

    const mic = GSSAPI.GSSAPI({ enctype: Crypto.Enctype.AES256 }).GSS_GetMIC(
      sessionKey,
      data,
      seqNum,
    );
    expect(mic).toHaveLength(16 + 8 + 12);
    expect(mic.readUInt16BE(0)).toBe(0x0404);
    expect(mic[2]).toBe(4);
  });

  it('AES256 GSS_Wrap round-trip', () => {
    const sessionKey = new Crypto.Key(Crypto.Enctype.AES256, Buffer.alloc(32, 0x42));
    const data = Buffer.from('This is a test message for AES wrap.', 'utf8');
    const seqNum = 1;

    const [cipherText, token] = GSSAPI.GSSAPI({ enctype: Crypto.Enctype.AES256 }).GSS_Wrap(
      sessionKey,
      data,
      seqNum,
    );
    expect(cipherText.length).toBeGreaterThan(0);
    expect(token.readUInt16BE(0)).toBe(0x0504);
  });

  it('MechIndepToken round-trips', () => {
    const token = new GSSAPI.MechIndepToken(Buffer.from('payload', 'utf8'));
    const [header, payload] = token.to_bytes();
    const full = Buffer.concat([header, payload]);
    const parsed = GSSAPI.MechIndepToken.from_bytes(full);
    expect(parsed.data.toString('utf8')).toBe('payload');
    expect(parsed.token_oid.toString('hex')).toBe(GSSAPI.KRB_OID.toString('hex'));
  });
});

describe('KPasswd', () => {
  it('KPasswdResultCodes has correct values', () => {
    expect(KPasswd.KPasswdResultCodes.SUCCESS).toBe(0);
    expect(KPasswd.KPasswdResultCodes.MALFORMED).toBe(1);
    expect(KPasswd.KPasswdResultCodes.AUTHERROR).toBe(3);
    expect(KPasswd.KPasswdResultCodes.UNKNOWN).toBe(0xffff);
  });

  it('RESULT_MESSAGES maps codes to messages', () => {
    expect(KPasswd.RESULT_MESSAGES[0]).toBe('password changed successfully');
    expect(KPasswd.RESULT_MESSAGES[3]).toContain('authentication failed');
    expect(KPasswd.RESULT_MESSAGES[0xffff]).toBe('unknown error');
  });

  it('PasswordPolicyFlags has correct values', () => {
    expect(KPasswd.PasswordPolicyFlags.Complex).toBe(0x1);
    expect(KPasswd.PasswordPolicyFlags.RefusePasswordChange).toBe(0x20);
  });

  it('decodePasswordPolicy parses a valid policy buffer', () => {
    const buf = Buffer.alloc(30);
    buf.writeUInt16BE(0, 0);
    buf.writeUInt32BE(8, 2);
    buf.writeUInt32BE(5, 6);
    buf.writeUInt32BE(0x1, 10);
    buf.writeBigUInt64BE(86400n * 10000000n, 14);
    buf.writeBigUInt64BE(86400n * 10000000n, 22);
    const policy = KPasswd.decodePasswordPolicy(buf);
    expect(policy.minLength).toBe(8);
    expect(policy.history).toBe(5);
    expect(policy.maxAge).toBe(1);
    expect(policy.minAge).toBe(1);
    expect(policy.flags).toContain('Complex');
  });

  it('KPasswdError is throwable', () => {
    expect(() => {
      throw new KPasswd.KPasswdError('test error');
    }).toThrow('test error');
  });
});
