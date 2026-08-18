import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import {
  DRS_HANDLE,
  DSNAME,
  WCHAR_ARRAY,
  DRS_MSG_CRACKREQ_V1,
  EXOP_ERR,
  DS_NAME_FORMAT,
  makeAttid,
  oidFromAttid,
  deriveKey,
  removeDESLayer,
  type PrefixTableEntryLike,
} from '../src/drsuapi';
import { ULONG } from '../src/dtypes';

describe('drsuapi constants & enums', () => {
  it('EXOP_ERR has 4-byte alignment and ULONG data', () => {
    const e = new EXOP_ERR();
    expect(e.getAlignment()).toBe(4);
    e.set('Data', 'EXOP_ERR_SUCCESS');
    expect(e.get('Data')).toBe(1);
    const data = e.getData();
    expect(data.length).toBe(4);
    expect(data.readUInt32LE(0)).toBe(1);
  });

  it('DS_NAME_FORMAT maps names to values', () => {
    const e = new DS_NAME_FORMAT();
    e.set('Data', 'DS_FQDN_1779_NAME');
    expect(e.get('Data')).toBe(1);
    e.set('Data', 'DS_USER_PRINCIPAL_NAME');
    expect(e.get('Data')).toBe(8);
  });
});

describe('drsuapi structures', () => {
  it('round-trips DRS_HANDLE (20-byte fixed)', () => {
    const h = new DRS_HANDLE();
    const buf = Buffer.alloc(20, 0xab);
    h.set('Data', buf);
    const data = h.getData();
    expect(data.length).toBe(20);
    expect(data.equals(Buffer.alloc(20, 0xab))).toBe(true);
    const parsed = new DRS_HANDLE(data);
    expect((parsed.get('Data') as Buffer).equals(Buffer.alloc(20, 0xab))).toBe(true);
  });

  it('round-trips DSNAME with WCHAR_ARRAY', () => {
    const dn = new DSNAME();
    dn.set('structLen', 0x50);
    dn.set('SidLen', 0);
    dn.set('NameLen', 7);
    dn.set('StringName', 'DC=test');

    const data = dn.getData();
    expect(data.length).toBeGreaterThan(40);

    const parsed = new DSNAME(data);
    expect(parsed.get('structLen')).toBe(0x50);
    expect(parsed.get('SidLen')).toBe(0);
    expect(parsed.get('NameLen')).toBe(7);
    const stringName = parsed.fields['StringName'] as WCHAR_ARRAY;
    expect(stringName.get('Data')).toBe('DC=test');
  });

  it('round-trips DRS_MSG_CRACKREQ_V1', () => {
    const req = new DRS_MSG_CRACKREQ_V1();
    req.set('CodePage', 0);
    req.set('LocaleId', 0);
    req.set('dwFlags', 0);
    req.set('formatOffered', DS_NAME_FORMAT.enumValues.DS_UNKNOWN_NAME);
    req.set('formatDesired', DS_NAME_FORMAT.enumValues.DS_FQDN_1779_NAME);
    req.set('cNames', 1);

    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);

    const parsed = new DRS_MSG_CRACKREQ_V1(data);
    expect(parsed.get('CodePage')).toBe(0);
    expect(parsed.get('formatDesired')).toBe(1);
    expect(parsed.get('cNames')).toBe(1);
  });
});

describe('drsuapi MakeAttid / OidFromAttid', () => {
  it('matches Python impacket known-answer vectors', () => {
    const prefixTable: PrefixTableEntryLike[] = [];
    const oids = [
      '1.2.840.113556.1.4.94',
      '2.5.6.2',
      '1.2.840.113556.1.2.1',
      '1.2.840.113556.1.3.223',
      '1.2.840.113556.1.5.7000.53',
    ];
    const expected = [0x5e, 0x10002, 0x20001, 0x300df, 0x40035];

    for (let i = 0; i < oids.length; i++) {
      const attid = makeAttid(prefixTable, oids[i]!);
      expect(attid).toBe(expected[i]);
    }
  });

  it('round-trips OID → ATTRTYP → OID', () => {
    const prefixTable: PrefixTableEntryLike[] = [];
    const oids = [
      '1.2.840.113556.1.4.94',
      '2.5.6.2',
      '1.2.840.113556.1.2.1',
      '1.2.840.113556.1.3.223',
      '1.2.840.113556.1.5.7000.53',
    ];
    for (const oid of oids) {
      const attid = makeAttid(prefixTable, oid);
      const restored = oidFromAttid(prefixTable, attid);
      expect(restored).toBe(oid);
    }
  });
});

describe('drsuapi DES layer (removeDESLayer)', () => {
  it('derives keys matching Python impacket for RID 500', () => {
    const [k1, k2] = deriveKey(500);
    expect(k1.toString('hex')).toBe('f40040000ea00400');
    expect(k2.toString('hex')).toBe('007a00200006d002');
  });

  it('decrypts a known-answer vector matching Python impacket', () => {
    const encrypted = Buffer.alloc(16, 0x11);
    const decrypted = removeDESLayer(encrypted, 500);
    expect(decrypted.toString('hex')).toBe('a69970cdb400a19a7e704ddfc8977327');
  });
});
