import { Buffer } from 'node:buffer';
import { describe, it, expect } from 'vitest';
import {
  LDAP_SID,
  SR_SECURITY_DESCRIPTOR,
  ACCESS_MASK,
  ACE,
  ACL,
  ACCESS_ALLOWED_ACE,
  ACCESS_DENIED_ACE,
  ACCESS_ALLOWED_OBJECT_ACE,
  ACE_TYPE_MAP,
  OBJECTTYPE_GUID_MAP,
  LDAP_SERVER_SD_FLAGS,
} from '../src/ldaptypes.js';

describe('ldaptypes — LDAP_SID', () => {
  it('round-trips a canonical SID', () => {
    const sid = new LDAP_SID();
    sid.fromCanonical('S-1-5-32-544');
    expect(sid.get('Revision')).toBe(1);
    expect(sid.get('SubAuthorityCount')).toBe(2);
    expect(sid.formatCanonical()).toBe('S-1-5-32-544');
  });

  it('round-trips a well-known SID (Everyone)', () => {
    const sid = new LDAP_SID();
    sid.fromCanonical('S-1-1-0');
    expect(sid.formatCanonical()).toBe('S-1-1-0');
  });

  it('round-trips a domain SID with 5 sub-authorities', () => {
    const sid = new LDAP_SID();
    sid.fromCanonical('S-1-5-21-3623811015-3361044348-30300820-1001');
    expect(sid.get('SubAuthorityCount')).toBe(5);
    expect(sid.formatCanonical()).toBe('S-1-5-21-3623811015-3361044348-30300820-1001');
  });

  it('parses from binary data', () => {
    const sid = new LDAP_SID();
    sid.fromCanonical('S-1-5-21-3623811015-3361044348-30300820-1001');
    const data = sid.getData();
    const sid2 = new LDAP_SID(data);
    expect(sid2.get('Revision')).toBe(1);
    expect(sid2.get('SubAuthorityCount')).toBe(5);
    expect(sid2.formatCanonical()).toBe('S-1-5-21-3623811015-3361044348-30300820-1001');
  });
});

describe('ldaptypes — ACCESS_MASK', () => {
  it('sets and checks privileges', () => {
    const mask = new ACCESS_MASK();
    mask.set('Mask', 0);
    mask.setPriv(ACCESS_MASK.GENERIC_READ);
    mask.setPriv(ACCESS_MASK.GENERIC_WRITE);
    expect(mask.hasPriv(ACCESS_MASK.GENERIC_READ)).toBe(true);
    expect(mask.hasPriv(ACCESS_MASK.GENERIC_ALL)).toBe(false);
    expect(mask.get('Mask')).toBe((ACCESS_MASK.GENERIC_READ | ACCESS_MASK.GENERIC_WRITE) >>> 0);
  });

  it('removes privileges', () => {
    const mask = new ACCESS_MASK();
    mask.set('Mask', ACCESS_MASK.GENERIC_READ | ACCESS_MASK.GENERIC_WRITE);
    mask.removePriv(ACCESS_MASK.GENERIC_WRITE);
    expect(mask.hasPriv(ACCESS_MASK.GENERIC_WRITE)).toBe(false);
    expect(mask.hasPriv(ACCESS_MASK.GENERIC_READ)).toBe(true);
  });
});

describe('ldaptypes — ACE and ACL', () => {
  it('builds an ACCESS_ALLOWED_ACE and round-trips through ACE', () => {
    const sid = new LDAP_SID();
    sid.fromCanonical('S-1-1-0');
    const aceBody = new ACCESS_ALLOWED_ACE();
    aceBody.set('Mask', new ACCESS_MASK());
    (aceBody.get('Mask') as ACCESS_MASK).set('Mask', 0x20000000);
    aceBody.set('Sid', sid);
    const ace = new ACE();
    ace.set('AceType', ACCESS_ALLOWED_ACE.ACE_TYPE);
    ace.set('AceFlags', 0);
    ace.aceData = aceBody;
    const data = ace.getData();
    expect(data.length).toBeGreaterThanOrEqual(4 + 4 + 8);
    const ace2 = new ACE(data);
    expect(ace2.get('AceType')).toBe(ACCESS_ALLOWED_ACE.ACE_TYPE);
    expect(ace2.typeName).toBe('ACCESS_ALLOWED_ACE');
  });

  it('builds an ACL with multiple ACEs', () => {
    const sid1 = new LDAP_SID();
    sid1.fromCanonical('S-1-1-0');
    const aceBody1 = new ACCESS_ALLOWED_ACE();
    aceBody1.set('Mask', new ACCESS_MASK());
    (aceBody1.get('Mask') as ACCESS_MASK).set('Mask', 0x10000000);
    aceBody1.set('Sid', sid1);
    const ace1 = new ACE();
    ace1.set('AceType', ACCESS_ALLOWED_ACE.ACE_TYPE);
    ace1.set('AceFlags', 0);
    ace1.aceData = aceBody1;

    const sid2 = new LDAP_SID();
    sid2.fromCanonical('S-1-5-32-544');
    const aceBody2 = new ACCESS_DENIED_ACE();
    aceBody2.set('Mask', new ACCESS_MASK());
    (aceBody2.get('Mask') as ACCESS_MASK).set('Mask', 0x00010000);
    aceBody2.set('Sid', sid2);
    const ace2 = new ACE();
    ace2.set('AceType', ACCESS_DENIED_ACE.ACE_TYPE);
    ace2.set('AceFlags', 0);
    ace2.aceData = aceBody2;

    const acl = new ACL();
    acl.aces = [ace1, ace2];
    const data = acl.getData();
    expect(data.length).toBeGreaterThanOrEqual(8);
    expect(acl.get('AceCount')).toBe(2);

    const acl2 = new ACL(data);
    expect(acl2.aces.length).toBe(2);
    expect(acl2.aces[0]!.get('AceType')).toBe(ACCESS_ALLOWED_ACE.ACE_TYPE);
    expect(acl2.aces[1]!.get('AceType')).toBe(ACCESS_DENIED_ACE.ACE_TYPE);
  });
});

describe('ldaptypes — ACE_TYPE_MAP', () => {
  it('maps all ACE types', () => {
    expect(ACE_TYPE_MAP[0x00]).toBe(ACCESS_ALLOWED_ACE);
    expect(ACE_TYPE_MAP[0x01]).toBe(ACCESS_DENIED_ACE);
    expect(ACE_TYPE_MAP[0x05]).toBe(ACCESS_ALLOWED_OBJECT_ACE);
    expect(ACE_TYPE_MAP[0x13]).toBeDefined();
  });
});

describe('ldaptypes — OBJECTTYPE_GUID_MAP', () => {
  it('maps common object classes', () => {
    expect(OBJECTTYPE_GUID_MAP['user']).toBe('bf967aba-0de6-11d0-a285-00aa003049e2');
    expect(OBJECTTYPE_GUID_MAP['group']).toBe('bf967a9c-0de6-11d0-a285-00aa003049e2');
    expect(OBJECTTYPE_GUID_MAP['domain']).toBe('19195a5a-6da0-11d0-afd3-00c04fd930c9');
  });
});

describe('ldaptypes — LDAP_SERVER_SD_FLAGS', () => {
  it('has correct flag values', () => {
    expect(LDAP_SERVER_SD_FLAGS.OWNER_SECURITY_INFORMATION).toBe(0x1);
    expect(LDAP_SERVER_SD_FLAGS.GROUP_SECURITY_INFORMATION).toBe(0x2);
    expect(LDAP_SERVER_SD_FLAGS.DACL_SECURITY_INFORMATION).toBe(0x4);
    expect(LDAP_SERVER_SD_FLAGS.SACL_SECURITY_INFORMATION).toBe(0x8);
  });
});
