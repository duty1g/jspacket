import { describe, it, expect } from 'vitest';
import { Buffer } from 'node:buffer';
import {
  FileNTUser,
  ACL_SID,
  FileNTACE,
  SecurityAttributes,
  SMB_ACE_FLAG_OI,
  SMB_ACE_FLAG_CI,
  SEC_INFO_SPECIFIC_FULL,
  SUPPORTED_PERMISSIONS,
} from '../src';

describe('acl', () => {
  it('ACL_SID round-trip from string', () => {
    const sid = ACL_SID.buildFromString('S-1-5-32-544');
    expect(sid.toString()).toBe('S-1-5-32-544');
  });

  it('ACL_SID round-trip domain SID', () => {
    const sid = ACL_SID.buildFromString('S-1-5-21-316352084-282881915-462937787-500');
    expect(sid.toString()).toBe('S-1-5-21-316352084-282881915-462937787-500');
  });

  it('ACL_SID from raw bytes', () => {
    const raw = Buffer.concat([
      Buffer.from([1, 5]),
      Buffer.alloc(5, 0),
      Buffer.from([5]),
      Buffer.alloc(20, 0),
    ]);
    raw.writeUInt32LE(21, 8);
    raw.writeUInt32LE(316352084, 12);
    raw.writeUInt32LE(282881915, 16);
    raw.writeUInt32LE(462937787, 20);
    raw.writeUInt32LE(500, 24);
    const sid = new ACL_SID(raw);
    expect(sid.toString()).toBe('S-1-5-21-316352084-282881915-462937787-500');
  });

  it('FileNTACE flags readable', () => {
    const raw = Buffer.alloc(8 + 28);
    raw.writeUInt8(0, 0);
    raw.writeUInt8(SMB_ACE_FLAG_OI | SMB_ACE_FLAG_CI, 1);
    raw.writeUInt16LE(8 + 28, 2);
    raw.writeUInt16LE(SEC_INFO_SPECIFIC_FULL, 4);
    const ace = new FileNTACE(raw);
    expect(ace.getReadableNtaceFlags()).toBe('(OI)(CI)');
    expect(ace.getReadableSpecificRights()).toBe('(F)');
    expect(ace.toString()).toBe('(OI)(CI)(F)');
  });

  it('FileNTUser round-trip', () => {
    const nt = new FileNTUser();
    nt.set('NumACEs', 2);
    nt.set('Buffer', Buffer.alloc(16, 0));
    const data = nt.getData();
    const nt2 = new FileNTUser(data);
    expect(nt2.get('NumACEs')).toBe(2);
  });

  it('SUPPORTED_PERMISSIONS has F=full', () => {
    expect(SUPPORTED_PERMISSIONS.F).toBe(0x001f01ff);
  });

  it('SecurityAttributes toString', () => {
    const sa = new SecurityAttributes('SYSTEM', 'SYSTEM');
    sa.readableDacls.set('S-1-5-32-544', 'BUILTIN\\Administrators:(F)');
    expect(sa.toString()).toContain('Owner:');
    expect(sa.toString()).toContain('BUILTIN\\Administrators:(F)');
  });
});
