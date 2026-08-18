import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import {
  SHARE_DEL_HANDLE,
  SHARE_INFO_1,
  SHARE_INFO_502,
  SHARE_ENUM_STRUCT,
  SHARE_ENUM_UNION,
  SERVER_INFO_101,
  STAT_SERVER_0,
  CONNECTION_INFO_1,
  FILE_INFO_3,
  SESSION_INFO_1,
  TIME_OF_DAY_INFO,
  PASSWORD_ARRAY,
  DISK_INFO,
  NetrShareEnum,
  NetrShareEnumResponse,
  NetrServerGetInfo,
  NetrServerGetInfoResponse,
  NetrRemoteTOD,
  NetrRemoteTODResponse,
  NetrFileClose,
  STYPE_DISKTREE,
  STYPE_IPC,
  STYPE_SPECIAL,
  STYPE_MASK,
  PLATFORM_ID_NT,
  SV_TYPE_SERVER,
  SV_TYPE_DOMAIN_CTRL,
  SV_TYPE_ALL,
  SESS_GUEST,
  SESS_NOENCRYPTION,
  PERM_FILE_READ,
  PERM_FILE_WRITE,
  SHARE_NETNAME_PARMNUM,
  SHARE_PATH_PARMNUM,
  SHI1005_FLAGS_DFS,
  FILE_SUPERSEDE,
  FILE_OPEN,
  FILE_CREATE,
  MSRPC_UUID_SRVS,
} from '../src/srvs';
import { NULL } from '../src/ndr';

describe('srvs UUID', () => {
  it('MSRPC_UUID_SRVS matches [MS-SRVS] 1.9', () => {
    expect(MSRPC_UUID_SRVS.length).toBe(20);
    const uuidHex = MSRPC_UUID_SRVS.subarray(0, 16).toString('hex');
    expect(uuidHex).toBe('c84f324b7016d30112785a47bf6ee188');
  });
});

describe('srvs constants', () => {
  it('STYPE_* match [MS-SRVS] 2.2.2.4', () => {
    expect(STYPE_DISKTREE).toBe(0x00000000);
    expect(STYPE_IPC).toBe(0x00000003);
    expect(STYPE_SPECIAL).toBe(0x80000000);
    expect(STYPE_MASK).toBe(0x000000ff);
  });

  it('PLATFORM_ID_NT is 500 per [MS-SRVS] 2.2.2.6', () => {
    expect(PLATFORM_ID_NT).toBe(500);
  });

  it('SV_TYPE_* match [MS-SRVS] 2.2.2.7', () => {
    expect(SV_TYPE_SERVER).toBe(0x00000002);
    expect(SV_TYPE_DOMAIN_CTRL).toBe(0x00000008);
    expect(SV_TYPE_ALL).toBe(0xffffffff);
  });

  it('SESS_* flags match [MS-SRVS] 2.2.2.3', () => {
    expect(SESS_GUEST).toBe(0x00000001);
    expect(SESS_NOENCRYPTION).toBe(0x00000002);
  });

  it('PERM_* match [MS-SRVS] 2.2.4.7', () => {
    expect(PERM_FILE_READ).toBe(0x00000001);
    expect(PERM_FILE_WRITE).toBe(0x00000002);
  });

  it('SHARE_*_PARMNUM match [MS-SRVS] 2.2.2.11', () => {
    expect(SHARE_NETNAME_PARMNUM).toBe(1);
    expect(SHARE_PATH_PARMNUM).toBe(8);
  });

  it('SHI1005_FLAGS_DFS is 0x1 per [MS-SRVS] 2.2.4.29', () => {
    expect(SHI1005_FLAGS_DFS).toBe(0x00000001);
  });

  it('FILE_* disposition values match [MS-SRVS] 3.1.4.42', () => {
    expect(FILE_SUPERSEDE).toBe(0x00000000);
    expect(FILE_OPEN).toBe(0x00000001);
    expect(FILE_CREATE).toBe(0x00000002);
  });
});

describe('srvs structures', () => {
  it('SHARE_DEL_HANDLE is 20 bytes with 1-byte alignment', () => {
    const h = new SHARE_DEL_HANDLE();
    expect(h.getAlignment()).toBe(1);
    const data = h.getData();
    expect(data.length).toBe(20);
  });

  it('round-trips SHARE_INFO_1', () => {
    const info = new SHARE_INFO_1();
    info.set('shi1_type', STYPE_DISKTREE);
    const data = info.getData();
    expect(data.length).toBeGreaterThan(0);
    const parsed = new SHARE_INFO_1(data);
    expect(parsed.get('shi1_type')).toBe(STYPE_DISKTREE);
  });

  it('round-trips SERVER_INFO_101 with PLATFORM_ID_NT', () => {
    const info = new SERVER_INFO_101();
    info.set('sv101_platform_id', PLATFORM_ID_NT);
    info.set('sv101_version_major', 10);
    info.set('sv101_version_minor', 0);
    info.set('sv101_type', SV_TYPE_SERVER | SV_TYPE_DOMAIN_CTRL);
    const data = info.getData();
    const parsed = new SERVER_INFO_101(data);
    expect(parsed.get('sv101_platform_id')).toBe(PLATFORM_ID_NT);
    expect(parsed.get('sv101_version_major')).toBe(10);
    expect(parsed.get('sv101_type')).toBe(SV_TYPE_SERVER | SV_TYPE_DOMAIN_CTRL);
  });

  it('STAT_SERVER_0 has 17 DWORD fields = 68 bytes', () => {
    const stat = new STAT_SERVER_0();
    stat.set('sts0_start', 100);
    stat.set('sts0_fopens', 5);
    const data = stat.getData();
    expect(data.length).toBe(17 * 4);
    const parsed = new STAT_SERVER_0(data);
    expect(parsed.get('sts0_start')).toBe(100);
    expect(parsed.get('sts0_fopens')).toBe(5);
  });

  it('round-trips CONNECTION_INFO_1', () => {
    const info = new CONNECTION_INFO_1();
    info.set('coni1_id', 42);
    info.set('coni1_num_opens', 3);
    info.set('coni1_num_users', 2);
    const data = info.getData();
    const parsed = new CONNECTION_INFO_1(data);
    expect(parsed.get('coni1_id')).toBe(42);
    expect(parsed.get('coni1_num_opens')).toBe(3);
  });

  it('round-trips FILE_INFO_3', () => {
    const info = new FILE_INFO_3();
    info.set('fi3_id', 99);
    info.set('fi3_permissions', PERM_FILE_READ | PERM_FILE_WRITE);
    info.set('fi3_num_locks', 1);
    const data = info.getData();
    const parsed = new FILE_INFO_3(data);
    expect(parsed.get('fi3_id')).toBe(99);
    expect(parsed.get('fi3_permissions')).toBe(PERM_FILE_READ | PERM_FILE_WRITE);
  });

  it('round-trips SESSION_INFO_1 with SESS_GUEST flag', () => {
    const info = new SESSION_INFO_1();
    info.set('sesi1_num_opens', 4);
    info.set('sesi1_user_flags', SESS_GUEST);
    const data = info.getData();
    const parsed = new SESSION_INFO_1(data);
    expect(parsed.get('sesi1_num_opens')).toBe(4);
    expect(parsed.get('sesi1_user_flags')).toBe(SESS_GUEST);
  });

  it('round-trips TIME_OF_DAY_INFO (12 DWORDs = 48 bytes)', () => {
    const tod = new TIME_OF_DAY_INFO();
    tod.set('tod_hours', 14);
    tod.set('tod_mins', 30);
    tod.set('tod_year', 2026);
    const data = tod.getData();
    expect(data.length).toBe(12 * 4);
    const parsed = new TIME_OF_DAY_INFO(data);
    expect(parsed.get('tod_hours')).toBe(14);
    expect(parsed.get('tod_mins')).toBe(30);
    expect(parsed.get('tod_year')).toBe(2026);
  });

  it('PASSWORD_ARRAY parses 256 bytes', () => {
    const arr = new PASSWORD_ARRAY(Buffer.alloc(256, 0));
    expect(arr.getDataLen(Buffer.alloc(256))).toBe(256);
  });

  it('round-trips DISK_INFO', () => {
    const disk = new DISK_INFO();
    const diskField = disk.fields['Disk'] as unknown as { set: (k: string, v: unknown) => void };
    diskField.set('Data', 'C:\\');
    const data = disk.getData();
    expect(data.length).toBeGreaterThan(0);
    const parsed = new DISK_INFO(data);
    const parsedDisk = parsed.fields['Disk'] as unknown as { get: (k: string) => unknown };
    expect(parsedDisk.get('Data')).toBe('C:\\');
  });

  it('round-trips SHARE_INFO_502 with DWORD fields', () => {
    const info = new SHARE_INFO_502();
    info.set('shi502_type', STYPE_IPC);
    info.set('shi502_max_uses', 100);
    info.set('shi502_current_uses', 5);
    info.set('shi502_reserved', 0);
    const data = info.getData();
    const parsed = new SHARE_INFO_502(data);
    expect(parsed.get('shi502_type')).toBe(STYPE_IPC);
    expect(parsed.get('shi502_max_uses')).toBe(100);
    expect(parsed.get('shi502_current_uses')).toBe(5);
  });
});

describe('srvs RPC calls', () => {
  it('round-trips NetrShareEnum request', () => {
    const req = new NetrShareEnum();
    req.set('ServerName', NULL);
    req.set('PreferedMaximumLength', 0xffffffff);
    req.set('ResumeHandle', 0);
    const infoStruct = req.fields['InfoStruct'] as SHARE_ENUM_STRUCT;
    infoStruct.set('Level', 1);
    const shareInfo = infoStruct.fields['ShareInfo'] as SHARE_ENUM_UNION;
    shareInfo.set('tag', 1);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
    const parsed = new NetrShareEnum(data);
    expect(parsed.get('PreferedMaximumLength')).toBe(0xffffffff);
  });

  it('round-trips NetrServerGetInfo request', () => {
    const req = new NetrServerGetInfo();
    req.set('ServerName', NULL);
    req.set('Level', 101);
    const data = req.getData();
    const parsed = new NetrServerGetInfo(data);
    expect(parsed.get('Level')).toBe(101);
  });

  it('round-trips NetrRemoteTOD request (ServerName only)', () => {
    const req = new NetrRemoteTOD();
    req.set('ServerName', NULL);
    const data = req.getData();
    const parsed = new NetrRemoteTOD(data);
    expect(data.length).toBeGreaterThan(0);
    expect(parsed).toBeInstanceOf(NetrRemoteTOD);
  });

  it('round-trips NetrFileClose request', () => {
    const req = new NetrFileClose();
    req.set('ServerName', NULL);
    req.set('FileId', 12345);
    const data = req.getData();
    const parsed = new NetrFileClose(data);
    expect(parsed.get('FileId')).toBe(12345);
  });

  it('NetrShareEnumResponse with SHARE_ENUM union', () => {
    const resp = new NetrShareEnumResponse();
    const infoStruct = resp.fields['InfoStruct'] as SHARE_ENUM_STRUCT;
    infoStruct.set('Level', 1);
    const shareInfo = infoStruct.fields['ShareInfo'] as SHARE_ENUM_UNION;
    shareInfo.set('tag', 1);
    resp.set('TotalEntries', 10);
    resp.set('ErrorCode', 0);
    const data = resp.getData();
    const parsed = new NetrShareEnumResponse(data);
    expect(parsed.get('TotalEntries')).toBe(10);
    expect(parsed.get('ErrorCode')).toBe(0);
  });

  it('NetrServerGetInfoResponse with SERVER_INFO union', () => {
    const resp = new NetrServerGetInfoResponse();
    const infoUnion = resp.fields['InfoStruct'] as unknown as { set: (k: string, v: unknown) => void };
    infoUnion.set('tag', 101);
    resp.set('ErrorCode', 0);
    const data = resp.getData();
    const parsed = new NetrServerGetInfoResponse(data);
    expect(parsed.get('ErrorCode')).toBe(0);
  });
});
