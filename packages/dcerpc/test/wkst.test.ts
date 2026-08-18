import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import {
  NetrWkstaGetInfo,
  NetrWkstaGetInfoResponse,
  WKSTA_INFO_100,
  WKSTA_INFO_101,
  STAT_WORKSTATION_0,
  USE_INFO_1,
  USE_INFO_2,
  JOINPR_ENCRYPTED_USER_PASSWORD,
  NETSETUP_JOIN_STATUS,
  NETSETUP_NAME_TYPE,
  NET_COMPUTER_NAME_TYPE,
  JOIN_MAX_PASSWORD_LENGTH,
  JOIN_OBFUSCATOR_LENGTH,
  USE_OK,
  USE_PAUSED,
  USE_DISKDEV,
  USE_IPC,
  USE_NOFORCE,
  USE_FORCE,
  USE_LOTS_OF_FORCE,
  NETSETUP_JOIN_DOMAIN,
  NETSETUP_ACCT_CREATE,
  NETSETUP_IGNORE_UNSUPPORTED_FLAGS,
} from '../src/wkst';
import { NULL } from '../src/ndr';
import { ULONG } from '../src/dtypes';

describe('wkst constants', () => {
  it('USE_* status values match [MS-WKST] 2.2.5.22', () => {
    expect(USE_OK).toBe(0);
    expect(USE_PAUSED).toBe(1);
  });

  it('USE_* device type values match [MS-WKST] 2.2.5.22', () => {
    expect(USE_DISKDEV).toBe(0);
    expect(USE_IPC).toBe(3);
  });

  it('USE_* force level values match [MS-WKST] 3.2.4.9', () => {
    expect(USE_NOFORCE).toBe(0);
    expect(USE_FORCE).toBe(1);
    expect(USE_LOTS_OF_FORCE).toBe(2);
  });

  it('NETSETUP_* options match [MS-WKST] 3.2.4.13', () => {
    expect(NETSETUP_JOIN_DOMAIN).toBe(0x1);
    expect(NETSETUP_ACCT_CREATE).toBe(0x2);
    expect(NETSETUP_IGNORE_UNSUPPORTED_FLAGS).toBe(0x10000000);
  });

  it('JOIN_MAX_PASSWORD_LENGTH and JOIN_OBFUSCATOR_LENGTH', () => {
    expect(JOIN_MAX_PASSWORD_LENGTH).toBe(256);
    expect(JOIN_OBFUSCATOR_LENGTH).toBe(8);
  });
});

describe('wkst enums', () => {
  it('NETSETUP_JOIN_STATUS maps names to values', () => {
    const e = new NETSETUP_JOIN_STATUS();
    e.set('Data', 'NetSetupDomainName');
    expect(e.get('Data')).toBe(3);
  });

  it('NETSETUP_NAME_TYPE maps names to values', () => {
    const e = new NETSETUP_NAME_TYPE();
    e.set('Data', 'NetSetupDnsMachine');
    expect(e.get('Data')).toBe(5);
  });

  it('NET_COMPUTER_NAME_TYPE maps names to values', () => {
    const e = new NET_COMPUTER_NAME_TYPE();
    e.set('Data', 'NetAllComputerNames');
    expect(e.get('Data')).toBe(2);
  });
});

describe('wkst structures', () => {
  it('round-trips WKSTA_INFO_100', () => {
    const info = new WKSTA_INFO_100();
    info.set('wki100_platform_id', 500);
    info.set('wki100_ver_major', 10);
    info.set('wki100_ver_minor', 0);

    const data = info.getData();
    expect(data.length).toBeGreaterThan(0);

    const parsed = new WKSTA_INFO_100(data);
    expect(parsed.get('wki100_platform_id')).toBe(500);
    expect(parsed.get('wki100_ver_major')).toBe(10);
    expect(parsed.get('wki100_ver_minor')).toBe(0);
  });

  it('round-trips WKSTA_INFO_101', () => {
    const info = new WKSTA_INFO_101();
    info.set('wki101_platform_id', 500);
    info.set('wki101_ver_major', 10);
    info.set('wki101_ver_minor', 0);

    const data = info.getData();
    const parsed = new WKSTA_INFO_101(data);
    expect(parsed.get('wki101_platform_id')).toBe(500);
    expect(parsed.get('wki101_ver_major')).toBe(10);
  });

  it('STAT_WORKSTATION_0 has 13 LARGE_INTEGER + 27 ULONG fields', () => {
    const stat = new STAT_WORKSTATION_0();
    stat.set('StatisticsStartTime', 0n);
    stat.set('BytesReceived', 100n);
    stat.set('Sessions', 5);
    stat.set('UseCount', 10);

    const data = stat.getData();
    expect(data.length).toBe(13 * 8 + 27 * 4);

    const parsed = new STAT_WORKSTATION_0(data);
    expect(parsed.get('BytesReceived')).toBe(100n);
    expect(parsed.get('Sessions')).toBe(5);
    expect(parsed.get('UseCount')).toBe(10);
  });

  it('round-trips USE_INFO_1', () => {
    const info = new USE_INFO_1();
    info.set('ui1_status', USE_OK);
    info.set('ui1_asg_type', USE_DISKDEV);
    info.set('ui1_refcount', 1);
    info.set('ui1_usecount', 2);

    const data = info.getData();
    const parsed = new USE_INFO_1(data);
    expect(parsed.get('ui1_status')).toBe(USE_OK);
    expect(parsed.get('ui1_asg_type')).toBe(USE_DISKDEV);
    expect(parsed.get('ui1_refcount')).toBe(1);
    expect(parsed.get('ui1_usecount')).toBe(2);
  });

  it('round-trips USE_INFO_2 (nested USE_INFO_1)', () => {
    const info = new USE_INFO_2();
    info.set('ui2_username', 'duty\x00');
    info.set('ui2_domainname', 'TESTZ\x00');

    const data = info.getData();
    expect(data.length).toBeGreaterThan(0);

    const parsed = new USE_INFO_2(data);
    expect(parsed.get('ui2_username')).toBeTruthy();
  });

  it('JOINPR_ENCRYPTED_USER_PASSWORD is 524 bytes with 1-byte alignment', () => {
    const pw = new JOINPR_ENCRYPTED_USER_PASSWORD();
    expect(pw.getAlignment()).toBe(1);
    const data = pw.getData();
    expect(data.length).toBe(524);
  });
});

describe('wkst RPC calls', () => {
  it('round-trips NetrWkstaGetInfo', () => {
    const req = new NetrWkstaGetInfo();
    req.set('ServerName', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
    req.set('Level', 100);

    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);

    const parsed = new NetrWkstaGetInfo(data);
    expect(parsed.get('Level')).toBe(100);
  });

  it('NetrWkstaGetInfoResponse with WKSTA_INFO union', () => {
    const resp = new NetrWkstaGetInfoResponse();
    const wkstaInfo = resp.fields['WkstaInfo'] as typeof WKSTA_INFO extends new () => infer R
      ? R
      : never;
    const infoUnion = resp.fields['WkstaInfo'] as unknown as {
      set: (k: string, v: unknown) => void;
    };
    infoUnion.set('tag', 100);
    resp.set('ErrorCode', 0);

    const data = resp.getData();
    expect(data.length).toBeGreaterThan(0);

    const parsed = new NetrWkstaGetInfoResponse(data);
    expect(parsed.get('ErrorCode')).toBe(0);
  });
});
