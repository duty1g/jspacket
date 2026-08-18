import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import {
  SchRpcHighestVersion,
  SchRpcHighestVersionResponse,
  SchRpcRegisterTask,
  SchRpcRun,
  SchRpcEnableTask,
  TASK_USER_CRED,
  TASK_XML_ERROR_INFO,
  FIXDLEN_DATA,
  TRIGGERS,
  TASK_FLAG_INTERACTIVE,
  TASK_FLAG_DISABLED,
  TASK_LOGON_PASSWORD,
  TASK_STATE_RUNNING,
  ONCE,
  DAILY,
  WEEKLY,
  MONTHLYDATE,
  MONTHLYDOW,
  SUNDAY,
  MONDAY,
  FIRST_WEEK,
} from '../src/tsch';
import { NULL } from '../src/ndr';
import { DWORD } from '../src/dtypes';

describe('tsch constants', () => {
  it('TASK_FLAG_* values match [MS-TSCH] 2.3.7', () => {
    expect(TASK_FLAG_INTERACTIVE).toBe(0x1);
    expect(TASK_FLAG_DISABLED).toBe(0x4);
  });

  it('TASK_LOGON_* values match [MS-TSCH] 2.3.9', () => {
    expect(TASK_LOGON_PASSWORD).toBe(1);
  });

  it('TASK_STATE_* values match [MS-TSCH] 2.3.13', () => {
    expect(TASK_STATE_RUNNING).toBe(4);
  });

  it('Trigger type constants match [MS-TSCH] 2.4.2.11', () => {
    expect(ONCE).toBe(0);
    expect(DAILY).toBe(1);
    expect(WEEKLY).toBe(2);
    expect(MONTHLYDATE).toBe(3);
    expect(MONTHLYDOW).toBe(4);
  });

  it('Day/week constants', () => {
    expect(SUNDAY).toBe(0);
    expect(MONDAY).toBe(1);
    expect(FIRST_WEEK).toBe(1);
  });
});

describe('tsch structures', () => {
  it('round-trips TASK_USER_CRED', () => {
    const cred = new TASK_USER_CRED();
    cred.set('userId', 'TESTZ\\duty\x00');
    cred.set('password', 'Passw0rd!\x00');
    cred.set('flags', 0);

    const data = cred.getData();
    expect(data.length).toBeGreaterThan(0);

    const parsed = new TASK_USER_CRED(data);
    expect(parsed.get('flags')).toBe(0);
  });

  it('round-trips TASK_XML_ERROR_INFO', () => {
    const info = new TASK_XML_ERROR_INFO();
    info.set('line', 42);
    info.set('column', 10);

    const data = info.getData();
    const parsed = new TASK_XML_ERROR_INFO(data);
    expect(parsed.get('line')).toBe(42);
    expect(parsed.get('column')).toBe(10);
  });

  it('round-trips SchRpcHighestVersion (empty request)', () => {
    const req = new SchRpcHighestVersion();
    const data = req.getData();
    expect(data.length).toBe(0);

    const resp = new SchRpcHighestVersionResponse();
    resp.set('pVersion', 0x10001);
    resp.set('ErrorCode', 0);
    const respData = resp.getData();
    const parsed = new SchRpcHighestVersionResponse(respData);
    expect(parsed.get('pVersion')).toBe(0x10001);
    expect(parsed.get('ErrorCode')).toBe(0);
  });

  it('round-trips SchRpcEnableTask', () => {
    const req = new SchRpcEnableTask();
    req.set('path', '\\\\TESTZ\x00');
    req.set('enabled', 1);

    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);

    const parsed = new SchRpcEnableTask(data);
    expect(parsed.get('enabled')).toBe(1);
  });

  it('round-trips SchRpcRun with args', () => {
    const req = new SchRpcRun();
    req.set('path', '\\Test\x00');
    req.set('cArgs', 2);
    req.set('flags', 0);
    req.set('sessionId', 0);
    req.set('user', NULL);

    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);

    const parsed = new SchRpcRun(data);
    expect(parsed.get('cArgs')).toBe(2);
    expect(parsed.get('flags')).toBe(0);
  });
});

describe('tsch legacy Structure classes', () => {
  it('FIXDLEN_DATA has correct fixed size', () => {
    const fd = new FIXDLEN_DATA();
    const data = fd.getData();
    expect(data.length).toBe(52);
  });

  it('TRIGGERS has correct fixed size', () => {
    const tr = new TRIGGERS();
    const data = tr.getData();
    expect(data.length).toBe(48);
  });
});
